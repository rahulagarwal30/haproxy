/*
 * Master Worker
 *
 * Copyright HAProxy Technologies 2019 - William Lallemand <wlallemand@haproxy.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>

#include <common/initcall.h>
#include <common/mini-clist.h>

#include <types/cli.h>
#include <types/global.h>
#include <types/peers.h>
#include <types/signal.h>

#include <proto/cli.h>
#include <proto/fd.h>
#include <proto/listener.h>
#include <proto/log.h>
#include <proto/mworker.h>
#include <proto/proxy.h>
#include <proto/signal.h>
#include <proto/stream.h>
#include <proto/stream_interface.h>


#if defined(USE_SYSTEMD)
#include <systemd/sd-daemon.h>
#endif

static int exitcode = -1;

/* ----- children processes handling ----- */

/*
 * Send signal to every known children.
 */

static void mworker_kill(int sig)
{
	struct mworker_proc *child;

	list_for_each_entry(child, &proc_list, list) {
		/* careful there, we must be sure that the pid > 0, we don't want to emit a kill -1 */
		if ((child->type == 'w' || child->type == 'e') && (child->reloads == 0) && (child->pid > 0))
			kill(child->pid, sig);
	}
}


/* return 1 if a pid is a current child otherwise 0 */
int mworker_current_child(int pid)
{
	struct mworker_proc *child;

	list_for_each_entry(child, &proc_list, list) {
		if ((child->type == 'w' || child->type == 'e') && (child->reloads == 0) && (child->pid == pid))
			return 1;
	}
	return 0;
}

/*
 * Return the number of new and old children (including workers and external
 * processes)
 */
int mworker_child_nb()
{
	struct mworker_proc *child;
	int ret = 0;

	list_for_each_entry(child, &proc_list, list) {
		if ((child->type == 'w' || child->type == 'e'))
			ret++;
	}

	return ret;
}


/*
 * serialize the proc list and put it in the environment
 */
void mworker_proc_list_to_env()
{
	char *msg = NULL;
	struct mworker_proc *child;

	list_for_each_entry(child, &proc_list, list) {
		if (child->pid > -1)
			memprintf(&msg, "%s|type=%c;fd=%d;pid=%d;rpid=%d;reloads=%d;timestamp=%d;id=%s", msg ? msg : "", child->type, child->ipc_fd[0], child->pid, child->relative_pid, child->reloads, child->timestamp, child->id ? child->id : "");
	}
	if (msg)
		setenv("HAPROXY_PROCESSES", msg, 1);
}

/*
 * unserialize the proc list from the environment
 */
void mworker_env_to_proc_list()
{
	char *msg, *token = NULL, *s1;

	msg = getenv("HAPROXY_PROCESSES");
	if (!msg)
		return;

	while ((token = strtok_r(msg, "|", &s1))) {
		struct mworker_proc *child;
		char *subtoken = NULL;
		char *s2;

		msg = NULL;

		child = calloc(1, sizeof(*child));

		while ((subtoken = strtok_r(token, ";", &s2))) {

			token = NULL;

			if (strncmp(subtoken, "type=", 5) == 0) {
				child->type = *(subtoken+5);
				if (child->type == 'm') /* we are in the master, assign it */
					proc_self = child;
			} else if (strncmp(subtoken, "fd=", 3) == 0) {
				child->ipc_fd[0] = atoi(subtoken+3);
			} else if (strncmp(subtoken, "pid=", 4) == 0) {
				child->pid = atoi(subtoken+4);
			} else if (strncmp(subtoken, "rpid=", 5) == 0) {
				child->relative_pid = atoi(subtoken+5);
			} else if (strncmp(subtoken, "reloads=", 8) == 0) {
				/* we reloaded this process once more */
				child->reloads = atoi(subtoken+8) + 1;
			} else if (strncmp(subtoken, "timestamp=", 10) == 0) {
				child->timestamp = atoi(subtoken+10);
			} else if (strncmp(subtoken, "id=", 3) == 0) {
				child->id = strdup(subtoken+3);
			}
		}
		if (child->pid) {
			LIST_ADDQ(&proc_list, &child->list);
		} else {
			free(child->id);
			free(child);

		}
	}

	unsetenv("HAPROXY_PROCESSES");
}

/* Signal blocking and unblocking */

void mworker_block_signals()
{
	sigset_t set;

	sigemptyset(&set);
	sigaddset(&set, SIGUSR1);
	sigaddset(&set, SIGUSR2);
	sigaddset(&set, SIGHUP);
	sigaddset(&set, SIGCHLD);
	ha_sigmask(SIG_SETMASK, &set, NULL);
}

void mworker_unblock_signals()
{
	haproxy_unblock_signals();
}

/* ----- mworker signal handlers ----- */

/*
 * When called, this function reexec haproxy with -sf followed by current
 * children PIDs and possibly old children PIDs if they didn't leave yet.
 */
void mworker_catch_sighup(struct sig_handler *sh)
{
	mworker_reload();
}

void mworker_catch_sigterm(struct sig_handler *sh)
{
	int sig = sh->arg;

#if defined(USE_SYSTEMD)
	if (global.tune.options & GTUNE_USE_SYSTEMD) {
		sd_notify(0, "STOPPING=1");
	}
#endif
	ha_warning("Exiting Master process...\n");
	mworker_kill(sig);
}

/*
 * Wait for every children to exit
 */

void mworker_catch_sigchld(struct sig_handler *sh)
{
	int exitpid = -1;
	int status = 0;
	struct mworker_proc *child, *it;
	int childfound;

restart_wait:

	childfound = 0;

	exitpid = waitpid(-1, &status, WNOHANG);
	if (exitpid > 0) {
		if (WIFEXITED(status))
			status = WEXITSTATUS(status);
		else if (WIFSIGNALED(status))
			status = 128 + WTERMSIG(status);
		else if (WIFSTOPPED(status))
			status = 128 + WSTOPSIG(status);
		else
			status = 255;

		/* delete the child from the process list */
		list_for_each_entry_safe(child, it, &proc_list, list) {
			if (child->pid != exitpid)
				continue;

			LIST_DEL(&child->list);
			close(child->ipc_fd[0]);
			childfound = 1;
			break;
		}

		if (!childfound) {
			/* We didn't find the PID in the list, that shouldn't happen but we can emit a warning */
			ha_warning("Process %d exited with code %d (%s)\n", exitpid, status, (status >= 128) ? strsignal(status - 128) : "Exit");
		} else {
			/* check if exited child is a current child */
			if (child->reloads == 0) {
				if (child->type == 'w')
					ha_alert("Current worker #%d (%d) exited with code %d (%s)\n", child->relative_pid, exitpid, status, (status >= 128) ? strsignal(status - 128) : "Exit");
				else if (child->type == 'e')
					ha_alert("Current program '%s' (%d) exited with code %d (%s)\n", child->id, exitpid, status, (status >= 128) ? strsignal(status - 128) : "Exit");

				if (status != 0 && status != 130 && status != 143
				    && !(global.tune.options & GTUNE_NOEXIT_ONFAILURE)) {
					ha_alert("exit-on-failure: killing every processes with SIGTERM\n");
					if (exitcode < 0)
						exitcode = status;
					mworker_kill(SIGTERM);
				}
			} else {
				if (child->type == 'w') {
					ha_warning("Former worker #%d (%d) exited with code %d (%s)\n", child->relative_pid, exitpid, status, (status >= 128) ? strsignal(status - 128) : "Exit");
					delete_oldpid(exitpid);
				} else if (child->type == 'e') {
					ha_warning("Former program '%s' (%d) exited with code %d (%s)\n", child->id, exitpid, status, (status >= 128) ? strsignal(status - 128) : "Exit");
				}
			}
			free(child);
		}

		/* do it again to check if it was the last worker */
		goto restart_wait;
	}
	/* Better rely on the system than on a list of process to check if it was the last one */
	else if (exitpid == -1 && errno == ECHILD) {
		ha_warning("All workers exited. Exiting... (%d)\n", (exitcode > 0) ? exitcode : status);
		atexit_flag = 0;
		if (exitcode > 0)
			exit(exitcode);
		exit(status); /* parent must leave using the latest status code known */
	}

}

/* ----- IPC FD (sockpair) related ----- */

/* This wrapper is called from the workers. It is registered instead of the
 * normal listener_accept() so the worker can exit() when it detects that the
 * master closed the IPC FD. If it's not a close, we just call the regular
 * listener_accept() function */
void mworker_accept_wrapper(int fd)
{
	char c;
	int ret;

	while (1) {
		ret = recv(fd, &c, 1, MSG_PEEK);
		if (ret == -1) {
			if (errno == EINTR)
				continue;
			if (errno == EAGAIN) {
				fd_cant_recv(fd);
				return;
			}
			break;
		} else if (ret > 0) {
			listener_accept(fd);
			return;
		} else if (ret == 0) {
			/* At this step the master is down before
			 * this worker perform a 'normal' exit.
			 * So we want to exit with an error but
			 * other threads could currently process
			 * some stuff so we can't perform a clean
			 * deinit().
			 */
			exit(EXIT_FAILURE);
		}
	}
	return;
}

/*
 * This function register the accept wrapper for the sockpair of the master worker
 */
void mworker_pipe_register()
{
	/* The iocb should be already initialized with listener_accept */
	if (fdtab[proc_self->ipc_fd[1]].iocb == mworker_accept_wrapper)
		return;

	fcntl(proc_self->ipc_fd[1], F_SETFL, O_NONBLOCK);
	/* In multi-tread, we need only one thread to process
	 * events on the pipe with master
	 */
	fd_insert(proc_self->ipc_fd[1], fdtab[proc_self->ipc_fd[1]].owner, mworker_accept_wrapper, 1);
	fd_want_recv(proc_self->ipc_fd[1]);
}

/* ----- proxies ----- */
/*
 * Upon a reload, the master worker needs to close all listeners FDs but the mworker_pipe
 * fd, and the FD provided by fd@
 */
void mworker_cleanlisteners()
{
	struct listener *l, *l_next;
	struct proxy *curproxy;
	struct peers *curpeers;

	/* we might have to unbind some peers sections from some processes */
	for (curpeers = cfg_peers; curpeers; curpeers = curpeers->next) {
		if (!curpeers->peers_fe)
			continue;

		stop_proxy(curpeers->peers_fe);
		/* disable this peer section so that it kills itself */
		signal_unregister_handler(curpeers->sighandler);
		task_delete(curpeers->sync_task);
		task_free(curpeers->sync_task);
		curpeers->sync_task = NULL;
		task_free(curpeers->peers_fe->task);
		curpeers->peers_fe->task = NULL;
		curpeers->peers_fe = NULL;
	}

	for (curproxy = proxies_list; curproxy; curproxy = curproxy->next) {
		int listen_in_master = 0;

		list_for_each_entry_safe(l, l_next, &curproxy->conf.listeners, by_fe) {
			/* remove the listener, but not those we need in the master... */
			if (!(l->options & LI_O_MWORKER)) {
				/* unbind the listener but does not close if
				   the FD is inherited with fd@ from the parent
				   process */
				if (l->options & LI_O_INHERITED)
					unbind_listener_no_close(l);
				else
					unbind_listener(l);
				delete_listener(l);
			} else {
				listen_in_master = 1;
			}
		}
		/* if the proxy shouldn't be in the master, we stop it */
		if (!listen_in_master)
			curproxy->state = PR_STSTOPPED;
	}
}

/*  Displays workers and processes  */
static int cli_io_handler_show_proc(struct appctx *appctx)
{
	struct stream_interface *si = appctx->owner;
	struct mworker_proc *child;
	int old = 0;
	int up = now.tv_sec - proc_self->timestamp;

	if (unlikely(si_ic(si)->flags & (CF_WRITE_ERROR|CF_SHUTW)))
		return 1;

	chunk_reset(&trash);

	chunk_printf(&trash, "#%-14s %-15s %-15s %-15s %s\n", "<PID>", "<type>", "<relative PID>", "<reloads>", "<uptime>");
	chunk_appendf(&trash, "%-15u %-15s %-15u %-15d %dd %02dh%02dm%02ds\n", getpid(), "master", 0, proc_self->reloads, up / 86400, (up % 86400) / 3600, (up % 3600) / 60, (up % 60));

	/* displays current processes */

	chunk_appendf(&trash, "# workers\n");
	list_for_each_entry(child, &proc_list, list) {
		up = now.tv_sec - child->timestamp;

		if (child->type != 'w')
			continue;

		if (child->reloads > 0) {
			old++;
			continue;
		}
		chunk_appendf(&trash, "%-15u %-15s %-15u %-15d %dd %02dh%02dm%02ds\n", child->pid, "worker", child->relative_pid, child->reloads, up / 86400, (up % 86400) / 3600, (up % 3600) / 60, (up % 60));
	}

	/* displays old processes */

	if (old) {
		char *msg = NULL;

		chunk_appendf(&trash, "# old workers\n");
		list_for_each_entry(child, &proc_list, list) {
			up = now.tv_sec - child->timestamp;

			if (child->type != 'w')
				continue;

			if (child->reloads > 0) {
				memprintf(&msg, "[was: %u]", child->relative_pid);
				chunk_appendf(&trash, "%-15u %-15s %-15s %-15d %dd %02dh%02dm%02ds\n", child->pid, "worker", msg, child->reloads, up / 86400, (up % 86400) / 3600, (up % 3600) / 60, (up % 60));
			}
		}
		free(msg);
	}

	/* displays external process */
	chunk_appendf(&trash, "# programs\n");
	old = 0;
	list_for_each_entry(child, &proc_list, list) {
		up = now.tv_sec - child->timestamp;

		if (child->type != 'e')
			continue;

		if (child->reloads > 0) {
			old++;
			continue;
		}
		chunk_appendf(&trash, "%-15u %-15s %-15s %-15d %dd %02dh%02dm%02ds\n", child->pid, child->id, "-", child->reloads, up / 86400, (up % 86400) / 3600, (up % 3600) / 60, (up % 60));
	}

	if (old) {
		chunk_appendf(&trash, "# old programs\n");
		list_for_each_entry(child, &proc_list, list) {
			up = now.tv_sec - child->timestamp;

			if (child->type != 'e')
				continue;

			if (child->reloads > 0) {
				chunk_appendf(&trash, "%-15u %-15s %-15s %-15d %dd %02dh%02dm%02ds\n", child->pid, child->id, "-", child->reloads, up / 86400, (up % 86400) / 3600, (up % 3600) / 60, (up % 60));
			}
		}
	}



	if (ci_putchk(si_ic(si), &trash) == -1) {
		si_rx_room_blk(si);
		return 0;
	}

	/* dump complete */
	return 1;
}

/* reload the master process */
static int cli_parse_reload(char **args, char *payload, struct appctx *appctx, void *private)
{
	if (!cli_has_level(appctx, ACCESS_LVL_OPER))
		return 1;

	mworker_reload();

	return 1;
}


/* register cli keywords */
static struct cli_kw_list cli_kws = {{ },{
	{ { "@<relative pid>", NULL }, "@<relative pid> : send a command to the <relative pid> process", NULL, cli_io_handler_show_proc, NULL, NULL, ACCESS_MASTER_ONLY},
	{ { "@!<pid>", NULL }, "@!<pid>        : send a command to the <pid> process", cli_parse_default, NULL, NULL, NULL, ACCESS_MASTER_ONLY},
	{ { "@master", NULL }, "@master        : send a command to the master process", cli_parse_default, NULL, NULL, NULL, ACCESS_MASTER_ONLY},
	{ { "show", "proc", NULL }, "show proc      : show processes status", cli_parse_default, cli_io_handler_show_proc, NULL, NULL, ACCESS_MASTER_ONLY},
	{ { "reload", NULL },    "reload         : reload haproxy", cli_parse_reload, NULL, NULL, NULL, ACCESS_MASTER_ONLY},
	{{},}
}};

INITCALL1(STG_REGISTER, cli_register_kw, &cli_kws);
