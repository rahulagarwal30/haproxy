#include <sys/socket.h>

#include <lauxlib.h>
#include <lua.h>
#include <lualib.h>

#if !defined(LUA_VERSION_NUM) || LUA_VERSION_NUM < 502
#error "Requires Lua 5.2 or later."
#endif

#include <ebpttree.h>

#include <common/cfgparse.h>

#include <types/connection.h>
#include <types/hlua.h>
#include <types/proto_tcp.h>
#include <types/proxy.h>

#include <proto/arg.h>
#include <proto/channel.h>
#include <proto/hdr_idx.h>
#include <proto/hlua.h>
#include <proto/obj_type.h>
#include <proto/pattern.h>
#include <proto/payload.h>
#include <proto/proto_http.h>
#include <proto/proto_tcp.h>
#include <proto/raw_sock.h>
#include <proto/sample.h>
#include <proto/server.h>
#include <proto/session.h>
#include <proto/ssl_sock.h>
#include <proto/stream_interface.h>
#include <proto/task.h>

/* Lua uses longjmp to perform yield or throwing errors. This
 * macro is used only for identifying the function that can
 * not return because a longjmp is executed.
 *   __LJMP marks a prototype of hlua file that can use longjmp.
 *   WILL_LJMP() marks an lua function that will use longjmp.
 *   MAY_LJMP() marks an lua function that may use longjmp.
 */
#define __LJMP
#define WILL_LJMP(func) func
#define MAY_LJMP(func) func

/* The main Lua execution context. */
struct hlua gL;

/* This is the memory pool containing all the signal structs. These
 * struct are used to store each requiered signal between two tasks.
 */
struct pool_head *pool2_hlua_com;
struct pool_head *pool2_hlua_sleep;

/* Used for Socket connection. */
static struct proxy socket_proxy;
static struct server socket_tcp;
#ifdef USE_OPENSSL
static struct server socket_ssl;
#endif

/* List head of the function called at the initialisation time. */
struct list hlua_init_functions = LIST_HEAD_INIT(hlua_init_functions);

/* Store the fast lua context for coroutines. This tree uses the
 * Lua stack pointer value as indexed entry, and store the associated
 * hlua context.
 */
struct eb_root hlua_ctx = EB_ROOT_UNIQUE;

/* The following variables contains the reference of the different
 * Lua classes. These references are useful for identify metadata
 * associated with an object.
 */
static int class_core_ref;
static int class_txn_ref;
static int class_socket_ref;
static int class_channel_ref;

/* Global Lua execution timeout. By default Lua, execution linked
 * with session (actions, sample-fetches and converters) have a
 * short timeout. Lua linked with tasks doesn't have a timeout
 * because a task may remain alive during all the haproxy execution.
 */
static unsigned int hlua_timeout_session = 4000; /* session timeout. */
static unsigned int hlua_timeout_task = TICK_ETERNITY; /* task timeout. */

/* Interrupts the Lua processing each "hlua_nb_instruction" instructions.
 * it is used for preventing infinite loops.
 *
 * I test the scheer with an infinite loop containing one incrementation
 * and one test. I run this loop between 10 seconds, I raise a ceil of
 * 710M loops from one interrupt each 9000 instructions, so I fix the value
 * to one interrupt each 10 000 instructions.
 *
 *  configured    | Number of
 *  instructions  | loops executed
 *  between two   | in milions
 *  forced yields |
 * ---------------+---------------
 *  10            | 160
 *  500           | 670
 *  1000          | 680
 *  5000          | 700
 *  7000          | 700
 *  8000          | 700
 *  9000          | 710 <- ceil
 *  10000         | 710
 *  100000        | 710
 *  1000000       | 710
 *
 */
static unsigned int hlua_nb_instruction = 10000;

/* These functions converts types between HAProxy internal args or
 * sample and LUA types. Another function permits to check if the
 * LUA stack contains arguments according with an required ARG_T
 * format.
 */
static int hlua_arg2lua(lua_State *L, const struct arg *arg);
static int hlua_lua2arg(lua_State *L, int ud, struct arg *arg);
__LJMP static int hlua_lua2arg_check(lua_State *L, int first, struct arg *argp, unsigned int mask);
static int hlua_smp2lua(lua_State *L, const struct sample *smp);
static int hlua_lua2smp(lua_State *L, int ud, struct sample *smp);

/* Used to check an Lua function type in the stack. It creates and
 * returns a reference of the function. This function throws an
 * error if the rgument is not a "function".
 */
__LJMP unsigned int hlua_checkfunction(lua_State *L, int argno)
{
	if (!lua_isfunction(L, argno)) {
		const char *msg = lua_pushfstring(L, "function expected, got %s", luaL_typename(L, -1));
		WILL_LJMP(luaL_argerror(L, argno, msg));
	}
	lua_pushvalue(L, argno);
	return luaL_ref(L, LUA_REGISTRYINDEX);
}

/* The three following functions are useful for adding entries
 * in a table. These functions takes a string and respectively an
 * integer, a string or a function and add it to the table in the
 * top of the stack.
 *
 * These functions throws an error if no more stack size is
 * available.
 */
__LJMP static inline void hlua_class_const_int(lua_State *L, const char *name,
                                               int value)
{
	if (!lua_checkstack(L, 2))
	WILL_LJMP(luaL_error(L, "full stack"));
	lua_pushstring(L, name);
	lua_pushinteger(L, value);
	lua_settable(L, -3);
}
__LJMP static inline void hlua_class_const_str(lua_State *L, const char *name,
                                        const char *value)
{
	if (!lua_checkstack(L, 2))
		WILL_LJMP(luaL_error(L, "full stack"));
	lua_pushstring(L, name);
	lua_pushstring(L, value);
	lua_settable(L, -3);
}
__LJMP static inline void hlua_class_function(lua_State *L, const char *name,
                                       int (*function)(lua_State *L))
{
	if (!lua_checkstack(L, 2))
		WILL_LJMP(luaL_error(L, "full stack"));
	lua_pushstring(L, name);
	lua_pushcclosure(L, function, 0);
	lua_settable(L, -3);
}

/* This function check the number of arguments available in the
 * stack. If the number of arguments available is not the same
 * then <nb> an error is throwed.
 */
__LJMP static inline void check_args(lua_State *L, int nb, char *fcn)
{
	if (lua_gettop(L) == nb)
		return;
	WILL_LJMP(luaL_error(L, "'%s' needs %d arguments", fcn, nb));
}

/* Return true if the data in stack[<ud>] is an object of
 * type <class_ref>.
 */
static int hlua_udataistype(lua_State *L, int ud, int class_ref)
{
	void *p = lua_touserdata(L, ud);
	if (!p)
		return 0;

	if (!lua_getmetatable(L, ud))
		return 0;

	lua_rawgeti(L, LUA_REGISTRYINDEX, class_ref);
	if (!lua_rawequal(L, -1, -2)) {
		lua_pop(L, 2);
		return 0;
	}

	lua_pop(L, 2);
	return 1;
}

/* Return an object of the expected type, or throws an error. */
__LJMP static void *hlua_checkudata(lua_State *L, int ud, int class_ref)
{
	if (!hlua_udataistype(L, ud, class_ref))
		WILL_LJMP(luaL_argerror(L, 1, NULL));
	return lua_touserdata(L, ud);
}

/* This fucntion push an error string prefixed by the file name
 * and the line number where the error is encountered.
 */
static int hlua_pusherror(lua_State *L, const char *fmt, ...)
{
	va_list argp;
	va_start(argp, fmt);
	luaL_where(L, 1);
	lua_pushvfstring(L, fmt, argp);
	va_end(argp);
	lua_concat(L, 2);
	return 1;
}

/* This function register a new signal. "lua" is the current lua
 * execution context. It contains a pointer to the associated task.
 * "link" is a list head attached to an other task that must be wake
 * the lua task if an event occurs. This is useful with external
 * events like TCP I/O or sleep functions. This funcion allocate
 * memory for the signal.
 */
static int hlua_com_new(struct hlua *lua, struct list *link)
{
	struct hlua_com *com = pool_alloc2(pool2_hlua_com);
	if (!com)
		return 0;
	LIST_ADDQ(&lua->com, &com->purge_me);
	LIST_ADDQ(link, &com->wake_me);
	com->task = lua->task;
	return 1;
}

/* This function purge all the pending signals when the LUA execution
 * is finished. This prevent than a coprocess try to wake a deleted
 * task. This function remove the memory associated to the signal.
 */
static void hlua_com_purge(struct hlua *lua)
{
	struct hlua_com *com, *back;

	/* Delete all pending communication signals. */
	list_for_each_entry_safe(com, back, &lua->com, purge_me) {
		LIST_DEL(&com->purge_me);
		LIST_DEL(&com->wake_me);
		pool_free2(pool2_hlua_com, com);
	}
}

/* This function sends signals. It wakes all the tasks attached
 * to a list head, and remove the signal, and free the used
 * memory.
 */
static void hlua_com_wake(struct list *wake)
{
	struct hlua_com *com, *back;

	/* Wake task and delete all pending communication signals. */
	list_for_each_entry_safe(com, back, wake, wake_me) {
		LIST_DEL(&com->purge_me);
		LIST_DEL(&com->wake_me);
		task_wakeup(com->task, TASK_WOKEN_MSG);
		pool_free2(pool2_hlua_com, com);
	}
}

/* This functions is used with sample fetch and converters. It
 * converts the HAProxy configuration argument in a lua stack
 * values.
 *
 * It takes an array of "arg", and each entry of the array is
 * converted and pushed in the LUA stack.
 */
static int hlua_arg2lua(lua_State *L, const struct arg *arg)
{
	switch (arg->type) {
	case ARGT_SINT:
		lua_pushinteger(L, arg->data.sint);
		break;

	case ARGT_UINT:
	case ARGT_TIME:
	case ARGT_SIZE:
		lua_pushinteger(L, arg->data.sint);
		break;

	case ARGT_STR:
		lua_pushlstring(L, arg->data.str.str, arg->data.str.len);
		break;

	case ARGT_IPV4:
	case ARGT_IPV6:
	case ARGT_MSK4:
	case ARGT_MSK6:
	case ARGT_FE:
	case ARGT_BE:
	case ARGT_TAB:
	case ARGT_SRV:
	case ARGT_USR:
	case ARGT_MAP:
	default:
		lua_pushnil(L);
		break;
	}
	return 1;
}

/* This function take one entrie in an LUA stack at the index "ud",
 * and try to convert it in an HAProxy argument entry. This is useful
 * with sample fetch wrappers. The input arguments are gived to the
 * lua wrapper and converted as arg list by thi function.
 */
static int hlua_lua2arg(lua_State *L, int ud, struct arg *arg)
{
	switch (lua_type(L, ud)) {

	case LUA_TNUMBER:
	case LUA_TBOOLEAN:
		arg->type = ARGT_SINT;
		arg->data.sint = lua_tointeger(L, ud);
		break;

	case LUA_TSTRING:
		arg->type = ARGT_STR;
		arg->data.str.str = (char *)lua_tolstring(L, ud, (size_t *)&arg->data.str.len);
		break;

	case LUA_TUSERDATA:
	case LUA_TNIL:
	case LUA_TTABLE:
	case LUA_TFUNCTION:
	case LUA_TTHREAD:
	case LUA_TLIGHTUSERDATA:
		arg->type = ARGT_SINT;
		arg->data.uint = 0;
		break;
	}
	return 1;
}

/* the following functions are used to convert a struct sample
 * in Lua type. This useful to convert the return of the
 * fetchs or converters.
 */
static int hlua_smp2lua(lua_State *L, const struct sample *smp)
{
	switch (smp->type) {
	case SMP_T_SINT:
	case SMP_T_BOOL:
	case SMP_T_UINT:
		lua_pushinteger(L, smp->data.sint);
		break;

	case SMP_T_BIN:
	case SMP_T_STR:
		lua_pushlstring(L, smp->data.str.str, smp->data.str.len);
		break;

	case SMP_T_METH:
		switch (smp->data.meth.meth) {
		case HTTP_METH_OPTIONS: lua_pushstring(L, "OPTIONS"); break;
		case HTTP_METH_GET:     lua_pushstring(L, "GET");     break;
		case HTTP_METH_HEAD:    lua_pushstring(L, "HEAD");    break;
		case HTTP_METH_POST:    lua_pushstring(L, "POST");    break;
		case HTTP_METH_PUT:     lua_pushstring(L, "PUT");     break;
		case HTTP_METH_DELETE:  lua_pushstring(L, "DELETE");  break;
		case HTTP_METH_TRACE:   lua_pushstring(L, "TRACE");   break;
		case HTTP_METH_CONNECT: lua_pushstring(L, "CONNECT"); break;
		case HTTP_METH_OTHER:
			lua_pushlstring(L, smp->data.meth.str.str, smp->data.meth.str.len);
			break;
		default:
			lua_pushnil(L);
			break;
		}
		break;

	case SMP_T_IPV4:
	case SMP_T_IPV6:
	case SMP_T_ADDR: /* This type is never used to qualify a sample. */
	default:
		lua_pushnil(L);
		break;
	}
	return 1;
}

/* the following functions are used to convert an Lua type in a
 * struct sample. This is useful to provide data from a converter
 * to the LUA code.
 */
static int hlua_lua2smp(lua_State *L, int ud, struct sample *smp)
{
	switch (lua_type(L, ud)) {

	case LUA_TNUMBER:
		smp->type = SMP_T_SINT;
		smp->data.sint = lua_tointeger(L, ud);
		break;


	case LUA_TBOOLEAN:
		smp->type = SMP_T_BOOL;
		smp->data.uint = lua_toboolean(L, ud);
		break;

	case LUA_TSTRING:
		smp->type = SMP_T_STR;
		smp->flags |= SMP_F_CONST;
		smp->data.str.str = (char *)lua_tolstring(L, ud, (size_t *)&smp->data.str.len);
		break;

	case LUA_TUSERDATA:
	case LUA_TNIL:
	case LUA_TTABLE:
	case LUA_TFUNCTION:
	case LUA_TTHREAD:
	case LUA_TLIGHTUSERDATA:
		smp->type = SMP_T_BOOL;
		smp->data.uint = 0;
		break;
	}
	return 1;
}

/* This function check the "argp" builded by another conversion function
 * is in accord with the expected argp defined by the "mask". The fucntion
 * returns true or false. It can be adjust the types if there compatibles.
 */
__LJMP int hlua_lua2arg_check(lua_State *L, int first, struct arg *argp, unsigned int mask)
{
	int min_arg;
	int idx;

	idx = 0;
	min_arg = ARGM(mask);
	mask >>= ARGM_BITS;

	while (1) {

		/* Check oversize. */
		if (idx >= ARGM_NBARGS && argp[idx].type != ARGT_STOP) {
			WILL_LJMP(luaL_argerror(L, first + idx, "Malformed argument mask"));
		}

		/* Check for mandatory arguments. */
		if (argp[idx].type == ARGT_STOP) {
			if (idx + 1 < min_arg)
				WILL_LJMP(luaL_argerror(L, first + idx, "Mandatory argument expected"));
			return 0;
		}

		/* Check for exceed the number of requiered argument. */
		if ((mask & ARGT_MASK) == ARGT_STOP &&
		    argp[idx].type != ARGT_STOP) {
			WILL_LJMP(luaL_argerror(L, first + idx, "Last argument expected"));
		}

		if ((mask & ARGT_MASK) == ARGT_STOP &&
		    argp[idx].type == ARGT_STOP) {
			return 0;
		}

		/* Compatibility mask. */
		switch (argp[idx].type) {
		case ARGT_SINT:
			switch (mask & ARGT_MASK) {
			case ARGT_UINT: argp[idx].type = mask & ARGT_MASK; break;
			case ARGT_TIME: argp[idx].type = mask & ARGT_MASK; break;
			case ARGT_SIZE: argp[idx].type = mask & ARGT_MASK; break;
			}
			break;
		}

		/* Check for type of argument. */
		if ((mask & ARGT_MASK) != argp[idx].type) {
			const char *msg = lua_pushfstring(L, "'%s' expected, got '%s'",
			                                  arg_type_names[(mask & ARGT_MASK)],
			                                  arg_type_names[argp[idx].type & ARGT_MASK]);
			WILL_LJMP(luaL_argerror(L, first + idx, msg));
		}

		/* Next argument. */
		mask >>= ARGT_BITS;
		idx++;
	}
}

/*
 * The following functions are used to make correspondance between the the
 * executed lua pointer and the "struct hlua *" that contain the context.
 * They run with the tree head "hlua_ctx", they just perform lookup in the
 * tree.
 *
 *  - hlua_gethlua : return the hlua context associated with an lua_State.
 *  - hlua_delhlua : remove the association between hlua context and lua_state.
 *  - hlua_sethlua : create the association between hlua context and lua_state.
 */
static inline struct hlua *hlua_gethlua(lua_State *L)
{
	struct ebpt_node *node;

	node = ebpt_lookup(&hlua_ctx, L);
	if (!node)
		return NULL;
	return ebpt_entry(node, struct hlua, node);
}
static inline void hlua_delhlua(struct hlua *hlua)
{
	if (hlua->node.key)
		ebpt_delete(&hlua->node);
}
static inline void hlua_sethlua(struct hlua *hlua)
{
	hlua->node.key = hlua->T;
	ebpt_insert(&hlua_ctx, &hlua->node);
}

/* This function just ensure that the yield will be always
 * returned with a timeout and permit to set some flags
 */
__LJMP void hlua_yieldk(lua_State *L, int nresults, int ctx,
                        lua_KFunction k, int timeout, unsigned int flags)
{
	struct hlua *hlua = hlua_gethlua(L);

	/* Set the wake timeout. If timeout is required, we set
	 * the expiration time.
	 */
	hlua->wake_time = tick_first(timeout, hlua->expire);

	hlua->flags |= flags;

	/* Process the yield. */
	WILL_LJMP(lua_yieldk(L, nresults, ctx, k));
}

/* This function initialises the Lua environment stored in the session.
 * It must be called at the start of the session. This function creates
 * an LUA coroutine. It can not be use to crete the main LUA context.
 */
int hlua_ctx_init(struct hlua *lua, struct task *task)
{
	lua->Mref = LUA_REFNIL;
	lua->flags = 0;
	LIST_INIT(&lua->com);
	lua->T = lua_newthread(gL.T);
	if (!lua->T) {
		lua->Tref = LUA_REFNIL;
		return 0;
	}
	hlua_sethlua(lua);
	lua->Tref = luaL_ref(gL.T, LUA_REGISTRYINDEX);
	lua->task = task;
	return 1;
}

/* Used to destroy the Lua coroutine when the attached session or task
 * is destroyed. The destroy also the memory context. The struct "lua"
 * is not freed.
 */
void hlua_ctx_destroy(struct hlua *lua)
{
	if (!lua->T)
		return;

	/* Remove context. */
	hlua_delhlua(lua);

	/* Purge all the pending signals. */
	hlua_com_purge(lua);

	/* The thread is garbage collected by Lua. */
	luaL_unref(lua->T, LUA_REGISTRYINDEX, lua->Mref);
	luaL_unref(gL.T, LUA_REGISTRYINDEX, lua->Tref);
}

/* This function is used to restore the Lua context when a coroutine
 * fails. This function copy the common memory between old coroutine
 * and the new coroutine. The old coroutine is destroyed, and its
 * replaced by the new coroutine.
 * If the flag "keep_msg" is set, the last entry of the old is assumed
 * as string error message and it is copied in the new stack.
 */
static int hlua_ctx_renew(struct hlua *lua, int keep_msg)
{
	lua_State *T;
	int new_ref;

	/* Renew the main LUA stack doesn't have sense. */
	if (lua == &gL)
		return 0;

	/* Remove context. */
	hlua_delhlua(lua);

	/* New Lua coroutine. */
	T = lua_newthread(gL.T);
	if (!T)
		return 0;

	/* Copy last error message. */
	if (keep_msg)
		lua_xmove(lua->T, T, 1);

	/* Copy data between the coroutines. */
	lua_rawgeti(lua->T, LUA_REGISTRYINDEX, lua->Mref);
	lua_xmove(lua->T, T, 1);
	new_ref = luaL_ref(T, LUA_REGISTRYINDEX); /* Valur poped. */

	/* Destroy old data. */
	luaL_unref(lua->T, LUA_REGISTRYINDEX, lua->Mref);

	/* The thread is garbage collected by Lua. */
	luaL_unref(gL.T, LUA_REGISTRYINDEX, lua->Tref);

	/* Fill the struct with the new coroutine values. */
	lua->Mref = new_ref;
	lua->T = T;
	lua->Tref = luaL_ref(gL.T, LUA_REGISTRYINDEX);

	/* Set context. */
	hlua_sethlua(lua);

	return 1;
}

void hlua_hook(lua_State *L, lua_Debug *ar)
{
	struct hlua *hlua = hlua_gethlua(L);

	/* Lua cannot yield when its returning from a function,
	 * so, we can fix the interrupt hook to 1 instruction,
	 * expecting that the function is finnished.
	 */
	if (lua_gethookmask(L) & LUA_MASKRET) {
		lua_sethook(hlua->T, hlua_hook, LUA_MASKCOUNT, 1);
		return;
	}

	/* restore the interrupt condition. */
	lua_sethook(hlua->T, hlua_hook, LUA_MASKCOUNT, hlua_nb_instruction);

	/* If we interrupt the Lua processing in yieldable state, we yield.
	 * If the state is not yieldable, trying yield causes an error.
	 */
	if (lua_isyieldable(L))
		WILL_LJMP(hlua_yieldk(L, 0, 0, NULL, TICK_ETERNITY, HLUA_CTRLYIELD));

	/* If we cannot yield, check the timeout. */
	if (tick_is_expired(hlua->expire, now_ms)) {
		lua_pushfstring(L, "execution timeout");
		WILL_LJMP(lua_error(L));
	}

	/* Try to interrupt the process at the end of the current
	 * unyieldable function.
	 */
	lua_sethook(hlua->T, hlua_hook, LUA_MASKRET|LUA_MASKCOUNT, hlua_nb_instruction);
}

/* This function start or resumes the Lua stack execution. If the flag
 * "yield_allowed" if no set and the  LUA stack execution returns a yield
 * The function return an error.
 *
 * The function can returns 4 values:
 *  - HLUA_E_OK     : The execution is terminated without any errors.
 *  - HLUA_E_AGAIN  : The execution must continue at the next associated
 *                    task wakeup.
 *  - HLUA_E_ERRMSG : An error has occured, an error message is set in
 *                    the top of the stack.
 *  - HLUA_E_ERR    : An error has occured without error message.
 *
 * If an error occured, the stack is renewed and it is ready to run new
 * LUA code.
 */
static enum hlua_exec hlua_ctx_resume(struct hlua *lua, int yield_allowed)
{
	int ret;
	const char *msg;

	HLUA_SET_RUN(lua);

	/* If we want to resume the task, then check first the execution timeout.
	 * if it is reached, we can interrupt the Lua processing.
	 */
	if (tick_is_expired(lua->expire, now_ms))
		goto timeout_reached;

resume_execution:

	/* This hook interrupts the Lua processing each 'hlua_nb_instruction'
	 * instructions. it is used for preventing infinite loops.
	 */
	lua_sethook(lua->T, hlua_hook, LUA_MASKCOUNT, hlua_nb_instruction);

	/* Remove all flags except the running flags. */
	lua->flags = HLUA_RUN;

	/* Call the function. */
	ret = lua_resume(lua->T, gL.T, lua->nargs);
	switch (ret) {

	case LUA_OK:
		ret = HLUA_E_OK;
		break;

	case LUA_YIELD:
		/* Check if the execution timeout is expired. It it is the case, we
		 * break the Lua execution.
		 */
		if (tick_is_expired(lua->expire, now_ms)) {

timeout_reached:

			lua_settop(lua->T, 0); /* Empty the stack. */
			if (!lua_checkstack(lua->T, 1)) {
				ret = HLUA_E_ERR;
				break;
			}
			lua_pushfstring(lua->T, "execution timeout");
			ret = HLUA_E_ERRMSG;
			break;
		}
		/* Process the forced yield. if the general yield is not allowed or
		 * if no task were associated this the current Lua execution
		 * coroutine, we resume the execution. Else we want to return in the
		 * scheduler and we want to be waked up again, to continue the
		 * current Lua execution. So we schedule our own task.
		 */
		if (HLUA_IS_CTRLYIELDING(lua)) {
			if (!yield_allowed || !lua->task)
				goto resume_execution;
			task_wakeup(lua->task, TASK_WOKEN_MSG);
		}
		if (!yield_allowed) {
			lua_settop(lua->T, 0); /* Empty the stack. */
			if (!lua_checkstack(lua->T, 1)) {
				ret = HLUA_E_ERR;
				break;
			}
			lua_pushfstring(lua->T, "yield not allowed");
			ret = HLUA_E_ERRMSG;
			break;
		}
		ret = HLUA_E_AGAIN;
		break;

	case LUA_ERRRUN:
		lua->wake_time = TICK_ETERNITY;
		if (!lua_checkstack(lua->T, 1)) {
			ret = HLUA_E_ERR;
			break;
		}
		msg = lua_tostring(lua->T, -1);
		lua_settop(lua->T, 0); /* Empty the stack. */
		lua_pop(lua->T, 1);
		if (msg)
			lua_pushfstring(lua->T, "runtime error: %s", msg);
		else
			lua_pushfstring(lua->T, "unknown runtime error");
		ret = HLUA_E_ERRMSG;
		break;

	case LUA_ERRMEM:
		lua->wake_time = TICK_ETERNITY;
		lua_settop(lua->T, 0); /* Empty the stack. */
		if (!lua_checkstack(lua->T, 1)) {
			ret = HLUA_E_ERR;
			break;
		}
		lua_pushfstring(lua->T, "out of memory error");
		ret = HLUA_E_ERRMSG;
		break;

	case LUA_ERRERR:
		lua->wake_time = TICK_ETERNITY;
		if (!lua_checkstack(lua->T, 1)) {
			ret = HLUA_E_ERR;
			break;
		}
		msg = lua_tostring(lua->T, -1);
		lua_settop(lua->T, 0); /* Empty the stack. */
		lua_pop(lua->T, 1);
		if (msg)
			lua_pushfstring(lua->T, "message handler error: %s", msg);
		else
			lua_pushfstring(lua->T, "message handler error");
		ret = HLUA_E_ERRMSG;
		break;

	default:
		lua->wake_time = TICK_ETERNITY;
		lua_settop(lua->T, 0); /* Empty the stack. */
		if (!lua_checkstack(lua->T, 1)) {
			ret = HLUA_E_ERR;
			break;
		}
		lua_pushfstring(lua->T, "unknonwn error");
		ret = HLUA_E_ERRMSG;
		break;
	}

	switch (ret) {
	case HLUA_E_AGAIN:
		break;

	case HLUA_E_ERRMSG:
		hlua_com_purge(lua);
		hlua_ctx_renew(lua, 1);
		HLUA_CLR_RUN(lua);
		break;

	case HLUA_E_ERR:
		HLUA_CLR_RUN(lua);
		hlua_com_purge(lua);
		hlua_ctx_renew(lua, 0);
		break;

	case HLUA_E_OK:
		HLUA_CLR_RUN(lua);
		hlua_com_purge(lua);
		break;
	}

	return ret;
}

/* This function is an LUA binding. It provides a function
 * for deleting ACL from a referenced ACL file.
 */
__LJMP static int hlua_del_acl(lua_State *L)
{
	const char *name;
	const char *key;
	struct pat_ref *ref;

	MAY_LJMP(check_args(L, 2, "del_acl"));

	name = MAY_LJMP(luaL_checkstring(L, 1));
	key = MAY_LJMP(luaL_checkstring(L, 2));

	ref = pat_ref_lookup(name);
	if (!ref)
		WILL_LJMP(luaL_error(L, "'del_acl': unkown acl file '%s'", name));

	pat_ref_delete(ref, key);
	return 0;
}

/* This function is an LUA binding. It provides a function
 * for deleting map entry from a referenced map file.
 */
static int hlua_del_map(lua_State *L)
{
	const char *name;
	const char *key;
	struct pat_ref *ref;

	MAY_LJMP(check_args(L, 2, "del_map"));

	name = MAY_LJMP(luaL_checkstring(L, 1));
	key = MAY_LJMP(luaL_checkstring(L, 2));

	ref = pat_ref_lookup(name);
	if (!ref)
		WILL_LJMP(luaL_error(L, "'del_map': unkown acl file '%s'", name));

	pat_ref_delete(ref, key);
	return 0;
}

/* This function is an LUA binding. It provides a function
 * for adding ACL pattern from a referenced ACL file.
 */
static int hlua_add_acl(lua_State *L)
{
	const char *name;
	const char *key;
	struct pat_ref *ref;

	MAY_LJMP(check_args(L, 2, "add_acl"));

	name = MAY_LJMP(luaL_checkstring(L, 1));
	key = MAY_LJMP(luaL_checkstring(L, 2));

	ref = pat_ref_lookup(name);
	if (!ref)
		WILL_LJMP(luaL_error(L, "'add_acl': unkown acl file '%s'", name));

	if (pat_ref_find_elt(ref, key) == NULL)
		pat_ref_add(ref, key, NULL, NULL);
	return 0;
}

/* This function is an LUA binding. It provides a function
 * for setting map pattern and sample from a referenced map
 * file.
 */
static int hlua_set_map(lua_State *L)
{
	const char *name;
	const char *key;
	const char *value;
	struct pat_ref *ref;

	MAY_LJMP(check_args(L, 3, "set_map"));

	name = MAY_LJMP(luaL_checkstring(L, 1));
	key = MAY_LJMP(luaL_checkstring(L, 2));
	value = MAY_LJMP(luaL_checkstring(L, 3));

	ref = pat_ref_lookup(name);
	if (!ref)
		WILL_LJMP(luaL_error(L, "'set_map': unkown map file '%s'", name));

	if (pat_ref_find_elt(ref, key) != NULL)
		pat_ref_set(ref, key, value, NULL);
	else
		pat_ref_add(ref, key, value, NULL);
	return 0;
}

/* A class is a lot of memory that contain data. This data can be a table,
 * an integer or user data. This data is associated with a metatable. This
 * metatable have an original version registred in the global context with
 * the name of the object (_G[<name>] = <metable> ).
 *
 * A metable is a table that modify the standard behavior of a standard
 * access to the associated data. The entries of this new metatable are
 * defined as is:
 *
 * http://lua-users.org/wiki/MetatableEvents
 *
 *    __index
 *
 * we access an absent field in a table, the result is nil. This is
 * true, but it is not the whole truth. Actually, such access triggers
 * the interpreter to look for an __index metamethod: If there is no
 * such method, as usually happens, then the access results in nil;
 * otherwise, the metamethod will provide the result.
 *
 * Control 'prototype' inheritance. When accessing "myTable[key]" and
 * the key does not appear in the table, but the metatable has an __index
 * property:
 *
 * - if the value is a function, the function is called, passing in the
 *   table and the key; the return value of that function is returned as
 *   the result.
 *
 * - if the value is another table, the value of the key in that table is
 *   asked for and returned (and if it doesn't exist in that table, but that
 *   table's metatable has an __index property, then it continues on up)
 *
 * - Use "rawget(myTable,key)" to skip this metamethod.
 *
 * http://www.lua.org/pil/13.4.1.html
 *
 *    __newindex
 *
 * Like __index, but control property assignment.
 *
 *    __mode - Control weak references. A string value with one or both
 *             of the characters 'k' and 'v' which specifies that the the
 *             keys and/or values in the table are weak references.
 *
 *    __call - Treat a table like a function. When a table is followed by
 *             parenthesis such as "myTable( 'foo' )" and the metatable has
 *             a __call key pointing to a function, that function is invoked
 *             (passing any specified arguments) and the return value is
 *             returned.
 *
 *    __metatable - Hide the metatable. When "getmetatable( myTable )" is
 *                  called, if the metatable for myTable has a __metatable
 *                  key, the value of that key is returned instead of the
 *                  actual metatable.
 *
 *    __tostring - Control string representation. When the builtin
 *                 "tostring( myTable )" function is called, if the metatable
 *                 for myTable has a __tostring property set to a function,
 *                 that function is invoked (passing myTable to it) and the
 *                 return value is used as the string representation.
 *
 *    __len - Control table length. When the table length is requested using
 *            the length operator ( '#' ), if the metatable for myTable has
 *            a __len key pointing to a function, that function is invoked
 *            (passing myTable to it) and the return value used as the value
 *            of "#myTable".
 *
 *    __gc - Userdata finalizer code. When userdata is set to be garbage
 *           collected, if the metatable has a __gc field pointing to a
 *           function, that function is first invoked, passing the userdata
 *           to it. The __gc metamethod is not called for tables.
 *           (See http://lua-users.org/lists/lua-l/2006-11/msg00508.html)
 *
 * Special metamethods for redefining standard operators:
 * http://www.lua.org/pil/13.1.html
 *
 *    __add    "+"
 *    __sub    "-"
 *    __mul    "*"
 *    __div    "/"
 *    __unm    "!"
 *    __pow    "^"
 *    __concat ".."
 *
 * Special methods for redfining standar relations
 * http://www.lua.org/pil/13.2.html
 *
 *    __eq "=="
 *    __lt "<"
 *    __le "<="
 */

/*
 *
 *
 * Class Socket
 *
 *
 */

__LJMP static struct hlua_socket *hlua_checksocket(lua_State *L, int ud)
{
	return (struct hlua_socket *)MAY_LJMP(hlua_checkudata(L, ud, class_socket_ref));
}

/* This function is the handler called for each I/O on the established
 * connection. It is used for notify space avalaible to send or data
 * received.
 */
static void hlua_socket_handler(struct stream_interface *si)
{
	struct appctx *appctx = objt_appctx(si->end);
	struct connection *c = objt_conn(si->ib->cons->end);

	/* Wakeup the main session if the client connection is closed. */
	if (!c || channel_output_closed(si->ib) || channel_input_closed(si->ob)) {
		if (appctx->ctx.hlua.socket) {
			appctx->ctx.hlua.socket->s = NULL;
			appctx->ctx.hlua.socket = NULL;
		}
		si_shutw(si);
		si_shutr(si);
		si->ib->flags |= CF_READ_NULL;
		hlua_com_wake(&appctx->ctx.hlua.wake_on_read);
		hlua_com_wake(&appctx->ctx.hlua.wake_on_write);
		return;
	}

	if (!(c->flags & CO_FL_CONNECTED))
		return;

	/* This function is called after the connect. */
	appctx->ctx.hlua.connected = 1;

	/* Wake the tasks which wants to write if the buffer have avalaible space. */
	if (channel_may_recv(si->ob))
		hlua_com_wake(&appctx->ctx.hlua.wake_on_write);

	/* Wake the tasks which wants to read if the buffer contains data. */
	if (channel_is_empty(si->ib))
		hlua_com_wake(&appctx->ctx.hlua.wake_on_read);
}

/* This function is called when the "struct session" is destroyed.
 * Remove the link from the object to this session.
 * Wake all the pending signals.
 */
static void hlua_socket_release(struct stream_interface *si)
{
	struct appctx *appctx = objt_appctx(si->end);

	/* Remove my link in the original object. */
	if (appctx->ctx.hlua.socket)
		appctx->ctx.hlua.socket->s = NULL;

	/* Wake all the task waiting for me. */
	hlua_com_wake(&appctx->ctx.hlua.wake_on_read);
	hlua_com_wake(&appctx->ctx.hlua.wake_on_write);
}

/* If the garbage collectio of the object is launch, nobody
 * uses this object. If the session does not exists, just quit.
 * Send the shutdown signal to the session. In some cases,
 * pending signal can rest in the read and write lists. destroy
 * it.
 */
__LJMP static int hlua_socket_gc(lua_State *L)
{
	struct hlua_socket *socket;
	struct appctx *appctx;

	MAY_LJMP(check_args(L, 1, "__gc"));

	socket = MAY_LJMP(hlua_checksocket(L, 1));
	if (!socket->s)
		return 0;

	/* Remove all reference between the Lua stack and the coroutine session. */
	appctx = objt_appctx(socket->s->si[0].end);
	session_shutdown(socket->s, SN_ERR_KILLED);
	socket->s = NULL;
	appctx->ctx.hlua.socket = NULL;

	return 0;
}

/* The close function send shutdown signal and break the
 * links between the session and the object.
 */
__LJMP static int hlua_socket_close(lua_State *L)
{
	struct hlua_socket *socket;
	struct appctx *appctx;

	MAY_LJMP(check_args(L, 1, "close"));

	socket = MAY_LJMP(hlua_checksocket(L, 1));
	if (!socket->s)
		return 0;

	/* Close the session and remove the associated stop task. */
	session_shutdown(socket->s, SN_ERR_KILLED);
	appctx = objt_appctx(socket->s->si[0].end);
	appctx->ctx.hlua.socket = NULL;
	socket->s = NULL;

	return 0;
}

/* This Lua function assumes that the stack contain three parameters.
 *  1 - USERDATA containing a struct socket
 *  2 - INTEGER with values of the macro defined below
 *      If the integer is -1, we must read at most one line.
 *      If the integer is -2, we ust read all the data until the
 *      end of the stream.
 *      If the integer is positive value, we must read a number of
 *      bytes corresponding to this value.
 */
#define HLSR_READ_LINE (-1)
#define HLSR_READ_ALL (-2)
__LJMP static int hlua_socket_receive_yield(struct lua_State *L, int status, lua_KContext ctx)
{
	struct hlua_socket *socket = MAY_LJMP(hlua_checksocket(L, 1));
	int wanted = lua_tointeger(L, 2);
	struct hlua *hlua = hlua_gethlua(L);
	struct appctx *appctx;
	int len;
	int nblk;
	char *blk1;
	int len1;
	char *blk2;
	int len2;

	/* Check if this lua stack is schedulable. */
	if (!hlua || !hlua->task)
		WILL_LJMP(luaL_error(L, "The 'receive' function is only allowed in "
		                      "'frontend', 'backend' or 'task'"));

	/* check for connection closed. If some data where read, return it. */
	if (!socket->s)
		goto connection_closed;

	if (wanted == HLSR_READ_LINE) {

		/* Read line. */
		nblk = bo_getline_nc(socket->s->si[0].ob, &blk1, &len1, &blk2, &len2);
		if (nblk < 0) /* Connection close. */
			goto connection_closed;
		if (nblk == 0) /* No data avalaible. */
			goto connection_empty;
	}

	else if (wanted == HLSR_READ_ALL) {

		/* Read all the available data. */
		nblk = bo_getblk_nc(socket->s->si[0].ob, &blk1, &len1, &blk2, &len2);
		if (nblk < 0) /* Connection close. */
			goto connection_closed;
		if (nblk == 0) /* No data avalaible. */
			goto connection_empty;
	}

	else {

		/* Read a block of data. */
		nblk = bo_getblk_nc(socket->s->si[0].ob, &blk1, &len1, &blk2, &len2);
		if (nblk < 0) /* Connection close. */
			goto connection_closed;
		if (nblk == 0) /* No data avalaible. */
			goto connection_empty;

		if (len1 > wanted) {
			nblk = 1;
			len1 = wanted;
		} if (nblk == 2 && len1 + len2 > wanted)
			len2 = wanted - len1;
	}

	len = len1;

	luaL_addlstring(&socket->b, blk1, len1);
	if (nblk == 2) {
		len += len2;
		luaL_addlstring(&socket->b, blk2, len2);
	}

	/* Consume data. */
	bo_skip(socket->s->si[0].ob, len);

	/* Don't wait anything. */
	si_update(&socket->s->si[0]);

	/* If the pattern reclaim to read all the data
	 * in the connection, got out.
	 */
	if (wanted == HLSR_READ_ALL)
		goto connection_empty;
	else if (wanted >= 0 && len < wanted)
		goto connection_empty;

	/* Return result. */
	luaL_pushresult(&socket->b);
	return 1;

connection_closed:

	/* If the buffer containds data. */
	if (socket->b.n > 0) {
		luaL_pushresult(&socket->b);
		return 1;
	}
	lua_pushnil(L);
	lua_pushstring(L, "connection closed.");
	return 2;

connection_empty:

	appctx = objt_appctx(socket->s->si[0].end);
	if (!hlua_com_new(hlua, &appctx->ctx.hlua.wake_on_read))
		WILL_LJMP(luaL_error(L, "out of memory"));
	WILL_LJMP(hlua_yieldk(L, 0, 0, hlua_socket_receive_yield, TICK_ETERNITY, 0));
	return 0;
}

/* This Lus function gets two parameters. The first one can be string
 * or a number. If the string is "*l", the user require one line. If
 * the string is "*a", the user require all the content of the stream.
 * If the value is a number, the user require a number of bytes equal
 * to the value. The default value is "*l" (a line).
 *
 * This paraeter with a variable type is converted in integer. This
 * integer takes this values:
 *  -1 : read a line
 *  -2 : read all the stream
 *  >0 : amount if bytes.
 *
 * The second parameter is optinal. It contains a string that must be
 * concatenated with the read data.
 */
__LJMP static int hlua_socket_receive(struct lua_State *L)
{
	int wanted = HLSR_READ_LINE;
	const char *pattern;
	int type;
	char *error;
	size_t len;
	struct hlua_socket *socket;

	if (lua_gettop(L) < 1 || lua_gettop(L) > 3)
		WILL_LJMP(luaL_error(L, "The 'receive' function requires between 1 and 3 arguments."));

	socket = MAY_LJMP(hlua_checksocket(L, 1));

	/* check for pattern. */
	if (lua_gettop(L) >= 2) {
		type = lua_type(L, 2);
		if (type == LUA_TSTRING) {
			pattern = lua_tostring(L, 2);
			if (strcmp(pattern, "*a") == 0)
				wanted = HLSR_READ_ALL;
			else if (strcmp(pattern, "*l") == 0)
				wanted = HLSR_READ_LINE;
			else {
				wanted = strtoll(pattern, &error, 10);
				if (*error != '\0')
					WILL_LJMP(luaL_error(L, "Unsupported pattern."));
			}
		}
		else if (type == LUA_TNUMBER) {
			wanted = lua_tointeger(L, 2);
			if (wanted < 0)
				WILL_LJMP(luaL_error(L, "Unsupported size."));
		}
	}

	/* Set pattern. */
	lua_pushinteger(L, wanted);
	lua_replace(L, 2);

	/* init bufffer, and fiil it wih prefix. */
	luaL_buffinit(L, &socket->b);

	/* Check prefix. */
	if (lua_gettop(L) >= 3) {
		if (lua_type(L, 3) != LUA_TSTRING)
			WILL_LJMP(luaL_error(L, "Expect a 'string' for the prefix"));
		pattern = lua_tolstring(L, 3, &len);
		luaL_addlstring(&socket->b, pattern, len);
	}

	return __LJMP(hlua_socket_receive_yield(L, 0, 0));
}

/* Write the Lua input string in the output buffer.
 * This fucntion returns a yield if no space are available.
 */
static int hlua_socket_write_yield(struct lua_State *L,int status, lua_KContext ctx)
{
	struct hlua_socket *socket;
	struct hlua *hlua = hlua_gethlua(L);
	struct appctx *appctx;
	size_t buf_len;
	const char *buf;
	int len;
	int send_len;
	int sent;

	/* Check if this lua stack is schedulable. */
	if (!hlua || !hlua->task)
		WILL_LJMP(luaL_error(L, "The 'write' function is only allowed in "
		                      "'frontend', 'backend' or 'task'"));

	/* Get object */
	socket = MAY_LJMP(hlua_checksocket(L, 1));
	buf = MAY_LJMP(luaL_checklstring(L, 2, &buf_len));
	sent = MAY_LJMP(luaL_checkinteger(L, 3));

	/* Check for connection close. */
	if (!socket->s || channel_output_closed(socket->s->req)) {
		lua_pushinteger(L, -1);
		return 1;
	}

	/* Update the input buffer data. */
	buf += sent;
	send_len = buf_len - sent;

	/* All the data are sent. */
	if (sent >= buf_len)
		return 1; /* Implicitly return the length sent. */

	/* Check for avalaible space. */
	len = buffer_total_space(socket->s->si[0].ib->buf);
	if (len <= 0)
		goto hlua_socket_write_yield_return;

	/* send data */
	if (len < send_len)
		send_len = len;
	len = bi_putblk(socket->s->si[0].ib, buf+sent, send_len);

	/* "Not enough space" (-1), "Buffer too little to contain
	 * the data" (-2) are not expected because the available length
	 * is tested.
	 * Other unknown error are also not expected.
	 */
	if (len <= 0) {
		MAY_LJMP(hlua_socket_close(L));
		lua_pop(L, 1);
		lua_pushinteger(L, -1);
		return 1;
	}

	/* update buffers. */
	si_update(&socket->s->si[0]);
	socket->s->si[0].ib->rex = TICK_ETERNITY;
	socket->s->si[0].ob->wex = TICK_ETERNITY;

	/* Update length sent. */
	lua_pop(L, 1);
	lua_pushinteger(L, sent + len);

	/* All the data buffer is sent ? */
	if (sent + len >= buf_len)
		return 1;

hlua_socket_write_yield_return:
	appctx = objt_appctx(socket->s->si[0].end);
	if (!hlua_com_new(hlua, &appctx->ctx.hlua.wake_on_write))
		WILL_LJMP(luaL_error(L, "out of memory"));
	WILL_LJMP(hlua_yieldk(L, 0, 0, hlua_socket_write_yield, TICK_ETERNITY, 0));
	return 0;
}

/* This function initiate the send of data. It just check the input
 * parameters and push an integer in the Lua stack that contain the
 * amount of data writed in the buffer. This is used by the function
 * "hlua_socket_write_yield" that can yield.
 *
 * The Lua function gets between 3 and 4 parameters. The first one is
 * the associated object. The second is a string buffer. The third is
 * a facultative integer that represents where is the buffer position
 * of the start of the data that can send. The first byte is the
 * position "1". The default value is "1". The fourth argument is a
 * facultative integer that represents where is the buffer position
 * of the end of the data that can send. The default is the last byte.
 */
static int hlua_socket_send(struct lua_State *L)
{
	int i;
	int j;
	const char *buf;
	size_t buf_len;

	/* Check number of arguments. */
	if (lua_gettop(L) < 2 || lua_gettop(L) > 4)
		WILL_LJMP(luaL_error(L, "'send' needs between 2 and 4 arguments"));

	/* Get the string. */
	buf = MAY_LJMP(luaL_checklstring(L, 2, &buf_len));

	/* Get and check j. */
	if (lua_gettop(L) == 4) {
		j = MAY_LJMP(luaL_checkinteger(L, 4));
		if (j < 0)
			j = buf_len + j + 1;
		if (j > buf_len)
			j = buf_len + 1;
		lua_pop(L, 1);
	}
	else
		j = buf_len;

	/* Get and check i. */
	if (lua_gettop(L) == 3) {
		i = MAY_LJMP(luaL_checkinteger(L, 3));
		if (i < 0)
			i = buf_len + i + 1;
		if (i > buf_len)
			i = buf_len + 1;
		lua_pop(L, 1);
	} else
		i = 1;

	/* Check bth i and j. */
	if (i > j) {
		lua_pushinteger(L, 0);
		return 1;
	}
	if (i == 0 && j == 0) {
		lua_pushinteger(L, 0);
		return 1;
	}
	if (i == 0)
		i = 1;
	if (j == 0)
		j = 1;

	/* Pop the string. */
	lua_pop(L, 1);

	/* Update the buffer length. */
	buf += i - 1;
	buf_len = j - i + 1;
	lua_pushlstring(L, buf, buf_len);

	/* This unsigned is used to remember the amount of sent data. */
	lua_pushinteger(L, 0);

	return MAY_LJMP(hlua_socket_write_yield(L, 0, 0));
}

#define SOCKET_INFO_EXPANDED_FORM "[0000:0000:0000:0000:0000:0000:0000:0000]:12345"
static char _socket_info_expanded_form[] = SOCKET_INFO_EXPANDED_FORM;
#define SOCKET_INFO_MAX_LEN (sizeof(_socket_info_expanded_form))
__LJMP static inline int hlua_socket_info(struct lua_State *L, struct sockaddr_storage *addr)
{
	static char buffer[SOCKET_INFO_MAX_LEN];
	int ret;
	int len;
	char *p;

	ret = addr_to_str(addr, buffer+1, SOCKET_INFO_MAX_LEN-1);
	if (ret <= 0) {
		lua_pushnil(L);
		return 1;
	}

	if (ret == AF_UNIX) {
		lua_pushstring(L, buffer+1);
		return 1;
	}
	else if (ret == AF_INET6) {
		buffer[0] = '[';
		len = strlen(buffer);
		buffer[len] = ']';
		len++;
		buffer[len] = ':';
		len++;
		p = buffer;
	}
	else if (ret == AF_INET) {
		p = buffer + 1;
		len = strlen(p);
		p[len] = ':';
		len++;
	}
	else {
		lua_pushnil(L);
		return 1;
	}

	if (port_to_str(addr, p + len, SOCKET_INFO_MAX_LEN-1 - len) <= 0) {
		lua_pushnil(L);
		return 1;
	}

	lua_pushstring(L, p);
	return 1;
}

/* Returns information about the peer of the connection. */
__LJMP static int hlua_socket_getpeername(struct lua_State *L)
{
	struct hlua_socket *socket;
	struct connection *conn;

	MAY_LJMP(check_args(L, 1, "getpeername"));

	socket = MAY_LJMP(hlua_checksocket(L, 1));

	/* Check if the tcp object is avalaible. */
	if (!socket->s) {
		lua_pushnil(L);
		return 1;
	}

	conn = objt_conn(socket->s->si[1].end);
	if (!conn) {
		lua_pushnil(L);
		return 1;
	}

	if (!(conn->flags & CO_FL_ADDR_TO_SET)) {
		unsigned int salen = sizeof(conn->addr.to);
		if (getpeername(conn->t.sock.fd, (struct sockaddr *)&conn->addr.to, &salen) == -1) {
			lua_pushnil(L);
			return 1;
		}
		conn->flags |= CO_FL_ADDR_TO_SET;
	}

	return MAY_LJMP(hlua_socket_info(L, &conn->addr.to));
}

/* Returns information about my connection side. */
static int hlua_socket_getsockname(struct lua_State *L)
{
	struct hlua_socket *socket;
	struct connection *conn;

	MAY_LJMP(check_args(L, 1, "getsockname"));

	socket = MAY_LJMP(hlua_checksocket(L, 1));

	/* Check if the tcp object is avalaible. */
	if (!socket->s) {
		lua_pushnil(L);
		return 1;
	}

	conn = objt_conn(socket->s->si[1].end);
	if (!conn) {
		lua_pushnil(L);
		return 1;
	}

	if (!(conn->flags & CO_FL_ADDR_FROM_SET)) {
		unsigned int salen = sizeof(conn->addr.from);
		if (getsockname(conn->t.sock.fd, (struct sockaddr *)&conn->addr.from, &salen) == -1) {
			lua_pushnil(L);
			return 1;
		}
		conn->flags |= CO_FL_ADDR_FROM_SET;
	}

	return hlua_socket_info(L, &conn->addr.from);
}

/* This struct define the applet. */
static struct si_applet update_applet = {
	.obj_type = OBJ_TYPE_APPLET,
	.name = "<LUA_TCP>",
	.fct = hlua_socket_handler,
	.release = hlua_socket_release,
};

__LJMP static int hlua_socket_connect_yield(struct lua_State *L, int status, lua_KContext ctx)
{
	struct hlua_socket *socket = MAY_LJMP(hlua_checksocket(L, 1));
	struct hlua *hlua = hlua_gethlua(L);
	struct appctx *appctx;

	/* Check for connection close. */
	if (!hlua || !socket->s || channel_output_closed(socket->s->req)) {
		lua_pushnil(L);
		lua_pushstring(L, "Can't connect");
		return 2;
	}

	appctx = objt_appctx(socket->s->si[0].end);

	/* Check for connection established. */
	if (appctx->ctx.hlua.connected) {
		lua_pushinteger(L, 1);
		return 1;
	}

	if (!hlua_com_new(hlua, &appctx->ctx.hlua.wake_on_write))
		WILL_LJMP(luaL_error(L, "out of memory error"));
	WILL_LJMP(hlua_yieldk(L, 0, 0, hlua_socket_connect_yield, TICK_ETERNITY, 0));
	return 0;
}

/* This function fail or initite the connection. */
__LJMP static int hlua_socket_connect(struct lua_State *L)
{
	struct hlua_socket *socket;
	int port;
	const char *ip;
	struct connection *conn;

	MAY_LJMP(check_args(L, 3, "connect"));

	/* Get args. */
	socket  = MAY_LJMP(hlua_checksocket(L, 1));
	ip      = MAY_LJMP(luaL_checkstring(L, 2));
	port    = MAY_LJMP(luaL_checkinteger(L, 3));

	conn = si_alloc_conn(socket->s->req->cons, 0);
	if (!conn)
		WILL_LJMP(luaL_error(L, "connect: internal error"));

	/* Parse ip address. */
	conn->addr.to.ss_family = AF_UNSPEC;
	if (!str2ip2(ip, &conn->addr.to, 0))
		WILL_LJMP(luaL_error(L, "connect: cannot parse ip address '%s'", ip));

	/* Set port. */
	if (conn->addr.to.ss_family == AF_INET)
		((struct sockaddr_in *)&conn->addr.to)->sin_port = htons(port);
	else if (conn->addr.to.ss_family == AF_INET6)
		((struct sockaddr_in6 *)&conn->addr.to)->sin6_port = htons(port);

	/* it is important not to call the wakeup function directly but to
	 * pass through task_wakeup(), because this one knows how to apply
	 * priorities to tasks.
	 */
	task_wakeup(socket->s->task, TASK_WOKEN_INIT);

	WILL_LJMP(hlua_yieldk(L, 0, 0, hlua_socket_connect_yield, TICK_ETERNITY, 0));

	return 0;
}

#ifdef USE_OPENSSL
__LJMP static int hlua_socket_connect_ssl(struct lua_State *L)
{
	struct hlua_socket *socket;

	MAY_LJMP(check_args(L, 3, "connect_ssl"));
	socket  = MAY_LJMP(hlua_checksocket(L, 1));
	socket->s->target = &socket_ssl.obj_type;
	return MAY_LJMP(hlua_socket_connect(L));
}
#endif

__LJMP static int hlua_socket_setoption(struct lua_State *L)
{
	return 0;
}

__LJMP static int hlua_socket_settimeout(struct lua_State *L)
{
	struct hlua_socket *socket;
	int tmout;

	MAY_LJMP(check_args(L, 2, "settimeout"));

	socket = MAY_LJMP(hlua_checksocket(L, 1));
	tmout = MAY_LJMP(luaL_checkinteger(L, 2)) * 1000;

	socket->s->req->rto = tmout;
	socket->s->req->wto = tmout;
	socket->s->rep->rto = tmout;
	socket->s->rep->wto = tmout;

	return 0;
}

__LJMP static int hlua_socket_new(lua_State *L)
{
	struct hlua_socket *socket;
	struct appctx *appctx;

	/* Check stack size. */
	if (!lua_checkstack(L, 2)) {
		hlua_pusherror(L, "socket: full stack");
		goto out_fail_conf;
	}

	socket = MAY_LJMP(lua_newuserdata(L, sizeof(*socket)));
	memset(socket, 0, sizeof(*socket));

	/* Pop a class session metatable and affect it to the userdata. */
	lua_rawgeti(L, LUA_REGISTRYINDEX, class_socket_ref);
	lua_setmetatable(L, -2);

	/*
	 *
	 * Get memory for the request.
	 *
	 */

	socket->s = pool_alloc2(pool2_session);
	if (!socket->s) {
		hlua_pusherror(L, "socket: out of memory");
		goto out_fail_conf;
	}

	socket->s->task = task_new();
	if (!socket->s->task) {
		hlua_pusherror(L, "socket: out of memory");
		goto out_free_session;
	}

	socket->s->req = pool_alloc2(pool2_channel);
	if (!socket->s->req) {
		hlua_pusherror(L, "socket: out of memory");
		goto out_fail_req;
	}

	socket->s->req->buf = pool_alloc2(pool2_buffer);
	if (!socket->s->req->buf) {
		hlua_pusherror(L, "socket: out of memory");
		goto out_fail_req_buf;
	}

	socket->s->rep = pool_alloc2(pool2_channel);
	if (!socket->s->rep) {
		hlua_pusherror(L, "socket: out of memory");
		goto out_fail_rep;
	}

	socket->s->rep->buf = pool_alloc2(pool2_buffer);
	if (!socket->s->rep->buf) {
		hlua_pusherror(L, "socket: out of memory");
		goto out_fail_rep_buf;
	}

	/* Configura empty Lua for the session. */
	socket->s->hlua.T = NULL;
	socket->s->hlua.Tref = LUA_REFNIL;
	socket->s->hlua.Mref = LUA_REFNIL;
	socket->s->hlua.nargs = 0;
	socket->s->hlua.flags = 0;
	LIST_INIT(&socket->s->hlua.com);

	/* session initialisation. */
	session_init_srv_conn(socket->s);

	/*
	 *
	 * Configure the associated task.
	 *
	 */

	/* This is the dedicated function to process the session. This function
	 * is able to establish the conection, process the timeouts, etc ...
	 */
	socket->s->task->process = process_session;

	/* Back reference to session. This is used by process_session(). */
	socket->s->task->context = socket->s;

	/* The priority of the task is normal. */
	socket->s->task->nice = 0;

	/* Init the next run to eternity. Later in this function, this task is
	 * waked.
	 */
	socket->s->task->expire = TICK_ETERNITY;

	/*
	 *
	 * Initialize the attached buffers
	 *
	 */
	socket->s->req->buf->size = global.tune.bufsize;
	socket->s->rep->buf->size = global.tune.bufsize;

	/*
	 *
	 * Initialize channels.
	 *
	 */

	/* This function reset the struct. It must be called
	 * before the configuration.
	 */
	channel_init(socket->s->req);
	channel_init(socket->s->rep);

	socket->s->req->prod = &socket->s->si[0];
	socket->s->req->cons = &socket->s->si[1];

	socket->s->rep->prod = &socket->s->si[1];
	socket->s->rep->cons = &socket->s->si[0];

	socket->s->si[0].ib = socket->s->req;
	socket->s->si[0].ob = socket->s->rep;

	socket->s->si[1].ib = socket->s->rep;
	socket->s->si[1].ob = socket->s->req;

	socket->s->req->analysers = 0;
	socket->s->req->rto = socket_proxy.timeout.client;
	socket->s->req->wto = socket_proxy.timeout.server;
	socket->s->req->rex = TICK_ETERNITY;
	socket->s->req->wex = TICK_ETERNITY;
	socket->s->req->analyse_exp = TICK_ETERNITY;

	socket->s->rep->analysers = 0;
	socket->s->rep->rto = socket_proxy.timeout.server;
	socket->s->rep->wto = socket_proxy.timeout.client;
	socket->s->rep->rex = TICK_ETERNITY;
	socket->s->rep->wex = TICK_ETERNITY;
	socket->s->rep->analyse_exp = TICK_ETERNITY;

	/*
	 *
	 * Configure the session.
	 *
	 */

	/* The session dont have listener. The listener is used with real
	 * proxies.
	 */
	socket->s->listener = NULL;

	/* The flags are initialized to 0. Values are setted later. */
	socket->s->flags = 0;

	/* Assign the configured proxy to the new session. */
	socket->s->be = &socket_proxy;
	socket->s->fe = &socket_proxy;

	/* XXX: Set namy variables */
	socket->s->store_count = 0;
	memset(socket->s->stkctr, 0, sizeof(socket->s->stkctr));

	/* Configure logs. */
	socket->s->logs.logwait = 0;
	socket->s->logs.level = 0;
	socket->s->logs.accept_date = date; /* user-visible date for logging */
	socket->s->logs.tv_accept = now;  /* corrected date for internal use */
	socket->s->do_log = NULL;

	/* Function used if an error is occured. */
	socket->s->srv_error = default_srv_error;

	/* Init the list of buffers. */
	LIST_INIT(&socket->s->buffer_wait);

	/* Dont configure the unique ID. */
	socket->s->uniq_id = 0;
	socket->s->unique_id = NULL;

	/* XXX: ? */
	socket->s->pend_pos = NULL;

	/* XXX: See later. */
	socket->s->txn.sessid = NULL;
	socket->s->txn.srv_cookie = NULL;
	socket->s->txn.cli_cookie = NULL;
	socket->s->txn.uri = NULL;
	socket->s->txn.req.cap = NULL;
	socket->s->txn.rsp.cap = NULL;
	socket->s->txn.hdr_idx.v = NULL;
	socket->s->txn.hdr_idx.size = 0;
	socket->s->txn.hdr_idx.used = 0;

	/* Configure "left" stream interface as applet. This "si" produce
	 * and use the data received from the server. The applet is initialized
	 * and is attached to the stream interface.
	 */

	/* The data producer is already connected. It is the applet. */
	socket->s->req->flags = CF_READ_ATTACHED;

	channel_auto_connect(socket->s->req); /* don't wait to establish connection */
	channel_auto_close(socket->s->req); /* let the producer forward close requests */

	si_reset(&socket->s->si[0], socket->s->task);
	si_set_state(&socket->s->si[0], SI_ST_EST); /* connection established (resource exists) */

	appctx = stream_int_register_handler(&socket->s->si[0], &update_applet);
	if (!appctx)
		goto out_fail_conn1;
	appctx->ctx.hlua.socket = socket;
	appctx->ctx.hlua.connected = 0;
	LIST_INIT(&appctx->ctx.hlua.wake_on_write);
	LIST_INIT(&appctx->ctx.hlua.wake_on_read);

	/* Configure "right" stream interface. this "si" is used to connect
	 * and retrieve data from the server. The connection is initialized
	 * with the "struct server".
	 */
	si_reset(&socket->s->si[1], socket->s->task);
	si_set_state(&socket->s->si[1], SI_ST_INI);
	socket->s->si[1].conn_retries = socket_proxy.conn_retries;

	/* Force destination server. */
	socket->s->flags |= SN_DIRECT | SN_ASSIGNED | SN_ADDR_SET | SN_BE_ASSIGNED;
	socket->s->target = &socket_tcp.obj_type;

	/* This session is added to te lists of alive sessions. */
	LIST_ADDQ(&sessions, &socket->s->list);

	/* XXX: I think that this list is used by stats. */
	LIST_INIT(&socket->s->back_refs);

	/* Update statistics counters. */
	socket_proxy.feconn++; /* beconn will be increased later */
	jobs++;
	totalconn++;

	/* Return yield waiting for connection. */
	return 1;

out_fail_conn1:
	pool_free2(pool2_buffer, socket->s->rep->buf);
out_fail_rep_buf:
	pool_free2(pool2_channel, socket->s->rep);
out_fail_rep:
	pool_free2(pool2_buffer, socket->s->req->buf);
out_fail_req_buf:
	pool_free2(pool2_channel, socket->s->req);
out_fail_req:
	task_free(socket->s->task);
out_free_session:
	pool_free2(pool2_session, socket->s);
out_fail_conf:
	WILL_LJMP(lua_error(L));
	return 0;
}

/*
 *
 *
 * Class Channel
 *
 *
 */

/* Returns the struct hlua_channel join to the class channel in the
 * stack entry "ud" or throws an argument error.
 */
__LJMP static struct hlua_channel *hlua_checkchannel(lua_State *L, int ud)
{
	return (struct hlua_channel *)MAY_LJMP(hlua_checkudata(L, ud, class_channel_ref));
}

/* Creates new channel object and put it on the top of the stack.
 * If the stask does not have a free slots, the function fails
 * and returns 0;
 */
static int hlua_channel_new(lua_State *L, struct session *s, struct channel *channel)
{
	struct hlua_channel *chn;

	/* Check stack size. */
	if (!lua_checkstack(L, 2))
		return 0;

	/* NOTE: The allocation never fails. The failure
	 * throw an error, and the function never returns.
	 */
	chn = lua_newuserdata(L, sizeof(*chn));
	chn->chn = channel;
	chn->s = s;

	/* Pop a class sesison metatable and affect it to the userdata. */
	lua_rawgeti(L, LUA_REGISTRYINDEX, class_channel_ref);
	lua_setmetatable(L, -2);

	return 1;
}

/* Duplicate all the data present in the input channel and put it
 * in a string LUA variables. Returns -1 and push a nil value in
 * the stack if the channel is closed and all the data are consumed,
 * returns 0 if no data are available, otherwise it returns the length
 * of the builded string.
 */
static inline int _hlua_channel_dup(struct hlua_channel *chn, lua_State *L)
{
	char *blk1;
	char *blk2;
	int len1;
	int len2;
	int ret;
	luaL_Buffer b;

	ret = bi_getblk_nc(chn->chn, &blk1, &len1, &blk2, &len2);
	if (unlikely(ret == 0))
		return 0;

	if (unlikely(ret < 0)) {
		lua_pushnil(L);
		return -1;
	}

	luaL_buffinit(L, &b);
	luaL_addlstring(&b, blk1, len1);
	if (unlikely(ret == 2))
		luaL_addlstring(&b, blk2, len2);
	luaL_pushresult(&b);

	if (unlikely(ret == 2))
		return len1 + len2;
	return len1;
}

/* "_hlua_channel_dup" wrapper. If no data are available, it returns
 * a yield. This function keep the data in the buffer.
 */
__LJMP static int hlua_channel_dup_yield(lua_State *L, int status, lua_KContext ctx)
{
	struct hlua_channel *chn;

	chn = MAY_LJMP(hlua_checkchannel(L, 1));

	if (_hlua_channel_dup(chn, L) == 0)
		WILL_LJMP(hlua_yieldk(L, 0, 0, hlua_channel_dup_yield, TICK_ETERNITY, 0));
	return 1;
}

/* Check arguments for the function "hlua_channel_dup_yield". */
__LJMP static int hlua_channel_dup(lua_State *L)
{
	MAY_LJMP(check_args(L, 1, "dup"));
	MAY_LJMP(hlua_checkchannel(L, 1));
	return MAY_LJMP(hlua_channel_dup_yield(L, 0, 0));
}

/* "_hlua_channel_dup" wrapper. If no data are available, it returns
 * a yield. This function consumes the data in the buffer. It returns
 * a string containing the data or a nil pointer if no data are available
 * and the channel is closed.
 */
__LJMP static int hlua_channel_get_yield(lua_State *L, int status, lua_KContext ctx)
{
	struct hlua_channel *chn;
	int ret;

	chn = MAY_LJMP(hlua_checkchannel(L, 1));

	ret = _hlua_channel_dup(chn, L);
	if (unlikely(ret == 0))
		WILL_LJMP(hlua_yieldk(L, 0, 0, hlua_channel_get_yield, TICK_ETERNITY, 0));

	if (unlikely(ret == -1))
		return 1;

	chn->chn->buf->i -= ret;
	return 1;
}

/* Check arguments for the fucntion "hlua_channel_get_yield". */
__LJMP static int hlua_channel_get(lua_State *L)
{
	MAY_LJMP(check_args(L, 1, "get"));
	MAY_LJMP(hlua_checkchannel(L, 1));
	return MAY_LJMP(hlua_channel_get_yield(L, 0, 0));
}

/* This functions consumes and returns one line. If the channel is closed,
 * and the last data does not contains a final '\n', the data are returned
 * without the final '\n'. When no more data are avalaible, it returns nil
 * value.
 */
__LJMP static int hlua_channel_getline_yield(lua_State *L, int status, lua_KContext ctx)
{
	char *blk1;
	char *blk2;
	int len1;
	int len2;
	int len;
	struct hlua_channel *chn;
	int ret;
	luaL_Buffer b;

	chn = MAY_LJMP(hlua_checkchannel(L, 1));

	ret = bi_getline_nc(chn->chn, &blk1, &len1, &blk2, &len2);
	if (ret == 0)
		WILL_LJMP(hlua_yieldk(L, 0, 0, hlua_channel_getline_yield, TICK_ETERNITY, 0));

	if (ret == -1) {
		lua_pushnil(L);
		return 1;
	}

	luaL_buffinit(L, &b);
	luaL_addlstring(&b, blk1, len1);
	len = len1;
	if (unlikely(ret == 2)) {
		luaL_addlstring(&b, blk2, len2);
		len += len2;
	}
	luaL_pushresult(&b);
	buffer_replace2(chn->chn->buf, chn->chn->buf->p, chn->chn->buf->p + len,  NULL, 0);
	return 1;
}

/* Check arguments for the fucntion "hlua_channel_getline_yield". */
__LJMP static int hlua_channel_getline(lua_State *L)
{
	MAY_LJMP(check_args(L, 1, "getline"));
	MAY_LJMP(hlua_checkchannel(L, 1));
	return MAY_LJMP(hlua_channel_getline_yield(L, 0, 0));
}

/* This function takes a string as input, and append it at the
 * input side of channel. If the data is too big, but a space
 * is probably available after sending some data, the function
 * yield. If the data is bigger than the buffer, or if the
 * channel is closed, it returns -1. otherwise, it returns the
 * amount of data writed.
 */
__LJMP static int hlua_channel_append_yield(lua_State *L, int status, lua_KContext ctx)
{
	struct hlua_channel *chn = MAY_LJMP(hlua_checkchannel(L, 1));
	size_t len;
	const char *str = MAY_LJMP(luaL_checklstring(L, 2, &len));
	int l = MAY_LJMP(luaL_checkinteger(L, 3));
	int ret;
	int max;

	max = channel_recv_limit(chn->chn) - buffer_len(chn->chn->buf);
	if (max > len - l)
		max = len - l;

	ret = bi_putblk(chn->chn, str+l, max);
	if (ret == -2 || ret == -3) {
		lua_pushinteger(L, -1);
		return 1;
	}
	if (ret == -1)
		WILL_LJMP(hlua_yieldk(L, 0, 0, hlua_channel_append_yield, TICK_ETERNITY, 0));
	l += ret;
	lua_pop(L, 1);
	lua_pushinteger(L, l);

	max = channel_recv_limit(chn->chn) - buffer_len(chn->chn->buf);
	if (max == 0 && chn->chn->buf->o == 0) {
		/* There are no space avalaible, and the output buffer is empty.
		 * in this case, we cannot add more data, so we cannot yield,
		 * we return the amount of copyied data.
		 */
		return 1;
	}
	if (l < len)
		WILL_LJMP(hlua_yieldk(L, 0, 0, hlua_channel_append_yield, TICK_ETERNITY, 0));
	return 1;
}

/* just a wrapper of "hlua_channel_append_yield". It returns the length
 * of the writed string, or -1 if the channel is closed or if the
 * buffer size is too little for the data.
 */
__LJMP static int hlua_channel_append(lua_State *L)
{
	size_t len;

	MAY_LJMP(check_args(L, 2, "append"));
	MAY_LJMP(hlua_checkchannel(L, 1));
	MAY_LJMP(luaL_checklstring(L, 2, &len));
	MAY_LJMP(luaL_checkinteger(L, 3));
	lua_pushinteger(L, 0);

	return MAY_LJMP(hlua_channel_append_yield(L, 0, 0));
}

/* just a wrapper of "hlua_channel_append_yield". This wrapper starts
 * his process by cleaning the buffer. The result is a replacement
 * of the current data. It returns the length of the writed string,
 * or -1 if the channel is closed or if the buffer size is too
 * little for the data.
 */
__LJMP static int hlua_channel_set(lua_State *L)
{
	struct hlua_channel *chn;

	MAY_LJMP(check_args(L, 2, "set"));
	chn = MAY_LJMP(hlua_checkchannel(L, 1));
	lua_pushinteger(L, 0);

	chn->chn->buf->i = 0;

	return MAY_LJMP(hlua_channel_append_yield(L, 0, 0));
}

/* Append data in the output side of the buffer. This data is immediatly
 * sent. The fcuntion returns the ammount of data writed. If the buffer
 * cannot contains the data, the function yield. The function returns -1
 * if the channel is closed.
 */
__LJMP static int hlua_channel_send_yield(lua_State *L, int status, lua_KContext ctx)
{
	struct hlua_channel *chn = MAY_LJMP(hlua_checkchannel(L, 1));
	size_t len;
	const char *str = MAY_LJMP(luaL_checklstring(L, 2, &len));
	int l = MAY_LJMP(luaL_checkinteger(L, 3));
	int max;
	struct hlua *hlua = hlua_gethlua(L);

	if (unlikely(channel_output_closed(chn->chn))) {
		lua_pushinteger(L, -1);
		return 1;
	}

	/* Check if the buffer is avalaible because HAProxy doesn't allocate
	 * the request buffer if its not required.
	 */
	if (chn->chn->buf->size == 0) {
		if (!session_alloc_recv_buffer(chn->s, &chn->chn->buf)) {
			chn->chn->prod->flags |= SI_FL_WAIT_ROOM;
			WILL_LJMP(hlua_yieldk(L, 0, 0, hlua_channel_send_yield, TICK_ETERNITY, 0));
		}
	}

	/* the writed data will be immediatly sent, so we can check
	 * the avalaible space without taking in account the reserve.
	 * The reserve is guaranted for the processing of incoming
	 * data, because the buffer will be flushed.
	 */
	max = chn->chn->buf->size - buffer_len(chn->chn->buf);

	/* If there are no space avalaible, and the output buffer is empty.
	 * in this case, we cannot add more data, so we cannot yield,
	 * we return the amount of copyied data.
	 */
	if (max == 0 && chn->chn->buf->o == 0)
		return 1;

	/* Adjust the real required length. */
	if (max > len - l)
		max = len - l;

	/* The buffer avalaible size may be not contiguous. This test
	 * detects a non contiguous buffer and realign it.
	 */
	if (bi_space_for_replace(chn->chn->buf) < max)
		buffer_slow_realign(chn->chn->buf);

	/* Copy input data in the buffer. */
	max = buffer_replace2(chn->chn->buf, chn->chn->buf->p, chn->chn->buf->p, str+l, max);

	/* buffer replace considers that the input part is filled.
	 * so, I must forward these new data in the output part.
	 */
	b_adv(chn->chn->buf, max);

	l += max;
	lua_pop(L, 1);
	lua_pushinteger(L, l);

	/* If there are no space avalaible, and the output buffer is empty.
	 * in this case, we cannot add more data, so we cannot yield,
	 * we return the amount of copyied data.
	 */
	max = chn->chn->buf->size - buffer_len(chn->chn->buf);
	if (max == 0 && chn->chn->buf->o == 0)
		return 1;

	if (l < len) {
		/* If we are waiting for space in the response buffer, we
		 * must set the flag WAKERESWR. This flag required the task
		 * wake up if any activity is detected on the response buffer.
		 */
		if (chn->chn == chn->s->rep)
			HLUA_SET_WAKERESWR(hlua);
		else
			HLUA_SET_WAKEREQWR(hlua);
		WILL_LJMP(hlua_yieldk(L, 0, 0, hlua_channel_send_yield, TICK_ETERNITY, 0));
	}

	return 1;
}

/* Just a wraper of "_hlua_channel_send". This wrapper permits
 * yield the LUA process, and resume it without checking the
 * input arguments.
 */
__LJMP static int hlua_channel_send(lua_State *L)
{
	MAY_LJMP(check_args(L, 2, "send"));
	lua_pushinteger(L, 0);

	return MAY_LJMP(hlua_channel_send_yield(L, 0, 0));
}

/* This function forward and amount of butes. The data pass from
 * the input side of the buffer to the output side, and can be
 * forwarded. This function never fails.
 *
 * The Lua function takes an amount of bytes to be forwarded in
 * imput. It returns the number of bytes forwarded.
 */
__LJMP static int hlua_channel_forward_yield(lua_State *L, int status, lua_KContext ctx)
{
	struct hlua_channel *chn;
	int len;
	int l;
	int max;
	struct hlua *hlua = hlua_gethlua(L);

	chn = MAY_LJMP(hlua_checkchannel(L, 1));
	len = MAY_LJMP(luaL_checkinteger(L, 2));
	l = MAY_LJMP(luaL_checkinteger(L, -1));

	max = len - l;
	if (max > chn->chn->buf->i)
		max = chn->chn->buf->i;
	channel_forward(chn->chn, max);
	l += max;

	lua_pop(L, 1);
	lua_pushinteger(L, l);

	/* Check if it miss bytes to forward. */
	if (l < len) {
		/* The the input channel or the output channel are closed, we
		 * must return the amount of data forwarded.
		 */
		if (channel_input_closed(chn->chn) || channel_output_closed(chn->chn))
			return 1;

		/* If we are waiting for space data in the response buffer, we
		 * must set the flag WAKERESWR. This flag required the task
		 * wake up if any activity is detected on the response buffer.
		 */
		if (chn->chn == chn->s->rep)
			HLUA_SET_WAKERESWR(hlua);
		else
			HLUA_SET_WAKEREQWR(hlua);

		/* Otherwise, we can yield waiting for new data in the inpout side. */
		WILL_LJMP(hlua_yieldk(L, 0, 0, hlua_channel_forward_yield, TICK_ETERNITY, 0));
	}

	return 1;
}

/* Just check the input and prepare the stack for the previous
 * function "hlua_channel_forward_yield"
 */
__LJMP static int hlua_channel_forward(lua_State *L)
{
	MAY_LJMP(check_args(L, 2, "forward"));
	MAY_LJMP(hlua_checkchannel(L, 1));
	MAY_LJMP(luaL_checkinteger(L, 2));

	lua_pushinteger(L, 0);
	return MAY_LJMP(hlua_channel_forward_yield(L, 0, 0));
}

/* Just returns the number of bytes available in the input
 * side of the buffer. This function never fails.
 */
__LJMP static int hlua_channel_get_in_len(lua_State *L)
{
	struct hlua_channel *chn;

	MAY_LJMP(check_args(L, 1, "get_in_len"));
	chn = MAY_LJMP(hlua_checkchannel(L, 1));
	lua_pushinteger(L, chn->chn->buf->i);
	return 1;
}

/* Just returns the number of bytes available in the output
 * side of the buffer. This function never fails.
 */
__LJMP static int hlua_channel_get_out_len(lua_State *L)
{
	struct hlua_channel *chn;

	MAY_LJMP(check_args(L, 1, "get_out_len"));
	chn = MAY_LJMP(hlua_checkchannel(L, 1));
	lua_pushinteger(L, chn->chn->buf->o);
	return 1;
}


/*
 *
 *
 * Class TXN
 *
 *
 */

/* Returns a struct hlua_session if the stack entry "ud" is
 * a class session, otherwise it throws an error.
 */
__LJMP static struct hlua_txn *hlua_checktxn(lua_State *L, int ud)
{
	return (struct hlua_txn *)MAY_LJMP(hlua_checkudata(L, ud, class_txn_ref));
}

__LJMP static int hlua_setpriv(lua_State *L)
{
	struct hlua *hlua;

	MAY_LJMP(check_args(L, 2, "set_priv"));

	/* It is useles to retrieve the session, but this function
	 * runs only in a session context.
	 */
	MAY_LJMP(hlua_checktxn(L, 1));
	hlua = hlua_gethlua(L);

	/* Remove previous value. */
	if (hlua->Mref != -1)
		luaL_unref(L, hlua->Mref, LUA_REGISTRYINDEX);

	/* Get and store new value. */
	lua_pushvalue(L, 2); /* Copy the element 2 at the top of the stack. */
	hlua->Mref = luaL_ref(L, LUA_REGISTRYINDEX); /* pop the previously pushed value. */

	return 0;
}

__LJMP static int hlua_getpriv(lua_State *L)
{
	struct hlua *hlua;

	MAY_LJMP(check_args(L, 1, "get_priv"));

	/* It is useles to retrieve the session, but this function
	 * runs only in a session context.
	 */
	MAY_LJMP(hlua_checktxn(L, 1));
	hlua = hlua_gethlua(L);

	/* Push configuration index in the stack. */
	lua_rawgeti(L, LUA_REGISTRYINDEX, hlua->Mref);

	return 1;
}

/* Create stack entry containing a class TXN. This function
 * return 0 if the stack does not contains free slots,
 * otherwise it returns 1.
 */
static int hlua_txn_new(lua_State *L, struct session *s, struct proxy *p, void *l7)
{
	struct hlua_txn *hs;

	/* Check stack size. */
	if (!lua_checkstack(L, 2))
		return 0;

	/* NOTE: The allocation never fails. The failure
	 * throw an error, and the function never returns.
	 * if the throw is not avalaible, the process is aborted.
	 */
	hs = lua_newuserdata(L, sizeof(struct hlua_txn));
	hs->s = s;
	hs->p = p;
	hs->l7 = l7;

	/* Pop a class sesison metatable and affect it to the userdata. */
	lua_rawgeti(L, LUA_REGISTRYINDEX, class_txn_ref);
	lua_setmetatable(L, -2);

	return 1;
}

/* This function returns a channel object associated
 * with the request channel. This function never fails,
 * however if the stack is full, it throws an error.
 */
__LJMP static int hlua_txn_req_channel(lua_State *L)
{
	struct hlua_txn *s;

	MAY_LJMP(check_args(L, 1, "req_channel"));
	s = MAY_LJMP(hlua_checktxn(L, 1));

	if (!hlua_channel_new(L, s->s, s->s->req))
		WILL_LJMP(luaL_error(L, "full stack"));

	return 1;
}

/* This function returns a channel object associated
 * with the response channel. This function never fails,
 * however if the stack is full, it throws an error.
 */
__LJMP static int hlua_txn_res_channel(lua_State *L)
{
	struct hlua_txn *s;

	MAY_LJMP(check_args(L, 1, "req_channel"));
	s = MAY_LJMP(hlua_checktxn(L, 1));

	if (!hlua_channel_new(L, s->s, s->s->rep))
		WILL_LJMP(luaL_error(L, "full stack"));

	return 1;
}

/* This function is an Lua binding that send pending data
 * to the client, and close the stream interface.
 */
__LJMP static int hlua_txn_close(lua_State *L)
{
	struct hlua_txn *s;

	MAY_LJMP(check_args(L, 1, "close"));
	s = MAY_LJMP(hlua_checktxn(L, 1));

	channel_abort(s->s->si[0].ib);
	channel_auto_close(s->s->si[0].ib);
	channel_erase(s->s->si[0].ib);
	channel_auto_read(s->s->si[0].ob);
	channel_auto_close(s->s->si[0].ob);
	channel_shutr_now(s->s->si[0].ob);

	return 0;
}

/* This function is an LUA binding. It is called with each sample-fetch.
 * It uses closure argument to store the associated sample-fetch. It
 * returns only one argument or throws an error. An error is thrown
 * only if an error is encountered during the argument parsing. If
 * the "sample-fetch" function fails, nil is returned.
 */
__LJMP static int hlua_run_sample_fetch(lua_State *L)
{
	struct hlua_txn *s;
	struct hlua_sample_fetch *f;
	struct arg args[ARGM_NBARGS + 1];
	int i;
	struct sample smp;

	/* Get closure arguments. */
	f = (struct hlua_sample_fetch *)lua_touserdata(L, lua_upvalueindex(1));

	/* Get traditionnal arguments. */
	s = MAY_LJMP(hlua_checktxn(L, 1));

	/* Get extra arguments. */
	for (i = 0; i < lua_gettop(L) - 1; i++) {
		if (i >= ARGM_NBARGS)
			break;
		hlua_lua2arg(L, i + 2, &args[i]);
	}
	args[i].type = ARGT_STOP;

	/* Check arguments. */
	MAY_LJMP(hlua_lua2arg_check(L, 1, args, f->f->arg_mask));

	/* Run the special args checker. */
	if (f->f->val_args && !f->f->val_args(args, NULL)) {
		lua_pushfstring(L, "error in arguments");
		WILL_LJMP(lua_error(L));
	}

	/* Initialise the sample. */
	memset(&smp, 0, sizeof(smp));

	/* Run the sample fetch process. */
	if (!f->f->process(s->p, s->s, s->l7, 0, args, &smp, f->f->kw, f->f->private)) {
		lua_pushnil(L);
		return 1;
	}

	/* Convert the returned sample in lua value. */
	hlua_smp2lua(L, &smp);
	return 1;
}

/* This function is an LUA binding. It creates ans returns
 * an array of HTTP headers. This function does not fails.
 */
static int hlua_session_getheaders(lua_State *L)
{
	struct hlua_txn *s = MAY_LJMP(hlua_checktxn(L, 1));
	struct session *sess = s->s;
	const char *cur_ptr, *cur_next, *p;
	int old_idx, cur_idx;
	struct hdr_idx_elem *cur_hdr;
	const char *hn, *hv;
	int hnl, hvl;

	/* Create the table. */
	lua_newtable(L);

	/* Build array of headers. */
	old_idx = 0;
	cur_next = sess->req->buf->p + hdr_idx_first_pos(&sess->txn.hdr_idx);

	while (1) {
		cur_idx = sess->txn.hdr_idx.v[old_idx].next;
		if (!cur_idx)
			break;
		old_idx = cur_idx;

		cur_hdr  = &sess->txn.hdr_idx.v[cur_idx];
		cur_ptr  = cur_next;
		cur_next = cur_ptr + cur_hdr->len + cur_hdr->cr + 1;

		/* Now we have one full header at cur_ptr of len cur_hdr->len,
		 * and the next header starts at cur_next. We'll check
		 * this header in the list as well as against the default
		 * rule.
		 */

		/* look for ': *'. */
		hn = cur_ptr;
		for (p = cur_ptr; p < cur_ptr + cur_hdr->len && *p != ':'; p++);
		if (p >= cur_ptr+cur_hdr->len)
			continue;
		hnl = p - hn;
		p++;
		while (p < cur_ptr+cur_hdr->len && ( *p == ' ' || *p == '\t' ))
			p++;
		if (p >= cur_ptr+cur_hdr->len)
			continue;
		hv = p;
		hvl = cur_ptr+cur_hdr->len-p;

		/* Push values in the table. */
		lua_pushlstring(L, hn, hnl);
		lua_pushlstring(L, hv, hvl);
		lua_settable(L, -3);
	}

	return 1;
}

__LJMP static int hlua_sleep_yield(lua_State *L, int status, lua_KContext ctx)
{
	int wakeup_ms = lua_tointeger(L, -1);
	if (now_ms < wakeup_ms)
		WILL_LJMP(hlua_yieldk(L, 0, 0, hlua_sleep_yield, wakeup_ms, 0));
	return 0;
}

__LJMP static int hlua_sleep(lua_State *L)
{
	unsigned int delay;
	unsigned int wakeup_ms;

	MAY_LJMP(check_args(L, 1, "sleep"));

	delay = MAY_LJMP(luaL_checkinteger(L, 1)) * 1000;
	wakeup_ms = tick_add(now_ms, delay);
	lua_pushinteger(L, wakeup_ms);

	WILL_LJMP(hlua_yieldk(L, 0, 0, hlua_sleep_yield, wakeup_ms, 0));
	return 0;
}

__LJMP static int hlua_msleep(lua_State *L)
{
	unsigned int delay;
	unsigned int wakeup_ms;

	MAY_LJMP(check_args(L, 1, "msleep"));

	delay = MAY_LJMP(luaL_checkinteger(L, 1));
	wakeup_ms = tick_add(now_ms, delay);
	lua_pushinteger(L, wakeup_ms);

	WILL_LJMP(hlua_yieldk(L, 0, 0, hlua_sleep_yield, wakeup_ms, 0));
	return 0;
}

/* This functionis an LUA binding. it permits to give back
 * the hand at the HAProxy scheduler. It is used when the
 * LUA processing consumes a lot of time.
 */
__LJMP static int hlua_yield_yield(lua_State *L, int status, lua_KContext ctx)
{
	return 0;
}

__LJMP static int hlua_yield(lua_State *L)
{
	WILL_LJMP(hlua_yieldk(L, 0, 0, hlua_yield_yield, TICK_ETERNITY, HLUA_CTRLYIELD));
	return 0;
}

/* This function change the nice of the currently executed
 * task. It is used set low or high priority at the current
 * task.
 */
__LJMP static int hlua_setnice(lua_State *L)
{
	struct hlua *hlua;
	int nice;

	MAY_LJMP(check_args(L, 1, "set_nice"));
	hlua = hlua_gethlua(L);
	nice = MAY_LJMP(luaL_checkinteger(L, 1));

	/* If he task is not set, I'm in a start mode. */
	if (!hlua || !hlua->task)
		return 0;

	if (nice < -1024)
		nice = -1024;
	else if (nice > 1024)
		nice = 1024;

	hlua->task->nice = nice;
	return 0;
}

/* This function is used as a calback of a task. It is called by the
 * HAProxy task subsystem when the task is awaked. The LUA runtime can
 * return an E_AGAIN signal, the emmiter of this signal must set a
 * signal to wake the task.
 */
static struct task *hlua_process_task(struct task *task)
{
	struct hlua *hlua = task->context;
	enum hlua_exec status;

	/* We need to remove the task from the wait queue before executing
	 * the Lua code because we don't know if it needs to wait for
	 * another timer or not in the case of E_AGAIN.
	 */
	task_delete(task);

	/* If it is the first call to the task, we must initialize the
	 * execution timeouts.
	 */
	if (!HLUA_IS_RUNNING(hlua))
		hlua->expire = tick_add(now_ms, hlua_timeout_task);

	/* Execute the Lua code. */
	status = hlua_ctx_resume(hlua, 1);

	switch (status) {
	/* finished or yield */
	case HLUA_E_OK:
		hlua_ctx_destroy(hlua);
		task_delete(task);
		task_free(task);
		break;

	case HLUA_E_AGAIN: /* co process or timeout wake me later. */
		if (hlua->wake_time != TICK_ETERNITY)
			task_schedule(task, hlua->wake_time);
		break;

	/* finished with error. */
	case HLUA_E_ERRMSG:
		send_log(NULL, LOG_ERR, "Lua task: %s.", lua_tostring(hlua->T, -1));
		if (!(global.mode & MODE_QUIET) || (global.mode & MODE_VERBOSE))
			Alert("Lua task: %s.\n", lua_tostring(hlua->T, -1));
		hlua_ctx_destroy(hlua);
		task_delete(task);
		task_free(task);
		break;

	case HLUA_E_ERR:
	default:
		send_log(NULL, LOG_ERR, "Lua task: unknown error.");
		if (!(global.mode & MODE_QUIET) || (global.mode & MODE_VERBOSE))
			Alert("Lua task: unknown error.\n");
		hlua_ctx_destroy(hlua);
		task_delete(task);
		task_free(task);
		break;
	}
	return NULL;
}

/* This function is an LUA binding that register LUA function to be
 * executed after the HAProxy configuration parsing and before the
 * HAProxy scheduler starts. This function expect only one LUA
 * argument that is a function. This function returns nothing, but
 * throws if an error is encountered.
 */
__LJMP static int hlua_register_init(lua_State *L)
{
	struct hlua_init_function *init;
	int ref;

	MAY_LJMP(check_args(L, 1, "register_init"));

	ref = MAY_LJMP(hlua_checkfunction(L, 1));

	init = malloc(sizeof(*init));
	if (!init)
		WILL_LJMP(luaL_error(L, "lua out of memory error."));

	init->function_ref = ref;
	LIST_ADDQ(&hlua_init_functions, &init->l);
	return 0;
}

/* This functio is an LUA binding. It permits to register a task
 * executed in parallel of the main HAroxy activity. The task is
 * created and it is set in the HAProxy scheduler. It can be called
 * from the "init" section, "post init" or during the runtime.
 *
 * Lua prototype:
 *
 *   <none> core.register_task(<function>)
 */
static int hlua_register_task(lua_State *L)
{
	struct hlua *hlua;
	struct task *task;
	int ref;

	MAY_LJMP(check_args(L, 1, "register_task"));

	ref = MAY_LJMP(hlua_checkfunction(L, 1));

	hlua = malloc(sizeof(*hlua));
	if (!hlua)
		WILL_LJMP(luaL_error(L, "lua out of memory error."));

	task = task_new();
	task->context = hlua;
	task->process = hlua_process_task;

	if (!hlua_ctx_init(hlua, task))
		WILL_LJMP(luaL_error(L, "lua out of memory error."));

	/* Restore the function in the stack. */
	lua_rawgeti(hlua->T, LUA_REGISTRYINDEX, ref);
	hlua->nargs = 0;

	/* Schedule task. */
	task_schedule(task, now_ms);

	return 0;
}

/* Wrapper called by HAProxy to execute an LUA converter. This wrapper
 * doesn't allow "yield" functions because the HAProxy engine cannot
 * resume converters.
 */
static int hlua_sample_conv_wrapper(struct session *session, const struct arg *arg_p,
                                    struct sample *smp, void *private)
{
	struct hlua_function *fcn = (struct hlua_function *)private;

	/* In the execution wrappers linked with a session, the
	 * Lua context can be not initialized. This behavior
	 * permits to save performances because a systematic
	 * Lua initialization cause 5% performances loss.
	 */
	if (!session->hlua.T && !hlua_ctx_init(&session->hlua, session->task)) {
		send_log(session->be, LOG_ERR, "Lua converter '%s': can't initialize Lua context.", fcn->name);
		if (!(global.mode & MODE_QUIET) || (global.mode & MODE_VERBOSE))
			Alert("Lua converter '%s': can't initialize Lua context.\n", fcn->name);
		return 0;
	}

	/* If it is the first run, initialize the data for the call. */
	if (!HLUA_IS_RUNNING(&session->hlua)) {
		/* Check stack available size. */
		if (!lua_checkstack(session->hlua.T, 1)) {
			send_log(session->be, LOG_ERR, "Lua converter '%s': full stack.", fcn->name);
			if (!(global.mode & MODE_QUIET) || (global.mode & MODE_VERBOSE))
				Alert("Lua converter '%s': full stack.\n", fcn->name);
			return 0;
		}

		/* Restore the function in the stack. */
		lua_rawgeti(session->hlua.T, LUA_REGISTRYINDEX, fcn->function_ref);

		/* convert input sample and pust-it in the stack. */
		if (!lua_checkstack(session->hlua.T, 1)) {
			send_log(session->be, LOG_ERR, "Lua converter '%s': full stack.", fcn->name);
			if (!(global.mode & MODE_QUIET) || (global.mode & MODE_VERBOSE))
				Alert("Lua converter '%s': full stack.\n", fcn->name);
			return 0;
		}
		hlua_smp2lua(session->hlua.T, smp);
		session->hlua.nargs = 2;

		/* push keywords in the stack. */
		if (arg_p) {
			for (; arg_p->type != ARGT_STOP; arg_p++) {
				if (!lua_checkstack(session->hlua.T, 1)) {
					send_log(session->be, LOG_ERR, "Lua converter '%s': full stack.", fcn->name);
					if (!(global.mode & MODE_QUIET) || (global.mode & MODE_VERBOSE))
						Alert("Lua converter '%s': full stack.\n", fcn->name);
					return 0;
				}
				hlua_arg2lua(session->hlua.T, arg_p);
				session->hlua.nargs++;
			}
		}

		/* We must initialize the execution timeouts. */
		session->hlua.expire = tick_add(now_ms, hlua_timeout_session);

		/* Set the currently running flag. */
		HLUA_SET_RUN(&session->hlua);
	}

	/* Execute the function. */
	switch (hlua_ctx_resume(&session->hlua, 0)) {
	/* finished. */
	case HLUA_E_OK:
		/* Convert the returned value in sample. */
		hlua_lua2smp(session->hlua.T, -1, smp);
		lua_pop(session->hlua.T, 1);
		return 1;

	/* yield. */
	case HLUA_E_AGAIN:
		send_log(session->be, LOG_ERR, "Lua converter '%s': cannot use yielded functions.", fcn->name);
		if (!(global.mode & MODE_QUIET) || (global.mode & MODE_VERBOSE))
			Alert("Lua converter '%s': cannot use yielded functions.\n", fcn->name);
		return 0;

	/* finished with error. */
	case HLUA_E_ERRMSG:
		/* Display log. */
		send_log(session->be, LOG_ERR, "Lua converter '%s': %s.", fcn->name, lua_tostring(session->hlua.T, -1));
		if (!(global.mode & MODE_QUIET) || (global.mode & MODE_VERBOSE))
			Alert("Lua converter '%s': %s.\n", fcn->name, lua_tostring(session->hlua.T, -1));
		lua_pop(session->hlua.T, 1);
		return 0;

	case HLUA_E_ERR:
		/* Display log. */
		send_log(session->be, LOG_ERR, "Lua converter '%s' returns an unknown error.", fcn->name);
		if (!(global.mode & MODE_QUIET) || (global.mode & MODE_VERBOSE))
			Alert("Lua converter '%s' returns an unknown error.\n", fcn->name);

	default:
		return 0;
	}
}

/* Wrapper called by HAProxy to execute a sample-fetch. this wrapper
 * doesn't allow "yield" functions because the HAProxy engine cannot
 * resume sample-fetches.
 */
static int hlua_sample_fetch_wrapper(struct proxy *px, struct session *s, void *l7,
                                     unsigned int opt, const struct arg *arg_p,
                                     struct sample *smp, const char *kw, void *private)
{
	struct hlua_function *fcn = (struct hlua_function *)private;

	/* In the execution wrappers linked with a session, the
	 * Lua context can be not initialized. This behavior
	 * permits to save performances because a systematic
	 * Lua initialization cause 5% performances loss.
	 */
	if (!s->hlua.T && !hlua_ctx_init(&s->hlua, s->task)) {
		send_log(s->be, LOG_ERR, "Lua sample-fetch '%s': can't initialize Lua context.", fcn->name);
		if (!(global.mode & MODE_QUIET) || (global.mode & MODE_VERBOSE))
			Alert("Lua sample-fetch '%s': can't initialize Lua context.\n", fcn->name);
		return 0;
	}

	/* If it is the first run, initialize the data for the call. */
	if (!HLUA_IS_RUNNING(&s->hlua)) {
		/* Check stack available size. */
		if (!lua_checkstack(s->hlua.T, 2)) {
			send_log(px, LOG_ERR, "Lua sample-fetch '%s': full stack.", fcn->name);
			if (!(global.mode & MODE_QUIET) || (global.mode & MODE_VERBOSE))
				Alert("Lua sample-fetch '%s': full stack.\n", fcn->name);
			return 0;
		}

		/* Restore the function in the stack. */
		lua_rawgeti(s->hlua.T, LUA_REGISTRYINDEX, fcn->function_ref);

		/* push arguments in the stack. */
		if (!hlua_txn_new(s->hlua.T, s, px, l7)) {
			send_log(px, LOG_ERR, "Lua sample-fetch '%s': full stack.", fcn->name);
			if (!(global.mode & MODE_QUIET) || (global.mode & MODE_VERBOSE))
				Alert("Lua sample-fetch '%s': full stack.\n", fcn->name);
			return 0;
		}
		s->hlua.nargs = 1;

		/* push keywords in the stack. */
		for (; arg_p && arg_p->type != ARGT_STOP; arg_p++) {
			/* Check stack available size. */
			if (!lua_checkstack(s->hlua.T, 1)) {
				send_log(px, LOG_ERR, "Lua sample-fetch '%s': full stack.", fcn->name);
				if (!(global.mode & MODE_QUIET) || (global.mode & MODE_VERBOSE))
					Alert("Lua sample-fetch '%s': full stack.\n", fcn->name);
				return 0;
			}
			if (!lua_checkstack(s->hlua.T, 1)) {
				send_log(px, LOG_ERR, "Lua sample-fetch '%s': full stack.", fcn->name);
				if (!(global.mode & MODE_QUIET) || (global.mode & MODE_VERBOSE))
					Alert("Lua sample-fetch '%s': full stack.\n", fcn->name);
				return 0;
			}
			hlua_arg2lua(s->hlua.T, arg_p);
			s->hlua.nargs++;
		}

		/* We must initialize the execution timeouts. */
		s->hlua.expire = tick_add(now_ms, hlua_timeout_session);

		/* Set the currently running flag. */
		HLUA_SET_RUN(&s->hlua);
	}

	/* Execute the function. */
	switch (hlua_ctx_resume(&s->hlua, 0)) {
	/* finished. */
	case HLUA_E_OK:
		/* Convert the returned value in sample. */
		hlua_lua2smp(s->hlua.T, -1, smp);
		lua_pop(s->hlua.T, 1);

		/* Set the end of execution flag. */
		smp->flags &= ~SMP_F_MAY_CHANGE;
		return 1;

	/* yield. */
	case HLUA_E_AGAIN:
		send_log(px, LOG_ERR, "Lua sample-fetch '%s': cannot use yielded functions.", fcn->name);
		if (!(global.mode & MODE_QUIET) || (global.mode & MODE_VERBOSE))
			Alert("Lua sample-fetch '%s': cannot use yielded functions.\n", fcn->name);
		return 0;

	/* finished with error. */
	case HLUA_E_ERRMSG:
		/* Display log. */
		send_log(px, LOG_ERR, "Lua sample-fetch '%s': %s.", fcn->name, lua_tostring(s->hlua.T, -1));
		if (!(global.mode & MODE_QUIET) || (global.mode & MODE_VERBOSE))
			Alert("Lua sample-fetch '%s': %s.\n", fcn->name, lua_tostring(s->hlua.T, -1));
		lua_pop(s->hlua.T, 1);
		return 0;

	case HLUA_E_ERR:
		/* Display log. */
		send_log(px, LOG_ERR, "Lua sample-fetch '%s' returns an unknown error.", fcn->name);
		if (!(global.mode & MODE_QUIET) || (global.mode & MODE_VERBOSE))
			Alert("Lua sample-fetch '%s': returns an unknown error.\n", fcn->name);

	default:
		return 0;
	}
}

/* This function is an LUA binding used for registering
 * "sample-conv" functions. It expects a converter name used
 * in the haproxy configuration file, and an LUA function.
 */
__LJMP static int hlua_register_converters(lua_State *L)
{
	struct sample_conv_kw_list *sck;
	const char *name;
	int ref;
	int len;
	struct hlua_function *fcn;

	MAY_LJMP(check_args(L, 2, "register_converters"));

	/* First argument : converter name. */
	name = MAY_LJMP(luaL_checkstring(L, 1));

	/* Second argument : lua function. */
	ref = MAY_LJMP(hlua_checkfunction(L, 2));

	/* Allocate and fill the sample fetch keyword struct. */
	sck = malloc(sizeof(struct sample_conv_kw_list) +
	             sizeof(struct sample_conv) * 2);
	if (!sck)
		WILL_LJMP(luaL_error(L, "lua out of memory error."));
	fcn = malloc(sizeof(*fcn));
	if (!fcn)
		WILL_LJMP(luaL_error(L, "lua out of memory error."));

	/* Fill fcn. */
	fcn->name = strdup(name);
	if (!fcn->name)
		WILL_LJMP(luaL_error(L, "lua out of memory error."));
	fcn->function_ref = ref;

	/* List head */
	sck->list.n = sck->list.p = NULL;

	/* converter keyword. */
	len = strlen("lua.") + strlen(name) + 1;
	sck->kw[0].kw = malloc(len);
	if (!sck->kw[0].kw)
		WILL_LJMP(luaL_error(L, "lua out of memory error."));

	snprintf((char *)sck->kw[0].kw, len, "lua.%s", name);
	sck->kw[0].process = hlua_sample_conv_wrapper;
	sck->kw[0].arg_mask = ARG5(0,STR,STR,STR,STR,STR);
	sck->kw[0].val_args = NULL;
	sck->kw[0].in_type = SMP_T_STR;
	sck->kw[0].out_type = SMP_T_STR;
	sck->kw[0].private = fcn;

	/* End of array. */
	memset(&sck->kw[1], 0, sizeof(struct sample_conv));

	/* Register this new converter */
	sample_register_convs(sck);

	return 0;
}

/* This fucntion is an LUA binding used for registering
 * "sample-fetch" functions. It expects a converter name used
 * in the haproxy configuration file, and an LUA function.
 */
__LJMP static int hlua_register_fetches(lua_State *L)
{
	const char *name;
	int ref;
	int len;
	struct sample_fetch_kw_list *sfk;
	struct hlua_function *fcn;

	MAY_LJMP(check_args(L, 2, "register_fetches"));

	/* First argument : sample-fetch name. */
	name = MAY_LJMP(luaL_checkstring(L, 1));

	/* Second argument : lua function. */
	ref = MAY_LJMP(hlua_checkfunction(L, 2));

	/* Allocate and fill the sample fetch keyword struct. */
	sfk = malloc(sizeof(struct sample_fetch_kw_list) +
	             sizeof(struct sample_fetch) * 2);
	if (!sfk)
		WILL_LJMP(luaL_error(L, "lua out of memory error."));
	fcn = malloc(sizeof(*fcn));
	if (!fcn)
		WILL_LJMP(luaL_error(L, "lua out of memory error."));

	/* Fill fcn. */
	fcn->name = strdup(name);
	if (!fcn->name)
		WILL_LJMP(luaL_error(L, "lua out of memory error."));
	fcn->function_ref = ref;

	/* List head */
	sfk->list.n = sfk->list.p = NULL;

	/* sample-fetch keyword. */
	len = strlen("lua.") + strlen(name) + 1;
	sfk->kw[0].kw = malloc(len);
	if (!sfk->kw[0].kw)
		return luaL_error(L, "lua out of memory error.");

	snprintf((char *)sfk->kw[0].kw, len, "lua.%s", name);
	sfk->kw[0].process = hlua_sample_fetch_wrapper;
	sfk->kw[0].arg_mask = ARG5(0,STR,STR,STR,STR,STR);
	sfk->kw[0].val_args = NULL;
	sfk->kw[0].out_type = SMP_T_STR;
	sfk->kw[0].use = SMP_USE_HTTP_ANY;
	sfk->kw[0].val = 0;
	sfk->kw[0].private = fcn;

	/* End of array. */
	memset(&sfk->kw[1], 0, sizeof(struct sample_fetch));

	/* Register this new fetch. */
	sample_register_fetches(sfk);

	return 0;
}

/* global {tcp|http}-request parser. Return 1 in succes case, else return 0. */
static int hlua_parse_rule(const char **args, int *cur_arg, struct proxy *px,
                           struct hlua_rule **rule_p, char **err)
{
	struct hlua_rule *rule;

	/* Memory for the rule. */
	rule = malloc(sizeof(*rule));
	if (!rule) {
		memprintf(err, "out of memory error");
		return 0;
	}
	*rule_p = rule;

	/* The requiered arg is a function name. */
	if (!args[*cur_arg]) {
		memprintf(err, "expect Lua function name");
		return 0;
	}

	/* Lookup for the symbol, and check if it is a function. */
	lua_getglobal(gL.T, args[*cur_arg]);
	if (lua_isnil(gL.T, -1)) {
		lua_pop(gL.T, 1);
		memprintf(err, "Lua function '%s' not found", args[*cur_arg]);
		return 0;
	}
	if (!lua_isfunction(gL.T, -1)) {
		lua_pop(gL.T, 1);
		memprintf(err, "'%s' is not a function",  args[*cur_arg]);
		return 0;
	}

	/* Reference the Lua function and store the reference. */
	rule->fcn.function_ref = luaL_ref(gL.T, LUA_REGISTRYINDEX);
	rule->fcn.name = strdup(args[*cur_arg]);
	if (!rule->fcn.name) {
		memprintf(err, "out of memory error.");
		return 0;
	}
	(*cur_arg)++;

	/* TODO: later accept arguments. */
	rule->args = NULL;

	return 1;
}

/* This function is a wrapper to execute each LUA function declared
 * as an action wrapper during the initialisation period. This function
 * return 1 if the processing is finished (with oe without error) and
 * return 0 if the function must be called again because the LUA
 * returns a yield.
 */
static int hlua_request_act_wrapper(struct hlua_rule *rule, struct proxy *px,
                                    struct session *s, struct http_txn *http_txn,
                                    unsigned int analyzer)
{
	char **arg;

	/* In the execution wrappers linked with a session, the
	 * Lua context can be not initialized. This behavior
	 * permits to save performances because a systematic
	 * Lua initialization cause 5% performances loss.
	 */
	if (!s->hlua.T && !hlua_ctx_init(&s->hlua, s->task)) {
		send_log(px, LOG_ERR, "Lua action '%s': can't initialize Lua context.", rule->fcn.name);
		if (!(global.mode & MODE_QUIET) || (global.mode & MODE_VERBOSE))
			Alert("Lua action '%s': can't initialize Lua context.\n", rule->fcn.name);
		return 0;
	}

	/* If it is the first run, initialize the data for the call. */
	if (!HLUA_IS_RUNNING(&s->hlua)) {
		/* Check stack available size. */
		if (!lua_checkstack(s->hlua.T, 1)) {
			send_log(px, LOG_ERR, "Lua function '%s': full stack.", rule->fcn.name);
			if (!(global.mode & MODE_QUIET) || (global.mode & MODE_VERBOSE))
				Alert("Lua function '%s': full stack.\n", rule->fcn.name);
			return 0;
		}

		/* Restore the function in the stack. */
		lua_rawgeti(s->hlua.T, LUA_REGISTRYINDEX, rule->fcn.function_ref);

		/* Create and and push object session in the stack. */
		if (!hlua_txn_new(s->hlua.T, s, px, http_txn)) {
			send_log(px, LOG_ERR, "Lua function '%s': full stack.", rule->fcn.name);
			if (!(global.mode & MODE_QUIET) || (global.mode & MODE_VERBOSE))
				Alert("Lua function '%s': full stack.\n", rule->fcn.name);
			return 0;
		}
		s->hlua.nargs = 1;

		/* push keywords in the stack. */
		for (arg = rule->args; arg && *arg; arg++) {
			if (!lua_checkstack(s->hlua.T, 1)) {
				send_log(px, LOG_ERR, "Lua function '%s': full stack.", rule->fcn.name);
				if (!(global.mode & MODE_QUIET) || (global.mode & MODE_VERBOSE))
					Alert("Lua function '%s': full stack.\n", rule->fcn.name);
				return 0;
			}
			lua_pushstring(s->hlua.T, *arg);
			s->hlua.nargs++;
		}

		/* We must initialize the execution timeouts. */
		s->hlua.expire = tick_add(now_ms, hlua_timeout_session);

		/* Set the currently running flag. */
		HLUA_SET_RUN(&s->hlua);
	}

	/* Execute the function. */
	switch (hlua_ctx_resume(&s->hlua, 1)) {
	/* finished. */
	case HLUA_E_OK:
		return 1;

	/* yield. */
	case HLUA_E_AGAIN:
		/* Set timeout in the required channel. */
		if (s->hlua.wake_time != TICK_ETERNITY) {
			if (analyzer & (AN_REQ_INSPECT_FE|AN_REQ_HTTP_PROCESS_FE))
				s->req->analyse_exp = s->hlua.wake_time;
			else if (analyzer & (AN_RES_INSPECT|AN_RES_HTTP_PROCESS_BE))
				s->rep->analyse_exp = s->hlua.wake_time;
		}
		/* Some actions can be wake up when a "write" event
		 * is detected on a response channel. This is useful
		 * only for actions targetted on the requests.
		 */
		if (HLUA_IS_WAKERESWR(&s->hlua)) {
			s->rep->flags |= CF_WAKE_WRITE;
		}
		if ((analyzer & (AN_REQ_INSPECT_FE|AN_REQ_HTTP_PROCESS_FE)))
			s->rep->analysers |= analyzer;
		if (HLUA_IS_WAKEREQWR(&s->hlua))
			s->req->flags |= CF_WAKE_WRITE;
		return 0;

	/* finished with error. */
	case HLUA_E_ERRMSG:
		/* Display log. */
		send_log(px, LOG_ERR, "Lua function '%s': %s.", rule->fcn.name, lua_tostring(s->hlua.T, -1));
		if (!(global.mode & MODE_QUIET) || (global.mode & MODE_VERBOSE))
			Alert("Lua function '%s': %s.\n", rule->fcn.name, lua_tostring(s->hlua.T, -1));
		lua_pop(s->hlua.T, 1);
		return 1;

	case HLUA_E_ERR:
		/* Display log. */
		send_log(px, LOG_ERR, "Lua function '%s' return an unknown error.", rule->fcn.name);
		if (!(global.mode & MODE_QUIET) || (global.mode & MODE_VERBOSE))
			Alert("Lua function '%s' return an unknown error.\n", rule->fcn.name);

	default:
		return 1;
	}
}

/* Lua execution wrapper for "tcp-request". This function uses
 * "hlua_request_act_wrapper" for executing the LUA code.
 */
int hlua_tcp_req_act_wrapper(struct tcp_rule *tcp_rule, struct proxy *px,
                             struct session *s)
{
	return hlua_request_act_wrapper((struct hlua_rule *)tcp_rule->act_prm.data,
	                                px, s, NULL, AN_REQ_INSPECT_FE);
}

/* Lua execution wrapper for "tcp-response". This function uses
 * "hlua_request_act_wrapper" for executing the LUA code.
 */
int hlua_tcp_res_act_wrapper(struct tcp_rule *tcp_rule, struct proxy *px,
                             struct session *s)
{
	return hlua_request_act_wrapper((struct hlua_rule *)tcp_rule->act_prm.data,
	                                px, s, NULL, AN_RES_INSPECT);
}

/* Lua execution wrapper for http-request.
 * This function uses "hlua_request_act_wrapper" for executing
 * the LUA code.
 */
int hlua_http_req_act_wrapper(struct http_req_rule *rule, struct proxy *px,
                              struct session *s, struct http_txn *http_txn)
{
	return hlua_request_act_wrapper((struct hlua_rule *)rule->arg.data, px,
	                                s, http_txn, AN_REQ_HTTP_PROCESS_FE);
}

/* Lua execution wrapper for http-response.
 * This function uses "hlua_request_act_wrapper" for executing
 * the LUA code.
 */
int hlua_http_res_act_wrapper(struct http_res_rule *rule, struct proxy *px,
                              struct session *s, struct http_txn *http_txn)
{
	return hlua_request_act_wrapper((struct hlua_rule *)rule->arg.data, px,
	                                s, http_txn, AN_RES_HTTP_PROCESS_BE);
}

/* tcp-request <*> configuration wrapper. */
static int tcp_req_action_register_lua(const char **args, int *cur_arg, struct proxy *px,
                                       struct tcp_rule *rule, char **err)
{
	if (!hlua_parse_rule(args, cur_arg, px, (struct hlua_rule **)&rule->act_prm.data, err))
		return 0;
	rule->action = TCP_ACT_CUSTOM;
	rule->action_ptr = hlua_tcp_req_act_wrapper;
	return 1;
}

/* tcp-response <*> configuration wrapper. */
static int tcp_res_action_register_lua(const char **args, int *cur_arg, struct proxy *px,
                                       struct tcp_rule *rule, char **err)
{
	if (!hlua_parse_rule(args, cur_arg, px, (struct hlua_rule **)&rule->act_prm.data, err))
		return 0;
	rule->action = TCP_ACT_CUSTOM;
	rule->action_ptr = hlua_tcp_res_act_wrapper;
	return 1;
}

/* http-request <*> configuration wrapper. */
static int http_req_action_register_lua(const char **args, int *cur_arg, struct proxy *px,
                                        struct http_req_rule *rule, char **err)
{
	if (!hlua_parse_rule(args, cur_arg, px, (struct hlua_rule **)&rule->arg.data, err))
		return -1;
	rule->action = HTTP_REQ_ACT_CUSTOM_CONT;
	rule->action_ptr = hlua_http_req_act_wrapper;
	return 1;
}

/* http-response <*> configuration wrapper. */
static int http_res_action_register_lua(const char **args, int *cur_arg, struct proxy *px,
                                        struct http_res_rule *rule, char **err)
{
	if (!hlua_parse_rule(args, cur_arg, px, (struct hlua_rule **)&rule->arg.data, err))
		return -1;
	rule->action = HTTP_RES_ACT_CUSTOM_CONT;
	rule->action_ptr = hlua_http_res_act_wrapper;
	return 1;
}

static int hlua_read_timeout(char **args, int section_type, struct proxy *curpx,
                             struct proxy *defpx, const char *file, int line,
                             char **err, unsigned int *timeout)
{
	const char *error;

	error = parse_time_err(args[1], timeout, TIME_UNIT_MS);
	if (error && *error != '\0') {
		memprintf(err, "%s: invalid timeout", args[0]);
		return -1;
	}
	return 0;
}

static int hlua_session_timeout(char **args, int section_type, struct proxy *curpx,
                                struct proxy *defpx, const char *file, int line,
                                char **err)
{
	return hlua_read_timeout(args, section_type, curpx, defpx,
	                         file, line, err, &hlua_timeout_session);
}

static int hlua_task_timeout(char **args, int section_type, struct proxy *curpx,
                             struct proxy *defpx, const char *file, int line,
                             char **err)
{
	return hlua_read_timeout(args, section_type, curpx, defpx,
	                         file, line, err, &hlua_timeout_task);
}

static int hlua_forced_yield(char **args, int section_type, struct proxy *curpx,
                             struct proxy *defpx, const char *file, int line,
                             char **err)
{
	char *error;

	hlua_nb_instruction = strtoll(args[1], &error, 10);
	if (*error != '\0') {
		memprintf(err, "%s: invalid number", args[0]);
		return -1;
	}
	return 0;
}

/* This function is called by the main configuration key "lua-load". It loads and
 * execute an lua file during the parsing of the HAProxy configuration file. It is
 * the main lua entry point.
 *
 * This funtion runs with the HAProxy keywords API. It returns -1 if an error is
 * occured, otherwise it returns 0.
 *
 * In some error case, LUA set an error message in top of the stack. This function
 * returns this error message in the HAProxy logs and pop it from the stack.
 */
static int hlua_load(char **args, int section_type, struct proxy *curpx,
                     struct proxy *defpx, const char *file, int line,
                     char **err)
{
	int error;

	/* Just load and compile the file. */
	error = luaL_loadfile(gL.T, args[1]);
	if (error) {
		memprintf(err, "error in lua file '%s': %s", args[1], lua_tostring(gL.T, -1));
		lua_pop(gL.T, 1);
		return -1;
	}

	/* If no syntax error where detected, execute the code. */
	error = lua_pcall(gL.T, 0, LUA_MULTRET, 0);
	switch (error) {
	case LUA_OK:
		break;
	case LUA_ERRRUN:
		memprintf(err, "lua runtime error: %s\n", lua_tostring(gL.T, -1));
		lua_pop(gL.T, 1);
		return -1;
	case LUA_ERRMEM:
		memprintf(err, "lua out of memory error\n");
		return -1;
	case LUA_ERRERR:
		memprintf(err, "lua message handler error: %s\n", lua_tostring(gL.T, -1));
		lua_pop(gL.T, 1);
		return -1;
	case LUA_ERRGCMM:
		memprintf(err, "lua garbage collector error: %s\n", lua_tostring(gL.T, -1));
		lua_pop(gL.T, 1);
		return -1;
	default:
		memprintf(err, "lua unknonwn error: %s\n", lua_tostring(gL.T, -1));
		lua_pop(gL.T, 1);
		return -1;
	}

	return 0;
}

/* configuration keywords declaration */
static struct cfg_kw_list cfg_kws = {{ },{
	{ CFG_GLOBAL, "lua-load",                 hlua_load },
	{ CFG_GLOBAL, "tune.lua.session-timeout", hlua_session_timeout },
	{ CFG_GLOBAL, "tune.lua.task-timeout",    hlua_task_timeout },
	{ CFG_GLOBAL, "tune.lua.forced-yield",    hlua_forced_yield },
	{ 0, NULL, NULL },
}};

static struct http_req_action_kw_list http_req_kws = {"lua", { }, {
	{ "lua", http_req_action_register_lua },
	{ NULL, NULL }
}};

static struct http_res_action_kw_list http_res_kws = {"lua", { }, {
	{ "lua", http_res_action_register_lua },
	{ NULL, NULL }
}};

static struct tcp_action_kw_list tcp_req_cont_kws = {"lua", { }, {
	{ "lua", tcp_req_action_register_lua },
	{ NULL, NULL }
}};

static struct tcp_action_kw_list tcp_res_cont_kws = {"lua", { }, {
	{ "lua", tcp_res_action_register_lua },
	{ NULL, NULL }
}};

int hlua_post_init()
{
	struct hlua_init_function *init;
	const char *msg;
	enum hlua_exec ret;

	list_for_each_entry(init, &hlua_init_functions, l) {
		lua_rawgeti(gL.T, LUA_REGISTRYINDEX, init->function_ref);
		ret = hlua_ctx_resume(&gL, 0);
		switch (ret) {
		case HLUA_E_OK:
			lua_pop(gL.T, -1);
			return 1;
		case HLUA_E_AGAIN:
			Alert("lua init: yield not allowed.\n");
			return 0;
		case HLUA_E_ERRMSG:
			msg = lua_tostring(gL.T, -1);
			Alert("lua init: %s.\n", msg);
			return 0;
		case HLUA_E_ERR:
		default:
			Alert("lua init: unknown runtime error.\n");
			return 0;
		}
	}
	return 1;
}

void hlua_init(void)
{
	int i;
	int idx;
	struct sample_fetch *sf;
	struct hlua_sample_fetch *hsf;
	char *p;
#ifdef USE_OPENSSL
	char *args[4];
	struct srv_kw *kw;
	int tmp_error;
	char *error;
#endif

	/* Initialise com signals pool session. */
	pool2_hlua_com = create_pool("hlua_com", sizeof(struct hlua_com), MEM_F_SHARED);

	/* Initialise sleep pool. */
	pool2_hlua_sleep = create_pool("hlua_sleep", sizeof(struct hlua_sleep), MEM_F_SHARED);

	/* Register configuration keywords. */
	cfg_register_keywords(&cfg_kws);

	/* Register custom HTTP rules. */
	http_req_keywords_register(&http_req_kws);
	http_res_keywords_register(&http_res_kws);
	tcp_req_cont_keywords_register(&tcp_req_cont_kws);
	tcp_res_cont_keywords_register(&tcp_res_cont_kws);

	/* Init main lua stack. */
	gL.Mref = LUA_REFNIL;
	gL.flags = 0;
	LIST_INIT(&gL.com);
	gL.T = luaL_newstate();
	hlua_sethlua(&gL);
	gL.Tref = LUA_REFNIL;
	gL.task = NULL;

	/* Initialise lua. */
	luaL_openlibs(gL.T);

	/*
	 *
	 * Create "core" object.
	 *
	 */

	/* This integer entry is just used as base value for the object "core". */
	lua_pushinteger(gL.T, 0);

	/* Create and fill the metatable. */
	lua_newtable(gL.T);

	/* Create and fill the __index entry. */
	lua_pushstring(gL.T, "__index");
	lua_newtable(gL.T);

	/* Push the loglevel constants. */
	for (i = 0; i < NB_LOG_LEVELS; i++)
		hlua_class_const_int(gL.T, log_levels[i], i);

	/* Register special functions. */
	hlua_class_function(gL.T, "register_init", hlua_register_init);
	hlua_class_function(gL.T, "register_task", hlua_register_task);
	hlua_class_function(gL.T, "register_fetches", hlua_register_fetches);
	hlua_class_function(gL.T, "register_converters", hlua_register_converters);
	hlua_class_function(gL.T, "yield", hlua_yield);
	hlua_class_function(gL.T, "set_nice", hlua_setnice);
	hlua_class_function(gL.T, "sleep", hlua_sleep);
	hlua_class_function(gL.T, "msleep", hlua_msleep);
	hlua_class_function(gL.T, "add_acl", hlua_add_acl);
	hlua_class_function(gL.T, "del_acl", hlua_del_acl);
	hlua_class_function(gL.T, "set_map", hlua_set_map);
	hlua_class_function(gL.T, "del_map", hlua_del_map);
	hlua_class_function(gL.T, "tcp", hlua_socket_new);

	/* Store the table __index in the metable. */
	lua_settable(gL.T, -3);

	/* Register previous table in the registry with named entry. */
	lua_pushvalue(gL.T, -1); /* Copy the -1 entry and push it on the stack. */
	lua_setfield(gL.T, LUA_REGISTRYINDEX, CLASS_CORE); /* register class session. */

	/* Register previous table in the registry with reference. */
	lua_pushvalue(gL.T, -1); /* Copy the -1 entry and push it on the stack. */
	class_core_ref = luaL_ref(gL.T, LUA_REGISTRYINDEX); /* reference class session. */

	/* Create new object with class Core. */
	lua_setmetatable(gL.T, -2);
	lua_setglobal(gL.T, "core");

	/*
	 *
	 * Register class Channel
	 *
	 */

	/* Create and fill the metatable. */
	lua_newtable(gL.T);

	/* Create and fille the __index entry. */
	lua_pushstring(gL.T, "__index");
	lua_newtable(gL.T);

	/* Register . */
	hlua_class_function(gL.T, "get",         hlua_channel_get);
	hlua_class_function(gL.T, "dup",         hlua_channel_dup);
	hlua_class_function(gL.T, "getline",     hlua_channel_getline);
	hlua_class_function(gL.T, "set",         hlua_channel_set);
	hlua_class_function(gL.T, "append",      hlua_channel_append);
	hlua_class_function(gL.T, "send",        hlua_channel_send);
	hlua_class_function(gL.T, "forward",     hlua_channel_forward);
	hlua_class_function(gL.T, "get_in_len",  hlua_channel_get_in_len);
	hlua_class_function(gL.T, "get_out_len", hlua_channel_get_out_len);

	lua_settable(gL.T, -3);

	/* Register previous table in the registry with reference and named entry. */
	lua_pushvalue(gL.T, -1); /* Copy the -1 entry and push it on the stack. */
	lua_setfield(gL.T, LUA_REGISTRYINDEX, CLASS_CHANNEL); /* register class session. */
	class_channel_ref = luaL_ref(gL.T, LUA_REGISTRYINDEX); /* reference class session. */

	/*
	 *
	 * Register class TXN
	 *
	 */

	/* Create and fill the metatable. */
	lua_newtable(gL.T);

	/* Create and fille the __index entry. */
	lua_pushstring(gL.T, "__index");
	lua_newtable(gL.T);

	/* Browse existing fetches and create the associated
	 * object method.
	 */
	sf = NULL;
	while ((sf = sample_fetch_getnext(sf, &idx)) != NULL) {

		/* Dont register the keywork if the arguments check function are
		 * not safe during the runtime.
		 */
		if ((sf->val_args != NULL) &&
		    (sf->val_args != val_payload_lv) &&
			 (sf->val_args != val_hdr))
			continue;

		/* gL.Tua doesn't support '.' and '-' in the function names, replace it
		 * by an underscore.
		 */
		strncpy(trash.str, sf->kw, trash.size);
		trash.str[trash.size - 1] = '\0';
		for (p = trash.str; *p; p++)
			if (*p == '.' || *p == '-' || *p == '+')
				*p = '_';

		/* Register the function. */
		lua_pushstring(gL.T, trash.str);
		hsf = lua_newuserdata(gL.T, sizeof(struct hlua_sample_fetch));
		hsf->f = sf;
		lua_pushcclosure(gL.T, hlua_run_sample_fetch, 1);
		lua_settable(gL.T, -3);
	}

	/* Register Lua functions. */
	hlua_class_function(gL.T, "get_headers", hlua_session_getheaders);
	hlua_class_function(gL.T, "set_priv",    hlua_setpriv);
	hlua_class_function(gL.T, "get_priv",    hlua_getpriv);
	hlua_class_function(gL.T, "req_channel", hlua_txn_req_channel);
	hlua_class_function(gL.T, "res_channel", hlua_txn_res_channel);
	hlua_class_function(gL.T, "close",       hlua_txn_close);

	lua_settable(gL.T, -3);

	/* Register previous table in the registry with reference and named entry. */
	lua_pushvalue(gL.T, -1); /* Copy the -1 entry and push it on the stack. */
	lua_setfield(gL.T, LUA_REGISTRYINDEX, CLASS_TXN); /* register class session. */
	class_txn_ref = luaL_ref(gL.T, LUA_REGISTRYINDEX); /* reference class session. */

	/*
	 *
	 * Register class Socket
	 *
	 */

	/* Create and fill the metatable. */
	lua_newtable(gL.T);

	/* Create and fille the __index entry. */
	lua_pushstring(gL.T, "__index");
	lua_newtable(gL.T);

#ifdef USE_OPENSSL
	hlua_class_function(gL.T, "connect_ssl", hlua_socket_connect_ssl);
#endif
	hlua_class_function(gL.T, "connect",     hlua_socket_connect);
	hlua_class_function(gL.T, "send",        hlua_socket_send);
	hlua_class_function(gL.T, "receive",     hlua_socket_receive);
	hlua_class_function(gL.T, "close",       hlua_socket_close);
	hlua_class_function(gL.T, "getpeername", hlua_socket_getpeername);
	hlua_class_function(gL.T, "getsockname", hlua_socket_getsockname);
	hlua_class_function(gL.T, "setoption",   hlua_socket_setoption);
	hlua_class_function(gL.T, "settimeout",  hlua_socket_settimeout);

	lua_settable(gL.T, -3); /* Push the last 2 entries in the table at index -3 */

	/* Register the garbage collector entry. */
	lua_pushstring(gL.T, "__gc");
	lua_pushcclosure(gL.T, hlua_socket_gc, 0);
	lua_settable(gL.T, -3); /* Push the last 2 entries in the table at index -3 */

	/* Register previous table in the registry with reference and named entry. */
	lua_pushvalue(gL.T, -1); /* Copy the -1 entry and push it on the stack. */
	lua_pushvalue(gL.T, -1); /* Copy the -1 entry and push it on the stack. */
	lua_setfield(gL.T, LUA_REGISTRYINDEX, CLASS_SOCKET); /* register class socket. */
	class_socket_ref = luaL_ref(gL.T, LUA_REGISTRYINDEX); /* reference class socket. */

	/* Proxy and server configuration initialisation. */
	memset(&socket_proxy, 0, sizeof(socket_proxy));
	init_new_proxy(&socket_proxy);
	socket_proxy.parent = NULL;
	socket_proxy.last_change = now.tv_sec;
	socket_proxy.id = "LUA-SOCKET";
	socket_proxy.cap = PR_CAP_FE | PR_CAP_BE;
	socket_proxy.maxconn = 0;
	socket_proxy.accept = NULL;
	socket_proxy.options2 |= PR_O2_INDEPSTR;
	socket_proxy.srv = NULL;
	socket_proxy.conn_retries = 0;
	socket_proxy.timeout.connect = 5000; /* By default the timeout connection is 5s. */

	/* Init TCP server: unchanged parameters */
	memset(&socket_tcp, 0, sizeof(socket_tcp));
	socket_tcp.next = NULL;
	socket_tcp.proxy = &socket_proxy;
	socket_tcp.obj_type = OBJ_TYPE_SERVER;
	LIST_INIT(&socket_tcp.actconns);
	LIST_INIT(&socket_tcp.pendconns);
	socket_tcp.state = SRV_ST_RUNNING; /* early server setup */
	socket_tcp.last_change = 0;
	socket_tcp.id = "LUA-TCP-CONN";
	socket_tcp.check.state &= ~CHK_ST_ENABLED; /* Disable health checks. */
	socket_tcp.agent.state &= ~CHK_ST_ENABLED; /* Disable health checks. */
	socket_tcp.pp_opts = 0; /* Remove proxy protocol. */

	/* XXX: Copy default parameter from default server,
	 * but the default server is not initialized.
	 */
	socket_tcp.maxqueue     = socket_proxy.defsrv.maxqueue;
	socket_tcp.minconn      = socket_proxy.defsrv.minconn;
	socket_tcp.maxconn      = socket_proxy.defsrv.maxconn;
	socket_tcp.slowstart    = socket_proxy.defsrv.slowstart;
	socket_tcp.onerror      = socket_proxy.defsrv.onerror;
	socket_tcp.onmarkeddown = socket_proxy.defsrv.onmarkeddown;
	socket_tcp.onmarkedup   = socket_proxy.defsrv.onmarkedup;
	socket_tcp.consecutive_errors_limit = socket_proxy.defsrv.consecutive_errors_limit;
	socket_tcp.uweight      = socket_proxy.defsrv.iweight;
	socket_tcp.iweight      = socket_proxy.defsrv.iweight;

	socket_tcp.check.status = HCHK_STATUS_INI;
	socket_tcp.check.rise   = socket_proxy.defsrv.check.rise;
	socket_tcp.check.fall   = socket_proxy.defsrv.check.fall;
	socket_tcp.check.health = socket_tcp.check.rise;   /* socket, but will fall down at first failure */
	socket_tcp.check.server = &socket_tcp;

	socket_tcp.agent.status = HCHK_STATUS_INI;
	socket_tcp.agent.rise   = socket_proxy.defsrv.agent.rise;
	socket_tcp.agent.fall   = socket_proxy.defsrv.agent.fall;
	socket_tcp.agent.health = socket_tcp.agent.rise;   /* socket, but will fall down at first failure */
	socket_tcp.agent.server = &socket_tcp;

	socket_tcp.xprt = &raw_sock;

#ifdef USE_OPENSSL
	/* Init TCP server: unchanged parameters */
	memset(&socket_ssl, 0, sizeof(socket_ssl));
	socket_ssl.next = NULL;
	socket_ssl.proxy = &socket_proxy;
	socket_ssl.obj_type = OBJ_TYPE_SERVER;
	LIST_INIT(&socket_ssl.actconns);
	LIST_INIT(&socket_ssl.pendconns);
	socket_ssl.state = SRV_ST_RUNNING; /* early server setup */
	socket_ssl.last_change = 0;
	socket_ssl.id = "LUA-SSL-CONN";
	socket_ssl.check.state &= ~CHK_ST_ENABLED; /* Disable health checks. */
	socket_ssl.agent.state &= ~CHK_ST_ENABLED; /* Disable health checks. */
	socket_ssl.pp_opts = 0; /* Remove proxy protocol. */

	/* XXX: Copy default parameter from default server,
	 * but the default server is not initialized.
	 */
	socket_ssl.maxqueue     = socket_proxy.defsrv.maxqueue;
	socket_ssl.minconn      = socket_proxy.defsrv.minconn;
	socket_ssl.maxconn      = socket_proxy.defsrv.maxconn;
	socket_ssl.slowstart    = socket_proxy.defsrv.slowstart;
	socket_ssl.onerror      = socket_proxy.defsrv.onerror;
	socket_ssl.onmarkeddown = socket_proxy.defsrv.onmarkeddown;
	socket_ssl.onmarkedup   = socket_proxy.defsrv.onmarkedup;
	socket_ssl.consecutive_errors_limit = socket_proxy.defsrv.consecutive_errors_limit;
	socket_ssl.uweight      = socket_proxy.defsrv.iweight;
	socket_ssl.iweight      = socket_proxy.defsrv.iweight;

	socket_ssl.check.status = HCHK_STATUS_INI;
	socket_ssl.check.rise   = socket_proxy.defsrv.check.rise;
	socket_ssl.check.fall   = socket_proxy.defsrv.check.fall;
	socket_ssl.check.health = socket_ssl.check.rise;   /* socket, but will fall down at first failure */
	socket_ssl.check.server = &socket_ssl;

	socket_ssl.agent.status = HCHK_STATUS_INI;
	socket_ssl.agent.rise   = socket_proxy.defsrv.agent.rise;
	socket_ssl.agent.fall   = socket_proxy.defsrv.agent.fall;
	socket_ssl.agent.health = socket_ssl.agent.rise;   /* socket, but will fall down at first failure */
	socket_ssl.agent.server = &socket_ssl;

	socket_ssl.xprt = &raw_sock;

	args[0] = "ssl";
	args[1] = "verify";
	args[2] = "none";
	args[3] = NULL;

	for (idx = 0; idx < 3; idx++) {
		if ((kw = srv_find_kw(args[idx])) != NULL) { /* Maybe it's registered server keyword */
			/*
			 *
			 * If the keyword is not known, we can search in the registered
			 * server keywords. This is usefull to configure special SSL
			 * features like client certificates and ssl_verify.
			 *
			 */
			tmp_error = kw->parse(args, &idx, &socket_proxy, &socket_ssl, &error);
			if (tmp_error != 0) {
				fprintf(stderr, "INTERNAL ERROR: %s\n", error);
				abort(); /* This must be never arrives because the command line
				            not editable by the user. */
			}
			idx += kw->skip;
		}
	}

	/* Initialize SSL server. */
	if (socket_ssl.xprt == &ssl_sock) {
		socket_ssl.use_ssl = 1;
		ssl_sock_prepare_srv_ctx(&socket_ssl, &socket_proxy);
	}
#endif
}
