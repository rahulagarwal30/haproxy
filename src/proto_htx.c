/*
 * HTTP protocol analyzer
 *
 * Copyright (C) 2018 HAProxy Technologies, Christopher Faulet <cfaulet@haproxy.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */

#include <common/base64.h>
#include <common/config.h>
#include <common/debug.h>
#include <common/uri_auth.h>

#include <types/cache.h>

#include <proto/acl.h>
#include <proto/channel.h>
#include <proto/checks.h>
#include <proto/connection.h>
#include <proto/filters.h>
#include <proto/hdr_idx.h>
#include <proto/log.h>
#include <proto/proto_http.h>
#include <proto/proxy.h>
#include <proto/stream.h>
#include <proto/stream_interface.h>
#include <proto/stats.h>

/* This stream analyser waits for a complete HTTP request. It returns 1 if the
 * processing can continue on next analysers, or zero if it either needs more
 * data or wants to immediately abort the request (eg: timeout, error, ...). It
 * is tied to AN_REQ_WAIT_HTTP and may may remove itself from s->req.analysers
 * when it has nothing left to do, and may remove any analyser when it wants to
 * abort.
 */
int htx_wait_for_request(struct stream *s, struct channel *req, int an_bit)
{
	/*
	 * We will parse the partial (or complete) lines.
	 * We will check the request syntax, and also join multi-line
	 * headers. An index of all the lines will be elaborated while
	 * parsing.
	 *
	 * For the parsing, we use a 28 states FSM.
	 *
	 * Here is the information we currently have :
	 *   ci_head(req)             = beginning of request
	 *   ci_head(req) + msg->eoh  = end of processed headers / start of current one
	 *   ci_tail(req)             = end of input data
	 *   msg->eol                 = end of current header or line (LF or CRLF)
	 *   msg->next                = first non-visited byte
	 *
	 * At end of parsing, we may perform a capture of the error (if any), and
	 * we will set a few fields (txn->meth, sn->flags/SF_REDIRECTABLE).
	 * We also check for monitor-uri, logging, HTTP/0.9 to 1.0 conversion, and
	 * finally headers capture.
	 */

	int cur_idx;
	struct session *sess = s->sess;
	struct http_txn *txn = s->txn;
	struct http_msg *msg = &txn->req;
	struct hdr_ctx ctx;

	DPRINTF(stderr,"[%u] %s: stream=%p b=%p, exp(r,w)=%u,%u bf=%08x bh=%lu analysers=%02x\n",
		now_ms, __FUNCTION__,
		s,
		req,
		req->rex, req->wex,
		req->flags,
		ci_data(req),
		req->analysers);

	/* we're speaking HTTP here, so let's speak HTTP to the client */
	s->srv_error = http_return_srv_error;

	/* If there is data available for analysis, log the end of the idle time. */
	if (c_data(req) && s->logs.t_idle == -1)
		s->logs.t_idle = tv_ms_elapsed(&s->logs.tv_accept, &now) - s->logs.t_handshake;

	/* There's a protected area at the end of the buffer for rewriting
	 * purposes. We don't want to start to parse the request if the
	 * protected area is affected, because we may have to move processed
	 * data later, which is much more complicated.
	 */
	if (c_data(req) && msg->msg_state < HTTP_MSG_ERROR) {
		if (txn->flags & TX_NOT_FIRST) {
			if (unlikely(!channel_is_rewritable(req))) {
				if (req->flags & (CF_SHUTW|CF_SHUTW_NOW|CF_WRITE_ERROR|CF_WRITE_TIMEOUT))
					goto failed_keep_alive;
				/* some data has still not left the buffer, wake us once that's done */
				channel_dont_connect(req);
				req->flags |= CF_READ_DONTWAIT; /* try to get back here ASAP */
				req->flags |= CF_WAKE_WRITE;
				return 0;
			}
			if (unlikely(ci_tail(req) < c_ptr(req, msg->next) ||
			             ci_tail(req) > b_wrap(&req->buf) - global.tune.maxrewrite))
				channel_slow_realign(req, trash.area);
		}

		if (likely(msg->next < ci_data(req))) /* some unparsed data are available */
			http_msg_analyzer(msg, &txn->hdr_idx);
	}

	/* 1: we might have to print this header in debug mode */
	if (unlikely((global.mode & MODE_DEBUG) &&
		     (!(global.mode & MODE_QUIET) || (global.mode & MODE_VERBOSE)) &&
		     msg->msg_state >= HTTP_MSG_BODY)) {
		char *eol, *sol;

		sol = ci_head(req);
		/* this is a bit complex : in case of error on the request line,
		 * we know that rq.l is still zero, so we display only the part
		 * up to the end of the line (truncated by debug_hdr).
		 */
		eol = sol + (msg->sl.rq.l ? msg->sl.rq.l : ci_data(req));
		debug_hdr("clireq", s, sol, eol);

		sol += hdr_idx_first_pos(&txn->hdr_idx);
		cur_idx = hdr_idx_first_idx(&txn->hdr_idx);

		while (cur_idx) {
			eol = sol + txn->hdr_idx.v[cur_idx].len;
			debug_hdr("clihdr", s, sol, eol);
			sol = eol + txn->hdr_idx.v[cur_idx].cr + 1;
			cur_idx = txn->hdr_idx.v[cur_idx].next;
		}
	}


	/*
	 * Now we quickly check if we have found a full valid request.
	 * If not so, we check the FD and buffer states before leaving.
	 * A full request is indicated by the fact that we have seen
	 * the double LF/CRLF, so the state is >= HTTP_MSG_BODY. Invalid
	 * requests are checked first. When waiting for a second request
	 * on a keep-alive stream, if we encounter and error, close, t/o,
	 * we note the error in the stream flags but don't set any state.
	 * Since the error will be noted there, it will not be counted by
	 * process_stream() as a frontend error.
	 * Last, we may increase some tracked counters' http request errors on
	 * the cases that are deliberately the client's fault. For instance,
	 * a timeout or connection reset is not counted as an error. However
	 * a bad request is.
	 */

	if (unlikely(msg->msg_state < HTTP_MSG_BODY)) {
		/*
		 * First, let's catch bad requests.
		 */
		if (unlikely(msg->msg_state == HTTP_MSG_ERROR)) {
			stream_inc_http_req_ctr(s);
			stream_inc_http_err_ctr(s);
			proxy_inc_fe_req_ctr(sess->fe);
			goto return_bad_req;
		}

		/* 1: Since we are in header mode, if there's no space
		 *    left for headers, we won't be able to free more
		 *    later, so the stream will never terminate. We
		 *    must terminate it now.
		 */
		if (unlikely(channel_full(req, global.tune.maxrewrite))) {
			/* FIXME: check if URI is set and return Status
			 * 414 Request URI too long instead.
			 */
			stream_inc_http_req_ctr(s);
			stream_inc_http_err_ctr(s);
			proxy_inc_fe_req_ctr(sess->fe);
			if (msg->err_pos < 0)
				msg->err_pos = ci_data(req);
			goto return_bad_req;
		}

		/* 2: have we encountered a read error ? */
		else if (req->flags & CF_READ_ERROR) {
			if (!(s->flags & SF_ERR_MASK))
				s->flags |= SF_ERR_CLICL;

			if (txn->flags & TX_WAIT_NEXT_RQ)
				goto failed_keep_alive;

			if (sess->fe->options & PR_O_IGNORE_PRB)
				goto failed_keep_alive;

			/* we cannot return any message on error */
			if (msg->err_pos >= 0) {
				http_capture_bad_message(sess->fe, s, msg, msg->err_state, sess->fe);
				stream_inc_http_err_ctr(s);
			}

			txn->status = 400;
			msg->err_state = msg->msg_state;
			msg->msg_state = HTTP_MSG_ERROR;
			http_reply_and_close(s, txn->status, NULL);
			req->analysers &= AN_REQ_FLT_END;
			stream_inc_http_req_ctr(s);
			proxy_inc_fe_req_ctr(sess->fe);
			HA_ATOMIC_ADD(&sess->fe->fe_counters.failed_req, 1);
			if (sess->listener->counters)
				HA_ATOMIC_ADD(&sess->listener->counters->failed_req, 1);

			if (!(s->flags & SF_FINST_MASK))
				s->flags |= SF_FINST_R;
			return 0;
		}

		/* 3: has the read timeout expired ? */
		else if (req->flags & CF_READ_TIMEOUT || tick_is_expired(req->analyse_exp, now_ms)) {
			if (!(s->flags & SF_ERR_MASK))
				s->flags |= SF_ERR_CLITO;

			if (txn->flags & TX_WAIT_NEXT_RQ)
				goto failed_keep_alive;

			if (sess->fe->options & PR_O_IGNORE_PRB)
				goto failed_keep_alive;

			/* read timeout : give up with an error message. */
			if (msg->err_pos >= 0) {
				http_capture_bad_message(sess->fe, s, msg, msg->err_state, sess->fe);
				stream_inc_http_err_ctr(s);
			}
			txn->status = 408;
			msg->err_state = msg->msg_state;
			msg->msg_state = HTTP_MSG_ERROR;
			http_reply_and_close(s, txn->status, http_error_message(s));
			req->analysers &= AN_REQ_FLT_END;

			stream_inc_http_req_ctr(s);
			proxy_inc_fe_req_ctr(sess->fe);
			HA_ATOMIC_ADD(&sess->fe->fe_counters.failed_req, 1);
			if (sess->listener->counters)
				HA_ATOMIC_ADD(&sess->listener->counters->failed_req, 1);

			if (!(s->flags & SF_FINST_MASK))
				s->flags |= SF_FINST_R;
			return 0;
		}

		/* 4: have we encountered a close ? */
		else if (req->flags & CF_SHUTR) {
			if (!(s->flags & SF_ERR_MASK))
				s->flags |= SF_ERR_CLICL;

			if (txn->flags & TX_WAIT_NEXT_RQ)
				goto failed_keep_alive;

			if (sess->fe->options & PR_O_IGNORE_PRB)
				goto failed_keep_alive;

			if (msg->err_pos >= 0)
				http_capture_bad_message(sess->fe, s, msg, msg->err_state, sess->fe);
			txn->status = 400;
			msg->err_state = msg->msg_state;
			msg->msg_state = HTTP_MSG_ERROR;
			http_reply_and_close(s, txn->status, http_error_message(s));
			req->analysers &= AN_REQ_FLT_END;
			stream_inc_http_err_ctr(s);
			stream_inc_http_req_ctr(s);
			proxy_inc_fe_req_ctr(sess->fe);
			HA_ATOMIC_ADD(&sess->fe->fe_counters.failed_req, 1);
			if (sess->listener->counters)
				HA_ATOMIC_ADD(&sess->listener->counters->failed_req, 1);

			if (!(s->flags & SF_FINST_MASK))
				s->flags |= SF_FINST_R;
			return 0;
		}

		channel_dont_connect(req);
		req->flags |= CF_READ_DONTWAIT; /* try to get back here ASAP */
		s->res.flags &= ~CF_EXPECT_MORE; /* speed up sending a previous response */
#ifdef TCP_QUICKACK
		if (sess->listener->options & LI_O_NOQUICKACK && ci_data(req) &&
		    objt_conn(sess->origin) && conn_ctrl_ready(__objt_conn(sess->origin))) {
			/* We need more data, we have to re-enable quick-ack in case we
			 * previously disabled it, otherwise we might cause the client
			 * to delay next data.
			 */
			setsockopt(__objt_conn(sess->origin)->handle.fd, IPPROTO_TCP, TCP_QUICKACK, &one, sizeof(one));
		}
#endif

		if ((msg->msg_state != HTTP_MSG_RQBEFORE) && (txn->flags & TX_WAIT_NEXT_RQ)) {
			/* If the client starts to talk, let's fall back to
			 * request timeout processing.
			 */
			txn->flags &= ~TX_WAIT_NEXT_RQ;
			req->analyse_exp = TICK_ETERNITY;
		}

		/* just set the request timeout once at the beginning of the request */
		if (!tick_isset(req->analyse_exp)) {
			if ((msg->msg_state == HTTP_MSG_RQBEFORE) &&
			    (txn->flags & TX_WAIT_NEXT_RQ) &&
			    tick_isset(s->be->timeout.httpka))
				req->analyse_exp = tick_add(now_ms, s->be->timeout.httpka);
			else
				req->analyse_exp = tick_add_ifset(now_ms, s->be->timeout.httpreq);
		}

		/* we're not ready yet */
		return 0;

	failed_keep_alive:
		/* Here we process low-level errors for keep-alive requests. In
		 * short, if the request is not the first one and it experiences
		 * a timeout, read error or shutdown, we just silently close so
		 * that the client can try again.
		 */
		txn->status = 0;
		msg->msg_state = HTTP_MSG_RQBEFORE;
		req->analysers &= AN_REQ_FLT_END;
		s->logs.logwait = 0;
		s->logs.level = 0;
		s->res.flags &= ~CF_EXPECT_MORE; /* speed up sending a previous response */
		http_reply_and_close(s, txn->status, NULL);
		return 0;
	}

	/* OK now we have a complete HTTP request with indexed headers. Let's
	 * complete the request parsing by setting a few fields we will need
	 * later. At this point, we have the last CRLF at req->buf.data + msg->eoh.
	 * If the request is in HTTP/0.9 form, the rule is still true, and eoh
	 * points to the CRLF of the request line. msg->next points to the first
	 * byte after the last LF. msg->sov points to the first byte of data.
	 * msg->eol cannot be trusted because it may have been left uninitialized
	 * (for instance in the absence of headers).
	 */

	stream_inc_http_req_ctr(s);
	proxy_inc_fe_req_ctr(sess->fe); /* one more valid request for this FE */

	if (txn->flags & TX_WAIT_NEXT_RQ) {
		/* kill the pending keep-alive timeout */
		txn->flags &= ~TX_WAIT_NEXT_RQ;
		req->analyse_exp = TICK_ETERNITY;
	}


	/* Maybe we found in invalid header name while we were configured not
	 * to block on that, so we have to capture it now.
	 */
	if (unlikely(msg->err_pos >= 0))
		http_capture_bad_message(sess->fe, s, msg, msg->err_state, sess->fe);

	/*
	 * 1: identify the method
	 */
	txn->meth = find_http_meth(ci_head(req), msg->sl.rq.m_l);

	/* we can make use of server redirect on GET and HEAD */
	if (txn->meth == HTTP_METH_GET || txn->meth == HTTP_METH_HEAD)
		s->flags |= SF_REDIRECTABLE;
	else if (txn->meth == HTTP_METH_OTHER &&
		 msg->sl.rq.m_l == 3 && memcmp(ci_head(req), "PRI", 3) == 0) {
		/* PRI is reserved for the HTTP/2 preface */
		msg->err_pos = 0;
		goto return_bad_req;
	}

	/*
	 * 2: check if the URI matches the monitor_uri.
	 * We have to do this for every request which gets in, because
	 * the monitor-uri is defined by the frontend.
	 */
	if (unlikely((sess->fe->monitor_uri_len != 0) &&
		     (sess->fe->monitor_uri_len == msg->sl.rq.u_l) &&
		     !memcmp(ci_head(req) + msg->sl.rq.u,
			     sess->fe->monitor_uri,
			     sess->fe->monitor_uri_len))) {
		/*
		 * We have found the monitor URI
		 */
		struct acl_cond *cond;

		s->flags |= SF_MONITOR;
		HA_ATOMIC_ADD(&sess->fe->fe_counters.intercepted_req, 1);

		/* Check if we want to fail this monitor request or not */
		list_for_each_entry(cond, &sess->fe->mon_fail_cond, list) {
			int ret = acl_exec_cond(cond, sess->fe, sess, s, SMP_OPT_DIR_REQ|SMP_OPT_FINAL);

			ret = acl_pass(ret);
			if (cond->pol == ACL_COND_UNLESS)
				ret = !ret;

			if (ret) {
				/* we fail this request, let's return 503 service unavail */
				txn->status = 503;
				http_reply_and_close(s, txn->status, http_error_message(s));
				if (!(s->flags & SF_ERR_MASK))
					s->flags |= SF_ERR_LOCAL; /* we don't want a real error here */
				goto return_prx_cond;
			}
		}

		/* nothing to fail, let's reply normaly */
		txn->status = 200;
		http_reply_and_close(s, txn->status, http_error_message(s));
		if (!(s->flags & SF_ERR_MASK))
			s->flags |= SF_ERR_LOCAL; /* we don't want a real error here */
		goto return_prx_cond;
	}

	/*
	 * 3: Maybe we have to copy the original REQURI for the logs ?
	 * Note: we cannot log anymore if the request has been
	 * classified as invalid.
	 */
	if (unlikely(s->logs.logwait & LW_REQ)) {
		/* we have a complete HTTP request that we must log */
		if ((txn->uri = pool_alloc(pool_head_requri)) != NULL) {
			int urilen = msg->sl.rq.l;

			if (urilen >= global.tune.requri_len )
				urilen = global.tune.requri_len - 1;
			memcpy(txn->uri, ci_head(req), urilen);
			txn->uri[urilen] = 0;

			if (!(s->logs.logwait &= ~(LW_REQ|LW_INIT)))
				s->do_log(s);
		} else {
			ha_alert("HTTP logging : out of memory.\n");
		}
	}

	/* RFC7230#2.6 has enforced the format of the HTTP version string to be
	 * exactly one digit "." one digit. This check may be disabled using
	 * option accept-invalid-http-request.
	 */
	if (!(sess->fe->options2 & PR_O2_REQBUG_OK)) {
		if (msg->sl.rq.v_l != 8) {
			msg->err_pos = msg->sl.rq.v;
			goto return_bad_req;
		}

		if (ci_head(req)[msg->sl.rq.v + 4] != '/' ||
		    !isdigit((unsigned char)ci_head(req)[msg->sl.rq.v + 5]) ||
		    ci_head(req)[msg->sl.rq.v + 6] != '.' ||
		    !isdigit((unsigned char)ci_head(req)[msg->sl.rq.v + 7])) {
			msg->err_pos = msg->sl.rq.v + 4;
			goto return_bad_req;
		}
	}
	else {
		/* 4. We may have to convert HTTP/0.9 requests to HTTP/1.0 */
		if (unlikely(msg->sl.rq.v_l == 0) && !http_upgrade_v09_to_v10(txn))
			goto return_bad_req;
	}

	/* ... and check if the request is HTTP/1.1 or above */
	if ((msg->sl.rq.v_l == 8) &&
	    ((ci_head(req)[msg->sl.rq.v + 5] > '1') ||
	     ((ci_head(req)[msg->sl.rq.v + 5] == '1') &&
	      (ci_head(req)[msg->sl.rq.v + 7] >= '1'))))
		msg->flags |= HTTP_MSGF_VER_11;

	/* "connection" has not been parsed yet */
	txn->flags &= ~(TX_HDR_CONN_PRS | TX_HDR_CONN_CLO | TX_HDR_CONN_KAL | TX_HDR_CONN_UPG);

	/* if the frontend has "option http-use-proxy-header", we'll check if
	 * we have what looks like a proxied connection instead of a connection,
	 * and in this case set the TX_USE_PX_CONN flag to use Proxy-connection.
	 * Note that this is *not* RFC-compliant, however browsers and proxies
	 * happen to do that despite being non-standard :-(
	 * We consider that a request not beginning with either '/' or '*' is
	 * a proxied connection, which covers both "scheme://location" and
	 * CONNECT ip:port.
	 */
	if ((sess->fe->options2 & PR_O2_USE_PXHDR) &&
	    ci_head(req)[msg->sl.rq.u] != '/' && ci_head(req)[msg->sl.rq.u] != '*')
		txn->flags |= TX_USE_PX_CONN;

	/* transfer length unknown*/
	msg->flags &= ~HTTP_MSGF_XFER_LEN;

	/* 5: we may need to capture headers */
	if (unlikely((s->logs.logwait & LW_REQHDR) && s->req_cap))
		http_capture_headers(ci_head(req), &txn->hdr_idx,
				     s->req_cap, sess->fe->req_cap);

	/* 6: determine the transfer-length according to RFC2616 #4.4, updated
	 * by RFC7230#3.3.3 :
	 *
	 * The length of a message body is determined by one of the following
	 *   (in order of precedence):
	 *
	 *   1.  Any response to a HEAD request and any response with a 1xx
	 *       (Informational), 204 (No Content), or 304 (Not Modified) status
	 *       code is always terminated by the first empty line after the
	 *       header fields, regardless of the header fields present in the
	 *       message, and thus cannot contain a message body.
	 *
	 *   2.  Any 2xx (Successful) response to a CONNECT request implies that
	 *       the connection will become a tunnel immediately after the empty
	 *       line that concludes the header fields.  A client MUST ignore any
	 *       Content-Length or Transfer-Encoding header fields received in
	 *       such a message.
	 *
	 *   3.  If a Transfer-Encoding header field is present and the chunked
	 *       transfer coding (Section 4.1) is the final encoding, the message
	 *       body length is determined by reading and decoding the chunked
	 *       data until the transfer coding indicates the data is complete.
	 *
	 *       If a Transfer-Encoding header field is present in a response and
	 *       the chunked transfer coding is not the final encoding, the
	 *       message body length is determined by reading the connection until
	 *       it is closed by the server.  If a Transfer-Encoding header field
	 *       is present in a request and the chunked transfer coding is not
	 *       the final encoding, the message body length cannot be determined
	 *       reliably; the server MUST respond with the 400 (Bad Request)
	 *       status code and then close the connection.
	 *
	 *       If a message is received with both a Transfer-Encoding and a
	 *       Content-Length header field, the Transfer-Encoding overrides the
	 *       Content-Length.  Such a message might indicate an attempt to
	 *       perform request smuggling (Section 9.5) or response splitting
	 *       (Section 9.4) and ought to be handled as an error.  A sender MUST
	 *       remove the received Content-Length field prior to forwarding such
	 *       a message downstream.
	 *
	 *   4.  If a message is received without Transfer-Encoding and with
	 *       either multiple Content-Length header fields having differing
	 *       field-values or a single Content-Length header field having an
	 *       invalid value, then the message framing is invalid and the
	 *       recipient MUST treat it as an unrecoverable error.  If this is a
	 *       request message, the server MUST respond with a 400 (Bad Request)
	 *       status code and then close the connection.  If this is a response
	 *       message received by a proxy, the proxy MUST close the connection
	 *       to the server, discard the received response, and send a 502 (Bad
	 *       Gateway) response to the client.  If this is a response message
	 *       received by a user agent, the user agent MUST close the
	 *       connection to the server and discard the received response.
	 *
	 *   5.  If a valid Content-Length header field is present without
	 *       Transfer-Encoding, its decimal value defines the expected message
	 *       body length in octets.  If the sender closes the connection or
	 *       the recipient times out before the indicated number of octets are
	 *       received, the recipient MUST consider the message to be
	 *       incomplete and close the connection.
	 *
	 *   6.  If this is a request message and none of the above are true, then
	 *       the message body length is zero (no message body is present).
	 *
	 *   7.  Otherwise, this is a response message without a declared message
	 *       body length, so the message body length is determined by the
	 *       number of octets received prior to the server closing the
	 *       connection.
	 */

	ctx.idx = 0;
	/* set TE_CHNK and XFER_LEN only if "chunked" is seen last */
	while (http_find_header2("Transfer-Encoding", 17, ci_head(req), &txn->hdr_idx, &ctx)) {
		if (ctx.vlen == 7 && strncasecmp(ctx.line + ctx.val, "chunked", 7) == 0)
			msg->flags |= HTTP_MSGF_TE_CHNK;
		else if (msg->flags & HTTP_MSGF_TE_CHNK) {
			/* chunked not last, return badreq */
			goto return_bad_req;
		}
	}

	/* Chunked requests must have their content-length removed */
	ctx.idx = 0;
	if (msg->flags & HTTP_MSGF_TE_CHNK) {
		while (http_find_header2("Content-Length", 14, ci_head(req), &txn->hdr_idx, &ctx))
			http_remove_header2(msg, &txn->hdr_idx, &ctx);
	}
	else while (http_find_header2("Content-Length", 14, ci_head(req), &txn->hdr_idx, &ctx)) {
		signed long long cl;

		if (!ctx.vlen) {
			msg->err_pos = ctx.line + ctx.val - ci_head(req);
			goto return_bad_req;
		}

		if (strl2llrc(ctx.line + ctx.val, ctx.vlen, &cl)) {
			msg->err_pos = ctx.line + ctx.val - ci_head(req);
			goto return_bad_req; /* parse failure */
		}

		if (cl < 0) {
			msg->err_pos = ctx.line + ctx.val - ci_head(req);
			goto return_bad_req;
		}

		if ((msg->flags & HTTP_MSGF_CNT_LEN) && (msg->chunk_len != cl)) {
			msg->err_pos = ctx.line + ctx.val - ci_head(req);
			goto return_bad_req; /* already specified, was different */
		}

		msg->flags |= HTTP_MSGF_CNT_LEN;
		msg->body_len = msg->chunk_len = cl;
	}

	/* even bodyless requests have a known length */
	msg->flags |= HTTP_MSGF_XFER_LEN;

	/* Until set to anything else, the connection mode is set as Keep-Alive. It will
	 * only change if both the request and the config reference something else.
	 * Option httpclose by itself sets tunnel mode where headers are mangled.
	 * However, if another mode is set, it will affect it (eg: server-close/
	 * keep-alive + httpclose = close). Note that we avoid to redo the same work
	 * if FE and BE have the same settings (common). The method consists in
	 * checking if options changed between the two calls (implying that either
	 * one is non-null, or one of them is non-null and we are there for the first
	 * time.
	 */
	if (!(txn->flags & TX_HDR_CONN_PRS) ||
	    ((sess->fe->options & PR_O_HTTP_MODE) != (s->be->options & PR_O_HTTP_MODE)))
		http_adjust_conn_mode(s, txn, msg);

	/* we may have to wait for the request's body */
	if ((s->be->options & PR_O_WREQ_BODY) &&
	    (msg->body_len || (msg->flags & HTTP_MSGF_TE_CHNK)))
		req->analysers |= AN_REQ_HTTP_BODY;

	/*
	 * RFC7234#4:
	 *   A cache MUST write through requests with methods
	 *   that are unsafe (Section 4.2.1 of [RFC7231]) to
	 *   the origin server; i.e., a cache is not allowed
	 *   to generate a reply to such a request before
	 *   having forwarded the request and having received
	 *   a corresponding response.
	 *
	 * RFC7231#4.2.1:
	 *   Of the request methods defined by this
	 *   specification, the GET, HEAD, OPTIONS, and TRACE
	 *   methods are defined to be safe.
	 */
	if (likely(txn->meth == HTTP_METH_GET ||
		   txn->meth == HTTP_METH_HEAD ||
		   txn->meth == HTTP_METH_OPTIONS ||
		   txn->meth == HTTP_METH_TRACE))
		txn->flags |= TX_CACHEABLE | TX_CACHE_COOK;

	/* end of job, return OK */
	req->analysers &= ~an_bit;
	req->analyse_exp = TICK_ETERNITY;
	return 1;

 return_bad_req:
	/* We centralize bad requests processing here */
	if (unlikely(msg->msg_state == HTTP_MSG_ERROR) || msg->err_pos >= 0) {
		/* we detected a parsing error. We want to archive this request
		 * in the dedicated proxy area for later troubleshooting.
		 */
		http_capture_bad_message(sess->fe, s, msg, msg->err_state, sess->fe);
	}

	txn->req.err_state = txn->req.msg_state;
	txn->req.msg_state = HTTP_MSG_ERROR;
	txn->status = 400;
	http_reply_and_close(s, txn->status, http_error_message(s));

	HA_ATOMIC_ADD(&sess->fe->fe_counters.failed_req, 1);
	if (sess->listener->counters)
		HA_ATOMIC_ADD(&sess->listener->counters->failed_req, 1);

 return_prx_cond:
	if (!(s->flags & SF_ERR_MASK))
		s->flags |= SF_ERR_PRXCOND;
	if (!(s->flags & SF_FINST_MASK))
		s->flags |= SF_FINST_R;

	req->analysers &= AN_REQ_FLT_END;
	req->analyse_exp = TICK_ETERNITY;
	return 0;
}


/* This stream analyser runs all HTTP request processing which is common to
 * frontends and backends, which means blocking ACLs, filters, connection-close,
 * reqadd, stats and redirects. This is performed for the designated proxy.
 * It returns 1 if the processing can continue on next analysers, or zero if it
 * either needs more data or wants to immediately abort the request (eg: deny,
 * error, ...).
 */
int htx_process_req_common(struct stream *s, struct channel *req, int an_bit, struct proxy *px)
{
	struct session *sess = s->sess;
	struct http_txn *txn = s->txn;
	struct http_msg *msg = &txn->req;
	struct redirect_rule *rule;
	struct cond_wordlist *wl;
	enum rule_result verdict;
	int deny_status = HTTP_ERR_403;
	struct connection *conn = objt_conn(sess->origin);

	if (unlikely(msg->msg_state < HTTP_MSG_BODY)) {
		/* we need more data */
		goto return_prx_yield;
	}

	DPRINTF(stderr,"[%u] %s: stream=%p b=%p, exp(r,w)=%u,%u bf=%08x bh=%lu analysers=%02x\n",
		now_ms, __FUNCTION__,
		s,
		req,
		req->rex, req->wex,
		req->flags,
		ci_data(req),
		req->analysers);

	/* just in case we have some per-backend tracking */
	stream_inc_be_http_req_ctr(s);

	/* evaluate http-request rules */
	if (!LIST_ISEMPTY(&px->http_req_rules)) {
		verdict = http_req_get_intercept_rule(px, &px->http_req_rules, s, &deny_status);

		switch (verdict) {
		case HTTP_RULE_RES_YIELD: /* some data miss, call the function later. */
			goto return_prx_yield;

		case HTTP_RULE_RES_CONT:
		case HTTP_RULE_RES_STOP: /* nothing to do */
			break;

		case HTTP_RULE_RES_DENY: /* deny or tarpit */
			if (txn->flags & TX_CLTARPIT)
				goto tarpit;
			goto deny;

		case HTTP_RULE_RES_ABRT: /* abort request, response already sent. Eg: auth */
			goto return_prx_cond;

		case HTTP_RULE_RES_DONE: /* OK, but terminate request processing (eg: redirect) */
			goto done;

		case HTTP_RULE_RES_BADREQ: /* failed with a bad request */
			goto return_bad_req;
		}
	}

	if (conn && (conn->flags & CO_FL_EARLY_DATA) &&
	    (conn->flags & (CO_FL_EARLY_SSL_HS | CO_FL_HANDSHAKE))) {
		struct hdr_ctx ctx;

		ctx.idx = 0;
		if (!http_find_header2("Early-Data", strlen("Early-Data"),
		    ci_head(&s->req), &txn->hdr_idx, &ctx)) {
			if (unlikely(http_header_add_tail2(&txn->req,
			    &txn->hdr_idx, "Early-Data: 1",
			    strlen("Early-Data: 1")) < 0)) {
				goto return_bad_req;
			 }
		}

	}

	/* OK at this stage, we know that the request was accepted according to
	 * the http-request rules, we can check for the stats. Note that the
	 * URI is detected *before* the req* rules in order not to be affected
	 * by a possible reqrep, while they are processed *after* so that a
	 * reqdeny can still block them. This clearly needs to change in 1.6!
	 */
	if (stats_check_uri(&s->si[1], txn, px)) {
		s->target = &http_stats_applet.obj_type;
		if (unlikely(!stream_int_register_handler(&s->si[1], objt_applet(s->target)))) {
			txn->status = 500;
			s->logs.tv_request = now;
			http_reply_and_close(s, txn->status, http_error_message(s));

			if (!(s->flags & SF_ERR_MASK))
				s->flags |= SF_ERR_RESOURCE;
			goto return_prx_cond;
		}

		/* parse the whole stats request and extract the relevant information */
		http_handle_stats(s, req);
		verdict = http_req_get_intercept_rule(px, &px->uri_auth->http_req_rules, s, &deny_status);
		/* not all actions implemented: deny, allow, auth */

		if (verdict == HTTP_RULE_RES_DENY) /* stats http-request deny */
			goto deny;

		if (verdict == HTTP_RULE_RES_ABRT) /* stats auth / stats http-request auth */
			goto return_prx_cond;
	}

	/* evaluate the req* rules except reqadd */
	if (px->req_exp != NULL) {
		if (apply_filters_to_request(s, req, px) < 0)
			goto return_bad_req;

		if (txn->flags & TX_CLDENY)
			goto deny;

		if (txn->flags & TX_CLTARPIT) {
			deny_status = HTTP_ERR_500;
			goto tarpit;
		}
	}

	/* add request headers from the rule sets in the same order */
	list_for_each_entry(wl, &px->req_add, list) {
		if (wl->cond) {
			int ret = acl_exec_cond(wl->cond, px, sess, s, SMP_OPT_DIR_REQ|SMP_OPT_FINAL);
			ret = acl_pass(ret);
			if (((struct acl_cond *)wl->cond)->pol == ACL_COND_UNLESS)
				ret = !ret;
			if (!ret)
				continue;
		}

		if (unlikely(http_header_add_tail2(&txn->req, &txn->hdr_idx, wl->s, strlen(wl->s)) < 0))
			goto return_bad_req;
	}


	/* Proceed with the stats now. */
	if (unlikely(objt_applet(s->target) == &http_stats_applet) ||
	    unlikely(objt_applet(s->target) == &http_cache_applet)) {
		/* process the stats request now */
		if (sess->fe == s->be) /* report it if the request was intercepted by the frontend */
			HA_ATOMIC_ADD(&sess->fe->fe_counters.intercepted_req, 1);

		if (!(s->flags & SF_ERR_MASK))      // this is not really an error but it is
			s->flags |= SF_ERR_LOCAL;   // to mark that it comes from the proxy
		if (!(s->flags & SF_FINST_MASK))
			s->flags |= SF_FINST_R;

		/* enable the minimally required analyzers to handle keep-alive and compression on the HTTP response */
		req->analysers &= (AN_REQ_HTTP_BODY | AN_REQ_FLT_HTTP_HDRS | AN_REQ_FLT_END);
		req->analysers &= ~AN_REQ_FLT_XFER_DATA;
		req->analysers |= AN_REQ_HTTP_XFER_BODY;
		goto done;
	}

	/* check whether we have some ACLs set to redirect this request */
	list_for_each_entry(rule, &px->redirect_rules, list) {
		if (rule->cond) {
			int ret;

			ret = acl_exec_cond(rule->cond, px, sess, s, SMP_OPT_DIR_REQ|SMP_OPT_FINAL);
			ret = acl_pass(ret);
			if (rule->cond->pol == ACL_COND_UNLESS)
				ret = !ret;
			if (!ret)
				continue;
		}
		if (!http_apply_redirect_rule(rule, s, txn))
			goto return_bad_req;
		goto done;
	}

	/* POST requests may be accompanied with an "Expect: 100-Continue" header.
	 * If this happens, then the data will not come immediately, so we must
	 * send all what we have without waiting. Note that due to the small gain
	 * in waiting for the body of the request, it's easier to simply put the
	 * CF_SEND_DONTWAIT flag any time. It's a one-shot flag so it will remove
	 * itself once used.
	 */
	req->flags |= CF_SEND_DONTWAIT;

 done:	/* done with this analyser, continue with next ones that the calling
	 * points will have set, if any.
	 */
	req->analyse_exp = TICK_ETERNITY;
 done_without_exp: /* done with this analyser, but dont reset the analyse_exp. */
	req->analysers &= ~an_bit;
	return 1;

 tarpit:
	/* Allow cookie logging
	 */
	if (s->be->cookie_name || sess->fe->capture_name)
		manage_client_side_cookies(s, req);

	/* When a connection is tarpitted, we use the tarpit timeout,
	 * which may be the same as the connect timeout if unspecified.
	 * If unset, then set it to zero because we really want it to
	 * eventually expire. We build the tarpit as an analyser.
	 */
	channel_erase(&s->req);

	/* wipe the request out so that we can drop the connection early
	 * if the client closes first.
	 */
	channel_dont_connect(req);

	txn->status = http_err_codes[deny_status];

	req->analysers &= AN_REQ_FLT_END; /* remove switching rules etc... */
	req->analysers |= AN_REQ_HTTP_TARPIT;
	req->analyse_exp = tick_add_ifset(now_ms,  s->be->timeout.tarpit);
	if (!req->analyse_exp)
		req->analyse_exp = tick_add(now_ms, 0);
	stream_inc_http_err_ctr(s);
	HA_ATOMIC_ADD(&sess->fe->fe_counters.denied_req, 1);
	if (sess->fe != s->be)
		HA_ATOMIC_ADD(&s->be->be_counters.denied_req, 1);
	if (sess->listener->counters)
		HA_ATOMIC_ADD(&sess->listener->counters->denied_req, 1);
	goto done_without_exp;

 deny:	/* this request was blocked (denied) */

	/* Allow cookie logging
	 */
	if (s->be->cookie_name || sess->fe->capture_name)
		manage_client_side_cookies(s, req);

	txn->flags |= TX_CLDENY;
	txn->status = http_err_codes[deny_status];
	s->logs.tv_request = now;
	http_reply_and_close(s, txn->status, http_error_message(s));
	stream_inc_http_err_ctr(s);
	HA_ATOMIC_ADD(&sess->fe->fe_counters.denied_req, 1);
	if (sess->fe != s->be)
		HA_ATOMIC_ADD(&s->be->be_counters.denied_req, 1);
	if (sess->listener->counters)
		HA_ATOMIC_ADD(&sess->listener->counters->denied_req, 1);
	goto return_prx_cond;

 return_bad_req:
	/* We centralize bad requests processing here */
	if (unlikely(msg->msg_state == HTTP_MSG_ERROR) || msg->err_pos >= 0) {
		/* we detected a parsing error. We want to archive this request
		 * in the dedicated proxy area for later troubleshooting.
		 */
		http_capture_bad_message(sess->fe, s, msg, msg->err_state, sess->fe);
	}

	txn->req.err_state = txn->req.msg_state;
	txn->req.msg_state = HTTP_MSG_ERROR;
	txn->status = 400;
	http_reply_and_close(s, txn->status, http_error_message(s));

	HA_ATOMIC_ADD(&sess->fe->fe_counters.failed_req, 1);
	if (sess->listener->counters)
		HA_ATOMIC_ADD(&sess->listener->counters->failed_req, 1);

 return_prx_cond:
	if (!(s->flags & SF_ERR_MASK))
		s->flags |= SF_ERR_PRXCOND;
	if (!(s->flags & SF_FINST_MASK))
		s->flags |= SF_FINST_R;

	req->analysers &= AN_REQ_FLT_END;
	req->analyse_exp = TICK_ETERNITY;
	return 0;

 return_prx_yield:
	channel_dont_connect(req);
	return 0;
}

/* This function performs all the processing enabled for the current request.
 * It returns 1 if the processing can continue on next analysers, or zero if it
 * needs more data, encounters an error, or wants to immediately abort the
 * request. It relies on buffers flags, and updates s->req.analysers.
 */
int htx_process_request(struct stream *s, struct channel *req, int an_bit)
{
	struct session *sess = s->sess;
	struct http_txn *txn = s->txn;
	struct http_msg *msg = &txn->req;
	struct connection *cli_conn = objt_conn(strm_sess(s)->origin);

	if (unlikely(msg->msg_state < HTTP_MSG_BODY)) {
		/* we need more data */
		channel_dont_connect(req);
		return 0;
	}

	DPRINTF(stderr,"[%u] %s: stream=%p b=%p, exp(r,w)=%u,%u bf=%08x bh=%lu analysers=%02x\n",
		now_ms, __FUNCTION__,
		s,
		req,
		req->rex, req->wex,
		req->flags,
		ci_data(req),
		req->analysers);

	/*
	 * Right now, we know that we have processed the entire headers
	 * and that unwanted requests have been filtered out. We can do
	 * whatever we want with the remaining request. Also, now we
	 * may have separate values for ->fe, ->be.
	 */

	/*
	 * If HTTP PROXY is set we simply get remote server address parsing
	 * incoming request. Note that this requires that a connection is
	 * allocated on the server side.
	 */
	if ((s->be->options & PR_O_HTTP_PROXY) && !(s->flags & SF_ADDR_SET)) {
		struct connection *conn;
		char *path;

		/* Note that for now we don't reuse existing proxy connections */
		if (unlikely((conn = cs_conn(si_alloc_cs(&s->si[1], NULL))) == NULL)) {
			txn->req.err_state = txn->req.msg_state;
			txn->req.msg_state = HTTP_MSG_ERROR;
			txn->status = 500;
			req->analysers &= AN_REQ_FLT_END;
			http_reply_and_close(s, txn->status, http_error_message(s));

			if (!(s->flags & SF_ERR_MASK))
				s->flags |= SF_ERR_RESOURCE;
			if (!(s->flags & SF_FINST_MASK))
				s->flags |= SF_FINST_R;

			return 0;
		}

		path = http_txn_get_path(txn);
		if (url2sa(ci_head(req) + msg->sl.rq.u,
			   path ? path - (ci_head(req) + msg->sl.rq.u) : msg->sl.rq.u_l,
			   &conn->addr.to, NULL) == -1)
			goto return_bad_req;

		/* if the path was found, we have to remove everything between
		 * ci_head(req) + msg->sl.rq.u and path (excluded). If it was not
		 * found, we need to replace from ci_head(req) + msg->sl.rq.u for
		 * u_l characters by a single "/".
		 */
		if (path) {
			char *cur_ptr = ci_head(req);
			char *cur_end = cur_ptr + txn->req.sl.rq.l;
			int delta;

			delta = b_rep_blk(&req->buf, cur_ptr + msg->sl.rq.u, path, NULL, 0);
			http_msg_move_end(&txn->req, delta);
			cur_end += delta;
			if (http_parse_reqline(&txn->req, HTTP_MSG_RQMETH,  cur_ptr, cur_end + 1, NULL, NULL) == NULL)
				goto return_bad_req;
		}
		else {
			char *cur_ptr = ci_head(req);
			char *cur_end = cur_ptr + txn->req.sl.rq.l;
			int delta;

			delta = b_rep_blk(&req->buf, cur_ptr + msg->sl.rq.u,
						cur_ptr + msg->sl.rq.u + msg->sl.rq.u_l, "/", 1);
			http_msg_move_end(&txn->req, delta);
			cur_end += delta;
			if (http_parse_reqline(&txn->req, HTTP_MSG_RQMETH,  cur_ptr, cur_end + 1, NULL, NULL) == NULL)
				goto return_bad_req;
		}
	}

	/*
	 * 7: Now we can work with the cookies.
	 * Note that doing so might move headers in the request, but
	 * the fields will stay coherent and the URI will not move.
	 * This should only be performed in the backend.
	 */
	if (s->be->cookie_name || sess->fe->capture_name)
		manage_client_side_cookies(s, req);

	/* add unique-id if "header-unique-id" is specified */

	if (!LIST_ISEMPTY(&sess->fe->format_unique_id) && !s->unique_id) {
		if ((s->unique_id = pool_alloc(pool_head_uniqueid)) == NULL)
			goto return_bad_req;
		s->unique_id[0] = '\0';
		build_logline(s, s->unique_id, UNIQUEID_LEN, &sess->fe->format_unique_id);
	}

	if (sess->fe->header_unique_id && s->unique_id) {
		if (chunk_printf(&trash, "%s: %s", sess->fe->header_unique_id, s->unique_id) < 0)
			goto return_bad_req;
		if (unlikely(http_header_add_tail2(&txn->req, &txn->hdr_idx, trash.area, trash.data) < 0))
		   goto return_bad_req;
	}

	/*
	 * 9: add X-Forwarded-For if either the frontend or the backend
	 * asks for it.
	 */
	if ((sess->fe->options | s->be->options) & PR_O_FWDFOR) {
		struct hdr_ctx ctx = { .idx = 0 };
		if (!((sess->fe->options | s->be->options) & PR_O_FF_ALWAYS) &&
			http_find_header2(s->be->fwdfor_hdr_len ? s->be->fwdfor_hdr_name : sess->fe->fwdfor_hdr_name,
			                  s->be->fwdfor_hdr_len ? s->be->fwdfor_hdr_len : sess->fe->fwdfor_hdr_len,
			                  ci_head(req), &txn->hdr_idx, &ctx)) {
			/* The header is set to be added only if none is present
			 * and we found it, so don't do anything.
			 */
		}
		else if (cli_conn && cli_conn->addr.from.ss_family == AF_INET) {
			/* Add an X-Forwarded-For header unless the source IP is
			 * in the 'except' network range.
			 */
			if ((!sess->fe->except_mask.s_addr ||
			     (((struct sockaddr_in *)&cli_conn->addr.from)->sin_addr.s_addr & sess->fe->except_mask.s_addr)
			     != sess->fe->except_net.s_addr) &&
			    (!s->be->except_mask.s_addr ||
			     (((struct sockaddr_in *)&cli_conn->addr.from)->sin_addr.s_addr & s->be->except_mask.s_addr)
			     != s->be->except_net.s_addr)) {
				int len;
				unsigned char *pn;
				pn = (unsigned char *)&((struct sockaddr_in *)&cli_conn->addr.from)->sin_addr;

				/* Note: we rely on the backend to get the header name to be used for
				 * x-forwarded-for, because the header is really meant for the backends.
				 * However, if the backend did not specify any option, we have to rely
				 * on the frontend's header name.
				 */
				if (s->be->fwdfor_hdr_len) {
					len = s->be->fwdfor_hdr_len;
					memcpy(trash.area,
					       s->be->fwdfor_hdr_name, len);
				} else {
					len = sess->fe->fwdfor_hdr_len;
					memcpy(trash.area,
					       sess->fe->fwdfor_hdr_name, len);
				}
				len += snprintf(trash.area + len,
						trash.size - len,
						": %d.%d.%d.%d", pn[0], pn[1],
						pn[2], pn[3]);

				if (unlikely(http_header_add_tail2(&txn->req, &txn->hdr_idx, trash.area, len) < 0))
					goto return_bad_req;
			}
		}
		else if (cli_conn && cli_conn->addr.from.ss_family == AF_INET6) {
			/* FIXME: for the sake of completeness, we should also support
			 * 'except' here, although it is mostly useless in this case.
			 */
			int len;
			char pn[INET6_ADDRSTRLEN];
			inet_ntop(AF_INET6,
				  (const void *)&((struct sockaddr_in6 *)(&cli_conn->addr.from))->sin6_addr,
				  pn, sizeof(pn));

			/* Note: we rely on the backend to get the header name to be used for
			 * x-forwarded-for, because the header is really meant for the backends.
			 * However, if the backend did not specify any option, we have to rely
			 * on the frontend's header name.
			 */
			if (s->be->fwdfor_hdr_len) {
				len = s->be->fwdfor_hdr_len;
				memcpy(trash.area, s->be->fwdfor_hdr_name,
				       len);
			} else {
				len = sess->fe->fwdfor_hdr_len;
				memcpy(trash.area, sess->fe->fwdfor_hdr_name,
				       len);
			}
			len += snprintf(trash.area + len, trash.size - len,
					": %s", pn);

			if (unlikely(http_header_add_tail2(&txn->req, &txn->hdr_idx, trash.area, len) < 0))
				goto return_bad_req;
		}
	}

	/*
	 * 10: add X-Original-To if either the frontend or the backend
	 * asks for it.
	 */
	if ((sess->fe->options | s->be->options) & PR_O_ORGTO) {

		/* FIXME: don't know if IPv6 can handle that case too. */
		if (cli_conn && cli_conn->addr.from.ss_family == AF_INET) {
			/* Add an X-Original-To header unless the destination IP is
			 * in the 'except' network range.
			 */
			conn_get_to_addr(cli_conn);

			if (cli_conn->addr.to.ss_family == AF_INET &&
			    ((!sess->fe->except_mask_to.s_addr ||
			      (((struct sockaddr_in *)&cli_conn->addr.to)->sin_addr.s_addr & sess->fe->except_mask_to.s_addr)
			      != sess->fe->except_to.s_addr) &&
			     (!s->be->except_mask_to.s_addr ||
			      (((struct sockaddr_in *)&cli_conn->addr.to)->sin_addr.s_addr & s->be->except_mask_to.s_addr)
			      != s->be->except_to.s_addr))) {
				int len;
				unsigned char *pn;
				pn = (unsigned char *)&((struct sockaddr_in *)&cli_conn->addr.to)->sin_addr;

				/* Note: we rely on the backend to get the header name to be used for
				 * x-original-to, because the header is really meant for the backends.
				 * However, if the backend did not specify any option, we have to rely
				 * on the frontend's header name.
				 */
				if (s->be->orgto_hdr_len) {
					len = s->be->orgto_hdr_len;
					memcpy(trash.area,
					       s->be->orgto_hdr_name, len);
				} else {
					len = sess->fe->orgto_hdr_len;
					memcpy(trash.area,
					       sess->fe->orgto_hdr_name, len);
				}
				len += snprintf(trash.area + len,
						trash.size - len,
						": %d.%d.%d.%d", pn[0], pn[1],
						pn[2], pn[3]);

				if (unlikely(http_header_add_tail2(&txn->req, &txn->hdr_idx, trash.area, len) < 0))
					goto return_bad_req;
			}
		}
	}

	/* 11: add "Connection: close" or "Connection: keep-alive" if needed and not yet set.
	 * If an "Upgrade" token is found, the header is left untouched in order not to have
	 * to deal with some servers bugs : some of them fail an Upgrade if anything but
	 * "Upgrade" is present in the Connection header.
	 */
	if (!(txn->flags & TX_HDR_CONN_UPG) && (txn->flags & TX_CON_WANT_MSK) != TX_CON_WANT_TUN) {
		unsigned int want_flags = 0;

		if (msg->flags & HTTP_MSGF_VER_11) {
			if ((txn->flags & TX_CON_WANT_MSK) >= TX_CON_WANT_SCL &&
			    !((sess->fe->options2|s->be->options2) & PR_O2_FAKE_KA))
				want_flags |= TX_CON_CLO_SET;
		} else {
			if ((txn->flags & TX_CON_WANT_MSK) == TX_CON_WANT_KAL ||
			    ((sess->fe->options2|s->be->options2) & PR_O2_FAKE_KA))
				want_flags |= TX_CON_KAL_SET;
		}

		if (want_flags != (txn->flags & (TX_CON_CLO_SET|TX_CON_KAL_SET)))
			http_change_connection_header(txn, msg, want_flags);
	}


	/* If we have no server assigned yet and we're balancing on url_param
	 * with a POST request, we may be interested in checking the body for
	 * that parameter. This will be done in another analyser.
	 */
	if (!(s->flags & (SF_ASSIGNED|SF_DIRECT)) &&
	    s->txn->meth == HTTP_METH_POST && s->be->url_param_name != NULL &&
	    (msg->flags & (HTTP_MSGF_CNT_LEN|HTTP_MSGF_TE_CHNK))) {
		channel_dont_connect(req);
		req->analysers |= AN_REQ_HTTP_BODY;
	}

	req->analysers &= ~AN_REQ_FLT_XFER_DATA;
	req->analysers |= AN_REQ_HTTP_XFER_BODY;
#ifdef TCP_QUICKACK
	/* We expect some data from the client. Unless we know for sure
	 * we already have a full request, we have to re-enable quick-ack
	 * in case we previously disabled it, otherwise we might cause
	 * the client to delay further data.
	 */
	if ((sess->listener->options & LI_O_NOQUICKACK) &&
	    cli_conn && conn_ctrl_ready(cli_conn) &&
	    ((msg->flags & HTTP_MSGF_TE_CHNK) ||
	     (msg->body_len > ci_data(req) - txn->req.eoh - 2)))
		setsockopt(cli_conn->handle.fd, IPPROTO_TCP, TCP_QUICKACK, &one, sizeof(one));
#endif

	/*************************************************************
	 * OK, that's finished for the headers. We have done what we *
	 * could. Let's switch to the DATA state.                    *
	 ************************************************************/
	req->analyse_exp = TICK_ETERNITY;
	req->analysers &= ~an_bit;

	s->logs.tv_request = now;
	/* OK let's go on with the BODY now */
	return 1;

 return_bad_req: /* let's centralize all bad requests */
	if (unlikely(msg->msg_state == HTTP_MSG_ERROR) || msg->err_pos >= 0) {
		/* we detected a parsing error. We want to archive this request
		 * in the dedicated proxy area for later troubleshooting.
		 */
		http_capture_bad_message(sess->fe, s, msg, msg->err_state, sess->fe);
	}

	txn->req.err_state = txn->req.msg_state;
	txn->req.msg_state = HTTP_MSG_ERROR;
	txn->status = 400;
	req->analysers &= AN_REQ_FLT_END;
	http_reply_and_close(s, txn->status, http_error_message(s));

	HA_ATOMIC_ADD(&sess->fe->fe_counters.failed_req, 1);
	if (sess->listener->counters)
		HA_ATOMIC_ADD(&sess->listener->counters->failed_req, 1);

	if (!(s->flags & SF_ERR_MASK))
		s->flags |= SF_ERR_PRXCOND;
	if (!(s->flags & SF_FINST_MASK))
		s->flags |= SF_FINST_R;
	return 0;
}

/* This function is an analyser which processes the HTTP tarpit. It always
 * returns zero, at the beginning because it prevents any other processing
 * from occurring, and at the end because it terminates the request.
 */
int htx_process_tarpit(struct stream *s, struct channel *req, int an_bit)
{
	struct http_txn *txn = s->txn;

	/* This connection is being tarpitted. The CLIENT side has
	 * already set the connect expiration date to the right
	 * timeout. We just have to check that the client is still
	 * there and that the timeout has not expired.
	 */
	channel_dont_connect(req);
	if ((req->flags & (CF_SHUTR|CF_READ_ERROR)) == 0 &&
	    !tick_is_expired(req->analyse_exp, now_ms))
		return 0;

	/* We will set the queue timer to the time spent, just for
	 * logging purposes. We fake a 500 server error, so that the
	 * attacker will not suspect his connection has been tarpitted.
	 * It will not cause trouble to the logs because we can exclude
	 * the tarpitted connections by filtering on the 'PT' status flags.
	 */
	s->logs.t_queue = tv_ms_elapsed(&s->logs.tv_accept, &now);

	if (!(req->flags & CF_READ_ERROR))
		http_reply_and_close(s, txn->status, http_error_message(s));

	req->analysers &= AN_REQ_FLT_END;
	req->analyse_exp = TICK_ETERNITY;

	if (!(s->flags & SF_ERR_MASK))
		s->flags |= SF_ERR_PRXCOND;
	if (!(s->flags & SF_FINST_MASK))
		s->flags |= SF_FINST_T;
	return 0;
}

/* This function is an analyser which waits for the HTTP request body. It waits
 * for either the buffer to be full, or the full advertised contents to have
 * reached the buffer. It must only be called after the standard HTTP request
 * processing has occurred, because it expects the request to be parsed and will
 * look for the Expect header. It may send a 100-Continue interim response. It
 * takes in input any state starting from HTTP_MSG_BODY and leaves with one of
 * HTTP_MSG_CHK_SIZE, HTTP_MSG_DATA or HTTP_MSG_TRAILERS. It returns zero if it
 * needs to read more data, or 1 once it has completed its analysis.
 */
int htx_wait_for_request_body(struct stream *s, struct channel *req, int an_bit)
{
	struct session *sess = s->sess;
	struct http_txn *txn = s->txn;
	struct http_msg *msg = &s->txn->req;

	/* We have to parse the HTTP request body to find any required data.
	 * "balance url_param check_post" should have been the only way to get
	 * into this. We were brought here after HTTP header analysis, so all
	 * related structures are ready.
	 */

	if (msg->msg_state < HTTP_MSG_CHUNK_SIZE) {
		/* This is the first call */
		if (msg->msg_state < HTTP_MSG_BODY)
			goto missing_data;

		if (msg->msg_state < HTTP_MSG_100_SENT) {
			/* If we have HTTP/1.1 and Expect: 100-continue, then we must
			 * send an HTTP/1.1 100 Continue intermediate response.
			 */
			if (msg->flags & HTTP_MSGF_VER_11) {
				struct hdr_ctx ctx;
				ctx.idx = 0;
				/* Expect is allowed in 1.1, look for it */
				if (http_find_header2("Expect", 6, ci_head(req), &txn->hdr_idx, &ctx) &&
				    unlikely(ctx.vlen == 12 && strncasecmp(ctx.line+ctx.val, "100-continue", 12) == 0)) {
					co_inject(&s->res, HTTP_100.ptr, HTTP_100.len);
					http_remove_header2(&txn->req, &txn->hdr_idx, &ctx);
				}
			}
			msg->msg_state = HTTP_MSG_100_SENT;
		}

		/* we have msg->sov which points to the first byte of message body.
		 * ci_head(req) still points to the beginning of the message. We
		 * must save the body in msg->next because it survives buffer
		 * re-alignments.
		 */
		msg->next = msg->sov;

		if (msg->flags & HTTP_MSGF_TE_CHNK)
			msg->msg_state = HTTP_MSG_CHUNK_SIZE;
		else
			msg->msg_state = HTTP_MSG_DATA;
	}

	if (!(msg->flags & HTTP_MSGF_TE_CHNK)) {
		/* We're in content-length mode, we just have to wait for enough data. */
		if (http_body_bytes(msg) < msg->body_len)
			goto missing_data;

		/* OK we have everything we need now */
		goto http_end;
	}

	/* OK here we're parsing a chunked-encoded message */

	if (msg->msg_state == HTTP_MSG_CHUNK_SIZE) {
		/* read the chunk size and assign it to ->chunk_len, then
		 * set ->sov and ->next to point to the body and switch to DATA or
		 * TRAILERS state.
		 */
		unsigned int chunk;
		int ret = h1_parse_chunk_size(&req->buf, co_data(req) + msg->next, c_data(req), &chunk);

		if (!ret)
			goto missing_data;
		else if (ret < 0) {
			msg->err_pos = ci_data(req) + ret;
			if (msg->err_pos < 0)
				msg->err_pos += req->buf.size;
			stream_inc_http_err_ctr(s);
			goto return_bad_req;
		}

		msg->chunk_len = chunk;
		msg->body_len += chunk;

		msg->sol = ret;
		msg->next += ret;
		msg->msg_state = msg->chunk_len ? HTTP_MSG_DATA : HTTP_MSG_TRAILERS;
	}

	/* Now we're in HTTP_MSG_DATA or HTTP_MSG_TRAILERS state.
	 * We have the first data byte is in msg->sov + msg->sol. We're waiting
	 * for at least a whole chunk or the whole content length bytes after
	 * msg->sov + msg->sol.
	 */
	if (msg->msg_state == HTTP_MSG_TRAILERS)
		goto http_end;

	if (http_body_bytes(msg) >= msg->body_len)   /* we have enough bytes now */
		goto http_end;

 missing_data:
	/* we get here if we need to wait for more data. If the buffer is full,
	 * we have the maximum we can expect.
	 */
	if (channel_full(req, global.tune.maxrewrite))
		goto http_end;

	if ((req->flags & CF_READ_TIMEOUT) || tick_is_expired(req->analyse_exp, now_ms)) {
		txn->status = 408;
		http_reply_and_close(s, txn->status, http_error_message(s));

		if (!(s->flags & SF_ERR_MASK))
			s->flags |= SF_ERR_CLITO;
		if (!(s->flags & SF_FINST_MASK))
			s->flags |= SF_FINST_D;
		goto return_err_msg;
	}

	/* we get here if we need to wait for more data */
	if (!(req->flags & (CF_SHUTR | CF_READ_ERROR))) {
		/* Not enough data. We'll re-use the http-request
		 * timeout here. Ideally, we should set the timeout
		 * relative to the accept() date. We just set the
		 * request timeout once at the beginning of the
		 * request.
		 */
		channel_dont_connect(req);
		if (!tick_isset(req->analyse_exp))
			req->analyse_exp = tick_add_ifset(now_ms, s->be->timeout.httpreq);
		return 0;
	}

 http_end:
	/* The situation will not evolve, so let's give up on the analysis. */
	s->logs.tv_request = now;  /* update the request timer to reflect full request */
	req->analysers &= ~an_bit;
	req->analyse_exp = TICK_ETERNITY;
	return 1;

 return_bad_req: /* let's centralize all bad requests */
	txn->req.err_state = txn->req.msg_state;
	txn->req.msg_state = HTTP_MSG_ERROR;
	txn->status = 400;
	http_reply_and_close(s, txn->status, http_error_message(s));

	if (!(s->flags & SF_ERR_MASK))
		s->flags |= SF_ERR_PRXCOND;
	if (!(s->flags & SF_FINST_MASK))
		s->flags |= SF_FINST_R;

 return_err_msg:
	req->analysers &= AN_REQ_FLT_END;
	HA_ATOMIC_ADD(&sess->fe->fe_counters.failed_req, 1);
	if (sess->listener->counters)
		HA_ATOMIC_ADD(&sess->listener->counters->failed_req, 1);
	return 0;
}

/* This function is an analyser which forwards request body (including chunk
 * sizes if any). It is called as soon as we must forward, even if we forward
 * zero byte. The only situation where it must not be called is when we're in
 * tunnel mode and we want to forward till the close. It's used both to forward
 * remaining data and to resync after end of body. It expects the msg_state to
 * be between MSG_BODY and MSG_DONE (inclusive). It returns zero if it needs to
 * read more data, or 1 once we can go on with next request or end the stream.
 * When in MSG_DATA or MSG_TRAILERS, it will automatically forward chunk_len
 * bytes of pending data + the headers if not already done.
 */
int htx_request_forward_body(struct stream *s, struct channel *req, int an_bit)
{
	struct session *sess = s->sess;
	struct http_txn *txn = s->txn;
	struct http_msg *msg = &s->txn->req;
	int ret;

	DPRINTF(stderr,"[%u] %s: stream=%p b=%p, exp(r,w)=%u,%u bf=%08x bh=%lu analysers=%02x\n",
		now_ms, __FUNCTION__,
		s,
		req,
		req->rex, req->wex,
		req->flags,
		ci_data(req),
		req->analysers);

	if (unlikely(msg->msg_state < HTTP_MSG_BODY))
		return 0;

	if ((req->flags & (CF_READ_ERROR|CF_READ_TIMEOUT|CF_WRITE_ERROR|CF_WRITE_TIMEOUT)) ||
	    ((req->flags & CF_SHUTW) && (req->to_forward || co_data(req)))) {
		/* Output closed while we were sending data. We must abort and
		 * wake the other side up.
		 */
		msg->err_state = msg->msg_state;
		msg->msg_state = HTTP_MSG_ERROR;
		http_resync_states(s);
		return 1;
	}

	/* Note that we don't have to send 100-continue back because we don't
	 * need the data to complete our job, and it's up to the server to
	 * decide whether to return 100, 417 or anything else in return of
	 * an "Expect: 100-continue" header.
	 */
	if (msg->msg_state == HTTP_MSG_BODY) {
		msg->msg_state = ((msg->flags & HTTP_MSGF_TE_CHNK)
				  ? HTTP_MSG_CHUNK_SIZE
				  : HTTP_MSG_DATA);

		/* TODO/filters: when http-buffer-request option is set or if a
		 * rule on url_param exists, the first chunk size could be
		 * already parsed. In that case, msg->next is after the chunk
		 * size (including the CRLF after the size). So this case should
		 * be handled to */
	}

	/* Some post-connect processing might want us to refrain from starting to
	 * forward data. Currently, the only reason for this is "balance url_param"
	 * whichs need to parse/process the request after we've enabled forwarding.
	 */
	if (unlikely(msg->flags & HTTP_MSGF_WAIT_CONN)) {
		if (!(s->res.flags & CF_READ_ATTACHED)) {
			channel_auto_connect(req);
			req->flags |= CF_WAKE_CONNECT;
			channel_dont_close(req); /* don't fail on early shutr */
			goto waiting;
		}
		msg->flags &= ~HTTP_MSGF_WAIT_CONN;
	}

	/* in most states, we should abort in case of early close */
	channel_auto_close(req);

	if (req->to_forward) {
		/* We can't process the buffer's contents yet */
		req->flags |= CF_WAKE_WRITE;
		goto missing_data_or_waiting;
	}

	if (msg->msg_state < HTTP_MSG_DONE) {
		ret = ((msg->flags & HTTP_MSGF_TE_CHNK)
		       ? http_msg_forward_chunked_body(s, msg)
		       : http_msg_forward_body(s, msg));
		if (!ret)
			goto missing_data_or_waiting;
		if (ret < 0)
			goto return_bad_req;
	}

	/* other states, DONE...TUNNEL */
	/* we don't want to forward closes on DONE except in tunnel mode. */
	if ((txn->flags & TX_CON_WANT_MSK) != TX_CON_WANT_TUN)
		channel_dont_close(req);

	http_resync_states(s);
	if (!(req->analysers & an_bit)) {
		if (unlikely(msg->msg_state == HTTP_MSG_ERROR)) {
			if (req->flags & CF_SHUTW) {
				/* request errors are most likely due to the
				 * server aborting the transfer. */
				goto aborted_xfer;
			}
			if (msg->err_pos >= 0)
				http_capture_bad_message(sess->fe, s, msg, msg->err_state, s->be);
			goto return_bad_req;
		}
		return 1;
	}

	/* If "option abortonclose" is set on the backend, we want to monitor
	 * the client's connection and forward any shutdown notification to the
	 * server, which will decide whether to close or to go on processing the
	 * request. We only do that in tunnel mode, and not in other modes since
	 * it can be abused to exhaust source ports. */
	if ((s->be->options & PR_O_ABRT_CLOSE) && !(s->si[0].flags & SI_FL_CLEAN_ABRT)) {
		channel_auto_read(req);
		if ((req->flags & (CF_SHUTR|CF_READ_NULL)) &&
		    ((txn->flags & TX_CON_WANT_MSK) != TX_CON_WANT_TUN))
			s->si[1].flags |= SI_FL_NOLINGER;
		channel_auto_close(req);
	}
	else if (s->txn->meth == HTTP_METH_POST) {
		/* POST requests may require to read extra CRLF sent by broken
		 * browsers and which could cause an RST to be sent upon close
		 * on some systems (eg: Linux). */
		channel_auto_read(req);
	}
	return 0;

 missing_data_or_waiting:
	/* stop waiting for data if the input is closed before the end */
	if (msg->msg_state < HTTP_MSG_ENDING && req->flags & CF_SHUTR) {
		if (!(s->flags & SF_ERR_MASK))
			s->flags |= SF_ERR_CLICL;
		if (!(s->flags & SF_FINST_MASK)) {
			if (txn->rsp.msg_state < HTTP_MSG_ERROR)
				s->flags |= SF_FINST_H;
			else
				s->flags |= SF_FINST_D;
		}

		HA_ATOMIC_ADD(&sess->fe->fe_counters.cli_aborts, 1);
		HA_ATOMIC_ADD(&s->be->be_counters.cli_aborts, 1);
		if (objt_server(s->target))
			HA_ATOMIC_ADD(&objt_server(s->target)->counters.cli_aborts, 1);

		goto return_bad_req_stats_ok;
	}

 waiting:
	/* waiting for the last bits to leave the buffer */
	if (req->flags & CF_SHUTW)
		goto aborted_xfer;

	/* When TE: chunked is used, we need to get there again to parse remaining
	 * chunks even if the client has closed, so we don't want to set CF_DONTCLOSE.
	 * And when content-length is used, we never want to let the possible
	 * shutdown be forwarded to the other side, as the state machine will
	 * take care of it once the client responds. It's also important to
	 * prevent TIME_WAITs from accumulating on the backend side, and for
	 * HTTP/2 where the last frame comes with a shutdown.
	 */
	if (msg->flags & (HTTP_MSGF_TE_CHNK|HTTP_MSGF_CNT_LEN))
		channel_dont_close(req);

	/* We know that more data are expected, but we couldn't send more that
	 * what we did. So we always set the CF_EXPECT_MORE flag so that the
	 * system knows it must not set a PUSH on this first part. Interactive
	 * modes are already handled by the stream sock layer. We must not do
	 * this in content-length mode because it could present the MSG_MORE
	 * flag with the last block of forwarded data, which would cause an
	 * additional delay to be observed by the receiver.
	 */
	if (msg->flags & HTTP_MSGF_TE_CHNK)
		req->flags |= CF_EXPECT_MORE;

	return 0;

 return_bad_req: /* let's centralize all bad requests */
	HA_ATOMIC_ADD(&sess->fe->fe_counters.failed_req, 1);
	if (sess->listener->counters)
		HA_ATOMIC_ADD(&sess->listener->counters->failed_req, 1);

 return_bad_req_stats_ok:
	txn->req.err_state = txn->req.msg_state;
	txn->req.msg_state = HTTP_MSG_ERROR;
	if (txn->status) {
		/* Note: we don't send any error if some data were already sent */
		http_reply_and_close(s, txn->status, NULL);
	} else {
		txn->status = 400;
		http_reply_and_close(s, txn->status, http_error_message(s));
	}
	req->analysers   &= AN_REQ_FLT_END;
	s->res.analysers &= AN_RES_FLT_END; /* we're in data phase, we want to abort both directions */

	if (!(s->flags & SF_ERR_MASK))
		s->flags |= SF_ERR_PRXCOND;
	if (!(s->flags & SF_FINST_MASK)) {
		if (txn->rsp.msg_state < HTTP_MSG_ERROR)
			s->flags |= SF_FINST_H;
		else
			s->flags |= SF_FINST_D;
	}
	return 0;

 aborted_xfer:
	txn->req.err_state = txn->req.msg_state;
	txn->req.msg_state = HTTP_MSG_ERROR;
	if (txn->status) {
		/* Note: we don't send any error if some data were already sent */
		http_reply_and_close(s, txn->status, NULL);
	} else {
		txn->status = 502;
		http_reply_and_close(s, txn->status, http_error_message(s));
	}
	req->analysers   &= AN_REQ_FLT_END;
	s->res.analysers &= AN_RES_FLT_END; /* we're in data phase, we want to abort both directions */

	HA_ATOMIC_ADD(&sess->fe->fe_counters.srv_aborts, 1);
	HA_ATOMIC_ADD(&s->be->be_counters.srv_aborts, 1);
	if (objt_server(s->target))
		HA_ATOMIC_ADD(&objt_server(s->target)->counters.srv_aborts, 1);

	if (!(s->flags & SF_ERR_MASK))
		s->flags |= SF_ERR_SRVCL;
	if (!(s->flags & SF_FINST_MASK)) {
		if (txn->rsp.msg_state < HTTP_MSG_ERROR)
			s->flags |= SF_FINST_H;
		else
			s->flags |= SF_FINST_D;
	}
	return 0;
}

/* This stream analyser waits for a complete HTTP response. It returns 1 if the
 * processing can continue on next analysers, or zero if it either needs more
 * data or wants to immediately abort the response (eg: timeout, error, ...). It
 * is tied to AN_RES_WAIT_HTTP and may may remove itself from s->res.analysers
 * when it has nothing left to do, and may remove any analyser when it wants to
 * abort.
 */
int htx_wait_for_response(struct stream *s, struct channel *rep, int an_bit)
{
	struct session *sess = s->sess;
	struct http_txn *txn = s->txn;
	struct http_msg *msg = &txn->rsp;
	struct hdr_ctx ctx;
	int use_close_only;
	int cur_idx;
	int n;

	DPRINTF(stderr,"[%u] %s: stream=%p b=%p, exp(r,w)=%u,%u bf=%08x bh=%lu analysers=%02x\n",
		now_ms, __FUNCTION__,
		s,
		rep,
		rep->rex, rep->wex,
		rep->flags,
		ci_data(rep),
		rep->analysers);

	/*
	 * Now parse the partial (or complete) lines.
	 * We will check the response syntax, and also join multi-line
	 * headers. An index of all the lines will be elaborated while
	 * parsing.
	 *
	 * For the parsing, we use a 28 states FSM.
	 *
	 * Here is the information we currently have :
	 *   ci_head(rep)             = beginning of response
	 *   ci_head(rep) + msg->eoh  = end of processed headers / start of current one
	 *   ci_tail(rep)             = end of input data
	 *   msg->eol                 = end of current header or line (LF or CRLF)
	 *   msg->next                = first non-visited byte
	 */

 next_one:
	/* There's a protected area at the end of the buffer for rewriting
	 * purposes. We don't want to start to parse the request if the
	 * protected area is affected, because we may have to move processed
	 * data later, which is much more complicated.
	 */
	if (c_data(rep) && msg->msg_state < HTTP_MSG_ERROR) {
		if (unlikely(!channel_is_rewritable(rep))) {
			/* some data has still not left the buffer, wake us once that's done */
			if (rep->flags & (CF_SHUTW|CF_SHUTW_NOW|CF_WRITE_ERROR|CF_WRITE_TIMEOUT))
				goto abort_response;
			channel_dont_close(rep);
			rep->flags |= CF_READ_DONTWAIT; /* try to get back here ASAP */
			rep->flags |= CF_WAKE_WRITE;
			return 0;
		}

		if (unlikely(ci_tail(rep) < c_ptr(rep, msg->next) ||
		             ci_tail(rep) > b_wrap(&rep->buf) - global.tune.maxrewrite))
			channel_slow_realign(rep, trash.area);

		if (likely(msg->next < ci_data(rep)))
			http_msg_analyzer(msg, &txn->hdr_idx);
	}

	/* 1: we might have to print this header in debug mode */
	if (unlikely((global.mode & MODE_DEBUG) &&
		     (!(global.mode & MODE_QUIET) || (global.mode & MODE_VERBOSE)) &&
		     msg->msg_state >= HTTP_MSG_BODY)) {
		char *eol, *sol;

		sol = ci_head(rep);
		eol = sol + (msg->sl.st.l ? msg->sl.st.l : ci_data(rep));
		debug_hdr("srvrep", s, sol, eol);

		sol += hdr_idx_first_pos(&txn->hdr_idx);
		cur_idx = hdr_idx_first_idx(&txn->hdr_idx);

		while (cur_idx) {
			eol = sol + txn->hdr_idx.v[cur_idx].len;
			debug_hdr("srvhdr", s, sol, eol);
			sol = eol + txn->hdr_idx.v[cur_idx].cr + 1;
			cur_idx = txn->hdr_idx.v[cur_idx].next;
		}
	}

	/*
	 * Now we quickly check if we have found a full valid response.
	 * If not so, we check the FD and buffer states before leaving.
	 * A full response is indicated by the fact that we have seen
	 * the double LF/CRLF, so the state is >= HTTP_MSG_BODY. Invalid
	 * responses are checked first.
	 *
	 * Depending on whether the client is still there or not, we
	 * may send an error response back or not. Note that normally
	 * we should only check for HTTP status there, and check I/O
	 * errors somewhere else.
	 */

	if (unlikely(msg->msg_state < HTTP_MSG_BODY)) {
		/* Invalid response */
		if (unlikely(msg->msg_state == HTTP_MSG_ERROR)) {
			/* we detected a parsing error. We want to archive this response
			 * in the dedicated proxy area for later troubleshooting.
			 */
		hdr_response_bad:
			if (msg->msg_state == HTTP_MSG_ERROR || msg->err_pos >= 0)
				http_capture_bad_message(s->be, s, msg, msg->err_state, sess->fe);

			HA_ATOMIC_ADD(&s->be->be_counters.failed_resp, 1);
			if (objt_server(s->target)) {
				HA_ATOMIC_ADD(&objt_server(s->target)->counters.failed_resp, 1);
				health_adjust(objt_server(s->target), HANA_STATUS_HTTP_HDRRSP);
			}
		abort_response:
			channel_auto_close(rep);
			rep->analysers &= AN_RES_FLT_END;
			txn->status = 502;
			s->si[1].flags |= SI_FL_NOLINGER;
			channel_truncate(rep);
			http_reply_and_close(s, txn->status, http_error_message(s));

			if (!(s->flags & SF_ERR_MASK))
				s->flags |= SF_ERR_PRXCOND;
			if (!(s->flags & SF_FINST_MASK))
				s->flags |= SF_FINST_H;

			return 0;
		}

		/* too large response does not fit in buffer. */
		else if (channel_full(rep, global.tune.maxrewrite)) {
			if (msg->err_pos < 0)
				msg->err_pos = ci_data(rep);
			goto hdr_response_bad;
		}

		/* read error */
		else if (rep->flags & CF_READ_ERROR) {
			if (msg->err_pos >= 0)
				http_capture_bad_message(s->be, s, msg, msg->err_state, sess->fe);
			else if (txn->flags & TX_NOT_FIRST)
				goto abort_keep_alive;

			HA_ATOMIC_ADD(&s->be->be_counters.failed_resp, 1);
			if (objt_server(s->target)) {
				HA_ATOMIC_ADD(&objt_server(s->target)->counters.failed_resp, 1);
				health_adjust(objt_server(s->target), HANA_STATUS_HTTP_READ_ERROR);
			}

			channel_auto_close(rep);
			rep->analysers &= AN_RES_FLT_END;
			txn->status = 502;

			/* Check to see if the server refused the early data.
			 * If so, just send a 425
			 */
			if (objt_cs(s->si[1].end)) {
				struct connection *conn = objt_cs(s->si[1].end)->conn;

				if (conn->err_code == CO_ER_SSL_EARLY_FAILED)
					txn->status = 425;
			}

			s->si[1].flags |= SI_FL_NOLINGER;
			channel_truncate(rep);
			http_reply_and_close(s, txn->status, http_error_message(s));

			if (!(s->flags & SF_ERR_MASK))
				s->flags |= SF_ERR_SRVCL;
			if (!(s->flags & SF_FINST_MASK))
				s->flags |= SF_FINST_H;
			return 0;
		}

		/* read timeout : return a 504 to the client. */
		else if (rep->flags & CF_READ_TIMEOUT) {
			if (msg->err_pos >= 0)
				http_capture_bad_message(s->be, s, msg, msg->err_state, sess->fe);

			HA_ATOMIC_ADD(&s->be->be_counters.failed_resp, 1);
			if (objt_server(s->target)) {
				HA_ATOMIC_ADD(&objt_server(s->target)->counters.failed_resp, 1);
				health_adjust(objt_server(s->target), HANA_STATUS_HTTP_READ_TIMEOUT);
			}

			channel_auto_close(rep);
			rep->analysers &= AN_RES_FLT_END;
			txn->status = 504;
			s->si[1].flags |= SI_FL_NOLINGER;
			channel_truncate(rep);
			http_reply_and_close(s, txn->status, http_error_message(s));

			if (!(s->flags & SF_ERR_MASK))
				s->flags |= SF_ERR_SRVTO;
			if (!(s->flags & SF_FINST_MASK))
				s->flags |= SF_FINST_H;
			return 0;
		}

		/* client abort with an abortonclose */
		else if ((rep->flags & CF_SHUTR) && ((s->req.flags & (CF_SHUTR|CF_SHUTW)) == (CF_SHUTR|CF_SHUTW))) {
			HA_ATOMIC_ADD(&sess->fe->fe_counters.cli_aborts, 1);
			HA_ATOMIC_ADD(&s->be->be_counters.cli_aborts, 1);
			if (objt_server(s->target))
				HA_ATOMIC_ADD(&objt_server(s->target)->counters.cli_aborts, 1);

			rep->analysers &= AN_RES_FLT_END;
			channel_auto_close(rep);

			txn->status = 400;
			channel_truncate(rep);
			http_reply_and_close(s, txn->status, http_error_message(s));

			if (!(s->flags & SF_ERR_MASK))
				s->flags |= SF_ERR_CLICL;
			if (!(s->flags & SF_FINST_MASK))
				s->flags |= SF_FINST_H;

			/* process_stream() will take care of the error */
			return 0;
		}

		/* close from server, capture the response if the server has started to respond */
		else if (rep->flags & CF_SHUTR) {
			if (msg->msg_state >= HTTP_MSG_RPVER || msg->err_pos >= 0)
				http_capture_bad_message(s->be, s, msg, msg->err_state, sess->fe);
			else if (txn->flags & TX_NOT_FIRST)
				goto abort_keep_alive;

			HA_ATOMIC_ADD(&s->be->be_counters.failed_resp, 1);
			if (objt_server(s->target)) {
				HA_ATOMIC_ADD(&objt_server(s->target)->counters.failed_resp, 1);
				health_adjust(objt_server(s->target), HANA_STATUS_HTTP_BROKEN_PIPE);
			}

			channel_auto_close(rep);
			rep->analysers &= AN_RES_FLT_END;
			txn->status = 502;
			s->si[1].flags |= SI_FL_NOLINGER;
			channel_truncate(rep);
			http_reply_and_close(s, txn->status, http_error_message(s));

			if (!(s->flags & SF_ERR_MASK))
				s->flags |= SF_ERR_SRVCL;
			if (!(s->flags & SF_FINST_MASK))
				s->flags |= SF_FINST_H;
			return 0;
		}

		/* write error to client (we don't send any message then) */
		else if (rep->flags & CF_WRITE_ERROR) {
			if (msg->err_pos >= 0)
				http_capture_bad_message(s->be, s, msg, msg->err_state, sess->fe);
			else if (txn->flags & TX_NOT_FIRST)
				goto abort_keep_alive;

			HA_ATOMIC_ADD(&s->be->be_counters.failed_resp, 1);
			rep->analysers &= AN_RES_FLT_END;
			channel_auto_close(rep);

			if (!(s->flags & SF_ERR_MASK))
				s->flags |= SF_ERR_CLICL;
			if (!(s->flags & SF_FINST_MASK))
				s->flags |= SF_FINST_H;

			/* process_stream() will take care of the error */
			return 0;
		}

		channel_dont_close(rep);
		rep->flags |= CF_READ_DONTWAIT; /* try to get back here ASAP */
		return 0;
	}

	/* More interesting part now : we know that we have a complete
	 * response which at least looks like HTTP. We have an indicator
	 * of each header's length, so we can parse them quickly.
	 */

	if (unlikely(msg->err_pos >= 0))
		http_capture_bad_message(s->be, s, msg, msg->err_state, sess->fe);

	/*
	 * 1: get the status code
	 */
	n = ci_head(rep)[msg->sl.st.c] - '0';
	if (n < 1 || n > 5)
		n = 0;
	/* when the client triggers a 4xx from the server, it's most often due
	 * to a missing object or permission. These events should be tracked
	 * because if they happen often, it may indicate a brute force or a
	 * vulnerability scan.
	 */
	if (n == 4)
		stream_inc_http_err_ctr(s);

	if (objt_server(s->target))
		HA_ATOMIC_ADD(&objt_server(s->target)->counters.p.http.rsp[n], 1);

	/* RFC7230#2.6 has enforced the format of the HTTP version string to be
	 * exactly one digit "." one digit. This check may be disabled using
	 * option accept-invalid-http-response.
	 */
	if (!(s->be->options2 & PR_O2_RSPBUG_OK)) {
		if (msg->sl.st.v_l != 8) {
			msg->err_pos = 0;
			goto hdr_response_bad;
		}

		if (ci_head(rep)[4] != '/' ||
		    !isdigit((unsigned char)ci_head(rep)[5]) ||
		    ci_head(rep)[6] != '.' ||
		    !isdigit((unsigned char)ci_head(rep)[7])) {
			msg->err_pos = 4;
			goto hdr_response_bad;
		}
	}

	/* check if the response is HTTP/1.1 or above */
	if ((msg->sl.st.v_l == 8) &&
	    ((ci_head(rep)[5] > '1') ||
	     ((ci_head(rep)[5] == '1') && (ci_head(rep)[7] >= '1'))))
		msg->flags |= HTTP_MSGF_VER_11;

	/* "connection" has not been parsed yet */
	txn->flags &= ~(TX_HDR_CONN_PRS|TX_HDR_CONN_CLO|TX_HDR_CONN_KAL|TX_HDR_CONN_UPG|TX_CON_CLO_SET|TX_CON_KAL_SET);

	/* transfer length unknown*/
	msg->flags &= ~HTTP_MSGF_XFER_LEN;

	txn->status = strl2ui(ci_head(rep) + msg->sl.st.c, msg->sl.st.c_l);

	/* Adjust server's health based on status code. Note: status codes 501
	 * and 505 are triggered on demand by client request, so we must not
	 * count them as server failures.
	 */
	if (objt_server(s->target)) {
		if (txn->status >= 100 && (txn->status < 500 || txn->status == 501 || txn->status == 505))
			health_adjust(objt_server(s->target), HANA_STATUS_HTTP_OK);
		else
			health_adjust(objt_server(s->target), HANA_STATUS_HTTP_STS);
	}

	/*
	 * We may be facing a 100-continue response, or any other informational
	 * 1xx response which is non-final, in which case this is not the right
	 * response, and we're waiting for the next one. Let's allow this response
	 * to go to the client and wait for the next one. There's an exception for
	 * 101 which is used later in the code to switch protocols.
	 */
	if (txn->status < 200 &&
	    (txn->status == 100 || txn->status >= 102)) {
		hdr_idx_init(&txn->hdr_idx);
		msg->next -= channel_forward(rep, msg->next);
		msg->msg_state = HTTP_MSG_RPBEFORE;
		txn->status = 0;
		s->logs.t_data = -1; /* was not a response yet */
		FLT_STRM_CB(s, flt_http_reset(s, msg));
		goto next_one;
	}

	/*
	 * 2: check for cacheability.
	 */

	switch (txn->status) {
	case 200:
	case 203:
	case 204:
	case 206:
	case 300:
	case 301:
	case 404:
	case 405:
	case 410:
	case 414:
	case 501:
		break;
	default:
		/* RFC7231#6.1:
		 *   Responses with status codes that are defined as
		 *   cacheable by default (e.g., 200, 203, 204, 206,
		 *   300, 301, 404, 405, 410, 414, and 501 in this
		 *   specification) can be reused by a cache with
		 *   heuristic expiration unless otherwise indicated
		 *   by the method definition or explicit cache
		 *   controls [RFC7234]; all other status codes are
		 *   not cacheable by default.
		 */
		txn->flags &= ~(TX_CACHEABLE | TX_CACHE_COOK);
		break;
	}

	/*
	 * 3: we may need to capture headers
	 */
	s->logs.logwait &= ~LW_RESP;
	if (unlikely((s->logs.logwait & LW_RSPHDR) && s->res_cap))
		http_capture_headers(ci_head(rep), &txn->hdr_idx,
				     s->res_cap, sess->fe->rsp_cap);

	/* 4: determine the transfer-length according to RFC2616 #4.4, updated
	 * by RFC7230#3.3.3 :
	 *
	 * The length of a message body is determined by one of the following
	 *   (in order of precedence):
	 *
	 *   1.  Any 2xx (Successful) response to a CONNECT request implies that
	 *       the connection will become a tunnel immediately after the empty
	 *       line that concludes the header fields.  A client MUST ignore
	 *       any Content-Length or Transfer-Encoding header fields received
	 *       in such a message. Any 101 response (Switching Protocols) is
	 *       managed in the same manner.
	 *
	 *   2.  Any response to a HEAD request and any response with a 1xx
	 *       (Informational), 204 (No Content), or 304 (Not Modified) status
	 *       code is always terminated by the first empty line after the
	 *       header fields, regardless of the header fields present in the
	 *       message, and thus cannot contain a message body.
	 *
	 *   3.  If a Transfer-Encoding header field is present and the chunked
	 *       transfer coding (Section 4.1) is the final encoding, the message
	 *       body length is determined by reading and decoding the chunked
	 *       data until the transfer coding indicates the data is complete.
	 *
	 *       If a Transfer-Encoding header field is present in a response and
	 *       the chunked transfer coding is not the final encoding, the
	 *       message body length is determined by reading the connection until
	 *       it is closed by the server.  If a Transfer-Encoding header field
	 *       is present in a request and the chunked transfer coding is not
	 *       the final encoding, the message body length cannot be determined
	 *       reliably; the server MUST respond with the 400 (Bad Request)
	 *       status code and then close the connection.
	 *
	 *       If a message is received with both a Transfer-Encoding and a
	 *       Content-Length header field, the Transfer-Encoding overrides the
	 *       Content-Length.  Such a message might indicate an attempt to
	 *       perform request smuggling (Section 9.5) or response splitting
	 *       (Section 9.4) and ought to be handled as an error.  A sender MUST
	 *       remove the received Content-Length field prior to forwarding such
	 *       a message downstream.
	 *
	 *   4.  If a message is received without Transfer-Encoding and with
	 *       either multiple Content-Length header fields having differing
	 *       field-values or a single Content-Length header field having an
	 *       invalid value, then the message framing is invalid and the
	 *       recipient MUST treat it as an unrecoverable error.  If this is a
	 *       request message, the server MUST respond with a 400 (Bad Request)
	 *       status code and then close the connection.  If this is a response
	 *       message received by a proxy, the proxy MUST close the connection
	 *       to the server, discard the received response, and send a 502 (Bad
	 *       Gateway) response to the client.  If this is a response message
	 *       received by a user agent, the user agent MUST close the
	 *       connection to the server and discard the received response.
	 *
	 *   5.  If a valid Content-Length header field is present without
	 *       Transfer-Encoding, its decimal value defines the expected message
	 *       body length in octets.  If the sender closes the connection or
	 *       the recipient times out before the indicated number of octets are
	 *       received, the recipient MUST consider the message to be
	 *       incomplete and close the connection.
	 *
	 *   6.  If this is a request message and none of the above are true, then
	 *       the message body length is zero (no message body is present).
	 *
	 *   7.  Otherwise, this is a response message without a declared message
	 *       body length, so the message body length is determined by the
	 *       number of octets received prior to the server closing the
	 *       connection.
	 */

	/* Skip parsing if no content length is possible. The response flags
	 * remain 0 as well as the chunk_len, which may or may not mirror
	 * the real header value, and we note that we know the response's length.
	 * FIXME: should we parse anyway and return an error on chunked encoding ?
	 */
	if (unlikely((txn->meth == HTTP_METH_CONNECT && txn->status == 200) ||
		     txn->status == 101)) {
		/* Either we've established an explicit tunnel, or we're
		 * switching the protocol. In both cases, we're very unlikely
		 * to understand the next protocols. We have to switch to tunnel
		 * mode, so that we transfer the request and responses then let
		 * this protocol pass unmodified. When we later implement specific
		 * parsers for such protocols, we'll want to check the Upgrade
		 * header which contains information about that protocol for
		 * responses with status 101 (eg: see RFC2817 about TLS).
		 */
		txn->flags = (txn->flags & ~TX_CON_WANT_MSK) | TX_CON_WANT_TUN;
		msg->flags |= HTTP_MSGF_XFER_LEN;
		goto end;
	}

	if (txn->meth == HTTP_METH_HEAD ||
	    (txn->status >= 100 && txn->status < 200) ||
	    txn->status == 204 || txn->status == 304) {
		msg->flags |= HTTP_MSGF_XFER_LEN;
		goto skip_content_length;
	}

	use_close_only = 0;
	ctx.idx = 0;
	while (http_find_header2("Transfer-Encoding", 17, ci_head(rep), &txn->hdr_idx, &ctx)) {
		if (ctx.vlen == 7 && strncasecmp(ctx.line + ctx.val, "chunked", 7) == 0)
			msg->flags |= (HTTP_MSGF_TE_CHNK | HTTP_MSGF_XFER_LEN);
		else if (msg->flags & HTTP_MSGF_TE_CHNK) {
			/* bad transfer-encoding (chunked followed by something else) */
			use_close_only = 1;
			msg->flags &= ~(HTTP_MSGF_TE_CHNK | HTTP_MSGF_XFER_LEN);
			break;
		}
	}

	/* Chunked responses must have their content-length removed */
	ctx.idx = 0;
	if (use_close_only || (msg->flags & HTTP_MSGF_TE_CHNK)) {
		while (http_find_header2("Content-Length", 14, ci_head(rep), &txn->hdr_idx, &ctx))
			http_remove_header2(msg, &txn->hdr_idx, &ctx);
	}
	else while (http_find_header2("Content-Length", 14, ci_head(rep), &txn->hdr_idx, &ctx)) {
		signed long long cl;

		if (!ctx.vlen) {
			msg->err_pos = ctx.line + ctx.val - ci_head(rep);
			goto hdr_response_bad;
		}

		if (strl2llrc(ctx.line + ctx.val, ctx.vlen, &cl)) {
			msg->err_pos = ctx.line + ctx.val - ci_head(rep);
			goto hdr_response_bad; /* parse failure */
		}

		if (cl < 0) {
			msg->err_pos = ctx.line + ctx.val - ci_head(rep);
			goto hdr_response_bad;
		}

		if ((msg->flags & HTTP_MSGF_CNT_LEN) && (msg->chunk_len != cl)) {
			msg->err_pos = ctx.line + ctx.val - ci_head(rep);
			goto hdr_response_bad; /* already specified, was different */
		}

		msg->flags |= HTTP_MSGF_CNT_LEN | HTTP_MSGF_XFER_LEN;
		msg->body_len = msg->chunk_len = cl;
	}

 skip_content_length:
	/* Now we have to check if we need to modify the Connection header.
	 * This is more difficult on the response than it is on the request,
	 * because we can have two different HTTP versions and we don't know
	 * how the client will interprete a response. For instance, let's say
	 * that the client sends a keep-alive request in HTTP/1.0 and gets an
	 * HTTP/1.1 response without any header. Maybe it will bound itself to
	 * HTTP/1.0 because it only knows about it, and will consider the lack
	 * of header as a close, or maybe it knows HTTP/1.1 and can consider
	 * the lack of header as a keep-alive. Thus we will use two flags
	 * indicating how a request MAY be understood by the client. In case
	 * of multiple possibilities, we'll fix the header to be explicit. If
	 * ambiguous cases such as both close and keepalive are seen, then we
	 * will fall back to explicit close. Note that we won't take risks with
	 * HTTP/1.0 clients which may not necessarily understand keep-alive.
	 * See doc/internals/connection-header.txt for the complete matrix.
	 */
	if ((txn->status >= 200) && !(txn->flags & TX_HDR_CONN_PRS) &&
	    (txn->flags & TX_CON_WANT_MSK) != TX_CON_WANT_TUN) {
		int to_del = 0;

		/* on unknown transfer length, we must close */
		if (!(msg->flags & HTTP_MSGF_XFER_LEN))
			txn->flags = (txn->flags & ~TX_CON_WANT_MSK) | TX_CON_WANT_CLO;

		/* now adjust header transformations depending on current state */
		if ((txn->flags & TX_CON_WANT_MSK) == TX_CON_WANT_CLO) {
			to_del |= 2; /* remove "keep-alive" on any response */
			if (!(msg->flags & HTTP_MSGF_VER_11))
				to_del |= 1; /* remove "close" for HTTP/1.0 responses */
		}
		else { /* SCL / KAL */
			to_del |= 1; /* remove "close" on any response */
			if (txn->req.flags & msg->flags & HTTP_MSGF_VER_11)
				to_del |= 2; /* remove "keep-alive" on pure 1.1 responses */
		}

		/* Parse and remove some headers from the connection header */
		http_parse_connection_header(txn, msg, to_del);

		/* Some keep-alive responses are converted to Server-close if
		 * the server wants to close.
		 */
		if ((txn->flags & TX_CON_WANT_MSK) == TX_CON_WANT_KAL) {
			if ((txn->flags & TX_HDR_CONN_CLO) ||
			    (!(txn->flags & TX_HDR_CONN_KAL) && !(msg->flags & HTTP_MSGF_VER_11)))
				txn->flags = (txn->flags & ~TX_CON_WANT_MSK) | TX_CON_WANT_SCL;
		}
	}

 end:
	/* we want to have the response time before we start processing it */
	s->logs.t_data = tv_ms_elapsed(&s->logs.tv_accept, &now);

	/* end of job, return OK */
	rep->analysers &= ~an_bit;
	rep->analyse_exp = TICK_ETERNITY;
	channel_auto_close(rep);
	return 1;

 abort_keep_alive:
	/* A keep-alive request to the server failed on a network error.
	 * The client is required to retry. We need to close without returning
	 * any other information so that the client retries.
	 */
	txn->status = 0;
	rep->analysers   &= AN_RES_FLT_END;
	s->req.analysers &= AN_REQ_FLT_END;
	channel_auto_close(rep);
	s->logs.logwait = 0;
	s->logs.level = 0;
	s->res.flags &= ~CF_EXPECT_MORE; /* speed up sending a previous response */
	channel_truncate(rep);
	http_reply_and_close(s, txn->status, NULL);
	return 0;
}

/* This function performs all the processing enabled for the current response.
 * It normally returns 1 unless it wants to break. It relies on buffers flags,
 * and updates s->res.analysers. It might make sense to explode it into several
 * other functions. It works like process_request (see indications above).
 */
int htx_process_res_common(struct stream *s, struct channel *rep, int an_bit, struct proxy *px)
{
	struct session *sess = s->sess;
	struct http_txn *txn = s->txn;
	struct http_msg *msg = &txn->rsp;
	struct proxy *cur_proxy;
	struct cond_wordlist *wl;
	enum rule_result ret = HTTP_RULE_RES_CONT;

	DPRINTF(stderr,"[%u] %s: stream=%p b=%p, exp(r,w)=%u,%u bf=%08x bh=%lu analysers=%02x\n",
		now_ms, __FUNCTION__,
		s,
		rep,
		rep->rex, rep->wex,
		rep->flags,
		ci_data(rep),
		rep->analysers);

	if (unlikely(msg->msg_state < HTTP_MSG_BODY))	/* we need more data */
		return 0;

	/* The stats applet needs to adjust the Connection header but we don't
	 * apply any filter there.
	 */
	if (unlikely(objt_applet(s->target) == &http_stats_applet)) {
		rep->analysers &= ~an_bit;
		rep->analyse_exp = TICK_ETERNITY;
		goto skip_filters;
	}

	/*
	 * We will have to evaluate the filters.
	 * As opposed to version 1.2, now they will be evaluated in the
	 * filters order and not in the header order. This means that
	 * each filter has to be validated among all headers.
	 *
	 * Filters are tried with ->be first, then with ->fe if it is
	 * different from ->be.
	 *
	 * Maybe we are in resume condiion. In this case I choose the
	 * "struct proxy" which contains the rule list matching the resume
	 * pointer. If none of theses "struct proxy" match, I initialise
	 * the process with the first one.
	 *
	 * In fact, I check only correspondance betwwen the current list
	 * pointer and the ->fe rule list. If it doesn't match, I initialize
	 * the loop with the ->be.
	 */
	if (s->current_rule_list == &sess->fe->http_res_rules)
		cur_proxy = sess->fe;
	else
		cur_proxy = s->be;
	while (1) {
		struct proxy *rule_set = cur_proxy;

		/* evaluate http-response rules */
		if (ret == HTTP_RULE_RES_CONT) {
			ret = http_res_get_intercept_rule(cur_proxy, &cur_proxy->http_res_rules, s);

			if (ret == HTTP_RULE_RES_BADREQ)
				goto return_srv_prx_502;

			if (ret == HTTP_RULE_RES_DONE) {
				rep->analysers &= ~an_bit;
				rep->analyse_exp = TICK_ETERNITY;
				return 1;
			}
		}

		/* we need to be called again. */
		if (ret == HTTP_RULE_RES_YIELD) {
			channel_dont_close(rep);
			return 0;
		}

		/* try headers filters */
		if (rule_set->rsp_exp != NULL) {
			if (apply_filters_to_response(s, rep, rule_set) < 0) {
			return_bad_resp:
				if (objt_server(s->target)) {
					HA_ATOMIC_ADD(&objt_server(s->target)->counters.failed_resp, 1);
					health_adjust(objt_server(s->target), HANA_STATUS_HTTP_RSP);
				}
				HA_ATOMIC_ADD(&s->be->be_counters.failed_resp, 1);
			return_srv_prx_502:
				rep->analysers &= AN_RES_FLT_END;
				txn->status = 502;
				s->logs.t_data = -1; /* was not a valid response */
				s->si[1].flags |= SI_FL_NOLINGER;
				channel_truncate(rep);
				http_reply_and_close(s, txn->status, http_error_message(s));
				if (!(s->flags & SF_ERR_MASK))
					s->flags |= SF_ERR_PRXCOND;
				if (!(s->flags & SF_FINST_MASK))
					s->flags |= SF_FINST_H;
				return 0;
			}
		}

		/* has the response been denied ? */
		if (txn->flags & TX_SVDENY) {
			if (objt_server(s->target))
				HA_ATOMIC_ADD(&objt_server(s->target)->counters.failed_secu, 1);

			HA_ATOMIC_ADD(&s->be->be_counters.denied_resp, 1);
			HA_ATOMIC_ADD(&sess->fe->fe_counters.denied_resp, 1);
			if (sess->listener->counters)
				HA_ATOMIC_ADD(&sess->listener->counters->denied_resp, 1);

			goto return_srv_prx_502;
		}

		/* add response headers from the rule sets in the same order */
		list_for_each_entry(wl, &rule_set->rsp_add, list) {
			if (txn->status < 200 && txn->status != 101)
				break;
			if (wl->cond) {
				int ret = acl_exec_cond(wl->cond, px, sess, s, SMP_OPT_DIR_RES|SMP_OPT_FINAL);
				ret = acl_pass(ret);
				if (((struct acl_cond *)wl->cond)->pol == ACL_COND_UNLESS)
					ret = !ret;
				if (!ret)
					continue;
			}
			if (unlikely(http_header_add_tail2(&txn->rsp, &txn->hdr_idx, wl->s, strlen(wl->s)) < 0))
				goto return_bad_resp;
		}

		/* check whether we're already working on the frontend */
		if (cur_proxy == sess->fe)
			break;
		cur_proxy = sess->fe;
	}

	/* After this point, this anayzer can't return yield, so we can
	 * remove the bit corresponding to this analyzer from the list.
	 *
	 * Note that the intermediate returns and goto found previously
	 * reset the analyzers.
	 */
	rep->analysers &= ~an_bit;
	rep->analyse_exp = TICK_ETERNITY;

	/* OK that's all we can do for 1xx responses */
	if (unlikely(txn->status < 200 && txn->status != 101))
		goto skip_header_mangling;

	/*
	 * Now check for a server cookie.
	 */
	if (s->be->cookie_name || sess->fe->capture_name || (s->be->options & PR_O_CHK_CACHE))
		manage_server_side_cookies(s, rep);

	/*
	 * Check for cache-control or pragma headers if required.
	 */
	if ((s->be->options & PR_O_CHK_CACHE) || (s->be->ck_opts & PR_CK_NOC))
		check_response_for_cacheability(s, rep);

	/*
	 * Add server cookie in the response if needed
	 */
	if (objt_server(s->target) && (s->be->ck_opts & PR_CK_INS) &&
	    !((txn->flags & TX_SCK_FOUND) && (s->be->ck_opts & PR_CK_PSV)) &&
	    (!(s->flags & SF_DIRECT) ||
	     ((s->be->cookie_maxidle || txn->cookie_last_date) &&
	      (!txn->cookie_last_date || (txn->cookie_last_date - date.tv_sec) < 0)) ||
	     (s->be->cookie_maxlife && !txn->cookie_first_date) ||  // set the first_date
	     (!s->be->cookie_maxlife && txn->cookie_first_date)) && // remove the first_date
	    (!(s->be->ck_opts & PR_CK_POST) || (txn->meth == HTTP_METH_POST)) &&
	    !(s->flags & SF_IGNORE_PRST)) {
		/* the server is known, it's not the one the client requested, or the
		 * cookie's last seen date needs to be refreshed. We have to
		 * insert a set-cookie here, except if we want to insert only on POST
		 * requests and this one isn't. Note that servers which don't have cookies
		 * (eg: some backup servers) will return a full cookie removal request.
		 */
		if (!objt_server(s->target)->cookie) {
			chunk_printf(&trash,
				     "Set-Cookie: %s=; Expires=Thu, 01-Jan-1970 00:00:01 GMT; path=/",
				     s->be->cookie_name);
		}
		else {
			chunk_printf(&trash, "Set-Cookie: %s=%s", s->be->cookie_name, objt_server(s->target)->cookie);

			if (s->be->cookie_maxidle || s->be->cookie_maxlife) {
				/* emit last_date, which is mandatory */
				trash.area[trash.data++] = COOKIE_DELIM_DATE;
				s30tob64((date.tv_sec+3) >> 2,
					 trash.area + trash.data);
				trash.data += 5;

				if (s->be->cookie_maxlife) {
					/* emit first_date, which is either the original one or
					 * the current date.
					 */
					trash.area[trash.data++] = COOKIE_DELIM_DATE;
					s30tob64(txn->cookie_first_date ?
						 txn->cookie_first_date >> 2 :
						 (date.tv_sec+3) >> 2,
						 trash.area + trash.data);
					trash.data += 5;
				}
			}
			chunk_appendf(&trash, "; path=/");
		}

		if (s->be->cookie_domain)
			chunk_appendf(&trash, "; domain=%s", s->be->cookie_domain);

		if (s->be->ck_opts & PR_CK_HTTPONLY)
			chunk_appendf(&trash, "; HttpOnly");

		if (s->be->ck_opts & PR_CK_SECURE)
			chunk_appendf(&trash, "; Secure");

		if (unlikely(http_header_add_tail2(&txn->rsp, &txn->hdr_idx, trash.area, trash.data) < 0))
			goto return_bad_resp;

		txn->flags &= ~TX_SCK_MASK;
		if (__objt_server(s->target)->cookie && (s->flags & SF_DIRECT))
			/* the server did not change, only the date was updated */
			txn->flags |= TX_SCK_UPDATED;
		else
			txn->flags |= TX_SCK_INSERTED;

		/* Here, we will tell an eventual cache on the client side that we don't
		 * want it to cache this reply because HTTP/1.0 caches also cache cookies !
		 * Some caches understand the correct form: 'no-cache="set-cookie"', but
		 * others don't (eg: apache <= 1.3.26). So we use 'private' instead.
		 */
		if ((s->be->ck_opts & PR_CK_NOC) && (txn->flags & TX_CACHEABLE)) {

			txn->flags &= ~TX_CACHEABLE & ~TX_CACHE_COOK;

			if (unlikely(http_header_add_tail2(&txn->rsp, &txn->hdr_idx,
			                                   "Cache-control: private", 22) < 0))
				goto return_bad_resp;
		}
	}

	/*
	 * Check if result will be cacheable with a cookie.
	 * We'll block the response if security checks have caught
	 * nasty things such as a cacheable cookie.
	 */
	if (((txn->flags & (TX_CACHEABLE | TX_CACHE_COOK | TX_SCK_PRESENT)) ==
	     (TX_CACHEABLE | TX_CACHE_COOK | TX_SCK_PRESENT)) &&
	    (s->be->options & PR_O_CHK_CACHE)) {
		/* we're in presence of a cacheable response containing
		 * a set-cookie header. We'll block it as requested by
		 * the 'checkcache' option, and send an alert.
		 */
		if (objt_server(s->target))
			HA_ATOMIC_ADD(&objt_server(s->target)->counters.failed_secu, 1);

		HA_ATOMIC_ADD(&s->be->be_counters.denied_resp, 1);
		HA_ATOMIC_ADD(&sess->fe->fe_counters.denied_resp, 1);
		if (sess->listener->counters)
			HA_ATOMIC_ADD(&sess->listener->counters->denied_resp, 1);

		ha_alert("Blocking cacheable cookie in response from instance %s, server %s.\n",
			 s->be->id, objt_server(s->target) ? objt_server(s->target)->id : "<dispatch>");
		send_log(s->be, LOG_ALERT,
			 "Blocking cacheable cookie in response from instance %s, server %s.\n",
			 s->be->id, objt_server(s->target) ? objt_server(s->target)->id : "<dispatch>");
		goto return_srv_prx_502;
	}

 skip_filters:
	/*
	 * Adjust "Connection: close" or "Connection: keep-alive" if needed.
	 * If an "Upgrade" token is found, the header is left untouched in order
	 * not to have to deal with some client bugs : some of them fail an upgrade
	 * if anything but "Upgrade" is present in the Connection header. We don't
	 * want to touch any 101 response either since it's switching to another
	 * protocol.
	 */
	if ((txn->status != 101) && !(txn->flags & TX_HDR_CONN_UPG) &&
	    (txn->flags & TX_CON_WANT_MSK) != TX_CON_WANT_TUN) {
		unsigned int want_flags = 0;

		if ((txn->flags & TX_CON_WANT_MSK) == TX_CON_WANT_KAL ||
		    (txn->flags & TX_CON_WANT_MSK) == TX_CON_WANT_SCL) {
			/* we want a keep-alive response here. Keep-alive header
			 * required if either side is not 1.1.
			 */
			if (!(txn->req.flags & msg->flags & HTTP_MSGF_VER_11))
				want_flags |= TX_CON_KAL_SET;
		}
		else { /* CLO */
			/* we want a close response here. Close header required if
			 * the server is 1.1, regardless of the client.
			 */
			if (msg->flags & HTTP_MSGF_VER_11)
				want_flags |= TX_CON_CLO_SET;
		}

		if (want_flags != (txn->flags & (TX_CON_CLO_SET|TX_CON_KAL_SET)))
			http_change_connection_header(txn, msg, want_flags);
	}

 skip_header_mangling:
	/* Always enter in the body analyzer */
	rep->analysers &= ~AN_RES_FLT_XFER_DATA;
	rep->analysers |= AN_RES_HTTP_XFER_BODY;

	/* if the user wants to log as soon as possible, without counting
	 * bytes from the server, then this is the right moment. We have
	 * to temporarily assign bytes_out to log what we currently have.
	 */
	if (!LIST_ISEMPTY(&sess->fe->logformat) && !(s->logs.logwait & LW_BYTES)) {
		s->logs.t_close = s->logs.t_data; /* to get a valid end date */
		s->logs.bytes_out = txn->rsp.eoh;
		s->do_log(s);
		s->logs.bytes_out = 0;
	}
	return 1;
}

/* This function is an analyser which forwards response body (including chunk
 * sizes if any). It is called as soon as we must forward, even if we forward
 * zero byte. The only situation where it must not be called is when we're in
 * tunnel mode and we want to forward till the close. It's used both to forward
 * remaining data and to resync after end of body. It expects the msg_state to
 * be between MSG_BODY and MSG_DONE (inclusive). It returns zero if it needs to
 * read more data, or 1 once we can go on with next request or end the stream.
 *
 * It is capable of compressing response data both in content-length mode and
 * in chunked mode. The state machines follows different flows depending on
 * whether content-length and chunked modes are used, since there are no
 * trailers in content-length :
 *
 *       chk-mode        cl-mode
 *          ,----- BODY -----.
 *         /                  \
 *        V     size > 0       V    chk-mode
 *  .--> SIZE -------------> DATA -------------> CRLF
 *  |     | size == 0          | last byte         |
 *  |     v      final crlf    v inspected         |
 *  |  TRAILERS -----------> DONE                  |
 *  |                                              |
 *  `----------------------------------------------'
 *
 * Compression only happens in the DATA state, and must be flushed in final
 * states (TRAILERS/DONE) or when leaving on missing data. Normal forwarding
 * is performed at once on final states for all bytes parsed, or when leaving
 * on missing data.
 */
int htx_response_forward_body(struct stream *s, struct channel *res, int an_bit)
{
	struct session *sess = s->sess;
	struct http_txn *txn = s->txn;
	struct http_msg *msg = &s->txn->rsp;
	int ret;

	DPRINTF(stderr,"[%u] %s: stream=%p b=%p, exp(r,w)=%u,%u bf=%08x bh=%lu analysers=%02x\n",
		now_ms, __FUNCTION__,
		s,
		res,
		res->rex, res->wex,
		res->flags,
		ci_data(res),
		res->analysers);

	if (unlikely(msg->msg_state < HTTP_MSG_BODY))
		return 0;

	if ((res->flags & (CF_READ_ERROR|CF_READ_TIMEOUT|CF_WRITE_ERROR|CF_WRITE_TIMEOUT)) ||
	    ((res->flags & CF_SHUTW) && (res->to_forward || co_data(res))) ||
	     !s->req.analysers) {
		/* Output closed while we were sending data. We must abort and
		 * wake the other side up.
		 */
		msg->err_state = msg->msg_state;
		msg->msg_state = HTTP_MSG_ERROR;
		http_resync_states(s);
		return 1;
	}

	/* in most states, we should abort in case of early close */
	channel_auto_close(res);

	if (msg->msg_state == HTTP_MSG_BODY) {
		msg->msg_state = ((msg->flags & HTTP_MSGF_TE_CHNK)
				  ? HTTP_MSG_CHUNK_SIZE
				  : HTTP_MSG_DATA);
	}

	if (res->to_forward) {
                /* We can't process the buffer's contents yet */
		res->flags |= CF_WAKE_WRITE;
		goto missing_data_or_waiting;
	}

	if (msg->msg_state < HTTP_MSG_DONE) {
		ret = ((msg->flags & HTTP_MSGF_TE_CHNK)
		       ? http_msg_forward_chunked_body(s, msg)
		       : http_msg_forward_body(s, msg));
		if (!ret)
			goto missing_data_or_waiting;
		if (ret < 0)
			goto return_bad_res;
	}

	/* other states, DONE...TUNNEL */
	/* for keep-alive we don't want to forward closes on DONE */
	if ((txn->flags & TX_CON_WANT_MSK) == TX_CON_WANT_KAL ||
	    (txn->flags & TX_CON_WANT_MSK) == TX_CON_WANT_SCL)
		channel_dont_close(res);

	http_resync_states(s);
	if (!(res->analysers & an_bit)) {
		if (unlikely(msg->msg_state == HTTP_MSG_ERROR)) {
			if (res->flags & CF_SHUTW) {
				/* response errors are most likely due to the
				 * client aborting the transfer. */
				goto aborted_xfer;
			}
			if (msg->err_pos >= 0)
				http_capture_bad_message(s->be, s, msg, msg->err_state, strm_fe(s));
			goto return_bad_res;
		}
		return 1;
	}
	return 0;

  missing_data_or_waiting:
	if (res->flags & CF_SHUTW)
		goto aborted_xfer;

	/* stop waiting for data if the input is closed before the end. If the
	 * client side was already closed, it means that the client has aborted,
	 * so we don't want to count this as a server abort. Otherwise it's a
	 * server abort.
	 */
	if (msg->msg_state < HTTP_MSG_ENDING && res->flags & CF_SHUTR) {
		if ((s->req.flags & (CF_SHUTR|CF_SHUTW)) == (CF_SHUTR|CF_SHUTW))
			goto aborted_xfer;
		/* If we have some pending data, we continue the processing */
		if (!ci_data(res)) {
			if (!(s->flags & SF_ERR_MASK))
				s->flags |= SF_ERR_SRVCL;
			HA_ATOMIC_ADD(&s->be->be_counters.srv_aborts, 1);
			if (objt_server(s->target))
				HA_ATOMIC_ADD(&objt_server(s->target)->counters.srv_aborts, 1);
			goto return_bad_res_stats_ok;
		}
	}

	/* we need to obey the req analyser, so if it leaves, we must too */
	if (!s->req.analysers)
		goto return_bad_res;

	/* When TE: chunked is used, we need to get there again to parse
	 * remaining chunks even if the server has closed, so we don't want to
	 * set CF_DONTCLOSE. Similarly, if keep-alive is set on the client side
	 * or if there are filters registered on the stream, we don't want to
	 * forward a close
	 */
	if ((msg->flags & HTTP_MSGF_TE_CHNK) ||
	    HAS_DATA_FILTERS(s, res) ||
	    (txn->flags & TX_CON_WANT_MSK) == TX_CON_WANT_KAL ||
	    (txn->flags & TX_CON_WANT_MSK) == TX_CON_WANT_SCL)
		channel_dont_close(res);

	/* We know that more data are expected, but we couldn't send more that
	 * what we did. So we always set the CF_EXPECT_MORE flag so that the
	 * system knows it must not set a PUSH on this first part. Interactive
	 * modes are already handled by the stream sock layer. We must not do
	 * this in content-length mode because it could present the MSG_MORE
	 * flag with the last block of forwarded data, which would cause an
	 * additional delay to be observed by the receiver.
	 */
	if ((msg->flags & HTTP_MSGF_TE_CHNK) || (msg->flags & HTTP_MSGF_COMPRESSING))
		res->flags |= CF_EXPECT_MORE;

	/* the stream handler will take care of timeouts and errors */
	return 0;

 return_bad_res: /* let's centralize all bad responses */
	HA_ATOMIC_ADD(&s->be->be_counters.failed_resp, 1);
	if (objt_server(s->target))
		HA_ATOMIC_ADD(&objt_server(s->target)->counters.failed_resp, 1);

 return_bad_res_stats_ok:
	txn->rsp.err_state = txn->rsp.msg_state;
	txn->rsp.msg_state = HTTP_MSG_ERROR;
	/* don't send any error message as we're in the body */
	http_reply_and_close(s, txn->status, NULL);
	res->analysers   &= AN_RES_FLT_END;
	s->req.analysers &= AN_REQ_FLT_END; /* we're in data phase, we want to abort both directions */
	if (objt_server(s->target))
		health_adjust(objt_server(s->target), HANA_STATUS_HTTP_HDRRSP);

	if (!(s->flags & SF_ERR_MASK))
		s->flags |= SF_ERR_PRXCOND;
	if (!(s->flags & SF_FINST_MASK))
		s->flags |= SF_FINST_D;
	return 0;

 aborted_xfer:
	txn->rsp.err_state = txn->rsp.msg_state;
	txn->rsp.msg_state = HTTP_MSG_ERROR;
	/* don't send any error message as we're in the body */
	http_reply_and_close(s, txn->status, NULL);
	res->analysers   &= AN_RES_FLT_END;
	s->req.analysers &= AN_REQ_FLT_END; /* we're in data phase, we want to abort both directions */

	HA_ATOMIC_ADD(&sess->fe->fe_counters.cli_aborts, 1);
	HA_ATOMIC_ADD(&s->be->be_counters.cli_aborts, 1);
	if (objt_server(s->target))
		HA_ATOMIC_ADD(&objt_server(s->target)->counters.cli_aborts, 1);

	if (!(s->flags & SF_ERR_MASK))
		s->flags |= SF_ERR_CLICL;
	if (!(s->flags & SF_FINST_MASK))
		s->flags |= SF_FINST_D;
	return 0;
}

__attribute__((constructor))
static void __htx_protocol_init(void)
{
}


/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
