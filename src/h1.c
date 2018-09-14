/*
 * HTTP/1 protocol analyzer
 *
 * Copyright 2000-2017 Willy Tarreau <w@1wt.eu>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */

#include <ctype.h>
#include <common/config.h>
#include <common/http-hdr.h>

#include <proto/channel.h>
#include <proto/h1.h>
#include <proto/hdr_idx.h>

/*
 * This function parses a status line between <ptr> and <end>, starting with
 * parser state <state>. Only states HTTP_MSG_RPVER, HTTP_MSG_RPVER_SP,
 * HTTP_MSG_RPCODE, HTTP_MSG_RPCODE_SP and HTTP_MSG_RPREASON are handled. Others
 * will give undefined results.
 * Note that it is upon the caller's responsibility to ensure that ptr < end,
 * and that msg->sol points to the beginning of the response.
 * If a complete line is found (which implies that at least one CR or LF is
 * found before <end>, the updated <ptr> is returned, otherwise NULL is
 * returned indicating an incomplete line (which does not mean that parts have
 * not been updated). In the incomplete case, if <ret_ptr> or <ret_state> are
 * non-NULL, they are fed with the new <ptr> and <state> values to be passed
 * upon next call.
 *
 * This function was intentionally designed to be called from
 * http_msg_analyzer() with the lowest overhead. It should integrate perfectly
 * within its state machine and use the same macros, hence the need for same
 * labels and variable names. Note that msg->sol is left unchanged.
 */
const char *http_parse_stsline(struct http_msg *msg,
                               enum h1_state state, const char *ptr, const char *end,
                               unsigned int *ret_ptr, enum h1_state *ret_state)
{
	const char *msg_start = ci_head(msg->chn);

	switch (state)	{
	case HTTP_MSG_RPVER:
	http_msg_rpver:
		if (likely(HTTP_IS_VER_TOKEN(*ptr)))
			EAT_AND_JUMP_OR_RETURN(ptr, end, http_msg_rpver, http_msg_ood, state, HTTP_MSG_RPVER);

		if (likely(HTTP_IS_SPHT(*ptr))) {
			msg->sl.st.v_l = ptr - msg_start;
			EAT_AND_JUMP_OR_RETURN(ptr, end, http_msg_rpver_sp, http_msg_ood, state, HTTP_MSG_RPVER_SP);
		}
		msg->err_state = HTTP_MSG_RPVER;
		state = HTTP_MSG_ERROR;
		break;

	case HTTP_MSG_RPVER_SP:
	http_msg_rpver_sp:
		if (likely(!HTTP_IS_LWS(*ptr))) {
			msg->sl.st.c = ptr - msg_start;
			goto http_msg_rpcode;
		}
		if (likely(HTTP_IS_SPHT(*ptr)))
			EAT_AND_JUMP_OR_RETURN(ptr, end, http_msg_rpver_sp, http_msg_ood, state, HTTP_MSG_RPVER_SP);
		/* so it's a CR/LF, this is invalid */
		msg->err_state = HTTP_MSG_RPVER_SP;
		state = HTTP_MSG_ERROR;
		break;

	case HTTP_MSG_RPCODE:
	http_msg_rpcode:
		if (likely(!HTTP_IS_LWS(*ptr)))
			EAT_AND_JUMP_OR_RETURN(ptr, end, http_msg_rpcode, http_msg_ood, state, HTTP_MSG_RPCODE);

		if (likely(HTTP_IS_SPHT(*ptr))) {
			msg->sl.st.c_l = ptr - msg_start - msg->sl.st.c;
			EAT_AND_JUMP_OR_RETURN(ptr, end, http_msg_rpcode_sp, http_msg_ood, state, HTTP_MSG_RPCODE_SP);
		}

		/* so it's a CR/LF, so there is no reason phrase */
		msg->sl.st.c_l = ptr - msg_start - msg->sl.st.c;
	http_msg_rsp_reason:
		/* FIXME: should we support HTTP responses without any reason phrase ? */
		msg->sl.st.r = ptr - msg_start;
		msg->sl.st.r_l = 0;
		goto http_msg_rpline_eol;

	case HTTP_MSG_RPCODE_SP:
	http_msg_rpcode_sp:
		if (likely(!HTTP_IS_LWS(*ptr))) {
			msg->sl.st.r = ptr - msg_start;
			goto http_msg_rpreason;
		}
		if (likely(HTTP_IS_SPHT(*ptr)))
			EAT_AND_JUMP_OR_RETURN(ptr, end, http_msg_rpcode_sp, http_msg_ood, state, HTTP_MSG_RPCODE_SP);
		/* so it's a CR/LF, so there is no reason phrase */
		goto http_msg_rsp_reason;

	case HTTP_MSG_RPREASON:
	http_msg_rpreason:
		if (likely(!HTTP_IS_CRLF(*ptr)))
			EAT_AND_JUMP_OR_RETURN(ptr, end, http_msg_rpreason, http_msg_ood, state, HTTP_MSG_RPREASON);
		msg->sl.st.r_l = ptr - msg_start - msg->sl.st.r;
	http_msg_rpline_eol:
		/* We have seen the end of line. Note that we do not
		 * necessarily have the \n yet, but at least we know that we
		 * have EITHER \r OR \n, otherwise the response would not be
		 * complete. We can then record the response length and return
		 * to the caller which will be able to register it.
		 */
		msg->sl.st.l = ptr - msg_start - msg->sol;
		return ptr;

	default:
#ifdef DEBUG_FULL
		fprintf(stderr, "FIXME !!!! impossible state at %s:%d = %d\n", __FILE__, __LINE__, state);
		exit(1);
#endif
		;
	}

 http_msg_ood:
	/* out of valid data */
	if (ret_state)
		*ret_state = state;
	if (ret_ptr)
		*ret_ptr = ptr - msg_start;
	return NULL;
}

/*
 * This function parses a request line between <ptr> and <end>, starting with
 * parser state <state>. Only states HTTP_MSG_RQMETH, HTTP_MSG_RQMETH_SP,
 * HTTP_MSG_RQURI, HTTP_MSG_RQURI_SP and HTTP_MSG_RQVER are handled. Others
 * will give undefined results.
 * Note that it is upon the caller's responsibility to ensure that ptr < end,
 * and that msg->sol points to the beginning of the request.
 * If a complete line is found (which implies that at least one CR or LF is
 * found before <end>, the updated <ptr> is returned, otherwise NULL is
 * returned indicating an incomplete line (which does not mean that parts have
 * not been updated). In the incomplete case, if <ret_ptr> or <ret_state> are
 * non-NULL, they are fed with the new <ptr> and <state> values to be passed
 * upon next call.
 *
 * This function was intentionally designed to be called from
 * http_msg_analyzer() with the lowest overhead. It should integrate perfectly
 * within its state machine and use the same macros, hence the need for same
 * labels and variable names. Note that msg->sol is left unchanged.
 */
const char *http_parse_reqline(struct http_msg *msg,
			       enum h1_state state, const char *ptr, const char *end,
			       unsigned int *ret_ptr, enum h1_state *ret_state)
{
	const char *msg_start = ci_head(msg->chn);

	switch (state)	{
	case HTTP_MSG_RQMETH:
	http_msg_rqmeth:
		if (likely(HTTP_IS_TOKEN(*ptr)))
			EAT_AND_JUMP_OR_RETURN(ptr, end, http_msg_rqmeth, http_msg_ood, state, HTTP_MSG_RQMETH);

		if (likely(HTTP_IS_SPHT(*ptr))) {
			msg->sl.rq.m_l = ptr - msg_start;
			EAT_AND_JUMP_OR_RETURN(ptr, end, http_msg_rqmeth_sp, http_msg_ood, state, HTTP_MSG_RQMETH_SP);
		}

		if (likely(HTTP_IS_CRLF(*ptr))) {
			/* HTTP 0.9 request */
			msg->sl.rq.m_l = ptr - msg_start;
		http_msg_req09_uri:
			msg->sl.rq.u = ptr - msg_start;
		http_msg_req09_uri_e:
			msg->sl.rq.u_l = ptr - msg_start - msg->sl.rq.u;
		http_msg_req09_ver:
			msg->sl.rq.v = ptr - msg_start;
			msg->sl.rq.v_l = 0;
			goto http_msg_rqline_eol;
		}
		msg->err_state = HTTP_MSG_RQMETH;
		state = HTTP_MSG_ERROR;
		break;

	case HTTP_MSG_RQMETH_SP:
	http_msg_rqmeth_sp:
		if (likely(!HTTP_IS_LWS(*ptr))) {
			msg->sl.rq.u = ptr - msg_start;
			goto http_msg_rquri;
		}
		if (likely(HTTP_IS_SPHT(*ptr)))
			EAT_AND_JUMP_OR_RETURN(ptr, end, http_msg_rqmeth_sp, http_msg_ood, state, HTTP_MSG_RQMETH_SP);
		/* so it's a CR/LF, meaning an HTTP 0.9 request */
		goto http_msg_req09_uri;

	case HTTP_MSG_RQURI:
	http_msg_rquri:
#if defined(__x86_64__) ||						\
    defined(__i386__) || defined(__i486__) || defined(__i586__) || defined(__i686__) || \
    defined(__ARM_ARCH_7A__)
		/* speedup: skip bytes not between 0x21 and 0x7e inclusive */
		while (ptr <= end - sizeof(int)) {
			int x = *(int *)ptr - 0x21212121;
			if (x & 0x80808080)
				break;

			x -= 0x5e5e5e5e;
			if (!(x & 0x80808080))
				break;

			ptr += sizeof(int);
		}
#endif
		if (ptr >= end) {
			state = HTTP_MSG_RQURI;
			goto http_msg_ood;
		}
	http_msg_rquri2:
		if (likely((unsigned char)(*ptr - 33) <= 93)) /* 33 to 126 included */
			EAT_AND_JUMP_OR_RETURN(ptr, end, http_msg_rquri2, http_msg_ood, state, HTTP_MSG_RQURI);

		if (likely(HTTP_IS_SPHT(*ptr))) {
			msg->sl.rq.u_l = ptr - msg_start - msg->sl.rq.u;
			EAT_AND_JUMP_OR_RETURN(ptr, end, http_msg_rquri_sp, http_msg_ood, state, HTTP_MSG_RQURI_SP);
		}

		if (likely((unsigned char)*ptr >= 128)) {
			/* non-ASCII chars are forbidden unless option
			 * accept-invalid-http-request is enabled in the frontend.
			 * In any case, we capture the faulty char.
			 */
			if (msg->err_pos < -1)
				goto invalid_char;
			if (msg->err_pos == -1)
				msg->err_pos = ptr - msg_start;
			EAT_AND_JUMP_OR_RETURN(ptr, end, http_msg_rquri, http_msg_ood, state, HTTP_MSG_RQURI);
		}

		if (likely(HTTP_IS_CRLF(*ptr))) {
			/* so it's a CR/LF, meaning an HTTP 0.9 request */
			goto http_msg_req09_uri_e;
		}

		/* OK forbidden chars, 0..31 or 127 */
	invalid_char:
		msg->err_pos = ptr - msg_start;
		msg->err_state = HTTP_MSG_RQURI;
		state = HTTP_MSG_ERROR;
		break;

	case HTTP_MSG_RQURI_SP:
	http_msg_rquri_sp:
		if (likely(!HTTP_IS_LWS(*ptr))) {
			msg->sl.rq.v = ptr - msg_start;
			goto http_msg_rqver;
		}
		if (likely(HTTP_IS_SPHT(*ptr)))
			EAT_AND_JUMP_OR_RETURN(ptr, end, http_msg_rquri_sp, http_msg_ood, state, HTTP_MSG_RQURI_SP);
		/* so it's a CR/LF, meaning an HTTP 0.9 request */
		goto http_msg_req09_ver;

	case HTTP_MSG_RQVER:
	http_msg_rqver:
		if (likely(HTTP_IS_VER_TOKEN(*ptr)))
			EAT_AND_JUMP_OR_RETURN(ptr, end, http_msg_rqver, http_msg_ood, state, HTTP_MSG_RQVER);

		if (likely(HTTP_IS_CRLF(*ptr))) {
			msg->sl.rq.v_l = ptr - msg_start - msg->sl.rq.v;
		http_msg_rqline_eol:
			/* We have seen the end of line. Note that we do not
			 * necessarily have the \n yet, but at least we know that we
			 * have EITHER \r OR \n, otherwise the request would not be
			 * complete. We can then record the request length and return
			 * to the caller which will be able to register it.
			 */
			msg->sl.rq.l = ptr - msg_start - msg->sol;
			return ptr;
		}

		/* neither an HTTP_VER token nor a CRLF */
		msg->err_state = HTTP_MSG_RQVER;
		state = HTTP_MSG_ERROR;
		break;

	default:
#ifdef DEBUG_FULL
		fprintf(stderr, "FIXME !!!! impossible state at %s:%d = %d\n", __FILE__, __LINE__, state);
		exit(1);
#endif
		;
	}

 http_msg_ood:
	/* out of valid data */
	if (ret_state)
		*ret_state = state;
	if (ret_ptr)
		*ret_ptr = ptr - msg_start;
	return NULL;
}

/*
 * This function parses an HTTP message, either a request or a response,
 * depending on the initial msg->msg_state. The caller is responsible for
 * ensuring that the message does not wrap. The function can be preempted
 * everywhere when data are missing and recalled at the exact same location
 * with no information loss. The message may even be realigned between two
 * calls. The header index is re-initialized when switching from
 * MSG_R[PQ]BEFORE to MSG_RPVER|MSG_RQMETH. It modifies msg->sol among other
 * fields. Note that msg->sol will be initialized after completing the first
 * state, so that none of the msg pointers has to be initialized prior to the
 * first call.
 */
void http_msg_analyzer(struct http_msg *msg, struct hdr_idx *idx)
{
	enum h1_state state;       /* updated only when leaving the FSM */
	register const char *ptr, *end; /* request pointers, to avoid dereferences */
	struct buffer *buf = &msg->chn->buf;
	char *input = b_head(buf);

	state = msg->msg_state;
	ptr = input + msg->next;
	end = b_stop(buf);

	if (unlikely(ptr >= end))
		goto http_msg_ood;

	switch (state)	{
	/*
	 * First, states that are specific to the response only.
	 * We check them first so that request and headers are
	 * closer to each other (accessed more often).
	 */
	case HTTP_MSG_RPBEFORE:
	http_msg_rpbefore:
		if (likely(HTTP_IS_TOKEN(*ptr))) {
			/* we have a start of message, but we have to check
			 * first if we need to remove some CRLF. We can only
			 * do this when o=0.
			 */
			if (unlikely(ptr != input)) {
				if (co_data(msg->chn))
					goto http_msg_ood;
				/* Remove empty leading lines, as recommended by RFC2616. */
				b_del(buf, ptr - input);
				input = b_head(buf);
			}
			msg->sol = 0;
			msg->sl.st.l = 0; /* used in debug mode */
			hdr_idx_init(idx);
			state = HTTP_MSG_RPVER;
			goto http_msg_rpver;
		}

		if (unlikely(!HTTP_IS_CRLF(*ptr))) {
			state = HTTP_MSG_RPBEFORE;
			goto http_msg_invalid;
		}

		if (unlikely(*ptr == '\n'))
			EAT_AND_JUMP_OR_RETURN(ptr, end, http_msg_rpbefore, http_msg_ood, state, HTTP_MSG_RPBEFORE);
		EAT_AND_JUMP_OR_RETURN(ptr, end, http_msg_rpbefore_cr, http_msg_ood, state, HTTP_MSG_RPBEFORE_CR);
		/* stop here */

	case HTTP_MSG_RPBEFORE_CR:
	http_msg_rpbefore_cr:
		EXPECT_LF_HERE(ptr, http_msg_invalid, state, HTTP_MSG_RPBEFORE_CR);
		EAT_AND_JUMP_OR_RETURN(ptr, end, http_msg_rpbefore, http_msg_ood, state, HTTP_MSG_RPBEFORE);
		/* stop here */

	case HTTP_MSG_RPVER:
	http_msg_rpver:
	case HTTP_MSG_RPVER_SP:
	case HTTP_MSG_RPCODE:
	case HTTP_MSG_RPCODE_SP:
	case HTTP_MSG_RPREASON:
		ptr = (char *)http_parse_stsline(msg,
						 state, ptr, end,
						 &msg->next, &msg->msg_state);
		if (unlikely(!ptr))
			return;

		/* we have a full response and we know that we have either a CR
		 * or an LF at <ptr>.
		 */
		hdr_idx_set_start(idx, msg->sl.st.l, *ptr == '\r');

		msg->sol = ptr - input;
		if (likely(*ptr == '\r'))
			EAT_AND_JUMP_OR_RETURN(ptr, end, http_msg_rpline_end, http_msg_ood, state, HTTP_MSG_RPLINE_END);
		goto http_msg_rpline_end;

	case HTTP_MSG_RPLINE_END:
	http_msg_rpline_end:
		/* msg->sol must point to the first of CR or LF. */
		EXPECT_LF_HERE(ptr, http_msg_invalid, state, HTTP_MSG_RPLINE_END);
		EAT_AND_JUMP_OR_RETURN(ptr, end, http_msg_hdr_first, http_msg_ood, state, HTTP_MSG_HDR_FIRST);
		/* stop here */

	/*
	 * Second, states that are specific to the request only
	 */
	case HTTP_MSG_RQBEFORE:
	http_msg_rqbefore:
		if (likely(HTTP_IS_TOKEN(*ptr))) {
			/* we have a start of message, but we have to check
			 * first if we need to remove some CRLF. We can only
			 * do this when o=0.
			 */
			if (likely(ptr != input)) {
				if (co_data(msg->chn))
					goto http_msg_ood;
				/* Remove empty leading lines, as recommended by RFC2616. */
				b_del(buf, ptr - input);
				input = b_head(buf);
			}
			msg->sol = 0;
			msg->sl.rq.l = 0; /* used in debug mode */
			state = HTTP_MSG_RQMETH;
			goto http_msg_rqmeth;
		}

		if (unlikely(!HTTP_IS_CRLF(*ptr))) {
			state = HTTP_MSG_RQBEFORE;
			goto http_msg_invalid;
		}

		if (unlikely(*ptr == '\n'))
			EAT_AND_JUMP_OR_RETURN(ptr, end, http_msg_rqbefore, http_msg_ood, state, HTTP_MSG_RQBEFORE);
		EAT_AND_JUMP_OR_RETURN(ptr, end, http_msg_rqbefore_cr, http_msg_ood, state, HTTP_MSG_RQBEFORE_CR);
		/* stop here */

	case HTTP_MSG_RQBEFORE_CR:
	http_msg_rqbefore_cr:
		EXPECT_LF_HERE(ptr, http_msg_invalid, state, HTTP_MSG_RQBEFORE_CR);
		EAT_AND_JUMP_OR_RETURN(ptr, end, http_msg_rqbefore, http_msg_ood, state, HTTP_MSG_RQBEFORE);
		/* stop here */

	case HTTP_MSG_RQMETH:
	http_msg_rqmeth:
	case HTTP_MSG_RQMETH_SP:
	case HTTP_MSG_RQURI:
	case HTTP_MSG_RQURI_SP:
	case HTTP_MSG_RQVER:
		ptr = (char *)http_parse_reqline(msg,
						 state, ptr, end,
						 &msg->next, &msg->msg_state);
		if (unlikely(!ptr))
			return;

		/* we have a full request and we know that we have either a CR
		 * or an LF at <ptr>.
		 */
		hdr_idx_set_start(idx, msg->sl.rq.l, *ptr == '\r');

		msg->sol = ptr - input;
		if (likely(*ptr == '\r'))
			EAT_AND_JUMP_OR_RETURN(ptr, end, http_msg_rqline_end, http_msg_ood, state, HTTP_MSG_RQLINE_END);
		goto http_msg_rqline_end;

	case HTTP_MSG_RQLINE_END:
	http_msg_rqline_end:
		/* check for HTTP/0.9 request : no version information available.
		 * msg->sol must point to the first of CR or LF.
		 */
		if (unlikely(msg->sl.rq.v_l == 0))
			goto http_msg_last_lf;

		EXPECT_LF_HERE(ptr, http_msg_invalid, state, HTTP_MSG_RQLINE_END);
		EAT_AND_JUMP_OR_RETURN(ptr, end, http_msg_hdr_first, http_msg_ood, state, HTTP_MSG_HDR_FIRST);
		/* stop here */

	/*
	 * Common states below
	 */
	case HTTP_MSG_HDR_FIRST:
	http_msg_hdr_first:
		msg->sol = ptr - input;
		if (likely(!HTTP_IS_CRLF(*ptr))) {
			goto http_msg_hdr_name;
		}

		if (likely(*ptr == '\r'))
			EAT_AND_JUMP_OR_RETURN(ptr, end, http_msg_last_lf, http_msg_ood, state, HTTP_MSG_LAST_LF);
		goto http_msg_last_lf;

	case HTTP_MSG_HDR_NAME:
	http_msg_hdr_name:
		/* assumes msg->sol points to the first char */
		if (likely(HTTP_IS_TOKEN(*ptr)))
			EAT_AND_JUMP_OR_RETURN(ptr, end, http_msg_hdr_name, http_msg_ood, state, HTTP_MSG_HDR_NAME);

		if (likely(*ptr == ':'))
			EAT_AND_JUMP_OR_RETURN(ptr, end, http_msg_hdr_l1_sp, http_msg_ood, state, HTTP_MSG_HDR_L1_SP);

		if (likely(msg->err_pos < -1) || *ptr == '\n') {
			state = HTTP_MSG_HDR_NAME;
			goto http_msg_invalid;
		}

		if (msg->err_pos == -1) /* capture error pointer */
			msg->err_pos = ptr - input; /* >= 0 now */

		/* and we still accept this non-token character */
		EAT_AND_JUMP_OR_RETURN(ptr, end, http_msg_hdr_name, http_msg_ood, state, HTTP_MSG_HDR_NAME);

	case HTTP_MSG_HDR_L1_SP:
	http_msg_hdr_l1_sp:
		/* assumes msg->sol points to the first char */
		if (likely(HTTP_IS_SPHT(*ptr)))
			EAT_AND_JUMP_OR_RETURN(ptr, end, http_msg_hdr_l1_sp, http_msg_ood, state, HTTP_MSG_HDR_L1_SP);

		/* header value can be basically anything except CR/LF */
		msg->sov = ptr - input;

		if (likely(!HTTP_IS_CRLF(*ptr))) {
			goto http_msg_hdr_val;
		}

		if (likely(*ptr == '\r'))
			EAT_AND_JUMP_OR_RETURN(ptr, end, http_msg_hdr_l1_lf, http_msg_ood, state, HTTP_MSG_HDR_L1_LF);
		goto http_msg_hdr_l1_lf;

	case HTTP_MSG_HDR_L1_LF:
	http_msg_hdr_l1_lf:
		EXPECT_LF_HERE(ptr, http_msg_invalid, state, HTTP_MSG_HDR_L1_LF);
		EAT_AND_JUMP_OR_RETURN(ptr, end, http_msg_hdr_l1_lws, http_msg_ood, state, HTTP_MSG_HDR_L1_LWS);

	case HTTP_MSG_HDR_L1_LWS:
	http_msg_hdr_l1_lws:
		if (likely(HTTP_IS_SPHT(*ptr))) {
			/* replace HT,CR,LF with spaces */
			for (; input + msg->sov < ptr; msg->sov++)
				input[msg->sov] = ' ';
			goto http_msg_hdr_l1_sp;
		}
		/* we had a header consisting only in spaces ! */
		msg->eol = msg->sov;
		goto http_msg_complete_header;

	case HTTP_MSG_HDR_VAL:
	http_msg_hdr_val:
		/* assumes msg->sol points to the first char, and msg->sov
		 * points to the first character of the value.
		 */

		/* speedup: we'll skip packs of 4 or 8 bytes not containing bytes 0x0D
		 * and lower. In fact since most of the time is spent in the loop, we
		 * also remove the sign bit test so that bytes 0x8e..0x0d break the
		 * loop, but we don't care since they're very rare in header values.
		 */
#if defined(__x86_64__)
		while (ptr <= end - sizeof(long)) {
			if ((*(long *)ptr - 0x0e0e0e0e0e0e0e0eULL) & 0x8080808080808080ULL)
				goto http_msg_hdr_val2;
			ptr += sizeof(long);
		}
#endif
#if defined(__x86_64__) || \
    defined(__i386__) || defined(__i486__) || defined(__i586__) || defined(__i686__) || \
    defined(__ARM_ARCH_7A__)
		while (ptr <= end - sizeof(int)) {
			if ((*(int*)ptr - 0x0e0e0e0e) & 0x80808080)
				goto http_msg_hdr_val2;
			ptr += sizeof(int);
		}
#endif
		if (ptr >= end) {
			state = HTTP_MSG_HDR_VAL;
			goto http_msg_ood;
		}
	http_msg_hdr_val2:
		if (likely(!HTTP_IS_CRLF(*ptr)))
			EAT_AND_JUMP_OR_RETURN(ptr, end, http_msg_hdr_val2, http_msg_ood, state, HTTP_MSG_HDR_VAL);

		msg->eol = ptr - input;
		/* Note: we could also copy eol into ->eoh so that we have the
		 * real header end in case it ends with lots of LWS, but is this
		 * really needed ?
		 */
		if (likely(*ptr == '\r'))
			EAT_AND_JUMP_OR_RETURN(ptr, end, http_msg_hdr_l2_lf, http_msg_ood, state, HTTP_MSG_HDR_L2_LF);
		goto http_msg_hdr_l2_lf;

	case HTTP_MSG_HDR_L2_LF:
	http_msg_hdr_l2_lf:
		EXPECT_LF_HERE(ptr, http_msg_invalid, state, HTTP_MSG_HDR_L2_LF);
		EAT_AND_JUMP_OR_RETURN(ptr, end, http_msg_hdr_l2_lws, http_msg_ood, state, HTTP_MSG_HDR_L2_LWS);

	case HTTP_MSG_HDR_L2_LWS:
	http_msg_hdr_l2_lws:
		if (unlikely(HTTP_IS_SPHT(*ptr))) {
			/* LWS: replace HT,CR,LF with spaces */
			for (; input + msg->eol < ptr; msg->eol++)
				input[msg->eol] = ' ';
			goto http_msg_hdr_val;
		}
	http_msg_complete_header:
		/*
		 * It was a new header, so the last one is finished.
		 * Assumes msg->sol points to the first char, msg->sov points
		 * to the first character of the value and msg->eol to the
		 * first CR or LF so we know how the line ends. We insert last
		 * header into the index.
		 */
		if (unlikely(hdr_idx_add(msg->eol - msg->sol, input[msg->eol] == '\r',
					 idx, idx->tail) < 0)) {
			state = HTTP_MSG_HDR_L2_LWS;
			goto http_msg_invalid;
		}

		msg->sol = ptr - input;
		if (likely(!HTTP_IS_CRLF(*ptr))) {
			goto http_msg_hdr_name;
		}

		if (likely(*ptr == '\r'))
			EAT_AND_JUMP_OR_RETURN(ptr, end, http_msg_last_lf, http_msg_ood, state, HTTP_MSG_LAST_LF);
		goto http_msg_last_lf;

	case HTTP_MSG_LAST_LF:
	http_msg_last_lf:
		/* Assumes msg->sol points to the first of either CR or LF.
		 * Sets ->sov and ->next to the total header length, ->eoh to
		 * the last CRLF, and ->eol to the last CRLF length (1 or 2).
		 */
		EXPECT_LF_HERE(ptr, http_msg_invalid, state, HTTP_MSG_LAST_LF);
		ptr++;
		msg->sov = msg->next = ptr - input;
		msg->eoh = msg->sol;
		msg->sol = 0;
		msg->eol = msg->sov - msg->eoh;
		msg->msg_state = HTTP_MSG_BODY;
		return;

	case HTTP_MSG_ERROR:
		/* this may only happen if we call http_msg_analyser() twice with an error */
		break;

	default:
#ifdef DEBUG_FULL
		fprintf(stderr, "FIXME !!!! impossible state at %s:%d = %d\n", __FILE__, __LINE__, state);
		exit(1);
#endif
		;
	}
 http_msg_ood:
	/* out of data */
	msg->msg_state = state;
	msg->next = ptr - input;
	return;

 http_msg_invalid:
	/* invalid message */
	msg->err_state = state;
	msg->msg_state = HTTP_MSG_ERROR;
	msg->next = ptr - input;
	return;
}


/* Parse the Content-Length header field of an HTTP/1 request. The function
 * checks all possible occurrences of a comma-delimited value, and verifies
 * if any of them doesn't match a previous value. It returns <0 if a value
 * differs, 0 if the whole header can be dropped (i.e. already known), or >0
 * if the value can be indexed (first one). In the last case, the value might
 * be adjusted and the caller must only add the updated value.
 */
int h1_parse_cont_len_header(struct h1m *h1m, struct ist *value)
{
	char *e, *n;
	long long cl;
	int not_first = !!(h1m->flags & H1_MF_CLEN);
	struct ist word;

	word.ptr = value->ptr - 1; // -1 for next loop's pre-increment
	e = value->ptr + value->len;

	while (++word.ptr < e) {
		/* skip leading delimitor and blanks */
		if (unlikely(HTTP_IS_LWS(*word.ptr)))
			continue;

		/* digits only now */
		for (cl = 0, n = word.ptr; n < e; n++) {
			unsigned int c = *n - '0';
			if (unlikely(c > 9)) {
				/* non-digit */
				if (unlikely(n == word.ptr)) // spaces only
					goto fail;
				break;
			}
			if (unlikely(cl > ULLONG_MAX / 10ULL))
				goto fail; /* multiply overflow */
			cl = cl * 10ULL;
			if (unlikely(cl + c < cl))
				goto fail; /* addition overflow */
			cl = cl + c;
		}

		/* keep a copy of the exact cleaned value */
		word.len = n - word.ptr;

		/* skip trailing LWS till next comma or EOL */
		for (; n < e; n++) {
			if (!HTTP_IS_LWS(*n)) {
				if (unlikely(*n != ','))
					goto fail;
				break;
			}
		}

		/* if duplicate, must be equal */
		if (h1m->flags & H1_MF_CLEN && cl != h1m->body_len)
			goto fail;

		/* OK, store this result as the one to be indexed */
		h1m->flags |= H1_MF_CLEN;
		h1m->curr_len = h1m->body_len = cl;
		*value = word;
		word.ptr = n;
	}
	/* here we've reached the end with a single value or a series of
	 * identical values, all matching previous series if any. The last
	 * parsed value was sent back into <value>. We just have to decide
	 * if this occurrence has to be indexed (it's the first one) or
	 * silently skipped (it's not the first one)
	 */
	return !not_first;
 fail:
	return -1;
}

/* Parse the Transfer-Encoding: header field of an HTTP/1 request, looking for
 * "chunked" being the last value, and setting H1_MF_CHNK in h1m->flags only in
 * this case. Any other token found or any empty header field found will reset
 * this flag, so that it accurately represents the token's presence at the last
 * position. The H1_MF_XFER_ENC flag is always set. Note that transfer codings
 * are case-insensitive (cf RFC7230#4).
 */
void h1_parse_xfer_enc_header(struct h1m *h1m, struct ist value)
{
	char *e, *n;
	struct ist word;

	h1m->flags |= H1_MF_XFER_ENC;
	h1m->flags &= ~H1_MF_CHNK;

	word.ptr = value.ptr - 1; // -1 for next loop's pre-increment
	e = value.ptr + value.len;

	while (++word.ptr < e) {
		/* skip leading delimitor and blanks */
		if (HTTP_IS_LWS(*word.ptr))
			continue;

		n = http_find_hdr_value_end(word.ptr, e); // next comma or end of line
		word.len = n - word.ptr;

		/* trim trailing blanks */
		while (word.len && HTTP_IS_LWS(word.ptr[word.len-1]))
			word.len--;

		h1m->flags &= ~H1_MF_CHNK;
		if (isteqi(word, ist("chunked")))
			h1m->flags |= H1_MF_CHNK;

		word.ptr = n;
	}
}

/* Parse the Connection: header of an HTTP/1 request, looking for "close",
 * "keep-alive", and "upgrade" values, and updating h1m->flags according to
 * what was found there. Note that flags are only added, not removed, so the
 * function is safe for being called multiple times if multiple occurrences
 * are found.
 */
void h1_parse_connection_header(struct h1m *h1m, struct ist value)
{
	char *e, *n;
	struct ist word;

	word.ptr = value.ptr - 1; // -1 for next loop's pre-increment
	e = value.ptr + value.len;

	while (++word.ptr < e) {
		/* skip leading delimitor and blanks */
		if (HTTP_IS_LWS(*word.ptr))
			continue;

		n = http_find_hdr_value_end(word.ptr, e); // next comma or end of line
		word.len = n - word.ptr;

		/* trim trailing blanks */
		while (word.len && HTTP_IS_LWS(word.ptr[word.len-1]))
			word.len--;

		if (isteqi(word, ist("keep-alive")))
			h1m->flags |= H1_MF_CONN_KAL;
		else if (isteqi(word, ist("close")))
			h1m->flags |= H1_MF_CONN_CLO;
		else if (isteqi(word, ist("upgrade")))
			h1m->flags |= H1_MF_CONN_UPG;

		word.ptr = n;
	}
}

/* This function parses a contiguous HTTP/1 headers block starting at <start>
 * and ending before <stop>, at once, and converts it a list of (name,value)
 * pairs representing header fields into the array <hdr> of size <hdr_num>,
 * whose last entry will have an empty name and an empty value. If <hdr_num> is
 * too small to represent the whole message, an error is returned. Some
 * protocol elements such as content-length and transfer-encoding will be
 * parsed and stored into h1m as well. <hdr> may be null, in which case only
 * the parsing state will be updated. This may be used to restart the parsing
 * where it stopped for example.
 *
 * For now it's limited to the response. If the header block is incomplete,
 * 0 is returned, waiting to be called again with more data to try it again.
 * The caller is responsible for initializing h1m->state to H1_MSG_RPBEFORE,
 * and h1m->next to zero on the first call, the parser will do the rest. If
 * an incomplete message is seen, the caller only needs to present h1m->state
 * and h1m->next again, with an empty header list so that the parser can start
 * again. In this case, it will detect that it interrupted a previous session
 * and will first look for the end of the message before reparsing it again and
 * indexing it at the same time. This ensures that incomplete messages fed 1
 * character at a time are never processed entirely more than exactly twice,
 * and that there is no need to store all the internal state and pre-parsed
 * headers or start line between calls.
 *
 * A pointer to a start line descriptor may be passed in <slp>, in which case
 * the parser will fill it with whatever it found.
 *
 * The code derived from the main HTTP/1 parser above but was simplified and
 * optimized to process responses produced or forwarded by haproxy. The caller
 * is responsible for ensuring that the message doesn't wrap, and should ensure
 * it is complete to avoid having to retry the operation after a failed
 * attempt. The message is not supposed to be invalid, which is why a few
 * properties such as the character set used in the header field names are not
 * checked. In case of an unparsable response message, a negative value will be
 * returned with h1m->err_pos and h1m->err_state matching the location and
 * state where the error was met. Leading blank likes are tolerated but not
 * recommended.
 *
 * This function returns :
 *    -1 in case of error. In this case, h1m->err_state is filled (if h1m is
 *       set) with the state the error occurred in and h1m->err_pos with the
 *       the position relative to <start>
 *    -2 if the output is full (hdr_num reached). err_state and err_pos also
 *       indicate where it failed.
 *     0 in case of missing data.
 *   > 0 on success, it then corresponds to the number of bytes read since
 *       <start> so that the caller can go on with the payload.
 */
int h1_headers_to_hdr_list(char *start, const char *stop,
                           struct http_hdr *hdr, unsigned int hdr_num,
                           struct h1m *h1m, union h1_sl *slp)
{
	enum h1m_state state;
	register char *ptr;
	register const char *end;
	unsigned int hdr_count;
	unsigned int skip; /* number of bytes skipped at the beginning */
	unsigned int sol;  /* start of line */
	unsigned int col;  /* position of the colon */
	unsigned int eol;  /* end of line */
	unsigned int sov;  /* start of value */
	union h1_sl sl;
	int skip_update;
	int restarting;
	struct ist n, v;       /* header name and value during parsing */

	skip = 0; // do it only once to keep track of the leading CRLF.

 try_again:
	hdr_count = sol = col = eol = sov = 0;
	sl.st.status = 0;
	skip_update = restarting = 0;

	ptr   = start + h1m->next;
	end   = stop;
	state = h1m->state;

	if (state != H1_MSG_RQBEFORE && state != H1_MSG_RPBEFORE)
		restarting = 1;

	if (unlikely(ptr >= end))
		goto http_msg_ood;

	/* don't update output if hdr is NULL or if we're restarting */
	if (!hdr || restarting)
		skip_update = 1;

	switch (state)	{
	case H1_MSG_RQBEFORE:
	http_msg_rqbefore:
		if (likely(HTTP_IS_TOKEN(*ptr))) {
			/* we have a start of message, we may have skipped some
			 * heading CRLF. Skip them now.
			 */
			skip += ptr - start;
			start = ptr;

			sol = 0;
			sl.rq.m = skip;
			hdr_count = 0;
			state = H1_MSG_RQMETH;
			goto http_msg_rqmeth;
		}

		if (unlikely(!HTTP_IS_CRLF(*ptr))) {
			state = H1_MSG_RQBEFORE;
			goto http_msg_invalid;
		}

		if (unlikely(*ptr == '\n'))
			EAT_AND_JUMP_OR_RETURN(ptr, end, http_msg_rqbefore, http_msg_ood, state, H1_MSG_RQBEFORE);
		EAT_AND_JUMP_OR_RETURN(ptr, end, http_msg_rqbefore_cr, http_msg_ood, state, H1_MSG_RQBEFORE_CR);
		/* stop here */

	case H1_MSG_RQBEFORE_CR:
	http_msg_rqbefore_cr:
		EXPECT_LF_HERE(ptr, http_msg_invalid, state, H1_MSG_RQBEFORE_CR);
		EAT_AND_JUMP_OR_RETURN(ptr, end, http_msg_rqbefore, http_msg_ood, state, H1_MSG_RQBEFORE);
		/* stop here */

	case H1_MSG_RQMETH:
	http_msg_rqmeth:
		if (likely(HTTP_IS_TOKEN(*ptr)))
			EAT_AND_JUMP_OR_RETURN(ptr, end, http_msg_rqmeth, http_msg_ood, state, H1_MSG_RQMETH);

		if (likely(HTTP_IS_SPHT(*ptr))) {
			sl.rq.m_l = ptr - start;
			sl.rq.meth = find_http_meth(start, sl.rq.m_l);
			EAT_AND_JUMP_OR_RETURN(ptr, end, http_msg_rqmeth_sp, http_msg_ood, state, H1_MSG_RQMETH_SP);
		}

		if (likely(HTTP_IS_CRLF(*ptr))) {
			/* HTTP 0.9 request */
			sl.rq.m_l = ptr - start;
			sl.rq.meth = find_http_meth(start, sl.rq.m_l);
		http_msg_req09_uri:
			sl.rq.u = ptr - start + skip;
		http_msg_req09_uri_e:
			sl.rq.u_l = ptr - start + skip - sl.rq.u;
		http_msg_req09_ver:
			sl.rq.v = ptr - start + skip;
			sl.rq.v_l = 0;
			goto http_msg_rqline_eol;
		}
		state = H1_MSG_RQMETH;
		goto http_msg_invalid;

	case H1_MSG_RQMETH_SP:
	http_msg_rqmeth_sp:
		if (likely(!HTTP_IS_LWS(*ptr))) {
			sl.rq.u = ptr - start + skip;
			goto http_msg_rquri;
		}
		if (likely(HTTP_IS_SPHT(*ptr)))
			EAT_AND_JUMP_OR_RETURN(ptr, end, http_msg_rqmeth_sp, http_msg_ood, state, H1_MSG_RQMETH_SP);
		/* so it's a CR/LF, meaning an HTTP 0.9 request */
		goto http_msg_req09_uri;

	case H1_MSG_RQURI:
	http_msg_rquri:
#if defined(__x86_64__) ||						\
    defined(__i386__) || defined(__i486__) || defined(__i586__) || defined(__i686__) || \
    defined(__ARM_ARCH_7A__)
		/* speedup: skip bytes not between 0x21 and 0x7e inclusive */
		while (ptr <= end - sizeof(int)) {
			int x = *(int *)ptr - 0x21212121;
			if (x & 0x80808080)
				break;

			x -= 0x5e5e5e5e;
			if (!(x & 0x80808080))
				break;

			ptr += sizeof(int);
		}
#endif
		if (ptr >= end) {
			state = H1_MSG_RQURI;
			goto http_msg_ood;
		}
	http_msg_rquri2:
		if (likely((unsigned char)(*ptr - 33) <= 93)) /* 33 to 126 included */
			EAT_AND_JUMP_OR_RETURN(ptr, end, http_msg_rquri2, http_msg_ood, state, H1_MSG_RQURI);

		if (likely(HTTP_IS_SPHT(*ptr))) {
			sl.rq.u_l = ptr - start + skip - sl.rq.u;
			EAT_AND_JUMP_OR_RETURN(ptr, end, http_msg_rquri_sp, http_msg_ood, state, H1_MSG_RQURI_SP);
		}
		if (likely((unsigned char)*ptr >= 128)) {
			/* non-ASCII chars are forbidden unless option
			 * accept-invalid-http-request is enabled in the frontend.
			 * In any case, we capture the faulty char.
			 */
			if (h1m->err_pos < -1)
				goto invalid_char;
			if (h1m->err_pos == -1)
				h1m->err_pos = ptr - start + skip;
			EAT_AND_JUMP_OR_RETURN(ptr, end, http_msg_rquri, http_msg_ood, state, H1_MSG_RQURI);
		}

		if (likely(HTTP_IS_CRLF(*ptr))) {
			/* so it's a CR/LF, meaning an HTTP 0.9 request */
			goto http_msg_req09_uri_e;
		}

		/* OK forbidden chars, 0..31 or 127 */
	invalid_char:
		state = H1_MSG_RQURI;
		goto http_msg_invalid;

	case H1_MSG_RQURI_SP:
	http_msg_rquri_sp:
		if (likely(!HTTP_IS_LWS(*ptr))) {
			sl.rq.v = ptr - start + skip;
			goto http_msg_rqver;
		}
		if (likely(HTTP_IS_SPHT(*ptr)))
			EAT_AND_JUMP_OR_RETURN(ptr, end, http_msg_rquri_sp, http_msg_ood, state, H1_MSG_RQURI_SP);
		/* so it's a CR/LF, meaning an HTTP 0.9 request */
		goto http_msg_req09_ver;


	case H1_MSG_RQVER:
	http_msg_rqver:
		if (likely(HTTP_IS_VER_TOKEN(*ptr)))
			EAT_AND_JUMP_OR_RETURN(ptr, end, http_msg_rqver, http_msg_ood, state, H1_MSG_RQVER);

		if (likely(HTTP_IS_CRLF(*ptr))) {
			sl.rq.v_l = ptr - start + skip - sl.rq.v;
		http_msg_rqline_eol:
			/* We have seen the end of line. Note that we do not
			 * necessarily have the \n yet, but at least we know that we
			 * have EITHER \r OR \n, otherwise the request would not be
			 * complete. We can then record the request length and return
			 * to the caller which will be able to register it.
			 */

			if (likely(!skip_update)) {
				if ((sl.rq.v_l == 8) &&
				    ((start[sl.rq.v + 5] > '1') ||
				     ((start[sl.rq.v + 5] == '1') && (start[sl.rq.v + 7] >= '1'))))
					h1m->flags |= H1_MF_VER_11;

				if (unlikely(hdr_count >= hdr_num)) {
					state = H1_MSG_RQVER;
					goto http_output_full;
				}
				http_set_hdr(&hdr[hdr_count++], ist(":method"), ist2(start + sl.rq.m, sl.rq.m_l));

				if (unlikely(hdr_count >= hdr_num)) {
					state = H1_MSG_RQVER;
					goto http_output_full;
				}
				http_set_hdr(&hdr[hdr_count++], ist(":path"), ist2(start + sl.rq.u, sl.rq.u_l));
			}

			sol = ptr - start;
			if (likely(*ptr == '\r'))
				EAT_AND_JUMP_OR_RETURN(ptr, end, http_msg_rqline_end, http_msg_ood, state, H1_MSG_RQLINE_END);
			goto http_msg_rqline_end;
		}

		/* neither an HTTP_VER token nor a CRLF */
		state = H1_MSG_RQVER;
		goto http_msg_invalid;

	case H1_MSG_RQLINE_END:
	http_msg_rqline_end:
		/* check for HTTP/0.9 request : no version information
		 * available. sol must point to the first of CR or LF. However
		 * since we don't save these elements between calls, if we come
		 * here from a restart, we don't necessarily know. Thus in this
		 * case we simply start over.
		 */
		if (restarting)
			goto restart;

		if (unlikely(sl.rq.v_l == 0))
			goto http_msg_last_lf;

		EXPECT_LF_HERE(ptr, http_msg_invalid, state, H1_MSG_RQLINE_END);
		EAT_AND_JUMP_OR_RETURN(ptr, end, http_msg_hdr_first, http_msg_ood, state, H1_MSG_HDR_FIRST);
		/* stop here */

	/*
	 * Common states below
	 */
	case H1_MSG_RPBEFORE:
	http_msg_rpbefore:
		if (likely(HTTP_IS_TOKEN(*ptr))) {
			/* we have a start of message, we may have skipped some
			 * heading CRLF. Skip them now.
			 */
			skip += ptr - start;
			start = ptr;

			sol = 0;
			sl.st.v = skip;
			hdr_count = 0;
			state = H1_MSG_RPVER;
			goto http_msg_rpver;
		}

		if (unlikely(!HTTP_IS_CRLF(*ptr))) {
			state = H1_MSG_RPBEFORE;
			goto http_msg_invalid;
		}

		if (unlikely(*ptr == '\n'))
			EAT_AND_JUMP_OR_RETURN(ptr, end, http_msg_rpbefore, http_msg_ood, state, H1_MSG_RPBEFORE);
		EAT_AND_JUMP_OR_RETURN(ptr, end, http_msg_rpbefore_cr, http_msg_ood, state, H1_MSG_RPBEFORE_CR);
		/* stop here */

	case H1_MSG_RPBEFORE_CR:
	http_msg_rpbefore_cr:
		EXPECT_LF_HERE(ptr, http_msg_invalid, state, H1_MSG_RPBEFORE_CR);
		EAT_AND_JUMP_OR_RETURN(ptr, end, http_msg_rpbefore, http_msg_ood, state, H1_MSG_RPBEFORE);
		/* stop here */

	case H1_MSG_RPVER:
	http_msg_rpver:
		if (likely(HTTP_IS_VER_TOKEN(*ptr)))
			EAT_AND_JUMP_OR_RETURN(ptr, end, http_msg_rpver, http_msg_ood, state, H1_MSG_RPVER);

		if (likely(HTTP_IS_SPHT(*ptr))) {
			sl.st.v_l = ptr - start;

			if ((sl.st.v_l == 8) &&
			    ((start[sl.st.v + 5] > '1') ||
			     ((start[sl.st.v + 5] == '1') && (start[sl.st.v + 7] >= '1'))))
				h1m->flags |= H1_MF_VER_11;

			EAT_AND_JUMP_OR_RETURN(ptr, end, http_msg_rpver_sp, http_msg_ood, state, H1_MSG_RPVER_SP);
		}
		state = H1_MSG_RPVER;
		goto http_msg_invalid;

	case H1_MSG_RPVER_SP:
	http_msg_rpver_sp:
		if (likely(!HTTP_IS_LWS(*ptr))) {
			sl.st.status = 0;
			sl.st.c = ptr - start + skip;
			goto http_msg_rpcode;
		}
		if (likely(HTTP_IS_SPHT(*ptr)))
			EAT_AND_JUMP_OR_RETURN(ptr, end, http_msg_rpver_sp, http_msg_ood, state, H1_MSG_RPVER_SP);
		/* so it's a CR/LF, this is invalid */
		state = H1_MSG_RPVER_SP;
		goto http_msg_invalid;

	case H1_MSG_RPCODE:
	http_msg_rpcode:
		if (likely(HTTP_IS_DIGIT(*ptr))) {
			sl.st.status = sl.st.status * 10 + *ptr - '0';
			EAT_AND_JUMP_OR_RETURN(ptr, end, http_msg_rpcode, http_msg_ood, state, H1_MSG_RPCODE);
		}

		if (unlikely(!HTTP_IS_LWS(*ptr))) {
			state = H1_MSG_RPCODE;
			goto http_msg_invalid;
		}

		if (likely(HTTP_IS_SPHT(*ptr))) {
			sl.st.c_l = ptr - start + skip - sl.st.c;
			EAT_AND_JUMP_OR_RETURN(ptr, end, http_msg_rpcode_sp, http_msg_ood, state, H1_MSG_RPCODE_SP);
		}

		/* so it's a CR/LF, so there is no reason phrase */
		sl.st.c_l = ptr - start + skip - sl.st.c;

	http_msg_rsp_reason:
		sl.st.r = ptr - start + skip;
		sl.st.r_l = 0;
		goto http_msg_rpline_eol;

	case H1_MSG_RPCODE_SP:
	http_msg_rpcode_sp:
		if (likely(!HTTP_IS_LWS(*ptr))) {
			sl.st.r = ptr - start + skip;
			goto http_msg_rpreason;
		}
		if (likely(HTTP_IS_SPHT(*ptr)))
			EAT_AND_JUMP_OR_RETURN(ptr, end, http_msg_rpcode_sp, http_msg_ood, state, H1_MSG_RPCODE_SP);
		/* so it's a CR/LF, so there is no reason phrase */
		goto http_msg_rsp_reason;

	case H1_MSG_RPREASON:
	http_msg_rpreason:
		if (likely(!HTTP_IS_CRLF(*ptr)))
			EAT_AND_JUMP_OR_RETURN(ptr, end, http_msg_rpreason, http_msg_ood, state, H1_MSG_RPREASON);
		sl.st.r_l = ptr - start + skip - sl.st.r;
	http_msg_rpline_eol:
		/* We have seen the end of line. Note that we do not
		 * necessarily have the \n yet, but at least we know that we
		 * have EITHER \r OR \n, otherwise the response would not be
		 * complete. We can then record the response length and return
		 * to the caller which will be able to register it.
		 */

		if (likely(!skip_update)) {
			if (unlikely(hdr_count >= hdr_num)) {
				state = H1_MSG_RPREASON;
				goto http_output_full;
			}
			http_set_hdr(&hdr[hdr_count++], ist(":status"), ist2(start + sl.st.c, sl.st.c_l));
		}

		sol = ptr - start;
		if (likely(*ptr == '\r'))
			EAT_AND_JUMP_OR_RETURN(ptr, end, http_msg_rpline_end, http_msg_ood, state, H1_MSG_RPLINE_END);
		goto http_msg_rpline_end;

	case H1_MSG_RPLINE_END:
	http_msg_rpline_end:
		/* sol must point to the first of CR or LF. */
		EXPECT_LF_HERE(ptr, http_msg_invalid, state, H1_MSG_RPLINE_END);
		EAT_AND_JUMP_OR_RETURN(ptr, end, http_msg_hdr_first, http_msg_ood, state, H1_MSG_HDR_FIRST);
		/* stop here */

	case H1_MSG_HDR_FIRST:
	http_msg_hdr_first:
		sol = ptr - start;
		if (likely(!HTTP_IS_CRLF(*ptr))) {
			goto http_msg_hdr_name;
		}

		if (likely(*ptr == '\r'))
			EAT_AND_JUMP_OR_RETURN(ptr, end, http_msg_last_lf, http_msg_ood, state, H1_MSG_LAST_LF);
		goto http_msg_last_lf;

	case H1_MSG_HDR_NAME:
	http_msg_hdr_name:
		/* assumes sol points to the first char */
		if (likely(HTTP_IS_TOKEN(*ptr))) {
			/* turn it to lower case if needed */
			if (isupper((unsigned char)*ptr) && h1m->flags & H1_MF_TOLOWER)
				*ptr = tolower(*ptr);
			EAT_AND_JUMP_OR_RETURN(ptr, end, http_msg_hdr_name, http_msg_ood, state, H1_MSG_HDR_NAME);
		}

		if (likely(*ptr == ':')) {
			col = ptr - start;
			EAT_AND_JUMP_OR_RETURN(ptr, end, http_msg_hdr_l1_sp, http_msg_ood, state, H1_MSG_HDR_L1_SP);
		}

		if (likely(h1m->err_pos < -1) || *ptr == '\n') {
			state = H1_MSG_HDR_NAME;
			goto http_msg_invalid;
		}

		if (h1m->err_pos == -1) /* capture the error pointer */
			h1m->err_pos = ptr - start + skip; /* >= 0 now */

		/* and we still accept this non-token character */
		EAT_AND_JUMP_OR_RETURN(ptr, end, http_msg_hdr_name, http_msg_ood, state, H1_MSG_HDR_NAME);

	case H1_MSG_HDR_L1_SP:
	http_msg_hdr_l1_sp:
		/* assumes sol points to the first char */
		if (likely(HTTP_IS_SPHT(*ptr)))
			EAT_AND_JUMP_OR_RETURN(ptr, end, http_msg_hdr_l1_sp, http_msg_ood, state, H1_MSG_HDR_L1_SP);

		/* header value can be basically anything except CR/LF */
		sov = ptr - start;

		if (likely(!HTTP_IS_CRLF(*ptr))) {
			goto http_msg_hdr_val;
		}

		if (likely(*ptr == '\r'))
			EAT_AND_JUMP_OR_RETURN(ptr, end, http_msg_hdr_l1_lf, http_msg_ood, state, H1_MSG_HDR_L1_LF);
		goto http_msg_hdr_l1_lf;

	case H1_MSG_HDR_L1_LF:
	http_msg_hdr_l1_lf:
		EXPECT_LF_HERE(ptr, http_msg_invalid, state, H1_MSG_HDR_L1_LF);
		EAT_AND_JUMP_OR_RETURN(ptr, end, http_msg_hdr_l1_lws, http_msg_ood, state, H1_MSG_HDR_L1_LWS);

	case H1_MSG_HDR_L1_LWS:
	http_msg_hdr_l1_lws:
		if (likely(HTTP_IS_SPHT(*ptr))) {
			/* replace HT,CR,LF with spaces */
			for (; start + sov < ptr; sov++)
				start[sov] = ' ';
			goto http_msg_hdr_l1_sp;
		}
		/* we had a header consisting only in spaces ! */
		eol = sov;
		goto http_msg_complete_header;

	case H1_MSG_HDR_VAL:
	http_msg_hdr_val:
		/* assumes sol points to the first char, and sov
		 * points to the first character of the value.
		 */

		/* speedup: we'll skip packs of 4 or 8 bytes not containing bytes 0x0D
		 * and lower. In fact since most of the time is spent in the loop, we
		 * also remove the sign bit test so that bytes 0x8e..0x0d break the
		 * loop, but we don't care since they're very rare in header values.
		 */
#if defined(__x86_64__)
		while (ptr <= end - sizeof(long)) {
			if ((*(long *)ptr - 0x0e0e0e0e0e0e0e0eULL) & 0x8080808080808080ULL)
				goto http_msg_hdr_val2;
			ptr += sizeof(long);
		}
#endif
#if defined(__x86_64__) || \
    defined(__i386__) || defined(__i486__) || defined(__i586__) || defined(__i686__) || \
    defined(__ARM_ARCH_7A__)
		while (ptr <= end - sizeof(int)) {
			if ((*(int*)ptr - 0x0e0e0e0e) & 0x80808080)
				goto http_msg_hdr_val2;
			ptr += sizeof(int);
		}
#endif
		if (ptr >= end) {
			state = H1_MSG_HDR_VAL;
			goto http_msg_ood;
		}
	http_msg_hdr_val2:
		if (likely(!HTTP_IS_CRLF(*ptr)))
			EAT_AND_JUMP_OR_RETURN(ptr, end, http_msg_hdr_val2, http_msg_ood, state, H1_MSG_HDR_VAL);

		eol = ptr - start;
		/* Note: we could also copy eol into ->eoh so that we have the
		 * real header end in case it ends with lots of LWS, but is this
		 * really needed ?
		 */
		if (likely(*ptr == '\r'))
			EAT_AND_JUMP_OR_RETURN(ptr, end, http_msg_hdr_l2_lf, http_msg_ood, state, H1_MSG_HDR_L2_LF);
		goto http_msg_hdr_l2_lf;

	case H1_MSG_HDR_L2_LF:
	http_msg_hdr_l2_lf:
		EXPECT_LF_HERE(ptr, http_msg_invalid, state, H1_MSG_HDR_L2_LF);
		EAT_AND_JUMP_OR_RETURN(ptr, end, http_msg_hdr_l2_lws, http_msg_ood, state, H1_MSG_HDR_L2_LWS);

	case H1_MSG_HDR_L2_LWS:
	http_msg_hdr_l2_lws:
		if (unlikely(HTTP_IS_SPHT(*ptr))) {
			/* LWS: replace HT,CR,LF with spaces */
			for (; start + eol < ptr; eol++)
				start[eol] = ' ';
			goto http_msg_hdr_val;
		}
	http_msg_complete_header:
		/*
		 * It was a new header, so the last one is finished. Assumes
		 * <sol> points to the first char of the name, <col> to the
		 * colon, <sov> points to the first character of the value and
		 * <eol> to the first CR or LF so we know how the line ends. We
		 * will trim spaces around the value. It's possible to do it by
		 * adjusting <eol> and <sov> which are no more used after this.
		 * We can add the header field to the list.
		 */
		while (sov < eol && HTTP_IS_LWS(start[sov]))
			sov++;

		while (eol - 1 > sov && HTTP_IS_LWS(start[eol - 1]))
			eol--;


		n = ist2(start + sol, col - sol);
		v = ist2(start + sov, eol - sov);

		if (likely(!skip_update)) do {
			int ret;

			if (unlikely(hdr_count >= hdr_num)) {
				state = H1_MSG_HDR_L2_LWS;
				goto http_output_full;
			}

			if (isteqi(n, ist("transfer-encoding"))) {
				h1_parse_xfer_enc_header(h1m, v);
			}
			else if (isteqi(n, ist("content-length"))) {
				ret = h1_parse_cont_len_header(h1m, &v);

				if (ret < 0) {
					state = H1_MSG_HDR_L2_LWS;
					goto http_msg_invalid;
				}
				else if (ret == 0) {
					/* skip it */
					break;
				}
			}
			else if (isteqi(n, ist("connection"))) {
				h1_parse_connection_header(h1m, v);
			}

			http_set_hdr(&hdr[hdr_count++], n, v);
		} while (0);

		sol = ptr - start;
		if (likely(!HTTP_IS_CRLF(*ptr)))
			goto http_msg_hdr_name;

		if (likely(*ptr == '\r'))
			EAT_AND_JUMP_OR_RETURN(ptr, end, http_msg_last_lf, http_msg_ood, state, H1_MSG_LAST_LF);
		goto http_msg_last_lf;

	case H1_MSG_LAST_LF:
	http_msg_last_lf:
		EXPECT_LF_HERE(ptr, http_msg_invalid, state, H1_MSG_LAST_LF);
		ptr++;
		/* <ptr> now points to the first byte of payload. If needed sol
		 * still points to the first of either CR or LF of the empty
		 * line ending the headers block.
		 */
		if (likely(!skip_update)) {
			if (unlikely(hdr_count >= hdr_num)) {
				state = H1_MSG_LAST_LF;
				goto http_output_full;
			}
			http_set_hdr(&hdr[hdr_count++], ist(""), ist(""));
		}

		/* reaching here we've parsed the whole message. We may detect
		 * that we were already continuing an interrupted parsing pass
		 * so we were silently looking for the end of message not
		 * updating anything before deciding to parse it fully at once.
		 * It's guaranteed that we won't match this test twice in a row
		 * since restarting will turn zero.
		 */
		if (restarting)
			goto restart;

		state = H1_MSG_DATA;
		if (h1m->flags & H1_MF_XFER_ENC) {
			if (h1m->flags & H1_MF_CLEN) {
				h1m->flags &= ~H1_MF_CLEN;
				hdr_count = http_del_hdr(hdr, ist("content-length"));
			}

			if (h1m->flags & H1_MF_CHNK)
				state = H1_MSG_CHUNK_SIZE;
			else if (!(h1m->flags & H1_MF_RESP)) {
				/* cf RFC7230#3.3.3 : transfer-encoding in
				 * request without chunked encoding is invalid.
				 */
				goto http_msg_invalid;
			}
		}

		break;

	default:
		/* impossible states */
		goto http_msg_invalid;
	}

	/* Now we've left the headers state and are either in H1_MSG_DATA or
	 * H1_MSG_CHUNK_SIZE.
	 */

	if (slp && !skip_update)
		*slp = sl;

	h1m->state = state;
	h1m->next  = ptr - start + skip;
	return h1m->next;

 http_msg_ood:
	/* out of data at <ptr> during state <state> */
	if (slp && !skip_update)
		*slp = sl;

	h1m->state = state;
	h1m->next  = ptr - start + skip;
	return 0;

 http_msg_invalid:
	/* invalid message, error at <ptr> */
	if (slp && !skip_update)
		*slp = sl;

	h1m->err_state = h1m->state = state;
	h1m->err_pos   = h1m->next  = ptr - start + skip;
	return -1;

 http_output_full:
	/* no more room to store the current header, error at <ptr> */
	if (slp && !skip_update)
		*slp = sl;

	h1m->err_state = h1m->state = state;
	h1m->err_pos   = h1m->next  = ptr - start + skip;
	return -2;

 restart:
	h1m->next  = 0;
	if (h1m->flags & H1_MF_RESP)
		h1m->state = H1_MSG_RPBEFORE;
	else
		h1m->state = H1_MSG_RQBEFORE;
	goto try_again;
}

/* This function performs a very minimal parsing of the trailers block present
 * at offset <ofs> in <buf> for up to <max> bytes, and returns the number of
 * bytes to delete to skip the trailers. It may return 0 if it's missing some
 * input data, or < 0 in case of parse error (in which case the caller may have
 * to decide how to proceed, possibly eating everything).
 */
int h1_measure_trailers(const struct buffer *buf, unsigned int ofs, unsigned int max)
{
	const char *stop = b_peek(buf, ofs + max);
	int count = ofs;

	while (1) {
		const char *p1 = NULL, *p2 = NULL;
		const char *start = b_peek(buf, count);
		const char *ptr   = start;

		/* scan current line and stop at LF or CRLF */
		while (1) {
			if (ptr == stop)
				return 0;

			if (*ptr == '\n') {
				if (!p1)
					p1 = ptr;
				p2 = ptr;
				break;
			}

			if (*ptr == '\r') {
				if (p1)
					return -1;
				p1 = ptr;
			}

			ptr = b_next(buf, ptr);
		}

		/* after LF; point to beginning of next line */
		p2 = b_next(buf, p2);
		count += b_dist(buf, start, p2);

		/* LF/CRLF at beginning of line => end of trailers at p2.
		 * Everything was scheduled for forwarding, there's nothing left
		 * from this message. */
		if (p1 == start)
			break;
		/* OK, next line then */
	}
	return count - ofs;
}

/* This function skips trailers in the buffer associated with HTTP message
 * <msg>. The first visited position is msg->next. If the end of the trailers is
 * found, the function returns >0. So, the caller can automatically schedul it
 * to be forwarded, and switch msg->msg_state to HTTP_MSG_DONE. If not enough
 * data are available, the function does not change anything except maybe
 * msg->sol if it could parse some lines, and returns zero.  If a parse error
 * is encountered, the function returns < 0 and does not change anything except
 * maybe msg->sol. Note that the message must already be in HTTP_MSG_TRAILERS
 * state before calling this function, which implies that all non-trailers data
 * have already been scheduled for forwarding, and that msg->next exactly
 * matches the length of trailers already parsed and not forwarded. It is also
 * important to note that this function is designed to be able to parse wrapped
 * headers at end of buffer.
 */
int http_forward_trailers(struct http_msg *msg)
{
	const struct buffer *buf = &msg->chn->buf;
	const char *parse = ci_head(msg->chn);
	const char *stop  = b_tail(buf);

	/* we have msg->next which points to next line. Look for CRLF. But
	 * first, we reset msg->sol */
	msg->sol = 0;
	while (1) {
		const char *p1 = NULL, *p2 = NULL;
		const char *start = c_ptr(msg->chn, msg->next + msg->sol);
		const char *ptr   = start;

		/* scan current line and stop at LF or CRLF */
		while (1) {
			if (ptr == stop)
				return 0;

			if (*ptr == '\n') {
				if (!p1)
					p1 = ptr;
				p2 = ptr;
				break;
			}

			if (*ptr == '\r') {
				if (p1) {
					msg->err_pos = b_dist(buf, parse, ptr);
					return -1;
				}
				p1 = ptr;
			}

			ptr = b_next(buf, ptr);
		}

		/* after LF; point to beginning of next line */
		p2 = b_next(buf, p2);
		msg->sol += b_dist(buf, start, p2);

		/* LF/CRLF at beginning of line => end of trailers at p2.
		 * Everything was scheduled for forwarding, there's nothing left
		 * from this message. */
		if (p1 == start)
			return 1;

		/* OK, next line then */
	}
}
