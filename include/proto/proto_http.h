/*
 * include/proto/proto_http.h
 * This file contains HTTP protocol definitions.
 *
 * Copyright (C) 2000-2011 Willy Tarreau - w@1wt.eu
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation, version 2.1
 * exclusively.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

#ifndef _PROTO_PROTO_HTTP_H
#define _PROTO_PROTO_HTTP_H

#include <common/config.h>
#include <types/proto_http.h>
#include <types/stream.h>
#include <types/task.h>
#include <proto/channel.h>
#include <proto/h1.h>

#define IS_HTX_STRM(strm) (strm_fe(strm)->options2 & PR_O2_USE_HTX)
#define IS_HTX_SMP(smp)   ((smp)->strm && IS_HTX_STRM((smp)->strm))

extern struct pool_head *pool_head_uniqueid;

int process_cli(struct stream *s);
int process_srv_data(struct stream *s);
int process_srv_conn(struct stream *s);
int http_wait_for_request(struct stream *s, struct channel *req, int an_bit);
int http_process_req_common(struct stream *s, struct channel *req, int an_bit, struct proxy *px);
int http_process_request(struct stream *s, struct channel *req, int an_bit);
int http_process_tarpit(struct stream *s, struct channel *req, int an_bit);
int http_wait_for_request_body(struct stream *s, struct channel *req, int an_bit);
int http_send_name_header(struct stream *s, struct proxy* be, const char* svr_name);
int http_wait_for_response(struct stream *s, struct channel *rep, int an_bit);
int http_process_res_common(struct stream *s, struct channel *rep, int an_bit, struct proxy *px);
int http_request_forward_body(struct stream *s, struct channel *req, int an_bit);
int http_response_forward_body(struct stream *s, struct channel *res, int an_bit);
int http_upgrade_v09_to_v10(struct http_txn *txn);
void http_msg_analyzer(struct http_msg *msg, struct hdr_idx *idx);
void http_txn_reset_req(struct http_txn *txn);
void http_txn_reset_res(struct http_txn *txn);

/* Export HTX analyzers and helpers */
// FIXME: Rename all these functions http_* once legacy code will be removed
struct htx;

int htx_wait_for_request(struct stream *s, struct channel *req, int an_bit);
int htx_process_req_common(struct stream *s, struct channel *req, int an_bit, struct proxy *px);
int htx_process_request(struct stream *s, struct channel *req, int an_bit);
int htx_process_tarpit(struct stream *s, struct channel *req, int an_bit);
int htx_wait_for_request_body(struct stream *s, struct channel *req, int an_bit);
int htx_send_name_header(struct http_txn *txn, struct proxy* be, const char* svr_name);
int htx_wait_for_response(struct stream *s, struct channel *rep, int an_bit);
int htx_process_res_common(struct stream *s, struct channel *rep, int an_bit, struct proxy *px);
int htx_request_forward_body(struct stream *s, struct channel *req, int an_bit);
int htx_response_forward_body(struct stream *s, struct channel *res, int an_bit);
void htx_adjust_conn_mode(struct stream *s, struct http_txn *txn);
int htx_apply_redirect_rule(struct redirect_rule *rule, struct stream *s, struct http_txn *txn);
int htx_transform_header_str(struct stream* s, struct channel *chn, struct htx *htx,
			     struct ist name, const char *str, struct my_regex *re, int action);
int htx_req_replace_stline(int action, const char *replace, int len,
			   struct proxy *px, struct stream *s);
void htx_res_set_status(unsigned int status, const char *reason, struct stream *s);
void htx_server_error(struct stream *s, struct stream_interface *si, int err, int finst, const struct buffer *msg);
void htx_reply_and_close(struct stream *s, short status, struct buffer *msg);


void debug_hdr(const char *dir, struct stream *s, const char *start, const char *end);
int apply_filter_to_req_headers(struct stream *s, struct channel *req, struct hdr_exp *exp);
int apply_filter_to_req_line(struct stream *s, struct channel *req, struct hdr_exp *exp);
int apply_filters_to_request(struct stream *s, struct channel *req, struct proxy *px);
int apply_filters_to_response(struct stream *s, struct channel *rtr, struct proxy *px);
void manage_client_side_cookies(struct stream *s, struct channel *req);
void manage_server_side_cookies(struct stream *s, struct channel *rtr);
void check_request_for_cacheability(struct stream *s, struct channel *chn);
void check_response_for_cacheability(struct stream *s, struct channel *rtr);
int stats_check_uri(struct stream_interface *si, struct http_txn *txn, struct proxy *backend);
void init_proto_http();
int http_find_full_header2(const char *name, int len,
                           char *sol, struct hdr_idx *idx,
                           struct hdr_ctx *ctx);
int http_find_header2(const char *name, int len,
		      char *sol, struct hdr_idx *idx,
		      struct hdr_ctx *ctx);
int http_find_next_header(char *sol, struct hdr_idx *idx,
                          struct hdr_ctx *ctx);
int http_remove_header2(struct http_msg *msg, struct hdr_idx *idx, struct hdr_ctx *ctx);
int http_header_add_tail2(struct http_msg *msg, struct hdr_idx *hdr_idx, const char *text, int len);
int http_replace_req_line(int action, const char *replace, int len, struct proxy *px, struct stream *s);
void http_set_status(unsigned int status, const char *reason, struct stream *s);
int http_transform_header_str(struct stream* s, struct http_msg *msg, const char* name,
                              unsigned int name_len, const char *str, struct my_regex *re,
                              int action);
void inet_set_tos(int fd, const struct sockaddr_storage *from, int tos);
int http_handle_stats(struct stream *s, struct channel *req);
enum rule_result http_req_get_intercept_rule(struct proxy *px, struct list *rules,
					     struct stream *s, int *deny_status);
enum rule_result http_res_get_intercept_rule(struct proxy *px, struct list *rules,
					     struct stream *s);
int http_apply_redirect_rule(struct redirect_rule *rule, struct stream *s, struct http_txn *txn);
void http_perform_server_redirect(struct stream *s, struct stream_interface *si);
void http_return_srv_error(struct stream *s, struct stream_interface *si);
void http_capture_headers(char *som, struct hdr_idx *idx,
			  char **cap, struct cap_hdr *cap_hdr);
void http_capture_bad_message(struct proxy *proxy, struct stream *s,
                              struct http_msg *msg,
			      enum h1_state state, struct proxy *other_end);
unsigned int http_get_hdr(const struct http_msg *msg, const char *hname, int hlen,
			  struct hdr_idx *idx, int occ,
			  struct hdr_ctx *ctx, char **vptr, size_t *vlen);
unsigned int http_get_fhdr(const struct http_msg *msg, const char *hname, int hlen,
			   struct hdr_idx *idx, int occ,
			   struct hdr_ctx *ctx, char **vptr, size_t *vlen);
char *http_txn_get_path(const struct http_txn *txn);

struct http_txn *http_alloc_txn(struct stream *s);
void http_init_txn(struct stream *s);
void http_end_txn(struct stream *s);
void http_reset_txn(struct stream *s);
void http_end_txn_clean_session(struct stream *s);
void http_resync_states(struct stream *s);
void http_parse_connection_header(struct http_txn *txn, struct http_msg *msg, int to_del);
void http_change_connection_header(struct http_txn *txn, struct http_msg *msg, int wanted);
void http_adjust_conn_mode(struct stream *s, struct http_txn *txn, struct http_msg *msg);

int http_msg_forward_body(struct stream *s, struct http_msg *msg);
int http_msg_forward_chunked_body(struct stream *s, struct http_msg *msg);

void http_reply_and_close(struct stream *s, short status, struct buffer *msg);
struct buffer *http_error_message(struct stream *s);

/* to be used when contents change in an HTTP message */
#define http_msg_move_end(msg, bytes) do { \
		unsigned int _bytes = (bytes);	\
		(msg)->next += (_bytes);	\
		(msg)->sov += (_bytes);		\
		(msg)->eoh += (_bytes);		\
	} while (0)


/* Return the amount of bytes that need to be rewound before buf->p to access
 * the current message's headers. The purpose is to be able to easily fetch
 * the message's beginning before headers are forwarded, as well as after.
 * The principle is that msg->eoh and msg->eol are immutable while msg->sov
 * equals the sum of the two before forwarding and is zero after forwarding,
 * so the difference cancels the rewinding.
 */
static inline int http_hdr_rewind(const struct http_msg *msg)
{
	return msg->eoh + msg->eol - msg->sov;
}

/* Return the amount of bytes that need to be rewound before buf->p to access
 * the current message's URI. The purpose is to be able to easily fetch
 * the message's beginning before headers are forwarded, as well as after.
 */
static inline int http_uri_rewind(const struct http_msg *msg)
{
	return http_hdr_rewind(msg) - msg->sl.rq.u;
}

/* Return the amount of bytes that need to be rewound before buf->p to access
 * the current message's BODY. The purpose is to be able to easily fetch
 * the message's beginning before headers are forwarded, as well as after.
 */
static inline int http_body_rewind(const struct http_msg *msg)
{
	return http_hdr_rewind(msg) - msg->eoh - msg->eol;
}

/* Return the amount of bytes that need to be rewound before buf->p to access
 * the current message's DATA. The difference with the function above is that
 * if a chunk is present and has already been parsed, its size is skipped so
 * that the byte pointed to is the first byte of actual data. The function is
 * safe for use in state HTTP_MSG_DATA regardless of whether the headers were
 * already forwarded or not.
 */
static inline int http_data_rewind(const struct http_msg *msg)
{
	return http_body_rewind(msg) - msg->sol;
}

/* Return the maximum amount of bytes that may be read after the beginning of
 * the message body, according to the advertised length. The function is safe
 * for use between HTTP_MSG_BODY and HTTP_MSG_DATA regardless of whether the
 * headers were already forwarded or not.
 */
static inline int http_body_bytes(const struct http_msg *msg)
{
	int len;

	len = ci_data(msg->chn) - msg->sov - msg->sol;
	if (len > msg->body_len)
		len = msg->body_len;
	return len;
}

#endif /* _PROTO_PROTO_HTTP_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
