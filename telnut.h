/* libtenut - telnet async client library */
/* Copyright (c) 2014 Laurent Ghigonis <laurent@gouloum.fr>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <stdio.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <bsd/sys/queue.h>

#include <libtelnet.h>

#define TELNUT_NOVERBOSE 0
#define TELNUT_VERBOSE 1

#define TELNUT_FILEBUF_SIZE 100000

enum telnut_reconnect {
	TELNUT_NORECONNECT = 0,
	TELNUT_RECONNECT_3TIMES = 3,
	TELNUT_RECONNECT_INFINITE = -1,
};

enum telnut_state {
	TELNUT_STATE_UNINITIALIZED = 0,
	TELNUT_STATE_CONNECTING,
	TELNUT_STATE_DISCONNECTED,
	TELNUT_STATE_LOGIN_ENTERLOGIN,
	TELNUT_STATE_LOGIN_ENTERPASS,
	TELNUT_STATE_LOGIN_WAITPROMPT,
	TELNUT_STATE_CONNECTED,
	TELNUT_STATE_EXEC_WAITANSWER,
};

enum telnut_error {
	TELNUT_NOERROR = 0,
	TELNUT_ERROR_UNKNOWN_STATE,
	TELNUT_ERROR_CONNECTION,
	TELNUT_ERROR_CONNECTION_CLOSED,
	TELNUT_ERROR_LOGIN,
};

enum telnut_action {
	TELNUT_NOACTION = 0,
	TELNUT_ACTION_EXEC = 1,
};

struct telnut {
	struct event_base *evb;
	enum telnut_state state;
	enum telnut_action action;
	enum telnut_error error;
	struct event *ev_wait;
	struct timeval tv_wait;
	struct {
		char *ip;
		int port;
		char *user;
		char *pass;
		enum telnut_reconnect reconnect;
		int verbose;
	} conf;
	struct {
		telnet_t *telnet;
		struct bufferevent *bufev;
		struct evbuffer *telnetbuf_in; /* buffer after libtelnet receive handling */
	} conn;
	struct {
		char *login_userprompt;
		char *login_passprompt;
		char *shell_prompt;
	} learn;
	void (*cbusr_connect)(struct telnut *, void *);
	void (*cbusr_disconnect)(struct telnut *, enum telnut_error, void *);
	void *cbusr_arg;
	union {
		struct {
			char *cmd;
			struct evbuffer *output;
			int lastrecv_tick;
			void (*cbusr_done)(struct telnut *, enum telnut_error, char *, char *, int, void *);
		} exec;
		struct {
			char *path_local;
			char *path_remote;
			FILE *file;
			struct stat fileinfo;
			char *filebuf;
			int filebuf_size;
			int filebuf_remaining;
			void (*cbusr_done)(struct telnut *, enum telnut_error, void *);
		} push;
	} act;
	void *act_cbusr_arg;
};

/* telnut.c */

struct telnut *telnut_new(struct event_base *evb, char *ip, int port, char *user, char *pass, enum telnut_reconnect reconnect, int verbose,
	void (*cbusr_connect)(struct telnut *, void *),
	void (*cbusr_disconnect)(struct telnut *, enum telnut_error, void *), void *arg);
void telnut_free(struct telnut *tel);

int telnut_connect(struct telnut *tel);
int telnut_disconnect(struct telnut *tel);
void telnut_err_print(enum telnut_error error);

int telnut_exec(struct telnut *tel, char *cmd, 
	void (*cbusr_done)(struct telnut *, enum telnut_error, char *, char *, int, void *), void *cbusr_arg);
int telnut_push(struct telnut *tel, char *path_local, char *path_remote,
	void (*cbusr_done)(struct telnut *, enum telnut_error, void *), void *arg);
/*int telnut_pull(struct telnut *tel, char *path_remote, char *path_local, int flags,
	void (*cb)(struct telnut *, int, void *), void *arg);*/
void telnut_action_stop(struct telnut *tel);
