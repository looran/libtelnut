/* libtelnut - telnet async client library */
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
#include <sys/queue.h>

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
	TELNUT_STATE_DISCONNECTED,
	TELNUT_STATE_CONNECTING,
	TELNUT_STATE_CONNECTED,
	TELNUT_STATE_INTERACTIVE,
	TELNUT_STATE_EXEC_WAITANSWER,
	TELNUT_STATE_PUSH_CAT,
	TELNUT_STATE_PUSH_SEND,
	TELNUT_STATE_PUSH_CTRLC,
};

enum telnut_error {
	TELNUT_NOERROR = 0,
	TELNUT_ERROR_UNKNOWN_STATE,
	TELNUT_ERROR_CONNECTION,
	TELNUT_ERROR_CONNECTION_CLOSED,
	TELNUT_ERROR_LOGIN,
	TELNUT_ERROR_SHELL,
	TELNUT_ERROR_TELNETPROTO,
};

enum telnut_action {
	TELNUT_NOACTION = 0,
	TELNUT_ACTION_EXEC = 1,
	TELNUT_ACTION_PUSH = 2,
	TELNUT_ACTION_INTERACTIVE = 3,
};

enum tfp_state {
	TFP_STATE_LOGIN_USER = 0,
	TFP_STATE_LOGIN_PASS,
	TFP_STATE_CONSOLE,
	TFP_STATE_CHECK_SHELL,
	TFP_STATE_SHELL,
};

enum tfp_action {
	TFP_SEND = 0,
	TFP_WAIT,
	TFP_HAS_SHELL,
	TFP_ERROR,
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
		struct evbuffer *telnetbuf_in; /* buffer after libtelnet receive handling */
		struct tfp *tfp;
		struct bufferevent *bufev;
		int echosuppress_count;
		int wait_count;
	} conn;
	void (*cbusr_connect)(struct telnut *, void *);
	void (*cbusr_disconnect)(struct telnut *, enum telnut_error, void *);
	void *cbusr_arg;
	union {
		struct {
			struct event *stdin;
		} interactive;
		struct {
			char *cmd;
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
	struct {
		struct evbuffer *in;
		int lastrecv_ticks;
		int total_ticks;
		int max_ticks;
	} recvbuf;
	struct {
		struct evbuffer *out;
		struct event    *ev_send;
		struct timeval   tv_send;
	} senddefer;
};

struct tfp {
	enum tfp_state state;
	struct {
		char *user;
		char *pass;
		int verbose;
	} conf;
	struct {
		char *login_user;
		char *login_pass;
		char *login_console;
		char *shell_prompt;
	} learn;
	struct tfp_login  *login;
	struct tfp_console *console;
	int                 console_count;
};

struct tfp_login {
	char *name;
	struct {
		char *user;
		int   cflags;
	} user;
	struct {
		char *pass;
		int   cflags;
	} pass;
};

struct tfp_login_failed {
	struct {
		char *pass;
		int   cflags;
	} pass;
	struct {
		char *console;
		int   cflags;
	} console;
};

struct tfp_console {
	char *name;
	struct {
		char *user;
		int   user_cflags;
		char *pass;
		int   pass_cflags;
		char *console;
		int   console_cflags;
	} login;
	struct {
		char *cmd;
	} getshell;
	struct {
		char *shell;
		int   shell_cflags;
	} fpshell;
};

struct tfp_creds {
	char *console_name; /* reference to tfp_console.name, or NULL for generic */
	char *usernames;    /* list comma separated */
	char *passwords;    /* list comma separated */
};

/* telnut.c */

struct telnut *telnut_new(struct event_base *evb, char *ip, int port, char *user, char *pass, enum telnut_reconnect reconnect, int verbose,
	void (*cbusr_connect)(struct telnut *, void *),
	void (*cbusr_disconnect)(struct telnut *, enum telnut_error, void *), void *arg);
void           telnut_free(struct telnut *tel);

int  telnut_connect(struct telnut *tel);
int  telnut_disconnect(struct telnut *tel);
void telnut_err_print(enum telnut_error error);

int telnut_interactive(struct telnut *tel);
int telnut_exec(struct telnut *tel, char *cmd, 
	void (*cbusr_done)(struct telnut *, enum telnut_error, char *, char *, int, void *), void *cbusr_arg);
int telnut_push(struct telnut *tel, char *path_local, char *path_remote,
	void (*cbusr_done)(struct telnut *, enum telnut_error, void *), void *cbusr_arg);
void telnut_action_stop(struct telnut *tel);

/* tfp.c */

struct tfp     *tfp_new(char *user, char *pass, int verbose);
void            tfp_free(struct tfp *tfp);
enum tfp_action tfp_getaction(struct tfp *tfp, char *recv, int recv_len, const char **cmd, int *cmdlen);
const char     *tfp_str(struct tfp *tfp);
