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

#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <event2/bufferevent.h>
#include <event2/buffer.h>
#include <event2/event.h>

#include "telnut.h"

#define LOG_VERBOSE(parg, ...) do { if (tel->conf.verbose) { printf("sshut:" parg, ##__VA_ARGS__); } }while(0);

static const telnet_telopt_t _telopts[] = {
	{ TELNET_TELOPT_ECHO,		TELNET_WONT, TELNET_DO   },
	{ TELNET_TELOPT_TTYPE,		TELNET_WILL, TELNET_DONT },
	{ TELNET_TELOPT_COMPRESS2,	TELNET_WONT, TELNET_DO   },
	{ TELNET_TELOPT_MSSP,		TELNET_WONT, TELNET_DO   },
	{ -1, 0, 0 }
};

static void _state(struct telnut *);
static void _state_next(struct telnut *, enum telnut_state);
static int  _s_login_enterlogin(struct telnut *);
static int  _s_login_enterpass(struct telnut *);
static int  _s_login_waitprompt(struct telnut *);
static int  _s_connected(struct telnut *);
static int  _s_exec_waitanswer(struct telnut *);
static void _error(struct telnut *, enum telnut_error);
static void _wait(struct telnut *, float);
static void _send(struct telnut *, char *, size_t, int);
static void _cb_wait(int, short, void *);
static void _cb_sock_read(struct bufferevent *, void *);
static void _cb_sock_event(struct bufferevent *, short, void *);
static void _cb_telnet_event(telnet_t *, telnet_event_t *, void *);
static void _recvbuf_init(struct telnut *);
static int  _recvbuf(struct telnut *tel);

struct telnut *
telnut_new(struct event_base *evb, char *ip, int port, char *user, char *pass, enum telnut_reconnect reconnect, int verbose,
	void (*cbusr_connect)(struct telnut *, void *),
	void (*cbusr_disconnect)(struct telnut *, enum telnut_error, void *), void *cbusr_arg)
{
	struct telnut *tel;

	tel = calloc(1, sizeof(struct telnut));
	tel->evb = evb;
	tel->state = TELNUT_STATE_UNINITIALIZED;
	tel->ev_wait = evtimer_new(evb, _cb_wait, tel);
	tel->conf.ip = strdup(ip);
	tel->conf.port = port;
	tel->conf.user = strdup(user);
	tel->conf.pass = strdup(pass);
	tel->conf.reconnect = reconnect;
	tel->conf.verbose = verbose;
	tel->cbusr_connect = cbusr_connect;
	tel->cbusr_disconnect = cbusr_disconnect;
	tel->cbusr_arg = cbusr_arg;
	telnut_connect(tel);
	return tel;
}

void
telnut_free(struct telnut *tel)
{
	telnut_disconnect(tel);
	free(tel->conf.ip);
	free(tel->conf.user);
	free(tel->conf.pass);
	free(tel);
}

int
telnut_connect(struct telnut *tel)
{
	unsigned long hostaddr;
	struct sockaddr_in sin;
	
	tel->state = TELNUT_STATE_CONNECTING;

	hostaddr = inet_addr(tel->conf.ip);
	sin.sin_family = AF_INET;
	sin.sin_port = htons(tel->conf.port);
	sin.sin_addr.s_addr = hostaddr;

	tel->conn.telnet = telnet_init(_telopts, _cb_telnet_event, 0, tel);
	tel->conn.telnetbuf_in = evbuffer_new();

	tel->conn.bufev = bufferevent_socket_new(tel->evb, -1, BEV_OPT_CLOSE_ON_FREE);
	bufferevent_setcb(tel->conn.bufev, _cb_sock_read, NULL, _cb_sock_event, tel);
	bufferevent_enable(tel->conn.bufev, EV_READ|EV_WRITE);
	if (bufferevent_socket_connect(tel->conn.bufev, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
		_error(tel, TELNUT_ERROR_CONNECTION_CLOSED);
		return -1;
	}

	_state_next(tel, TELNUT_STATE_LOGIN_ENTERLOGIN);
	return 0;
}

int
telnut_disconnect(struct telnut *tel)
{
	LOG_VERBOSE("telnut_disconnect\n");
	bufferevent_free(tel->conn.bufev);
	telnet_free(tel->conn.telnet);
	evbuffer_free(tel->conn.telnetbuf_in);
	event_del(tel->ev_wait);
	tel->cbusr_disconnect(tel, tel->error, tel->cbusr_arg);
	return 0;
}

void
telnut_err_print(enum telnut_error error)
{
	printf("telnut error: %d\n", error);
}

int
telnut_exec(struct telnut *tel, char *cmd, 
	void (*cbusr_done)(struct telnut *, enum telnut_error, char *, char *, int, void *), void *cbusr_arg)
{
	tel->action = TELNUT_ACTION_EXEC;
	tel->act.exec.cmd = strdup(cmd);
	tel->act.exec.cbusr_done = cbusr_done;
	tel->act_cbusr_arg = cbusr_arg;
	_send(tel, tel->act.exec.cmd, strlen(cmd), 1);
	_state_next(tel, TELNUT_STATE_EXEC_WAITANSWER);
	return 0;
}

void
telnut_action_stop(struct telnut *tel)
{
	switch(tel->action) {
	case TELNUT_NOACTION:
		break;
	case TELNUT_ACTION_EXEC:
		free(tel->act.exec.cmd);
		tel->act.exec.cbusr_done = NULL;
		// XXX if we where TELNUT_STATE_EXEC_WAITANSWER, need to ignore cmd result receive
		break;
	}
	tel->action = TELNUT_NOACTION;
	tel->state = TELNUT_STATE_CONNECTED;
}

static void
_state(struct telnut *tel)
{
	int rc;

	LOG_VERBOSE("_state: %d\n", tel->state);
	rc = 0;
	switch(tel->state) {
	case TELNUT_STATE_UNINITIALIZED: _error(tel, TELNUT_ERROR_UNKNOWN_STATE); break;
	case TELNUT_STATE_DISCONNECTED: _error(tel, TELNUT_ERROR_UNKNOWN_STATE); break;
	case TELNUT_STATE_CONNECTING: _error(tel, TELNUT_ERROR_UNKNOWN_STATE); break;
	case TELNUT_STATE_LOGIN_ENTERLOGIN: rc=_s_login_enterlogin(tel); break;
	case TELNUT_STATE_LOGIN_ENTERPASS: rc=_s_login_enterpass(tel); break;
	case TELNUT_STATE_LOGIN_WAITPROMPT: rc=_s_login_waitprompt(tel); break;
	case TELNUT_STATE_CONNECTED: rc=_s_connected(tel); break;
	case TELNUT_STATE_EXEC_WAITANSWER: rc=_s_exec_waitanswer(tel); break;
	}
	if (rc == -1)
		_state_next(tel, tel->state);
	else if (rc > 0)
		_state_next(tel, rc);
}

static void
_state_next(struct telnut *tel, enum telnut_state state)
{
	int statechange;

	LOG_VERBOSE("_state_next: %d\n", state);
	statechange = 0;
	if (state != tel->state) {
		statechange = 1;
		tel->state = state;
	}

	switch(state) {
	case TELNUT_STATE_UNINITIALIZED:
	case TELNUT_STATE_DISCONNECTED:
	case TELNUT_STATE_CONNECTING:
		_error(tel, TELNUT_ERROR_UNKNOWN_STATE); break;
		break;
	case TELNUT_STATE_LOGIN_ENTERLOGIN:
	case TELNUT_STATE_LOGIN_ENTERPASS:
	case TELNUT_STATE_LOGIN_WAITPROMPT:
	case TELNUT_STATE_EXEC_WAITANSWER:
		if (statechange)
			_recvbuf_init(tel);
		_wait(tel, 0.2);
		break;
	case TELNUT_STATE_CONNECTED:
		_state(tel);
		break;
	}
}

static int
_s_login_enterlogin(struct telnut *tel)
{
	if (!_recvbuf(tel)) {
		tel->learn.login_userprompt = strndup((char *)evbuffer_pullup(tel->recvbuf.in, -1),
							(int)evbuffer_get_length(tel->recvbuf.in));
		_send(tel, tel->conf.user, strlen(tel->conf.user), 1);
		return TELNUT_STATE_LOGIN_ENTERPASS;
	}
	return -1;
}

static int
_s_login_enterpass(struct telnut *tel)
{
	if (!_recvbuf(tel)) {
		tel->learn.login_passprompt = strndup((char *)evbuffer_pullup(tel->recvbuf.in, -1),
							(int)evbuffer_get_length(tel->recvbuf.in));
		_send(tel, tel->conf.pass, strlen(tel->conf.pass), 1);
		return TELNUT_STATE_LOGIN_WAITPROMPT;
	}
	return -1;
}

static int
_s_login_waitprompt(struct telnut *tel)
{
	if (!_recvbuf(tel)) {
		tel->learn.shell_prompt = strndup((char *)evbuffer_pullup(tel->recvbuf.in, -1),
							(int)evbuffer_get_length(tel->recvbuf.in));
		return TELNUT_STATE_CONNECTED;
	}
	return -1;
}

static int
_s_connected(struct telnut *tel)
{
	tel->cbusr_connect(tel, tel->cbusr_arg);
	LOG_VERBOSE("learn.login_userprompt: %s\n", tel->learn.login_userprompt);
	LOG_VERBOSE("learn.login_passprompt: %s\n", tel->learn.login_passprompt);
	LOG_VERBOSE("learn.shell_prompt: %s\n", tel->learn.shell_prompt);
	return 0;
}

static int
_s_exec_waitanswer(struct telnut *tel)
{
	if (!_recvbuf(tel)) {
		tel->act.exec.cbusr_done(tel, tel->error, tel->act.exec.cmd,
					 (char *)evbuffer_pullup(tel->recvbuf.in, -1),
					 (int)evbuffer_get_length(tel->recvbuf.in),
					 tel->act_cbusr_arg);
		telnut_action_stop(tel);
		return 0;
	}
	return -1;
}

static void
_error(struct telnut *tel, enum telnut_error error)
{
	tel->error = error;
	telnut_disconnect(tel);
}

static void
_wait(struct telnut *tel, float sec)
{
	tel->tv_wait.tv_sec = (int)sec;
	tel->tv_wait.tv_usec = (sec - (float)tel->tv_wait.tv_sec) * 1000000;
	evtimer_add(tel->ev_wait, &tel->tv_wait);
}

static void
_send(struct telnut *tel, char *buffer, size_t size, int addcrlf)
{
	static char crlf[] = { '\r', '\n' };
	int i;

	for (i = 0; i != size; ++i) {
		/* if we got a CR or LF, replace with CRLF
		 * NOTE that usually you'd get a CR in UNIX, but in raw
		 * mode we get LF instead (not sure why)
		 */
		if (buffer[i] == '\r' || buffer[i] == '\n')
			telnet_send(tel->conn.telnet, crlf, 2);
		else
			telnet_send(tel->conn.telnet, buffer + i, 1);
	}
	if (addcrlf)
		telnet_send(tel->conn.telnet, crlf, 2);
}

static void
_cb_wait(int fd, short why, void *data)
{
	struct telnut *tel;

	tel = data;
	_state(tel);
}

static void
_cb_sock_read(struct bufferevent *bev, void *ctx)
{
	struct telnut *tel;
	struct evbuffer *bufin;
	char *data;
	int len;

	tel = ctx;
	bufin = bufferevent_get_input(tel->conn.bufev);
	len = (int)evbuffer_get_length(bufin);
	data = (char *)evbuffer_pullup(bufin, -1);
	telnet_recv(tel->conn.telnet, data, len);
	evbuffer_drain(bufin, -1);
}

static void
_cb_sock_event(struct bufferevent *bev, short events, void *ctx)
{
	struct telnut *tel;

	tel = ctx;
	if (events & BEV_EVENT_CONNECTED) {
	} else if (events & (BEV_EVENT_ERROR|BEV_EVENT_EOF)) {
		_error(tel, TELNUT_ERROR_CONNECTION_CLOSED);
	}
}

static void
_cb_telnet_event(telnet_t *telnet, telnet_event_t *ev, void *user_data)
{
	struct telnut *tel;

	tel = user_data;

	LOG_VERBOSE("_cb_telnet_event %d\n", ev->type);
	switch (ev->type) {
	/* data received */
	case TELNET_EV_DATA:
		// printf(data)
		evbuffer_add(tel->conn.telnetbuf_in, ev->data.buffer, ev->data.size);
		LOG_VERBOSE("_cb_telnet_event: DATA: %.*s\n", (int)ev->data.size, ev->data.buffer);
		break;
	/* data must be sent */
	case TELNET_EV_SEND:
		// _send(tel, ev->data.buffer, ev->data.size);
		bufferevent_write(tel->conn.bufev, ev->data.buffer, ev->data.size);
		break;
	/* request to enable remote feature (or receipt) */
	case TELNET_EV_WILL:
		/* we'll agree to turn off our echo if server wants us to stop */
		// if (ev->neg.telopt == TELNET_TELOPT_ECHO)
		break;
	/* notification of disabling remote feature (or receipt) */
	case TELNET_EV_WONT:
		// if (ev->neg.telopt == TELNET_TELOPT_ECHO)
		break;
	/* request to enable local feature (or receipt) */
	case TELNET_EV_DO:
		break;
	/* demand to disable local feature (or receipt) */
	case TELNET_EV_DONT:
		break;
	/* respond to TTYPE commands */
	case TELNET_EV_TTYPE:
		/* respond with our terminal type, if requested */
		if (ev->ttype.cmd == TELNET_TTYPE_SEND) {
			telnet_ttype_is(telnet, getenv("TERM"));
		}
		break;
	/* respond to particular subnegotiations */
	case TELNET_EV_SUBNEGOTIATION:
		break;
	/* error */
	case TELNET_EV_ERROR:
		_error(tel, TELNUT_ERROR_TELNETPROTO);
		break;
	default:
		/* ignore */
		break;
	}
}

static void
_recvbuf_init(struct telnut *tel)
{
	if (!tel->recvbuf.in)
		tel->recvbuf.in = evbuffer_new();
	else
		evbuffer_drain(tel->recvbuf.in, -1);
	tel->recvbuf.lastrecv_ticks = 0;
	tel->recvbuf.total_ticks = 0;
}

static int
_recvbuf(struct telnut *tel)
{
	int len;

	len = evbuffer_get_length(tel->conn.telnetbuf_in);
	LOG_VERBOSE("_recvbuf: len=%d lastrecv_tick=%d\n", len, tel->recvbuf.lastrecv_ticks);
	if (len <= 0) {
		if (tel->recvbuf.lastrecv_ticks > 4)
			return 0;
		else if (evbuffer_get_length(tel->recvbuf.in) > 0)
			tel->recvbuf.lastrecv_ticks++;
	} else {
		evbuffer_add_buffer(tel->recvbuf.in, tel->conn.telnetbuf_in);
	}
	return -1;
}

