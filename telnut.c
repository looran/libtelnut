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

#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <libgen.h>

#include <event2/bufferevent.h>
#include <event2/buffer.h>
#include <event2/event.h>

#include "telnut.h"
#include "b64otf/b64otf.h"

#define TELNUT_FILEBUF_SIZE 100000
#define TELNUT_BEBUF_SIZE 4096 /* smaller than TELNUT_FILEBUF_SIZE, so we dont brute the b64 decoder on remote end */
#define CTRL_C "\x03"
#define CTRL_D "\x04"

#define LOG_VERBOSE(parg, ...) do { if (tel->conf.verbose >= 1) { printf(parg, ##__VA_ARGS__); } }while(0);
#define LOG_DEBUG(parg, ...) do { if (tel->conf.verbose >= 2) { printf("telnut: " parg, ##__VA_ARGS__); } }while(0);

static const telnet_telopt_t _telopts[] = {
	{ TELNET_TELOPT_SGA,		TELNET_WONT, TELNET_DO   },
	{ TELNET_TELOPT_TTYPE,		TELNET_WILL, TELNET_DONT },
	{ TELNET_TELOPT_NEW_ENVIRON,	TELNET_WILL, TELNET_DONT },
	{ TELNET_TELOPT_STATUS,		TELNET_WONT, TELNET_DO   },
	{ TELNET_TELOPT_XDISPLOC,	TELNET_WILL, TELNET_DONT },
	{ TELNET_TELOPT_ECHO,		TELNET_WONT, TELNET_DONT },
	{ TELNET_TELOPT_COMPRESS2,	TELNET_WONT, TELNET_DO   },
	{ TELNET_TELOPT_MSSP,		TELNET_WONT, TELNET_DO   },
	{ -1, 0, 0 }
};

enum telnut_push_step _push_steps[4][7] = {
	/* TELNUT_PUSH_MODE_RAW */
	{ TELNUT_PUSH_UNINITIALIZED,
	  TELNUT_PUSH_4_PUSHFILE,
	  0, 0, 0, 0, 0 },
	/* TELNUT_PUSH_MODE_RAW_DECNAT */
	{ TELNUT_PUSH_UNINITIALIZED,
	  TELNUT_PUSH_1_PUSHDEC1L,
	  TELNUT_PUSH_2_PUSHDECNAT,
	  TELNUT_PUSH_3_RMDEC1L,
	  TELNUT_PUSH_4_PUSHFILE,
	  TELNUT_PUSH_5_RMDECNAT,
	  0 },
	/* TELNUT_PUSH_MODE_B64 */
	{ TELNUT_PUSH_UNINITIALIZED,
	  TELNUT_PUSH_1_PUSHDEC1L,
	  TELNUT_PUSH_4_PUSHFILE,
	  TELNUT_PUSH_3_RMDEC1L,
	  0, 0, 0 },
	/* TELNUT_PUSH_MODE_B64_DECNAT */
	{ TELNUT_PUSH_UNINITIALIZED,
	  TELNUT_PUSH_1_PUSHDEC1L,
	  TELNUT_PUSH_2_PUSHDECNAT,
	  TELNUT_PUSH_3_RMDEC1L,
	  TELNUT_PUSH_4_PUSHFILE,
	  TELNUT_PUSH_5_RMDECNAT,
	  0 },
};

char _b64_dec1l[] = B64_DECODER_ONELINER; /* from b64otf/b64otf.h */

static int  _exec(struct telnut *, char *);
static int  _push_step(struct telnut *);
static enum telnut_push_step _push_step_getnext(enum telnut_push_mode, enum telnut_push_step);
static enum telnut_state     _push_file_init(struct telnut *, enum telnut_encoder, char *);
static void                  _push_file_free(struct telnut *);
static void _state(struct telnut *);
static void _state_next(struct telnut *, enum telnut_state);
static int  _s_connecting(struct telnut *);
static int  _s_connected(struct telnut *);
static int  _s_exec_waitanswer(struct telnut *);
static int  _s_push_cat(struct telnut *);
static int  _s_push_send(struct telnut *);
static int  _s_push_waitprompt(struct telnut *);
static void _error(struct telnut *, enum telnut_error, int);
static void _wait(struct telnut *, float);
static void _send(struct telnut *, const char *, size_t, int);
static void _cb_wait(int, short, void *);
static void _cb_stdin_read(int, short, void *);
static void _cb_sock_read(struct bufferevent *, void *);
static void _cb_sock_write(struct bufferevent *, void *);
static void _cb_sock_event(struct bufferevent *, short, void *);
static void _cb_telnet_event(telnet_t *, telnet_event_t *, void *);
static void _recvbuf_init(struct telnut *);
static int  _recvbuf(struct telnut *tel);
static void _send_sock_defer(struct telnut *, const char *, size_t);
static void _senddefer_schedule(struct telnut *);
static void _cb_senddefer(int, short, void *);

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
	event_free(tel->ev_wait);
	free(tel);
}

int
telnut_connect(struct telnut *tel)
{
	unsigned long hostaddr;
	struct sockaddr_in sin;
	
	LOG_VERBOSE("[+] Connecting to \"%s\"\n", tel->conf.ip);
	hostaddr = inet_addr(tel->conf.ip);
	sin.sin_family = AF_INET;
	sin.sin_port = htons(tel->conf.port);
	sin.sin_addr.s_addr = hostaddr;

	tel->conn.telnet = telnet_init(_telopts, _cb_telnet_event, 0, tel);
	tel->conn.telnetbuf_in = evbuffer_new();
	tel->conn.tfp = tfp_new(tel->conf.user, tel->conf.pass, tel->conf.verbose);

	tel->senddefer.out = evbuffer_new();
	tel->senddefer.ev_send = evtimer_new(tel->evb, _cb_senddefer, tel);

	tel->conn.bufev = bufferevent_socket_new(tel->evb, -1, BEV_OPT_CLOSE_ON_FREE);
	bufferevent_setcb(tel->conn.bufev, _cb_sock_read, _cb_sock_write, _cb_sock_event, tel);
	bufferevent_enable(tel->conn.bufev, EV_READ|EV_WRITE);
	if (bufferevent_socket_connect(tel->conn.bufev, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
		_error(tel, TELNUT_ERROR_CONNECTION_CLOSED, 1);
		return -1;
	}
	tel->conn.wait_count = 0;
	_state_next(tel, TELNUT_STATE_CONNECTING);

	return 0;
}

int
telnut_disconnect(struct telnut *tel)
{
	if (tel->state <= TELNUT_STATE_DISCONNECTED)
		return -1;
	LOG_DEBUG("telnut_disconnect\n");

	bufferevent_free(tel->conn.bufev);

	event_free(tel->senddefer.ev_send);
	evbuffer_free(tel->senddefer.out);

	tfp_free(tel->conn.tfp);
	telnet_free(tel->conn.telnet);
	evbuffer_free(tel->conn.telnetbuf_in);

	tel->state = TELNUT_STATE_DISCONNECTED;
	tel->cbusr_disconnect(tel, tel->error, tel->cbusr_arg);
	return 0;
}

void
telnut_err_print(enum telnut_error error)
{
	printf("Telnut error: ");
	switch(error) {
	case TELNUT_NOERROR: printf("no error\n"); break;
	case TELNUT_ERROR_UNKNOWN_STATE: printf("Unknown state\n"); break;
	case TELNUT_ERROR_CONNECTION: printf("Connection error\n"); break;
	case TELNUT_ERROR_CONNECTION_CLOSED: printf("Connection closed\n"); break;
	case TELNUT_ERROR_LOGIN: printf("Login error\n"); break;
	case TELNUT_ERROR_SHELL: printf("Error while trying to get a shell\n"); break;
	case TELNUT_ERROR_PUSH_LOCALFILENOTFOUND: printf("Local file not found\n"); break;
	case TELNUT_ERROR_TELNETPROTO: printf("Internal libtelnet error\n"); break;
	}
}

int
telnut_interactive(struct telnut *tel)
{
	LOG_VERBOSE("[+] Action: Interactive shell\n");
	tel->action = TELNUT_ACTION_INTERACTIVE;
	tel->state = TELNUT_STATE_INTERACTIVE;
	fcntl(STDIN_FILENO, F_SETFL, fcntl(STDIN_FILENO, F_GETFL) | O_NONBLOCK);
	tel->act.interactive.stdin = event_new(tel->evb, STDIN_FILENO, EV_READ|EV_PERSIST, _cb_stdin_read, tel);
	event_add(tel->act.interactive.stdin, NULL);
	_send(tel, "", 0, 1);
	return 0;
}

int
telnut_exec(struct telnut *tel, char *cmd, 
	void (*cbusr_done)(struct telnut *, enum telnut_error, char *, int, void *), void *cbusr_arg)
{
	LOG_VERBOSE("[+] Action: Execute \"%s\"\n", cmd);
	tel->action = TELNUT_ACTION_EXEC;
	tel->act.exec.cbusr_done = cbusr_done;
	tel->act_cbusr_arg = cbusr_arg;
	_state_next(tel, _exec(tel, cmd));
	return 0;
}

int
telnut_push(struct telnut *tel, char *path_local, char *path_remote, enum telnut_encoder encoder, char *decoder,
	void (*cbusr_done)(struct telnut *, enum telnut_error, void *), void *cbusr_arg)
{
	LOG_VERBOSE("[+] Action: Push file \"%s\"\n", path_local);
	tel->action = TELNUT_ACTION_PUSH;
	tel->act.push.path_local = strdup(path_local);
	tel->act.push.path_remote = strdup(path_remote);
	tel->act.push.path_remotedir = strdup(dirname(tel->act.push.path_remote));
	tel->act.push.path_remote = strdup(path_remote);
	tel->act.push.path_remotebase = strdup(basename(tel->act.push.path_remote));
	tel->act.push.path_remote = strdup(path_remote);
	tel->act.push.encoder = encoder;
	tel->act.push.decoder = decoder;
	tel->act.push.cbusr_done = cbusr_done;
	tel->act.pushstep.file = NULL;
	tel->act_cbusr_arg = cbusr_arg;
	tel->act.push.step = TELNUT_PUSH_UNINITIALIZED;
	if (encoder == PUSH_RAW && !decoder)
		tel->act.push.mode = TELNUT_PUSH_MODE_RAW;
	else if (encoder == PUSH_RAW && decoder)
		tel->act.push.mode = TELNUT_PUSH_MODE_RAW_DECNAT;
	else if (encoder == PUSH_B64 && !decoder)
		tel->act.push.mode = TELNUT_PUSH_MODE_B64;
	else if (encoder == PUSH_B64 && decoder)
		tel->act.push.mode = TELNUT_PUSH_MODE_B64_DECNAT;
	else
		goto err;

	_state_next(tel, _push_step(tel));

	return 0;
err:
	free(tel->act.push.path_local);
	free(tel->act.push.path_remote);
	free(tel->act.push.path_remotedir);
	free(tel->act.push.path_remotebase);
	return -1;
}

void
telnut_action_stop(struct telnut *tel)
{
	tel->state = TELNUT_STATE_CONNECTED;
	switch(tel->action) {
	case TELNUT_NOACTION:
		break;
	case TELNUT_ACTION_INTERACTIVE:
		tel->action = TELNUT_NOACTION;
		event_free(tel->act.interactive.stdin);
		break;
	case TELNUT_ACTION_EXEC:
		tel->action = TELNUT_NOACTION;
		free(tel->act.exec.cmd);
		// XXX if we where TELNUT_STATE_EXEC_WAITANSWER, need to ignore cmd result receive
		tel->act.exec.cbusr_done(tel, tel->error,
					 (char *)evbuffer_pullup(tel->recvbuf.in, -1),
					 (int)evbuffer_get_length(tel->recvbuf.in),
					 tel->act_cbusr_arg);
		break;
	case TELNUT_ACTION_PUSH:
		tel->action = TELNUT_NOACTION;
		free(tel->act.push.path_local);
		free(tel->act.push.path_remote);
		free(tel->act.push.path_remotedir);
		free(tel->act.push.path_remotebase);
		tel->act.push.cbusr_done(tel, tel->error, tel->act_cbusr_arg);
		break;
	}
}

static int
_exec(struct telnut *tel, char *cmd)
{
	tel->act.exec.cmd = strdup(cmd);
	_send(tel, tel->act.exec.cmd, strlen(cmd), 1);
	return TELNUT_STATE_EXEC_WAITANSWER;
}

static int
_push_step(struct telnut *tel)
{
	char buf[200];
	char *pipe_decoder;
	enum telnut_encoder enc;

	LOG_DEBUG("_push_step\n");
	if (tel->act.pushstep.file || tel->act.pushstep.be)
		_push_file_free(tel);

	tel->act.push.step = _push_step_getnext(tel->act.push.mode, tel->act.push.step);
	LOG_DEBUG("_push_step: step %d\n", tel->act.push.step);
	tel->state = TELNUT_STATE_CONNECTED;

	switch (tel->act.push.step) {
	case TELNUT_PUSH_UNINITIALIZED:
		_error(tel, TELNUT_ERROR_UNKNOWN_STATE, 0);
		break;
	case TELNUT_PUSH_DONE:
		telnut_action_stop(tel);
		break;
	case TELNUT_PUSH_1_PUSHDEC1L:
		LOG_VERBOSE("[-] Push shell base64 decoder (RAW)\n");
		snprintf(buf, sizeof(buf), "%s/.%se",
			tel->act.push.path_remotedir, tel->act.push.path_remotebase);
		tel->act.push.path_remote_dec1l = strdup(buf);
		tel->act.pushstep.path_local = NULL;
		tel->act.pushstep.path_remote = tel->act.push.path_remote_dec1l;
		return _push_file_init(tel, PUSH_RAW, NULL);
	case TELNUT_PUSH_2_PUSHDECNAT:
		LOG_VERBOSE("[-] Push native base64 decoder ");
		snprintf(buf, sizeof(buf), "%s/.%sf",
			tel->act.push.path_remotedir, tel->act.push.path_remotebase);
		tel->act.push.path_remote_decnat = strdup(buf);
		tel->act.pushstep.path_local = tel->act.push.path_local_decnat;
		tel->act.pushstep.path_remote = tel->act.push.path_remote_decnat;
		return _push_file_init(tel, PUSH_B64, tel->act.push.path_remote_dec1l);
	case TELNUT_PUSH_3_RMDEC1L:
		LOG_VERBOSE("[-] Remove shell base64 decoder\n");
		snprintf(buf, sizeof(buf), "rm -f %s", tel->act.push.path_remote_dec1l);
		return _exec(tel, buf);
	case TELNUT_PUSH_4_PUSHFILE:
		LOG_VERBOSE("[-] Push target file ");
		tel->act.pushstep.path_local = tel->act.push.path_local;
		tel->act.pushstep.path_remote = tel->act.push.path_remote;
		switch(tel->act.push.mode) {
		case TELNUT_PUSH_MODE_RAW: 	  enc=PUSH_RAW; pipe_decoder=NULL; break;
		case TELNUT_PUSH_MODE_RAW_DECNAT: enc=PUSH_B64; pipe_decoder=tel->act.push.path_remote_decnat; break;
		case TELNUT_PUSH_MODE_B64: 	  enc=PUSH_B64; pipe_decoder=tel->act.push.path_remote_dec1l; break;
		case TELNUT_PUSH_MODE_B64_DECNAT: enc=PUSH_B64; pipe_decoder=tel->act.push.path_remote_decnat; break;
		}
		return _push_file_init(tel, enc, pipe_decoder);
	case TELNUT_PUSH_5_RMDECNAT:
		LOG_VERBOSE("[-] Remove native base64 decoder\n");
		snprintf(buf, sizeof(buf), "rm -f %s", tel->act.push.path_remote_decnat);
		return _exec(tel, buf);
	}
	return 0;
}

static enum telnut_push_step
_push_step_getnext(enum telnut_push_mode mode, enum telnut_push_step step)
{
	enum telnut_push_step s;
        int i;

        i = 0;
        do {
                s = _push_steps[mode][i];
                if (s == step) return _push_steps[mode][i+1];
                i++;
        } while (s != TELNUT_PUSH_DONE);
        return TELNUT_PUSH_DONE;
}

static enum telnut_state
_push_file_init(struct telnut *tel, enum telnut_encoder encoder, char *pipe_decoder)
{
	char buf[200];

	LOG_DEBUG("_push_file_init: %s -> %s\n",
		tel->act.pushstep.path_local, tel->act.pushstep.path_remote);
	if (tel->act.pushstep.path_local) {
		switch (encoder) {
		case PUSH_RAW:
			LOG_VERBOSE("(RAW)\n");
			tel->act.pushstep.file = fopen(tel->act.pushstep.path_local, "rb");
			if (!tel->act.pushstep.file) {
				tel->error = TELNUT_ERROR_PUSH_LOCALFILENOTFOUND;
				return _push_step(tel); /* continue to cleanup */
			}
			stat(tel->act.pushstep.path_local, &tel->act.pushstep.fileinfo);
			tel->act.pushstep.filebuf = malloc(TELNUT_FILEBUF_SIZE * sizeof(char));
			break;
		case PUSH_B64:
			LOG_VERBOSE("(BASE64 on-the-fly)\n");
			tel->act.pushstep.be = b64e_new(tel->act.push.path_local, TELNUT_BEBUF_SIZE);
			if (!tel->act.pushstep.be) {
				tel->error = TELNUT_ERROR_PUSH_LOCALFILENOTFOUND;
				return _push_step(tel); /* continue to cleanup */
			}
			tel->act.pushstep.filebuf = malloc(TELNUT_BEBUF_SIZE * sizeof(char));
			break;
		}
	}
	tel->act.pushstep.filebuf_remaining = 0;
	if (pipe_decoder)
		snprintf(buf, sizeof(buf), "cat | %s > %s", pipe_decoder, tel->act.pushstep.path_remote);
	else
		snprintf(buf, sizeof(buf), "cat > %s", tel->act.pushstep.path_remote);
	_send(tel, buf, strlen(buf), 1);

	return TELNUT_STATE_PUSH_CAT;
}

static void
_push_file_free(struct telnut *tel)
{
	if (tel->act.pushstep.be) {
		b64e_free(tel->act.pushstep.be);
		tel->act.pushstep.be = NULL;
	} else {
		fclose(tel->act.pushstep.file);
		tel->act.pushstep.file = NULL;
	}
	free(tel->act.pushstep.filebuf);
}

static void
_state(struct telnut *tel)
{
	int rc;

	LOG_DEBUG("_state: %d\n", tel->state);
	rc = 0;
	switch(tel->state) {
	case TELNUT_STATE_UNINITIALIZED: _error(tel, TELNUT_ERROR_UNKNOWN_STATE, 1); break;
	case TELNUT_STATE_DISCONNECTED: _error(tel, TELNUT_ERROR_UNKNOWN_STATE, 1); break;
	case TELNUT_STATE_CONNECTING: rc=_s_connecting(tel); break;
	case TELNUT_STATE_CONNECTED: rc=_s_connected(tel); break;
	case TELNUT_STATE_INTERACTIVE: break;
	case TELNUT_STATE_EXEC_WAITANSWER: rc=_s_exec_waitanswer(tel); break;
	case TELNUT_STATE_PUSH_CAT: rc=_s_push_cat(tel); break;
	case TELNUT_STATE_PUSH_SEND: rc=_s_push_send(tel); break;
	case TELNUT_STATE_PUSH_WAITPROMPT: rc=_s_push_waitprompt(tel); break;
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

	LOG_DEBUG("_state_next: %d\n", state);
	statechange = 0;
	if (state != tel->state) {
		statechange = 1;
		tel->state = state;
	}

	switch(state) {
	case TELNUT_STATE_UNINITIALIZED:
	case TELNUT_STATE_DISCONNECTED:
	case TELNUT_STATE_INTERACTIVE:
		_error(tel, TELNUT_ERROR_UNKNOWN_STATE, 1); break;
		break;
	case TELNUT_STATE_CONNECTING:
	case TELNUT_STATE_EXEC_WAITANSWER:
	case TELNUT_STATE_PUSH_CAT:
	case TELNUT_STATE_PUSH_WAITPROMPT:
		if (statechange)
			_recvbuf_init(tel);
		_wait(tel, 0.2);
		break;
	case TELNUT_STATE_CONNECTED:
	case TELNUT_STATE_PUSH_SEND:
		_state(tel);
		break;
	}
}

static int
_s_connecting(struct telnut *tel)
{
	enum tfp_action action;
	const char *cmd;
	int cmdlen;

	if (!_recvbuf(tel)) {
		action = tfp_getaction(tel->conn.tfp,
			(char *)evbuffer_pullup(tel->recvbuf.in, -1), (int)evbuffer_get_length(tel->recvbuf.in),
			&cmd, &cmdlen);
		switch (action) {
		case TFP_SEND:
			_recvbuf_init(tel);
			_send(tel, cmd, cmdlen, 1);
			break;
		case TFP_WAIT:
			if (tel->conn.wait_count > 5) {
				_error(tel, TELNUT_ERROR_LOGIN, 1);
				return 0;
			}
			_recvbuf_init(tel);
			_send(tel, "", 0, 1); /* sometimes sending crlf helps */
			tel->conn.wait_count += 1;
			break;
		case TFP_HAS_SHELL:
			return TELNUT_STATE_CONNECTED;
		case TFP_ERROR:
			_error(tel, TELNUT_ERROR_LOGIN, 1); // XXX use correct error
			return 0;
		}
	}
	return -1;
}

static int
_s_connected(struct telnut *tel)
{
	tel->cbusr_connect(tel, tel->cbusr_arg);
	LOG_DEBUG("Host fingerprint:\n%s\n", tfp_str(tel->conn.tfp));
	return 0;
}

static int
_s_exec_waitanswer(struct telnut *tel)
{
	if (!_recvbuf(tel)) {
		if (tel->action == TELNUT_ACTION_EXEC) {
			telnut_action_stop(tel);
			return 0;
		} else {
			return _push_step(tel);
		}
	}
	return -1;
}

static int
_s_push_cat(struct telnut *tel)
{
	if (!_recvbuf(tel)) {
		// XXX check cat output for errors
		return TELNUT_STATE_PUSH_SEND;
	}
	return -1;
}

static int
_s_push_send(struct telnut *tel)
{
	unsigned char *filebuf_start;

	if (tel->act.push.step == TELNUT_PUSH_1_PUSHDEC1L) { /* not local file based */
		if (!tel->act.pushstep.filebuf_remaining) {
			bufferevent_write(tel->conn.bufev, _b64_dec1l, strlen(_b64_dec1l));
			bufferevent_write(tel->conn.bufev, "\r\n", 2);
			tel->act.pushstep.filebuf_remaining = -1;
		} else {
			bufferevent_write(tel->conn.bufev, "\r\n", 2);
			bufferevent_write(tel->conn.bufev, CTRL_D, 1);
			bufferevent_write(tel->conn.bufev, "\r\n", 2);
			return TELNUT_STATE_PUSH_WAITPROMPT;
		}
	} else {					    /* local file based */
		if (!tel->act.pushstep.filebuf_remaining) {
			if (tel->act.pushstep.be)
				tel->act.pushstep.filebuf_size = b64e_read(tel->act.pushstep.be,
									   tel->act.pushstep.filebuf);
			else
				tel->act.pushstep.filebuf_size = fread(tel->act.pushstep.filebuf, 1,
								       TELNUT_FILEBUF_SIZE, tel->act.pushstep.file);
			tel->act.pushstep.filebuf_remaining = tel->act.pushstep.filebuf_size;
		}
		if (tel->act.pushstep.filebuf_remaining <= 0) { /* EOF */
			bufferevent_write(tel->conn.bufev, "\r\n", 2);
			bufferevent_write(tel->conn.bufev, CTRL_D, 1);
			if (tel->act.pushstep.be)
				LOG_VERBOSE("[-] Push done, waiting for decoding to finish\n");
			return TELNUT_STATE_PUSH_WAITPROMPT;
		}
		filebuf_start = (tel->act.pushstep.filebuf + tel->act.pushstep.filebuf_size) - tel->act.pushstep.filebuf_remaining;
		if (!bufferevent_write(tel->conn.bufev, filebuf_start, tel->act.pushstep.filebuf_remaining))
			tel->act.pushstep.filebuf_remaining = 0;
	}
	return 0; /* do not trigger _state_next(), _cb_sock_write() will call us again */
}

static int
_s_push_waitprompt(struct telnut *tel)
{
	char buf[200];

	if (!_recvbuf(tel)) {
		if (!tfp_hasprompt(tel->conn.tfp, (char *)evbuffer_pullup(tel->recvbuf.in, -1))) {
			snprintf(buf, sizeof(buf), "chmod 700 %s", tel->act.pushstep.path_remote);
			return _exec(tel, buf);
		}
		_recvbuf_init(tel);
	}
	return -1;
}

static void
_error(struct telnut *tel, enum telnut_error error, int disconnect)
{
	tel->error = error;
	if (disconnect)
		telnut_disconnect(tel);
	else
		telnut_action_stop(tel);
}

static void
_wait(struct telnut *tel, float sec)
{
	tel->tv_wait.tv_sec = (int)sec;
	tel->tv_wait.tv_usec = (sec - (float)tel->tv_wait.tv_sec) * 1000000;
	evtimer_add(tel->ev_wait, &tel->tv_wait);
}

static void
_send(struct telnut *tel, const char *buffer, size_t size, int addcrlf)
{
	static char crlf[] = { '\r', '\n' };
	// static char crlf[] = { '\r' };
	int i;

	LOG_DEBUG("\n=== SENDING ===\n%.*s\n", (int)size, buffer);
	for (i = 0; i != size; ++i) {
		/* if we got a CR or LF, replace with CRLF
		 * NOTE that usually you'd get a CR in UNIX, but in raw
		 * mode we get LF instead (not sure why)
		 */
		if (buffer[i] == '\r' || buffer[i] == '\n') {
			telnet_send(tel->conn.telnet, crlf, 2);
			// tel->conn.echosuppress_count += 1;
		} else {
			telnet_send(tel->conn.telnet, buffer + i, 1);
			// tel->conn.echosuppress_count += 1;
		}
	}
	if (addcrlf) {
		telnet_send(tel->conn.telnet, crlf, 2);
		// tel->conn.echosuppress_count += 1;
	}
}

static void
_cb_wait(int fd, short why, void *data)
{
	struct telnut *tel;

	tel = data;
	_state(tel);
}

static void
_cb_stdin_read(int fd, short why, void *data)
{
	struct telnut *tel;
	char buf[512];
	int len;

	tel = data;
	LOG_DEBUG("_cb_stdin_read\n");
	while ((len = read(STDIN_FILENO, buf, sizeof(buf))) > 0)
		bufferevent_write(tel->conn.bufev, buf, len);
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
_cb_sock_write(struct bufferevent *bev, void *ctx)
{
	struct telnut *tel;

	tel = ctx;
	switch (tel->state) {
	case TELNUT_STATE_UNINITIALIZED:
	case TELNUT_STATE_DISCONNECTED:
	case TELNUT_STATE_CONNECTING:
	case TELNUT_STATE_CONNECTED:
	case TELNUT_STATE_INTERACTIVE:
	case TELNUT_STATE_EXEC_WAITANSWER:
	case TELNUT_STATE_PUSH_CAT:
	case TELNUT_STATE_PUSH_WAITPROMPT:
		return;
	case TELNUT_STATE_PUSH_SEND:
		_state(tel);
	}
}

static void
_cb_sock_event(struct bufferevent *bev, short events, void *ctx)
{
	struct telnut *tel;

	tel = ctx;
	if (events & BEV_EVENT_CONNECTED) {
	} else if (events & (BEV_EVENT_ERROR|BEV_EVENT_EOF)) {
		_error(tel, TELNUT_ERROR_CONNECTION_CLOSED, 1);
	}
}

static void
_cb_telnet_event(telnet_t *telnet, telnet_event_t *ev, void *user_data)
{
	struct telnut *tel;
	char *bufptr;
	int writelen;

	tel = user_data;

	LOG_DEBUG("_cb_telnet_event %d\n", ev->type);
	switch (ev->type) {
	/* data received */
	case TELNET_EV_DATA:
		LOG_DEBUG("_cb_telnet_event: DATA: %.*s\n", (int)ev->data.size, ev->data.buffer);
		/* echo cancellation, best effort */
		writelen = ev->data.size - tel->conn.echosuppress_count;
		if (writelen <= 0) {
			tel->conn.echosuppress_count -= ev->data.size;
			break;
		}
		bufptr = (char *)ev->data.buffer + tel->conn.echosuppress_count;
		tel->conn.echosuppress_count = 0;
		if (tel->state == TELNUT_STATE_INTERACTIVE)
			printf("%.*s", writelen, bufptr);
		else
			evbuffer_add(tel->conn.telnetbuf_in, bufptr, writelen); /* recvbuf buffer */
		break;
	/* data must be sent */
	case TELNET_EV_SEND:
		if ((ev->data.size >= 3) && (!strncmp(ev->data.buffer, "\xff", 1)))
			bufferevent_write(tel->conn.bufev, ev->data.buffer, ev->data.size); /* telnet cmd, fast */
		else
			_send_sock_defer(tel, ev->data.buffer, ev->data.size); /* data, humanoid like, slow */
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
		_error(tel, TELNUT_ERROR_TELNETPROTO, 1);
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
	tel->recvbuf.max_ticks = 8;
}

static int
_recvbuf(struct telnut *tel)
{
	int len;

	len = evbuffer_get_length(tel->conn.telnetbuf_in);
	LOG_DEBUG("_recvbuf: len=%d lastrecv_tick=%d\n", len, tel->recvbuf.lastrecv_ticks);
	if (len <= 0) {
		if (tel->recvbuf.lastrecv_ticks > tel->recvbuf.max_ticks)
			return 0;
		else if (evbuffer_get_length(tel->recvbuf.in) > 0)
			tel->recvbuf.lastrecv_ticks++;
	} else {
		evbuffer_add_buffer(tel->recvbuf.in, tel->conn.telnetbuf_in);
	}
	return -1;
}

static void
_send_sock_defer(struct telnut *tel, const char *buffer, size_t size)
{
	evbuffer_add(tel->senddefer.out, buffer, size);
	_senddefer_schedule(tel);
}

static void
_senddefer_schedule(struct telnut *tel)
{
	struct timeval next;

	if (evtimer_pending(tel->senddefer.ev_send, NULL))
		return;
	next.tv_sec = 0;
	next.tv_usec = 75000; // XXX randomize
	evtimer_add(tel->senddefer.ev_send, &next);
}

static void
_cb_senddefer(int fd, short why, void *data)
{
	struct telnut *tel;
	int len, sendlen, remaining, rs;
	char *buf;

	tel = data;
	len = evbuffer_get_length(tel->senddefer.out);
	if (!len)
		return;
	sendlen = 1;
	buf = (char *)evbuffer_pullup(tel->senddefer.out, sendlen);
	if (len >= 2 && !strncmp(buf, "\r", 1)) { /* clrf */
		sendlen = 2;
		buf = (char *)evbuffer_pullup(tel->senddefer.out, sendlen);
	}
	remaining = sendlen;
	while (remaining > 0) {
		if ((rs = send(bufferevent_getfd(tel->conn.bufev), buf, remaining, 0)) == -1) {
			LOG_DEBUG("_cb_senddefer: send() failed: %s\n", strerror(errno));
			return;
		} else if (rs == 0) {
			LOG_DEBUG("_cb_senddefer: send() unexpectedly returned 0\n");
			return;
		}
		buf += rs;
		remaining -= rs;
	}
	evbuffer_drain(tel->senddefer.out, sendlen);

	len = evbuffer_get_length(tel->senddefer.out);
	if (len > 0)
		_senddefer_schedule(tel);
}

