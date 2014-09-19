#include <sys/types.h>
#include <regex.h>
#include <string.h>

#include "telnut.h"

#ifdef TFP_DATA_EXTERNAL_H
#include "tfp_data_external.h"
#else
#include "tfp_data.h"
#endif
extern struct tfp_login _logins[];
extern struct tfp_console _consoles[];

#define TFP_LOGINS_COUNT (int)(sizeof(_logins) / sizeof(_logins[0]))
#define TFP_LOGINS_FAILED_COUNT (int)(sizeof(_logins_failed) / sizeof(_logins_failed[0]))
#define TFP_CONSOLES_COUNT (int)(sizeof(_consoles) / sizeof(_consoles[0]))

static enum tfp_action _login(struct tfp *, const char **, int *);
static int             _login_hasfailed(struct tfp *, const char **, int *);
static enum tfp_action _console(struct tfp *, const char **, int *);
static enum tfp_action _shell(struct tfp *, const char **, int *);
static int _regcmp(char *, char *, int);

// #define DEBUG

#ifdef DEBUG
#define LOG_VERBOSE(parg, ...) do { printf( parg, ##__VA_ARGS__); } while(0);
#else
#define LOG_VERBOSE(parg, ...) do { } while(0);
#endif

struct tfp *
tfp_new(char *user, char *pass)
{
	struct tfp *tfp;

	tfp = calloc(1, sizeof(struct tfp));
	tfp->conf.user = user;
	tfp->conf.pass = pass;
	return tfp;
}

void
tfp_free(struct tfp *tfp)
{
	if (tfp->learn.login_user)
		free(tfp->learn.login_user);
	if (tfp->learn.login_pass)
		free(tfp->learn.login_pass);
	if (tfp->learn.login_console)
		free(tfp->learn.login_console);
	if (tfp->learn.shell_prompt)
		free(tfp->learn.shell_prompt);
	free(tfp);
}

enum tfp_action
tfp_getaction(struct tfp *tfp, char *recv, int recv_len, const char **cmd, int *cmdlen)
{
	enum tfp_action action;

	LOG_VERBOSE("tfp_getaction: state=%d\n", tfp->state);
	switch (tfp->state) {
	case TFP_STATE_LOGIN_USER:
		tfp->learn.login_user = strndup(recv, recv_len);
		action = _login(tfp, cmd, cmdlen);
		break;
	case TFP_STATE_LOGIN_PASS:
		tfp->learn.login_pass = strndup(recv, recv_len);
		action = _login(tfp, cmd, cmdlen);
		break;
	case TFP_STATE_CONSOLE:
		if (!tfp->learn.login_console)
			tfp->learn.login_console = strndup(recv, recv_len);
		action = _console(tfp, cmd, cmdlen);
		break;
	case TFP_STATE_CHECK_SHELL:
		tfp->learn.shell_prompt = strndup(recv, recv_len);
		action = _shell(tfp, cmd, cmdlen);
		break;
	case TFP_STATE_SHELL:
		action = _shell(tfp, cmd, cmdlen);
		break;
	}

	return action;
}

const char *
tfp_str(struct tfp *tfp)
{
	static char buf[1024];

	snprintf(buf, sizeof(buf),
		"learn.login_user :\n%s\n"
		"learn.login_pass :\n%s\n"
		"learn.login_console :\n%s\n"
		"learn.shell_prompt :\n%s\n",
		tfp->learn.login_user, tfp->learn.login_pass,
		tfp->learn.login_console, tfp->learn.shell_prompt);
	
	return buf;
}

static enum tfp_action
_login(struct tfp *tfp, const char **cmd, int *cmdlen)
{
	struct tfp_login *login, *lastmatch;
	enum tfp_action action;
	int i, lastmatch_pass;

	if (_login_hasfailed(tfp, cmd, cmdlen))
		return TFP_ERROR;

	lastmatch = NULL;
	action = TFP_ERROR;
	for (i=0; i<TFP_LOGINS_COUNT; i++) {
		login = &_logins[i];
		if (!login->user.user
		    || !_regcmp(tfp->learn.login_user, login->user.user, login->user.cflags)) {
			if (tfp->learn.login_pass) {
				if (!login->pass.pass
				    || !_regcmp(tfp->learn.login_pass, login->pass.pass, login->pass.cflags)) {
					lastmatch = login;
					lastmatch_pass = 1;
				}
			} else {
				if (login->user.user) {
					lastmatch = login;
					lastmatch_pass = 0;
				} else if (login->pass.pass
				           && !_regcmp(tfp->learn.login_user, login->pass.pass, login->pass.cflags)) {
					lastmatch = login;
					lastmatch_pass = 1;
				}
			}
		}
	}
	if (lastmatch) {
		tfp->login = lastmatch;
		if (lastmatch_pass) {
			*cmd = tfp->conf.pass;
			*cmdlen = strlen(tfp->conf.pass);
			tfp->state = TFP_STATE_CONSOLE;
		} else {
			*cmd = tfp->conf.user;
			*cmdlen = strlen(tfp->conf.user);
			tfp->state = TFP_STATE_LOGIN_PASS;
		}
		action = TFP_SEND;
	}

	return action;
}

static int
_login_hasfailed(struct tfp *tfp, const char **cmd, int *cmdlen)
{
	struct tfp_login_failed *fail;
	int i;

	for (i=0; i<TFP_LOGINS_FAILED_COUNT; i++) {
		fail = &_logins_failed[i];
		if (tfp->learn.login_pass && fail->pass.pass
		    && !_regcmp(tfp->learn.login_pass, fail->pass.pass, fail->pass.cflags))
			return 1;
		if (tfp->learn.login_console && fail->console.console
		    && !_regcmp(tfp->learn.login_console, fail->console.console, fail->console.cflags))
			return 1;
	}

	return 0;
}

static enum tfp_action
_console(struct tfp *tfp, const char **cmd, int *cmdlen)
{
	struct tfp_console *console, *lastmatch;
	enum tfp_action action;
	int i;

	if (_login_hasfailed(tfp, cmd, cmdlen))
		return TFP_ERROR;

	LOG_VERBOSE("_console\n");
	lastmatch = NULL;
	for (i=0; i<TFP_CONSOLES_COUNT; i++) {
		console = &_consoles[i];
		if (!console->login.user || !tfp->learn.login_user
		    || !_regcmp(tfp->learn.login_user, console->login.user, console->login.user_cflags))
			if (!console->login.pass || !tfp->learn.login_pass
			    || !_regcmp(tfp->learn.login_pass, console->login.pass, console->login.pass_cflags))
				if (!console->login.console || !tfp->learn.login_console
				    || !_regcmp(tfp->learn.login_console, console->login.console, console->login.console_cflags))
					lastmatch = console;
	}
	if (lastmatch) {
		tfp->console = lastmatch;
		tfp->state = TFP_STATE_CHECK_SHELL;
		if (lastmatch->getshell.cmd) {
			action = TFP_SEND;
			*cmd = lastmatch->getshell.cmd;
			*cmdlen = strlen(lastmatch->getshell.cmd);
		} else {
			tfp->learn.shell_prompt = strdup(tfp->learn.login_console);
			tfp->state = TFP_STATE_CHECK_SHELL;
			action = _shell(tfp, cmd, cmdlen);
		}
	} else {
		action = TFP_WAIT;
	}

	return action;
}

static enum tfp_action
_shell(struct tfp *tfp, const char **cmd, int *cmdlen)
{
	enum tfp_action action;

	if ( (tfp->console->fpshell.shell && !_regcmp(tfp->learn.shell_prompt, tfp->console->fpshell.shell, tfp->console->fpshell.shell_cflags))
	     || (tfp->console->login.console && !_regcmp(tfp->learn.shell_prompt, tfp->console->login.console, tfp->console->login.console_cflags)) ) {
		tfp->state = TFP_STATE_SHELL;
		action = TFP_HAS_SHELL;
	} else {
		action = TFP_ERROR;
	}

	return action;
}

static int
_regcmp(char *str, char *regstr, int cflags)
{
	char errbuf[100];
	regex_t reg;
	int res;

        res = regcomp(&reg, regstr, cflags | REG_EXTENDED);
        if (res) {
		LOG_VERBOSE("_regcmp: regcomp FAILS on %s (%d)\n", regstr, res);
		return -1;
	}
        res = regexec(&reg, str, 0, NULL, 0);
        if( !res ){
                LOG_VERBOSE("_regcmp: MATCH : %s --- %s\n", str, regstr);
        }
        else if( res == REG_NOMATCH ){
                LOG_VERBOSE("_regcmp: NO MATCH : %s --- %s\n", str, regstr);
        }
        else{
                regerror(res, &reg, errbuf, sizeof(errbuf));
		LOG_VERBOSE("_regcmp: match FAILS %s --- %s: %s\n", str, regstr, errbuf);
        }
	regfree(&reg);

	return res;
}
