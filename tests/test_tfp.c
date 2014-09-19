#include <string.h>

#include "telnut.h"

#define ERR(msg, ...) do { printf("\nERROR: " msg "\n", ##__VA_ARGS__); printf("Testcase results:\nstate  : %d\naction : %d\ncmd    : %s\ncmdlen : %d\n", tfp->state, action, cmd, cmdlen);_print_tc(tc); return -1; } while (0);
#define ASSERT(test) do { if (!test){ ERR("\""#test"\" Fails"); } } while (0);

struct shell_tc {
	char *name;
	struct {
		char *login;
		char *console;
	} expected_match;
	struct {
		char           *prompt;
		enum tfp_action expected_action;
		char           *expected_cmd;
	} user;
	struct {
		char           *prompt;
		enum tfp_action expected_action;
		char           *expected_cmd;
	} pass;
	struct {
		char           *prompt;
		enum tfp_action expected_action;
		char           *expected_cmd;
	} console;
	struct {
		char           *prompt;
		enum tfp_action expected_action;
		char           *expected_cmd;
	} shell;
};

struct shell_tc _tcs[] = {
	{ "test direct shell",
	  { "default user/pass", "direct shell" },
	  { "\nlogin: ", TFP_SEND, "root" },
	  { "\npassword: ", TFP_SEND, "1234" },
	  { "\n #", TFP_HAS_SHELL, NULL },
	  { NULL, TFP_HAS_SHELL, NULL } },
	{ "test immediate password",
	  { "immediate password", "direct shell" },
	  { NULL, TFP_SEND, NULL },
	  { "Password: ", TFP_SEND, "1234" },
	  { "# ", TFP_HAS_SHELL, NULL },
	  { NULL, TFP_HAS_SHELL, NULL } },
	{ "test OS7030",
	  { "default user/pass", "OS7030" },
	  { "\nLinux 2.6.13-rtl (OS7030) (0)\n\n[OS7030]login:\n", TFP_SEND, "root" },
	  { "Password:", TFP_SEND, "1234" },
	  { "1. bash shell\n2. AFT\n3. Voice Mail CLI\n4. MGI CLI\n5. SP CLI\n6. Quit\n\nPlease select a menu number :", TFP_SEND, "1" },
	  { "bash-3.00# ", TFP_HAS_SHELL, NULL } },
};
#define TESTS_COUNT (int)(sizeof(_tcs) / sizeof(_tcs[0]))

void _print_tc(struct shell_tc *);

int
main(void)
{
	struct shell_tc *tc;
	struct tfp *tfp;
	int tc_num, res, cmdlen;
	const char *cmd;
	enum tfp_action action;

	for (tc_num=0; tc_num<TESTS_COUNT; tc_num++) {
		tc = &_tcs[tc_num];
		printf("==========================================================================\nTC %d/%d : %s\n", tc_num, TESTS_COUNT-1, tc->name);
		tfp = tfp_new("root", "1234");

		if (tc->user.prompt) {
			printf("behavioral test: login\n");
			action = tfp_getaction(tfp, tc->user.prompt, strlen(tc->user.prompt), &cmd, &cmdlen);
			ASSERT(tc->user.expected_action == action);
			if (tc->user.expected_cmd)
				ASSERT(!strcmp(tc->user.expected_cmd, cmd));
		}

		if (tc->pass.prompt) {
			printf("behavioral test: password\n");
			action = tfp_getaction(tfp, tc->pass.prompt, strlen(tc->pass.prompt), &cmd, &cmdlen);
			ASSERT(tc->pass.expected_action == action);
			if (tc->pass.expected_cmd)
				ASSERT(!strcmp(tc->pass.expected_cmd, cmd));
		}

		printf("internal test: matched login fingerprint\n");
		ASSERT(tfp->login);
		ASSERT(!strcmp(tc->expected_match.login, tfp->login->name));

		if (tc->console.prompt) {
			printf("behavioral test: console\n");
			action = tfp_getaction(tfp, tc->console.prompt, strlen(tc->console.prompt), &cmd, &cmdlen);
			ASSERT(tc->console.expected_action == action);
			if (tc->console.expected_cmd)
				ASSERT(!strcmp(tc->console.expected_cmd, cmd));
		}

		if (tc->shell.prompt) {
			printf("behavioral test: shell\n");
			action = tfp_getaction(tfp, tc->shell.prompt, strlen(tc->shell.prompt), &cmd, &cmdlen);
			ASSERT(tc->shell.expected_action == action);
			if (tc->shell.expected_cmd)
				ASSERT(!strcmp(tc->shell.expected_cmd, cmd));
		}

		printf("internal test: matched console/shell fingerprint\n");
		ASSERT(tfp->console);
		ASSERT(!strcmp(tc->expected_match.console, tfp->console->name));

		printf("internal test: final state\n");
		ASSERT(tfp->console == TFP_STATE_SHELL);

		tfp_free(tfp);
		printf("OK\n");
	}
	printf("\nALL TESTS OK\n");
	return 0;
}

void
_print_tc(struct shell_tc *tc)
{
	printf("Testcase: %s\n"
		"--user.prompt             : %s\n"
		"--user.expected_action    : %d\n"
		"--user.excected_cmd       : %s\n"
		"--pass.prompt             : %s\n"
		"--pass.expected_action    : %d\n"
		"--pass.excected_cmd       : %s\n"
		"--console.prompt          : %s\n"
		"--console.expected_action : %d\n"
		"--console.excected_cmd    : %s\n"
		"--shell.prompt            : %s\n"
		"--shell.expected_action   : %d\n"
		"--shell.excected_cmd      : %s\n",
		tc->name,
		tc->user.prompt, tc->user.expected_action, tc->user.expected_cmd,
		tc->pass.prompt, tc->pass.expected_action, tc->pass.expected_cmd,
		tc->console.prompt, tc->console.expected_action, tc->console.expected_cmd,
		tc->shell.prompt, tc->shell.expected_action, tc->shell.expected_cmd);
}

