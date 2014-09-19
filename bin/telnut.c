#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <getopt.h>

#include <event.h>
#include <telnut.h>

static void _cb_connect(struct telnut *, void *);
static void _cb_disconnect(struct telnut *, enum telnut_error, void *);
static void _cb_exec(struct telnut *, enum telnut_error, char *, char *, int, void *);

char *_exec_cmd = NULL;
char *_copy_file = NULL;

static void
usage(int doexit)
{
	printf("usage: telnut [-v] [-p port] (-c file | -e command) ip username [password]\n");
	if (doexit)
		exit(1);
}

static void
help(void)
{
	usage(0);
	printf("Command summary:\n\
	-c file    : Copy a file\n\
	-e command : Execute command\n\
	-h         : This help text\n\
	-p port    : Use different port than 23\n\
	-v         : Be verbose\n");
	exit(1);
}

int
main(int argc, char *argv[])
{
	struct event_base *evb;
	struct telnut_auth *auth;
	struct telnut *tel;
	int option;
	int verbose = 0;
	int port = 23;
	char *ip = NULL;
	char *username = NULL;
	char *password = NULL;
	char buf[100];

	while ((option = getopt(argc, argv,"c:e:hp:v")) != -1) {
		switch (option) {
		case 'c':
			_copy_file = optarg;
			break;
		case 'e':
			_exec_cmd = optarg;
			break;
		case 'h':
			help();
		case 'p':
			port = atoi(optarg);
			break;
		case 'v':
			verbose += 1;
			break;
		default: usage(1); 
		}
	}
	argc -= optind;
	argv += optind;
	if (_exec_cmd && _copy_file)
		usage(1);
	if (argc < 2 || argc > 3)
		usage(1);
	ip = argv[0];
	username = argv[1];
	if (argc == 3) {
		password = argv[2];
	} else {
		printf("Telnet password: ");
		fgets(buf, sizeof(buf), stdin);
		password = buf;
	}

	evb = event_base_new();

	tel = telnut_new(evb, ip, port, username, password,
		TELNUT_NORECONNECT, verbose, _cb_connect, _cb_disconnect, NULL);
	event_base_dispatch(evb);

	telnut_free(tel);
	return 0;
}

static void
_cb_connect(struct telnut *tel, void *arg)
{
	printf("Connected !\n");
	if (_exec_cmd)
		telnut_exec(tel, _exec_cmd, _cb_exec, NULL);
	if (_copy_file)
		printf("ERROR: Copy file not implemented yet !\n");
}

static void
_cb_disconnect(struct telnut *tel, enum telnut_error error, void *arg)
{
	if (error != TELNUT_NOERROR)
		telnut_err_print(error);
	event_base_loopbreak(tel->evb);
}

static void
_cb_exec(struct telnut *tel, enum telnut_error error, char *cmd, char *output, int output_len, void *arg)
{
	if (error != TELNUT_NOERROR)
		telnut_err_print(error);
	else
		printf("%.*s\n", output_len, output);
	event_base_loopbreak(tel->evb);
}

