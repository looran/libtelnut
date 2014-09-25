#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <getopt.h>

#include <event.h>
#include <telnut.h>

static void _action(struct telnut *);
static void _cb_connect(struct telnut *, void *);
static void _cb_disconnect(struct telnut *, enum telnut_error, void *);
static void _cb_exec(struct telnut *, enum telnut_error, char *, int, void *);
static void _cb_push(struct telnut *, enum telnut_error, void *);

char *_exec_cmd = NULL;
char *_copy_file = NULL;
char *_copy_file_remote = NULL;
int   _interactive = 0;
enum telnut_encoder _copy_encoder = PUSH_B64;
char               *_copy_decoder = NULL;

static void
usage(int doexit)
{
	printf("usage: telnut [-hv] [-p port]\n"
	       "              (-i | -e command | -c path_local [-C path_remote] [-r] [-d decoder_path])\n"
	       "              ip username [password]\n");
	if (doexit)
		exit(1);
}

static void
help(void)
{
	usage(0);
	printf("Command summary:\n\
	-c file    : Copy file\n\
	-C path    : Use remote path as destination, default is ./file\n\
	-d path    : Copy using this decoder on the remote\n\
	-e command : Execute command\n\
	-h         : This help text\n\
	-i         : Get an interactive shell\n\
	-p port    : Use different port than 23\n\
	-r         : Copy in raw mode (default is base64)\n\
	-v         : Be verbose\n\
In case -c, -e and -i are used together, the order will be copy, execute, interactive.\n");
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

	while ((option = getopt(argc, argv,"c:C:d:e:hip:rv")) != -1) {
		switch (option) {
		case 'c':
			_copy_file = optarg;
			break;
		case 'C':
			_copy_file_remote = optarg;
			break;
		case 'd':
			_copy_decoder = optarg;
			break;
		case 'e':
			_exec_cmd = optarg;
			break;
		case 'h':
			help();
		case 'i':
			_interactive = 1;
			break;
		case 'p':
			port = atoi(optarg);
			break;
		case 'r':
			_copy_encoder = PUSH_RAW;
			break;
		case 'v':
			verbose += 1;
			break;
		default: usage(1); 
		}
	}
	argc -= optind;
	argv += optind;
	if (!_copy_file && _copy_file_remote)
		usage(1);
	if (!_copy_file && !_exec_cmd && !_interactive)
		usage(1);
	if (argc < 2 || argc > 3)
		usage(1);
	if (!_copy_file && ((_copy_encoder == PUSH_RAW) && _copy_decoder))
		usage(1);
	if (_copy_file && !_copy_file_remote)
		_copy_file_remote = _copy_file;
	ip = argv[0];
	username = argv[1];
	if (argc == 3)
		password = argv[2];
	else
		password = getpass("Telnet password: ");

	evb = event_base_new();
	tel = telnut_new(evb, ip, port, username, password,
		TELNUT_NORECONNECT, verbose, _cb_connect, _cb_disconnect, NULL);
	event_base_dispatch(evb);

	telnut_free(tel);
	return 0;
}

static void
_action(struct telnut *tel)
{
	if (_copy_file) {
		telnut_push(tel, _copy_file, _copy_file_remote, _copy_encoder, _copy_decoder, _cb_push, NULL);
		_copy_file = NULL;
	} else if (_exec_cmd) {
		telnut_exec(tel, _exec_cmd, _cb_exec, NULL);
		_exec_cmd = NULL;
	} else if (_interactive) {
		telnut_interactive(tel);
		_interactive = 0;
	} else {
		event_base_loopbreak(tel->evb);
	}
}

static void
_cb_connect(struct telnut *tel, void *arg)
{
	printf("[*] Connected\n");
	_action(tel);
}

static void
_cb_disconnect(struct telnut *tel, enum telnut_error error, void *arg)
{
	if (error != TELNUT_NOERROR)
		telnut_err_print(error);
	event_base_loopbreak(tel->evb);
}

static void
_cb_push(struct telnut *tel, enum telnut_error error, void *arg)
{
	if (error != TELNUT_NOERROR)
		telnut_err_print(error);
	else
		printf("[*] File pushed successfuly !\n");
	_action(tel);
}

static void
_cb_exec(struct telnut *tel, enum telnut_error error, char *output, int output_len, void *arg)
{
	if (error != TELNUT_NOERROR)
		telnut_err_print(error);
	else
		printf("[*] %.*s\n", output_len, output);
	_action(tel);
}

