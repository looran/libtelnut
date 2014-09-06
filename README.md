libtelnut - telnet async client library
=======================================

### Example: execute a command via Telnet

```
#include <stdio.h>
#include <event.h>
#include <telnut.h>

static void
_cb_exec(struct telnut *tel, enum telnut_error error, char *cmd, char *output, int output_len, void *arg)
{
	if (error != TELNUT_NOERROR)
		telnut_err_print(error);
	else {
		printf("> %s\n", cmd);
		printf("%.*s\n", output_len, output);
	}
	event_base_loopbreak(tel->evb);
}

static void
_cb_connect(struct telnut *tel, void *arg)
{
	printf("Connected !\n");
	telnut_exec(tel, "uname -ap", _cb_exec, NULL);
}

static void
_cb_disconnect(struct telnut *tel, enum telnut_error error, void *arg)
{
	if (error != TELNUT_NOERROR)
		telnut_err_print(error);
	event_base_loopbreak(tel->evb);
}

int
main(void)
{
	struct event_base *evb;
	struct telnut_auth *auth;
	struct telnut *tel;

	evb = event_base_new();

	tel = telnut_new(evb, "127.0.0.1", 23, "user", "password", TELNUT_NORECONNECT, TELNUT_NOVERBOSE,
	 	_cb_connect, _cb_disconnect, NULL);
	event_base_dispatch(evb);

	telnut_free(tel);
	return 0;
}
```

To test this:
```bash
make -C examples/ && sudo ./examples/exec
```

Source code of this example: [examples/exec.c](examples/exec.c)

Other example, push a file to the remote host: XXX

### Install

```bash
make && sudo make install
```

### Dependencies

* libtelnet
* libevent
* libbsd (only at compile time for queue.h)

### API

See [telnut.h](telnut.h)

### Ressources

Telnet clients automated login:
* https://github.com/robotframework/robotframework/blob/master/src/robot/libraries/Telnet.py
* http://robotframework.googlecode.com/hg/doc/libraries/Telnet.html

Telnet password bruteforce:
* http://www.hsc.fr/ressources/outils/patator/download/patator_v0.6.py
* https://github.com/vanhauser-thc/thc-hydra/blob/master/hydra-telnet.c
* https://svn.nmap.org/nmap/scripts/telnet-brute.nse
* https://code.google.com/p/telforce/source/browse/trunk/telforce.py?r=2

