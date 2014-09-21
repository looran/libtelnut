libtelnut - telnet async client library
=======================================

### Telnut binary

```bash
$ telnut
usage: telnut [-v] [-p port] (-i | -e command | -c file_path [-C path_remote]) ip username [password]

$ telnut -e "uname -ap" 192.168.1.1 admin 1234
Connected !
Executing uname -ap
uname -ap
Linux ADSL2PlusRouter 2.6.19 #36 Fri Mar 30 14:43:39 CST 2012 mips unknown

$ telnut -c myfile 192.168.1.1 admin 1234
Connected !
Pushing myfile
File pushed successfuly !
```

### libtelnut Example: execute a command via Telnet

```
#include <stdio.h>
#include <event.h>
#include <telnut.h>

static void
_cb_exec(struct telnut *tel, enum telnut_error error, char *cmd, char *output, int output_len, void *arg)
{
	if (error != TELNUT_NOERROR)
		telnut_err_print(error);
	else
		printf("%.*s\n", output_len, output);
	event_base_loopbreak(tel->evb);
}

static void
_cb_connect(struct telnut *tel, void *arg)
{
	printf("Connected !\n");
	telnut_exec(tel, "ps", _cb_exec, NULL);
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

	tel = telnut_new(evb, "127.0.0.1", 23, "admin", "1234",
		TELNUT_NORECONNECT, TELNUT_NOVERBOSE, _cb_connect, _cb_disconnect, NULL);
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

Other example, push a file to the remote host: [examples/push.c](examples/push.c)

### Install

library:

```bash
make && sudo make install
```

binary:

```bash
make -C bin/ && sudo make -C bin/ install
```

### Dependencies

* [libtelnet](https://github.com/seanmiddleditch/libtelnet)
* libevent

### API

See [telnut.h](telnut.h)

### Ressources

On telnet
* http://www.ics.uci.edu/~rohit/IEEE-L7-v2.html

Telnet clients automated login:
* https://github.com/robotframework/robotframework/blob/master/src/robot/libraries/Telnet.py
* http://robotframework.googlecode.com/hg/doc/libraries/Telnet.html
* http://packetstorm.igor.onlinedirect.bg/UNIX/scanners/TelnetScanner.cs.txt

Telnet password bruteforce:
* http://www.hsc.fr/ressources/outils/patator/download/patator_v0.6.py
* https://github.com/vanhauser-thc/thc-hydra/blob/master/hydra-telnet.c
* https://svn.nmap.org/nmap/scripts/telnet-brute.nse
* https://code.google.com/p/telforce/source/browse/trunk/telforce.py?r=2

