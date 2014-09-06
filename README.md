libtelnut - telnet utility library
==================================

### Example: execute a command via Telnet

```
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

