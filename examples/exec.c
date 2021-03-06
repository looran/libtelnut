#include <stdio.h>
#include <event.h>
#include <telnut.h>

static void
_cb_exec(struct telnut *tel, enum telnut_error error, char *output, int output_len, void *arg)
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
