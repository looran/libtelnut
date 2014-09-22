#include <stdlib.h>

#include "b64otf.h"

static const unsigned char _base64_table[64] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

int _b64enc(unsigned char *, unsigned char *, int);

struct b64e *
b64e_new(char *srcfileplain, int buf64len)
{
	struct b64e *be;

	be = calloc(1, sizeof(struct b64e));
	be->buf64len = buf64len;
	be->filebuflen = (((buf64len-1) / 4) * 3); /* -1 because we add \0 at end of buf64 */
	be->filebuf = malloc(sizeof(unsigned char) * be->filebuflen);
	be->file = fopen(srcfileplain, "rb");
	if (!be->file)
		goto err;

	return be;
err:
	free(be);
	return NULL;
}

void
b64e_free(struct b64e *be)
{
	free(be->filebuf);
	fclose(be->file);
	free(be);
}

int
b64e_read(struct b64e *be, unsigned char *buf64)
{
	int len;

	len = fread(be->filebuf, 1, be->filebuflen, be->file);
	if (!len)
		return 0;
	return _b64enc(buf64, be->filebuf, len);
}

int
_b64enc(unsigned char *buf64, unsigned char *bufplain, int lenplain)
{
	unsigned char *bpos, *ppos, *pend;

	// printf("_b64enc: %.*s\n", lenplain, bufplain);
	bpos = buf64;
	ppos = bufplain;
	pend = bufplain + lenplain;
	while (pend - ppos >= 3) {
		*bpos++ = _base64_table[ppos[0] >> 2];
		*bpos++ = _base64_table[((ppos[0] & 0x03) << 4) | (ppos[1] >> 4)];
		*bpos++ = _base64_table[((ppos[1] & 0x0f) << 2) | (ppos[2] >> 6)];
		*bpos++ = _base64_table[ppos[2] & 0x3f];
		ppos += 3;
	}
	if (pend - ppos) {
		/* happends only when reaching eof */
		*bpos++ = _base64_table[ppos[0] >> 2];
		if (pend - ppos == 1) {
			*bpos++ = _base64_table[(ppos[0] & 0x03) << 4];
			*bpos++ = '=';
		} else {
			*bpos++ = _base64_table[((ppos[0] & 0x03) << 4) | (ppos[1] >> 4)];
			*bpos++ = _base64_table[(ppos[1] & 0x0f) << 2];
		}
		*bpos++ = '=';
	}
	*bpos = '\0';

	return bpos - buf64;
}
