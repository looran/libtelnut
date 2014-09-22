#include <stdio.h>

struct b64e {
	int   buf64len;
	FILE *file;
	unsigned char *filebuf;
	int   filebuflen;
};

/*
struct b64d {
	FILE *file;
};
*/

struct b64e *b64e_new(char *srcfileplain, int buf64len);
void         b64e_free(struct b64e *be);
int          b64e_read(struct b64e *be, unsigned char *buf64);

/*
struct b64d *b64d_new(char *dstfileplain);
void         b64d_free(struct b64d *bd);
int          b64d_write(struct b64d *bd, char *buf64, int buflen);
*/
