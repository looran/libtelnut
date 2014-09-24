#include <string.h>

#include "b64otf.h"

// #define DATA_B64 "RW4gdW4gbHVnYXIgZGUgbGEgTWFuY2hhLCBkZSBjdXlvIG5vbWJyZSBubyBxdWllcm8gYWNvcmRhcm1lLCBubyBoYSBtdWNobwp0aWVtcG8gcXVlIHZpdsOtYSB1biBoaWRhbGdvIGRlIGxvcyBkZSBsYW56YSBlbiBhc3RpbGxlcm8sIGFkYXJnYSBhbnRpZ3VhLApyb2PDrW4gZmxhY28geSBnYWxnbyBjb3JyZWRvci4gVW5hIG9sbGEgZGUgYWxnbyBtw6FzIHZhY2EgcXVlIGNhcm5lcm8sIHNhbHBpY8OzbgpsYXMgbcOhcyBub2NoZXMsIGR1ZWxvcyB5IHF1ZWJyYW50b3MgbG9zIHPDoWJhZG9zLCBsZW50ZWphcyBsb3Mgdmllcm5lcywgYWxnw7puCnBhbG9taW5vIGRlIGHDsWFkaWR1cmEgbG9zIGRvbWluZ29zLCBjb25zdW3DrWFuIGxhcyB0cmVzIHBhcnRlcyBkZSBzdSBoYWNpZW5kYS4KRWwgcmVzdG8gZGVsbGEgY29uY2x1w61hbiBzYXlvIGRlIHZlbGFydGUsIGNhbHphcyBkZSB2ZWxsdWRvIHBhcmEgbGFzIGZpZXN0YXMKY29uIHN1cyBwYW50dWZsb3MgZGUgbG8gbWlzbW8sIGxvcyBkw61hcyBkZSBlbnRyZSBzZW1hbmEgc2UgaG9ucmFiYSBjb24gc3UKdmVsbG9yaSBkZSBsbyBtw6FzIGZpbm8uIFRlbsOtYSBlbiBzdSBjYXNhIHVuYSBhbWEgcXVlIHBhc2FiYSBkZSBsb3MgY3VhcmVudGEsIHkKdW5hIHNvYnJpbmEgcXVlIG5vIGxsZWdhYmEgYSBsb3MgdmVpbnRlLCB5IHVuIG1vem8gZGUgY2FtcG8geSBwbGF6YSwgcXVlIGFzw60KZW5zaWxsYWJhIGVsIHJvY8OtbiBjb21vIHRvbWFiYSBsYSBwb2RhZGVyYS4gRnJpc2FiYSBsYSBlZGFkIGRlIG51ZXN0cm8gaGlkYWxnbwpjb24gbG9zIGNpbmN1ZW50YSBhw7FvcywgZXJhIGRlIGNvbXBsZXhpw7NuIHJlY2lhLCBzZWNvIGRlIGNhcm5lcywgZW5qdXRvIGRlCnJvc3RybzsgZ3JhbiBtYWRydWdhZG9yIHkgYW1pZ28gZGUgbGEgY2F6YS4gUXVpZXJlbiBkZWNpciBxdWUgdGVuw61hIGVsCnNvYnJlbm9tYnJlIGRlIFF1aWphZGEgbyBRdWVzYWRhIChxdWUgZW4gZXN0byBoYXkgYWxndW5hIGRpZmVyZW5jaWEgZW4gbG9zCmF1dG9yZXMgcXVlIGRlc3RlIGNhc28gZXNjcmliZW4pLCBhdW5xdWUgcG9yIGNvbmpldHVyYXMgdmVyb3PDrW1pbGVzIHNlIGRlamEKZW50ZW5kZXIgcXVlIHNlIGxsYW1hIFF1aWphbmE7IHBlcm8gZXN0byBpbXBvcnRhIHBvY28gYSBudWVzdHJvIGN1ZW50bzsgYmFzdGEKcXVlIGVuIGxhIG5hcnJhY2nDs24gZMOpbCBubyBzZSBzYWxnYSB1biBwdW50byBkZSBsYSB2ZXJkYWQuCgoAAQIDBAUGBwgJEBESExQVFhcYGSAhIiMkJSYnKCkwMTIzNDUKCuDw/woKCg=="
#define DATA_B64 "RW4gdW4gbHVnYXIgZGUgbGEgTWFuY2hhLCBkZSBjdXlvIG5vbWJyZSBubyBxdWllcm8gYWNv\n"\
"cmRhcm1lLCBubyBoYSBtdWNobwp0aWVtcG8gcXVlIHZpdsOtYSB1biBoaWRhbGdvIGRlIGxv\n"\
"cyBkZSBsYW56YSBlbiBhc3RpbGxlcm8sIGFkYXJnYSBhbnRpZ3VhLApyb2PDrW4gZmxhY28g\n"\
"eSBnYWxnbyBjb3JyZWRvci4gVW5hIG9sbGEgZGUgYWxnbyBtw6FzIHZhY2EgcXVlIGNhcm5l\n"\
"cm8sIHNhbHBpY8OzbgpsYXMgbcOhcyBub2NoZXMsIGR1ZWxvcyB5IHF1ZWJyYW50b3MgbG9z\n"\
"IHPDoWJhZG9zLCBsZW50ZWphcyBsb3Mgdmllcm5lcywgYWxnw7puCnBhbG9taW5vIGRlIGHD\n"\
"sWFkaWR1cmEgbG9zIGRvbWluZ29zLCBjb25zdW3DrWFuIGxhcyB0cmVzIHBhcnRlcyBkZSBz\n"\
"dSBoYWNpZW5kYS4KRWwgcmVzdG8gZGVsbGEgY29uY2x1w61hbiBzYXlvIGRlIHZlbGFydGUs\n"\
"IGNhbHphcyBkZSB2ZWxsdWRvIHBhcmEgbGFzIGZpZXN0YXMKY29uIHN1cyBwYW50dWZsb3Mg\n"\
"ZGUgbG8gbWlzbW8sIGxvcyBkw61hcyBkZSBlbnRyZSBzZW1hbmEgc2UgaG9ucmFiYSBjb24g\n"\
"c3UKdmVsbG9yaSBkZSBsbyBtw6FzIGZpbm8uIFRlbsOtYSBlbiBzdSBjYXNhIHVuYSBhbWEg\n"\
"cXVlIHBhc2FiYSBkZSBsb3MgY3VhcmVudGEsIHkKdW5hIHNvYnJpbmEgcXVlIG5vIGxsZWdh\n"\
"YmEgYSBsb3MgdmVpbnRlLCB5IHVuIG1vem8gZGUgY2FtcG8geSBwbGF6YSwgcXVlIGFzw60K\n"\
"ZW5zaWxsYWJhIGVsIHJvY8OtbiBjb21vIHRvbWFiYSBsYSBwb2RhZGVyYS4gRnJpc2FiYSBs\n"\
"YSBlZGFkIGRlIG51ZXN0cm8gaGlkYWxnbwpjb24gbG9zIGNpbmN1ZW50YSBhw7FvcywgZXJh\n"\
"IGRlIGNvbXBsZXhpw7NuIHJlY2lhLCBzZWNvIGRlIGNhcm5lcywgZW5qdXRvIGRlCnJvc3Ry\n"\
"bzsgZ3JhbiBtYWRydWdhZG9yIHkgYW1pZ28gZGUgbGEgY2F6YS4gUXVpZXJlbiBkZWNpciBx\n"\
"dWUgdGVuw61hIGVsCnNvYnJlbm9tYnJlIGRlIFF1aWphZGEgbyBRdWVzYWRhIChxdWUgZW4g\n"\
"ZXN0byBoYXkgYWxndW5hIGRpZmVyZW5jaWEgZW4gbG9zCmF1dG9yZXMgcXVlIGRlc3RlIGNh\n"\
"c28gZXNjcmliZW4pLCBhdW5xdWUgcG9yIGNvbmpldHVyYXMgdmVyb3PDrW1pbGVzIHNlIGRl\n"\
"amEKZW50ZW5kZXIgcXVlIHNlIGxsYW1hIFF1aWphbmE7IHBlcm8gZXN0byBpbXBvcnRhIHBv\n"\
"Y28gYSBudWVzdHJvIGN1ZW50bzsgYmFzdGEKcXVlIGVuIGxhIG5hcnJhY2nDs24gZMOpbCBu\n"\
"byBzZSBzYWxnYSB1biBwdW50byBkZSBsYSB2ZXJkYWQuCgoAAQIDBAUGBwgJEBESExQVFhcY\n"\
"GSAhIiMkJSYnKCkwMTIzNDUKCuDw/woKCg==\n"

int _test_encode_buf100(void);
int _test_encode_buf1024(void);
int _test_encode(unsigned char *, int);

int
main(void)
{
	int ret;

	printf("==============================================\ntest encode buf100:\n");
	if ((ret = _test_encode_buf100()) != 0)
		return ret;
	printf("OK\n");

	printf("==============================================\ntest encode buf1024:\n");
	if ((ret = _test_encode_buf1024()) != 0)
		return ret;
	printf("OK\n");

	printf("ALL TESTS OK\n");
	return 0;
}

int
_test_encode_buf100(void)
{
	unsigned char buf64[100];

	return _test_encode(buf64, sizeof(buf64));
}

int
_test_encode_buf1024(void)
{
	unsigned char buf64[1024];

	return _test_encode(buf64, sizeof(buf64));
}

int
_test_encode(unsigned char *buf64, int buf64len)
{
	unsigned char expected[] = DATA_B64;
	struct b64e *be;
	int redok, r;

	be = b64e_new("./data_plain.txt", buf64len);
	if (!be) {
		printf("ERROR: cannot find data file\n");
		return -1;
	}
	printf("be->filebuflen = %d\n", be->filebuflen);
	redok = 0;
	while ((r = b64e_read(be, buf64)) > 0) {
		if (strncmp((const char *)buf64, (const char *)expected + redok, r)) {
			printf("ERROR:\nredok   : %d\nreadlen  : %d\nbuf64   : %.*s\nexpected : %.*s\n",
				redok, r, r, buf64, r, expected + redok);
			return -1;
		}
		redok += r;
	};
	return 0;
}
