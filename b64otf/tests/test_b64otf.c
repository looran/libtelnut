#include <string.h>

#include "b64otf.h"

#define DATA_B64 "RW4gdW4gbHVnYXIgZGUgbGEgTWFuY2hhLCBkZSBjdXlvIG5vbWJyZSBubyBxdWllcm8gYWNvcmRhcm1lLCBubyBoYSBtdWNobwp0aWVtcG8gcXVlIHZpdsOtYSB1biBoaWRhbGdvIGRlIGxvcyBkZSBsYW56YSBlbiBhc3RpbGxlcm8sIGFkYXJnYSBhbnRpZ3VhLApyb2PDrW4gZmxhY28geSBnYWxnbyBjb3JyZWRvci4gVW5hIG9sbGEgZGUgYWxnbyBtw6FzIHZhY2EgcXVlIGNhcm5lcm8sIHNhbHBpY8OzbgpsYXMgbcOhcyBub2NoZXMsIGR1ZWxvcyB5IHF1ZWJyYW50b3MgbG9zIHPDoWJhZG9zLCBsZW50ZWphcyBsb3Mgdmllcm5lcywgYWxnw7puCnBhbG9taW5vIGRlIGHDsWFkaWR1cmEgbG9zIGRvbWluZ29zLCBjb25zdW3DrWFuIGxhcyB0cmVzIHBhcnRlcyBkZSBzdSBoYWNpZW5kYS4KRWwgcmVzdG8gZGVsbGEgY29uY2x1w61hbiBzYXlvIGRlIHZlbGFydGUsIGNhbHphcyBkZSB2ZWxsdWRvIHBhcmEgbGFzIGZpZXN0YXMKY29uIHN1cyBwYW50dWZsb3MgZGUgbG8gbWlzbW8sIGxvcyBkw61hcyBkZSBlbnRyZSBzZW1hbmEgc2UgaG9ucmFiYSBjb24gc3UKdmVsbG9yaSBkZSBsbyBtw6FzIGZpbm8uIFRlbsOtYSBlbiBzdSBjYXNhIHVuYSBhbWEgcXVlIHBhc2FiYSBkZSBsb3MgY3VhcmVudGEsIHkKdW5hIHNvYnJpbmEgcXVlIG5vIGxsZWdhYmEgYSBsb3MgdmVpbnRlLCB5IHVuIG1vem8gZGUgY2FtcG8geSBwbGF6YSwgcXVlIGFzw60KZW5zaWxsYWJhIGVsIHJvY8OtbiBjb21vIHRvbWFiYSBsYSBwb2RhZGVyYS4gRnJpc2FiYSBsYSBlZGFkIGRlIG51ZXN0cm8gaGlkYWxnbwpjb24gbG9zIGNpbmN1ZW50YSBhw7FvcywgZXJhIGRlIGNvbXBsZXhpw7NuIHJlY2lhLCBzZWNvIGRlIGNhcm5lcywgZW5qdXRvIGRlCnJvc3RybzsgZ3JhbiBtYWRydWdhZG9yIHkgYW1pZ28gZGUgbGEgY2F6YS4gUXVpZXJlbiBkZWNpciBxdWUgdGVuw61hIGVsCnNvYnJlbm9tYnJlIGRlIFF1aWphZGEgbyBRdWVzYWRhIChxdWUgZW4gZXN0byBoYXkgYWxndW5hIGRpZmVyZW5jaWEgZW4gbG9zCmF1dG9yZXMgcXVlIGRlc3RlIGNhc28gZXNjcmliZW4pLCBhdW5xdWUgcG9yIGNvbmpldHVyYXMgdmVyb3PDrW1pbGVzIHNlIGRlamEKZW50ZW5kZXIgcXVlIHNlIGxsYW1hIFF1aWphbmE7IHBlcm8gZXN0byBpbXBvcnRhIHBvY28gYSBudWVzdHJvIGN1ZW50bzsgYmFzdGEKcXVlIGVuIGxhIG5hcnJhY2nDs24gZMOpbCBubyBzZSBzYWxnYSB1biBwdW50byBkZSBsYSB2ZXJkYWQuCgoAAQIDBAUGBwgJEBESExQVFhcYGSAhIiMkJSYnKCkwMTIzNDUKCuDw/woKCg=="

int _test_encode(void);

int
main(void)
{
	int ret;

	printf("test encode: ");
	if ((ret = _test_encode()) != 0)
		return ret;
	printf("OK\n");
	return 0;
}

int
_test_encode(void)
{
	unsigned char expected[] = DATA_B64;
	unsigned char buf64[100];
	struct b64e *be;
	int redok, r;

	be = b64e_new("./data_plain.txt", sizeof(buf64));
	if (!be) {
		printf("ERROR: cannot find data file\n");
		return -1;
	}
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
