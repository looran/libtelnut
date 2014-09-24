/* b64otf - base64 on-the-fly encoder/decoder */
/* Copyright (c) 2014 Laurent Ghigonis <laurent@gouloum.fr>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <stdio.h>

//#define B64_DECODER_ONELINER 'a() { base$(( 2 ** 6 )) -d ; } ; b() { awk "BEGIN { F=\"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/\" ; while( getline < \"/dev/stdin\" ) { A = length( $0 ); for( B = 1; B <= A; ++B ) { C = index( F, substr( $0, B, 1 ) ); if( C-- ) { for( D = 0; D < 6; ++D ) { E = E*2+int( C/32 ); C = (C*2)%64; if( ++EDC == 8 ) { printf "%c", E; EDC = 0; E = 0; } } } } } }" ; } ; c() { A=0 ; B=0 ; C=0 ; while read -n1 D ; do E=$(printf %i \'"$D") ; if [ $E -eq 43 ] ; then F=62 ; elif [ $E -eq 47 ]; then F=63 ; elif [ $E -lt 48 ]; then continue ; elif [ $E -lt 58 ]; then F=$(( $E + 4 )) ; elif [ $E -eq 61 ]; then C=$(( $C + 1 )) ; F=0 ; elif [ $E -lt 65 ]; then continue ; elif [ $E -lt 91 ]; then F=$(( $E - 65 )) ; elif [ $E -lt 97 ]; then continue ; elif [ $E -lt 123 ]; then F=$(( $E - 71 )) ; else continue ; fi ; A=$(( $A + 1 )) ; B=$(( ($B << 6) | $F )) ; if [ $A -eq 4 ] ; then G=$(printf "%x" $(( ($B >> 16) & 0xFF ))) ; printf "\x$G" ; if [ $C -lt 2 ]; then G=$(printf "%x" $(( ($B >> 8) & 0xFF ))) ; printf "\x$G" ; fi ; if [ $C -eq 0 ]; then G=$(printf "%x" $(( $B & 0xFF ))) ; printf "\x$G" ; fi ; A=0 ; B=0 ; C=0 ; fi ; done ; } ; [ X"$(echo -n "YQ==" |base$(( 2 ** 6 )) -d 2>/dev/null)" == X"a" ] && a && exit ; [ X"$(echo -n "a b" |awk "{print \$1}" 2>/dev/null)" == X"a" ] && b && exit ; c ;'

// #define B64_DECODER_ONELINER 'a() { base$(( 2 ** 6 )) -d ; } ; b() { awk 'BEGIN { F="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/" ; while( getline < "/dev/stdin" ) { A = length( $0 ); for( B = 1; B <= A; ++B ) { C = index( F, substr( $0, B, 1 ) ); if( C-- ) { for( D = 0; D < 6; ++D ) { E = E*2+int( C/32 ); C = (C*2)%64; if( ++EDC == 8 ) { printf "%c", E; EDC = 0; E = 0; } } } } } }' ; } ; c() { A=0 ; B=0 ; C=0 ; while read -n1 D ; do E=$(printf %i \'"$D") ; if [ $E -eq 43 ] ; then F=62 ; elif [ $E -eq 47 ]; then F=63 ; elif [ $E -lt 48 ]; then continue ; elif [ $E -lt 58 ]; then F=$(( $E + 4 )) ; elif [ $E -eq 61 ]; then C=$(( $C + 1 )) ; F=0 ; elif [ $E -lt 65 ]; then continue ; elif [ $E -lt 91 ]; then F=$(( $E - 65 )) ; elif [ $E -lt 97 ]; then continue ; elif [ $E -lt 123 ]; then F=$(( $E - 71 )) ; else continue ; fi ; A=$(( $A + 1 )) ; B=$(( ($B << 6) | $F )) ; if [ $A -eq 4 ] ; then G=$(printf "%x" $(( ($B >> 16) & 0xFF ))) ; printf "\x$G" ; if [ $C -lt 2 ]; then G=$(printf "%x" $(( ($B >> 8) & 0xFF ))) ; printf "\x$G" ; fi ; if [ $C -eq 0 ]; then G=$(printf "%x" $(( $B & 0xFF ))) ; printf "\x$G" ; fi ; A=0 ; B=0 ; C=0 ; fi ; done ; } ; [ X"$(echo -n "YQ==" |xbase$(( 2 ** 6 )) -d 2>/dev/null)" == X"a" ] && a && exit ; [ X"$(echo -n "a b" |awk "{print \$1}" 2>/dev/null)" == X"a" ] && b && exit ; c ;'

#define B64_DECODER_ONELINER "a() { base$(( 2 ** 6 )) -d ; } ; b() { awk 'BEGIN { F=\"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/\" ; while( getline < \"/dev/stdin\" ) { A = length( $0 ); for( B = 1; B <= A; ++B ) { C = index( F, substr( $0, B, 1 ) ); if( C-- ) { for( D = 0; D < 6; ++D ) { E = E*2+int( C/32 ); C = (C*2)%64; if( ++EDC == 8 ) { printf \"%c\", E; EDC = 0; E = 0; } } } } } }' ; } ; c() { A=0 ; B=0 ; C=0 ; while read -n1 D ; do E=$(printf %i \\\'\"$D\") ; if [ $E -eq 43 ] ; then F=62 ; elif [ $E -eq 47 ]; then F=63 ; elif [ $E -lt 48 ]; then continue ; elif [ $E -lt 58 ]; then F=$(( $E + 4 )) ; elif [ $E -eq 61 ]; then C=$(( $C + 1 )) ; F=0 ; elif [ $E -lt 65 ]; then continue ; elif [ $E -lt 91 ]; then F=$(( $E - 65 )) ; elif [ $E -lt 97 ]; then continue ; elif [ $E -lt 123 ]; then F=$(( $E - 71 )) ; else continue ; fi ; A=$(( $A + 1 )) ; B=$(( ($B << 6) | $F )) ; if [ $A -eq 4 ] ; then G=$(printf \"%x\" $(( ($B >> 16) & 0xFF ))) ; printf \"\\x$G\" ; if [ $C -lt 2 ]; then G=$(printf \"%x\" $(( ($B >> 8) & 0xFF ))) ; printf \"\\x$G\" ; fi ; if [ $C -eq 0 ]; then G=$(printf \"%x\" $(( $B & 0xFF ))) ; printf \"\\x$G\" ; fi ; A=0 ; B=0 ; C=0 ; fi ; done ; } ; [ X\"$(echo -n 'YQ==' |xbase$(( 2 ** 6 )) -d 2>/dev/null)\" == X\"a\" ] && a && exit ; [ X\"$(echo -n 'a b' |awk '{print $1}' 2>/dev/null)\" == X\"a\" ] && b && exit ; c ;"

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
