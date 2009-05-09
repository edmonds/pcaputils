#include <ctype.h>

#include "socket.h"
#include "scanfmt.h"

unsigned fmt_mac(char *s, const char mac[6]){
	unsigned i;
	unsigned len = 0;

	i = fmt_xlong(s, (unsigned long) (unsigned char) mac[0]); len += i; if(s) s += i;
	if(s) *s++ = ':'; ++len;
	i = fmt_xlong(s, (unsigned long) (unsigned char) mac[1]); len += i; if(s) s += i;
	if(s) *s++ = ':'; ++len;
	i = fmt_xlong(s, (unsigned long) (unsigned char) mac[2]); len += i; if(s) s += i;
	if(s) *s++ = ':'; ++len;
	i = fmt_xlong(s, (unsigned long) (unsigned char) mac[3]); len += i; if(s) s += i;
	if(s) *s++ = ':'; ++len;
	i = fmt_xlong(s, (unsigned long) (unsigned char) mac[4]); len += i; if(s) s += i;
	if(s) *s++ = ':'; ++len;
	i = fmt_xlong(s, (unsigned long) (unsigned char) mac[5]); len += i; if(s) s += i;
	*s = '\0';
	return len;
}

unsigned scan_mac(const char *s, char mac[6]){
	const char *tmp = s;
	unsigned len = 0;
	unsigned pos = 0;
	while(isxdigit(*tmp)){
		mac[pos] = ((char) scan_fromhex(*tmp)) << 4 | ((char) scan_fromhex(*(tmp + 1)));
		++pos;
		++len;
		tmp += 2;
		if(*tmp == ':' || *tmp == '-' || *tmp == '.')
			++tmp;
	}
	return len;
}

/* derived from public domain djbdns code */

unsigned fmt_ulong(char *s, unsigned long u)
{
  unsigned len;
  unsigned long q;
  len = 1; q = u;
  while (q > 9) { ++len; q /= 10; }
  if (s) {
    s += len;
    do { *--s = '0' + (u % 10); u /= 10; } while(u); /* handles u == 0 */
  }
  return len;
}

unsigned scan_ulong(const char *s, unsigned long *u)
{
  unsigned pos = 0;
  unsigned long result = 0;
  unsigned long c;
  while ((c = (unsigned long) (unsigned char) (s[pos] - '0')) < 10) {
    result = result * 10 + c;
    ++pos;
  }
  *u = result;
  return pos;
}

unsigned fmt_xlong(char *s, unsigned long u)
{
  unsigned len; unsigned long q; char c;
  len = 1; q = u;
  while (q > 15) { ++len; q /= 16; }
  if (s) {
    s += len;
    do { c = '0' + (u & 15); if (c > '0' + 9) c += 'a' - '0' - 10;
    *--s = c; u /= 16; } while(u);
  }
  return len;
}

unsigned scan_xlong(const char *src, unsigned long *dest)
{
  const char *tmp=src;
  unsigned long l=0;
  unsigned char c;
  while ((c = (char) scan_fromhex(*tmp))<16) {
    l=(l<<4)+c;
    ++tmp;
  }
  *dest=l;
  return tmp-src;
}

int scan_fromhex(unsigned char c)
{
  c-='0';
  if (c<=9) return c;
  c&=~0x20;
  c-='A'-'0';
  if (c<6) return c+10;
  return -1;
}

unsigned fmt_ip4(char *s,const char ip[4])
{
  unsigned i;
  unsigned len = 0;

  i = fmt_ulong(s,(unsigned long) (unsigned char) ip[0]); len += i; if (s) s += i;
  if (s) *s++ = '.'; ++len;
  i = fmt_ulong(s,(unsigned long) (unsigned char) ip[1]); len += i; if (s) s += i;
  if (s) *s++ = '.'; ++len;
  i = fmt_ulong(s,(unsigned long) (unsigned char) ip[2]); len += i; if (s) s += i;
  if (s) *s++ = '.'; ++len;
  i = fmt_ulong(s,(unsigned long) (unsigned char) ip[3]); len += i; if (s) s += i;
  *s = '\0';
  return len;
}

unsigned scan_ip4(const char *s, char ip[4])
{
  unsigned i;
  unsigned len;
  unsigned long u;

  len = 0;
  i = scan_ulong(s,&u); if (!i) return 0; ip[0] = u; s += i; len += i;
  if (*s != '.') return 0; ++s; ++len;
  i = scan_ulong(s,&u); if (!i) return 0; ip[1] = u; s += i; len += i;
  if (*s != '.') return 0; ++s; ++len;
  i = scan_ulong(s,&u); if (!i) return 0; ip[2] = u; s += i; len += i;
  if (*s != '.') return 0; ++s; ++len;
  i = scan_ulong(s,&u); if (!i) return 0; ip[3] = u; s += i; len += i;
  return len;
}

/* functions from libowfat */

/*
 Copyright (c) 2001 Felix von Leitner.
 All rights reserved.

 This program is free software; you can redistribute it and/or modify it
 under the terms of the GNU General Public License Version 2 as published
 by the Free Software Foundation.
*/

unsigned fmt_ip6(char *s, const char ip[16])
{
  unsigned long len,temp, k, pos0=0,len0=0, pos1=0, compr=0;

  for (k=0; k<16; k+=2) {
    if (ip[k]==0 && ip[k+1]==0) {
      if (!compr) {
        compr=1;
        pos1=k;
      }
      if (k==14) { k=16; goto last; }
    } else if (compr) {
    last:
      if ((temp=k-pos1) > len0) {
        len0=temp;
        pos0=pos1;
      }
      compr=0;
    }
  }

  for (len=0,k=0; k<16; k+=2) {
    if (k==12 && ip6_isv4mapped(ip)) {
      len += fmt_ip4(s,ip+12);
      break;
    }
    if (pos0==k && len0) {
      if (k==0) { ++len; if (s) *s++ = ':'; }
      ++len; if (s) *s++ = ':';
      k += len0-2;
      continue;
    }
    temp = ((unsigned long) (unsigned char) ip[k] << 8) +
            (unsigned long) (unsigned char) ip[k+1];
    temp = fmt_xlong(s,temp); len += temp; if (s) s += temp;
    if (k<14) { ++len; if (s) *s++ = ':'; }
  }
  *s = '\0';
  return len;
}

unsigned scan_ip6(const char *s, char ip[16])
{
  unsigned i;
  unsigned len=0;
  unsigned long u;

  char suffix[16];
  unsigned prefixlen=0;
  unsigned suffixlen=0;

  if ((i=scan_ip4(s,ip+12))) {
    for (len=0; len<12; ++len) ip[len]=V4mappedprefix[len];
    return i;
  }
  for (i=0; i<16; i++) ip[i]=0;
  for (;;) {
    if (*s == ':') {
      ++len;
      ++s;
      if (*s == ':') {	/* Found "::", skip to part 2 */
	++len;
	++s;
	break;
      }
    }
    i = scan_xlong(s,&u);
    if (!i) return 0;
    if (prefixlen==12 && s[i]=='.') {
      /* the last 4 bytes may be written as IPv4 address */
      i=scan_ip4(s,ip+12);
      if (i)
	return i+len;
      else
	return 0;
    }
    ip[prefixlen++] = (u >> 8);
    ip[prefixlen++] = (u & 255);
    s += i; len += i;
    if (prefixlen==16)
      return len;
  }

/* part 2, after "::" */
  for (;;) {
    if (*s == ':') {
      if (suffixlen==0)
	break;
      s++;
      len++;
    } else if (suffixlen)
      break;
    i = scan_xlong(s,&u);
    if (!i) {
      if (suffixlen)
	--len;
      break;
    }
    if (suffixlen+prefixlen<=12 && s[i]=='.') {
      int j=scan_ip4(s,suffix+suffixlen);
      if (j) {
	suffixlen+=4;
	len+=j;
	break;
      } else
	prefixlen=12-suffixlen;	/* make end-of-loop test true */
    }
    suffix[suffixlen++] = (u >> 8);
    suffix[suffixlen++] = (u & 255);
    s += i; len += i;
    if (prefixlen+suffixlen==16)
      break;
  }
  for (i=0; i<suffixlen; i++)
    ip[16-suffixlen+i] = suffix[i];
  return len;
}
