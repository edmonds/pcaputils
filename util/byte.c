#include "byte.h"

/* derived from public domain djbdns code */

unsigned int byte_chr(const char* s,unsigned int n,int c)
{
  char ch;
  const char *t;

  ch = (char) c;
  t = s;
  for (;;) {
    if (!n) break; if (*t == ch) break; ++t; --n;
    if (!n) break; if (*t == ch) break; ++t; --n;
    if (!n) break; if (*t == ch) break; ++t; --n;
    if (!n) break; if (*t == ch) break; ++t; --n;
  }
  return t - s;
}

void byte_copy(void* To, unsigned int n, const void* From)
{
  char *to=To;
  const char *from=From;
  for (;;) {
    if (!n) return; *to++ = *from++; --n;
    if (!n) return; *to++ = *from++; --n;
    if (!n) return; *to++ = *from++; --n;
    if (!n) return; *to++ = *from++; --n;
  }
}

void byte_copyr(void* To,unsigned int n, const void* From)
{
  char *to=(char*)To+n;
  const char *from=(char*)From+n;
  for (;;) {
    if (!n) return; *--to = *--from; --n;
    if (!n) return; *--to = *--from; --n;
    if (!n) return; *--to = *--from; --n;
    if (!n) return; *--to = *--from; --n;
  }
}

int byte_diff(const void* S,unsigned int n, const void* T)
{
  const char *s=S;
  const char *t=T;
  for (;;) {
    if (!n) return 0; if (*s != *t) break; ++s; ++t; --n;
    if (!n) return 0; if (*s != *t) break; ++s; ++t; --n;
    if (!n) return 0; if (*s != *t) break; ++s; ++t; --n;
    if (!n) return 0; if (*s != *t) break; ++s; ++t; --n;
  }
  return ((int)(unsigned int)(unsigned char) *s)
       - ((int)(unsigned int)(unsigned char) *t);
}

void byte_zero(void* S,unsigned int n)
{
  char* s=S;
  for (;;) {
    if (!n) break; *s++ = 0; --n;
    if (!n) break; *s++ = 0; --n;
    if (!n) break; *s++ = 0; --n;
    if (!n) break; *s++ = 0; --n;
  }
}
