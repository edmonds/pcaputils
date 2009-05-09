#ifndef RSEUTIL_BYTE_H
#define RSEUTIL_BYTE_H

int byte_diff(const void *, unsigned int, const void *);
unsigned int byte_chr(const char *s, unsigned int n, int c);
unsigned int byte_rchr(const char *s, unsigned int n, int c);
void byte_copy(void *to, unsigned int n, const void *from);
void byte_copyr(void *to, unsigned int n, const void *from);
void byte_zero(void *, unsigned int);

#define byte_equal(s,n,t) (!byte_diff((s),(n),(t)))

#endif
