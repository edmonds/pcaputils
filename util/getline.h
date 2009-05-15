#ifndef GETLINE_H
#define GETLINE_H

#include <stdio.h>

ssize_t getdelim (char **lineptr, size_t *n, int delimiter, FILE *fp);
ssize_t getline (char **lineptr, size_t *n, FILE *stream);

#endif
