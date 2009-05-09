#ifndef CHECKSUM_H
#define CHECKSUM_H

#include "uint.h"
#include "util.h"

extern __inline u16 checksum_ip(const void *iph, unsigned ihl);
extern __inline u16 checksum_net(const void *p, unsigned len);

#endif
