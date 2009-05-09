#include "checksum.h"
#include "net.h"
#include "uint.h"
#include "util.h"

/*
 *  This is a version of ip_compute_csum() optimized for IP headers,
 *  which always checksum on 4 octet boundaries.
 *
 *  By Jorge Cwik <jorge@laser.satlink.net>, adapted for linux by
 *  Arnt Gulbrandsen.
 */

/**
 * ip_fast_csum - Compute the IPv4 header checksum efficiently.
 * iph: ipv4 header
 * ihl: length of header / 4
 */

#if defined(__i386__) || defined(__amd64__)
__inline u16 checksum_ip(const void *iph, unsigned ihl)
{
	unsigned sum;

	asm(	"  movl (%1), %0\n"
		"  subl $4, %2\n"
		"  jbe 2f\n"
		"  addl 4(%1), %0\n"
		"  adcl 8(%1), %0\n"
		"  adcl 12(%1), %0\n"
		"1: adcl 16(%1), %0\n"
		"  lea 4(%1), %1\n"
		"  decl %2\n"
		"  jne  1b\n"
		"  adcl $0, %0\n"
		"  movl %0, %2\n"
		"  shrl $16, %0\n"
		"  addw %w2, %w0\n"
		"  adcl $0, %0\n"
		"  notl %0\n"
		"2:"
	/* Since the input registers which are loaded with iph and ihl
	   are modified, we must also specify them as outputs, or gcc
	   will assume they contain their original values. */
	: "=r" (sum), "=r" (iph), "=r" (ihl)
	: "1" (iph), "2" (ihl)
	: "memory");
	return (u16) sum;
}
#else
__inline u16 checksum_ip(const void *iph, unsigned ihl)
{
	return checksum_net(iph, 4 * ihl);
}
#endif

__inline u16 checksum_net(const void *p, unsigned len)
{
	unsigned sum = 0;
	u16 *ip = (u16 *) p;
	while(len > 1){
		sum += *ip++;
		len -= 2;
	}
	while(sum >> 16)
		sum = (sum & 0xffff) + (sum >> 16);
#if __BYTE_ORDER == __LITTLE_ENDIAN	
	return (u16) (~sum);
#else
	return bswap16((u16) (~sum));
#endif
}
