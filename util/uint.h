#ifndef RSEUTIL_UINT_H
#define RSEUTIL_UINT_H

#include <stdint.h>
#include <inttypes.h>

typedef int8_t i8;
typedef int16_t i16;
typedef int32_t i32;
typedef int64_t i64;

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

extern void u16_pack(char *, u16);
extern void u16_pack_big(char *, u16);
extern void u16_unpack(const char *, u16 *);
extern void u16_unpack_big(const char *, u16 *);

extern void u32_pack(char *, u32);
extern void u32_pack_big(char *, u32);
extern void u32_unpack(const char *, u32 *);
extern void u32_unpack_big(const char *, u32 *);

#endif
