#include "uint.h"

/* derived from public domain djbdns code */

void u16_pack(char s[2], u16 u)
{
  s[0] = (char) (u & 255);
  s[1] = (char) (u >> 8);
}

void u16_pack_big(char s[2], u16 u)
{
  s[1] = (char) (u & 255);
  s[0] = (char) (u >> 8);
}

void u16_unpack(const char s[2], u16 *u)
{
  u16 result;
  
  result = (unsigned char) s[1];
  result <<= 8;
  result += (unsigned char) s[0];

  *u = result;
} 

void u16_unpack_big(const char s[2], u16 *u)
{
  u16 result;

  result = (unsigned char) s[0];
  result <<= 8;
  result += (unsigned char) s[1];

  *u = result;
}

void u32_pack(char s[4], u32 u)
{
  s[0] = (char) (u & 255);
  u >>= 8;
  s[1] = (char) (u & 255);
  u >>= 8;
  s[2] = (char) (u & 255);
  s[3] = (char) (u >> 8);
} 

void u32_pack_big(char s[4], u32 u)
{
  s[3] = (char) (u & 255);
  u >>= 8;
  s[2] = (char) (u & 255);
  u >>= 8; 
  s[1] = (char) (u & 255);
  s[0] = (char) (u >> 8);
}

void u32_unpack(const char s[4], u32 *u)
{
  u32 result;
  
  result = (unsigned char) s[3];
  result <<= 8;
  result += (unsigned char) s[2];
  result <<= 8;
  result += (unsigned char) s[1];
  result <<= 8;
  result += (unsigned char) s[0];

  *u = result;
} 

void u32_unpack_big(const char s[4], u32 *u)
{ 
  u32 result;

  result = (unsigned char) s[0];
  result <<= 8;
  result += (unsigned char) s[1];
  result <<= 8;
  result += (unsigned char) s[2];
  result <<= 8;
  result += (unsigned char) s[3];

  *u = result;
}
