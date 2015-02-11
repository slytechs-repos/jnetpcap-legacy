/* Header for jnetpcap_utils utility methods */

#ifndef _Included_nio_jbuffer_h
#define _Included_nio_jbuffer_h
#ifdef __cplusplus
extern "C" {
#define	EXTERN extern "C"
#endif

#include "export.h"

#if defined(HPUX) || defined(SUNOS) || defined(SOLARIS)
#include <sys/param.h>
#endif

#include <jni.h>

#define __STRICT_ALIGNMENT

// Generic MACROS
#ifndef __BYTE_ORDER

// GNU MACROS
#ifdef __BYTE_ORDER__

#define __LITTLE_ENDIAN __ORDER_LITTLE_ENDIAN__
#define __BIG_ENDIAN __ORDER_BIG_ENDIAN__
#define __BYTE_ORDER __BYTE_ORDER__

#else

#define __LITTLE_ENDIAN 1
#define __BIG_ENDIAN 2
#define __BYTE_ORDER __BIG_ENDIAN

#endif
#endif

/****************************************************************
 * **************************************************************
 * 
 * JNI IDs
 * 
 * **************************************************************
 ****************************************************************/
extern jfieldID jbufferOrderFID;
extern jfieldID jbufferReadonlyFID;

/****************************************************************
 * **************************************************************
 * 
 * ENDIAN MACROS - swap bytes for proper endianess
 * 
 * **************************************************************
 ****************************************************************/

#define IS_INT8_ALIGNED(p)		(TRUE)
#define IS_INT16_ALIGNED(p)		((p & 0x01) == 0)
#define IS_INT32_ALIGNED(p)		((p & 0x02) == 0)
#define IS_INT64_ALIGNED(p)		((p & 0x03) == 0)

#define BIG_ENDIAN8_GET(p) \
	((uint8_t)p[0])

#define BIG_ENDIAN16_GET(p) \
	(((uint16_t)p[0]) << 8L) | \
	(((uint16_t)p[1]) << 0L)

#define BIG_ENDIAN32_GET(p) \
	(((uint32_t)p[0]) << 24L) | \
	(((uint32_t)p[1]) << 16L) | \
	(((uint32_t)p[2]) << 8L)  | \
	(((uint32_t)p[3]) << 0L)

#define BIG_ENDIAN64_GET(p) \
	(((uint64_t)p[0]) << 56L) | \
	(((uint64_t)p[1]) << 48L) | \
	(((uint64_t)p[2]) << 40L) | \
	(((uint64_t)p[3]) << 32L) | \
	(((uint64_t)p[4]) << 24L) | \
	(((uint64_t)p[5]) << 16L) | \
	(((uint64_t)p[6]) << 8L)  | \
	(((uint64_t)p[7]) << 0L)

#define LITTLE_ENDIAN8_GET(p) \
	((uint8_t)p[0])

#define LITTLE_ENDIAN16_GET(p) \
	(((uint16_t)p[1]) << 8L) | \
	(((uint16_t)p[0]) << 0L)

#define LITTLE_ENDIAN32_GET(p) \
	(((uint32_t)p[3]) << 24L) | \
	(((uint32_t)p[2]) << 16L) | \
	(((uint32_t)p[1]) << 8L)  | \
	(((uint32_t)p[0]) << 0L)

#define LITTLE_ENDIAN64_GET(p) \
	(((uint64_t)p[7]) << 56L) | \
	(((uint64_t)p[6]) << 48L) | \
	(((uint64_t)p[5]) << 40L) | \
	(((uint64_t)p[4]) << 32L) | \
	(((uint64_t)p[3]) << 24L) | \
	(((uint64_t)p[2]) << 16L) | \
	(((uint64_t)p[1]) << 8L)  | \
	(((uint64_t)p[0]) << 0L)

#define ENDIAN16_GET_UNALIGNED(big, p) \
	((big == JNI_TRUE) ? BIG_ENDIAN16_GET(p) : LITTLE_ENDIAN16_GET(p))

#define ENDIAN32_GET_UNALIGNED(big, p) \
	((big == JNI_TRUE) ? BIG_ENDIAN32_GET(p) : LITTLE_ENDIAN32_GET(p))

#define ENDIAN64_GET_UNALIGNED(big, p) \
		((big == JNI_TRUE) ? BIG_ENDIAN64_GET(p) : LITTLE_ENDIAN64_GET(p))


#define ENDIAN16_ATOM_SWAP(data) (\
	((((uint16_t)data) >> 8)  & 0x00FF) | ((((uint16_t)data) << 8) &  0xFF00))

#define ENDIAN32_ATOM_SWAP(data) (\
	( (((uint32_t)data) >> 24) & 0x000000FF) | ((((uint32_t)data) >> 8)   & 0x0000FF00) |\
	( (((uint32_t)data) << 8)  &  0x00FF0000) | ((((uint32_t)data) << 24) & 0xFF000000))

#define ENDIAN64_ATOM_SWAP(data) (\
	( (((uint64_t)data) >> 56) & 0x00000000000000FFLLU) | ((((uint64_t)data) >> 40) & 0x000000000000FF00LLU) |\
	( (((uint64_t)data) >> 24) & 0x0000000000FF0000LLU) | ((((uint64_t)data) >> 8)  & 0x00000000FF000000LLU) |\
	( (((uint64_t)data) << 8)  & 0x000000FF00000000LLU) | ((((uint64_t)data) << 24) & 0x0000FF0000000000LLU) |\
	( (((uint64_t)data) << 40) & 0x00FF000000000000LLU) | ((((uint64_t)data) << 56) & 0xFF00000000000000LLU) \
	)

#define ENDIAN16_PTR_SWAP(data) \
	((uint16_t)*(data + 0) << 8) | ((uint16_t)*(data + 1))

#define ENDIAN32_PTR_SWAP(data) \
	((uint32_t)*(data + 0) << 24) | ((uint32_t)*(data + 3)     ) |\
	((uint32_t)*(data + 1) << 16) | ((uint32_t)*(data + 2) << 8)

#define ENDIAN64_PTR_SWAP(data) \
	((uint64_t)*(data + 0) << 56) | ((uint64_t)*(data + 7)      ) |\
	((uint64_t)*(data + 1) << 48) | ((uint64_t)*(data + 6) <<  8) |\
	((uint64_t)*(data + 2) << 40) | ((uint64_t)*(data + 5) << 16) |\
	((uint64_t)*(data + 3) << 32) | ((uint64_t)*(data + 4) << 24)

/*
 * These macros test for requested BIG ENDIAN condition and appropriately define
 * the correct byte swap macro for various CPU ENDIAN platforms.
 * 
 * Usage - if cond is TRUE will ensure that BIG_ENDIAN is returned on both 
 * LITTLE AND BIG platforms. If cond is FALSE then LITTLE_ENDIAN will be 
 * returned.
 */
#if __BYTE_ORDER == __LITTLE_ENDIAN

#define ENDIAN16_GET(big, data) \
	((big == JNI_TRUE)?ENDIAN16_ATOM_SWAP(data):data)

#define ENDIAN32_GET(big, data) \
	((big == JNI_TRUE)?ENDIAN32_ATOM_SWAP(data):data)

#define ENDIAN64_GET(big, data) \
	((big == JNI_TRUE)?ENDIAN64_ATOM_SWAP(data):data)

#define BIG_ENDIAN16(data)	ENDIAN16_ATOM_SWAP(data)
#define BIG_ENDIAN32(data)	ENDIAN32_ATOM_SWAP(data)
#define BIG_ENDIAN64(data)	ENDIAN64_ATOM_SWAP(data)

#define LITTLE_ENDIAN16(data)	data
#define LITTLE_ENDIAN32(data)	data
#define LITTLE_ENDIAN64(data)	data

#elif __BYTE_ORDER == __BIG_ENDIAN

#define ENDIAN16_GET(big, data) \
	((big == JNI_TRUE)?data:ENDIAN16_ATOM_SWAP(data))

#define ENDIAN32_GET(big, data) \
	((big == JNI_TRUE)?data:ENDIAN32_ATOM_SWAP(data))

#define ENDIAN64_GET(big, data) \
	((big == JNI_TRUE)?data:ENDIAN64_ATOM_SWAP(data))

#define BIG_ENDIAN16(data)	data
#define BIG_ENDIAN32(data)	data
#define BIG_ENDIAN64(data)	data

#define LITTLE_ENDIAN16(data)	ENDIAN16_ATOM_SWAP(data)
#define LITTLE_ENDIAN32(data)	ENDIAN32_ATOM_SWAP(data)
#define LITTLE_ENDIAN64(data)	ENDIAN64_ATOM_SWAP(data)

#else
# error "ENDIAN MACROS NOT DEFINED :("
#endif

#ifdef __cplusplus
}
#endif
#endif
