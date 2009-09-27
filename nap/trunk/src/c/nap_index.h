
// Include this file after jni.h is included. It undefines MS compiler, def for
// gcc specific one.
//
#ifndef Include_nap_index_h
#define Include_nap_index_h

#include <stdint.h>

#ifndef WIN32
#include <sys/socket.h>
#endif

#ifdef WIN32
#include <winsock2.h>
#endif

#undef __declspec
#define __declspec(a) extern "C"
#include "nap.h"

typedef struct nap_index_t {
	uint16_t	options:1;
	uint16_t	type:3;
	uint16_t	sub_type:12; // Record type specific
	uint16_t	reserved; 
	
	uint32_t	length;		 // Index of this last payload record
	uint32_t	index;		 // Index of this last payload record
	uint32_t	previous;	 // Offset of previous index-record of this type
	uint32_t	next;		 // Offset of next index-record, or 0 if last one
	
} nap_index_t;

#define NAP_ST_INDEX_1K		1
#define NAP_ST_INDEX_10K	2
#define NAP_ST_INDEX_100K	3
#define	NAP_ST_INDEX_1M		4

#define NAP_ST_INDEX_LENGTH	24


#endif
