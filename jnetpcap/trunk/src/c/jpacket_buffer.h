/* Header for jnetpcap_utils utility methods */

#ifndef _Included_jpacket_buffer
#define _Included_jpacket_buffer
#ifdef __cplusplus
extern "C" {
#define	EXTERN extern "C"
#endif

	
#include <jni.h>
#include <pcap.h>

#include "jnetpcap_utils.h"

	
/*
 * STRUCTURES
 */
	
#define JPACKET_BUFFER_HEADER_LENGTH	64

typedef struct jpacket_buffer_t {
	uint32_t	count; 		// pkt count
	uint32_t	dlt;   		// pkt dlt ID
	uint32_t	offset;     // Current position within the buffer
	uint32_t	capacity;   // Buffer capacity
} jpacket_buffer_t;

typedef struct cb_jpacket_buffer_t {
	pcap_t *p;
	jmethodID mid;
	JNIEnv *env;       // thread
	jobject obj;       // JPacketBufferHandler
	jobject jbuffer;   // JPacketBuffer
	jthrowable  exception; // Any exceptions to rethrow
	jobject user;
	jint 	id;           // Header ID
	uint32_t	buf_size; // User requested buffer size
	
	jpacket_buffer_t *buf;
} cb_jpacket_buffer_t;

/*
 * PROTOTYPES
 */

void cb_jpacket_buffer_handler(u_char*, const pcap_pkthdr*, const u_char*);

int jpacket_buffer_create(
		JNIEnv *env, 
		jobject *obj, 
		jpacket_buffer_t **buf, 
		size_t size, 
		size_t min_size,
		int dlt);

int jpacket_buffer_dispatch(		
		JNIEnv *env, 
		jobject obj, 
		jmethodID mid, 
		jobject *jbuffer, 
		jpacket_buffer_t *buf, 
		jobject user);

#ifdef __cplusplus
}
#endif
#endif
