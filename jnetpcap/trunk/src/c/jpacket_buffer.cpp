/***************************************************************************
 * Copyright (C) 2009, Sly Technologies, Inc                               *
 * Distributed under the Lesser GNU Public License  (LGPL)                 *
 ***************************************************************************/

#include <stdlib.h>
#include <string.h>

#include "jpacket_buffer.h"
#include "jnetpcap_ids.h"
#include "nio_jmemory.h"

/**
 * Handler which stores packets natively in a large buffer and dispatches to
 * the user when the buffer is full.
 */
void cb_jpacket_buffer_handler(
		u_char* user, 
		const pcap_pkthdr* pkt_header,
		const u_char* pkt_data) {
	
	cb_jpacket_buffer_t *data = (cb_jpacket_buffer_t *)user;
	
#define PCAP_HEADER_LENGTH 16
	
//	printf("cb_jpacket_buffer_handler(): bounds(offset=%d)\n",
//			data->buf->offset); fflush(stdout);
	/* New bounds */
	int end = data->buf->capacity - pkt_header->caplen  - PCAP_HEADER_LENGTH;
	/* Reset to 0 since uints don't work with signs very well for comparison */
	if (end < 0) {
		end = 0;
	}

//	printf("cb_jpacket_buffer_handler(): bounds(offset=%d, end=%d, cap=%d, len=%d)\n",
//			data->buf->offset,
//			end,
//			data->buf->capacity,
//			pkt_header->caplen); fflush(stdout);
	
	
	/*
	 * Dispatch to the user, the buffer is full
	 */			
	if (data->buf->offset > end) {
		
//		printf("cb_jpacket_buffer_handler(): dispatch()\n"); fflush(stdout);
		if (jpacket_buffer_dispatch(
				data->env,
				data->obj,
				data->mid,
				&data->jbuffer,
				data->buf,
				data->user)) {
			
			pcap_breakloop(data->p);
			data->exception = data->env->ExceptionOccurred();
			data->buf = NULL;
			
			return;
		}
	
//		printf("cb_jpacket_buffer_handler(): create()\n"); fflush(stdout);
		if (jpacket_buffer_create(
				data->env, 
				&data->jbuffer, 
				&data->buf, 
				data->buf_size,     // size
				pkt_header->caplen, // minsize
				data->id)) {
			
			pcap_breakloop(data->p);
			data->exception = data->env->ExceptionOccurred();
			
			return;
		}
	}
	
//	printf("cb_jpacket_buffer_handler(): copy1()\n"); fflush(stdout);
	data->buf->count ++;
	char *buf = ((char *)data->buf) + data->buf->offset;
	
#define PCAP_HEADER_LENGTH	16
	pcap_pkthdr *temp = (pcap_pkthdr *)buf;
	memcpy(buf, pkt_header, PCAP_HEADER_LENGTH);
	
	data->buf->offset += PCAP_HEADER_LENGTH;
	buf += PCAP_HEADER_LENGTH;
	
//	printf("cb_jpacket_buffer_handler(): copy2()\n"); fflush(stdout);
	memcpy(buf, pkt_data, pkt_header->caplen);
	data->buf->offset += pkt_header->caplen;
	data->buf->offset += (pkt_header->caplen % 2);
}



/**
 * Create a new JPacketBuffer object and allocate requested size memory for buffer
 */
int jpacket_buffer_create(
		JNIEnv *env, 
		jobject *obj, 
		jpacket_buffer_t **buf, 
		size_t size, 
		size_t min_size, 
		int dlt) {
	
	/*
	 * Free up local reference to previous buffer. This can happen when
	 * jpacket_buffer_create are called back to back.
	 */
	if (*obj != NULL) {
//		printf("jpacket_buffer_create(): DeleteLocalRef()\n"); fflush(stdout);
		env->DeleteLocalRef(*obj);
	}
	
	min_size += JPACKET_BUFFER_HEADER_LENGTH + PCAP_HEADER_LENGTH;
	if (size < min_size) {
		size = min_size ;
	}
	
//	printf("jpacket_buffer_create(): NewObject(class=%p, mid=%d, size=%d)\n",
//			jpacketBufferClass,
//			jpacketBufferConstructorMID,
//			size); fflush(stdout);
			
	*obj = env->NewObject(
			jpacketBufferClass, 
			jpacketBufferConstructorMID, 
			(jint) size);
	
	if (*obj == NULL) {
		return -1;
	}
	
//	printf("jpacket_buffer_create(): getPhysical()\n"); fflush(stdout);
	*buf = (jpacket_buffer_t *)getJMemoryPhysical(env, *obj);
//	printf("jpacket_buffer_create(): getPhysical()=%p\n", *buf); fflush(stdout);
	if (*buf == NULL) {
		throwVoidException(env, OUT_OF_MEMORY_ERROR);
		return -1; // Out of memory
	}
	
//	printf("jpacket_buffer_create(): init()\n"); fflush(stdout);
	(*buf)->capacity = (uint32_t) size;
	(*buf)->count = 0;
	(*buf)->offset = JPACKET_BUFFER_HEADER_LENGTH;
	(*buf)->dlt = dlt;
	
	return 0; // OK
}

int jpacket_buffer_dispatch(
		JNIEnv *env, 
		jobject jhandler, 
		jmethodID mid, 
		jobject *jbuffer, 
		jpacket_buffer_t *buf, 
		jobject user) {
	
//	jpacket_buffer_t *b2 = (jpacket_buffer_t *)getJMemoryPhysical(env, jbuffer);
//	printf("jpacket_buffer_dispatch(): b1=%p b2=%p\n",
//			buf, b2); fflush(stdout);

	
//	printf("jpacket_buffer_dispatch(): CallVoidMethod(jhandler=%p, mid=%d, jbuffer=%p, user=%p)\n",
//			jhandler, mid, jbuffer, user); fflush(stdout);
			
	
	/* Make sure we have some packets to dispatch */
	if (buf->count > 0) {
		env->CallVoidMethod(jhandler, mid, *jbuffer, user);
	}

	/*
	 * Cleanup our local reference to buffer object. This would
	 * be a serious memory leak if we didn't remove this reference after
	 * each dispatch
	 */
//	printf("jpacket_buffer_dispatch(): delete local ref()\n"); fflush(stdout);
	env->DeleteLocalRef(*jbuffer);
	*jbuffer = NULL;
	
	/*
	 * Check for exceptions being thrown in the user handler
	 */
//	printf("jpacket_buffer_dispatch(): check exception()\n"); fflush(stdout);
	if (env->ExceptionCheck() == JNI_TRUE) {
		return -2;
	}
	
	return 0;
}
