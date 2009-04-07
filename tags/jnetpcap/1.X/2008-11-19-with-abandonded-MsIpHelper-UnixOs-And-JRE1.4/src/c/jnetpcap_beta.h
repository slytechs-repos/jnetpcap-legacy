/* Header for jnetpcap_utils utility methods */

#ifndef _Included_jnetpcap_beta_h
#define _Included_jnetpcap_beta_h
#ifdef __cplusplus
extern "C" {
#define	EXTERN extern "C"
#endif
	
#include "export.h"
	
#include <jni.h>
	
/*
 * Structure which holds information for a callback from dispatch and loop.
 * Holds enough information so we can callback to Java handler and still return
 * the original generic user data object.
 */
typedef struct pcap_jhandler_t {
	JNIEnv *env;
	jobject obj;
	jobject user;
	jclass clazz;
	jmethodID mid;
	pcap_t *p;
		
} pcap_jhandler_data_t;


void pcap_jhandler_callback(u_char*, const pcap_pkthdr*, const u_char*);
	
#ifdef __cplusplus

}
#endif
#endif
