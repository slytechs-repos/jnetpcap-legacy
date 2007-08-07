#include <jni.h>
/* Header for jnetpcap_utils utility methods */

#ifndef _Included_org_jnetpcap_WinPcapStatEx
#define _Included_org_jnetpcap_WinPcapStatEx
#ifdef __cplusplus
extern "C" {
#define	EXTERN extern "C"
#endif
	
extern	jclass winPcapStatExClass;

// Prototypes
jobject newPcapStatEx(JNIEnv *env);
void setPcapStatEx(JNIEnv *env, jobject jstats, struct pcap_stat_ex *stats, 
		int size);


#ifdef __cplusplus
}
#endif
#endif
