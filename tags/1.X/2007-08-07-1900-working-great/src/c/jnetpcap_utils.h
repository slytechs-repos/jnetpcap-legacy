/* Header for jnetpcap_utils utility methods */

#ifndef _Included_org_jnetpcap_Pcap_utils
#define _Included_org_jnetpcap_Pcap_utils
#ifdef __cplusplus
extern "C" {
#define	EXTERN extern "C"
#endif

#include "export.h"
	
#include <jni.h>

	
#define ILLEGAL_STATE_EXCEPTION "java/lang/IllegalStateException"
#define INVALID_ARGUMENT_EXCEPTION "java/leng/InvalidArgumentException"
#define CLASS_NOT_FOUND_EXCEPTION "java/lang/ClassNotFoundException"
#define NO_SUCH_METHOD_EXCEPTION "java/lang/NoSuchMethodException"
#define NO_SUCH_FIELD_EXCEPTION "java/lang/NoSuchFieldException"
#define INDEX_OUT_OF_BOUNDS_EXCEPTION "java/lang/IndexOutOfBoundsException"
#define NULL_PTR_EXCEPTION "java/lang/NullPointerException"
#define UNSUPPORTED_OPERATION_EXCEPTION "java/lang/UnsuportOperationException"
#define PCAP_CLOSED_EXCEPTION "org/jnetpcap/PcapClosedException"
#define PCAP_EXTENSION_NOT_AVAILABLE_EXCEPTION "org/jnetpcap/PcapExtensionNotAvailableException"
	
extern	jclass pcapClass;
extern	jclass pcapHandlerClass;
extern	jclass stringBuilderClass;

extern	jfieldID pcapPhysicalFID;
extern jfieldID pcapIfNextFID;

extern	jmethodID pcapConstructorMID;
extern	jmethodID pcapHandlerMID;
extern	jmethodID appendMID;
extern	jmethodID setLengthMID;
	
// GENERIC utilities
char * toString(JNIEnv *env, jbyteArray ja);
jlong toLong(void *ptr);
void *toPtr(jlong lp);

jclass getClass(JNIEnv *env, char *clazz);


/*
 *  PCAP class related utilities
 */

/*
 * Structure which holds information for a callback from dispatch and loop.
 * Holds enough information so we can callback to Java handler and still return
 * the original generic user data object.
 */
typedef struct pcap_user_data_t {
	JNIEnv *env;
	jobject obj;
	jobject user;
	jclass clazz;
	jmethodID mid;
	pcap_t *p;
	
} pcap_user_data_t;

extern "C"
void pcap_callback(u_char*, const pcap_pkthdr*, const u_char*);
pcap_t *getPcap(JNIEnv *env, jobject obj);
jmethodID getPcapHandlerMID(JNIEnv *env);
jfieldID getPcapPhysicalFID(JNIEnv *env, jclass clazz);
jlong getPhysical(JNIEnv *, jobject);
void setPhysical(JNIEnv *, jobject, jlong);
void setString(JNIEnv *env, jobject buffer, const char *);
jmethodID getPcapConstructorMID(JNIEnv *env, jclass clazz);
pcap_pkthdr *getPktHeader(JNIEnv *env, jobject jpkt_header, pcap_pkthdr *pkt_header);
void setPktHeader(JNIEnv *env, jobject jpkt_header, pcap_pkthdr *pkt_header);
void setPktBuffer(JNIEnv *env, jobject jpkt_buffer, jobject jbuffer);
jclass findClass(JNIEnv *env, char *name);
jmethodID findMethod(JNIEnv *env, jobject obj, char *name, char *signature);

jobject newPcapAddr(JNIEnv *env, jobject jlist, jmethodID MID_add, pcap_addr *addr);
jobject newPcapIf(JNIEnv *env, jobject jlist, jmethodID MID_add, pcap_if_t *ifp);
jobject newPcapSockAddr(JNIEnv *env, sockaddr *a);

void setPcapStat(JNIEnv *env, jobject jstats, pcap_stat *stats);

void throwException(JNIEnv *env, const char *excClassName, char *message);

#ifdef __cplusplus
}
#endif
#endif
