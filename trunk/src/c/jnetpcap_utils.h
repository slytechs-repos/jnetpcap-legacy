/* Header for jnetpcap_utils utility methods */

#ifndef _Included_org_jnetpcap_Pcap_utils
#define _Included_org_jnetpcap_Pcap_utils
#ifdef __cplusplus
extern "C" {
#define	EXTERN extern "C"
#endif

#include "export.h"
	
#include <jni.h>
#include "packet_jscanner.h"

	
#define ILLEGAL_STATE_EXCEPTION "java/lang/IllegalStateException"
#define ILLEGAL_ARGUMENT_EXCEPTION "java/lang/IllegalArgumentException"
#define CLASS_NOT_FOUND_EXCEPTION "java/lang/ClassNotFoundException"
#define NO_SUCH_METHOD_EXCEPTION "java/lang/NoSuchMethodException"
#define NO_SUCH_FIELD_EXCEPTION "java/lang/NoSuchFieldException"
#define INDEX_OUT_OF_BOUNDS_EXCEPTION "java/lang/IndexOutOfBoundsException"
#define NULL_PTR_EXCEPTION "java/lang/NullPointerException"
#define UNSUPPORTED_OPERATION_EXCEPTION "java/lang/UnsupportedOperationException"
#define PCAP_CLOSED_EXCEPTION "org/jnetpcap/PcapClosedException"
#define PCAP_EXTENSION_NOT_AVAILABLE_EXCEPTION "org/jnetpcap/PcapExtensionNotAvailableException"
#define OUT_OF_MEMORY_ERROR "java/lang/OutOfMemoryError"
#define BUFFER_OVERFLOW_EXCEPTION "java/nio/BufferOverflowException"
#define BUFFER_UNDERFLOW_EXCEPTION "java/nio/BufferUnderflowException"
#define READ_ONLY_BUFFER_EXCETPION "java/nio/ReadOnlyBufferException"
#define UNREGISTERED_SCANNER_EXCEPTION "org/jnetpcap/packet/UnregisteredHeaderException"
#define IO_EXCEPTION "java/io/IOException"
	
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
const char *toCharArray(JNIEnv *env, jstring jstr, char *buf);
jstring toJavaString(JNIEnv *env, const char *buf);
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
	jobject pcap;
	jobject user;
	jclass clazz;
	jthrowable  exception; // Any exceptions to rethrow
	jmethodID mid;
	pcap_t *p;
	
} pcap_user_data_t;

typedef struct cb_byte_buffer_t {
	pcap_t *p;
	jmethodID mid;
	JNIEnv *env;    // thread
	jobject obj;    // ByteBufferHandler
	jobject pcap;
	jthrowable  exception; // Any exceptions to rethrow
	jobject user;
	jobject header; // PcapHeader
};

typedef struct cb_jbuffer_t {
	pcap_t *p;
	jmethodID mid;
	JNIEnv *env;    // thread
	jobject obj;    // JBufferHandler
	jobject pcap;
	jthrowable  exception; // Any exceptions to rethrow
	jobject user;
	jobject header; // PcapHeader
	jobject buffer; // JBuffer
};

typedef struct cb_jpacket_t {
	pcap_t *p;
	jmethodID mid;
	JNIEnv *env;       // thread
	jobject obj;       // JPacketHandler
	jobject pcap;
	jthrowable  exception; // Any exceptions to rethrow
	jobject user;
	jobject header;    // PcapHeader
	jobject packet;    // JPacket
	jobject state;     // JPacket.State
	jint id;           // Header ID
	jobject scanner;   // JScanner
	
};



extern "C"
void pcap_callback(u_char*, const pcap_pkthdr*, const u_char*);
void cb_byte_buffer_dispatch(u_char*, const pcap_pkthdr*, const u_char*);
void cb_jbuffer_dispatch(u_char*, const pcap_pkthdr*, const u_char*);
void cb_jpacket_dispatch(u_char*, const pcap_pkthdr*, const u_char*);
void cb_pcap_packet_dispatch(u_char*, const pcap_pkthdr*, const u_char*);

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

void throwException(JNIEnv *env, const char *exception, char *message);
void throwVoidException(JNIEnv *env, const char *exception);

#ifdef __cplusplus
}
#endif
#endif
