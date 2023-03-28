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
	
extern "C"

void throwException(JNIEnv *env, const char *exception, char *message);
void throwVoidException(JNIEnv *env, const char *exception);


#ifdef __cplusplus
}
#endif
#endif
