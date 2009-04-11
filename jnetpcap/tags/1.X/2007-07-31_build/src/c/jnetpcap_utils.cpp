/***************************************************************************
 * Copyright (C) 2007, Sly Technologies, Inc                               *
 * Distributed under the Lesser GNU Public License  (LGPL)                 *
 ***************************************************************************/

/*
 * Utility file that provides various conversion methods for chaging objects
 * back and forth between C and Java JNI.
 */

#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <jni.h>

#ifndef WIN32
#include <errno.h>
#include <string.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>
#endif /*WIN32*/

#include "jnetpcap_utils.h"
#include "jnetpcap_bpf.h"

/*****************************************************************************
 * UTILITY METHODS
 */

char * toString(JNIEnv *env, jbyteArray ja) {
	jbyte *string = env->GetByteArrayElements(ja, NULL);

	jsize as = env->GetArrayLength(ja);
	printf("array size=%d\n", as);

	for (int i = 0; i < as; i ++) {
		printf("[#%d %d]", i, string[i]);
	}
	printf("\n");

	return (char *)string;
}

jlong toLong(void *ptr) {
	jlong lp = (jlong) (jint) ptr;

	return lp;
}

void *toPtr(jlong lp) {
	void *ptr = (void *) ((jint) lp);

	return ptr;
}

/*****************************************************************************
 *  These are static and constant unless class file reloads
 */

jclass pcapClass = 0;
jclass byteBufferClass = 0;
jclass stringBuilderClass = 0;
jclass pcapIfClass = 0;
jclass pcapAddrClass = 0;
jclass pcapSockaddrClass = 0;

jfieldID pcapPhysicalFID = 0;

jfieldID pcapPkthdrSecondsFID = 0;
jfieldID pcapPkthdrUSecondsFID = 0;
jfieldID pcapPkthdrCaplenFID = 0;
jfieldID pcapPkthdrLenFID = 0;

jfieldID pcapPktBufferFID = 0;

jfieldID pcapIfNextFID = 0;
jfieldID pcapIfNameFID = 0;
jfieldID pcapIfDescriptionFID = 0;
jfieldID pcapIfAddressesFID = 0;
jfieldID pcapIfFlagsFID = 0;

jfieldID pcapAddrNextFID = 0;
jfieldID pcapAddrAddrFID = 0;
jfieldID pcapAddrNetmaskFID = 0;
jfieldID pcapAddrBroadaddrFID = 0;
jfieldID pcapAddrDstaddrFID = 0;

jfieldID pcapSockaddrFamilyFID = 0;
jfieldID pcapSockaddrDataFID = 0;

jmethodID pcapConstructorMID = 0;
jmethodID appendMID = 0;
jmethodID setLengthMID = 0;

/*
 * Class:     org_jnetpcap_Pcap
 * Method:    jniInitialize
 * Signature: ()V
 * Description: Initializes all of the jmethodID, jclass and jfieldIDs that are
 *              used by the entire collection of Pcap JNI related methods.
 *              This method only needs to be called once for all Pcap related
 *              classes. We do a lot of checks here and throw appropriate
 *              exceptions when something is not found. This is neccessary since
 *              no further runtime checks are performed after this initialization.
 */
EXTERN void JNICALL Java_org_jnetpcap_Pcap_jniInitialize
(JNIEnv *env, jclass clazz) {

	pcapClass = clazz; // This one is easy
	if ( (pcapConstructorMID = env->GetMethodID(clazz, "<init>", "(J)V")) == NULL) {
		throwException(env, NO_SUCH_METHOD_EXCEPTION,
				"Unable to initialize constructor Pcap.Pcap(long)");
		return;
	}

	if ( (pcapPhysicalFID = env->GetFieldID(clazz, "physical", "J")) == NULL) {
		throwException(env, NO_SUCH_FIELD_EXCEPTION,
				"Unable to initialize field Pcap.physical:long");
		return;
	}

	if ( (byteBufferClass = env->FindClass("java/nio/ByteBuffer")) == NULL) {
		throwException(env, CLASS_NOT_FOUND_EXCEPTION,
				"Unable to initialize class java.nio.ByteBuffer");
		return;
	}

	if ( (stringBuilderClass = env->FindClass("java/lang/StringBuilder")) == NULL) {
		throwException(env, CLASS_NOT_FOUND_EXCEPTION,
				"Unable to initialize class java.lang.StringBuilder");
		return;
	}

	if ( (appendMID = env->GetMethodID(stringBuilderClass, "append",
							"(Ljava/lang/String;)Ljava/lang/StringBuilder;")) == NULL) {
		throwException(env, NO_SUCH_METHOD_EXCEPTION,
				"Unable to initialize constructor java.lang.StringBuilder(String):StringBuilder");
		return;
	}

	if ( (setLengthMID = env->GetMethodID(stringBuilderClass, "setLength",
							"(I)V")) == NULL) {
		throwException(env, NO_SUCH_METHOD_EXCEPTION,
				"Unable to initialize constructor java.lang.StringBuilder.setLength(int):void)");
		return;
	}

	jclass c;

	// PcapPkthdr class
	if ( (c = env->FindClass("org/jnetpcap/PcapPkthdr")) == NULL) {
		throwException(env, CLASS_NOT_FOUND_EXCEPTION,
				"Unable to initialize class org.jnetpcap.PcapPkthdr");
		return;
	}

	if ( (pcapPkthdrSecondsFID = env->GetFieldID(c, "seconds", "J")) == NULL) {
		throwException(env, NO_SUCH_FIELD_EXCEPTION,
				"Unable to initialize field PcapPkthdr.seconds:long");
		return;
	}

	if ( (pcapPkthdrUSecondsFID = env->GetFieldID(c, "useconds", "I")) == NULL) {
		throwException(env, NO_SUCH_FIELD_EXCEPTION,
				"Unable to initialize field PcapPkthdr.useconds:int");
		return;
	}

	if ( (pcapPkthdrCaplenFID = env->GetFieldID(c, "caplen", "I")) == NULL) {
		throwException(env, NO_SUCH_FIELD_EXCEPTION,
				"Unable to initialize field PcapPkthdr.caplen:int");
		return;
	}

	if ( (pcapPkthdrLenFID = env->GetFieldID(c, "len", "I")) == NULL) {
		throwException(env, NO_SUCH_FIELD_EXCEPTION,
				"Unable to initialize field PcapPkthdr.len:int");
		return;
	}

	// PcapPktbuffer class
	if ( (c = env->FindClass("org/jnetpcap/PcapPktbuffer")) == NULL) {
		throwException(env, CLASS_NOT_FOUND_EXCEPTION,
				"Unable to initialize class org.jnetpcap.PcapPktbuffer");
		return;
	}

	if ( ( pcapPktBufferFID = env->GetFieldID(c, "buffer", "Ljava/nio/ByteBuffer;")) == NULL) {
		throwException(env, NO_SUCH_FIELD_EXCEPTION,
				"Unable to initialize field PcapPktbuffer.buffer:ByteBuffer");
		return;
	}
	
	// PcapIf class
	if ( (pcapIfClass = c = env->FindClass("org/jnetpcap/PcapIf")) == NULL) {
		throwException(env, CLASS_NOT_FOUND_EXCEPTION,
				"Unable to initialize class org.jnetpcap.PcapIf");
		return;
	}

	if ( ( pcapIfNextFID = env->GetFieldID(c, "next", "Lorg/jnetpcap/PcapIf;")) == NULL) {
		throwException(env, NO_SUCH_FIELD_EXCEPTION,
				"Unable to initialize field PcapIf.next:PcapIf");
		return;
	}
	
	if ( ( pcapIfNameFID = env->GetFieldID(c, "name", "Ljava/lang/String;")) == NULL) {
		throwException(env, NO_SUCH_FIELD_EXCEPTION,
				"Unable to initialize field PcapIf.name:String");
		return;
	}
	
	if ( ( pcapIfDescriptionFID = env->GetFieldID(c, "description", "Ljava/lang/String;")) == NULL) {
		throwException(env, NO_SUCH_FIELD_EXCEPTION,
				"Unable to initialize field PcapIf.description:String");
		return;
	}
	
	if ( ( pcapIfAddressesFID = env->GetFieldID(c, "addresses", "Lorg/jnetpcap/PcapAddr;")) == NULL) {
		throwException(env, NO_SUCH_FIELD_EXCEPTION,
				"Unable to initialize field PcapIf.addresses:PcapAddr");
		return;
	}
	
	if ( ( pcapIfFlagsFID = env->GetFieldID(c, "flags", "I")) == NULL) {
		throwException(env, NO_SUCH_FIELD_EXCEPTION,
				"Unable to initialize field PcapIf.flags:int");
		return;
	}
	
	
	
	// PcapAddr class
	if ( (pcapAddrClass = c = env->FindClass("org/jnetpcap/PcapAddr")) == NULL) {
		throwException(env, CLASS_NOT_FOUND_EXCEPTION,
				"Unable to initialize class org.jnetpcap.PcapAddr");
		return;
	}

	if ( ( pcapAddrNextFID = env->GetFieldID(c, "next", "Lorg/jnetpcap/PcapAddr;")) == NULL) {
		throwException(env, NO_SUCH_FIELD_EXCEPTION,
				"Unable to initialize field PcapAddr.next:PcapAddr");
		return;
	}
	
	if ( ( pcapAddrAddrFID = env->GetFieldID(c, "addr", "Lorg/jnetpcap/PcapSockaddr;")) == NULL) {
		throwException(env, NO_SUCH_FIELD_EXCEPTION,
				"Unable to initialize field PcapAddr.addr:PcapSockaddr");
		return;
	}
	
	if ( ( pcapAddrNetmaskFID = env->GetFieldID(c, "netmask", "Lorg/jnetpcap/PcapSockaddr;")) == NULL) {
		throwException(env, NO_SUCH_FIELD_EXCEPTION,
				"Unable to initialize field PcapAddr.netmask:PcapSockaddr");
		return;
	}

	if ( ( pcapAddrBroadaddrFID = env->GetFieldID(c, "broadaddr", "Lorg/jnetpcap/PcapSockaddr;")) == NULL) {
		throwException(env, NO_SUCH_FIELD_EXCEPTION,
				"Unable to initialize field PcapAddr.broadaddr:PcapSockaddr");
		return;
	}
	
	if ( ( pcapAddrDstaddrFID = env->GetFieldID(c, "dstaddr", "Lorg/jnetpcap/PcapSockaddr;")) == NULL) {
		throwException(env, NO_SUCH_FIELD_EXCEPTION,
				"Unable to initialize field PcapAddr.dstaddr:PcapSockaddr");
		return;
	}
	
	
	// PcapSockaddr class
	if ( (pcapSockaddrClass = c = env->FindClass("org/jnetpcap/PcapSockaddr")) == NULL) {
		throwException(env, CLASS_NOT_FOUND_EXCEPTION,
				"Unable to initialize class org.jnetpcap.PcapSockaddr");
		return;
	}

	if ( ( pcapSockaddrFamilyFID = env->GetFieldID(c, "family", "S")) == NULL) {
		throwException(env, NO_SUCH_FIELD_EXCEPTION,
				"Unable to initialize field PcapSockaddr.family:short");
		return;
	}
	
	if ( ( pcapSockaddrDataFID = env->GetFieldID(c, "data", "[B")) == NULL) {
		throwException(env, NO_SUCH_FIELD_EXCEPTION,
				"Unable to initialize field PcapSockaddr.data:byte[]");
		return;
	}
	
	
	// PcapBpfProgram class
	if ( (bpfProgramClass = c = env->FindClass("org/jnetpcap/PcapBpfProgram")) == NULL) {
		throwException(env, CLASS_NOT_FOUND_EXCEPTION,
				"Unable to initialize class org.jnetpcap.PcapBpfProgram");
		return;
	}

	if ( ( bpfProgramPhysicalFID = env->GetFieldID(c, "physical", "J")) == NULL) {
		throwException(env, NO_SUCH_FIELD_EXCEPTION,
				"Unable to initialize field PcapBpfProgram.physical:long");
		return;
	}
}

void pcap_callback(u_char *user, const pcap_pkthdr *pkt_header,
		const u_char *pkt_data) {

	pcap_user_data_t *data = (pcap_user_data_t *)user;

	JNIEnv *env = data->env;

	/**
	 * Check for pending exceptions
	 */
	if (env->ExceptionOccurred()) {
		return;
	}

	jobject buffer = env->NewDirectByteBuffer((void *)pkt_data,
			pkt_header->caplen);

	env->CallNonvirtualVoidMethod(data->obj, data->clazz, data->mid,
			(jobject) data->user, (jlong) pkt_header->ts.tv_sec,
			(jint)pkt_header->ts.tv_usec, (jint)pkt_header->caplen,
			(jint)pkt_header->len, buffer);
}

pcap_t *getPcap(JNIEnv *env, jobject obj) {
	jlong pt = env->GetLongField(obj, pcapPhysicalFID);

	if (pt == 0) {
		throwException(env, ILLEGAL_STATE_EXCEPTION,
				"Capture already closed (pcap_t) has already been deallocated.");

		return NULL;
	}

	pcap_t *p = (pcap_t *) toPtr(pt);

	return p;
}

jlong getPhysical(JNIEnv *env, jobject obj) {
	jlong physical = env->GetLongField(obj, pcapPhysicalFID);

	return physical;
}

void setPhysical(JNIEnv *env, jobject obj, jlong value) {
	env->SetLongField(obj, pcapPhysicalFID, value);
}

void setPktHeader(JNIEnv *env, jobject jpkt_header, pcap_pkthdr *pkt_header) {

	env->SetLongField(jpkt_header, pcapPkthdrSecondsFID,
			(jlong)pkt_header->ts.tv_sec);

	env->SetIntField(jpkt_header, pcapPkthdrUSecondsFID,
			(jint)pkt_header->ts.tv_usec);

	env->SetIntField(jpkt_header, pcapPkthdrCaplenFID, (jint)pkt_header->caplen);

	env->SetIntField(jpkt_header, pcapPkthdrLenFID, (jint)pkt_header->len);
}

void setPktBuffer(JNIEnv *env, jobject jpkt_buffer, jobject jbuffer) {
	env->SetObjectField(jpkt_buffer, pcapPktBufferFID, jbuffer);
}

/*
 * Throws specified exception with message to java. Any method calling on
 * this utility class, needs to make sure it returns as this exception does
 * not transfer control to back to java like it is in Java language, but returns
 * immediately.
 */
void throwException(JNIEnv *env, const char *excClassName, char *message) {
	jclass exception = env->FindClass(excClassName);

	if (exception != NULL) {
		env->ThrowNew(exception, message);
	}
}

/**
 * Calls on StringBuilder.setLength(0) and StringBuilder.append(String)
 */
void setString(JNIEnv *env, jobject buffer, const char *str) {
	jstring jstr = env->NewStringUTF(str);

	env->CallVoidMethod(buffer, setLengthMID, 0); // Set buffer to 0 length

	env->CallObjectMethod(buffer, appendMID, jstr); // append our string
	return;
}

/**
 * @param obj Pcap
 * @param ifp pcap_if_t structure to use in construction of java counter part
 * @return PcapIf
 */
jobject newPcapIf(JNIEnv *env, pcap_if_t *ifp) {

	jobject obj = env->AllocObject(pcapIfClass);
	
	if (ifp->next != NULL) {
		env->SetObjectField(obj, pcapIfNextFID, newPcapIf(env,  ifp->next));
	} else {
		env->SetObjectField(obj, pcapIfNextFID, NULL);
	}
	
	if (ifp->name != NULL) {
		env->SetObjectField(obj, pcapIfNameFID, env->NewStringUTF(ifp->name));
	} else {
		env->SetObjectField(obj, pcapIfNameFID, NULL);
	}
	
	if (ifp->description != NULL) {
		env->SetObjectField(obj, pcapIfDescriptionFID, env->NewStringUTF(ifp->description));
	} else {
		env->SetObjectField(obj, pcapIfDescriptionFID, NULL);
	}
	
	if (ifp->addresses != NULL) {
		env->SetObjectField(obj, pcapIfAddressesFID, newPcapAddr(env, ifp->addresses));
	} else {
		env->SetObjectField(obj, pcapIfAddressesFID, NULL);
	}
	
	
	env->SetIntField(obj, pcapIfFlagsFID, (jint) ifp->flags);
	
	return obj;
}

jobject newPcapAddr(JNIEnv *env, pcap_addr *a) {
	jobject obj = env->AllocObject(pcapAddrClass);

	if (a->next != NULL) {
		env->SetObjectField(obj, pcapAddrNextFID, newPcapAddr(env,  a->next));
	} else {
		env->SetObjectField(obj, pcapAddrNextFID, NULL);
	}
	
	if (a->addr != NULL) {
		env->SetObjectField(obj, pcapAddrAddrFID, newPcapSockaddr(env, a->addr));
	} else {
		env->SetObjectField(obj, pcapAddrAddrFID, NULL);
	}
	
	if (a->netmask != NULL) {
		env->SetObjectField(obj, pcapAddrNetmaskFID, newPcapSockaddr(env, a->netmask));
	} else {
		env->SetObjectField(obj, pcapAddrNetmaskFID, NULL);
	}
	
	if (a->broadaddr != NULL) {
		env->SetObjectField(obj, pcapAddrBroadaddrFID, newPcapSockaddr(env, a->broadaddr));
	} else {
		env->SetObjectField(obj, pcapAddrBroadaddrFID, NULL);
	}

	if (a->dstaddr != NULL) {
		env->SetObjectField(obj, pcapAddrDstaddrFID, newPcapSockaddr(env, a->dstaddr));
	} else {
		env->SetObjectField(obj, pcapAddrDstaddrFID, NULL);
	}
	
	return obj;
}

jobject newPcapSockaddr(JNIEnv *env, sockaddr *a) {
	jobject obj = env->AllocObject(pcapSockaddrClass);

	env->SetShortField(obj, pcapSockaddrFamilyFID, (jshort) a->sa_family);
		
	if (a->sa_family == AF_INET) {
		jbyteArray jarray = env->NewByteArray(4);
		env->SetByteArrayRegion(jarray, 0, 4, (jbyte *)(a->sa_data + 2));
		
		env->SetObjectField(obj, pcapSockaddrDataFID, jarray);
	} else if (a->sa_family == AF_INET6) {
		jbyteArray jarray = env->NewByteArray(16);
		env->SetByteArrayRegion(jarray, 0, 16, (jbyte *)(a->sa_data + 2));
		
		env->SetObjectField(obj, pcapSockaddrDataFID, jarray);
	} else {
		printf("Unknow sockaddr family=%d\n", a->sa_family);
	}

	return obj;
}
