/***************************************************************************
 * Copyright (C) 2007, Sly Technologies, Inc                               *
 * Distributed under the Lesser GNU Public License  (LGPL)                 *
 ***************************************************************************/

/*
 * Utility file that provides various conversion methods for chaging objects
 * back and forth between C and Java JNI.
 */
#include "export.h"

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

/*******************************************************************************
 * Pcap.java IDs
 ******************************************************************************/
jclass pcapClass = NULL;
jclass byteBufferClass = NULL;
jclass stringBuilderClass = NULL;

jfieldID pcapPhysicalFID = 0;

jmethodID pcapConstructorMID = 0;
jmethodID appendMID = 0;
jmethodID setLengthMID = 0;
/*
 * Class:     org_jnetpcap_Pcap
 * Method:    initIDs
 * Signature: ()V
 * Description: Initializes all of the jmethodID, jclass and jfieldIDs that are
 *              used by the entire collection of Pcap JNI related methods.
 *              This method only needs to be called once for all Pcap related
 *              classes. We do a lot of checks here and throw appropriate
 *              exceptions when something is not found. This is neccessary since
 *              no further runtime checks are performed after this initialization.
 */
JNIEXPORT void JNICALL Java_org_jnetpcap_Pcap_initIDs
(JNIEnv *env, jclass clazz) {

	pcapClass = (jclass) env->NewGlobalRef(clazz); // This one is easy

	if ( (pcapConstructorMID = env->GetMethodID(clazz, "<init>", "()V")) == NULL) {
		throwException(env, NO_SUCH_METHOD_EXCEPTION,
				"Unable to initialize constructor Pcap.Pcap()");
		return;
	}

	if ( (pcapPhysicalFID = env->GetFieldID(clazz, "physical", "J")) == NULL) {
		throwException(env, NO_SUCH_FIELD_EXCEPTION,
				"Unable to initialize field Pcap.physical:long");
		return;
	}

	if ( (byteBufferClass = findClass(env, "java/nio/ByteBuffer")) == NULL) {
		return;
	}

	if ( (stringBuilderClass = findClass(env, "java/lang/StringBuilder")) == NULL) {
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
}

/*******************************************************************************
 * PcapPkthdr.java IDs
 ******************************************************************************/
jfieldID pcapPkthdrSecondsFID = 0;
jfieldID pcapPkthdrUSecondsFID = 0;
jfieldID pcapPkthdrCaplenFID = 0;
jfieldID pcapPkthdrLenFID = 0;

jfieldID PcapPktBufferFID = 0;

/*
 * Class:     org_jnetpcap_PcapPkthdr
 * Method:    initIDs
 * Signature: ()V
 */
JNIEXPORT void JNICALL Java_org_jnetpcap_PcapPkthdr_initIDs
(JNIEnv *env, jclass clazz) {
	jclass c;
	// PcapPkthdr class
	if ( (c = findClass(env, "org/jnetpcap/PcapPkthdr")) == NULL) {
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

	// PcapPktBuffer class
	if ( (c = findClass(env, "org/jnetpcap/PcapPktBuffer")) == NULL) {
		return;
	}

	if ( ( PcapPktBufferFID = env->GetFieldID(c, "buffer", "Ljava/nio/ByteBuffer;")) == NULL) {
		throwException(env, NO_SUCH_FIELD_EXCEPTION,
				"Unable to initialize field PcapPktBuffer.buffer:ByteBuffer");
		return;
	}


}

/*******************************************************************************
 * PcapAddr.java IDs
 ******************************************************************************/
jclass pcapAddrClass = NULL;
jfieldID pcapAddrNextFID = 0;
jfieldID pcapAddrAddrFID = 0;
jfieldID pcapAddrNetmaskFID = 0;
jfieldID pcapAddrBroadaddrFID = 0;
jfieldID pcapAddrDstaddrFID = 0;
jmethodID pcapAddrConstructorMID = 0;

/*
 * Class:     org_jnetpcap_PcapIf
 * Method:    initIDs
 * Signature: ()V
 */
JNIEXPORT void JNICALL Java_org_jnetpcap_PcapAddr_initIDs
(JNIEnv *env, jclass clazz) {
	
	jclass c;
	// PcapAddr class
	if ( (pcapAddrClass = c = findClass(env, "org/jnetpcap/PcapAddr")) == NULL) {
		throwException(env, CLASS_NOT_FOUND_EXCEPTION,
				"Unable to initialize class org.jnetpcap.PcapAddr");
		return;
	}

	if ( (pcapAddrConstructorMID = env->GetMethodID(c, "<init>", "()V")) == NULL) {
		throwException(env, NO_SUCH_METHOD_EXCEPTION,
				"Unable to initialize constructor org.jnetpcap.PcapAddr()");
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
}
	
/*******************************************************************************
 * PcapIf.java IDs
 ******************************************************************************/
jclass pcapIfClass = NULL;
jfieldID pcapIfNextFID = 0;
jfieldID pcapIfNameFID = 0;
jfieldID pcapIfDescriptionFID = 0;
jfieldID pcapIfAddressesFID = 0;
jfieldID pcapIfFlagsFID = 0;jmethodID pcapIfConstructorMID = 0;

/*
 * Class:     org_jnetpcap_PcapIf
 * Method:    initIDs
 * Signature: ()V
 */
JNIEXPORT void JNICALL Java_org_jnetpcap_PcapIf_initIDs
(JNIEnv *env, jclass clazz) {
	jclass c;
	// PcapIf class
	if ( (pcapIfClass = c = findClass(env, "org/jnetpcap/PcapIf")) == NULL) {
		throwException(env, CLASS_NOT_FOUND_EXCEPTION,
				"Unable to initialize class org.jnetpcap.PcapIf");
		return;
	}

	if ( (pcapIfConstructorMID = env->GetMethodID(c, "<init>", "()V")) == NULL) {
		throwException(env, NO_SUCH_METHOD_EXCEPTION,
				"Unable to initialize constructor org.jnetpcap.PcapIf()");
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

	if ( ( pcapIfAddressesFID = env->GetFieldID(c, "addresses", "Ljava/util/List;")) == NULL) {
		throwException(env, NO_SUCH_FIELD_EXCEPTION,
				"Unable to initialize field PcapIf.addresses:List");
		return;
	}

	if ( ( pcapIfFlagsFID = env->GetFieldID(c, "flags", "I")) == NULL) {
		throwException(env, NO_SUCH_FIELD_EXCEPTION,
				"Unable to initialize field PcapIf.flags:int");
		return;
	}

}

/*******************************************************************************
 * PcapSockaddr.java IDs
 ******************************************************************************/
jclass pcapSockaddrClass = NULL;
jfieldID pcapSockaddrFamilyFID = 0;
jfieldID pcapSockaddrDataFID = 0;
jmethodID pcapSockaddrConstructorMID = 0;

/*
 * Class:     org_jnetpcap_PcapSockaddr
 * Method:    initIDs
 * Signature: ()V
 */
JNIEXPORT void JNICALL Java_org_jnetpcap_PcapSockaddr_initIDs
(JNIEnv *env, jclass clazz) {
	jclass c;
	
	// PcapSockaddr class
	if ( (pcapSockaddrClass = c = findClass(env, "org/jnetpcap/PcapSockaddr")) == NULL) {
		throwException(env, CLASS_NOT_FOUND_EXCEPTION,
				"Unable to initialize class org.jnetpcap.PcapSockaddr");
		return;
	}

	if ( (pcapSockaddrConstructorMID = env->GetMethodID(c, "<init>", "()V")) == NULL) {
		throwException(env, NO_SUCH_METHOD_EXCEPTION,
				"Unable to initialize constructor org.jnetpcap.PcapSockaddr()");
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

}

/*******************************************************************************
 * PcapStat.java IDs
 ******************************************************************************/

jclass pcapStatClass = NULL;

jfieldID pcapStatRecvFID = 0;
jfieldID pcapStatDropFID = 0;
jfieldID pcapStatIfDropFID = 0;
jfieldID pcapStatCaptFID = 0;

/*
 * Class:     org_jnetpcap_PcapStat
 * Method:    initIDs
 * Signature: ()V
 */
JNIEXPORT void JNICALL Java_org_jnetpcap_PcapStat_initIDs
(JNIEnv *env, jclass clazz) {

	pcapStatClass = (jclass) env->NewGlobalRef(clazz); // This one is easy

	if ( (pcapStatRecvFID = env->GetFieldID(clazz, "recv", "J")) == NULL) {
		throwException(env, NO_SUCH_FIELD_EXCEPTION,
				"Unable to initialize field PcapStat.recv:long");
		return;
	}

	if ( (pcapStatDropFID = env->GetFieldID(clazz, "drop", "J")) == NULL) {
		throwException(env, NO_SUCH_FIELD_EXCEPTION,
				"Unable to initialize field PcapStat.drop:long");
		return;
	}

	if ( (pcapStatIfDropFID = env->GetFieldID(clazz, "ifDrop", "J")) == NULL) {
		throwException(env, NO_SUCH_FIELD_EXCEPTION,
				"Unable to initialize field PcapStat.ifDrop:long");
		return;
	}

	if ( (pcapStatCaptFID = env->GetFieldID(clazz, "capt", "J")) == NULL) {
		throwException(env, NO_SUCH_FIELD_EXCEPTION,
				"Unable to initialize field PcapStat.capt:long");
		return;
	}
}

