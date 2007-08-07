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

jclass pcapClass = NULL;
jclass byteBufferClass = NULL;
jclass stringBuilderClass = NULL;
jclass pcapIfClass = NULL;
jclass pcapAddrClass = NULL;
jclass pcapSockaddrClass = NULL;
jclass pcapStatClass = NULL;

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

jfieldID pcapStatRecvFID = 0;
jfieldID pcapStatDropFID = 0;
jfieldID pcapStatIfDropFID = 0;
jfieldID pcapStatCaptFID = 0;

jmethodID pcapConstructorMID = 0;
jmethodID pcapIfConstructorMID = 0;
jmethodID pcapSockaddrConstructorMID = 0;
jmethodID pcapAddrConstructorMID = 0;
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
EXTERN void JNICALL Java_org_jnetpcap_Pcap_initIDs
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

	// PcapPktbuffer class
	if ( (c = findClass(env, "org/jnetpcap/PcapPktbuffer")) == NULL) {
		return;
	}

	if ( ( pcapPktBufferFID = env->GetFieldID(c, "buffer", "Ljava/nio/ByteBuffer;")) == NULL) {
		throwException(env, NO_SUCH_FIELD_EXCEPTION,
				"Unable to initialize field PcapPktbuffer.buffer:ByteBuffer");
		return;
	}
	
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
	
	
	// PcapBpfProgram class
	if ( (bpfProgramClass = c = findClass(env, "org/jnetpcap/PcapBpfProgram")) == NULL) {
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

jmethodID findMethod(JNIEnv *env, jobject obj, char *name, char *signature) {
	jclass clazz = (jclass)env->GetObjectClass(obj);
	if (clazz == NULL) {
		return 0; // Out of memory exception already thrown
	}
	
	jmethodID id;
	if ( (id = env->GetMethodID(clazz, name, signature)) == NULL) {
		throwException(env, NO_SUCH_METHOD_EXCEPTION, name);
		return 0;
	}
	
	env->DeleteLocalRef(clazz);
	
	return id;
}

/*
 * Class:     org_jnetpcap_PcapStat
 * Method:    initIDs
 * Signature: ()V
 */
EXTERN void JNICALL Java_org_jnetpcap_PcapStat_initIDs
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

/**
 * Find class or throw exception if not found.
 * 
 * @return global reference to class that needs to be freed manually before
 *         library exit
 */
jclass findClass(JNIEnv *env, char *name) {
	// List class
	jclass local;
	if ( (local = env->FindClass(name)) == NULL) {
		throwException(env, CLASS_NOT_FOUND_EXCEPTION, name);
		return NULL;
	}
	
	jclass global = (jclass) env->NewGlobalRef(local);
	
	env->DeleteLocalRef(local);
	
	if (global == NULL) {
		return NULL; // Out of memory exception already thrown
	}
	
	return global;
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

/*
 * Function: getPktHeader
 * Description: extracts the contents of PcapPkthdr java object into a
 *              pcap_pkthdr structure.
 * Return: the supplied structured filled in or if null, new allocated one.
 */
pcap_pkthdr *getPktHeader(JNIEnv *env, jobject jpkt_header, pcap_pkthdr *pkt_header) {
	
	if (pkt_header == NULL) {
		pkt_header = (pcap_pkthdr *) malloc(sizeof(pcap_pkthdr));
	}

	pkt_header->ts.tv_sec = (int) env->GetLongField(jpkt_header, pcapPkthdrSecondsFID);

	pkt_header->ts.tv_usec = (int) env->GetIntField(jpkt_header, pcapPkthdrUSecondsFID);

	pkt_header->caplen = (int) env->GetIntField(jpkt_header, pcapPkthdrCaplenFID);

	pkt_header->len = (int) env->GetIntField(jpkt_header, pcapPkthdrLenFID);
	
	return pkt_header;
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
 * Creates a new instance of Java PcapIf object, intializes all of its fields
 * from pcap_if_t structure and add the resulting element to jlist which is
 * a Java java.util.List object. The method id is cached but has to discovered
 * upon the first entry into findDevsAll since we don't know exactly the type
 * of actual object implementing the List interface. Could be ArrayList,
 * LinkedList or some other custom list. So that is the reason for the dynamic
 * methodID lookup. We pass the ID along to reuse it through out the life of
 * this recursive scan.
 * 
 * @param obj Pcap
 * @param jlist java.util.list to which we will add this PcapIf element
 * @param MID_add cached dynamic method ID of the "add" method
 * @param ifp pcap_if_t structure to use in construction of java counter part
 * @return PcapIf
 */
jobject newPcapIf(JNIEnv *env, jobject jlist, jmethodID MID_add, pcap_if_t *ifp) {
	jobject js;

	// Invoke new PcapIf()
	jobject obj = env->NewObject(pcapIfClass, pcapIfConstructorMID);
	
	/*
	 * Initialize PcapIf.next field. Also add the new PcapIf object that went
	 * into the field to the use supplied jlist.
	 */ 
	if (ifp->next != NULL) {
		jobject jpcapif = newPcapIf(env, jlist, MID_add, ifp->next);
		if (jpcapif == NULL) {
			return NULL; // Out of memory exception already thrown
		}
		
		env->SetObjectField(obj, pcapIfNextFID, jpcapif);
		if (env->CallBooleanMethod(jlist, MID_add, jpcapif) == JNI_FALSE) {
			env->DeleteLocalRef(jpcapif);
			return NULL; // Failed to add to the list
		}
		
		env->DeleteLocalRef(jpcapif);
	} else {
		env->SetObjectField(obj, pcapIfNextFID, NULL);
	}
	
	/**
	 * Assign PcapIf.name string field.
	 */
	if (ifp->name != NULL) {
		js = env->NewStringUTF(ifp->name);
		if (js == NULL) {
			return NULL; // Out of memory exception already thrown
		}
		
		env->SetObjectField(obj, pcapIfNameFID, js);
		
		env->DeleteLocalRef(js);
		
	} else {
		env->SetObjectField(obj, pcapIfNameFID, NULL);
	}
	
	/**
	 * Assign PcapIf.description string field.
	 */
	if (ifp->description != NULL) {
		js = env->NewStringUTF(ifp->description);
		if (js == NULL) {
			return NULL; // Out of memory exception already thrown
		}
		env->SetObjectField(obj, pcapIfDescriptionFID, js);
		
		env->DeleteLocalRef(js);
	} else {
		env->SetObjectField(obj, pcapIfDescriptionFID, NULL);
	}
	
	/**
	 * Add all addresses found in pcap_if.address linked list of sockaddr to
	 * the already Java allocated list in the PcapIf.addresses field.
	 */
	if (ifp->addresses != NULL) {
		
		// Lookup field and the List object from PcapIf.addresses field
		jobject jaddrlist = env->GetObjectField(obj, pcapIfAddressesFID);
		if (jaddrlist == NULL) {
			return NULL; // Exception already thrown
		}
		
		// Lookup List.add method ID within the object, can't be static as this
		// is a interface lookup, not a known object type implementing the
		// interface
		jmethodID MID_addr_add = findMethod(env, jaddrlist, "add", 
				"(Ljava/lang/Object;)Z");
		if (MID_addr_add == NULL) {
			env->DeleteLocalRef(jaddrlist);
			return NULL; // Exception already thrown
		}
		
		// Process the structure and get the next addr
		jobject jaddr = newPcapAddr(env, jaddrlist, MID_addr_add, ifp->addresses);
		if (jaddr == NULL) {
			env->DeleteLocalRef(jaddrlist);
			return NULL; // Out of memory exception already thrown
		}
		
		// Call on List.add method to add our new PcapAddr object
		if (env->CallBooleanMethod(jaddrlist, MID_addr_add, jaddr) == JNI_FALSE) {
			env->DeleteLocalRef(jaddrlist);
			env->DeleteLocalRef(jaddr);
			return NULL; // Failed to add to the list
		}
		
		// Release local resources
		env->DeleteLocalRef(jaddr);
		env->DeleteLocalRef(jaddrlist);
	}
	
	env->SetIntField(obj, pcapIfFlagsFID, (jint) ifp->flags);
	
	return obj;
}

jobject newPcapAddr(JNIEnv *env, jobject jlist, jmethodID MID_add, pcap_addr *a) {
	jobject obj = env->NewObject(pcapAddrClass, pcapAddrConstructorMID);

	if (a->next != NULL) {
		jobject jaddr = newPcapAddr(env, jlist, MID_add, a->next);
		if (jaddr == NULL) {
			env->DeleteLocalRef(jaddr);
			return NULL;
		}
		
		// Set the next field for the hell of it, not accessed in java 
		env->SetObjectField(obj, pcapAddrNextFID, jaddr);

		// Call List.add method to add our PcapAddr object
		if (env->CallBooleanMethod(jlist, MID_add, jaddr) == JNI_FALSE) {
			env->DeleteLocalRef(jaddr);
			return NULL;
		}
		
	} else {
		env->SetObjectField(obj, pcapAddrNextFID, NULL);
	}
	
	jobject jsock;
	if (a->addr != NULL) {
		if ( (jsock = newPcapSockaddr(env, a->addr)) == NULL) {
			return NULL;
		}
		
		env->SetObjectField(obj, pcapAddrAddrFID, jsock);
	} else {
		env->SetObjectField(obj, pcapAddrAddrFID, NULL);
	}
	
	if (a->netmask != NULL) {
		if ( (jsock = newPcapSockaddr(env, a->netmask)) == NULL) {
			return NULL;
		}
		env->SetObjectField(obj, pcapAddrNetmaskFID, jsock);
	} else {
		env->SetObjectField(obj, pcapAddrNetmaskFID, NULL);
	}
	
	if (a->broadaddr != NULL) {
		if ( (jsock = newPcapSockaddr(env, a->broadaddr)) == NULL) {
			return NULL;
		}
		env->SetObjectField(obj, pcapAddrBroadaddrFID, jsock);
	} else {
		env->SetObjectField(obj, pcapAddrBroadaddrFID, NULL);
	}

	if (a->dstaddr != NULL) {
		if ( (jsock = newPcapSockaddr(env, a->dstaddr)) == NULL) {
			return NULL;
		}
		env->SetObjectField(obj, pcapAddrDstaddrFID, jsock);
	} else {
		env->SetObjectField(obj, pcapAddrDstaddrFID, NULL);
	}
	
	return obj;
}

jobject newPcapSockaddr(JNIEnv *env, sockaddr *a) {
	jobject obj = env->NewObject(pcapSockaddrClass, pcapSockaddrConstructorMID);

	env->SetShortField(obj, pcapSockaddrFamilyFID, (jshort) a->sa_family);
		
	if (a->sa_family == AF_INET) {
		jbyteArray jarray = env->NewByteArray(4);
		env->SetByteArrayRegion(jarray, 0, 4, (jbyte *)(a->sa_data + 2));
		
		env->SetObjectField(obj, pcapSockaddrDataFID, jarray);
		
		env->DeleteLocalRef(jarray);
	} else if (a->sa_family == AF_INET6) {
		jbyteArray jarray = env->NewByteArray(16);
		env->SetByteArrayRegion(jarray, 0, 16, (jbyte *)(a->sa_data + 2));
		
		env->SetObjectField(obj, pcapSockaddrDataFID, jarray);
		env->DeleteLocalRef(jarray);
	} else {
		jbyteArray jarray = env->NewByteArray(14); // Has to be atleast 14 bytes
		env->SetByteArrayRegion(jarray, 0, 14, (jbyte *)(a->sa_data + 2));
		
		env->SetObjectField(obj, pcapSockaddrDataFID, jarray);
		env->DeleteLocalRef(jarray);

//		printf("Unknow sockaddr family=%d\n", a->sa_family);
	}

	return obj;
}

void setPcapStat(JNIEnv *env, jobject jstats, pcap_stat *stats) {
	
	env->SetLongField(jstats, pcapStatRecvFID, (jlong) stats->ps_recv);
	env->SetLongField(jstats, pcapStatDropFID, (jlong) stats->ps_drop);
	env->SetLongField(jstats, pcapStatIfDropFID, (jlong) stats->ps_ifdrop);
}
