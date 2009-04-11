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

#ifdef WIN32
#include <winsock2.h>
#include <iphlpapi.h>
#endif /*WIN32*/

#include "jnetpcap_ids.h"

#include "jnetpcap_utils.h"
#include "jnetpcap_bpf.h"
#include "nio_jmemory.h"
#include "export.h"




/*****************************************************************************
 * UTILITY METHODS
 */

const char *toCharArray(JNIEnv *env, jstring jstr, char *buf) {
	
	const char *s = env->GetStringUTFChars(jstr, NULL);
	strcpy(buf, s);
	
	env->ReleaseStringUTFChars(jstr, s);
	
	return buf;
}

jstring toJavaString(JNIEnv *env, const char *buf) {
	jstring s = env->NewString((jchar *)buf, (jsize) strlen(buf));
	
	return s;
}

jlong toLong(void *ptr) {
#ifndef WIN32
	jlong lp = (intptr_t) ptr;
#else
	jlong lp = (UINT_PTR) ptr;
#endif

	return lp;
}

void *toPtr(jlong lp) {
	
#ifndef WIN32
	void *ptr = (void *) ((intptr_t) lp);
#else
	void *ptr = (void *) ((UINT_PTR) lp);
#endif


	return ptr;
}

/*****************************************************************************
 *  These are static and constant unless class file reloads
 */


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


pcap_t *getPcap(JNIEnv *env, jobject obj) {
	jlong pt = env->GetLongField(obj, pcapPhysicalFID);

	if (pt == 0) {
		throwException(env, PCAP_CLOSED_EXCEPTION, NULL);

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

	env->SetLongField(jpkt_header, PcapPktHdrSecondsFID,
			(jlong)pkt_header->ts.tv_sec);

	env->SetIntField(jpkt_header, PcapPktHdrUSecondsFID,
			(jint)pkt_header->ts.tv_usec);

	env->SetIntField(jpkt_header, PcapPktHdrCaplenFID, (jint)pkt_header->caplen);

	env->SetIntField(jpkt_header, PcapPktHdrLenFID, (jint)pkt_header->len);
}

/*
 * Function: getPktHeader
 * Description: extracts the contents of PcapPktHdr java object into a
 *              pcap_pkthdr structure.
 * Return: the supplied structured filled in or if null, new allocated one.
 */
pcap_pkthdr *getPktHeader(JNIEnv *env, jobject jpkt_header, pcap_pkthdr *pkt_header) {
	
	if (pkt_header == NULL) {
		pkt_header = (pcap_pkthdr *) malloc(sizeof(pcap_pkthdr));
	}

	pkt_header->ts.tv_sec = (int) env->GetLongField(jpkt_header, PcapPktHdrSecondsFID);

	pkt_header->ts.tv_usec = (int) env->GetIntField(jpkt_header, PcapPktHdrUSecondsFID);

	pkt_header->caplen = (int) env->GetIntField(jpkt_header, PcapPktHdrCaplenFID);

	pkt_header->len = (int) env->GetIntField(jpkt_header, PcapPktHdrLenFID);
	
	return pkt_header;
}

void setPktBuffer(JNIEnv *env, jobject jpkt_buffer, jobject jbuffer) {
	env->SetObjectField(jpkt_buffer, PcapPktBufferFID, jbuffer);
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

/*
 * Throws specified exception with message to java. Any method calling on
 * this utility class, needs to make sure it returns as this exception does
 * not transfer control to back to java like it is in Java language, but returns
 * immediately.
 */
void throwVoidException(JNIEnv *env, const char *excClassName) {
	jclass clazz = env->FindClass(excClassName);

	jmethodID constructorMID;
	if ( (constructorMID = env->GetMethodID(clazz, "<init>", "()V")) == NULL) {
		throwException(env, NO_SUCH_FIELD_EXCEPTION,
				"Unable to initialize exception class ");
		return;
	}

	if (clazz != NULL) {
		jthrowable exception = (jthrowable)env->NewObject(clazz, constructorMID);
		env->Throw(exception);
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
		if ( (jsock = newPcapSockAddr(env, a->addr)) == NULL) {
			return NULL;
		}
		
		env->SetObjectField(obj, pcapAddrAddrFID, jsock);
	} else {
		env->SetObjectField(obj, pcapAddrAddrFID, NULL);
	}
	
	if (a->netmask != NULL) {
		if ( (jsock = newPcapSockAddr(env, a->netmask)) == NULL) {
			return NULL;
		}
		env->SetObjectField(obj, pcapAddrNetmaskFID, jsock);
	} else {
		env->SetObjectField(obj, pcapAddrNetmaskFID, NULL);
	}
	
	if (a->broadaddr != NULL) {
		if ( (jsock = newPcapSockAddr(env, a->broadaddr)) == NULL) {
			return NULL;
		}
		env->SetObjectField(obj, pcapAddrBroadaddrFID, jsock);
	} else {
		env->SetObjectField(obj, pcapAddrBroadaddrFID, NULL);
	}

	if (a->dstaddr != NULL) {
		if ( (jsock = newPcapSockAddr(env, a->dstaddr)) == NULL) {
			return NULL;
		}
		env->SetObjectField(obj, pcapAddrDstaddrFID, jsock);
	} else {
		env->SetObjectField(obj, pcapAddrDstaddrFID, NULL);
	}
	
	return obj;
}

jobject newPcapSockAddr(JNIEnv *env, sockaddr *a) {
	jobject obj = env->NewObject(PcapSockAddrClass, PcapSockAddrConstructorMID);

	env->SetShortField(obj, PcapSockAddrFamilyFID, (jshort) a->sa_family);
		
	if (a->sa_family == AF_INET) {
		jbyteArray jarray = env->NewByteArray(4);
		env->SetByteArrayRegion(jarray, 0, 4, (jbyte *)(a->sa_data + 2));
		
		env->SetObjectField(obj, PcapSockAddrDataFID, jarray);
		
		env->DeleteLocalRef(jarray);
	} else if (a->sa_family == AF_INET6) {
		jbyteArray jarray = env->NewByteArray(16);
		env->SetByteArrayRegion(jarray, 0, 16, (jbyte *)(a->sa_data + 2));
		
		env->SetObjectField(obj, PcapSockAddrDataFID, jarray);
		env->DeleteLocalRef(jarray);
	} else {
		jbyteArray jarray = env->NewByteArray(14); // Has to be atleast 14 bytes
		env->SetByteArrayRegion(jarray, 0, 14, (jbyte *)(a->sa_data + 2));
		
		env->SetObjectField(obj, PcapSockAddrDataFID, jarray);
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

/****************************************************************
 * **************************************************************
 * 
 * MS Ip Helper API calls
 * 
 * **************************************************************
 ****************************************************************/
#ifdef WIN32

/*
 * Get interface info, which contains Adapter[] that has the MIB index
 */
PIP_INTERFACE_INFO getIpInterfaceInfo(void) {

	DWORD size = 0;
	PIP_INTERFACE_INFO  info = NULL;
	
	// Get the require size of the structure
	if (GetInterfaceInfo(info, &size) == ERROR_INSUFFICIENT_BUFFER) {
		info = (PIP_INTERFACE_INFO) malloc(size);
	} else {
		return NULL;
	}
	
	// Now fill in the structure
	GetInterfaceInfo(info, &size);
	
	return info;
}


/*
 * MS get mib row
 */
PMIB_IFROW getMibIfRow (int index) {

	PMIB_IFROW row = (PMIB_IFROW) malloc(sizeof(MIB_IFROW));
	
	row->dwIndex = index;
	
	// Get the require size of the structure
	if (row != NULL && GetIfEntry(row) == NO_ERROR) {
		return row;
	} else {
		return NULL;
	}	
}


#endif // WIN32


/****************************************************************
 * **************************************************************
 * 
 * Java declared native functions
 * 
 * **************************************************************
 ****************************************************************/

/*
 * Class:     org_jnetpcap_PcapUtils
 * Method:    getHardwareAddress
 * Signature: (Ljava/lang/String;)[B
 */
JNIEXPORT jbyteArray JNICALL Java_org_jnetpcap_PcapUtils_getHardwareAddress
  (JNIEnv *env, jclass clazz, jstring jdevice) {
	
#ifndef IFNAMSIZ
#define IFNAMSIZ 512
#endif
	
	jbyteArray jba = NULL;
	char buf[IFNAMSIZ];
	
	// convert from jstring to char *
	toCharArray(env, jdevice, buf);
	
#ifdef WIN32 

	PIP_INTERFACE_INFO info = getIpInterfaceInfo();
	
	if (info == NULL) {
		throwException(env, IO_EXCEPTION, 
				"unable to retrieve interface info");
		return NULL;
	}
	
	for (int i = 0; i < info->NumAdapters; i ++) {
		PIP_ADAPTER_INDEX_MAP map = &info->Adapter[i];
		
		
		/*
		 * Name is in wide character format. So convert to plain UTF8.
		 */
		int size=WideCharToMultiByte(0, 0, map->Name, -1, NULL, 0, NULL, NULL);
		char utf8[size + 1];
		WideCharToMultiByte(0, 0, map->Name, -1, utf8, size, NULL, NULL);
		
#ifdef DEBUG
		printf("#%d name=%s buf=%s\n", i, utf8, buf); fflush(stdout);
#endif
		
		char *p1 = strchr(utf8, '{');
		char *p2 = strchr(buf,  '{');
		
		if(p1 == NULL || p2 == NULL) {
			p1 = utf8;
			p2 = buf;
		}

		if (strcmp(p1, p2) == 0) {
			PMIB_IFROW row = getMibIfRow(map->Index);
#ifdef DEBUG
			printf("FOUND index=%d len=%d\n", map->Index, row->dwPhysAddrLen); fflush(stdout);
#endif
			
			jba = env->NewByteArray((jsize) row->dwPhysAddrLen);
			
			env->SetByteArrayRegion(jba, (jsize) 0, (jsize) row->dwPhysAddrLen, 
					(jbyte *)row->bPhysAddr);
			
			free(row);
		}
	}
	
	free(info);
	
#else
	
   struct ifreq ifr;
   
   int sd = socket(PF_INET, SOCK_DGRAM, 0);
    if (sd < 0) {
		throwException(env, IO_EXCEPTION, "cannot open socket.");
        return NULL; // error: can't create socket.
    }

    /* set interface name (lo, eth0, eth1,..) */
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_ifrn.ifrn_name,buf, IFNAMSIZ);

    /* get a Get Interface Hardware Address */
    if (ioctl(sd, SIOCGIFHWADDR, &ifr) != 0) {
	return NULL;
    }

    close(sd);

    jba = env->NewByteArray((jsize) 6);
    env->SetByteArrayRegion(jba, 0, 6, (const jbyte *)ifr.ifr_ifru.ifru_hwaddr.sa_data);
#endif
	
	return jba;
}

/*
 * Legacy ByteBuffer dispatch function - deprecated.
 */
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
	if (buffer == NULL) {
		env->DeleteLocalRef(buffer);
		return;
	}

	env->CallNonvirtualVoidMethod(
			data->obj, 
			data->clazz, 
			data->mid,
			(jobject) data->user, 
			(jlong) pkt_header->ts.tv_sec,
			(jint)pkt_header->ts.tv_usec, 
			(jint)pkt_header->caplen,
			(jint)pkt_header->len, buffer);
	
	env->DeleteLocalRef(buffer);
	if (env->ExceptionCheck() == JNI_TRUE) {
		data->exception = env->ExceptionOccurred();
	}
}

/**
 * ByteBuffer dispatcher that allocates a new java.nio.ByteBuffer and dispatches
 * it to java listener.
 */
void cb_byte_buffer_dispatch(u_char *user, const pcap_pkthdr *pkt_header,
		const u_char *pkt_data) {

	cb_byte_buffer_t *data = (cb_byte_buffer_t *)user;

	JNIEnv *env = data->env;
	
	setJMemoryPhysical(env, data->header, toLong((void*)pkt_header));

	jobject buffer = env->NewDirectByteBuffer((void *)pkt_data,
			pkt_header->caplen);
	if (buffer == NULL) {
		return;
	}
	
	env->CallVoidMethod(
			data->obj, 
			data->mid, 
			(jobject) data->header,
			(jobject) buffer,
			(jobject) data->user);
	
	env->DeleteLocalRef(buffer);
	
	if (env->ExceptionCheck() == JNI_TRUE) {
		data->exception = env->ExceptionOccurred();
	}
}

/**
 * JBuffer dispatcher that dispatches JBuffers, without allocating the buffer
 */
void cb_jbuffer_dispatch(u_char *user, const pcap_pkthdr *pkt_header,
		const u_char *pkt_data) {

	cb_jbuffer_t *data = (cb_jbuffer_t *)user;

	JNIEnv *env = data->env;
	
	setJMemoryPhysical(env, data->header, toLong((void*)pkt_header));
	setJMemoryPhysical(env, data->buffer, toLong((void*)pkt_data));

	env->SetIntField(data->header, jmemorySizeFID, (jsize) sizeof(pcap_pkthdr));
	env->SetIntField(data->buffer, jmemorySizeFID, (jsize) pkt_header->caplen);

	env->SetObjectField(data->header, jmemoryKeeperFID, data->pcap);
	env->SetObjectField(data->buffer, jmemoryKeeperFID, data->pcap);
	
	env->CallVoidMethod(
			data->obj, 
			data->mid, 
			data->header, 
			data->buffer,
			data->user);
	
	if (env->ExceptionCheck() == JNI_TRUE) {
		data->exception = env->ExceptionOccurred();
	}
}

/**
 * JPacket dispatcher that dispatches decoded java packets
 */
void cb_jpacket_dispatch(u_char *user, const pcap_pkthdr *pkt_header,
		const u_char *pkt_data) {

	cb_jpacket_t *data = (cb_jpacket_t *)user;

	JNIEnv *env = data->env;
	
	setJMemoryPhysical(env, data->header, toLong((void*)pkt_header));
	setJMemoryPhysical(env, data->packet, toLong((void*)pkt_data));
	
	env->SetIntField(data->header, jmemorySizeFID, (jsize) sizeof(pcap_pkthdr));
	env->SetIntField(data->packet, jmemorySizeFID, (jsize) pkt_header->caplen);

	env->SetObjectField(data->header, jmemoryKeeperFID, data->pcap);
	env->SetObjectField(data->packet, jmemoryKeeperFID, data->pcap);

	if (Java_org_jnetpcap_packet_JScanner_scan(
			data->env, 
			data->scanner, 
			data->packet,
			data->state,
			data->id) < 0) {
		return;
	}

	env->CallVoidMethod(
			data->obj,
			data->mid, 
			data->packet,
			data->user);
	
	if (env->ExceptionCheck() == JNI_TRUE) {
		data->exception = env->ExceptionOccurred();
	}
}

/**
 * JPacket dispatcher that dispatches decoded java packets
 */
void cb_pcap_packet_dispatch(u_char *user, const pcap_pkthdr *pkt_header,
		const u_char *pkt_data) {

	cb_jpacket_t *data = (cb_jpacket_t *)user;

	JNIEnv *env = data->env;
	
	setJMemoryPhysical(env, data->header, toLong((void*)pkt_header));
	setJMemoryPhysical(env, data->packet, toLong((void*)pkt_data));
	
	env->SetIntField(data->header, jmemorySizeFID, (jsize) sizeof(pcap_pkthdr));
	env->SetIntField(data->packet, jmemorySizeFID, (jsize) pkt_header->caplen);

	env->SetObjectField(data->header, jmemoryKeeperFID, data->pcap);
	env->SetObjectField(data->packet, jmemoryKeeperFID, data->pcap);

	if (Java_org_jnetpcap_packet_JScanner_scan(
			data->env, 
			data->scanner, 
			data->packet,
			data->state,
			data->id) < 0) {
		return;
	}

	env->CallVoidMethod(
			data->obj,
			data->mid, 
			data->packet,
			data->user);
	
	if (env->ExceptionCheck() == JNI_TRUE) {
		data->exception = env->ExceptionOccurred();
	}
}


