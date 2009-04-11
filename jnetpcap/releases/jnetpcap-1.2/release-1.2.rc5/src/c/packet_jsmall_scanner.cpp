/***************************************************************************
 * Copyright (C) 2007, Sly Technologies, Inc                               *
 * Distributed under the Lesser GNU Public License  (LGPL)                 *
 ***************************************************************************/

/*
 * Utility file that provides various conversion methods for chaging objects
 * back and forth between C and Java JNI.
 */

#include <stdio.h>
#include <stdint.h>
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

#include "packet_jscanner.h"
#include "packet_protocol.h"
#include "jnetpcap_utils.h"
#include "nio_jmemory.h"
#include "nio_jbuffer.h"
#include "org_jnetpcap_protocol_JProtocol.h"
#include "export.h"

/****************************************************************
 * **************************************************************
 * 
 * NON Java declared native functions. Private scan function
 * 
 * **************************************************************
 ****************************************************************/
char str_buf[1024];
char id_str_buf[256];

/*
 * Converts our numerical header ID to a string, which is better suited for
 * debugging.
 */
char *id2str(int id) {

	if (id == END_OF_HEADERS) {
		return "END_OF_HEADERS";

	} else if (native_protocol_names[id] != NULL) {
		return native_protocol_names[id];

	} else {
		sprintf(id_str_buf, "%d", id);

		return id_str_buf;
	}
}

/**
 * Scan packet buffer
 */
int scan(JNIEnv *env, jobject obj, jobject jpacket, scanner_t *scanner,
		packet_state_t *p_packet, int first_id, char *buf, int buf_len) {

	scan_t scan; // Our current in progress scan's state information
	scan.env = env;
	scan.jscanner = obj;
	scan.jpacket = jpacket;
	scan.scanner = scanner;
	scan.packet = p_packet;
	scan.header = &p_packet->pkt_headers[0];
	scan.buf = buf;
	scan.buf_len = buf_len;
	scan.offset = 0;
	scan.length = 0;
	scan.id = first_id;
	scan.next_id = PAYLOAD_ID;

	// Point jscan 
	setJMemoryPhysical(env, scanner->sc_jscan, toLong(&scan));

	// Local temp variables
	register uint64_t mask;

//#define DEBUG

#ifdef DEBUG
	printf("\n\n");
#endif

	/*
	 * Main scanner loop, 1st scans for builtin header types then
	 * reverts to calling on JBinding objects to provide the binding chain
	 */
	while (scan.id != END_OF_HEADERS) {
#ifdef DEBUG
		printf("scan() loop-top   : id=%-16s offset=%-4d flags=%d\n",
				id2str(scan.id), scan.offset, scanner->sc_flags[scan.id]);
#endif

		/* 
		 * Scan of each protocol is done through a dispatch function table.
		 * Each protocol that has a protocol header scanner attached, a scanner
		 * designed specifically for that protocol. The protocol id is also the
		 * index into the table. There are 2 types of scanners both have exactly
		 * the same signature and thus both are set in this table. The first is
		 * the native scanner that only performs a direct scan of the header.
		 * The second scanner is a java header scanner. It is based on 
		 * JHeaderScanner class. A single dispatch method callJavaHeaderScanner
		 * uses the protocol ID to to dispatch to the appropriate java scanner.
		 * Uses a separate java specific table: sc_java_header_scanners[]. The
		 * java scanner is capable of calling the native scan method from java
		 * but also adds the ability to check all the attached JBinding[] for
		 * any additional registered bindings. Interesting fact is that if the
		 * java scanner doesn't have any bindings nor does it override the 
		 * default scan method to perform a scan in java and is also setup to 
		 * dispatch to native scanner, it is exactly same thing as if the 
		 * native scanner was dispatched directly from here, but round 
		 * about way through java land.
		 */
		if (scanner->sc_scan_table[scan.id] != NULL) {
			scanner->sc_scan_table[scan.id](&scan); // Dispatch to scanner
		}

#ifdef DEBUG
		printf("scan() loop-middle: id=%-16s offset=%-4d nid=%s length=%d\n",
				id2str(scan.id), scan.offset, id2str(scan.next_id), scan.length);
#endif

		if (scan.length == 0) {
#ifdef DEBUG
			printf("scan() loop-length==0\n");
#endif
			if (scan.id == PAYLOAD_ID) {
				scan.next_id = END_OF_HEADERS;
			} else {
				scan.next_id = PAYLOAD_ID;
			}

		} else { // length != 0

#ifdef DEBUG
			printf("scan() loop-length: %d\n", scan.length);
#endif

			/******************************************************
			 * ****************************************************
			 * * Now record discovered information in structures
			 * ****************************************************
			 ******************************************************/
			record_header(&scan);
		} // End if len != 0

#ifdef DEBUG
		printf("scan() loop-bottom: id=%-16s offset=%-4d nid=%s length=%d\n",
				id2str(scan.id), scan.offset, id2str(scan.next_id), scan.length);
#endif

		scan.id = scan.next_id;
		scan.next_id = PAYLOAD_ID;
		scan.length = 0;
	} // End for loop

	/* record number of header entries found */
	//	scan.packet->pkt_header_count = count;
	
	process_flow_key(&scan);

#ifdef DEBUG
	printf("scan() finished   : header_count=%d offset=%d header_map=0x%X\n",
			scan.packet->pkt_header_count, scan.offset,
			scan.packet->pkt_header_map);

	fflush(stdout);
#endif

	return scan.offset;
} // End scan()

/**
 * Record state of the header in the packet state structure.
 */
void record_header(scan_t *scan) {
#ifdef DEBUG
	printf(
			"scan() loop-record: id=%-16s offset=%-4d nid=%s length=%d\n",
			id2str(scan.id), scan.offset, id2str(scan.next_id),
			scan.length);
#endif
	
	/*
	 * Check if already recorded
	 */
	if (scan->id == -1) {
		return;
	}
	/*
	 * Initialize the header entry in our packet header array
	 */
	scan->packet->pkt_header_map |= (1 << scan->id);
	scan->header->hdr_id = scan->id;
	scan->header->hdr_offset = scan->offset;
	scan->header->hdr_analysis = NULL;

	/*
	 * Adjust for truncated packets
	 */
	scan->length
			= ((scan->length > scan->buf_len - scan->offset) ? scan->buf_len
					- scan->offset
					: scan->length);

	scan->header->hdr_length = scan->length;
	scan->offset += scan->length;
	scan->header ++; /* point to next header entry *** ptr arithmatic */
	scan->packet->pkt_header_count ++; /* number of entries */
	
	scan->id = -1; // Indicates, that header is already recorded
}

/**
 * Scan packet buffer by dispatching to JBinding java objects
 */
void callJavaHeaderScanner(scan_t *scan) {

	JNIEnv *env = scan->env;
	jobject jscanner = scan->scanner->sc_java_header_scanners[scan->id];

	if (jscanner == NULL) {
		sprintf(str_buf, "java header scanner not set for ID=%d (%s)",
				scan->id, id2str(scan->id));
#ifdef DEBUG
		fprintf(stdout, "scan() jscaner-ERR: %s\n", str_buf);
		fflush(stdout);
#endif
		throwException(scan->env, NULL_PTR_EXCEPTION, str_buf);
		return;
	}

	env->CallVoidMethod(jscanner, scanHeaderMID, scan->scanner->sc_jscan);
}

/**
 * Prepares a scan of packet buffer
 */
int scanJPacket(JNIEnv *env, jobject obj, jobject jpacket, jobject jstate,
		scanner_t *scanner, int first_id, char *buf, int buf_length) {

	/* Check if we need to wrap our entry buffer around */
	if (scanner->sc_offset > scanner->sc_len - sizeof(header_t)
			* MAX_ENTRY_COUNT) {
		scanner->sc_offset = 0;
	}

	packet_state_t *packet =(packet_state_t *)(((char *)scanner->sc_packet)
			+ scanner->sc_offset);
	
	/*
	 * Peer JPacket.state to packet_state_t structure
	 */
	setJMemoryPhysical(env, jstate, toLong(packet));
	env->SetObjectField(jstate, jmemoryKeeperFID, obj); // Set it to JScanner
	
	/*
	 * Reset the entire packet_state_t structure
	 */
	memset(packet, 0, sizeof(packet_state_t));

	/* 
	 * Initialize the packet_state_t structure for new packet entry. We need to 
	 * initialize everything since we may be wrapping around and writting over 
	 * previously stored data.
	 */
	packet->pkt_header_map = 0;
	packet->pkt_header_count = 0;
	packet->pkt_frame_num = scanner->sc_cur_frame_num ++;

	scanner->sc_offset +=scan(env, obj, jpacket, scanner, packet, first_id,
			buf, buf_length);

	env->SetIntField(jstate, jmemorySizeFID, (jsize) sizeof(packet_state_t)
			+ sizeof(header_t) * packet->pkt_header_count);
}


/****************************************************************
 * **************************************************************
 * 
 * Java declared native functions
 * 
 * **************************************************************
 ****************************************************************/

jclass jheaderScannerClass = NULL;

jmethodID scanHeaderMID = 0;

/*
 * Class:     org_jnetpcap_packet_JScanner
 * Method:    initIds
 * Signature: ()V
 */
JNIEXPORT void JNICALL Java_org_jnetpcap_packet_JScanner_initIds
(JNIEnv *env, jclass clazz) {

	if ( (jheaderScannerClass = findClass(
							env,
							"org/jnetpcap/packet/JHeaderScanner")) == NULL) {
		return;
	}

	if ( (scanHeaderMID = env->GetMethodID(
							jheaderScannerClass,
							"scanHeader",
							"(Lorg/jnetpcap/packet/JScan;)V")) == NULL) {
		return;
	}

	/*
	 * Initialize the global native scan function dispatch table.
	 * i.e. scan_ethernet(), scan_ip4(), etc...
	 */
	init_native_protocols();
}

/*
 * Class:     org_jnetpcap_packet_JScanner
 * Method:    sizeof
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_org_jnetpcap_packet_JScanner_sizeof
(JNIEnv *env, jclass obj) {
	return (jint)sizeof(scanner_t);
}

/*
 * Class:     org_jnetpcap_packet_JScanner
 * Method:    cleanup_jscanner
 * Signature: ()V
 */
JNIEXPORT void JNICALL Java_org_jnetpcap_packet_JScanner_cleanup_1jscanner
(JNIEnv *env, jobject obj) {

	scanner_t *scanner = (scanner_t *)getJMemoryPhysical(env, obj);
	if (scanner == NULL) {
		return;
	}

	env->DeleteGlobalRef(scanner->sc_jscan);
	scanner->sc_jscan = NULL;

	for (int i = 0; i < MAX_ID_COUNT; i ++) {
		if (scanner->sc_java_header_scanners[i] != NULL) {
			env->DeleteGlobalRef(scanner->sc_java_header_scanners[i]);
			scanner->sc_java_header_scanners[i] = NULL;
		}
	}
}

/*
 * Class:     org_jnetpcap_packet_JScanner
 * Method:    init
 * Signature: (Lorg.jnetpcap.packet.JScan;)V
 */
JNIEXPORT void JNICALL Java_org_jnetpcap_packet_JScanner_init
(JNIEnv *env, jobject obj, jobject jscan) {

	if (jscan == NULL) {
		throwException(env, NULL_PTR_EXCEPTION,
				"JScan parameter can not be null");
		return;
	}

	void *block = (char *)getJMemoryPhysical(env, obj);
	size_t size = (size_t)env->GetIntField(obj, jmemorySizeFID);

	memset(block, 0, size);

	scanner_t *scanner = (scanner_t *)block;
	scanner->sc_jscan = env->NewGlobalRef(jscan);
	scanner->sc_len = size - sizeof(scanner_t);
	scanner->sc_offset = 0;
	scanner->sc_packet = (packet_state_t *)((char *)block + sizeof(scanner_t));

	for (int i = 0; i < MAX_ID_COUNT; i++) {
		scanner->sc_scan_table[i] = native_protocols[i];
	}
}

/*
 * Class:     org_jnetpcap_packet_JScanner
 * Method:    loadScanners
 * Signature: (I[Lorg/jnetpcap/packet/JHeaderScanner;)V
 */
JNIEXPORT void JNICALL Java_org_jnetpcap_packet_JScanner_loadScanners
(JNIEnv *env, jobject obj, jobjectArray jascanners) {
	scanner_t *scanner = (scanner_t *)getJMemoryPhysical(env, obj);
	if (scanner == NULL) {
		return;
	}

	jsize size = env->GetArrayLength(jascanners);

#ifdef DEBUG
	printf("loadScanners(): loaded %d scanners\n", (int)size);
#endif

	if (size != MAX_ID_COUNT) {
		throwException(env,
				ILLEGAL_ARGUMENT_EXCEPTION,
				"size of array must be MAX_ID_COUNT size");
		return;
	}

	for (int i = 0; i < MAX_ID_COUNT; i ++) {
		jobject loc_ref = env->GetObjectArrayElement(jascanners, (jsize) i);
		if (loc_ref == NULL) {

			/*
			 * If we don't have a java header scanner, then setup the native
			 * scanner in its place. Any unused java scanner slot will be filled
			 * with native scanner.
			 */
			scanner->sc_scan_table[i] = native_protocols[i];
		} else {

			/*
			 * Record the java header scanner and replace the native scanner with
			 * our java scanner in dispatch table.
			 */
			scanner->sc_java_header_scanners[i] = env->NewGlobalRef(loc_ref);
			scanner->sc_scan_table[i] = callJavaHeaderScanner;

			env->DeleteLocalRef(loc_ref);
		}
	}
}

/*
 * Class:     org_jnetpcap_packet_JScanner
 * Method:    scan
 * Signature: (Lorg/jnetpcap/packet/JPacket;Lorg/jnetpcap/packet/JPacket$State;I)I
 */
JNIEXPORT jint JNICALL Java_org_jnetpcap_packet_JScanner_scan
(JNIEnv *env, jobject obj, jobject jpacket, jobject jstate, jint id) {

	scanner_t *scanner = (scanner_t *)getJMemoryPhysical(env, obj);
	if (scanner == NULL) {
		return -1;
	}

	char *buf = (char *)getJMemoryPhysical(env, jpacket);
	if (buf == NULL) {
		return -1;
	}

	int size = (int)env->GetIntField(jpacket, jmemorySizeFID);

	return scanJPacket(env, obj, jpacket, jstate, scanner, id, buf, size);
}

