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

#include "nio_jmemory.h"
#include "packet_jscanner.h"
#include "jnetpcap_utils.h"
#include "org_jnetpcap_packet_JHeaderScanner.h"
#include "export.h"

/****************************************************************
 * **************************************************************
 * 
 * Java declared native functions
 * 
 * **************************************************************
 ****************************************************************/

/*
 * Class:     org_jnetpcap_packet_JHeaderScanner
 * Method:    bindNativeScanner
 * Signature: (I)V
 */
JNIEXPORT void JNICALL Java_org_jnetpcap_packet_JHeaderScanner_bindNativeScanner
(JNIEnv *env, jobject obj, jint id) {
	
	jnp_enter("JHeaderScanner_bindNativeScanner");


	if (id < 0 || id > MAX_ID_COUNT) {
		sprintf(str_buf, "invalid ID=%d (%s)", id, id2str(id));
		throwException(env, UNREGISTERED_SCANNER_EXCEPTION, str_buf);
		jnp_exit_error();
		return;
	}

	if (native_protocols[id] == NULL) {
		
		sprintf(str_buf, "native scanner not registered under ID=%d (%s)", 
				id,
				id2str((int)id));
		throwException(env, UNREGISTERED_SCANNER_EXCEPTION,	str_buf);
		jnp_exit_error();
		return;
	}

	if (jpeer_obj_direct(env, obj, (char *)native_protocols[id], 0, NULL)) {
		jnp_exit_error();
		return;
	}
	
	jnp_exit_OK();
}

/*
 * Class:     org_jnetpcap_packet_JHeaderScanner
 * Method:    nativeScan
 * Signature: (Lorg/jnetpcap/packet/JScan;)V
 */
JNIEXPORT void JNICALL Java_org_jnetpcap_packet_JHeaderScanner_nativeScan
(JNIEnv *env, jobject obj, jobject jscan) {
	jnp_enter("JHeaderScanner_nativeScan");

	native_protocol_func_t func = (native_protocol_func_t)jmem_data_ro_get(env, obj);
	if (func == NULL) {
		jnp_exit_error();
		return;
	}

	scan_t *scan = (scan_t *)jmem_data_get(env, jscan);
	if (jscan == NULL) {
		jnp_exit_error();
		return;
	}

	// Dispatch to function pointer
	func(scan);
	jnp_exit_OK();
}

