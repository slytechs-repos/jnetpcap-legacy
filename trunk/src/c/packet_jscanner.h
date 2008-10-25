/* Header for jnetpcap_utils utility methods */

#ifndef _Included_jnetpcap_packet_jscanner_h
#define _Included_jnetpcap_packet_jscanner_h
#ifdef __cplusplus

#include "export.h"
#include "org_jnetpcap_packet_JScanner.h"
#include <jni.h>

/******************************
 ******************************
 */

#define MAX_ID_COUNT org_jnetpcap_packet_JScanner_MAX_ID_COUNT
#define MAX_BINDING_COUNT org_jnetpcap_packet_JScanner_MAX_BINDING_COUNT
#define MAX_ENTRY_COUNT org_jnetpcap_packet_JScanner_MAX_ENTRY_COUNT

#define PAYLOAD_ID org_jnetpcap_packet_JProtocol_PAYLOAD_ID

/******************************
 ******************************
 */
extern jclass jdependencyClass;
extern jclass jbindingClass;

extern 	jmethodID listDependenciesMID;
extern 	jmethodID getIdMID;
extern 	jmethodID jbindingCheckLengthMID;


/******************************
 ******************************
 */

typedef struct header_t {
	int32_t hdr_id; // header ID
	uint32_t hdr_offset; // offset into the packet_t->data buffer
	int32_t hdr_length; // length of the header in packet_t->data buffer
} header_t;

typedef struct packet_state_t {
	uint64_t pkt_header_map; // bit map of presence of headers
	char *pkt_data; // packet data buffer
	int32_t pkt_header_count; // total number of headers found

	// Keep track of how many instances of each header we have
	uint8_t pkt_instance_counts[MAX_ID_COUNT];
	header_t pkt_headers[]; // One per header + 1 more for payload
} packet_state_t;

typedef struct binding_t {
	int32_t bnd_id; // ID of the header that this binding is for
	// Map of required headers that must already processed in this packet
	uint64_t bnd_dependency_map;
	jobject bnd_jbinding; // JBinding object
} java_binding_t;

typedef struct scanner_t {
	int32_t sc_len; // bytes allocated for sc_packets buffer
	int32_t sc_offset; // offset into sc_packets for next packet
	uint64_t sc_binding_map; // bit mapping of java bindings 
	packet_state_t *sc_packet; // ptr into scanner_t where the first packet begins

	// Cumulative map of dependencies that must already exist in the packet
	uint64_t sc_dependency_map[MAX_ID_COUNT];

	// Overrides CORE protocol bindings
	uint64_t sc_override_map[MAX_ID_COUNT];

	// Array of binding structures; The second array is NULL terminated 
	binding_t sc_bindings[MAX_ID_COUNT][MAX_BINDING_COUNT];
} scanner_t;

/******************************
 ******************************
 */

int scan(JNIEnv *env, jobject obj, jobject jpacket, scanner_t *scanner, packet_state_t *packet,
		int first_id, char *buf, int buf_length);

int scanJPacket(JNIEnv *env, jobject obj, jobject jpacket, jobject jstate, scanner_t *scanner, int first_id, char *buf,
		int buf_length);

int scanJavaBinding(JNIEnv *env, jobject obj, jobject jpacket, scanner_t *scanner,
		packet_state_t *packet, int offset, int id, char *buf, int buf_length, header_t *header);

uint64_t toUlong64(JNIEnv *env, jintArray ja);

jint findHeaderById(packet_state_t *packet, jint id, jint instance);

#endif
#endif
