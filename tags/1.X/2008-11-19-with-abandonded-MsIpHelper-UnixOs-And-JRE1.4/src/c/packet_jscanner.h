/* Header for jnetpcap_utils utility methods */

#ifndef _Included_jnetpcap_packet_jscanner_h
#define _Included_jnetpcap_packet_jscanner_h
#ifdef __cplusplus

#include "export.h"
#include "org_jnetpcap_packet_JScanner.h"
#include "org_jnetpcap_packet_JRegistry.h"
#include "org_jnetpcap_packet_JProtocol.h"
#include <jni.h>

/******************************
 ******************************
 */

#define MAX_ID_COUNT org_jnetpcap_packet_JRegistry_MAX_ID_COUNT
#define MAX_ENTRY_COUNT org_jnetpcap_packet_JScanner_MAX_ENTRY_COUNT
#define FLAG_OVERRIDE_LENGTH org_jnetpcap_packet_JRegistry_FLAG_OVERRIDE_LENGTH
#define FLAG_OVERRIDE_BINDING org_jnetpcap_packet_JRegistry_FLAG_OVERRIDE_BINDING

#define PAYLOAD_ID org_jnetpcap_packet_JProtocol_PAYLOAD_ID

/******************************
 ******************************
 */
extern jclass jheaderScannerClass;

extern 	jmethodID scanHeaderMID;


/******************************
 ******************************
 */

// Forward references
struct scanner_t;
struct packet_state_t;
struct header_t;
struct scan_t;

/*
 * Array of function pointers. These functions perform a per protocol scan
 * and return the next header. They also return the length of the header in
 * the supplied int pointer.
 */
void init_native_protocols();
typedef void (*native_protocol_func_t)(scan_t *scan);

extern native_protocol_func_t native_protocols[];
extern char *native_protocol_names[];
void callJavaHeaderScanner(scan_t *scan);

extern char str_buf[1024];



// Structure maintains state for the duration of the scan in progress
typedef struct scan_t {
	JNIEnv *env;
	jobject jscanner;
	jobject jpacket;
	jobject jscan; // This structure as a java object
	scanner_t *scanner;
	packet_state_t *packet;
	header_t * header;
	char *buf;
	int   buf_len;
	int offset;
	int length;
	int id;
	int next_id;
	
} scan_t;

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

typedef struct scanner_t {
	int32_t sc_len; // bytes allocated for sc_packets buffer
	
	int32_t sc_offset; // offset into sc_packets for next packet

	uint32_t sc_flags[MAX_ID_COUNT]; // protocol flags
	
	jobject sc_jscan; // Java JScan structure for interacting with java space

	jobject sc_java_header_scanners[MAX_ID_COUNT]; // java scanners
	
	/*
	 * A per scanner instance table that can be populated with native and
	 * java scanners at the same time.
	 */
	native_protocol_func_t sc_scan_table[MAX_ID_COUNT];
	
	packet_state_t *sc_packet; // ptr into scanner_t where the first packet begins
} scanner_t;



/******************************
 ******************************
 */

int scan(JNIEnv *env, jobject obj, jobject jpacket, scanner_t *scanner, packet_state_t *packet,
		int first_id, char *buf, int buf_length);

int scanJPacket(JNIEnv *env, jobject obj, jobject jpacket, jobject jstate, scanner_t *scanner, int first_id, char *buf,
		int buf_length);

int scanJavaBinding(scan_t *scan);

uint64_t toUlong64(JNIEnv *env, jintArray ja);

jint findHeaderById(packet_state_t *packet, jint id, jint instance);

char *id2str(int id);

#endif
#endif
