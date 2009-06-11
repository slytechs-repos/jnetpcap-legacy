/* Header for jnetpcap_utils utility methods */

#ifndef _Included_jnetpcap_packet_jscanner_h
#define _Included_jnetpcap_packet_jscanner_h
#ifdef __cplusplus

#include <stdint.h>

#include "export.h"
#include "org_jnetpcap_packet_JScanner.h"
#include "org_jnetpcap_packet_JRegistry.h"
#include "org_jnetpcap_protocol_JProtocol.h"
#include "packet_flow.h"
#include <jni.h>

/******************************
 ******************************
 */

#define MAX_ID_COUNT org_jnetpcap_packet_JRegistry_MAX_ID_COUNT
#define MAX_ENTRY_COUNT org_jnetpcap_packet_JScanner_MAX_ENTRY_COUNT
#define FLAG_OVERRIDE_LENGTH org_jnetpcap_packet_JRegistry_FLAG_OVERRIDE_LENGTH
#define FLAG_OVERRIDE_BINDING org_jnetpcap_packet_JRegistry_FLAG_OVERRIDE_BINDING

#define PAYLOAD_ID org_jnetpcap_protocol_JProtocol_PAYLOAD_ID

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
void record_header(scan_t *scan);

extern char str_buf[1024];



/*
 * Structure maintains state for the duration of the scan in progress
 * 
 * The structure keeps track of the packet buffer and 3 types of lengths. 
 * 1) mem_len is the actual total length of the buffer in memory
 * 2) wire_len is the length of the original packet when it was captured before
 *    it was truncated
 * 3) buf_len is the runtime/effectual length of the buffer used by the scanner
 *    methods. This length may shrink if a protocol uses postfix for padding
 *    or some kind of trailer. The buf_len field is reduced by the scanner
 *    for that header by the appropriate amount so that next header doesn't 
 *    consider the previous header's postfix as valid part of the packet it
 *    needs to decode.
 */
typedef struct scan_t {
	JNIEnv *env;
	jobject jscanner;
	jobject jpacket;
	jobject jscan; // This structure as a java object
	scanner_t *scanner;
	
	packet_state_t *packet;
	header_t *header;
	char *buf;
	int   buf_len;  
	int   wire_len;
	int   mem_len;
	int offset;
	int length;
	int id;
	int next_id;	
} scan_t;

/*
 * Each header "record" may have the following physical structure:
 * +-------------------------------------------+
 * | prefix | header | gap | payload | postfix |
 * +-------------------------------------------+
 * 
 * Offset points at the start of the header, not the prefix. In order to calculate
 * the exact start of the record, you must subtract the prefix length from the 
 * offset as follows:
 * 
 * prefix_offset = hdr_offset - hdr_prefix;
 * 
 * To calculate the offset of the start of the payload:
 * 
 * payload_offset = hdr_offset + hdr_length + hdr_gap;
 * 
 * To calculate the offset of the start of the postfix
 * 
 * postfix_offset = hdr_offset + hdr_length + hdr_gap + hdr_payload;
 * 
 * To calculate the end of the header record:
 * 
 * end_offset = hdr_offset + hdr_length + hdr_gap + hdr_payload + hdr_postifx;
 * 
 * Note that most of the time the fields hdr_prefix, hdr_gap and hdr_postfix
 * will be zero, but this structure does allow a more complex headers in a 
 * frame to exist. Some protocols have prefixes such Ethernet2 frames on BSD 
 * systems and a trailer (represented as a postfix) which may contains padding,
 * CRC counters etc. Rtp header for example utilizes padding after its payload
 * and so do many other protocols. As of right now, the author is not aware of
 * any protocols utilizing an inter header-to-payload gap, which is another way
 * of saying a header-padding. None the less, the structure for gap is 
 * represented here for future compatibility.
 */
typedef struct header_t {
	uint8_t  hdr_id;         // header ID
	uint8_t  hdr_flags;      // flags for this header
	
	uint8_t  hdr_prefix;     // length of the prefix (preamble) before the header 
	uint32_t hdr_offset;     // offset into the packet_t->data buffer
	uint32_t hdr_length;     // length of the header in packet_t->data buffer
	uint8_t  hdr_gap;        // length of the gap between header and payload
	uint32_t hdr_payload;    // length of the payload
	uint16_t hdr_postfix;    // length of the postfix (trailer) after the payload
	
	jobject  hdr_analysis;   // Java JAnalysis based object if not null
} header_t;

typedef struct packet_state_t {
	uint8_t pkt_flags;       // flags for this packet
	flow_key_t pkt_flow_key; // Flow key calculated for this packet, must be first
	jobject pkt_analysis;    // Java JAnalysis based object if not null
	uint64_t pkt_frame_num;  // Packet's frame number assigned by scanner
	uint64_t pkt_header_map; // bit map of presence of headers
	int8_t pkt_header_count; // total number of headers found

	header_t pkt_headers[];  // One per header + 1 more for payload
} packet_state_t;

typedef struct scanner_t {
	int32_t sc_len; // bytes allocated for sc_packets buffer
	
	int32_t sc_offset; // offset into sc_packets for next packet
	uint64_t sc_cur_frame_num; // Current frame number

	uint32_t sc_flags[MAX_ID_COUNT]; // protocol flags
//	uint64_t sc_native_header_scanner_map;  // java binding map
	
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
