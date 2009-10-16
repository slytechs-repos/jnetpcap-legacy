
// Include this file after jni.h is included. It undefines MS compiler, def for
// gcc specific one.
//
#ifndef Include_nap_record_h
#define Include_nap_record_h

#include <stdint.h>

#include "nap_types.h"
#include "nap_buf.h"

#ifdef __cplusplus
extern "C" {
#define	EXTERN extern "C"
#endif


//#define NAP_SECTION_TEMPLATE	0x0

#define NAP_RECORD_FLAGS			0x0
#define NAP_RECORD_RESERVED			0x0

#define NAP_RECORD_TYPE_NOOP		0
#define NAP_RECORD_TYPE_SECTION		1
#define NAP_RECORD_TYPE_PAYLOAD		2
#define NAP_RECORD_TYPE_META		3
#define NAP_RECORD_TYPE_VENDOR		4

#define NAP_PAYLOAD_PACKET			1
#define NAP_PAYLOAD_SIMPLE			2

#define NAP_SECTION_RECORD_FLAGS	NAP_RECORD_FLAGS
#define NAP_SECTION_MAJOR			1
#define NAP_SECTION_MINOR			0
#define NAP_SECTION_MAGIC_LITTLE	0x12AA3BB4
#define NAP_SECTION_MAGIC_BIG		0xB43BAA12
#define NAP_SECTION_MAGIC			0x12AA3BB4
#define NAP_SECTION_PAYLOAD_TYPE	NAP_PAYLOAD_PACKET
#define NAP_SECTION_FLAGS			0

#define NAP_SECTION_MAX_SUPPORTED_VERSION	0x10	

#define NAP_RECORD_HEADER_LENGTH			8
#define NAP_RECORD_TRAILER_LENGTH			4
#define NAP_RECORD_MIN_LENGTH	\
	(NAP_RECORD_HEADER_LENGTH + NAP_RECORD_TRAILER_LENGTH)

/**
 * Standard record header/prefix to every record type.
 * Base header is always 8 bytes long. Enough to ensure that the basic record
 * information can be specified and read. Each specific record type further
 * adds additional structure to the record header and data.
 * 
 * <pre>
 *    0       4       8       12      16      20      24      28      32
 *    |-----Type------+-----Flags-----+-------+---Sub Type----+-------| 
 *    |   1   |   10  |C:D:I:P:0:0:0:0|     Major     |     Minor     |  
 *    |-------+-------+-------+-------+-------+-------+-------+-------| 
 *    |                         Record Length                         | 
 *    |-------+-------+-------+-------+-------+-------+-------+-------| 
 *    ~                          Record Data                          ~
 *    +- - - - - - - - - - - - - - - - - - - - - - - -+-------+-------+
 *    |                                               |  Pad Length   |
 *    |-------+-------+-------+-------+-------+-------+-------+-------|
 *    |                         Record Length                         |
 *    |-------+-------+-------+-------+-------+-------+-------+-------|
 * 
 * </pre>
 * 
 * Flags:
 *  C = Compressed record
 *  D = Disabled record
 *  P = Padded record (last byte before trailer contains length of pad)
 *  I = OK to Ignore this record (not mandatory interpretation)
 * 
 * Type: 
 *   type field is devided into a "type" and a "hdr_length" fields. Header
 *   length contains number of 4-byte words the header takes up (10 in example
 *   above or 40 bytes)
 * 
 * Sub Type:
 *   Has different meanings for different types of records. 
 * 
 *   For Section record: is divided up into major/minor version numbers for 
 *   the NAP spec of the library that created this section.
 * 
 *   For Vendor records: contains the "vendor id" that has been assigned to 
 *   a particular vendor. The record structure is interpreted according to
 *   that vendor's specificiation.
 * 
 *   For Meta records: meta record specific sub-type, as per part of spec.
 * 
 *   For No-Op records: its always 0
 */
typedef struct nap_record_hdr {
	
	struct {
		/**
		 * The type of record this is
		 */
		uint8_t		type:4;
		
		/**
		 * Length of this header
		 */
		uint8_t		len:4;
	} hdr;
	
	/**
	 * Various flags for this record.
	 */
	uint8_t		flags; // Record type specific
	
	union {
		/**
		 * Sub-type of this record.
		 */
		uint16_t sub_type; // Record type specific
		struct { // Major/minor version in type == SECTION record
			uint8_t	major;
			uint8_t	minor;
		} ver;
	
		/**
		 * Vendor ID in a type == VENDOR record.
		 */
		uint16_t	vendor_id;
	} u1;	
		
	/**
	 * Length of this record in octets
	 */
	uint32_t	length;	
} nap_record_hdr;

typedef struct nap_record_trailer {
	uint32_t	length;
} nap_record_trailer;

/**
 * A section record.
 */
typedef struct nap_section_hdr {
	nap_record_hdr	hdr;
	uint32_t		magic;
	uint16_t		flags;
	uint16_t		reserved;
	uint8_t			uuid[16];
	uint32_t		payload_sub_type:8;
	uint32_t		payload_count:24;
} nap_section_hdr;


/**
 * A PAYLOAD/packet record.
 */
typedef struct nap_packet_hdr {
	nap_record_hdr	hdr;
} nap_packet_hdr;

/**
 * A PAYLOAD/simple-packet record.
 */
typedef struct nap_simple_hdr {
	nap_record_hdr	hdr;
} nap_simple_hdr;

/**
 * A NO-OP record.
 */
typedef struct nap_noop_hdr {
	nap_record_hdr	hdr;
} nap_noop_hdr;

/**
 * A Meta/NIC record.
 */
typedef struct nap_nic_hdr {
	nap_record_hdr	hdr;
} nap_nic_hdr;

/**
 * A Meta/Index record.
 */
typedef struct nap_index_hdr {
	nap_record_hdr	hdr;
	
	uint16_t	options:1;
	uint16_t	type:3;
	uint16_t	sub_type:12; // Record type specific
	uint16_t	reserved; 
	
	uint32_t	length;		 // Index of this last payload record
	uint32_t	index;		 // Index of this last payload record
	uint32_t	previous;	 // Offset of previous index-record of this type
	uint32_t	next;		 // Offset of next index-record, or 0 if last one

} nap_index_hdr;

typedef struct nap_record_info{
	offset_t					offset;
	nap_file					nap;
	struct nap_record_info			*parent;
	struct nap_record_inforailer	*trailer;
	void						*data;
	
	union {
		struct nap_record_hdr	*record;
		struct nap_section_hdr	*section;
		struct nap_packet_hdr	*packet;
		struct nap_simple_hdr	*simple;
		struct nap_noop_hdr		*noop;
		struct nap_nic_hdr		*nic;
		struct nap_index_hdr	*index;
		void					*generic;
	} u;
} nap_record_info;


typedef nap_record_info nap_section_info;
typedef nap_record_info nap_packet_info;
typedef nap_record_info nap_simple_info;
typedef nap_record_info nap_noop_info;
typedef nap_record_info nap_nic_info;
typedef nap_record_info nap_index_info;

/*
 * PROTOTYPES
 * Record specific FILE operations
 */
int nap_record_read(FILE *fp, nap_record_hdr *record);
int nap_record_write(FILE *fp, nap_record_hdr *record);
int nap_record_trailer_read(FILE *fp, uint32_t *length);
int nap_record_trailer_write(FILE *fp, uint32_t length);

/*
 * PROTOTYPES
 * Record within a section specific iterator operations
 */
int nap_record_iterator_open(nap_buf_state_t *buf_state, 
		offset_t offset, size_t len, nap_record_iterator *iterator);
int nap_record_iterator_open_section(
		nap_section_info *section, nap_record_iterator *iterator);
int nap_record_iterator_close(nap_record_iterator iterator);
int nap_record_has_next(nap_record_iterator iterator);
int nap_record_next(nap_record_iterator iterator, nap_record_hdr **record);
int nap_record_has_prev(nap_record_iterator iterator);
int nap_record_prev(nap_record_iterator iterator, nap_record_hdr **record);
offset_t nap_record_pos(nap_record_iterator iterator);
int nap_record_seek_next(nap_record_iterator iterator);
int nap_record_seek_prev(nap_record_iterator iterator);
int nap_record_seek_first(nap_record_iterator iterator);
int nap_record_seek_last(nap_record_iterator iterator);
int nap_record_seek_type(nap_record_iterator iterator, int record_type);
int nap_record_seek_sub_type(nap_record_iterator iterator, int record_type, int sub_type);

/*
 * PROTOTYPES
 * Record within a section specific indexer operations
 */
int nap_record_indexer_open(nap_section_info *section, nap_record_indexer *indexer);
int nap_record_indexer_close(nap_record_indexer indexer);
int nap_record_count(nap_record_indexer indexer);
int nap_record_get(nap_record_indexer indexer, index_t index, nap_record_hdr *record);
int nap_record_find_type(nap_record_indexer indexer, int record_type);
int nap_record_find_sub_type(nap_record_indexer indexer, int record_type, int sub_type);

/*
 * PROTOTYPES
 * Record within a section specific editor operations
 */
int nap_record_editor_create(nap_handle nap, nap_record_editor *editor);
int nap_record_editor_open(nap_section_info *section, nap_record_editor *editor);
int nap_record_editor_close(nap_record_editor);
int nap_record_editor_flush(nap_record_editor editor);
int nap_record_append(nap_record_editor editor, nap_record_hdr *record);
int nap_record_disable(nap_record_editor editor, nap_record_hdr *record);

/*
 * PROTOTYPES
 * Record within a section specific editor operations
 */
int nap_record_dumper_create(nap_handle nap, nap_record_dumper *dumper);
int nap_record_dumper_open(nap_section_info *section, nap_record_dumper *dumper);
int nap_record_dumper_close(nap_record_dumper);
int nap_record_dumper_flush(nap_record_dumper dumper);
int nap_record_dump(nap_record_dumper dumper, nap_record_hdr *record, void *data);
int nap_record_disable(nap_record_dumper dumper, nap_record_hdr *record);

/*
 * PROTOTYPES
 * Section specific FILE operations
 */
int nap_section_load(nap_file nap, nap_section_info *section);
int nap_section_write(FILE *fp, nap_section_hdr *section);
int nap_section_read(FILE *fp, nap_section_hdr *section);
int nap_section_init(nap_section_hdr *section);

/*
 * PROTOTYPES
 * Section specific iterator operations
 */
int nap_section_iterator_open(nap_file nap, nap_section_iterator *iterator);
int nap_section_iterator_close(nap_section_iterator iterator);
int nap_section_has_next(nap_section_iterator iterator);
int nap_section_next(nap_section_iterator iterator, nap_section_hdr **section);
int nap_section_next_info(nap_section_iterator iterator, nap_section_info *info);
int nap_section_has_prev(nap_section_iterator iterator);
int nap_section_prev(nap_section_iterator iterator, nap_section_hdr **section);
int nap_section_prev_info(nap_section_iterator iterator, nap_section_info *info);
int nap_section_seek_first(nap_section_iterator iterator);
int nap_section_seek_last(nap_section_iterator iterator);
int nap_section_seek_uuid(nap_section_iterator iterator, nap_uuid_t uuid);

/*
 * PROTOTYPES
 * Section specific indexer operations
 */
int nap_section_indexer_open(nap_file nap, nap_section_indexer *indexer);
int nap_section_indexer_close(nap_section_indexer indexer);
int nap_section_count(nap_section_indexer indexer, size_t *count);
int nap_section_get(nap_section_indexer indexer, index_t index, nap_section_hdr **section);
int nap_section_get_info(nap_section_indexer indexer, index_t index, nap_section_info *info);
int nap_section_find_uuid(nap_section_indexer indexer, nap_uuid_t uuid, index_t *index);

/*
 * PROTOTYPES
 * Section specific editor operations
 */
int nap_section_editor_open(nap_file nap, nap_section_editor *editor);
int nap_section_editor_close(nap_section_editor editor);
int nap_section_editor_flush(nap_section_editor editor);
int nap_section_edit(nap_section_editor editor, nap_section_info *section);
int nap_section_append(nap_section_editor editor, nap_section_hdr *section);
int nap_section_disable(nap_section_editor editor, nap_section_hdr *section);

#endif
#ifdef __cplusplus
}
#endif
