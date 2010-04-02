/* Header for jnetpcap_utils utility methods */

#ifndef _Included_nio_jmemory_h
#define _Included_nio_jmemory_h
#ifdef __cplusplus
#include <exception>
extern "C" {
#define	EXTERN extern "C"
#endif

#include <stdint.h>
#include "export.h"

#include <jni.h>
#include "org_jnetpcap_nio_JMemory.h"
#include "jnp.h"
#include "jnetpcap_utils.h"
	
#define JMEM_ERROR(id)			(id | JNP_FAMILY_JMEM | JNP_ERROR)
	
#define JMEM_INACTIVE          	JMEM_ERROR(0)
#define JMEM_NO_HEADER         	JMEM_ERROR(1)
#define JMEM_OUT_OF_BOUNDS     	JMEM_ERROR(2)
#define JMEM_NOT_DATA_NODE     	JMEM_ERROR(3)
#define JMEM_LC_NOT_FOUND      	JMEM_ERROR(4)
#define JMEM_LC_ATTACH_ERROR   	JMEM_ERROR(5)
#define JMEM_ILLEGAL_CONNECT 	JMEM_ERROR(6)
#define JMEM_UNKNOWN_TYPE		JMEM_ERROR(7)
#define JMEM_NULL_OWNER_JREF  	JMEM_ERROR(8)
#define JMEM_PERMISSION       	JMEM_ERROR(8)
#define JMEM_NULL_JMEM_REF    	JMEM_ERROR(10)
#define JMEM_NOT_PEER_NODE    	JMEM_ERROR(11)
#define JMEM_ILLEGAL_PEER     	JMEM_ERROR(12)
#define JMEM_ILLEGAL_TYPE(type) JMEM_ERROR(13), jmem_name(type), type
#define JMEM_WRONG_TYPE(type, ex)JMEM_ERROR(14),jmem_name(type), type, jmem_name(ex), ex
#define JMEM_NOT_CONNECTED    	JMEM_ERROR(15)
#define JMEM_ALREADY_CONNECTED	JMEM_ERROR(16)
#define JMEM_ILLEGAL_TRANSFER 	JMEM_ERROR(17)
#define JMEM_MSG_COUNT        	18

#define JMEM_FALSE   0
#define JMEM_TRUE    1

	
#define JMEMORY_TYPE_BLOCK    org_jnetpcap_nio_JMemory_JMEMORY_TYPE_BLOCK
#define JMEMORY_TYPE_PEER     org_jnetpcap_nio_JMemory_JMEMORY_TYPE_PEER
#define JMEMORY_TYPE_JREF     org_jnetpcap_nio_JMemory_JMEMORY_TYPE_JREF

#define JMEMORY_TYPE_BLOCK_NAME    "BLOCK"
#define JMEMORY_TYPE_PEER_NAME     "PEER"
#define JMEMORY_TYPE_JREF_NAME     "JREF"
#define JMEMORY_TYPE_UNKNOWN_NAME  "UNKNOWN_TYPE"

/*
 * org.jnetpcap.nio.JMemory.class
 */
extern jclass    CLASS_jmemory;
extern jmethodID MID_jmemory_toDebugString;
extern jmethodID MID_jmemory_toString;
extern jfieldID  FID_jmemory_physical;
extern jfieldID  FID_jmemory_POINTER;
extern jobject   JREF_jmemory_POINTER; // JMemory.POINTER constant reference

/*
 * java.nio.Buffer.class - ByteBuffer extends Buffer
 */
extern jclass    CLASS_buffer;
extern jmethodID MID_buffer_isDirect;
extern jmethodID MID_buffer_position;
extern jmethodID MID_buffer_limit;
extern jmethodID MID_buffer_set_position;

/*
 * java.nio.Object.class - Object class methods
 */
extern jclass	CLASS_object;
extern jmethodID MID_object_toString;

/*
 * java.lang.Class.class - Class file operations
 */
extern jclass    CLASS_class;
extern jmethodID MID_class_getName;
extern jmethodID MID_class_getSimpleName;

#define JMEMORY_READ		      org_jnetpcap_nio_JMemory_JMEMORY_FLAG_READ
#define JMEMORY_WRITE             org_jnetpcap_nio_JMemory_JMEMORY_FLAG_WRITE
#define JMEMORY_DIRECT            org_jnetpcap_nio_JMemory_JMEMORY_FLAG_DIRECT
#define JMEMORY_REFERENCE         org_jnetpcap_nio_JMemory_JMEMORY_FLAG_REFERENCE
#define JMEMORY_JAVA_OWNED        org_jnetpcap_nio_JMemory_JMEMORY_FLAG_JAVA_OWNED
#define JMEMORY_ACTIVE            org_jnetpcap_nio_JMemory_JMEMORY_FLAG_ACTIVE
#define JMEMORY_PROXY             org_jnetpcap_nio_JMemory_JMEMORY_FLAG_PROXY
#define JMEMORY_DATA              org_jnetpcap_nio_JMemory_JMEMORY_FLAG_DATA
#define JMEMORY_BIG_ENDIAN        org_jnetpcap_nio_JMemory_JMEMORY_FLAG_BIG_ENDIAN
#define JMEMORY_NO_PEERING        org_jnetpcap_nio_JMemory_JMEMORY_FLAG_NO_PEERING
#define JMEMORY_LC_ATTACHED       org_jnetpcap_nio_JMemory_JMEMORY_FLAG_LC_ATTACHED

#define JMEMORY_DEFAULTS		JMEMORY_READ | \
								JMEMORY_WRITE 

#define JMEMORY_BLOCK_DEFAULTS	JMEMORY_DEFAULTS | JMEMORY_DATA
#define JMEMORY_PEER_DEFAULTS	JMEMORY_DEFAULTS | JMEMORY_DATA
#define JMEMORY_JREF_DEFAULTS	JMEMORY_DEFAULTS
#define JMEMORY_MODE_BITS		JMEMORY_READ | JMEMORY_WRITE

/*
 * Which bits should be carried over when flags are being reset 
 */
#define JMEMORY_CARRYOVER		JMEMORY_DATA | \
								JMEMORY_PROXY | \
								JMEMORY_JAVA_OWNED



typedef struct memory_usage_t {
	uint64_t total_allocated;
	uint64_t total_deallocated;

	uint64_t total_allocate_calls;
	uint64_t total_deallocate_calls;

	uint64_t seg_0_255_bytes;
	uint64_t seg_256_or_above_bytes;
} memory_usage_t;


/**
 * Base structure for all memory objects, with the exception of a chain.
 * 
 * This structure is always prefixed to the memory block being allocated and
 * describes the boundaries of that block. It further allows segments to be
 * attached to the block and when the block is deallocated so are the segments.
 * 
 */
typedef struct jmemory_t {
	uint16_t  type; // memory type
	uint16_t  flags; // User specific flags
	jobject weak_jref;  // A weak reference to the owner of this node
	struct jmemory_t *next; // Memory segment chain
} jmemory_t;


/**
 * A contigues block of memory that may have additional memory segments attached
 * The lifecycle of the segments is the same as the blocks.
 * 
 * A memory block can have a chain of segments attached that all get freed
 * when the memory block is freed.
 */
typedef struct block_t {
	jmemory_t h;  // node header
	
	size_t size;
} block_t;

/**
 * A peer and a proxy. A peer is able to reference memory of another memory block
 * while also maintaining a java reference to a java object, presumably that 
 * keeps the source memory active and allocated. 
 * 
 * A proxy is similar to a peer except that from peer's perpsective point of 
 * view, a proxy is the owner of the memory that it points at. A proxy is
 * a middle-man between a peer and a source of memory. Any peers have to do
 * a continues lookup through the proxy to arrive at the data address. If a
 * proxy is reset, then all the peers that have to dereference through the
 * proxy also are automatically nulled out. 
 * 
 * Both proxy provide 2 types of references. A direct reference, is a reference
 * to a non-jmemory based memory such as a system resource or memory allocated
 * with plain old malloc. While the second is a jmemory based, that points at
 * a jmemory managed memory. When peering a peer or a proxy to a jmemory block,
 * boundaries that the peer requests can be checked thoroughly, where as 
 * boundaries for direct peers, have to be verified externally by the user of
 * the peering function.
 */
typedef struct peer_t {
	jmemory_t h;  // node header
	
	char      *data;
	jobject   jref;
	size_t	  size;
	jmemory_t *jmem;
} peer_t;

/**
 * Another memory node type that doesn't reference or contain any data (its
 * a none-JMEMORY_DATA node type, but maintains a global jni reference to
 * a java object. This is useful in preventing certain java objects from being
 * GCed. As this is a normal jmemory node type, it can be "connected" with java
 * objects (creating a round-about java-to-java reference, not very useful),
 * more importantly it can create and maintain a java reference from native
 * code that is always released when parented java object is GCed. 
 */
typedef struct jref_t {
	jmemory_t h;  // node header

	jobject jref;
} jref_t ;

typedef union jmemory_hdr_t {
	jmemory_t h;
	block_t block;
	peer_t peer;
	jref_t jref;
} jmemory_hdr_t;

#define JMEMORY_HDR_LEN     sizeof(jmemory_hdr_t)

void            memory_usage_allocate(size_t size);
void            memory_usage_free(size_t size);
memory_usage_t *memory_usage();


/*
 * Memory node API.
 * 
 * All functions that take a JNIEnv* argument, automatically throw a java
 * exception upon an error. No exceptions are thrown if return status or 
 * jmem_error() == JMEM_OK.
 */
jmemory_t  *jmem_get            (JNIEnv *env, jobject obj);
jmemory_t  *jmem_get_owner      (JNIEnv *env, jobject obj);
char       *jmem_allocate       (JNIEnv *env, jobject obj, size_t size);
int         jmem_connect        (JNIEnv *env, jobject obj, jmemory_t *node);
int         jmem_is_connected   (JNIEnv *env, jobject obj);
int         jmem_disconnect     (JNIEnv *env, jobject obj);
int         jmem_free           (JNIEnv *env, jmemory_t *node);
int         jmem_reset          (JNIEnv *env, jmemory_t *node);
int         jmem_active         (JNIEnv *env, jmemory_t *node);
int         jmem_allow_peering  (jmemory_t *node, int mode);
int         jmem_set_mode       (jmemory_t *node, int mode);
char       *jmem_data_mode      (jmemory_t *node, int mode);
char       *jmem_data           (jmemory_t *node);
char       *jmem_data_ro        (jmemory_t *node);
char       *jmem_data_wo        (jmemory_t *node);
char       *jmem_data_mode_get  (JNIEnv *env, jobject obj, int mode);
char       *jmem_data_get       (JNIEnv *env, jobject obj);
char       *jmem_data_ro_get    (JNIEnv *env, jobject obj);
char       *jmem_data_wo_get    (JNIEnv *env, jobject obj);
size_t      jmem_size           (jmemory_t *node);
int         jmem_is_active      (jmemory_t *node);
int         jmem_is_java_owned  (jmemory_t *node);
int         jmem_is_data        (jmemory_t *node);
#define     jmem_is_lc(node)    (node->flags & JMEMORY_LC_ATTACHED)
int         jmem_bounds         (jmemory_t *node, int offset, size_t length);
jmemory_t  *jmem_owner          (jmemory_t *node);
const char *jmem_name           (int type);

/*
 * Life Cycle nodes. These nodes are attached to a root JAVA_MANAGED node and
 * their life-cycles are tied. When root node is freed, all the life-cycle
 * nodes are also freed. A reset on the root node, also causes all the
 * life-cycle nodes to be freed and no longer attached to the root node.
 * 
 * Life-cycle nodes are not allowed to be JAVA_MANAGED directly. An exception
 * will be thrown when some tries to either attach a JAVA_MANAGED node or
 * to JAVA_MANAGE an attached node.
 */
int         jmem_lc_attach     (jmemory_t *root, jmemory_t *node);
int         jmem_lc_detach     (jmemory_t *root, jmemory_t *node);
int         jmem_lc_free       (JNIEnv *env,     jmemory_t *root, jmemory_t *node);
int         jmem_lc_free_all   (JNIEnv *env,     jmemory_t *root);
jmemory_t  *jmem_lc_parent     (jmemory_t *root, jmemory_t *node);
jmemory_t  *jmem_lc_last       (jmemory_t *root);

/**
 * Block node type. A memory block that is allocated as a node. 
 * jmem_data() will return the exact pointer to where user memory starts
 */
block_t    *jblock_get           (JNIEnv *env, jobject obj);
block_t    *jblock_create        (size_t size);
block_t    *jblock_resize        (size_t size, block_t *block);
char       *jblock_lc_create     (jmemory_t *root, size_t size);
int         jblock_lc_free_data  (JNIEnv *env, jmemory_t *root, void *block_data);
#define     jblock(data)         ((jmemory_t *)(((char *)data) - JMEMORY_HDR_LEN))

/*
 *Peer node type.
 * 
 * Use jmem_reset() to unreference/unpeer peer nodes.
 * 
 * Note:
 * jpeer_disable_proxy() is disallowed and not provided. Proxy nodes just be
 * garbage collected. Proxy nodes can not be reused, only deactivated.
 * 
 * Note: Proxy node means a normal peer_t node with JMEMORY_PROXY bit set.
 */ 
peer_t *jpeer_get(JNIEnv *env, jobject obj);
peer_t *jpeer_create();
int     jpeer_enable_proxy(peer_t *peer);
int     jpeer_ref_jmem(JNIEnv *env, peer_t *us, void *data, size_t size, 
						jmemory_t *jmem);
int     jpeer_obj_jmem(JNIEnv *env, jobject peer, void *data, size_t size, 
						jmemory_t *jmem);
int     jpeer_ref_jmem_offset(JNIEnv *env, peer_t *us, int offset, size_t size, 
						jmemory_t *jmem);
int     jpeer_obj_jmem_offset(JNIEnv *env, jobject peer, int offset, size_t size, 
						jmemory_t *jmem);
int     jpeer_ref_direct(JNIEnv *env, peer_t *us, void *data, size_t size, 
						jobject jref);
int     jpeer_obj_direct(JNIEnv *env, jobject peer, void *data, size_t size, 
						jobject jref);
int		jpeer_resize_direct(peer_t *us, size_t size);
/*
 * JREF or java reference node type.
 * 
 * Use jmem_reset() to unreference jref type nodes.
 */
jref_t *jref_get        (JNIEnv *env, jobject obj);
jref_t *jref_create     ();
int     jref_ref        (JNIEnv *env, jref_t *jref, jobject obj);
jobject jref_lc_create  (JNIEnv *env, jmemory_t *root, jobject obj);
jref_t *jref_lc_obj     (jmemory_t *root, jobject obj);
int     jref_lc_free_obj(JNIEnv *env, jmemory_t *root, jobject obj);

/**
 * Global declarations
 */
extern memory_usage_t GLOBAL_memory_usage;
extern jnp_exception_t jmem_message_table[];


/* on back burner for now
jmemory_t *jmem_seg_attach (jmemory_t *chain, jmemory_t *seg);
jmemory_t *jmem_seg_dettach(jmemory_t *chain, jmemory_t *seg);
int        jmem_seg_free   (jmemory_t *chain, jmemory_t *seg);
jmemory_t *jmem_seg_find   (jmemory_t *chain, jmemory_t *seg);
jmemory_t *jmem_seg_last   (jmemory_t *chain);
int        jmem_seg_remove (jmemory_t *chain, jmemory_t *seg);

char      *jdata_seg_create (jmemory_t *chain, size_t size); 
char      *jdata_seg_resize (jmemory_t *chain, char *data, size_t size); 
int        jdata_seg_free   (jmemory_t *chain, char *data ); // frees a block 
char      *jdata_seg_attach (jmemory_t *chain, char *data ); // attaches a block 
char      *jdata_seg_dettach(jmemory_t *chain, char *data ); // attaches a block 

block_t   *jblock_seg_create  (jmemory_t *chain, size_t size); 
block_t   *jblock_seg_resize  (jmemory_t *chain, block_t *seg, size_t size, 
								int *result); 
block_t   *jblock_seg_attach  (jmemory_t *chain, block_t *seg);  
block_t   *jblock_seg_dettach (jmemory_t *chain, block_t *seg);  

proxy_t   *jproxy_seg_attach   (jmemory_t *chain, proxy_t *seg);
proxy_t   *jproxy_seg_dettach  (jmemory_t *chain, proxy_t *seg);
peer_t    *jpeer_seg_attach    (jmemory_t *chain, peer_t *seg); 
peer_t    *jpeer_seg_dettach   (jmemory_t *chain, peer_t *seg); 

*/

/*
 * ADDED temporarily so we can get the code to compile.
 */
//void *getJMemoryPhysical2(JNIEnv *env, jobject obj);
//void setJMemoryPhysical2(JNIEnv *env, jobject obj, long ptr);
//void jmemoryRefRelease(JNIEnv *env, jobject obj, void *ptr);
//jobject jmemoryRefCreate(JNIEnv *env, jobject obj, void *ptr);
//void jmemoryPeer(JNIEnv *env, jobject obj, const void *data, int len, jobject jref);

//extern jfieldID jmemorySizeFID;
//extern jfieldID jmemoryKeeperFID;
//extern jobject jmemoryPOINTER_CONST;

#ifdef __cplusplus
}
#endif
#endif
