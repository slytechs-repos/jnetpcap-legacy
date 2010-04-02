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

//#ifdef DEBUG
//#undef DEBUG
//#endif

#include "nio_jmemory.h"
#include "jnetpcap_utils.h"
#include "jnetpcap_ids.h"
#include "util_debug.h"
#include "export.h"

/*
 * Private function declarations that are not part of the public API
 */

int jmem_flags(jmemory_t *jmem);
int jmem_flags_set(jmemory_t *jmem, int flags);
jmemory_t *jmem_dereference(jmemory_t *jmem);
char *jblock_data(block_t *block);
char *jpeer_data(peer_t *peer);

/*
 * Global memory usage statistics for jmemory class
 */
memory_usage_t GLOBAL_memory_usage;

jnp_exception_t jmem_message_table[] = {
	{"memory node inactive", 			JNP_NULL_POINTER_EXCEPTION},
	{"unable to find memory node's jmemory_t header"},
	{NULL, 								JNP_BUFFER_UNDERFLOW_EXCEPTION},
	{"a non-data node"},
	{"life-cycle not not found"},
	{"illegal attach request for a LC node"},
	{"can not directly connect a LC node to a java object"},
	{"unknown memory node type: %d"},
	{"memory node is not owned by a java object"},
	{"read or write permission denied"},
	{"NULL reference to another memory node"},
	{"memory node not type: PEER"},
	{"can not peer with this memory node"},
	{"illegal memory node type %s(%d)"},
	{"wrong memory node type %s(%d), expected %s(%d)"},
	{"this node is not connected to a java object"},
	{"this node is already connected to a java object"},
	{"illegal attempt to transfer data"}
};


/*
 * TEMP TO BE DELETED
 */
jfieldID jmemorySizeFID;
jfieldID jmemoryKeeperFID;
jobject jmemoryPOINTER_CONST;

void *getJMemoryPhysical(JNIEnv *env, jobject obj) {
	throwException(env, UNSUPPORTED_OPERATION_EXCEPTION, "getJMemoryPhysical");
}

void setJMemoryPhysical(JNIEnv *env, jobject obj, long ptr) {
	throwException(env, UNSUPPORTED_OPERATION_EXCEPTION, "setJMemoryPhysical");
}

void jmemoryRefRelease(JNIEnv *env, jobject obj, void *ptr) {
	throwException(env, UNSUPPORTED_OPERATION_EXCEPTION, "jmemoryRefRelease");	
}

jobject jmemoryRefCreate(JNIEnv *env, jobject obj, void *ptr) {
	throwException(env, UNSUPPORTED_OPERATION_EXCEPTION, "jmemoryRefCreate");	
	return NULL;
}

void jmemoryPeer(JNIEnv *env, jobject obj, const void *data, int len, jobject jref) {
	throwException(env, UNSUPPORTED_OPERATION_EXCEPTION, "jmemoryPeer");	
}


/*******************************************************************************
 * 
 *                           memory_usage function set
 * 
 ******************************************************************************/
void memory_usage_allocate(size_t size) {

	GLOBAL_memory_usage.total_allocated += size;
	GLOBAL_memory_usage.total_allocate_calls ++;
}

void memory_usage_free(size_t size) {

	GLOBAL_memory_usage.total_deallocated += size;
	GLOBAL_memory_usage.total_deallocate_calls --;
}

memory_usage_t *memory_usage() {
	return &GLOBAL_memory_usage;
}

/*******************************************************************************
 * 
 *                               jmem function set
 * 
 ******************************************************************************/

jmemory_t *jmem_get(JNIEnv *env, jobject obj) {
	jnp_enter("jmem_get");
	jnp_trace("class=%s", jnp_class_getSimpleName(env, obj));
	
	if (env == NULL || obj == NULL) {
		jnp_trace("JNP_NULL_ARG (msg id=%d)", JNP_NULL_ARG);
		jnp_exit_exception_code(env, JNP_NULL_ARG);
		return NULL;
	}
		
	jmemory_t *jmem =(jmemory_t *)toPtr(env->GetLongField(obj,
			FID_jmemory_physical));
	if (jmem == NULL) {
		jnp_trace("JMEM_NOT_CONNECTED (msg id=%d)", JMEM_NOT_CONNECTED);
		jnp_exit_exception_code(env, JMEM_NOT_CONNECTED);
		return NULL;
	}
	
	jnp_exit_OK();
	return jmem;
}

jmemory_t *jmem_get_owner(JNIEnv *env, jobject obj) {
	jnp_enter("jmem_get_owner");
	
	register jmemory_t *node = jmem_get(env, obj);
	if (node == NULL) {
		jnp_exit_error();
		return NULL;
	}
	
	/*
	 * Dereference the node down to the owner of the memory block. If this
	 * node is already a BLOCK, then jmem_owner will figure that out, otherwise
	 * it will dereference PEER nodes to the memory owner.
	 */
	if ((node = jmem_owner(node)) == NULL) {
		jnp_exit_exception(env);
		return NULL;
	}
	
	jnp_exit_OK();
	return node;
}


char *jmem_allocate(JNIEnv *env, jobject obj, size_t size) {
	jnp_enter("jmem_allocate");
	
	if (env == NULL || obj == NULL) {
		jnp_exit_exception_code(env, JNP_NULL_ARG);
		return NULL;
	}
	
	if (size < 0) {
		jnp_exit_exception_code(env, JMEM_OUT_OF_BOUNDS);
		return NULL;
	}
	
	block_t *block = jblock_create(size);
	if (block == NULL) {
		jnp_exit_exception(env);
		return NULL;
	}
	
	if (jmem_connect(env, obj, &block->h)) {
		jnp_exit_error();
		return NULL; // Carry over error code
	}
	
	char *data = jmem_data(&block->h);
	if (data == NULL) {
		jnp_exit_exception(env);
		return NULL;
	}
	
	jnp_exit_OK();
	return data;
}

int jmem_connect(JNIEnv *env, jobject obj, jmemory_t *jmem) {
	jnp_enter("jmem_connect");
	
	if (env == NULL || obj == NULL) {
		return jnp_exit_exception_code(env, JNP_NULL_ARG);
	}
	
	if (jmem->flags & JMEMORY_LC_ATTACHED) {
		return jnp_exit_exception_code(env, JMEM_LC_ATTACH_ERROR);
	}

	env->SetLongField(obj, FID_jmemory_physical, toLong((void *)jmem));
	jmem->weak_jref = env->NewWeakGlobalRef(obj);
	if (jmem->weak_jref == NULL) {
		return jnp_exit_exception_code(env, JNP_OUT_OF_MEMORY);
	}

	jmem->flags |= JMEMORY_JAVA_OWNED;
	
	return jnp_exit_OK();
}

int jmem_is_connected (JNIEnv *env, jobject obj) {
	return env->GetLongField(obj, FID_jmemory_physical) != 0L;
}

int jmem_disconnect(JNIEnv *env, jmemory_t *jmem) {
	jnp_enter("jmem_disconnect");
	
	if (env == NULL || jmem == NULL) {
		return jnp_exit_exception_code(env, JNP_NULL_ARG);
	}

	if (!(jmem->flags & JMEMORY_JAVA_OWNED)) {
		return jnp_exit_OK(); // Nothing to do
	}

	if (jmem->weak_jref == NULL || env->IsSameObject(jmem->weak_jref, NULL)) {
		return jnp_exit_exception_code(env, JMEM_NULL_OWNER_JREF);
	}

	env->SetLongField(jmem->weak_jref, FID_jmemory_physical, (jint)0L);
	env->DeleteWeakGlobalRef(jmem->weak_jref);

	jmem->flags &= ~JMEMORY_JAVA_OWNED; // Turn off
	
	return jnp_exit_OK();
}

int jmem_free(JNIEnv *env, jmemory_t *jmem) {
	jnp_enter("jmem_free");

	size_t size = jmem_size(jmem);
	if (size > 0) {
		memory_usage_free(size);
	}
	
	if (jmem_reset(env, jmem) != JNP_OK) {
		return jnp_exit_error();
	}

	
	/*
	 * Check and see if node is still owned by a java object. If it is, we
	 * must disconnect as after we free this memory the user will not get
	 * a chance to disconnect (and free up additional resources).
	 */
	if (jmem_is_java_owned(jmem) && jmem_disconnect(env, jmem) != JNP_OK) {
		return jnp_exit_error();
	}

	/*
	 * Deallocate the node
	 */
	free(jmem);

	return jnp_exit_OK();
}

int jmem_reset(JNIEnv *env, jmemory_t *jmem) {
	jnp_enter("jmem_reset");

	if (env == NULL || jmem == NULL) {
		return jnp_exit_exception_code(env, JNP_NULL_ARG);
	}
	
	if ( (jmem->flags & JMEMORY_ACTIVE) == JNP_FALSE) {
		return jnp_exit_OK(); // Nothing to do
	}
	
	/* Check if life-cycle nodes need to be freed; only if we are root node */
	if (!jmem_is_lc(jmem) 
			&& jmem->next != NULL 
			&& jmem_lc_free_all(env, jmem)) {
		return jnp_exit_error();
	}

	/**
	 * First deallocate private members and jreferences
	 */

	if ((jmem->type == JMEMORY_TYPE_PEER) && (jmem->flags & JMEMORY_REFERENCE)
			&& (((peer_t *)jmem)->jref != NULL)) {
		env->DeleteGlobalRef(((peer_t *)jmem)->jref);
	}
	
	if (jmem->type == JMEMORY_TYPE_JREF && ((jref_t *)jmem)->jref != NULL) {
		env->DeleteGlobalRef(((jref_t *)jmem)->jref);
	}
	
	/*
	 * Reinitialized flags and carry over persistant ones
	 */
	jmem->flags = JMEMORY_DEFAULTS | (jmem->flags & (JMEMORY_CARRYOVER));

	return jnp_exit_OK();
}

int jmem_active(JNIEnv *env, jmemory_t *jmem) {
	jnp_enter("jmem_active");

	if (env == NULL || jmem == NULL) {
		return jnp_exit_exception_code(env, JNP_NULL_ARG);
	}
	
	if (jmem_is_active(jmem) == JMEM_FALSE) {
		jnp_trace("FALSE");
		return jnp_exit_exception_code(env, JMEM_INACTIVE);
	} else {
		jnp_trace("TRUE");
	}
	
	return jnp_exit_OK();
}

int jmem_allow_peering(jmemory_t *jmem, int mode) {
	if (mode) {
		jmem->flags &= ~JMEMORY_NO_PEERING;
	} else {
		jmem->flags |= JMEMORY_NO_PEERING;
	}
}


char *jmem_data_mode(jmemory_t *jmem, int mode) {
	jnp_enter("jmem_data_mode");
	
	if (jmem == NULL) {
		jnp_exit_ARG();
		return NULL;
	}
	
	if (!(jmem->flags & JMEMORY_DATA)) {
		jnp_exit_code(JMEM_NOT_DATA_NODE);
		return NULL;

	} else if (!(jmem->flags & (mode))) {
		jnp_exit_code(JMEM_PERMISSION);
		return NULL;

	}
	
	switch (jmem->type) {
	case JMEMORY_TYPE_BLOCK:
		return jnp_exit(jblock_data((block_t *)jmem));

	case JMEMORY_TYPE_PEER:
		return jnp_exit(jpeer_data((peer_t *)jmem));

	default: // JREF type
		jnp_exit_code(JMEM_NOT_DATA_NODE);
		return NULL;
	}
}

jmemory_t *jmem_dereference(jmemory_t *jmem) {
	jnp_enter("jmem_dereference");
		
	if (jmem == NULL) {
		jnp_exit_ARG();
		return NULL;
	}

	if (!(jmem->flags & JMEMORY_ACTIVE)) {
		jnp_exit_code(JMEM_INACTIVE);
		return NULL;
	}

	switch (jmem->type) {
	case JMEMORY_TYPE_BLOCK:
	case JMEMORY_TYPE_JREF:
		jnp_exit_OK();
		return jmem;

	case JMEMORY_TYPE_PEER:
		peer_t *peer = (peer_t *)jmem;
		if (peer->h.flags & (JMEMORY_PROXY | JMEMORY_DIRECT)) {
			jnp_exit_OK();
			return jmem;
		}

		return jnp_exit(jmem_dereference(peer->jmem));
	}
}

int jmem_set_mode(jmemory_t *jmem, int mode) {
	jnp_enter("jmem_set_mode");
		
	if (jmem == NULL) {
		return jnp_exit_ARG();
	}
	
	jmem->flags &= ~JMEMORY_MODE_BITS; // Reset mode bits
	jmem->flags |= (mode & JMEMORY_MODE_BITS); // now mask and set
	
	jnp_exit_OK();
}


char *jmem_data(jmemory_t *jmem) {
	return jmem_data_mode(jmem, JMEMORY_READ | JMEMORY_WRITE);
}

char *jmem_data_ro(jmemory_t *jmem) {
	return jmem_data_mode(jmem, JMEMORY_READ);
}

char *jmem_data_wo(jmemory_t *jmem) {
	return jmem_data_mode(jmem, JMEMORY_WRITE);
}

char *jmem_data_mode_get(JNIEnv *env, jobject obj, int mode) {
	jnp_enter("jmem_data_mode_get");
		
	jmemory_t *node = jmem_get(env, obj);
	if (node == NULL) {
		jnp_exit_ARG();
		return NULL;
	}
	
	char *data = jmem_data_mode(node, mode);
	if (data == NULL) {
		jnp_exit_exception(env);
		return NULL;
	}
	
	jnp_exit_OK();
	return data;
}

char *jmem_data_get(JNIEnv *env, jobject obj) {
	return jmem_data_mode_get(env, obj, JMEMORY_READ | JMEMORY_WRITE);
}

char *jmem_data_ro_get(JNIEnv *env, jobject obj) {
	return jmem_data_mode_get(env, obj, JMEMORY_READ);
}

char *jmem_data_wo_get(JNIEnv *env, jobject obj) {
	return jmem_data_mode_get(env, obj, JMEMORY_WRITE);
}

size_t jmem_size(jmemory_t *jmem) {
	jnp_enter("jmem_size");
		
	if (jmem == NULL) {
		jnp_exit_code(JNP_NULL_ARG);
		return 0;
	}
	
	if (jmem_is_active(jmem) == FALSE) {
		jnp_exit_code(JMEM_INACTIVE);
		return 0;
	}
	
	switch (jmem->type) {
	case JMEMORY_TYPE_BLOCK:
		jnp_trace("size=%d", ((block_t *)jmem)->size);
		jnp_exit_OK();
		return ((block_t *)jmem)->size;

	case JMEMORY_TYPE_PEER:
		jnp_trace("size=%d", ((peer_t *)jmem)->size);
		jnp_exit_OK();
		return ((peer_t *)jmem)->size;
		
	case JMEMORY_TYPE_JREF:
		jnp_exit_code(JMEM_NOT_DATA_NODE);
		return 0;
		
	default:
		jnp_exit_code(JMEM_UNKNOWN_TYPE, jmem->type);
		return 0;
	}
}

int jmem_is_active(jmemory_t *jmem) {
	jnp_enter("jmem_is_active");
		
	if (jmem == NULL) {
		jnp_exit_code(JNP_NULL_ARG);
		return JMEM_FALSE;
	}

	if (!(jmem->flags & JMEMORY_ACTIVE)) {
		jnp_trace("FALSE");
		jnp_exit_OK();
		return JMEM_FALSE;
	}


	switch (jmem->type) {
	case JMEMORY_TYPE_BLOCK:
	case JMEMORY_TYPE_JREF:
		jnp_trace("TRUE");
		jnp_exit_OK();
		return JMEM_TRUE;

	case JMEMORY_TYPE_PEER:
		if (jmem->flags & JMEMORY_REFERENCE) {
			if (((peer_t *)jmem)->jmem == NULL) {
				jnp_exit_code(JMEM_NULL_JMEM_REF);
				jnp_trace("FALSE");
				return JMEM_FALSE;
			}
			return jnp_exit(jmem_is_active(((peer_t *)jmem)->jmem));
		}

		jnp_trace("TRUE");
		jnp_exit_OK();
		return JMEM_TRUE;
		
	default:
		jnp_trace("FALSE");
		jnp_exit_code(JMEM_UNKNOWN_TYPE, jmem->type);
		return JMEM_FALSE;
	}
}

int jmem_is_java_owned(jmemory_t *jmem) {
	jnp_enter("jmem_is_java_owned");
		
	if (jmem == NULL) {
		jnp_trace("FALSE");
		jnp_exit_code(JNP_NULL_ARG);
		return JMEM_FALSE;
	}

	jnp_trace((jmem->flags & JMEMORY_JAVA_OWNED)?"TRUE":"FALSE");
	jnp_exit_OK();

	return (jmem->flags & JMEMORY_JAVA_OWNED) != 0;
}

int jmem_is_data(jmemory_t *jmem) {
	jnp_enter("jmem_is_data");
		
	if (jmem == NULL) {
		jnp_exit_code(JNP_NULL_ARG);
		return JMEM_FALSE;
	}

	jnp_exit_OK();

	return (jmem->flags & JMEMORY_DATA) != 0;
}

int jmem_flags(jmemory_t *jmem) {
	jnp_enter("jmem_flags");
		
	if (jmem == NULL) {
		jnp_exit_code(JNP_NULL_ARG);
		return JMEM_FALSE;
	}

	jnp_exit_OK();

	return (int) jmem->flags;
}

int jmem_flags_set(jmemory_t *jmem, int flags) {
	jnp_enter("jmem_flags_set");
		
	if (jmem == NULL) {
		jnp_exit_code(JNP_NULL_ARG);
		return JMEM_FALSE;
	}

	jmem->flags = flags;
	
	jnp_exit_OK();
}

int jmem_bounds(jmemory_t *jmem, int offset, size_t length) {
	jnp_enter("jmem_bounds");
		
	size_t size = jmem_size(jmem);
	if (jnp_error() != JNP_OK) {
		return jnp_exit_error();
	}

	jnp_trace("type=%s", jmem_name(jmem->type));
	jnp_trace("(%d < 0) || (%d < 0) || (%d + %d) > %d",
			offset, (int)length, offset, (int)length, (int)size);
	return (( (offset < 0) || (length < 0) || (offset + length) > size) 
			? jnp_exit_code(JMEM_OUT_OF_BOUNDS)
			: jnp_exit_OK());
}

jmemory_t *jmem_owner(jmemory_t *node) {
	jnp_enter("jmem_owner");
		
	if (node == NULL) {
		jnp_exit_ARG();
		return NULL;
	}
	
	switch (node->type) {
	case JMEMORY_TYPE_BLOCK:
	case JMEMORY_TYPE_JREF:
		jnp_exit_OK();
		return node;
		
	case JMEMORY_TYPE_PEER:
		if (node->flags & JMEMORY_DIRECT) {
			jnp_exit_OK();
			return node;
		} else {
			jmemory_t *t = ((peer_t *)node)->jmem;
			if (t == NULL) {
				jnp_exit_code(JMEM_ILLEGAL_PEER);
				return NULL;
			}
			
			jnp_exit_OK();
			return t;
		}
	
	default:
		jnp_exit_code(JMEM_UNKNOWN_TYPE, node->type);
		return NULL;
	}
}

const char *jmem_name(int type) {
	switch (type) {
	case JMEMORY_TYPE_BLOCK:
		return JMEMORY_TYPE_BLOCK_NAME;
		
	case JMEMORY_TYPE_PEER:
		return JMEMORY_TYPE_PEER_NAME;
		
	case JMEMORY_TYPE_JREF:
		return JMEMORY_TYPE_JREF_NAME;
		
	default:
		return JMEMORY_TYPE_UNKNOWN_NAME;
	}
}


/*******************************************************************************
 * 
 *                         jmem Life-Cycle function set
 * 
 ******************************************************************************/
int jmem_lc_attach(jmemory_t *root, jmemory_t *node) {
	jnp_enter("jmem_lc_attach");
		
	if (jmem_is_java_owned(root) == JNP_FALSE || 
			jmem_is_java_owned(node) == JNP_TRUE) {
		return jnp_exit_code(JMEM_LC_ATTACH_ERROR);
	}
	
	jmem_lc_last(root)->next = node;
	node->flags |= JMEMORY_LC_ATTACHED;
	
	return jnp_exit_OK();
}

int jmem_lc_detach(jmemory_t *root, jmemory_t *node) {
	jnp_enter("jmem_lc_detach");
	
	jmemory_t *parent = jmem_lc_parent(root, node);
	if (parent == NULL) {
		return jnp_exit_code(JMEM_LC_NOT_FOUND);
	}
	
	parent->next = NULL;
	node->flags &= ~JMEMORY_LC_ATTACHED;
	
	jnp_exit_OK();
}

int jmem_lc_free(JNIEnv *env, jmemory_t *root, jmemory_t *node) {	
	jnp_enter("jmem_lc_free");
	
	if (jmem_lc_detach(root, node)) {
		return jnp_exit_error();
	}
	
	return jnp_exit(jmem_free(env, node));
}


int jmem_lc_free_all(JNIEnv *env, jmemory_t *root) {
	jnp_enter("jmem_lc_free_all");
	
	register jmemory_t *next = root->next;
	
	while (next != NULL) {
		if (jmem_lc_detach(root, next) || jmem_free(env, next)) {
			return jnp_exit_error();
		}
		
		next = root->next;
	}
	
	return jnp_exit_OK();
}

jmemory_t *jmem_lc_parent(jmemory_t *root, jmemory_t *node) {
	register jmemory_t *parent = root;
	
	while (parent != NULL) {
		
		if (parent->next == node) {
			return parent;
		}
		parent = parent->next;
	}
	
	return parent;
}

jmemory_t *jmem_lc_last(jmemory_t *root) {
	register jmemory_t *last = root;
	
	while (last->next != NULL) {
		last = last->next;
	}
	
	return last;
}


/*******************************************************************************
 * 
 *                              jblock function set
 * 
 ******************************************************************************/
block_t *jblock_get(JNIEnv *env, jobject obj) {
	jnp_enter("jblock_get");

	jmemory_t *jmem = jmem_get(env, obj);
	if (jmem == NULL) {
		jnp_exit_error();
		return NULL; // Carry over error code
	}
	
	if (jmem->type != JMEMORY_TYPE_BLOCK) {
		jnp_exit_exception_code(env, JMEM_WRONG_TYPE(jmem->type, 
				JMEMORY_TYPE_BLOCK));
		return NULL;
	}
	
	jnp_exit_OK();
	return (block_t *)jmem;
}

block_t *jblock_create(size_t size) {
	jnp_enter("jblock_create");

	if (size <= 0) {
		jnp_exit_code(JMEM_OUT_OF_BOUNDS);
		return NULL;
	}

	block_t *block = (block_t *)malloc(size + JMEMORY_HDR_LEN);
	if (block == NULL) {
		jnp_exit_code(JNP_OUT_OF_MEMORY);
		return NULL;
	}
	block->size = size;
	block->h.next = NULL;
	block->h.type = JMEMORY_TYPE_BLOCK;
	block->h.weak_jref = NULL;
	block->h.flags = JMEMORY_BLOCK_DEFAULTS | JMEMORY_ACTIVE;

	memory_usage_allocate(size + JMEMORY_HDR_LEN);

	jnp_exit_OK();
	return block;
}

block_t *jblock_resize(size_t size, block_t *block) {
	jnp_enter("jblock_resize");

	if (size <= 0) {
		jnp_exit_code(JMEM_OUT_OF_BOUNDS);
		return NULL;
	} 
	block_t *n = (block_t *)realloc((void *)block, size + JMEMORY_HDR_LEN);
	if (n == NULL) {
		jnp_exit_code(JNP_OUT_OF_MEMORY);
		return NULL;
	}

	jnp_exit_OK();
	return n;
}

char *jblock_data(block_t *block) {
	jnp_enter("jblock_data");

	if (block == NULL) {
		jnp_exit_code(JNP_NULL_ARG);
		return NULL;
	}

	jnp_exit_OK();
	return ((char *)block) + JMEMORY_HDR_LEN;
}

char *jblock_lc_create(jmemory_t *root, size_t size) {
	jnp_enter("jblock_lc_create");

	block_t *block = jblock_create(size);
	if (block == NULL) {
		jnp_exit_error();
		return NULL;
	}
	
	if (jmem_lc_attach(root, &block->h)) {
		jnp_exit_error();
		return NULL;
	}
	
	return jnp_exit(jblock_data(block));
}

int jblock_lc_free_data(JNIEnv *env, jmemory_t *root, void *block_data) {
	jnp_enter("jblock_lc_free_data");
	
	return jnp_exit(jmem_lc_free(env, root, jblock(block_data)));
}


/*******************************************************************************
 * 
 *                               jpeer function set
 * 
 ******************************************************************************/
peer_t *jpeer_get(JNIEnv *env, jobject obj) {
	jnp_enter("jpeer_get");
	
	jmemory_t *jmem = jmem_get(env, obj);
	if (jmem == NULL) {
		jnp_exit_error();
		return NULL;
	}
	
	if (jmem->type != JMEMORY_TYPE_PEER) {
		jnp_trace("class=%s", jnp_class_getName(env, obj));
		jnp_exit_exception_code(env, JMEM_WRONG_TYPE(jmem->type, 
				JMEMORY_TYPE_PEER));
		return NULL;
	}
	
	jnp_exit_OK();
	return (peer_t *)jmem;
}

peer_t *jpeer_create() {
	jnp_enter("jpeer_create");
	
	peer_t *peer = (peer_t *)malloc(JMEMORY_HDR_LEN);
	if (peer == NULL) {
		jnp_exit_code(JNP_OUT_OF_MEMORY);
		return NULL;
	}
	peer->h.type = JMEMORY_TYPE_PEER;
	peer->h.flags = JMEMORY_PEER_DEFAULTS;
	peer->h.weak_jref = NULL;
	peer->h.next = NULL;
	peer->jref = NULL;
	peer->jmem = NULL;
	peer->data = NULL;
	peer->size = 0;

	jnp_exit_OK();
	return peer;
}

int jpeer_enable_proxy(peer_t *peer) {
	jnp_enter("jpeer_enable_proxy");
	
	if (peer == NULL) {
		return jnp_exit_code(JNP_NULL_ARG);
	}

	/*
	 * The only difference between peer and proxy, atleast when its being
	 * created is the PROXY flag bit. Of course, the main difference in 
	 * functionality is that PROXY nodes are like hard stops for peering. The
	 * make the peer node behave more like a BLOCK node (but via indirect
	 * reference), then a normal node.
	 */
	peer->h.flags |= JMEMORY_PROXY;

	return jnp_exit_OK();
}

/**
 * Peer to another jmemory node via an offset.
 */
int jpeer_ref_jmem(JNIEnv *env, peer_t *us, void *data, size_t size,
		jmemory_t *jmem) {
	jnp_enter("jpeer_ref_jmem");
	
	if (env == NULL || us == NULL || jmem == NULL) {
		return jnp_exit_exception_code(env, JNP_NULL_ARG);
	}
	
	char *them_data = jmem_data(jmem);
	if (them_data == NULL) {
		return jnp_exit_error();
	}
	
	int offset = ((char *)data) - them_data;
	jnp_trace("offset=%d", offset);

	return jnp_exit(jpeer_ref_jmem_offset(env, us, offset, size, jmem));
}

int jpeer_obj_jmem_offset(JNIEnv *env, jobject peer, int offset, size_t size, 
						jmemory_t *jmem) {
	jnp_enter("jpeer_obj_jmem_offset");
	
	peer_t *us = jpeer_get(env, peer);
	if (us == NULL) {
		return jnp_exit_error();
	}
	
	return jnp_exit(jpeer_ref_jmem_offset(env, us, offset, size, jmem));
}


/**
 * Peer to another jmemory node via a pointer.
 */
int jpeer_ref_jmem_offset(JNIEnv *env, peer_t *us, int offset, size_t size,
		jmemory_t *jmem) {
	
	jnp_enter("jpeer_ref_jmem_offset");

	if (env == NULL || us == NULL || jmem == NULL) {
		return jnp_exit_exception_code(env, JNP_NULL_ARG);
	}
	
	if (us->h.type != JMEMORY_TYPE_PEER) {
		return jnp_exit_exception_code(env, JMEM_NOT_PEER_NODE);
	}

	if (jmem_is_active(jmem) == JMEM_FALSE) {
		return jnp_exit_exception_code(env, JMEM_INACTIVE);
	}
	
	if (jmem_is_active(&us->h) == JMEM_TRUE 
			&& jmem_reset(env, &us->h) != JNP_OK) {
		return jnp_exit_error();
	}

	jnp_trace("offset=%d", offset);

	/*
	 * Unwind any multiple references to the last reference or to the first
	 * reference with PROXY flag bit set. If any of the references along the way
	 * are inactive we fail. Also any other types of errors are carried through
	 * the jnp_exit_error(). 
	 */
	register jmemory_t *them = jmem_dereference(jmem); // them is last reference
	if (them == NULL) {
		return jnp_exit_exception(env); // Carry over error code
	}
	
	/*
	 * Make sure we are within bounds of the first node we are trying to peer
	 * to or through.
	 */
	jnp_trace("owner=%s", jnp_class_getName(env, jmem->weak_jref));
	if (jmem_bounds(jmem, offset, size)) {
		jnp_trace("OK");
		return jnp_exit_exception(env);
	}
	
	jnp_trace("OK");
	
	
	if (us->h.flags & JMEMORY_NO_PEERING || jmem->flags & JMEMORY_NO_PEERING ||
			them->flags & JMEMORY_NO_PEERING) {
		return jnp_exit_exception_code(env, JMEM_ILLEGAL_PEER);
	}

	/*
	 * Enable the ACTIVE flag and carry over the permissions from first reference
	 * in the chain. Also set the DATA, and JMEM REFERENCE flags.
	 */
	us->h.flags = JMEMORY_PEER_DEFAULTS
		| (JMEMORY_ACTIVE | JMEMORY_REFERENCE) 
		| (us->h.flags & (JMEMORY_CARRYOVER));
	us->size = size;
	us->jmem = them;
	
	if ((us->data = jmem_data(jmem)) == NULL) {
		return jnp_exit_error();
	}

	
	/*
	 * For both BLOCK and PROXY nodes (peer + PROXY bit) we jref the java
	 * owner reference, not PROXY data jref. This is
	 * because we want to keep the PROXY node and the BLOCK node from being
	 * java GCed, which might happen if we don't create references to them.
	 */
	if (them->weak_jref != NULL && !env->IsSameObject(them->weak_jref, NULL)) {
		us->jref = env->NewGlobalRef(them->weak_jref);
		if (us->jref == NULL) {
			return jnp_exit_exception_code(env, JNP_OUT_OF_MEMORY);
		}
	}

	return jnp_exit_OK();
}

int jpeer_obj_jmem(JNIEnv *env, jobject peer, void *data, size_t size, 
						jmemory_t *jmem) {
	
	jnp_enter("jpeer_obj_jmem");

	peer_t *us = jpeer_get(env, peer);
	if (us == NULL) {
		return jnp_exit_error();
	}
	
	return jnp_exit(jpeer_ref_jmem(env, us, data, size, jmem));
}


int jpeer_ref_direct(JNIEnv *env, peer_t *us, void *data, size_t size, 
		jobject jref) {
	jnp_enter("jpeer_ref_direct");
	
	if (env == NULL || us == NULL) {
		return jnp_exit_exception_code(env, JNP_NULL_ARG);
	}
	
	if (us->h.type != JMEMORY_TYPE_PEER) {
		return jnp_exit_exception_code(env, JMEM_NOT_PEER_NODE);
	}

	if (jmem_is_active(&us->h) == JMEM_TRUE 
			&& jmem_reset(env, &us->h) != JNP_OK) {
		return jnp_exit_error();
	}
	
	us->h.flags = JMEMORY_PEER_DEFAULTS 
				| (us->h.flags & (JMEMORY_CARRYOVER))
				| (JMEMORY_ACTIVE | JMEMORY_DIRECT); 
	us->size = size;
	us->jmem = NULL;
	us->data = (char *)data;
	if (jref != NULL) {
		us->jref = env->NewGlobalRef(jref);
		if (us->jref == NULL) {
			return jnp_exit_exception_code(env, JNP_OUT_OF_MEMORY);
		}
	} else {
		us->jref == NULL;
	}
	
	
	return jnp_exit_OK();
}

int jpeer_obj_direct(JNIEnv *env, jobject peer, void *data, size_t size, 
						jobject jref) {
	
	jnp_enter("jpeer_obj_direct");
	
	peer_t *us = jpeer_get(env, peer);
	if (us == NULL) {
//		jnp_trace("error=%d", jnp_error());
		return jnp_exit_error();
	}
	
	if (jpeer_ref_direct(env, us, data, size, jref)) {
		return jnp_exit_error();
	}
	
	return jnp_exit_OK();
}

int jpeer_resize_direct(peer_t *us, size_t size) {
	jnp_enter("jpeer_resize_direct");
	
	if (us == NULL) {
		return jnp_exit_code(JNP_NULL_ARG);
	}
	
	if (us->h.type != JMEMORY_TYPE_PEER || !(us->h.flags & JMEMORY_DIRECT)) {
		return jnp_exit_code(JMEM_ILLEGAL_PEER);
	}
	
	if (size < 0) {
		return jnp_exit_code(JMEM_OUT_OF_BOUNDS);
	}
	// TODO: need a jpeer_is_active here to be more efficient
	if (jmem_is_active(&us->h) == JNP_FALSE) {
		return jnp_exit_code(JMEM_INACTIVE);
	}
	
	us->size = size;
	
	return jnp_exit_OK();
}

char *jpeer_data(peer_t *peer) {
	jnp_enter("jpeer_data");
	
	if (peer == NULL) {
		jnp_exit_code(JNP_NULL_ARG);
		return NULL;
	}
	
	if (jmem_is_active(&peer->h) == JMEM_FALSE) {
		jnp_exit_code(JMEM_INACTIVE);
		return NULL;
	}
	
	jnp_exit_OK();
	return peer->data;
}


/*******************************************************************************
 * 
 *                               jref function set
 * 
 ******************************************************************************/
jref_t *jref_get(JNIEnv *env, jobject obj) {
	jnp_enter("jref_get");
	
	jmemory_t *jmem = jmem_get(env, obj);
	if (jmem == NULL) {
		jnp_exit_exception_code(env, JNP_NULL_ARG);
		return NULL; // Carry over error code
	}
	
	if (jmem->type != JMEMORY_TYPE_JREF) {
		jnp_exit_exception_code(env, JMEM_WRONG_TYPE(jmem->type, 
				JMEMORY_TYPE_JREF));
		return NULL;
	}
	
	return (jref_t *)jmem;
}

jref_t *jref_create() {
	jnp_enter("jref_create");
	
	jref_t *jref = (jref_t *)malloc(JMEMORY_HDR_LEN);
	if (jref == NULL) {
		jnp_exit_code(JNP_OUT_OF_MEMORY);
		return NULL;
	}
	
	jref->h.type = JMEMORY_TYPE_JREF;
	jref->h.flags = JMEMORY_JREF_DEFAULTS;
	jref->h.weak_jref = NULL;
	jref->h.next = NULL;
	jref->jref = NULL;
	
	jnp_exit_OK();
	return jref;
}

int jref_ref(JNIEnv *env, jref_t *us, jobject jref) {
	jnp_enter("jref_ref");

	if (env == NULL || us == NULL || jref == NULL) {
		return jnp_exit_exception_code(env, JNP_NULL_ARG);
	}
	
	if (jmem_is_active(&us->h) == JMEM_TRUE 
			&& jmem_reset(env, &us->h) != JNP_OK) {

		return jnp_exit_error();
	}

	us->h.flags = JMEMORY_JREF_DEFAULTS | JMEMORY_ACTIVE;
	us->jref = env->NewGlobalRef(jref);
	if (us->jref == NULL) {
		return jnp_exit_exception_code(env, JNP_OUT_OF_MEMORY);
	}
	
	return jnp_exit_OK();
}

jobject jref_lc_create (JNIEnv *env, jmemory_t *root, jobject obj) {
	jnp_enter("jref_lc_create");

	jref_t *jref = jref_create();
	if (jref == NULL || jmem_lc_attach(root, &jref->h)) {
		jnp_exit_exception(env);
		return NULL;
	}
	
	if (jref_ref(env, jref, obj)) {
		jnp_exit_error();
		return NULL;
	}
	
	jnp_exit_OK();
	return jref->jref;
}

jref_t *jref_lc_obj     (jmemory_t *root, jobject obj){
	jnp_enter("jref_lc_obj");
	
	register jmemory_t *next = root->next;
	
	while (next != NULL) {
		if (next->type == JMEMORY_TYPE_JREF) {
			jref_t *jref = (jref_t *)next;
			
			if (jref->jref == obj) {
				jnp_exit_OK();
				return jref;
			}
		}
		
		next = next->next;
	}
	
	jnp_exit_code(JMEM_LC_NOT_FOUND);
	return NULL;
}

int jref_lc_free_obj(JNIEnv *env, jmemory_t *root, jobject obj) {
	jnp_enter("jref_lc_free_obj");
	
	jref_t *jref = jref_lc_obj(root, obj);
	if (jref == NULL) {
		return jnp_exit_exception(env);
	}
	
	return jnp_exit(jmem_lc_free(env, root, &jref->h));
}

