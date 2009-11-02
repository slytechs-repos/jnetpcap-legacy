/***************************************************************************
 * Copyright (C) 2009, Sly Technologies, Inc                               *
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
#include <stdarg.h>

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

#include "jnp.h"
#include "nio_jmemory.h"
#include "jnetpcap_utils.h"
#include "export.h"


int jnp_error_code = JNP_OK;
char jnp_errbuf[JNP_ERROR_BUF_SIZE];
const char *jnp_error_exception = NULL;

jnp_exception_t *jnp_error_table[JNP_FAMILY_COUNT];

jnp_exception_t jnp_msg_table[] = {
	{"ok"},
	{"null argument",	JNP_NULL_ARG_EXCEPTION},
	{NULL, 				JNP_OUT_OF_MEMORY_EXCEPTION},
	{"class field not found"},
	{"class method not found"},
	{"class file not found"},
};

jboolean jnp_initialized = JNP_FALSE;

/*
 * private prototypes
 */

void jnp_init() {
	if (jnp_initialized == JNP_TRUE) {
		return;
	}
	jnp_initialized = JNP_TRUE;	
	
	jnp_add_messages(JNP_FAMILY_CORE, jnp_msg_table);
	
	jnp_errbuf[0] = '\0';
}

/*******************************************************************************
 * 
 *                           jni java-class function set
 * 
 ******************************************************************************/
int jnp_class(JNIEnv *env, jclass *clazz, const char *name) {
	
	if (jnp_local_class(env, clazz, name)) {
		return jnp_error();
	}
	
	*clazz = (jclass) env->NewGlobalRef(*clazz);
	if (*clazz == NULL) {
		return jnp_exception_code(env, JNP_OUT_OF_MEMORY);
	}
	
	return jnp_OK();
}

int jnp_local_class(JNIEnv *env, jclass *clazz, const char *name) {
	
	if (env == NULL || clazz == NULL || name == NULL) {
		return jnp_exception_code(env, JNP_NULL_ARG);
	}
	
	*clazz = env->FindClass(name);
	if (*clazz == NULL) {
		/* Just return an error code. FindClass already throws an exception */
		return jnp_code(JNP_CLASS_NOT_FOUND);
	}
	
	return jnp_OK();
}

int jnp_method(JNIEnv *env, jclass clazz, jmethodID *id, const char *name, 
		const char *sig) {
	
	if (env == NULL || clazz == NULL || id == NULL || name == NULL) {
		return jnp_exception_code(env, JNP_NULL_ARG);
	}
	
	*id = env->GetMethodID(clazz, name, sig);
	if (*id == NULL 
			&& (*id = env->GetStaticMethodID(clazz, name, sig)) == NULL) {
		return jnp_exception_code(env, JNP_METHOD_NOT_FOUND, name);
	}
	
	return jnp_OK();
}

int jnp_field(JNIEnv *env, jclass clazz, jfieldID *id, const char *name, 
		const char *sig) {
	if (env == NULL || clazz == NULL || id == NULL || name == NULL) {
		return jnp_exception_code(env, JNP_NULL_ARG);
	}
	*id = env->GetFieldID(clazz, name, sig);
	if ((*id == NULL) 
			&& (*id = env->GetStaticFieldID(clazz, name, sig)) == NULL) {
		return jnp_code(JNP_FIELD_NOT_FOUND);
	}
	
	return jnp_OK();
}

/*******************************************************************************
 * 
 *                           jni exception/error function set
 * 
 ******************************************************************************/
int jnp_add_messages(int family, jnp_exception_t *messages) {
	jnp_init(); // Make sure its run atleast once, can be run multiple times
	
	jnp_error_table[JNP_FAMILY(family)] = messages;
	
	return jnp_OK();
}

int jnp_error() {
	return jnp_error_code;
}

int jnp_vcode(int code, va_list ap) {
	
	jnp_error_code = code;
	
	int family = JNP_FAMILY(code);
	int level = JNP_LEVEL(code);
	int index = JNP_CODE(code);
	
	if (family > JNP_FAMILY_COUNT || jnp_error_table[family] == NULL) {
		family = JNP_FAMILY_CORE;
	}
	
	jnp_exception_t *e = &jnp_error_table[family][index];
	char *c = jnp_errbuf;
	*c = '\0';
	if (code != JNP_OK) {
		sprintf(c, "[%X] ", code);
	}
	c += strlen(c);
	if (e->fmt != NULL) {
		vsprintf(c, e->fmt, ap);
	} 
	
	jnp_error_exception = ((e->exception == NULL) ? 
			JNP_DEFAULT_EXCEPTION : e->exception);
	
	return jnp_error_code;
}

int jnp_code(int code, ...) {
	va_list ap;
	va_start(ap, code);
	
	jnp_vcode(code, ap);
	
	va_end(ap);
}

const char *jnp_perror() {
	
	/*
	 * Override jnp_errbuf for JNP_OK and JNP_NULL_ARG. These two are macros
	 * that only set the numerical code and do not reset the error buffer. Since
	 * these are the builtin JNP error codes, we can make an exception and
	 * not have the initialize the errbuf, but simply override it here.
	 */
//	if (jnp_error_code == JNP_OK || jnp_error_code == JNP_NULL_ARG) {
//		return jnp_error_table[JNP_FAMILY_CORE][JNP_CODE(jnp_error_code)].fmt;
//	}
	
	int family = JNP_FAMILY(jnp_error_code);
	int index = JNP_CODE(jnp_error_code);
	if (jnp_error_table[family][index].fmt == NULL) {
		return NULL;
	}
	
	return (const char *)jnp_errbuf;
}

int jnp_exception_throw(JNIEnv *env, const char *exception, const char *msg) {
	
	if (msg == NULL) {
		throwVoidException(env, exception);
	} else {
		throwException(env, exception, msg);
	}
	
	return JNP_OK;
}

int jnp_exception_code(JNIEnv *env, int code, ...) {
	
	va_list ap;
	va_start(ap, code);
	
	jnp_vcode(code, ap);
	
	va_end(ap);
	
	return jnp_exception(env);
}

int jnp_exception(JNIEnv *env) {
	
	int code = jnp_error_code;
	/*
	 * Throw exceptions only for ERROR levels
	 */
	if (JNP_LEVEL(code) != JNP_LEVEL(JNP_ERROR)) {
		return jnp_error_code;
	}
		
	const char *msg = jnp_perror();
		
	jnp_exception_throw(env, jnp_error_exception, msg);
	
	return jnp_error_code;
}

char jnp_str_buf[1024];

char *jnp_class_getName(JNIEnv *env, jobject obj) {
	jnp_enter("jnp_class_getName");
	jclass clazz = env->GetObjectClass(obj);
	jstring str = (jstring) env->CallObjectMethod(clazz, MID_class_getName);
	if (str == NULL) {
		jnp_exit_error();
		return "";
	}
	
	jnp_exit_OK();
	return jnp_jstring(env, str, jnp_str_buf);
}

char *jnp_class_getSimpleName(JNIEnv *env, jobject obj) {
	jnp_enter("jnp_class_getSimpleName");
	jclass clazz = env->GetObjectClass(obj);
	jstring str = (jstring) env->CallObjectMethod(clazz, 
			MID_class_getSimpleName);
	if (str == NULL) {
		jnp_exit_error();
		return "";
	}
	
	return jnp_exit(jnp_jstring(env, str, jnp_str_buf));
}


char *jnp_to_string(JNIEnv *env, jobject obj) {
	jnp_enter("jnp_to_string");
	jstring str = (jstring) env->CallObjectMethod(obj, MID_object_toString);
	if (str == NULL) {
		jnp_exit_error();
		return "";
	}
	
	return jnp_exit(jnp_jstring(env, str, jnp_str_buf));
}

char *jnp_jstring(JNIEnv *env, jstring str, char *buf) {
	jnp_enter("jnp_jstring");
	
	jboolean is_copy = 0;
	const char *c = env->GetStringUTFChars(str, &is_copy);
	if (c == NULL) {
		jnp_exit_exception_code(env, JNP_OUT_OF_MEMORY);
		return "";
	}
	
	jsize len = env->GetStringUTFLength(str);
	
	strncpy(buf, c, len);
	buf[len] = '\0';
	
	env->ReleaseStringUTFChars(str, c);
	env->DeleteLocalRef(str); // Incase we get called repeatadly from a loop
	
	jnp_exit_OK();
	return buf;

}

