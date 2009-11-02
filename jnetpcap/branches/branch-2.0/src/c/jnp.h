/* Header for jnetpcap_utils utility methods */

#ifndef _Included_nio_jnp_utils_h
#define _Included_nio_jnp_utils_h
#ifdef __cplusplus
#include <exception>
extern "C" {
#define	EXTERN extern "C"
#endif

#include <stdint.h>
#include <stdarg.h>
#include <jni.h>
#include "export.h"

	
	
#define JNP_TRUE				1
#define JNP_FALSE				0
	
#define JNP_ERROR_BUF_SIZE		1024
	
#define JNP_ILLEGAL_STATE_EXCEPTION 	"java/lang/IllegalStateException"
#define JNP_NULL_ARG_EXCEPTION	 		"java/lang/NullPointerException"
#define JNP_NULL_POINTER_EXCEPTION		"java/lang/NullPointerException"
#define JNP_OUT_OF_MEMORY_EXCEPTION		"java/lang/OutOfMemory"
#define JNP_BUFFER_UNDERFLOW_EXCEPTION	"java/nio/BufferUnderflowException"
#define JNP_DEFAULT_EXCEPTION			JNP_ILLEGAL_STATE_EXCEPTION
	
/*
 * Message family registry
 */
#define JNP_FAMILY_CORE       0x00000000
#define JNP_FAMILY_JMEM       0x01000000
#define JNP_FAMILY_PCAP       0x02000000
#define JNP_FAMILY_DECODER    0x03000000
#define JNP_FAMILY_ANALYSIS   0x04000000
#define JNP_FAMILY_COUNT      5
	
#define JNP_FAMILY(code)      ((code & 0xFF000000) >> 24)
#define JNP_LEVEL(code)       ((code & 0x00FF0000) >> 16)
#define JNP_CODE(code)        ((code & 0x0000FFFF) >> 00)
	
#define JNP_INFO              0x00000000
#define JNP_WARNING           0x00010000
#define JNP_ERROR             0x00020000
	
/*
 * JNP internal messages
 */
#define JNP_OK                0 | JNP_FAMILY_CORE | JNP_INFO
#define JNP_NULL_ARG          1 | JNP_FAMILY_CORE | JNP_ERROR
#define JNP_OUT_OF_MEMORY     2 | JNP_FAMILY_CORE | JNP_ERROR
#define JNP_FIELD_NOT_FOUND   3 | JNP_FAMILY_CORE | JNP_ERROR
#define JNP_METHOD_NOT_FOUND  4 | JNP_FAMILY_CORE | JNP_ERROR
#define JNP_CLASS_NOT_FOUND   5 | JNP_FAMILY_CORE | JNP_ERROR
#define JNP_MSG_COUNT         6

int         jnp_class       (JNIEnv *env, jclass *clazz, const char *name);
int         jnp_local_class (JNIEnv *env, jclass *clazz, const char *name);
int         jnp_method      (JNIEnv *env, jclass clazz, jmethodID *id, 
						const char *name, const char *sig);
int         jnp_field       (JNIEnv *env, jclass clazz, jfieldID *id, 
						const char *name, const char *sig);

/*
 * A few macros to make the job easier and easier to read in resulting code. 
 * The macro names are extrememly short on purpose so that we can try and
 * fit the entire definition on a single line, allowing elements to be indented
 * into columns.
 * 
 * Usage: 
 *   Must always start with jnp_id_start(); and end with jnp_id_end();
 * 
 *   The jclass object reference is inherited from the last jnp_c call.
 *   If there is an error, an exception will be thrown and the macro will execute
 *   a return statement, aborting the function immediately.
 * 
 *   Lastly, the macros expect JNIEnv * to be declared with name "env"
 * 
 * API:
 * jnp_id_start() = always at the start of the definition block
 * jnp_id_end()   = always at the end of the definition block
 * jnp_c()        = calls jnp_class()
 * jnp_m()        = calls jnp_method()
 * jnp_f()        = calls jnp_field()
 * 
 * Example:
 * 
 * jnp_id_start();
 * jnp_c(&CLASS_jmemory,             "org/jnetpcap/nio/JMemory");
 * jnp_f(&FID_jmemory_physical,      "physical",      "J");
 * jnp_m(&MID_jmemory_toDebugString, "toDebugString", "()Ljava/lang/String;");
 *
 * jnp_c(&CLASS_buffer,        "java/nio/Buffer");
 * jnp_m(&MID_buffer_position, "position", "()I");
 * jnp_m(&MID_buffer_limit,    "limit",    "()I");
 * jnp_end();
 * 
 */
#define jnp_id_start(e, c) {JNIEnv *__env = e; jclass *__clazz = ((c == NULL)?NULL:&c)
#define jnp_c(id, n)        if(jnp_class (__env,(__clazz = &id), n))      return
#define jnp_m(id, n, sig)   if(jnp_method(__env, *__clazz, &id,  n, sig)) return
#define jnp_f(id, n, sig)   if(jnp_field (__env, *__clazz, &id,  n, sig)) return
#define jnp_id_end()        }

/*
 * Error handling
 */
typedef struct jnp_exception_t {
	const char *fmt;
	const char *exception;
		
} jnp_exception_t;
	
int         jnp_add_messages    (int family, jnp_exception_t *messages);
int         jnp_error           ();
const char *jnp_perror          ();
int         jnp_code            (int code, ...);
int         jnp_vcode           (int code, va_list ap);
#define     jnp_OK()            (jnp_error_code = JNP_OK)
#define     jnp_ARG()           (jnp_error_code = JNP_NULL_ARG)
int         jnp_exception       (JNIEnv *env);
int         jnp_exception_code  (JNIEnv *env, int code, ...);
char       *jnp_object_toString (JNIEnv *env, jobject obj);
char       *jnp_class_getName   (JNIEnv *env, jobject obj);
char       *jnp_class_getSimpleName(JNIEnv *env, jobject obj);
char       *jnp_jstring         (JNIEnv *env, jstring str, char *buf);

#ifdef DEBUG
#define jnp_enter(method)	debug_enter(method)
#define jnp_exit_code(code, ...) (jnp_code(code, ##__VA_ARGS__),debug_exit())
#define jnp_exit_error()       (jnp_error(),debug_exit())
#define jnp_exit_OK()          (jnp_code(JNP_OK),debug_exit())
#define jnp_exit_ARG()         (jnp_code(JNP_NULL_ARG),debug_exit())
#define jnp_exit_exception(env) (jnp_exception(env),debug_exit())
#define jnp_exit_exception_code(env, code, ...) (jnp_exception_code(env, code, ##__VA_ARGS__), debug_exit())
#define jnp_exit(a)			   (debug_exit_after(),a)

#define jnp_trace(fmt, ...)   debug_trace(fmt, ##__VA_ARGS__)
#else
#define jnp_enter(method) 
#define jnp_exit_code(code, ...) jnp_code(code, ##__VA_ARGS__)
#define jnp_exit_error()       jnp_error()
#define jnp_exit_OK()          jnp_code(JNP_OK)
#define jnp_exit_ARG()         jnp_code(JNP_NULL_ARG)
#define jnp_exit_exception(env) jnp_exception(env)
#define jnp_exit_exception_code(env, code, ...) jnp_exception_code(env, code, ##__VA_ARGS__)
#define jnp_exit(a)			  (a)
#define jnp_trace(fmt, ...)   
#endif
	
extern int jnp_error_code;
extern jnp_exception_t *jnp_error_table[JNP_FAMILY_COUNT];

#ifdef __cplusplus
}
#endif
#endif
