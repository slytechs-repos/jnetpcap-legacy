#ifndef _Included_api_descriptor_h
#define _Included_api_descriptor_h
#ifdef __cplusplus
extern "C" {
#define	EXTERN extern "C"
#endif

#include <jni.h>

typedef struct api_vtable {
	int vtable_count;
	JNINativeMethod *vtable;
} api_vtable;

jobject api_descriptor_jcreate(JNIEnv *env, api_vtable *ptr);
api_vtable *api_descriptor_jget(JNIEnv *env, jobject obj);

#ifdef __cplusplus
}
#endif
#endif
