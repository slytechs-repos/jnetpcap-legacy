
// Include this file after jni.h is included. It undefines MS compiler, def for
// gcc specific one.
//
#ifndef Include_export_h
#define Include_export_h

// JNIEXPORT is designed for microsoft compilers, we're using gcc to compile
#ifdef JNIEXPORT
#undef JNIEXPORT
#endif
#undef JNIEXPORT
#define JNIEXPORT extern "C"

#undef __declspec
#define __declspec(a) extern "C"

#ifndef FALSE
#define TRUE 1
#define FALSE !TRUE
#endif

#define u_int8_t uint8_t
#define u_int16_t uint16_t
#define u_int32_t uint32_t
#define u_int64_t uint64_t

#endif
