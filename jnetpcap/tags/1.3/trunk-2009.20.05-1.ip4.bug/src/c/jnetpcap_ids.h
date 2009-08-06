/* Header for jnetpcap_utils utility methods */

#ifndef _Included_jnetpcap_ids_h
#define _Included_jnetpcap_ids_h
#ifdef __cplusplus
extern "C" {
#define	EXTERN extern "C"
#endif

#include "export.h"
	
#include <jni.h>
	
extern jclass pcapClass;
extern jclass byteBufferClass;
extern jclass stringBuilderClass;
extern jclass pcapIfClass;
extern jclass pcapAddrClass;
extern jclass PcapSockAddrClass;
extern jclass pcapIntegerClass;

extern 	jmethodID byteBufferIsDirectMID;
extern 	jmethodID bufferGetPositionMID;
extern 	jmethodID bufferGetLimitMID;
extern 	jmethodID bufferSetLimitMID;
extern 	jmethodID bufferSetPositionMID;
extern 	jmethodID bufferGetPositionMID;
extern 	jmethodID bufferGetCapacityMID;


extern jclass msIpAdapterIndexMapClass;

extern jfieldID pcapPhysicalFID;
extern jfieldID pcapIntegerValueFID;


extern 	jfieldID PcapPktHdrSecondsFID;
extern 	jfieldID PcapPktHdrUSecondsFID;
extern 	jfieldID PcapPktHdrCaplenFID;
extern 	jfieldID PcapPktHdrLenFID;

extern 	jfieldID PcapPktBufferFID;

extern 	jfieldID pcapIfNextFID;
extern 	jfieldID pcapIfNameFID;
extern 	jfieldID pcapIfDescriptionFID;
extern 	jfieldID pcapIfAddressesFID;
extern 	jfieldID pcapIfFlagsFID;

extern 	jfieldID pcapAddrNextFID;
extern 	jfieldID pcapAddrAddrFID;
extern 	jfieldID pcapAddrNetmaskFID;
extern 	jfieldID pcapAddrBroadaddrFID;
extern 	jfieldID pcapAddrDstaddrFID;

extern 	jfieldID PcapSockAddrFamilyFID;
extern 	jfieldID PcapSockAddrDataFID;

extern 	jmethodID pcapConstructorMID;
extern 	jmethodID pcapIfConstructorMID;
extern 	jmethodID PcapSockAddrConstructorMID;
extern 	jmethodID pcapAddrConstructorMID;
extern 	jmethodID msIpAdapterIndexMapMID;

extern 	jmethodID appendMID;
extern 	jmethodID setLengthMID;

extern jclass pcapStatClass;

extern jfieldID pcapStatRecvFID;
extern jfieldID pcapStatDropFID;
extern jfieldID pcapStatIfDropFID;
extern jfieldID pcapStatCaptFID;
extern jfieldID pcapStatSentFID;
extern jfieldID pcapStatNetdropFID;

#ifdef __cplusplus
}
#endif
#endif
