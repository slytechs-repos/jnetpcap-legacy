/* Header for jnetpcap_utils utility methods */

#ifndef _Included_org_jnetpcap_Pcap_h
#define _Included_org_jnetpcap_Pcap_h

#include <pcap.h>
#include "jnp.h"

#define PCAP_ERROR(index)  (index | JNP_FAMILY_PCAP | JNP_ERROR)

#define PCAP_NEED_ALLOCATED_MEMORY		PCAP_ERROR(0)
#define PCAP_MSG_COUNT								1

extern jnp_exception_t pcap_msg_table[PCAP_MSG_COUNT];

#endif
