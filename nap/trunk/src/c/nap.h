
// Include this file after jni.h is included. It undefines MS compiler, def for
// gcc specific one.
//
#ifndef Include_nap_h
#define Include_nap_h

#include <stdint.h>

#ifndef WIN32
#include <sys/socket.h>
#endif

#ifdef WIN32
#include <winsock2.h>
#endif

#undef __declspec
#define __declspec(a) extern "C"

#include "nap_record.h"


typedef struct nap_t {
	char		fname[NAP_FNAME_SIZE];
	FILE		*fhandle;
	uint64_t	flength;	// file length
	char		fmode[8];
	int			is_swapped; // Is byte-ordering swapped on this architecture
} nap_t, *pcap_t;

#define	NAP_SIZE			sizeof(nap_t)
#define NAP_END_OF_LIST 	-1

const nap_t *nap_open(const char *file, char *errbuf);
const nap_t *nap_open_mode(const char *file, char *mode, char *errbuf);
const uint32_t  generate_id();

block_t *nap_alloc_block(nap_t *nap, size_t size);
void nap_free_block(block_t *block);

/* Public API */
typedef struct nap_dumper_t {
	nap_t	*nap; // Parent NAP
	FILE 	*file;
	char	*fname;
} nap_dumper_t;

typedef struct nap_interface_t {
	char *name;
	char *description;
	struct sockaddr addresses;
	int snaplen;
	int dlt;
	int open_flags;
	int ts_resolution;
} nap_interface_t;


nap_t 			*nap_open_file(const char *fname, char *errbuf);
nap_dumper_t	*nap_dump_open(nap_t *n, const char *fname);

typedef void (*nap_handler)(char *user, const nap_packet_t *h, const char *buffer);

int nap_dispatch(nap_t *n, int cnt, nap_handler cb, char *user);
int nap_loop(nap_t *n, int cnt, nap_handler cb, char *user);

int nap_list_interfaces(nap_t *n, nap_interface_t **int_buffer);
const char *nap_lib_version(void);

void nap_close(nap_t *n);
int nap_dump_flush(nap_dumper_t *d);
long nap_ftell(nap_dumper_t *d);
FILE *nap_dump_file(nap_dumper_t *d);
void nap_dump_close(nap_dumper_t *d);
void nap_dump(nap_dumper_t *dumper, nap_packet_t *hdr, char *d);

#endif
