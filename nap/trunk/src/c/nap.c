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

#include "nap.h"

nap_t *nap_open_offline(const char *fname, char *errbuf) {
	const char *mode = "rb";
	
	FILE	*fhandle;
	if ((fhandle = fopen(fname, mode)) == NULL) {
		perror(errbuf); // Copy system error message
		return NULL;
	}
	
	/*
	 * Allocate and initialize the memory block. We don't want any surprises
	 */
	nap_t *nap = (nap_t *) malloc(NAP_SIZE);
	if (nap == NULL) {
		strcpy(errbuf, NAP_MSG_OUT_OF_MEMORY);
		fclose(fhandle);
		
		return NULL;
	}
	
	memset(nap, NAP_SIZE, 0);
	
	strcpy(nap->fname, fname);
	nap->fhandle = fhandle;
	strcpy(nap->fmode, mode); // Remember how we opened the file
	
	/* Determine file length */
	fseek(fhandle, 0, SEEK_END); // end
	nap->flength = ftell(fhandle);
	fseek(fhandle, 0, SEEK_SET); // Begining
	
	return nap;
}

nap_dumper_t *nap_dump_open(nap_t *n, const char *fname) {
	nap_dumper_t *dumper = malloc(sizeof(nap_dumper_t));
	
	dumper->fname = (char *)fname;
	dumper->nap = n;
	
	
}

void nap_dump(nap_dumper_t *dumper, nap_packet_t *hdr, char *d) {
	
}

void nap_cb_handler(char *dumper, nap_packet_t *hdr, char *data) {
	nap_dump((nap_dumper_t *)dumper, hdr, data);
}
