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

const nap_t *nap_open(const char *fname, char *errbuf) {
	return nap_open_mode(fname, NAP_DEFAULT_OPEN_MODE, errbuf);
}

const nap_t *nap_open_mode(const char *fname, char *mode, char *errbuf) {
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


void nap_close(nap_t *nap) {
	if (nap != NULL) {
		fclose(nap->fhandle);
		free((void *) nap);

	} 
}

block_t *nap_alloc_block(nap_t *nap, size_t size) {
	
	block_t *block = (block_t *)malloc(sizeof(block_t));
	block->b_nap = nap;
	block->b_start = 0;
	block->b_offset = 0;
	block->b_read = 0;
	
	block->b_header = (nap_block_t *)malloc(size);
	block->b_length = size;
}

void nap_free_block(block_t *block) {
	
	free(block->b_header);
	free(block);
}


int read_block_hdr(block_t *block) {
	
	nap_t *nap = block->b_nap;
	
	if (nap->flength == 0) {
		return NAP_NOT_FOUND; // Emtpy file
	}
	
	if (block->b_read >= NAP_BLOCK_SIZE) { // Already prefetched
		return NAP_OK;
	}
	
	/*
	 * Otherwise we read the header into our temporary memory
	 */
	fseek(nap->fhandle, block->b_start, SEEK_SET); // From start of file
	if (fread((void *) block->b_header, NAP_BLOCK_SIZE, 1, nap->fhandle) != NAP_BLOCK_SIZE) {
		return NAP_NOT_OK;
	}
	
	block->b_read = NAP_BLOCK_SIZE;
	
	return NAP_OK;
}

int read_block(block_t *block) {
	
	nap_t *nap = block->b_nap;
	
	if (nap->flength == 0) {
		return NAP_NOT_FOUND; // Emtpy file
	}
	
	if ( (block->b_read >= NAP_BLOCK_SIZE) && 
			(block->b_read == block->b_header->length)) { // Already prefetched
		
		return NAP_OK;
	}
	
	fseek(nap->fhandle, block->b_start, SEEK_SET); // From start of file
	
	int r = fread((void *) block->b_header,	
			1, 
			block->b_header->length, 
			nap->fhandle);
	
	block->b_read = block->b_header->length;
	
	return (r == block->b_header->length) ? NAP_OK : NAP_NOT_OK;
}

int write_block(block_t *block) {
	nap_t *nap = block->b_nap;
	uint32_t len = block->b_header->length;
	
	fseek(nap->fhandle, block->b_start, SEEK_SET); // From start of file
	int r = fwrite((void *)block->b_header, 1, len, nap->fhandle);
	
	return (r == len) ? NAP_OK : NAP_NOT_OK;
}

int next_block(block_t *block) {
	
	block->b_start += block->b_header->length;
	block->b_offset = 0; // First record
	block->b_read = 0; // First record
	
	return NAP_OK;
}

int prev_block(block_t *block) {
	
	if (block->b_start == 0) {
		return NAP_NOT_FOUND;
	}
	
	block->b_start -= block->b_header->length;
	block->b_offset = 0; // First record
	block->b_read = 0; // First record
	
	return NAP_OK;
}

int nap_global_id = NAP_BLOCK_MAGIC;
const uint32_t  generate_id() {
	return ++nap_global_id;
}

int init_block_header(nap_block_t *hdr) {
	hdr->magic = NAP_BLOCK_MAGIC;
	hdr->length = NAP_DEFAULT_BLOCK_SIZE;
	hdr->major = NAP_BLOCK_MAJOR;
	hdr->minor = NAP_BLOCK_MINOR;
	
	hdr->flags = NAP_DEFAULT_BLOCK_FLAGS;
	hdr->record_count = 0;
	hdr->payload_count[0] = 0;
	
	return NAP_OK;
}
