/*
* pdp-file.c
*
* Copyright (c) 2008, Zachary N J Peterson <zachary@jhu.edu>
* All rights reserved.
*
* Redistribution and use in source and binary forms, with or without
* modification, are permitted provided that the following conditions are met:
*     * Redistributions of source code must retain the above copyright
*       notice, this list of conditions and the following disclaimer.
*     * Redistributions in binary form must reproduce the above copyright
*       notice, this list of conditions and the following disclaimer in the
*       documentation and/or other materials provided with the distribution.
*     * The name of the Zachary N J Peterson may be used to endorse or promote products
*       derived from this software without specific prior written permission.
*
* THIS SOFTWARE IS PROVIDED BY ZACHARY N J PETERSON ``AS IS'' AND ANY
* EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
* WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
* DISCLAIMED. IN NO EVENT SHALL ZACHARY N J PETERSON BE LIABLE FOR ANY
* DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
* (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
* LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
* ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
* (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
* SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/


/* pdp-file.c contains some high-level functions for performing PDP functions on files.
*  The model is assumed to be that a user will perform all the computation for tagging AND
*  verifying.  This works well if the remote storage is able to be locally mounted.
*/

#include "pdp.h"
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/param.h>
#ifdef THREADING
#include <pthread.h>
#endif


/* write_pdp_tag: Write a PDP tag to disk.  Takes in an open file structure and a PDP tag structure
*  and serializes the tag.  The tagfile must be open for writing. Returns 1 on success and 0 failure.
*  NOTE: This function is not thread safe.  It should be called sequentially with a ordered list of tags.
*/
static int write_pdp_tag(FILE *tagfile, PDP_tag *tag){

	unsigned char *tim = NULL;
	size_t tim_size = 0;

	if(!tagfile || !tag || !tag->Tim) return 0;

	/* Write Tim to disk */
	tim_size = BN_num_bytes(tag->Tim);
	fwrite(&tim_size, sizeof(size_t), 1, tagfile);
	if(ferror(tagfile)) goto cleanup;
	if( ((tim = malloc(tim_size)) == NULL)) goto cleanup;
	memset(tim, 0, tim_size);
	if(!BN_bn2bin(tag->Tim, tim)) goto cleanup;
	fwrite(tim, tim_size, 1, tagfile);
	if(ferror(tagfile)) goto cleanup;

	/* write index */
	fwrite(&(tag->index), sizeof(unsigned int), 1, tagfile);
	if(ferror(tagfile)) goto cleanup;

	/* write index prf */
	fwrite(&(tag->index_prf_size), sizeof(size_t), 1, tagfile);
	if(ferror(tagfile)) goto cleanup;
	fwrite(tag->index_prf, tag->index_prf_size, 1, tagfile);
	if(ferror(tagfile)) goto cleanup;

	if(tim) sfree(tim, tim_size);
	return 1;

cleanup:
	if(tim) sfree(tim, tim_size);
	return 0;
}

/* read_pdp_tag: Reads a PDP tag from disk.  Takes an open file structure and the index of a PDP tag
*  and reads from disk, returning a PDP tag structure or NULL on failure.  The tagfile must be open for
*  reading.
*/
PDP_tag *read_pdp_tag(FILE *tagfile, unsigned int index){

	PDP_tag *tag = NULL;
	unsigned char *tim = NULL;
	size_t tim_size = 0;
	size_t index_prf_size = 0;
	int i = 0;

	if(!tagfile) return NULL;

	/* Allocate memory */
	if( ((tag = generate_pdp_tag()) == NULL)) goto cleanup;

	/* Seek to start of tag file */
	if(fseek(tagfile, 0, SEEK_SET) < 0) goto cleanup;

	/* Seek to tag offset index */
	for(i = 0; i < index; i++){
		fread(&tim_size, sizeof(size_t), 1, tagfile);
		if(ferror(tagfile)) goto cleanup;
		if(fseek(tagfile, (tim_size + sizeof(unsigned int)), SEEK_CUR) < 0) goto cleanup;
		fread(&(index_prf_size), sizeof(size_t), 1, tagfile);
		if(fseek(tagfile, (index_prf_size), SEEK_CUR) < 0) goto cleanup;
	}

	/*Read in Tim */
	fread(&tim_size, sizeof(size_t), 1, tagfile);
	if(ferror(tagfile)) goto cleanup;
	if( ((tim = malloc((unsigned int)tim_size)) == NULL)) goto cleanup;
	memset(tim, 0, (unsigned int)tim_size);
	fread(tim, (unsigned int)tim_size, 1, tagfile);
	if(ferror(tagfile)) goto cleanup;

	if(!BN_bin2bn(tim, tim_size, tag->Tim)) goto cleanup;

	/* read index */
	fread(&(tag->index), sizeof(unsigned int), 1, tagfile);
	if(ferror(tagfile)) goto cleanup;

	/* write index prf */
	fread(&(tag->index_prf_size), sizeof(size_t), 1, tagfile);
	if(ferror(tagfile)) goto cleanup;
	if( ((tag->index_prf = malloc((unsigned int)tag->index_prf_size)) == NULL)) goto cleanup;
	memset(tag->index_prf, 0, (unsigned int)tag->index_prf_size);
	fread(tag->index_prf, (unsigned int)tag->index_prf_size, 1, tagfile);
	if(ferror(tagfile)) goto cleanup;

	if(tim) sfree(tim, tim_size);

	return tag;

cleanup:
	if(tag->index_prf) sfree(tag->index_prf, tag->index_prf_size);
	if(tag) destroy_pdp_tag(tag);
	if(tim) sfree(tim, tim_size);

	return NULL;
}

/**
 * write_pdp_challenge: Writes the challenge to disk
 */
int write_pdp_challenge(FILE *chalfile, PDP_challenge *chal) {
	unsigned char *g_s = NULL;
	unsigned char *s = NULL;
	size_t g_s_size = 0;
	size_t s_size = 0;
	size_t k1_size = 0;
	size_t k2_size = 0;

	if (!chalfile || !chal || !chal->g_s || !chal->s) return 0;

	/* Write c, number of blocks to file */
	fwrite(&(chal->c), sizeof(unsigned int), 1, chalfile);
	if(ferror(chalfile)) goto cleanup;

	/* Write numfileblocks, number of total blocks to file */
	fwrite(&(chal->numfileblocks), sizeof(unsigned int), 1, chalfile);
	if(ferror(chalfile)) goto cleanup;

	/* Write g_s, random secret base to file */
	g_s_size = BN_num_bytes(chal->g_s);
	fwrite(&g_s_size, sizeof(size_t), 1, chalfile);
	if(ferror(chalfile)) goto cleanup;
	if( (g_s = malloc(g_s_size)) == NULL) goto cleanup;
	memset(g_s, 0, g_s_size);
	if(!BN_bn2bin(chal->g_s, g_s)) goto cleanup;
	fwrite(g_s, g_s_size, 1, chalfile);
	if(ferror(chalfile)) goto cleanup;

	/* Write s, random secret to file */
	s_size = BN_num_bytes(chal->s);
	fwrite(&s_size, sizeof(size_t), 1, chalfile);
	if(ferror(chalfile)) goto cleanup;
	if( (s = malloc(s_size)) == NULL) goto cleanup;
	memset(s, 0, s_size);
	if(!BN_bn2bin(chal->s, s)) goto cleanup;
	fwrite(s, s_size, 1, chalfile);
	if(ferror(chalfile)) goto cleanup;

	/* Write k1, PRP key to file */
	k1_size = PRP_KEY_SIZE;
	fwrite(&(k1_size), sizeof(size_t), 1, chalfile);
	if(ferror(chalfile)) goto cleanup;
	fwrite(chal->k1, k1_size, 1, chalfile);
	if(ferror(chalfile)) goto cleanup;

	/* Write k2, PRF key to file */
	k2_size = PRP_KEY_SIZE;
	fwrite(&(k2_size), sizeof(size_t), 1, chalfile);
	if(ferror(chalfile)) goto cleanup;
	fwrite(chal->k2, k2_size, 1, chalfile);
	if(ferror(chalfile)) goto cleanup;

	if(g_s) sfree(g_s, g_s_size);
	if(s) sfree(s, s_size);
	return 1;

cleanup:
	if (g_s) sfree(g_s, g_s_size);
	if (s) sfree(s, s_size);
	return 0;
}

/**
 * write_pdp_server_challenge: Writes the server_challenge to disk
 */
int write_pdp_server_challenge(FILE *chalfile, PDP_challenge *chal) {
	unsigned char *g_s = NULL;
	size_t g_s_size = 0;
	size_t k1_size = 0;
	size_t k2_size = 0;

	if (!chalfile || !chal || !chal->g_s || !chal->s) return 0;

	/* Write c, number of blocks to file */
	fwrite(&(chal->c), sizeof(unsigned int), 1, chalfile);
	if(ferror(chalfile)) goto cleanup;

	/* Write numfileblocks, number of total blocks to file */
	fwrite(&(chal->numfileblocks), sizeof(unsigned int), 1, chalfile);
	if(ferror(chalfile)) goto cleanup;

	/* Write g_s, random secret base to file */
	g_s_size = BN_num_bytes(chal->g_s);
	fwrite(&g_s_size, sizeof(size_t), 1, chalfile);
	if(ferror(chalfile)) goto cleanup;
	if( (g_s = malloc(g_s_size)) == NULL) goto cleanup;
	memset(g_s, 0, g_s_size);
	if(!BN_bn2bin(chal->g_s, g_s)) goto cleanup;
	fwrite(g_s, g_s_size, 1, chalfile);
	if(ferror(chalfile)) goto cleanup;

	/* Write k1, PRP key to file */
	k1_size = PRP_KEY_SIZE;
	fwrite(&(k1_size), sizeof(size_t), 1, chalfile);
	if(ferror(chalfile)) goto cleanup;
	fwrite(chal->k1, k1_size, 1, chalfile);
	if(ferror(chalfile)) goto cleanup;

	/* Write k2, PRF key to file */
	k2_size = PRF_KEY_SIZE;
	fwrite(&(k2_size), sizeof(size_t), 1, chalfile);
	if(ferror(chalfile)) goto cleanup;
	fwrite(chal->k2, k2_size, 1, chalfile);
	if(ferror(chalfile)) goto cleanup;

	if(g_s) sfree(g_s, g_s_size);
	return 1;

cleanup:
	if (g_s) sfree(g_s, g_s_size);
	return 0;
}

/**
 * read_pdp_challenge: Reads the challenge from disk
 */
PDP_challenge *read_pdp_challenge(FILE *chalfile) {
	PDP_challenge *chal = NULL;
	unsigned char *g_s = NULL;
	unsigned char *s = NULL;
	size_t g_s_size = 0;
	size_t s_size = 0;
	size_t k1_size = 0;
	size_t k2_size = 0;

	if(!chalfile) return NULL;

	if((chal = generate_pdp_challenge()) == NULL) goto cleanup;

	/* Seek to beginning of the file */
	if(fseek(chalfile, 0, SEEK_SET) < 0) goto cleanup;

	/* Read in c */
	fread(&(chal->c), sizeof(unsigned int), 1, chalfile);
	if(ferror(chalfile)) goto cleanup;

	/* Read in numfileblocks */
	fread(&(chal->numfileblocks), sizeof(unsigned int), 1, chalfile);
	if(ferror(chalfile)) goto cleanup;

	/* Read in g_s */
	fread(&g_s_size, sizeof(size_t), 1, chalfile);
	if(ferror(chalfile)) goto cleanup;
	if( (g_s = malloc((unsigned int)g_s_size)) == NULL) goto cleanup;
	memset(g_s, 0, (unsigned int)g_s_size);
    fread(g_s, (unsigned int)g_s_size, 1, chalfile);
    if(ferror(chalfile)) goto cleanup;

    if(!BN_bin2bn(g_s, g_s_size, chal->g_s)) goto cleanup;

	/* Read in s */
	fread(&s_size, sizeof(size_t), 1, chalfile);
	if(ferror(chalfile)) goto cleanup;
	if( (s = malloc((unsigned int)s_size)) == NULL) goto cleanup;
	memset(s, 0, (unsigned int)s_size);
    fread(s, (unsigned int)s_size, 1, chalfile);
    if(ferror(chalfile)) goto cleanup;

    if(!BN_bin2bn(s, s_size, chal->s)) goto cleanup;

	/* Read in k1*/
	fread(&k1_size, sizeof(size_t), 1, chalfile);
	if(ferror(chalfile)) goto cleanup;
	if ((chal->k1 = malloc((unsigned int)k1_size)) == NULL) goto cleanup;
    memset(chal->k1, 0, (unsigned int)k1_size);
    fread(chal->k1, (unsigned int)k1_size, 1, chalfile);
    if(ferror(chalfile)) goto cleanup;

	/* Read in k2*/
	fread(&k2_size, sizeof(size_t), 1, chalfile);
	if(ferror(chalfile)) goto cleanup;
	if ((chal->k2 = malloc((unsigned int)k2_size)) == NULL) goto cleanup;
    memset(chal->k2, 0, (unsigned int)k2_size);
    fread(chal->k2, (unsigned int)k2_size, 1, chalfile);
    if(ferror(chalfile)) goto cleanup;

	if(g_s) sfree(g_s, g_s_size);
	if(s) sfree(s, s_size);

	return chal;

cleanup:
	if(chal->k1) sfree(chal->k1, k1_size);
	if(chal->k2) sfree(chal->k2, k2_size);
	if(chal->g_s) sfree(chal->g_s, g_s_size);
	if(chal->s) sfree(chal->s, s_size);
	if(chal) destroy_pdp_challenge(chal);
	return NULL;
}

/**
 * read_pdp_server_challenge: Reads the server_challenge from disk
 */
PDP_challenge *read_pdp_server_challenge(FILE *chalfile) {
	PDP_challenge *chal = NULL;
	unsigned char *g_s = NULL;
	size_t g_s_size = 0;
	size_t k1_size = 0;
	size_t k2_size = 0;

	if(!chalfile) return NULL;

	if((chal = generate_pdp_challenge()) == NULL) goto cleanup;

	/* Seek to beginning of the file */
	if(fseek(chalfile, 0, SEEK_SET) < 0) goto cleanup;

	/* Read in c */
	fread(&(chal->c), sizeof(unsigned int), 1, chalfile);
	if(ferror(chalfile)) goto cleanup;

	/* Read in numfileblocks */
	fread(&(chal->numfileblocks), sizeof(unsigned int), 1, chalfile);
	if(ferror(chalfile)) goto cleanup;

	/* Read in g_s */
	fread(&g_s_size, sizeof(size_t), 1, chalfile);
	if(ferror(chalfile)) goto cleanup;
	if( (g_s = malloc((unsigned int)g_s_size)) == NULL) goto cleanup;
	memset(g_s, 0, (unsigned int)g_s_size);
    fread(g_s, (unsigned int)g_s_size, 1, chalfile);
    if(ferror(chalfile)) goto cleanup;

    if(!BN_bin2bn(g_s, g_s_size, chal->g_s)) goto cleanup;

	/* Read in k1*/
	fread(&k1_size, sizeof(size_t), 1, chalfile);
	if(ferror(chalfile)) goto cleanup;
	if ((chal->k1 = malloc((unsigned int)k1_size)) == NULL) goto cleanup;
    memset(chal->k1, 0, (unsigned int)k1_size);
    fread(chal->k1, (unsigned int)k1_size, 1, chalfile);
    if(ferror(chalfile)) goto cleanup;

	/* Read in k2*/
	fread(&k2_size, sizeof(size_t), 1, chalfile);
	if(ferror(chalfile)) goto cleanup;
	if ((chal->k2 = malloc((unsigned int)k2_size)) == NULL) goto cleanup;
    memset(chal->k2, 0, (unsigned int)k2_size);
    fread(chal->k2, (unsigned int)k2_size, 1, chalfile);
    if(ferror(chalfile)) goto cleanup;

	if(g_s) sfree(g_s, g_s_size);

	return chal;

cleanup:
	if(chal->k1) sfree(chal->k1, k1_size);
	if(chal->k2) sfree(chal->k2, k2_size);
	if(chal->g_s) sfree(chal->g_s, g_s_size);
	if(chal) destroy_pdp_challenge(chal);
	return NULL;
}


/**
 * write_pdp_proof: Writes the proof to disk
 */
int write_pdp_proof(FILE *prooffile, PDP_proof *proof) {
	unsigned char *T = NULL;
	unsigned char *rho_temp = NULL;
	size_t T_size = 0;
	size_t rho_temp_size = 0;

	if (!prooffile || !proof || !proof->T || !proof->rho_temp) return 0;


	/* Write T, product of tags to file */
	T_size = BN_num_bytes(proof->T);
	fwrite(&T_size, sizeof(size_t), 1, prooffile);
	if(ferror(prooffile)) goto cleanup;
	if( (T = malloc(T_size)) == NULL) goto cleanup;
	memset(T, 0, T_size);
	if(!BN_bn2bin(proof->T, T)) goto cleanup;
	fwrite(T, T_size, 1, prooffile);
	if(ferror(prooffile)) goto cleanup;

	/* Write rho_temp, a running tally of rho to file */
	rho_temp_size = BN_num_bytes(proof->rho_temp);
	fwrite(&rho_temp_size, sizeof(size_t), 1, prooffile);
	if(ferror(prooffile)) goto cleanup;
	if( (rho_temp = malloc(rho_temp_size)) == NULL) goto cleanup;
	memset(rho_temp, 0, rho_temp_size);
	if(!BN_bn2bin(proof->rho_temp, rho_temp)) goto cleanup;
	fwrite(rho_temp, rho_temp_size, 1, prooffile);
	if(ferror(prooffile)) goto cleanup;

	/* Write rho, PRP key to file */
	fwrite(&(proof->rho_size), sizeof(size_t), 1, prooffile);
	if(ferror(prooffile)) goto cleanup;
	fwrite(proof->rho, proof->rho_size, 1, prooffile);
	if(ferror(prooffile)) goto cleanup;


	if(T) sfree(T, T_size);
	if(rho_temp) sfree(rho_temp, rho_temp_size);
	return 1;

cleanup:
	if (T) sfree(T, T_size);
	if (rho_temp) sfree(rho_temp, rho_temp_size);
	return 0;
}


/**
 * read_pdp_proof: Reads the proof from disk
 */
PDP_proof *read_pdp_proof(FILE *prooffile) {
	PDP_proof *proof = NULL;
	unsigned char *T = NULL;
	unsigned char *rho_temp = NULL;
	size_t T_size = 0;
	size_t rho_temp_size = 0;


	if(!prooffile) return NULL;

	if((proof = generate_pdp_proof()) == NULL) goto cleanup;

	/* Seek to beginning of the file */
	if(fseek(prooffile, 0, SEEK_SET) < 0) goto cleanup;

	/* Read in T */
	fread(&T_size, sizeof(size_t), 1, prooffile);
	if(ferror(prooffile)) goto cleanup;
	if( (T = malloc((unsigned int)T_size)) == NULL) goto cleanup;
	memset(T, 0, (unsigned int)T_size);
    fread(T, (unsigned int)T_size, 1, prooffile);
    if(ferror(prooffile)) goto cleanup;

    if(!BN_bin2bn(T, T_size, proof->T)) goto cleanup;

	/* Read in rho_temp */
	fread(&rho_temp_size, sizeof(size_t), 1, prooffile);
	if(ferror(prooffile)) goto cleanup;
	if( (rho_temp = malloc((unsigned int)rho_temp_size)) == NULL) goto cleanup;
	memset(rho_temp, 0, (unsigned int)rho_temp_size);
    fread(rho_temp, (unsigned int)rho_temp_size, 1, prooffile);
    if(ferror(prooffile)) goto cleanup;

    if(!BN_bin2bn(rho_temp, rho_temp_size, proof->rho_temp)) goto cleanup;

	/* Read in rho*/
	fread(&(proof->rho_size), sizeof(size_t), 1, prooffile);
	if(ferror(prooffile)) goto cleanup;
	if ((proof->rho = malloc((unsigned int)proof->rho_size)) == NULL) goto cleanup;
    memset(proof->rho, 0, (unsigned int)proof->rho_size);
    fread(proof->rho, (unsigned int)proof->rho_size, 1, prooffile);
    if(ferror(prooffile)) goto cleanup;

	if(T) sfree(T, T_size);
	if(rho_temp) sfree(rho_temp, rho_temp_size);

	return proof;

cleanup:
	if(proof->rho) sfree(proof->rho, proof->rho_size);
	if(proof->T) sfree(proof->T, T_size);
	if(proof->rho_temp) sfree(proof->rho_temp, rho_temp_size);
	if(proof) destroy_pdp_proof(proof);
	return NULL;
}

#ifdef THREADING

struct thread_arguments{

	FILE *file;		/* File to tag; a unique file descriptor to this thread */
	PDP_key *key;	/* PDP key pair */
	int threadid;	/* The ID of the thread used to determine which blocks to tag */
	int numblocks;	/* The number blocks this thread needs to tag */
	PDP_tag **tags;	/* Shared memory between threads used to store the result tags */
};

void *pdp_tag_thread(void *threadargs_ptr){

	PDP_tag *tag = NULL;
	int block;
	int *ret = NULL;
	unsigned char buf[PDP_BLOCKSIZE];
	struct thread_arguments *threadargs = threadargs_ptr;
	int i = 0;

	if(!threadargs || !threadargs->file || !threadargs->tags || !threadargs->key || !threadargs->numblocks) goto cleanup;

	/* Allocate memory for return value - this should be freed by the checker */
	ret = malloc(sizeof(int));
	if(!ret) goto cleanup;
	*ret = 0;

	/* For N threads, read in and tag each Nth block */
	block = threadargs->threadid;
	for(i = 0; i < threadargs->numblocks; i++){
		memset(buf, 0, PDP_BLOCKSIZE);
		fseek(threadargs->file, block*PDP_BLOCKSIZE, SEEK_SET);
		fread(buf, PDP_BLOCKSIZE, 1, threadargs->file);
		if(ferror(threadargs->file))goto cleanup;
		tag = pdp_tag_block(threadargs->key, buf, PDP_BLOCKSIZE, block);
		if(!tag) goto cleanup;
		/* Store the tag in a buffer until all threads are done. Writer should destroy tags. */
		threadargs->tags[block] = tag;
		block += NUM_THREADS;
	}

	*ret = 1;
	pthread_exit(ret);

cleanup:
	pthread_exit(ret);

}

#endif

/* pdp_tag_file: PDP tags the given file.  Takes in a path to a file, opens it, and performs a PDP
*  tagging of the data.  The output is written to a a file specified by tagfilepath or to the filepath
*  with a .tag extension.  Returns 1 on success and 0 on failure.
*/
int pdp_tag_file(char *filepath, size_t filepath_len, char *tagfilepath, size_t tagfilepath_len){

	PDP_key *key = NULL;
	FILE *file = NULL;
	FILE *tagfile = NULL;
	unsigned int index = 0;
	char yesorno = 0;
	char realtagfilepath[MAXPATHLEN];
	BIGNUM *m;
	unsigned char *h_result;
	size_t h_size = 0;
#ifdef THREADING
	pthread_t threads[NUM_THREADS];
	int *thread_return = NULL;
	struct thread_arguments threadargs[NUM_THREADS];
	struct stat st;
	size_t numfileblocks = 0;

	PDP_tag **tags = NULL;

	memset(threads, 0, sizeof(pthread_t) * NUM_THREADS);
	memset(&st, 0, sizeof(struct stat));
#else
	unsigned char buf[PDP_BLOCKSIZE];
	PDP_tag *tag = NULL;
#endif

	memset(realtagfilepath, 0, MAXPATHLEN);

	if(!filepath) return 0;
	if(filepath_len >= MAXPATHLEN) return 0;
	if(tagfilepath_len >= MAXPATHLEN) return 0;

	/* If no tag file path is specified, add a .tag extension to the filepath */
	if(!tagfilepath && (filepath_len < MAXPATHLEN - 5)){
		if( snprintf(realtagfilepath, MAXPATHLEN, "%s.tag", filepath) >= MAXPATHLEN ) goto cleanup;
	}else{
		memcpy(realtagfilepath, tagfilepath, tagfilepath_len);
	}

	/* Check to see if the tag file exists */
	if( access(realtagfilepath, F_OK) == 0){
#ifdef DEBUG_MODE
		yesorno = 'y';
#else
		fprintf(stdout, "WARNING: %s already exists; do you want to overwrite (y/N)?", realtagfilepath);
		scanf("%c", &yesorno);
#endif
		if(yesorno != 'y') goto exit;
	}

	tagfile = fopen(realtagfilepath, "w");
	if(!tagfile){
		fprintf(stderr, "ERROR: Was not able to create %s.\n", realtagfilepath);
		goto cleanup;
	}

	/* Get the PDP key */
	key = pdp_get_keypair();
	if(!key) goto cleanup;

	/* For each block of the file, tag it and write the tag to disk */

#ifdef THREADING
	/* Calculate the number pdp blocks in the file */
	if(stat(filepath, &st) < 0) return 0;
	numfileblocks = (st.st_size/PDP_BLOCKSIZE);
	if(st.st_size%PDP_BLOCKSIZE) numfileblocks++;

	/* Allocate buffer to hold tags until we write them out */
	if( ((tags = malloc( (sizeof(PDP_tag *) * numfileblocks) )) == NULL)) goto cleanup;
	memset(tags, 0, (sizeof(PDP_tag *) * numfileblocks));

	for(index = 0; index < NUM_THREADS; index++){
		/* Open a unique file descriptor for each thread to avoid race conditions */
		threadargs[index].file = fopen(filepath, "r");
		if(!threadargs[index].file) goto cleanup;
		threadargs[index].key = key;
		threadargs[index].threadid = index;
		threadargs[index].numblocks = numfileblocks/NUM_THREADS;
		threadargs[index].tags = tags;

		/* If there is not an equal number of blocks to tag, add the extra blocks to
		 * the corresponding threads */
		if(index < numfileblocks%NUM_THREADS)
			threadargs[index].numblocks++;
		/* If the thread has blocks to tag, spawn it */
		if(threadargs[index].numblocks > 0)
			if(pthread_create(&threads[index], NULL, pdp_tag_thread, (void *) &threadargs[index]) != 0) goto cleanup;
	}
	/* Check to see all tags were generated */
	for(index = 0; index < NUM_THREADS; index++){
		if(threads[index]){
			if(pthread_join(threads[index], (void **)&thread_return) != 0) goto cleanup;
			if(!thread_return || !(*thread_return))goto cleanup;
			else free(thread_return);
			/* Close the file */
			if(threadargs[index].file)
				fclose(threadargs[index].file);
		}
	}

	/* Write the tags out */
	for(index = 0; index < numfileblocks; index++){
		if(!tags[index]) goto cleanup;
		if(!write_pdp_tag(tagfile, tags[index])) goto cleanup;
		destroy_pdp_tag(tags[index]);
		tags[index] = NULL;
	}
	sfree(tags, (sizeof(PDP_tag *) * numfileblocks));
#else
	file = fopen(filepath, "r");
	if(!file){
		fprintf(stderr, "ERROR: Was not able to open %s for reading.\n", filepath);
		goto cleanup;
	}
	// int counter = 0;
	m = BN_new();
	do{
		memset(buf, 0, PDP_BLOCKSIZE);
		fread(buf, PDP_BLOCKSIZE, 1, file);
		if(ferror(file)) goto cleanup;
		tag = pdp_tag_block(key, buf, PDP_BLOCKSIZE, index);
		// if(!BN_bin2bn(buf, PDP_BLOCKSIZE, m)) perror("failed.");
		// h_result = generate_H(m, &h_size);
		if(!tag) goto cleanup;
		if(!write_pdp_tag(tagfile, tag)) goto cleanup;
		index++;
		destroy_pdp_tag(tag);
		tag = NULL;
	}while(!feof(file));
	// printf("\nIndex: %d\n", index);
#endif

exit:
	destroy_pdp_key(key);
	if(file) fclose(file);
	if(tagfile) fclose(tagfile);

	return 1;

cleanup:
	fprintf(stderr, "ERROR: Was unable to create tag file.\n");
#ifdef THREADING
	for(index = 0; index < NUM_THREADS; index++){
		if(threads[index] != NULL) pthread_cancel(threads[index]);
		if(threadargs[index].file) fclose(threadargs[index].file);
	}

	for(index = 0; index < numfileblocks; index++){
		if(tags[index]){
			destroy_pdp_tag(tags[index]);
			tags[index] = NULL;
		}
	}
	if(tags) sfree(tags, (sizeof(PDP_tag *) * numfileblocks));
#endif

	destroy_pdp_key(key);
	if(file) fclose(file);
	if(tagfile){
		ftruncate(fileno(tagfile), 0);
		unlink(realtagfilepath);
		fclose(tagfile);
	}
	return 0;
}

/* pdp_challenge_file: Creates a challenge for a file that is numfileblocks long.  Takes in a numfileblocks, the number of blocks
 * the file to be challenged.  Returns an allocated challenge structure or NULL on error.
 *
*/
PDP_challenge *pdp_challenge_file(unsigned int numfileblocks){

	PDP_key *key = NULL;
	PDP_challenge *challenge = NULL;

	if(!numfileblocks) return NULL;

	/* Get the PDP key */
	key = pdp_get_keypair();
	if(!key) goto cleanup;

	/* Create a challenge */
	challenge = pdp_challenge(key, numfileblocks);
	if(!challenge) goto cleanup;

	if(key) destroy_pdp_key(key);

	return challenge;

cleanup:
	if(challenge) destroy_pdp_challenge(challenge);
	if(key) destroy_pdp_key(key);

	return NULL;
}

/* pdp_prove_file: Computes the server-side proof.
 * Takes in the file to be proven, its corresponding tag file, and a "sanitized" challenge and key structure.
 * Returns an allocated proof structure or NULL on error.
*/
PDP_proof *pdp_prove_file(char *filepath, size_t filepath_len, char *tagfilepath, size_t tagfilepath_len, PDP_challenge *challenge, PDP_key *key){

	PDP_proof *proof = NULL;
	PDP_tag *tag = NULL;
	unsigned int *indices = NULL;
	FILE *file = NULL;
	FILE *tagfile = NULL;
	char realtagfilepath[MAXPATHLEN];
	unsigned char buf[PDP_BLOCKSIZE];
	int j = 0;

	memset(realtagfilepath, 0, MAXPATHLEN);

	if(!filepath || !challenge || !key) return NULL;
	if(filepath_len >= MAXPATHLEN) return NULL;
	if(tagfilepath_len >= MAXPATHLEN) return NULL;

	file = fopen(filepath, "r");
	if(!file){
		fprintf(stderr, "ERROR: Was unable to open %s\n", filepath);
		return NULL;
	}

	/* If no tag file path is specified, add a .tag extension to the filepath */
	if(!tagfilepath && (filepath_len < MAXPATHLEN - 5)){
		if( snprintf(realtagfilepath, MAXPATHLEN, "%s.tag", filepath) >= MAXPATHLEN) goto cleanup;
	}else{
		memcpy(realtagfilepath, tagfilepath, tagfilepath_len);
	}

	tagfile = fopen(realtagfilepath, "r");
	if(!tagfile) goto cleanup;

	/* Compute the indices i_j = pi_k1(j); the block indices to sample */
	indices = generate_prp_pi(challenge);
	if(!indices) goto cleanup;

	for(j = 0; j < challenge->c; j++){
		memset(buf, 0, PDP_BLOCKSIZE);

		/* Seek to data block at indices[j] */
		if(fseek(file, (PDP_BLOCKSIZE * (indices[j])), SEEK_SET) < 0) goto cleanup;

		/* Read data block */
		fread(buf, PDP_BLOCKSIZE, 1, file);
		if(ferror(file)) goto cleanup;

		/* Read tag for data block at indices[j] */
		tag = read_pdp_tag(tagfile, indices[j]);
		if(!tag) goto cleanup;

		proof = pdp_generate_proof_update(key, challenge, tag, proof, buf, PDP_BLOCKSIZE, j);
		if(!proof) goto cleanup;

		destroy_pdp_tag(tag);
		tag = NULL;
	}

	proof = pdp_generate_proof_final(key, challenge, proof);
	if(!proof) goto cleanup;

	if(indices) sfree(indices, (challenge->c * sizeof(unsigned int)));
	if(file) fclose(file);
	if(tagfile) fclose(tagfile);

	return proof;

cleanup:
	if(indices) sfree(indices, (challenge->c * sizeof(unsigned int)));
	if(proof) destroy_pdp_proof(proof);
	if(tag) destroy_pdp_tag(tag);
	if(file) fclose(file);
	if(tagfile) fclose(tagfile);
	return NULL;
}

int pdp_verify_file(PDP_challenge *challenge, PDP_proof *proof){

	PDP_key *key = NULL;
	int result = 0;

	if(!challenge || !proof) return 0;

	/* Get the PDP key */
	key = pdp_get_keypair();
	if(!key) return 0;

	result = pdp_verify_proof(key, challenge, proof);

	if(key) destroy_pdp_key(key);

	return result;
}

/* pdp_challenge_and_verify_file: Creates an challenge and PDP verifies the contents of a file.  Takes in the path
*  to a file and its corresponding tag file.  If the path to the tag file is NULL, .tag is added to the
*  file path and attempted to be open.  Returns 1 on verification and 0 on failure.
*/
int pdp_challenge_and_verify_file(char *filepath, size_t filepath_len, char *tagfilepath, size_t tagfilepath_len){

	PDP_key *key = NULL;
	PDP_challenge *challenge = NULL;
	PDP_tag *tag = NULL;
	PDP_proof *proof = NULL;
	FILE *file = NULL;
	FILE *tagfile = NULL;
	struct stat st;
	unsigned int numfileblocks = 0;
	int j = 0;
	int result = 0;
	unsigned int *indices = NULL;
	char realtagfilepath[MAXPATHLEN];
	unsigned char buf[PDP_BLOCKSIZE];

	memset(realtagfilepath, 0, MAXPATHLEN);

	if(!filepath) return 0;
	if(filepath_len >= MAXPATHLEN) return 0;
	if(tagfilepath_len >= MAXPATHLEN) return 0;

	file = fopen(filepath, "r");
	if(!file){
		fprintf(stderr, "ERROR: Was unable to open %s\n", filepath);
		return 0;
	}

	/* If no tag file path is specified, add a .tag extension to the filepath */
	if(!tagfilepath && (filepath_len < MAXPATHLEN - 5)){
		if( snprintf(realtagfilepath, MAXPATHLEN, "%s.tag", filepath) >= MAXPATHLEN) goto cleanup;
	}else{
		memcpy(realtagfilepath, tagfilepath, tagfilepath_len);
	}

	tagfile = fopen(realtagfilepath, "r");
	if(!tagfile){
		fprintf(stderr, "ERROR: Was unable to open %s\n", realtagfilepath);
		goto cleanup;
	}

	if(stat(filepath, &st) < 0) goto cleanup;

	/* Calculate the number pdp blocks in the file */
	numfileblocks = (st.st_size/PDP_BLOCKSIZE);
	if(st.st_size%PDP_BLOCKSIZE)
		numfileblocks++;

	/* Get the PDP key */
	key = pdp_get_keypair();
	if(!key) goto cleanup;

	/* Create a challenge */
	challenge = pdp_challenge(key, numfileblocks);
	if(!challenge) goto cleanup;

	/* Compute the indices i_j = pi_k1(j); the block indices to sample */
	indices = generate_prp_pi(challenge);
	if(!indices) goto cleanup;

	for(j = 0; j < challenge->c; j++){
		memset(buf, 0, PDP_BLOCKSIZE);

		/* Seek to data block at indices[j] */
		if(fseek(file, (PDP_BLOCKSIZE * (indices[j])), SEEK_SET) < 0) goto cleanup;

		/* Read data block */
		fread(buf, PDP_BLOCKSIZE, 1, file);
		if(ferror(file)) goto cleanup;

		/* Read tag for data block at indices[j] */
		tag = read_pdp_tag(tagfile, indices[j]);
		if(!tag) goto cleanup;

		proof = pdp_generate_proof_update(key, challenge, tag, proof, buf, PDP_BLOCKSIZE, j);
		if(!proof) goto cleanup;

		destroy_pdp_tag(tag);
	}

	proof = pdp_generate_proof_final(key, challenge, proof);
	if(!proof) goto cleanup;

	result = pdp_verify_proof(key, challenge, proof);

	if(indices) sfree(indices, (challenge->c * sizeof(unsigned int)));
	if(challenge) destroy_pdp_challenge(challenge);
	if(proof) destroy_pdp_proof(proof);
	if(key) destroy_pdp_key(key);
	if(file) fclose(file);
	if(tagfile) fclose(tagfile);

	return result;

cleanup:
	fprintf(stderr, "ERROR: There was an error verifying.\n");
	if(indices) sfree(indices, (challenge->c * sizeof(unsigned int)));
	if(challenge) destroy_pdp_challenge(challenge);
	if(proof) destroy_pdp_proof(proof);
	if(key) destroy_pdp_key(key);
	if(tag) destroy_pdp_tag(tag);
	if(file) fclose(file);
	if(tagfile) fclose(tagfile);

	return 0;
}

int write_merkel_tree(FILE* tree_file, unsigned char* hash) {
	if (!tree_file || !hash) goto cleanup;
	fwrite(hash, SHA_DIGEST_LENGTH, 1, tree_file);
	if(ferror(tree_file)) goto cleanup;

	return 1;

cleanup:
	return 0;
}

int write_tree_size(FILE* tree_file, size_t num_leaves) {
	if (!tree_file || !num_leaves) goto cleanup;
	fwrite(&num_leaves, sizeof(size_t), 1, tree_file);
	if(ferror(tree_file)) goto cleanup;

	return 1;

cleanup:
	return 0;
}



int generate_tree(char *filepath, size_t filepath_len, char *tagfilepath, size_t tagfilepath_len) {
	PDP_key *key = NULL;
	FILE *file = NULL;
	FILE *tagfile = NULL;
	unsigned int index = 0;

	char realtagfilepath[MAXPATHLEN];
	unsigned char buf[TREE_BLOCKSIZE];
	char yesorno = 0;

	/* Mine */
	BIGNUM *m;
	unsigned char *h_result = NULL;
	size_t h_size = 0;
	int num_blocks = 0;
	size_t file_size = 0;
	unsigned char *node_list[20];
	int i = 0;

	memset(realtagfilepath, 0, MAXPATHLEN);

	if(!filepath) return 0;
	if(filepath_len >= MAXPATHLEN) return 0;
	if(tagfilepath_len >= MAXPATHLEN) return 0;

	file_size = get_file_size(filepath);
	if (file_size % TREE_BLOCKSIZE == 0)
		num_blocks = file_size / TREE_BLOCKSIZE;
	else
		num_blocks = file_size / TREE_BLOCKSIZE + 1;

	printf("File size: %d, Num_blocks: %d \n", get_file_size(filepath), num_blocks);

	/* If no tag file path is specified, add a .tag extension to the filepath */
	if(!tagfilepath && (filepath_len < MAXPATHLEN - 6)){
		if( snprintf(realtagfilepath, MAXPATHLEN, "%s.tree", filepath) >= MAXPATHLEN ) goto cleanup;
	}else{
		memcpy(realtagfilepath, tagfilepath, tagfilepath_len);
	}

	/* Check to see if the tag file exists */
	if( access(realtagfilepath, F_OK) == 0){
		yesorno = 'y';
		if(yesorno != 'y') goto exit;
	}

	tagfile = fopen(realtagfilepath, "w");
	if(!tagfile){
		fprintf(stderr, "ERROR: Was not able to create %s.\n", realtagfilepath);
		goto cleanup;
	}

	/* Get the PDP key */
	key = pdp_get_keypair();
	if(!key) goto cleanup;

	/* For each block of the file, tag it and write the tag to disk */
	file = fopen(filepath, "r");
	if(!file){
		fprintf(stderr, "ERROR: Was not able to open %s for reading.\n", filepath);
		goto cleanup;
	}
	// int counter = 0;
	write_tree_size(tagfile, num_blocks);
	m = BN_new();
	do{
		memset(buf, 0, TREE_BLOCKSIZE);
		fread(buf, TREE_BLOCKSIZE, 1, file);
		if(ferror(file)) goto cleanup;
		if(!BN_bin2bn(buf, TREE_BLOCKSIZE, m)) goto cleanup;
		h_result = generate_H(m, &h_size);
		write_merkel_tree(tagfile, h_result);
		printhex(h_result, SHA_DIGEST_LENGTH);
		node_list[index] = h_result;
		index++;
		// destroy_tree_node(tag);
	}while(!feof(file));

	
	while (index != 1) {
		// printf("===Index: %d===\n", index);
		if (index % 2 == 1) {
			index = index / 2;
			for (i = 0; i < index; i++) {
				h_result = merkel_create_node(node_list[2*i], node_list[2*i+1]);
				write_merkel_tree(tagfile, h_result);
				node_list[i] = h_result;
			}
			h_result = merkel_create_node(node_list[2*i], NULL);
			write_merkel_tree(tagfile, h_result);
			node_list[i] = h_result;
			index += 1;
		} else {
			index /= 2;
			for (i = 0; i < index; i++) {
				h_result = merkel_create_node(node_list[i*2], node_list[i*2+1]);
				write_merkel_tree(tagfile, h_result);
				node_list[i] = h_result;
			}
		}	
	}

exit:
	destroy_pdp_key(key);
	if(file) fclose(file);
	if(tagfile) fclose(tagfile);

	return 1;

cleanup:
	fprintf(stderr, "ERROR: Was unable to create tag file.\n");

	if(m) BN_clear_free(m);
	for (int i = 0; i < num_blocks; i++)
		if (node_list[i]) destroy_tree_node(node_list[i]);
	
	destroy_pdp_key(key);
	if(file) fclose(file);
	if(tagfile){
		ftruncate(fileno(tagfile), 0);
		unlink(realtagfilepath);
		fclose(tagfile);
	}
	return 0;
}
