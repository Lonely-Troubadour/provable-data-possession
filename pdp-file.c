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

/* write_pdp_tag: Write a PDP tag to disk.  Takes in an open file structure and a PDP tag structure
*  and serializes the tag.  The tagfile must be open for writing. Returns 1 on success and 0 failure.
*  NOTE: This function is not thread safe.  It should be called sequentially with a ordered list of tags.
*/
static int write_pdp_tag(FILE *tagfile, PDP_tag *tag){

	unsigned char *tim = NULL;
	unsigned char *hm = NULL;
	size_t tim_size = 0;
	size_t hm_size = 0;

	if(!tagfile || !tag || !tag->Tim) return 0;

#ifdef USE_M_PDP

	/* Write Tim to disk */
	tim_size = BN_num_bytes(tag->Tim);
	fwrite(&tim_size, sizeof(size_t), 1, tagfile);
	if(ferror(tagfile)) goto cleanup;
	if( ((tim = malloc(tim_size)) == NULL)) goto cleanup;
	memset(tim, 0, tim_size);
	if(!BN_bn2bin(tag->Tim, tim)) goto cleanup;
	fwrite(tim, tim_size, 1, tagfile);
	if(ferror(tagfile)) goto cleanup;

	/* write h(m) */
	hm_size = BN_num_bytes(tag->hm);
	fwrite(&hm_size, sizeof(size_t), 1, tagfile);
	if(ferror(tagfile)) goto cleanup;
	if( ((hm = malloc(hm_size)) == NULL)) goto cleanup;
	memset(hm, 0, hm_size);
	if(!BN_bn2bin(tag->hm, hm)) goto cleanup;
	fwrite(hm, hm_size, 1, tagfile);
	if(ferror(tagfile)) goto cleanup;

	if(tim) sfree(tim, tim_size);
	if(hm) sfree(hm, hm_size);
	return 1;

#else

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

#endif

cleanup:
	if(tim) sfree(tim, tim_size);
	if(hm) sfree(hm, hm_size);
	return 0;
}

/* read_pdp_tag: Reads a PDP tag from disk.  Takes an open file structure and the index of a PDP tag
*  and reads from disk, returning a PDP tag structure or NULL on failure.  The tagfile must be open for
*  reading.
*/
PDP_tag *read_pdp_tag(FILE *tagfile, unsigned int index){

	PDP_tag *tag = NULL;
	unsigned char *tim = NULL;
	unsigned char *hm = NULL;
	size_t tim_size = 0;
	size_t hm_size = 0;
	size_t index_prf_size = 0;
	int i = 0;

	if(!tagfile) return NULL;

	/* Allocate memory */
	if( ((tag = generate_pdp_tag()) == NULL)) goto cleanup;

	/* Seek to start of tag file */
	if(fseek(tagfile, 0, SEEK_SET) < 0) goto cleanup;

#ifdef USE_M_PDP

	/* Seek to tag offset index */
	for(i = 0; i < index; i++){
		fread(&tim_size, sizeof(size_t), 1, tagfile);
		if(ferror(tagfile)) goto cleanup;
		if(fseek(tagfile, (tim_size), SEEK_CUR) < 0) goto cleanup;
		fread(&(hm_size), sizeof(size_t), 1, tagfile);
		if(fseek(tagfile, (hm_size), SEEK_CUR) < 0) goto cleanup;
	}

	/*Read in Tim */
	fread(&tim_size, sizeof(size_t), 1, tagfile);
	if(ferror(tagfile)) goto cleanup;
	if( ((tim = malloc((unsigned int)tim_size)) == NULL)) goto cleanup;
	memset(tim, 0, (unsigned int)tim_size);
	fread(tim, (unsigned int)tim_size, 1, tagfile);
	if(ferror(tagfile)) goto cleanup;

	if(!BN_bin2bn(tim, tim_size, tag->Tim)) goto cleanup;

	/* write h(m) */
	fread(&hm_size, sizeof(size_t), 1, tagfile);
	if(ferror(tagfile)) goto cleanup;
	if( ((hm = malloc((unsigned int)hm_size)) == NULL)) goto cleanup;
	memset(hm, 0, (unsigned int)hm_size);
	fread(hm, (unsigned int)hm_size, 1, tagfile);
	if(ferror(tagfile)) goto cleanup;

	if(!BN_bin2bn(hm, hm_size, tag->hm)) goto cleanup;

	if(tim) sfree(tim, tim_size);
	if(hm) sfree(hm, hm_size);
#else

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

#endif

	return tag;

cleanup:

#ifdef USE_M_PDP

	if (hm) sfree(hm, hm_size);
	if (tim) sfree(tim, tim_size);
	
#else

	if(tag->index_prf) sfree(tag->index_prf, tag->index_prf_size);

#endif

	if(tag) destroy_pdp_tag(tag);
	if(tim) sfree(tim, tim_size);

	return NULL;
}

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
	
	unsigned char buf[PDP_BLOCKSIZE];
	PDP_tag *tag = NULL;

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
	file = fopen(filepath, "r");
	if(!file){
		fprintf(stderr, "ERROR: Was not able to open %s for reading.\n", filepath);
		goto cleanup;
	}
	do{
		memset(buf, 0, PDP_BLOCKSIZE);
		fread(buf, PDP_BLOCKSIZE, 1, file);
		if(ferror(file)) goto cleanup;
		tag = pdp_tag_block(key, buf, PDP_BLOCKSIZE, index);
		if(!tag) goto cleanup;
		if(!write_pdp_tag(tagfile, tag)) goto cleanup;
		index++;
		destroy_pdp_tag(tag);
		tag = NULL;
	}while(!feof(file));
	// printf("\nIndex: %d\n", index);

exit:
	destroy_pdp_key(key);
	if(file) fclose(file);
	if(tagfile) fclose(tagfile);

	return 1;

cleanup:
	fprintf(stderr, "ERROR: Was unable to create tag file.\n");

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
	tree_node *root = NULL;
	tree_node *node = NULL;
	unsigned int *indices = NULL;
	FILE *file = NULL;
	FILE *tagfile = NULL;
	FILE *treefile = NULL;
	char realtagfilepath[MAXPATHLEN];
	char realtreefilepath[MAXPATHLEN];
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

#ifdef USE_M_PDP

	/* If no tree file path is specified, add .tree extension to the filepath */
	if( snprintf(realtreefilepath, MAXPATHLEN, "%s.tree", filepath) >= MAXPATHLEN) goto cleanup;

	/* Open tag file and tree file */
	treefile = fopen(realtreefilepath, "r");
	if(!treefile) goto cleanup;

	/* Construct merkel hash tree */
	root = construct_tree(filepath, filepath_len, NULL, 0);
	if(!root) goto cleanup;

#endif

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
		// printf("%ld, %ld\n", BN_num_bytes(tag->Tim), BN_num_bytes(tag->hm));
		if(!tag) goto cleanup;

		proof = pdp_generate_proof_update(key, challenge, tag, proof, buf, PDP_BLOCKSIZE, j);
		if(!proof) goto cleanup;
		destroy_pdp_tag(tag);
		tag = NULL;
	}

	proof = pdp_generate_proof_final(key, challenge, proof);
	if(!proof) goto cleanup;

#ifdef USE_M_PDP

	// root = read_root(realtreefilepath);
	if(!root) goto cleanup;
	proof = pdp_generate_proof_root(key, challenge, proof, root);
	if(!proof) goto cleanup;

	node = find_leaf(root, 1);
	proof = generate_aux_path(node, proof);
	node = find_leaf(root, 2);
	proof = generate_aux_path(node, proof);

#endif

	if(indices) sfree(indices, (challenge->c * sizeof(unsigned int)));
	if(file) fclose(file);
	if(tagfile) fclose(tagfile);
	if(treefile) fclose(treefile);

	return proof;

cleanup:
	if(indices) sfree(indices, (challenge->c * sizeof(unsigned int)));
	if(proof) destroy_pdp_proof(proof);
	if(tag) destroy_pdp_tag(tag);
	if(root) destroy_tree_node(root);
	if(file) fclose(file);
	if(tagfile) fclose(tagfile);
	if(treefile) fclose(treefile);

	return NULL;
}

int pdp_verify_file(char *filepath, PDP_challenge *challenge, PDP_proof *proof){

	PDP_key *key = NULL;
	int result = 0;
	int tree_result = 0;
	char tagpath[MAXPATHLEN];
	char treepath[MAXPATHLEN];

	if(!challenge || !proof) return 0;

	snprintf(tagpath, MAXPATHLEN, "%s.tag", filepath);
	snprintf(treepath, MAXPATHLEN, "%s.tree", filepath);

	/* Get the PDP key */
	key = pdp_get_keypair();
	if(!key) return 0;
	result = pdp_verify_proof(tagpath, key, challenge, proof);
	tree_result = check_root(treepath, key, challenge, proof);	

	if(key) destroy_pdp_key(key);

	return (result && tree_result);
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

	result = pdp_verify_proof(filepath, key, challenge, proof);

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
