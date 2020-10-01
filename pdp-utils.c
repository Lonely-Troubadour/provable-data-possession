#include "pdp.h"
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/param.h>

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
