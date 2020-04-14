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
	if(proof->rho) sfree(proof->rho, rho_size);
	if(proof->T) sfree(proof->T, T_size);
	if(proof->rho_temp) sfree(proof->rho_temp, rho_temp_size);
	if(proof) destroy_pdp_proof(proof);
	return NULL;
}
