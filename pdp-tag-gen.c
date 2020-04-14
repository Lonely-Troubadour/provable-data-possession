#include "pdp.h"
#include <stdio.h>
#include <getopt.h>
#include <sys/param.h>
#include <sys/time.h>
#include <sys/stat.h>

static struct option longopts[] = {
	{"keygen", no_argument, NULL, 'k'}, //TODO optional argument for key location
	{"tag", no_argument, NULL, 't'},
	{"verify", no_argument, NULL, 'v'},
	{"prf_key_size", no_argument, NULL, 'p'},
	{"prp_key_size", no_argument, NULL, 'r'},
	{"rsa_key_size", no_argument, NULL, 'N'},
	{"rsa_e", no_argument, NULL, 'e'},
	{"blocksize", no_argument, NULL, 'b'},
	{"numchallenge", no_argument, NULL, 'c'},
	{NULL, 0, NULL, 0}
};

int main(int argc, char **argv){

	PDP_key *key = NULL;
	PDP_challenge *challenge = NULL, *server_challenge = NULL;
	PDP_proof *proof = NULL;
	int opt = -1;
	unsigned int numfileblocks = 0;
	struct stat st;
	

	OpenSSL_add_all_algorithms();

	while((opt = getopt_long(argc, argv, "kt:v:s:", longopts, NULL)) != -1){
		switch(opt){
			case 'k':
				key = pdp_create_new_keypair();
				if(key) destroy_pdp_key(key);
				break;
			case 't':
				if(strlen(optarg) >= MAXPATHLEN){
					fprintf(stderr, "ERROR: File name is too long.\n");
					break;
                }

				if(pdp_tag_file(optarg, strlen(optarg), NULL, 0))
				break;
			case 'v':
				if(strlen(optarg) >= MAXPATHLEN){
					fprintf(stderr, "ERROR: File name is too long.\n");
					break;
				}
				fprintf(stdout, "Verifying %s...\n", optarg);

				/* Calculate the number pdp blocks in the file */
				stat(optarg, &st);
				numfileblocks = (st.st_size/PDP_BLOCKSIZE);
				if(st.st_size%PDP_BLOCKSIZE)
					numfileblocks++;
				
				challenge = pdp_challenge_file(numfileblocks);
				if(!challenge) fprintf(stderr, "No challenge\n");
				key = pdp_get_pubkey();
				server_challenge = sanitize_pdp_challenge(challenge);
				proof = pdp_prove_file(optarg, strlen(optarg), NULL, 0, server_challenge, key);
				if(!proof) fprintf(stderr, "No proof\n");
				if(pdp_verify_file(challenge, proof))
					fprintf(stdout, "Verified!\n");
				else
					fprintf(stdout, "Cheating!\n");
				
				destroy_pdp_challenge(challenge);
				destroy_pdp_challenge(server_challenge);
				destroy_pdp_proof(proof);
				break;

			case 's':
#ifdef USE_S3
				memset(tagfilepath, 0, MAXPATHLEN);
				
				snprintf(tagfilepath, MAXPATHLEN, "%s.tag", optarg);
				
				if(strlen(optarg) >= MAXPATHLEN){
					fprintf(stderr, "ERROR: File name is too long.\n");
					break;
				}

				gettimeofday(&tv1, NULL);
				fprintf(stdout, "Tagging %s...", optarg);
				fflush(stdout);
				if(pdp_tag_file(optarg, strlen(optarg), NULL, 0)) printf("Done.\n");
				gettimeofday(&tv2, NULL);
				printf("%lf\n", (double)( (double)(double)(((double)tv2.tv_sec) + (double)((double)tv2.tv_usec/1000000)) - (double)((double)((double)tv1.tv_sec) + (double)((double)tv1.tv_usec/1000000)) ) );

				gettimeofday(&tv1, NULL);				
				fprintf(stdout, "\tWriting file %s to S3...", optarg);
				fflush(stdout);
				if(!pdp_s3_put_file(optarg, strlen(optarg))) printf("Couldn't write %s to S3.\n", optarg);
				else printf("Done.\n");
				gettimeofday(&tv2, NULL);
				printf("%lf\n", (double)( (double)(double)(((double)tv2.tv_sec) + (double)((double)tv2.tv_usec/1000000)) - (double)((double)((double)tv1.tv_sec) + (double)((double)tv1.tv_usec/1000000)) ) );

				gettimeofday(&tv1, NULL);				
				fprintf(stdout, "\tWriting tag %s to S3...", optarg);
				if(!pdp_s3_put_file(tagfilepath, strlen(tagfilepath))) printf("Couldn't write %s to S3.\n", optarg);
				else printf("Done.\n");				
				gettimeofday(&tv2, NULL);
				printf("%lf\n", (double)( (double)(double)(((double)tv2.tv_sec) + (double)((double)tv2.tv_usec/1000000)) - (double)((double)((double)tv1.tv_sec) + (double)((double)tv1.tv_usec/1000000)) ) );

				
				gettimeofday(&tv1, NULL);
				fprintf(stdout, "Challenging file %s...\n", optarg);
				fflush(stdout);				
				fprintf(stdout, "\tCreating challenge %s...", optarg);fflush(stdout);
				/* Calculate the number pdp blocks in the file */
				stat(optarg, &st);
				numfileblocks = (st.st_size/PDP_BLOCKSIZE);
				if(st.st_size%PDP_BLOCKSIZE)
					numfileblocks++;
				
				challenge = pdp_challenge_file(numfileblocks);
				if(!challenge) fprintf(stderr, "No challenge\n");
				key = pdp_get_pubkey();
				server_challenge = sanitize_pdp_challenge(challenge);
				printf("Done.\n");
				gettimeofday(&tv2, NULL);
				printf("%lf\n", (double)( (double)(double)(((double)tv2.tv_sec) + (double)((double)tv2.tv_usec/1000000)) - (double)((double)((double)tv1.tv_sec) + (double)((double)tv1.tv_usec/1000000)) ) );

				gettimeofday(&tv1, NULL);
				printf("\tGetting tag file...");fflush(stdout);
				fflush(stdout);
				if(!pdp_s3_get_file(tagfilepath, strlen(tagfilepath))) printf("Cloudn't get tag file.\n");
				else printf("Done.\n");
				gettimeofday(&tv2, NULL);
				printf("%lf\n", (double)( (double)(double)(((double)tv2.tv_sec) + (double)((double)tv2.tv_usec/1000000)) - (double)((double)((double)tv1.tv_sec) + (double)((double)tv1.tv_usec/1000000)) ) );

				gettimeofday(&tv1, NULL);				
				printf("\tComputing proof...");fflush(stdout);
				proof = pdp_s3_prove_file(optarg, strlen(optarg), tagfilepath, strlen(tagfilepath), server_challenge, key);
				if(!proof) fprintf(stderr, "No proof\n");
				else printf("Done\n");
				gettimeofday(&tv2, NULL);
				printf("%lf\n", (double)( (double)(double)(((double)tv2.tv_sec) + (double)((double)tv2.tv_usec/1000000)) - (double)((double)((double)tv1.tv_sec) + (double)((double)tv1.tv_usec/1000000)) ) );

				gettimeofday(&tv1, NULL);
				printf("\tVerifying proof...");fflush(stdout);				
				if(pdp_verify_file(challenge, proof))
					fprintf(stdout, "Verified!\n");
				else
					fprintf(stdout, "Cheating!\n");
			
				gettimeofday(&tv2, NULL);
				printf("%lf\n", (double)( (double)(double)(((double)tv2.tv_sec) + (double)((double)tv2.tv_usec/1000000)) - (double)((double)((double)tv1.tv_sec) + (double)((double)tv1.tv_usec/1000000)) ) );
				
				destroy_pdp_challenge(challenge);
				destroy_pdp_challenge(server_challenge);
				destroy_pdp_proof(proof);
#endif				
				break;

/*				
#ifdef DEBUG_MODE
				gettimeofday(&tv1, NULL);

				if(pdp_challenge_and_verify_file(optarg, strlen(optarg), NULL, 0))
					fprintf(stdout, "Verified!\n");
				else
					fprintf(stdout, "Cheating!\n");

				gettimeofday(&tv2, NULL);
#endif
*/
			default:
				usage();
				break;
		}
	}

#ifdef DEBUG_MODE
//	printf("%lf\n", (double)( (double)(double)(((double)tv2.tv_sec) + (double)((double)tv2.tv_usec/1000000)) - (double)((double)((double)tv1.tv_sec) + (double)((double)tv1.tv_usec/1000000)) ) );
#endif

	return 0;
}

