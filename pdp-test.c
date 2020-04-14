#include "pdp.h"
#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <sys/param.h>
#include <sys/time.h>
#include <sys/stat.h>

float timedifference_msec(struct timeval t0, struct timeval t1)
{
    return (t1.tv_sec - t0.tv_sec) * 1000.0f + (t1.tv_usec - t0.tv_usec) / 1000.0f;
}

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

void usage(){

	fprintf(stdout, "pdp (provable data possesion) 1.0\n");
	fprintf(stdout, "Copyright (c) 2008 Zachary N J Peterson <znpeters@nps.edu>\n");
	fprintf(stdout, "This program comes with ABSOLUTELY NO WARRANTY.\n");
	fprintf(stdout, "This is free software, and you are welcome to redistribute it\n");
	fprintf(stdout, "under certain conditions.\n\n");
	fprintf(stdout, "usage: pdp [options] [file]\n\n");
	fprintf(stdout, "Commands:\n\n");
	fprintf(stdout, "-t, --tag [file]\t\t tag a file\n");
	fprintf(stdout, "-v, --verify [file]\t\t verify data possession\n\n");
	fprintf(stdout, "-k, --keygen\t\t\t generate a new PDP key pair\n\n");

}

int main(int argc, char **argv){

	PDP_key *key = NULL;
	PDP_challenge *challenge = NULL, *server_challenge = NULL;
	PDP_proof *proof = NULL;
	int opt = -1;
	unsigned int numfileblocks = 0;
	struct stat st;
    struct timeval t0;
	struct timeval t1;
	float elapsed;

	FILE *prooffile = NULL;
	FILE *chalfile = NULL;

    gettimeofday(&t0, 0);

	if(argc < 2) usage();

	OpenSSL_add_all_algorithms();
	gettimeofday(&t1, 0);
	elapsed = timedifference_msec(t0, t1);
	printf("Initialize time: %f ms\n", elapsed);
	while((opt = getopt_long(argc, argv, "kt:c:v:s:", longopts, NULL)) != -1){
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
                gettimeofday(&t0, 0);
				if(pdp_tag_file(optarg, strlen(optarg), NULL, 0)){
                    gettimeofday(&t1, 0);
                    elapsed = timedifference_msec(t0, t1);
                    printf("Tag time: %f ms\n" ,elapsed);
                    break;
                }
			case 'c':
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

                gettimeofday(&t0, 0);
				challenge = pdp_challenge_file(numfileblocks);
				gettimeofday(&t1, 0);
                elapsed = timedifference_msec(t0, t1);
                printf("GenChal time: %f ms\n", elapsed);

				if(!challenge) fprintf(stderr, "No challenge\n");
				key = pdp_get_pubkey();
				server_challenge = sanitize_pdp_challenge(challenge);

				/* Get proof */
				gettimeofday(&t0, 0);
				proof = pdp_prove_file(optarg, strlen(optarg), NULL, 0, server_challenge, key);
                gettimeofday(&t1, 0);
                elapsed = timedifference_msec(t0, t1);
                printf("GenProof: %f ms\n", elapsed);

				/* Write proof file to disk and read in */
				prooffile = fopen("/home/vincent/Desktop/blockchain/voting/proof", "w");
				if(!write_pdp_proof(prooffile, proof)) fprintf(stderr, "Write proof failed!");
				fclose(prooffile);
				destroy_pdp_proof(proof);

				/* Write challenge to disk */
				chalfile = fopen("/home/vincent/Desktop/blockchain/voting/challenge", "w");
				if(!write_pdp_challenge(chalfile, challenge)) fprintf(stderr, "Write challenge fialed!");
				fclose(chalfile);
				destroy_pdp_challenge(challenge);
				break;

			case 'v':
				/* Read in challenge */
				chalfile = fopen("/home/vincent/Desktop/blockchain/voting/challenge", "r");
				challenge = read_pdp_challenge(chalfile);
				fclose(chalfile);
				
				// PDP_challenge *newChal = NULL;
				// PDP_challenge *newServerChal = NULL;
				// PDP_proof *newProof = NULL;
				
				// chalfile = fopen("/home/vincent/Desktop/blockchain/voting/challenge", "r");
				// newChal = read_pdp_challenge(chalfile);
				// fclose(chalfile);

				// FILE *newChalFile = NULL;
				// newChalFile = fopen("/home/vincent/Desktop/blockchain/voting/newChal", "w");
				// if(!write_pdp_challenge(newChalFile, newChal)) fprintf(stderr, "Write challenge fialed!");
				// fclose(newChalFile);
				
				// printhex(challenge->k1, PRP_KEY_SIZE);
				// printhex(newChal->k1, PRP_KEY_SIZE);
				// newServerChal = sanitize_pdp_challenge(newChal);
				// FILE *serverChalFile = NULL;
				// FILE *newServerChalFile = NULL;

				// serverChalFile = fopen("/home/vincent/Desktop/blockchain/voting/serChal", "w");
				// if(!write_pdp_server_challenge(serverChalFile, server_challenge)) printf("Error");
				// fclose(serverChalFile);
				
				// newServerChalFile = fopen("/home/vincent/Desktop/blockchain/voting/newSerChal", "w");
				// if(!write_pdp_server_challenge(newServerChalFile, newServerChal)) printf("Error");
				// fclose(newServerChalFile);

				// newProof = pdp_prove_file(optarg, strlen(optarg), NULL, 0, newServerChal, key);
				// FILE *newProofFile = NULL;
				// newProofFile = fopen("/home/vincent/Desktop/blockchain/voting/newProof", "w");
				// if(!write_pdp_proof(newProofFile, newProof)) printf("Error");
				// fclose(newProofFile);
				

				/* Read in proof */
				prooffile = fopen("/home/vincent/Desktop/blockchain/voting/proof", "r");
				proof = read_pdp_proof(prooffile);
				fclose(prooffile);

			   	if(!proof) fprintf(stderr, "No proof\n");
                gettimeofday(&t0, 0);
				if(pdp_verify_file(challenge, proof))
					fprintf(stdout, "Verified!\n");
				else
					fprintf(stdout, "Cheating!\n");
				gettimeofday(&t1, 0);
                elapsed = timedifference_msec(t0, t1);
                printf("CheckProof: %f ms\n", elapsed);
				destroy_pdp_challenge(challenge);
				destroy_pdp_challenge(server_challenge);
				destroy_pdp_proof(proof);
				break;

			default:
				usage();
				break;
		}
	}

	return 0;
}

