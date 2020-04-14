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
	key = pdp_create_new_keypair();
	if(key) destroy_pdp_key(key);				
	return 0;
}

