#include "pdp.h"
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/param.h>

/** Destroy, generate, create */
void destroy_tree_node(tree_node* node) {
	if (!node) return;
	if(node->hash) sfree(node->hash, SHA_DIGEST_LENGTH);
	sfree(node, sizeof(tree_node));
}

tree_node *generate_tree_node() {
	tree_node* node = NULL;
	if ((node = malloc(sizeof(tree_node))) == NULL) return NULL;
	memset(node, 0, sizeof(tree_node));
	return node;
}

tree_node *create_leaf(unsigned char *left, unsigned char *right) {
    tree_node *node = NULL;
	unsigned char msg[SHA_DIGEST_LENGTH * 2];
	BIGNUM *m;
	size_t h_size = 0;

	if (!left && !right) return NULL;
	memset(msg, 0, SHA_DIGEST_LENGTH*2);
	if ((node = generate_tree_node()) == NULL) goto cleanup;
	if ((m = BN_new()) == NULL) goto cleanup;	

	memcpy(msg, left, SHA_DIGEST_LENGTH); 
	if (right) {
		memcpy((msg+SHA_DIGEST_LENGTH), right, SHA_DIGEST_LENGTH);
		if(!BN_bin2bn(msg, SHA_DIGEST_LENGTH*2, m)) goto cleanup;
	} else {
		if(!BN_bin2bn(msg, SHA_DIGEST_LENGTH, m)) goto cleanup;
	}
		
	node->hash = generate_H(m, &h_size);
    node->left = NULL;
    node->right = NULL;

	printf("Msg:\n");
	printhex(msg, SHA_DIGEST_LENGTH*2);
	printf("Node hash:\n");
	printhex(node->hash, h_size);
	return node;

cleanup:
	if (node) destroy_tree_node(node);
	if (m) BN_clear_free(m);
    return NULL;
}

tree_node *create_node(tree_node* left_child, tree_node* right_child) {
	tree_node* node = NULL;
    unsigned char *left = NULL, *right = NULL;

    if (left_child != NULL) left = left_child->hash;
    if (right_child != NULL) right = right_child->hash;

    if ((node = create_leaf(left, right)) == NULL) goto cleanup;
    if (left) node->left = left_child;
    if (right) node->right = right_child;

	return node;

cleanup:
	if (node) destroy_tree_node(node);
    return NULL;
}



/** Write */
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
	tree_node *node_list[20];
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
	// write_tree_size(tagfile, num_blocks);
	m = BN_new();
	do{
		memset(buf, 0, TREE_BLOCKSIZE);
		fread(buf, TREE_BLOCKSIZE, 1, file);
		if(ferror(file)) goto cleanup;
		if(!BN_bin2bn(buf, TREE_BLOCKSIZE, m)) goto cleanup;
		h_result = generate_H(m, &h_size);
		// write_merkel_tree(tagfile, h_result);
		printhex(h_result, SHA_DIGEST_LENGTH);
		node_list[index] = create_leaf(h_result, NULL);
		index++;
		// destroy_tree_node(tag);
	}while(!feof(file));

	/*
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
    */

exit:
	destroy_pdp_key(key);
	if(file) fclose(file);
	if(tagfile) fclose(tagfile);

	return 1;

cleanup:
	fprintf(stderr, "ERROR: Was unable to create tree file.\n");

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
