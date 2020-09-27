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

void destroy_tree(tree_node *root) {
	if (root->left) destroy_tree(root->left);
	if (root->right) destroy_tree(root->right);
	destroy_tree_node(root); 
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

/** Write tree to disk */
int write_merkel_tree(FILE* tree_file, tree_node *root) {
	write_node(tree_file, root);
	if (root->left) {
		fwrite("(", sizeof(char), 1, tree_file);
		write_merkel_tree(tree_file, root->left);
	}
	if (root->right) {
		write_merkel_tree(tree_file, root->right);
	}
	if (root->left) fwrite(")", sizeof(char), 1, tree_file);
	return 1;

cleanup:
	if (root) destroy_tree(root);
	return 0;
}

/* Write node content */
int write_node(FILE *tree_file, tree_node *node) {
	if (!tree_file || !node) return 0;
	fwrite(node->hash, SHA_DIGEST_LENGTH, 1, tree_file);
	if(ferror(tree_file)) goto cleanup;

cleanup:
	return 0;
}

/* Read tree from disk */
tree_node *read_node(FILE *tree_file) {
	unsigned char *hash;
	tree_node *node = NULL;
	tree_node *root = NULL;

	if (!tree_file) return NULL;
	if ((node = generate_tree_node()) == NULL) goto cleanup;
	
	root = node;
	node->hash = (unsigned char*) malloc(SHA_DIGEST_LENGTH);
	fread(node->hash, SHA_DIGEST_LENGTH, 1, tree_file);

	return node;

cleanup:
	if (hash) sfree(hash, SHA224_DIGEST_LENGTH);
	if (node) destroy_tree_node(node);
	return NULL;
}

int construct_tree(char *filepath, size_t filepath_len, char *treefilepath, size_t treefilepath_len) {
	unsigned char *realtreefilepath[MAXPATHLEN];
	unsigned char *buf[255];
	unsigned char *hash[SHA_DIGEST_LENGTH];
	FILE *file = NULL;
	tree_node *node = NULL;
	tree_node *root = NULL;

	snprintf(realtreefilepath, MAXPATHLEN, "%s.tree", filepath);
	if ( access(realtreefilepath, F_OK) != 0 ) {
		fprintf(stderr, "File access failed.\n");
	}
	file = fopen(realtreefilepath, "r");
	if (!file) {
		fprintf(stderr, "Cant open tree file.");
	}

	if (fseek(file, 0, SEEK_SET) < 0) goto cleanup;
	
	root = read_node(file);
	printf("\n");
	printhex(root->hash, SHA_DIGEST_LENGTH);
	
	fread(buf, sizeof(char), 1, file);
	fread(buf+sizeof(char), sizeof(char), 1, file);
	printf("---\n");
	printhex(buf, 21);
	// printhex(hash, SHA_DIGEST_LENGTH);
	printf("---\n");
	return 1;
cleanup:
	if (file) fclose(file);
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
	// int counter = 1;
	// write_tree_size(tagfile, num_blocks);
	if ((m = BN_new()) == NULL) goto cleanup;
	do{
		memset(buf, 0, TREE_BLOCKSIZE);
		fread(buf, TREE_BLOCKSIZE, 1, file);
		if(ferror(file)) goto cleanup;
		if(!BN_bin2bn(buf, TREE_BLOCKSIZE, m)) goto cleanup;
		h_result = generate_H(m, &h_size);

		printf("File hash:\n");
		printhex(h_result, SHA_DIGEST_LENGTH);

		node_list[index] = create_leaf(h_result, NULL);
		index++;
	}while(!feof(file));

	printf("Start constructing tree...\n");
	while (index != 1) {
		printf("===Index: %d===\n", index);
		if (index % 2 == 1) {
			index = index / 2;
			for (i = 0; i < index; i++) {
				node_list[i] = create_node(node_list[2*i], node_list[2*i+1]);
				// write_merkel_tree(tagfile, h_result);
			}
			node_list[i] = create_node(node_list[2*i], NULL);
			// write_merkel_tree(tagfile, h_result);
			index += 1;
		} else {
			index /= 2;
			for (i = 0; i < index; i++) {
				node_list[i] = create_node(node_list[i*2], node_list[i*2+1]);
				// write_merkel_tree(tagfile, h_result);
			}
		}	
	}
	printf("End...\n");
	write_merkel_tree(tagfile, node_list[0]);

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
