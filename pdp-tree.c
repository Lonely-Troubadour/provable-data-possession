#include "pdp.h"
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/param.h>

/** Destroy tree node */
void destroy_tree_node(tree_node* node) {
	if (!node) return;
	if(node->hash) sfree(node->hash, SHA_DIGEST_LENGTH);
	sfree(node, sizeof(tree_node));
}

/** Destroy tree */
void destroy_tree(tree_node *root) {
	if (root->left) destroy_tree(root->left);
	if (root->right) destroy_tree(root->right);
	destroy_tree_node(root); 
}

/** Generate tree node */
tree_node *generate_tree_node() {
	tree_node* node = NULL;
	if ((node = malloc(sizeof(tree_node))) == NULL) return NULL;
	memset(node, 0, sizeof(tree_node));
	return node;
}

/** Create leaf */
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

	if (m) BN_clear_free(m);
	return node;

cleanup:
	if (node) destroy_tree_node(node);
	if (m) BN_clear_free(m);
    return NULL;
}

/** Create tree node */
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
int write_merkel_tree(FILE* tree_file, tree_node *root, unsigned short level) {
	fwrite(&level, sizeof(unsigned short), 1, tree_file);
	write_node(tree_file, root);
	if (root->left) 
		write_merkel_tree(tree_file, root->left, (level+1));

	if (root->right) 
		write_merkel_tree(tree_file, root->right, (level+1));

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
	
	return 1;

cleanup:
	return 0;
}

/* Read tree node from disk */
tree_node *read_node(FILE *tree_file) {
	unsigned char *hash;
	tree_node *node = NULL;

	if (!tree_file) return NULL;
	if ((node = generate_tree_node()) == NULL) goto cleanup;
	
	node->hash = (unsigned char*) malloc(SHA_DIGEST_LENGTH);
	fread(node->hash, SHA_DIGEST_LENGTH, 1, tree_file);

	return node;

cleanup:
	if (hash) sfree(hash, SHA224_DIGEST_LENGTH);
	if (node) destroy_tree_node(node);
	return NULL;
}

/** Read tree root */
tree_node * read_root(char *treefilepath) {
	tree_node *root = NULL;
	FILE *treefile = NULL;

	treefile = fopen(treefilepath, "r");
	if (!treefile) {
		fprintf(stderr, "Error: Cannot open tree file.\n");
		goto cleanup;
	}	

	if(!fseek(treefile, 0, SEEK_SET) < 0) goto cleanup;
	if(!fseek(treefile, sizeof(unsigned short), SEEK_CUR) < 0) goto cleanup;

	root = read_node(treefile);
	if(!root) goto cleanup;
	if(treefile) fclose(treefile);

	return root;

cleanup:
	if (treefile) fclose(treefile);
	if (root) destroy_tree_node(root);
	fclose(treefile);
	return NULL;
}

/* Generate root in proof: This step generates H( g_s^(root) ), the proof of 
 * merkel hash tree root. */
PDP_proof *pdp_generate_proof_root(PDP_key *key, PDP_challenge *challenge, PDP_proof *proof, tree_node *root) {
	BIGNUM *bn_root = NULL;
	BN_CTX *ctx = NULL;

	if(!proof) return NULL;
	if(!key || !challenge || !root) return NULL;
	if(!key->rsa->n || !challenge->g_s) return NULL;
	if( ((bn_root = BN_new()) == NULL)) goto cleanup;
	if( ((ctx = BN_CTX_new()) == NULL)) goto cleanup;

	if(!BN_bin2bn(root->hash, SHA_DIGEST_LENGTH, bn_root)) goto cleanup;
	
	/* Compute g_s^(root) */
	if(!BN_mod_exp(bn_root, challenge->g_s, bn_root, key->rsa->n, ctx)) goto cleanup;

	/* Compute H( g_s^(root) ) */
	proof->root = generate_H(bn_root, &(proof->root_size));
	if(!proof->root) goto cleanup;

	if(bn_root) BN_clear_free(bn_root);
	if(ctx) BN_CTX_free(ctx);
	
	return proof;

cleanup:
	if(bn_root) BN_clear_free(bn_root);
	if(ctx) BN_CTX_free(ctx);
	if(proof) destroy_pdp_proof(proof);
	if(root) destroy_tree_node(root);

	return NULL;
}

/* Check root in verification step. H( (g^root)^s mod N ) ?= root_proof */
int check_root(char *filepath, PDP_key *key, PDP_challenge *challenge, PDP_proof *proof) {
	tree_node *root = NULL;
	BIGNUM *bn_root = NULL;
	BN_CTX *ctx = NULL;
	unsigned char *H_result = NULL;
	size_t H_result_size = 0;

	/* Check */
	if(!proof || !proof->root) goto cleanup;
	if( (bn_root = BN_new()) == NULL ) goto cleanup;
	if( (ctx = BN_CTX_new()) == NULL ) goto cleanup;

	/* Read in root from disk */
	root = read_root(filepath);
	if(!root) goto cleanup;

	/* Calculate H( (g^root)^s mod N )*/ 
	BN_bin2bn(root->hash, SHA_DIGEST_LENGTH, bn_root);
	if(!bn_root) goto cleanup;
	BN_mod_exp(bn_root, key->g, bn_root, key->rsa->n, ctx);
	BN_mod_exp(bn_root, bn_root, challenge->s, key->rsa->n, ctx);
	H_result = generate_H(bn_root, &H_result_size);
	if(!H_result) goto cleanup;

	/* Compare */
	if(memcmp(proof->root, H_result, proof->root_size)) return 0;

	/* Cleanup and exit */
	if(bn_root) BN_clear_free(bn_root);
	if(ctx) BN_CTX_free(ctx); 
	if(H_result && H_result_size > 0) sfree(H_result, H_result_size);
	
	return 1;

cleanup:
	if(root) destroy_tree_node(root);
	if(bn_root) BN_clear_free(bn_root);
	if(H_result && H_result_size > 0) sfree(H_result, H_result_size);

	return 0;
}

/* Check if the node is leaf. Return 1 if node is leaf, otherwise 0. */
int is_leaf(tree_node *node) {
	if(!node->left && !node->right) return 1;
	return 0;
}

/* Find leaf with indice j */
tree_node *find_leaf(tree_node *root, int j) {
	int counter = 0;
	tree_node *node = root;

	if(!root) return NULL;

	node = dfs_tree(root, &counter, j);

	if(!node) return NULL;

	return node;
}

tree_node *dfs_tree(tree_node *node, int *counter, int j) {
	tree_node *result = NULL;
	if(!node) return NULL;

	if(is_leaf(node)) {
		if(*counter == j) return node;
		(*counter)++;
		return NULL;
	}

	if(node->left) {
		result = dfs_tree(node->left, counter, j);
		if(result) return result;
	}

	if(node->right) {
		result = dfs_tree(node->right, counter, j);
		if(result) return result;
	}
}

/* Generates auxilary path of given indice of file block */
PDP_proof *generate_aux_path() {
	PDP_proof *proof;
	return proof;
}

/** Constuct tree from reading tree file */
tree_node* construct_tree(char *filepath, size_t filepath_len, char *treefilepath, size_t treefilepath_len) {
	unsigned char *realtreefilepath[MAXPATHLEN];
	unsigned char *hash[SHA_DIGEST_LENGTH];
	unsigned short level = 0;
	unsigned short prev_level = 0;
	unsigned short temp = 0;
	size_t size = 0;
	FILE *file = NULL;
	FILE *fp = NULL;
	tree_node *cur = NULL;
	tree_node *par = NULL;
	tree_node *root = NULL;

	snprintf(realtreefilepath, MAXPATHLEN, "%s.tree", filepath);
	if ( access(realtreefilepath, F_OK) != 0 ) {
		fprintf(stderr, "File access failed.\n");
	}
	// printf("\n\n%s\n\n", realtreefilepath);
	file = fopen(realtreefilepath, "r");
	if (!file) {
		fprintf(stderr, "Cant open tree file.");
		goto cleanup;
	}

	if (fseek(file, 0, SEEK_SET) < 0) goto cleanup;
	size = fread(&level, sizeof(unsigned short), 1, file);
	if (!size) goto cleanup;
	root = read_node(file);
	if (!root) goto cleanup;

	cur = par = root;
	prev_level = level;
	
	while (!feof(file)) {
		size = fread(&level, sizeof(unsigned short), 1, file);
		if (!size) break;
		// printf("====Level: %d\n", level);
		cur = read_node(file);
		// printhex(cur->hash, SHA_DIGEST_LENGTH);

		if (prev_level < level) {
			if (par->left == NULL) {
				par->left = cur;
				cur->parent = par;
				par = cur;
			} 
		} else if (prev_level == level) {
			par = par->parent;
			if (par->right == NULL) {
				par->right = cur;
				cur->parent = par;
				par = cur;
			}
		} else {
			temp = prev_level - level + 1;
			for (int i = temp; temp > 0; temp--) 
				par = par->parent;
			if (par->right == NULL) {
				par->right = cur;
				cur->parent = par;
				par = cur;
			}
		}
		prev_level = level;
	}

	// fp = fopen("/home/v/Desktop/new.tree", "w");
	// write_merkel_tree(fp, root, 0);
	// fclose(fp);
	fclose(file);
	return root;

cleanup:
	if (file) fclose(file);
	if (root) destroy_tree(root);
	return NULL;
}

/** Deprecated. Write tree size */
int write_tree_size(FILE* tree_file, size_t num_leaves) {
	if (!tree_file || !num_leaves) goto cleanup;
	fwrite(&num_leaves, sizeof(size_t), 1, tree_file);
	if(ferror(tree_file)) goto cleanup;
	return 1;

cleanup:
	return 0;
}

/** Generate tree from file */
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
	tree_node **node_list = NULL;
	tree_node *tmp = NULL, *left = NULL, *right = NULL;
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
	node_list = (tree_node**) malloc(sizeof(tree_node*) * num_blocks);
	memset(node_list, 0, sizeof(tree_node*) * num_blocks);

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

		// printf("File hash:\n");
		// printhex(h_result, SHA_DIGEST_LENGTH);

		node_list[index] = create_leaf(h_result, NULL);
		index++;
	}while(!feof(file));

	printf("Start constructing tree...\n");
	while (index != 1) {
		// printf("===Index: %d===\n", index);
		// printf("\n tmp = %p \n", tmp);
		if (index % 2 == 1) {
			index /= 2;
			for (i = 0; i < index; i++) {
				left = node_list[2*i]; 
				right = node_list[2*i+1];
				
				node_list[i] = create_node(left, right);
			}
			
			node_list[i] = create_node(left, NULL);
			
			index += 1;
		} else {
			index /= 2;
			for (i = 0; i < index; i++) {
				tmp = node_list[i];
				left = node_list[2*i];
				right = node_list[2*i+1];

				node_list[i] = create_node(left, right);
			}
		}
		
	}
	printf("End...\n");
	write_merkel_tree(tagfile, node_list[0], 0);

exit:
	if(m) BN_clear_free(m);
	destroy_pdp_key(key);
	for (int i = 0; i < num_blocks; i++)
		if (node_list[i]) destroy_tree_node(node_list[i]);

	sfree(node_list, sizeof(tree_node*) * num_blocks);
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
