#define FUSE_USE_VERSION 30

#include <fuse3/fuse.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <sys/time.h>
#include <math.h>

// Provide some simple file path extractions such as basename, filename, etc
#include <libgen.h>

#include <linux/limits.h>
#include <assert.h>

#include "block.h"
#include "myfs.h"

char diskfile_path[PATH_MAX];

struct superblock* superblock = NULL;

static inline void dump_str(const char*s, size_t len) {
	for (size_t i = 0; i < len; ++i) printf("%02x", (unsigned char)s[i]);

	printf("\n");
}

/**
 * Get the first available inode number from inode bitmap
 */
int get_avail_ino() {
	assert(superblock != NULL);

	bitmap_t bitmap_block = (bitmap_t)malloc(BLOCK_SIZE);
	
	if (block_read(superblock->i_bitmap_blk, bitmap_block) == -1) {
		perror("Unable to read inode bitmap");
		
		free(bitmap_block);

		return -1;
	}

	for (int i = 0; i < superblock->max_inum; ++i) {
		if (get_bitmap(bitmap_block, i) == 0) {
			set_bitmap(bitmap_block, i);
			
			if (block_write(superblock->i_bitmap_blk, bitmap_block) == -1) {
				perror("Failed to write inode bitmap");
				
				free(bitmap_block);

				return -1;
			}
			
			free(bitmap_block);
			
			return i;
		}
	}

	free(bitmap_block);

	return -1;
}

/**
 * Get the first available data block number from data block bitmap
 */
int get_avail_blkno() {
	assert(superblock != NULL);

	bitmap_t bitmap_block = (bitmap_t)malloc(BLOCK_SIZE);
	
	if (block_read(superblock->d_bitmap_blk, bitmap_block) == -1) {
		perror("Unable to read data bitmap block");
		
		free(bitmap_block);

		return -1;
	}

	for (int i = 0; i < superblock->max_dnum; ++i) {
		printf("\tChecking data block [%d]\n", i);

		if (get_bitmap(bitmap_block, i) == 0) {
			set_bitmap(bitmap_block, i);
			
			if (block_write(superblock->d_bitmap_blk, bitmap_block) == -1) {
				perror("Unable to write data bitmap block");

				free(bitmap_block);

				return -1;
			}

			free(bitmap_block);

			return i + superblock->d_start_blk;
		}
	}

	free(bitmap_block);
	
	return -1;
}

/**
 * Read inode info given inode number
 */
int read_inode(uint16_t ino, struct inode* inode) {
	assert(superblock != NULL);

	uint32_t block_index = ino / BLOCK_SIZE;
	uint32_t inode_index = ino % BLOCK_SIZE;
	uint32_t offset = superblock->i_start_blk;

	struct inode* inode_table = (struct inode*)malloc(BLOCK_SIZE);
	
	if (inode_table == NULL) {
		perror("Unable to allocate memory");

		return -1;
	}

	if (block_read(block_index + offset, (void*)inode_table) == -1) {
		perror("Unable to read block");

		free(inode_table);

		return -1;
	}

	memcpy(inode, inode_table + inode_index, sizeof(struct inode));
	
	free(inode_table);

	return 0;
}

/**
 * Write into inode given inode number
 */
int write_inode(uint16_t ino, struct inode* inode) {
	assert(superblock != NULL);

	uint32_t block_index = ino / BLOCK_SIZE;
	uint32_t inode_index = ino % BLOCK_SIZE;
	uint32_t offset = superblock->i_start_blk;
	
	struct inode* inode_table = (struct inode*)malloc(BLOCK_SIZE);

	if (block_read(block_index + offset, inode_table) == -1) {
		perror("Failed to read block");
	
		free(inode_table);

		return -1;
	}

	inode_table[inode_index].ino = inode->ino;
	inode_table[inode_index].valid = inode->valid;
	inode_table[inode_index].size = inode->size;
	inode_table[inode_index].type = inode->type;
	inode_table[inode_index].nlink = inode->nlink;
	inode_table[inode_index].uid = inode->uid;
	inode_table[inode_index].gid = inode->gid;
	inode_table[inode_index].atime = inode->atime;
	inode_table[inode_index].mtime = inode->mtime;
	inode_table[inode_index].ctime = inode->ctime;
	memcpy(inode_table[inode_index].directs, inode->directs, DIRECT_PTRS_COUNT * sizeof(int));
	inode_table[inode_index].indirect_ptr = inode->indirect_ptr;

	if (block_write(block_index + offset, inode_table) == -1) {
		perror("Failed to write block");

		free(inode_table);

		return -1;
	}

	free(inode_table);

	return 0;
}

/**
 * Find directory given name, return dirent struct
 */
int dir_find(uint16_t ino, const char* fname, size_t name_len, struct dirent* dirent) {
	struct inode dir_inode = { 0 };
	
	if (read_inode(ino, &dir_inode) == -1) {
		perror("dir_find");

		return -1;
	}

	int num_blocks = dir_inode.size / BLOCK_SIZE;

	if (num_blocks == 0) num_blocks = 1;

	int num_entry = dir_inode.size / sizeof(struct dirent);
	
	struct dirent* buffer = (struct dirent*)malloc(BLOCK_SIZE);

	for (int i = 0; i < num_blocks && i < DIRECT_PTRS_COUNT; ++i) {
		if (dir_inode.directs[i] == -1) continue;

		if (block_read(dir_inode.directs[i], buffer) == -1) {
			perror("Unable to read data block");
			
			free(buffer);

			return -1;
		}

		for (int j = 0; j < num_entry; ++j) {
			if (buffer[j].valid == 1 && strncmp(buffer[j].name, fname, name_len) == 0) {
				memcpy(dirent, &buffer[j], sizeof(struct dirent));

				free(buffer);

				return 0;
			}
		}
	}

	free(buffer);

	return -1;
}

/**
 * Add directory given name
 */
int dir_add(struct inode* dir_inode, uint16_t f_ino, const char* fname, size_t name_len) {
	assert(name_len <= NAME_MAX);
	
	struct dirent existing_entry = { 0 };
	
	if (dir_find(dir_inode->ino, fname, name_len, &existing_entry) == 0) {
		return -EEXIST;
	}

	// Find out which data block has space to add entry
	// adding sizeof(struct dirent) is to make sure it round it down to the next available block, for example if block 1 and 2 is full, without adding sizeof(), it will return the index of 2, instead of 3 (which is the next one empty)
	int block_index = (int)floor((float)(dir_inode->size + sizeof(struct dirent)) / BLOCK_SIZE);
	
	int num_dirents = dir_inode->size / sizeof(struct dirent);

	int next_avail_index = num_dirents % BLOCK_SIZE;
		
	struct dirent entry;

	entry.ino = f_ino;
	entry.valid = 1;
	
	if (name_len >= NAME_MAX) name_len = NAME_MAX - 1; 

	strncpy(entry.name, fname, name_len);

	entry.name[name_len] = '\0';

	entry.len = name_len;
	
	struct dirent* entry_table = (struct dirent*)malloc(BLOCK_SIZE);
	
	if (dir_inode->directs[block_index] == -1) {
		int next_avail_block = get_avail_blkno();

		if (next_avail_block == -1) {
			return -ENOSPC;
		}	

		dir_inode->directs[block_index] = next_avail_block;
	}

	if (block_read(dir_inode->directs[block_index], entry_table) == -1) {
		perror("Unable to obtain entry table");

		free(entry_table);

		return -1;
	}

	entry_table[next_avail_index].ino = entry.ino;
	entry_table[next_avail_index].len = entry.len;
	strncpy(entry_table[next_avail_index].name, entry.name, entry.len);
	entry_table[next_avail_index].valid = entry.valid;

	if (block_write(dir_inode->directs[block_index], (void*)entry_table) == -1) {
		perror("Unable to write entry table");
		
		free(entry_table);

		return -1;	
	}

	// Update dir inode
	dir_inode->size += sizeof(struct dirent);

	if (write_inode(dir_inode->ino, dir_inode) == -1) {
		perror("Cannot write inode of dir node");
		
		free(entry_table);

		return -1;
	}

	free(entry_table);
	
	return 0;
}

/**
 * Get inode number from the give path, save info into returned inode
 */
int get_node_by_path(const char* path, uint16_t ino, struct inode* inode) {
	if (strcmp(path, "/") == 0) {
		read_inode(ROOT_INODE, inode);

		return 0;
	}
	
	struct inode current = { 0 };

	// Start walking from the root node
	if (read_inode(ino, &current) == -1) {
		perror("Cannot read inode");
		return -1;
	}
	
	if (current.valid == 0) {
		return -ENOENT; // root inode is not valid
	}

	char* path_clone = strdup(path);
	char* token = strtok(path_clone, "/");
	
	struct dirent dir_entry = { 0 };
	
	while (token) {
		// Find the token in the current directory's inode
		if (dir_find(current.ino, token, strlen(token), &dir_entry) == -1) {
			// Token not found
			//
			free(path_clone);

			return -1;
		}

		// Read inode of the token, then move current to token's inode
		// a.k.a walking toward to target
		if (read_inode(dir_entry.ino, &current) == -1) {
			// Unable to read inode struct
			//
			free(path_clone);

			return -1;
		}

		// Move to the next token
		token = strtok(NULL, "/");
	}

	// Copy current inode to output inode
	memcpy(inode, &current, sizeof(struct inode));

	free(path_clone);
		
	return 0;
}

static inline struct timespec now(void) {
	struct timespec ts;

	ts.tv_sec = time(NULL);
	ts.tv_nsec = 0;

	return ts;	
}

/**
 * Make file system
 * - This is where to call dev_init to first init the storage file
 * - Init superblock in the storage file
 * - And write root directory into the first inode and data block
 */
int myfs_mkfs() {
	assert(diskfile_path != NULL);

	dev_init(diskfile_path);

	// STORATE FILE FORMAT:
	// | superblock | inode bitmap | data bitmap | inode | data |
	
	superblock = (struct superblock*)malloc(sizeof(struct superblock));
	
	if (superblock == NULL) {
		perror("Failed to allocate memory for superblock");
		return -1;
	}
	
	// Try to read the superblock of the opened file
	if (block_read(SUPERBLOCK_BLK_NUM, (void*)superblock) == 0) {
		if (superblock->magic_num == MAGIC_NUM) {
			// Storage file has been initialized before
			printf("Storage file has already existed\n");

			return 0;
		}
	}

	superblock->magic_num = MAGIC_NUM;
	superblock->max_inum = MAX_INODE_NUM;
	superblock->max_dnum = MAX_DATA_NUM;
	superblock->i_bitmap_blk = 1; // after superblock's block
	
	uint16_t total_required_blocks = INODE_BITMAP_BYTES / BLOCK_SIZE;

	if (total_required_blocks == 0) total_required_blocks = 1;

	// Initialize inode bitmap
	bitmap_t inode_bitmap = (bitmap_t)malloc(INODE_BITMAP_BYTES);
	
	if (inode_bitmap == NULL) {
		perror("Failed to allocate memory for inode bitmap");
		return -1;
	}

	// Set all bits in the bitmap to zero
	memset(inode_bitmap, 0, INODE_BITMAP_BYTES);

	// Mark inode 0 as root directory
	set_bitmap(inode_bitmap, ROOT_INODE);

	// Write the bitmap back to its block
	for (int i = 0, block = superblock->i_bitmap_blk, offset = 0; i < total_required_blocks; ++i, ++block, offset += BLOCK_SIZE) {
		if (block_write(block, inode_bitmap + offset) == -1) {
			perror("Failed to write bitmap");
			
			free(inode_bitmap);

			return -1;
		}
	}

	superblock->d_bitmap_blk = superblock->i_bitmap_blk + total_required_blocks;

	// Initialize data bitmap
	bitmap_t data_bitmap = (bitmap_t)malloc(DATA_BITMAP_BYTES);

	if (data_bitmap == NULL) {
		perror("Failed to allocate memory for data bitmap");
		return -1;
	}

	// Set all bits to zero
	memset(data_bitmap, 0, DATA_BITMAP_BYTES);
	
	total_required_blocks = DATA_BITMAP_BYTES / BLOCK_SIZE;

	if (total_required_blocks == 0) total_required_blocks = 1;

	// Write the bitmap back to its block
	for (int i = 0, block = superblock->d_bitmap_blk, offset = 0; i < total_required_blocks; ++i, ++block, offset += BLOCK_SIZE) {
		if (block_write(block, data_bitmap + offset) == -1) {
			perror("Failed to write data bitmap");

			free(data_bitmap);

			return -1;
		}
	}

	superblock->i_start_blk = superblock->d_bitmap_blk + total_required_blocks;

	// Initialize inode region
	total_required_blocks = superblock->max_inum * sizeof(struct inode) / BLOCK_SIZE;

	if (total_required_blocks == 0) total_required_blocks = 1;

	superblock->d_start_blk = superblock->i_start_blk + total_required_blocks;

	// Write superblock
	if (block_write(SUPERBLOCK_BLK_NUM, (void*)superblock) == -1) {
		free(inode_bitmap);
		free(data_bitmap);
	
		return -1;
	}

	// Update inode for root directory
	struct inode root_inode;
	
	root_inode.ino = ROOT_INODE;
	root_inode.valid = 1;
	root_inode.size = 0;
	root_inode.type = S_IFDIR | 0755; // directory with rwxr-xr-x permission
	root_inode.nlink = 0;
	
	root_inode.atime = now();
	root_inode.mtime = now();
	root_inode.ctime = now();
	
	root_inode.uid = getuid(); // current user id
	root_inode.gid = getgid(); // current group id

	memset(root_inode.directs, 0, DIRECT_PTRS_COUNT * sizeof(int));
	root_inode.indirect_ptr = 0;

	if (write_inode(ROOT_INODE, &root_inode) == -1) {
		free(inode_bitmap);
		free(data_bitmap);

		return -1;
	}

	// if (dir_add(&root_inode, ROOT_INODE, ".", 1) == -1) {
	// 	perror("Cannot add entry to root directory");

	// 	free(inode_bitmap);
	// 	free(data_bitmap);

	// 	return -1;
	// }

	// if (dir_add(&root_inode, ROOT_INODE, "..", 2) == -1) {
	// 	perror("Cannot add entry to root directory");

	// 	free(inode_bitmap);
	// 	free(data_bitmap);

	// 	return -1;
	// }

	free(inode_bitmap);
	free(data_bitmap);

	return 0;
}

/**
 * Init MYFS
 */
static void* myfs_init(struct fuse_conn_info *conn, struct fuse_config* fconfig) {
	printf("MYFS initilizing...\n");
	
	if (superblock != NULL) {
		printf("MYFS has been initialized before. You should restart MYFS to init again\n");

		return NULL;
	}	

	if (myfs_mkfs() == -1) {
		perror("Failed to init MYFS");

		exit(EXIT_FAILURE);
	}

	return NULL;
}

/**
 * Destroy MYFS
 */
static void  myfs_destroy(void *userdata) {
	free(superblock);

	dev_close();
}

static int myfs_getattr(const char* path, struct stat *st_buf, struct fuse_file_info *fi) {
	struct inode finode = { 0 };
	
	int res = get_node_by_path(path, ROOT_INODE, &finode); // start finding from the root
	
	if (res < 0) {
		return -ENOENT;
	}

	if (finode.valid == 0) {
		return -ENOENT;
	}

	st_buf->st_ino = finode.ino;
	st_buf->st_size = finode.size;
	st_buf->st_nlink = finode.nlink;
   	st_buf->st_mode = finode.type;
	st_buf->st_uid = finode.uid;
	st_buf->st_gid = finode.gid;
	st_buf->st_atim = finode.atime;
	st_buf->st_mtim = finode.mtime;
	st_buf->st_ctim = finode.ctime;

	return 0;
}

static int myfs_opendir(const char* path, struct fuse_file_info *fi) {
	struct inode dir_inode = { 0 };

	if (get_node_by_path(path, ROOT_INODE, &dir_inode) == -1) {
		perror("Failed to open dir");
		return -ENOENT;
	}

	if (dir_inode.valid == 0) {
		perror("dir inode is not valid");
		return -ENOENT;
	}

	// Save inode number of this dir into *fh struct of fuse_file_info
	fi->fh = (uint64_t)dir_inode.ino + 1;
	
	return 0;
}

static int myfs_readdir(const char* path, void* buffer, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info *fi, enum fuse_readdir_flags flags) {
	// Check if inode is cached with opendir
	if (fi->fh == (uint64_t)0) {
		perror("opendir is not called prior to this function call");
		return -1;
	}

	struct inode dir_inode = { 0 };

	if (read_inode(fi->fh - 1, &dir_inode) == -1) {
		perror("Cannot read inode");

		return -1;
	}

	if (dir_inode.valid == 0) {
		perror("Dir is not valid");
		return -1;
	}
	
	int total_dirent = dir_inode.size / sizeof(struct dirent);

	// Figure out how many struct dirent can be put into a block
	int num_dirent_per_block = BLOCK_SIZE / sizeof(struct dirent);
	
	// Number of blocks
	int num_blocks = total_dirent / num_dirent_per_block;
	
	// In case there are only a few dirents in a block
	// we only need to read one block from direct pointer
	if (num_blocks == 0) num_blocks = 1;
	
	struct dirent* block_buffer = (struct dirent*)malloc(BLOCK_SIZE);
	
	if (block_buffer == NULL) {
		perror("Failed to allocate memory");

		return -1;
	}

	struct dirent entry = { 0 };

	int total_dirent_read = 0;
	
	int b = 0;
	
	// Read from direct first
	for(; b < num_blocks && b < DIRECT_PTRS_COUNT; ++b) {
		if (total_dirent_read == total_dirent) break;
		
		if (dir_inode.directs[b] == -1) continue;
		
		if (block_read(dir_inode.directs[b], block_buffer) == -1) {
			perror("Unable to read block");

			return -1;
		}

		for (int i = 0; i < num_dirent_per_block && i < total_dirent; ++i) {
			if (total_dirent_read == total_dirent) break;
			
			entry = block_buffer[i];

			printf("\tItem[%d]: %s\n", i, entry.name);

			dump_str(entry.name, entry.len + 1);
						
			if (entry.valid == 1) {
				if (filler(buffer, entry.name, NULL, 0, 0) != 0) {
					perror("filler");
					
					free(block_buffer);

					return -ENOMEM;
				}
			}

			total_dirent_read++;	
		}
	}

	// TODO: read from indirect ptr

	free(block_buffer);

	return 0;	
}

static int myfs_mkdir(const char* path, mode_t mode) {
	char *tmp1 = strdup(path);
	char *tmp2 = strdup(path);

	if (tmp1 == NULL || tmp2 == NULL) {
		perror("Failed to allocate memory for path");

		if (tmp1) free(tmp1);
		if (tmp2) free(tmp2);

		return -1;
	}

	char *dir = strdup(dirname(tmp1));
	char *base = strdup(basename(tmp2));

	free(tmp1);
	free(tmp2);

	if (dir == NULL || base == NULL) {
		perror("Unable to extract base or dir name due to space");

		if (dir) free(dir);
		if (base) free(base);

		return -1;
	}

	struct inode parent_inode = { 0 };

	if (get_node_by_path(dir, ROOT_INODE, &parent_inode) == -1) {
		perror("Unable to get node by path");

		return -1;
	}

	if (parent_inode.valid == 0) {
		perror("Parent inode is not valid");
		
		free(base);
		free(dir);

		return -1;
	}
	
	// Check if the target directory already exists
	struct dirent entry = { 0 };

	if (dir_find(parent_inode.ino, base, strlen(base), &entry) == 0) {
		// Directory already exist
		perror("Directory already exists");

		free(base);
		free(dir);

		return -EEXIST;
	}

	// Get next available inode number for this new directory
	int ino = get_avail_ino();

	if (ino == -1) {
		free(base);
		free(dir);

		return -ENOSPC;
	}

	struct inode new_dir_inode;

	new_dir_inode.ino = ino;
	new_dir_inode.valid = 1;
	new_dir_inode.size = 0;
	new_dir_inode.type = S_IFDIR | mode;
	new_dir_inode.nlink = 2; // . and ..
	
	memset(new_dir_inode.directs, -1, DIRECT_PTRS_COUNT * sizeof(int));
	new_dir_inode.indirect_ptr = -1;
	
	new_dir_inode.uid = getuid();
	new_dir_inode.gid = getgid();

	new_dir_inode.atime = now();
	new_dir_inode.mtime = now();
	new_dir_inode.ctime = now();

	write_inode(ino, &new_dir_inode);
	
	dir_add(&new_dir_inode, ino, ".", 1);
	
	dir_add(&new_dir_inode, parent_inode.ino, "..", 2);
	
	dir_add(&parent_inode, ino, base, strlen(base));
	
	free(dir);
	free(base);

	return 0;
}

static int myfs_create(const char* path, mode_t mode, struct fuse_file_info* fi) {
	char *tmp1, *tmp2;

	tmp1 = strdup(path);
	tmp2 = strdup(path);

	if (tmp1 == NULL || tmp2 == NULL) {
		perror("Failed to allocate memory");

		if (tmp1) free(tmp1);
		if (tmp2) free(tmp2);
	}	

	char* base = basename(strdup(tmp1));
	char* dir = dirname(strdup(tmp2));
	
	free(tmp1);
	free(tmp2);

	if (base == NULL || dir == NULL) {
		perror("Failed to allocate memory");

		if (base) free(base);
		if (dir) free(dir);
	}
	
	// Get parent inode and check if the target file is already exist
	struct inode parent_inode = { 0 };

	if (get_node_by_path(dir, ROOT_INODE, &parent_inode) == -1) {
		perror("Failed to get inode from path");
		
		free(base);
		free(dir);
		
		return -1;
	}

	if (parent_inode.valid == 0) {
		perror("Parent inode is not valid");
			
		free(base);
		free(dir);

		return -1;
	}

	// Check if the target file already exists
	struct dirent entry = { 0 };

	if (dir_find(parent_inode.ino, base, strlen(base), &entry) == 0) {
		perror("File already exists");
	
		free(base);
		free(dir);

		return -EEXIST;
	}

	// Get the next available inode number for this file
	int ino = get_avail_ino();

	if (ino == -1) {
		free(base);
		free(dir);

		return -ENOSPC;
	}

	struct inode new_file_inode;

	new_file_inode.ino = ino;
	new_file_inode.valid = 1;
	new_file_inode.size = 0;
	new_file_inode.type = __S_IFREG | mode;
	new_file_inode.nlink = 1;

	memset(new_file_inode.directs, -1, DIRECT_PTRS_COUNT * sizeof(int));
	new_file_inode.indirect_ptr = -1;

	new_file_inode.uid = getuid();
	new_file_inode.gid = getgid();

	new_file_inode.atime = now();
	new_file_inode.mtime = now();
	new_file_inode.ctime = now();

	write_inode(ino, &new_file_inode);

	dir_add(&parent_inode, ino, base, strlen(base));
	
	// Save inode into cache for later use
	fi->fh = (uint64_t)ino + 1;
	
	return 0;
}

static int myfs_open(const char* path, struct fuse_file_info *fi) {
	struct inode finode = { 0 };

	if (get_node_by_path(path, ROOT_INODE, &finode) == -1) {
		perror("get_path_by_node");

		return -1;
	}

	if (finode.valid == 0) {
		perror("File is not valid");

		return -1;
	}

	fi->fh = (uint64_t)finode.ino + 1;

	return 0;
}

static int myfs_read(const char* path, char* buffer, size_t size, off_t offset, struct fuse_file_info* fi) {
	struct inode finode = { 0 };

	if (fi->fh == (uint64_t)0) {
		perror("Call open() before this operation");

		return -1;
	}

	read_inode(fi->fh - 1, &finode);

	if (finode.valid == 0) {
		perror("File is not valid");

		return -ENOENT;
	}

	if (offset >= finode.size) {
		// offset is beyond file size
		return 0;
	}	

	if (size + offset > finode.size) {
		// cap size
		size = finode.size - offset;
	}

	size_t bytes_read = 0;
	off_t current_offset = offset;
	size_t remaining = size;
	
	void* block = malloc(BLOCK_SIZE);

	while (remaining > 0) {
		size_t block_index = current_offset / BLOCK_SIZE;
		size_t block_offset = current_offset % BLOCK_SIZE;
		size_t to_read = BLOCK_SIZE - block_offset;

		if (to_read > remaining) to_read = remaining;

		// Assume we only use direct ptr firstly
		assert(block_index < DIRECT_PTRS_COUNT);

		int data_block_num = finode.directs[block_index];

		if (data_block_num == -1) {
			// not allocated
			memset(buffer + bytes_read, 0, to_read);
		} else {
			block_read(data_block_num, block);

			memcpy(buffer + bytes_read, (char*)block + block_offset, to_read);
		}

		bytes_read += to_read;
		current_offset += to_read;
		remaining -= to_read;
	}

	free(block);

	return bytes_read;
}

static int myfs_write(const char* path, const char* buffer, size_t size, off_t offset, struct fuse_file_info* fi) {
	struct inode finode = { 0 };

	if (fi->fh == (uint64_t)0) {
		perror("Call open before this operation");

		return -1;
	}

	if (read_inode(fi->fh - 1, &finode) == -1) {
		perror("read_inode");

		return -1;
	}

	if (finode.valid == 0) {
		perror("File is not valid");

		return -ENOENT;
	}

	size_t bytes_written = 0;
	off_t current_offset = offset;
	size_t remaining = size;
	
	void* block_buffer = malloc(BLOCK_SIZE);
	
	if (block_buffer == NULL) {
		perror("Unable to allocate block buffer");

		return -ENOSPC;
	}

	// TODO: handle case when offset is beyond file size
	// the portion from the last byte to offset should be allocated and then write
	while (remaining > 0) {
		size_t block_index = current_offset / BLOCK_SIZE;
		size_t block_offset = current_offset % BLOCK_SIZE;
		size_t to_write = BLOCK_SIZE - block_offset;

		if (to_write > remaining) to_write = remaining;

		// Assume file size is in direct pointers bound
		assert(block_index < DIRECT_PTRS_COUNT);

		int data_block_num = finode.directs[block_index];

		if (data_block_num == -1) {
			// Allocate new data block
			data_block_num = get_avail_blkno();

			if (data_block_num == -1) return -ENOSPC;

			finode.directs[block_index] = data_block_num;
		}

		if (to_write == BLOCK_SIZE) {
			// rewrite the whole block
			// Copy data from buffer to block buffer
			memcpy(block_buffer, buffer + bytes_written, to_write);
			
			// TODO: is there a way to just use the buffer?
			block_write(data_block_num, block_buffer);
		} else {
			// partial write
			block_read(data_block_num, block_buffer);

			memcpy((char*)block_buffer + block_offset, buffer + bytes_written, to_write);

			block_write(data_block_num, block_buffer);
		}

		bytes_written += to_write;
		current_offset += to_write;
		remaining -= to_write;
	}

	// Update file size in inode
	if (offset + bytes_written > finode.size) {
		finode.size = offset + bytes_written;
	}

	// Update time
	finode.mtime = now();

	if (write_inode(finode.ino, &finode) == -1) {
		perror("write_inode");

		return -1;
	}

	free(block_buffer);

	return bytes_written;
}

static int myfs_rmdir(const char* path) {
	return 0;
}

static int myfs_releasedir(const char* path, struct fuse_file_info *fi) {
	return 0;
}

static int myfs_unlink(const char* path) {
	return 0;
}

static int myfs_truncate(const char *path, off_t size, struct fuse_file_info *fi) {
	return 0;
}

static int myfs_flush(const char* path, struct fuse_file_info *fi) {
	return 0;
}

static int myfs_utimens(const char* path, const struct timespec tv[2], struct fuse_file_info* fi) {
	return 0;
}

static int myfs_release(const char* path, struct fuse_file_info *fi) {
	return 0;
}

static struct fuse_operations myfs_ope = {
	.init = myfs_init,
	.destroy = myfs_destroy,

	.getattr = myfs_getattr,
	.readdir = myfs_readdir,
	.opendir = myfs_opendir,
	.mkdir = myfs_mkdir,

	.create = myfs_create,
	.open = myfs_open,
	.read = myfs_read,
	.write = myfs_write,

	.rmdir = myfs_rmdir,
	.releasedir = myfs_releasedir,
	.unlink = myfs_unlink,
	.truncate = myfs_truncate,
	.flush = myfs_flush,
	.utimens = myfs_utimens,
	.release = myfs_release
};

// Entry point of the library
int main(int argc, char* argv[]) {
	printf("Starting MYFS file system...\n");

	int fuse_stat;

	if (getcwd(diskfile_path, PATH_MAX) == NULL) {
		perror("Failed to get diskfile path");
		exit(EXIT_FAILURE);
	}
	
	printf("Disk path is %s\n", diskfile_path);

	strcat(diskfile_path, "/DISKFILE");

	printf("Disk file is %s\n", diskfile_path);
	
	printf("Starting FUSE...\n");

	// Start FUSE
	fuse_stat = fuse_main(argc, argv, &myfs_ope, NULL);
	
	return fuse_stat;
}
