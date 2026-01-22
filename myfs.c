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
int ROOT_INO = -1;

static inline void dump_str(const char*s, size_t len) {
	for (size_t i = 0; i < len; ++i) printf("%02x", (unsigned char)s[i]);

	printf("\n");
}

static inline struct timespec now(void) {
	struct timespec ts;

	ts.tv_sec = time(NULL);
	ts.tv_nsec = 0;

	return ts;	
}

/**
 * Get the first available inode number from inode bitmap
 * Also set it as "used" in the bitmap
 */
int get_avail_ino() {
	assert(superblock != NULL);

	printf("[get_avail_ino]\n");

	int inode_bitmap_blocks = superblock->d_bitmap_blk - superblock->i_bitmap_blk;

	int num_bits_per_blocks = BLOCK_SIZE * 8; 

	assert(inode_bitmap_blocks >= 1);

	assert(num_bits_per_blocks > 0);

	printf("\tReading %d blocks (%d bits) of inode bitmap\n", inode_bitmap_blocks, num_bits_per_blocks);

	bitmap_t bitmap = (bitmap_t)malloc(BLOCK_SIZE);

	if (bitmap == NULL) {
		perror("Cannot allocate memory");

		return -1;
	}

	for (int i = 0; i < inode_bitmap_blocks; ++i) {
		if (block_read(superblock->i_bitmap_blk + i, bitmap) < 0) {
			perror("Cannot read block");

			free(bitmap);

			return -1;
		}

		// Check for next free ino
		for (int j = i * num_bits_per_blocks; j < (i + 1) * num_bits_per_blocks; ++j) {
			if (j >= superblock->max_inum - 1) break;

			printf("\t\tChecking ino %d\n", j);

			if (get_bitmap(bitmap, j - i * num_bits_per_blocks) == 0) {
				printf("\t\tFound ino %d free\n", j);

				set_bitmap(bitmap, j - i * num_bits_per_blocks);

				printf("\t\tSet bit %d in bitmap [%d_th block]\n", j - i * num_bits_per_blocks, superblock->i_bitmap_blk + i);

				if (block_write(superblock->i_bitmap_blk + i, bitmap) < 0) {
					perror("Cannot write block");

					free(bitmap);

					return -1;
				}

				printf("\tSaved to block %d\n", superblock->i_bitmap_blk + i);

				free(bitmap);

				printf("[get_avail_ino] Done.\n");

				return j;
			}
		}
	}

	free(bitmap);

	printf("[get_avail_ino] Done.\n");

	return -1;
}

/**
 * Get the first available data block number from data block bitmap (in data block region)
 * Also set it as used in the bitmap
 */
int get_avail_blkno() {
	assert(superblock != NULL);

	printf("[get_avail_blkno]\n");

	int data_bitmap_blocks = superblock->i_start_blk - superblock->d_bitmap_blk;

	int num_bits_per_blocks = BLOCK_SIZE * 8; 

	assert(data_bitmap_blocks >= 1);

	assert(num_bits_per_blocks > 0);

	printf("\tReading %d blocks (%d bits) of inode bitmap\n", data_bitmap_blocks, num_bits_per_blocks);

	bitmap_t bitmap = (bitmap_t)malloc(BLOCK_SIZE);

	if (bitmap == NULL) {
		perror("Cannot allocate memory");

		return -1;
	}

	for (int i = 0; i < data_bitmap_blocks; ++i) {
		if (block_read(superblock->d_bitmap_blk + i, bitmap) < 0) {
			perror("Cannot read block");

			free(bitmap);

			return -1;
		}

		// Check for next free data block
		for (int j = i * num_bits_per_blocks; j < (i + 1) * num_bits_per_blocks; ++j) {
			if (j >= superblock->max_dnum - 1) break;

			printf("\t\tChecking data block %d\n", j);

			if (get_bitmap(bitmap, j - i * num_bits_per_blocks) == 0) {
				printf("\t\tFound ino %d free\n", j);

				set_bitmap(bitmap, j - i * num_bits_per_blocks);

				printf("\t\tSet bit %d in bitmap [%d_th block]\n", j - i * num_bits_per_blocks, i);

				if (block_write(superblock->d_bitmap_blk + i, bitmap) < 0) {
					perror("Cannot write block");

					free(bitmap);

					return -1;
				}

				printf("\tSaved to block %d\n", superblock->d_bitmap_blk + i);

				free(bitmap);

				printf("\tReturn data block [%d]\n", j + superblock->d_start_blk);

				printf("[get_avail_blkno] Done.\n");

				return j + superblock->d_start_blk;
			}
		}
	}

	free(bitmap);

	printf("[get_avail_blkno] Done.\n");

	return -1;
}

int reset_ino(int ino) {
	printf("[reset_ino] ino: %d\n", ino);

	assert(superblock != NULL);

	assert(ino >= 0 && ino < superblock->max_inum);

	int num_bits_per_block = BLOCK_SIZE * 8;

	int block = superblock->i_bitmap_blk + (ino / num_bits_per_block);

	int bit_idx = ino % num_bits_per_block;

	bitmap_t bitmap = (bitmap_t)malloc(BLOCK_SIZE);

	printf("\tReading and updating bitmap from block %d at bit index %d\n", block, bit_idx);

	if (block_read(block, bitmap) < 0) {
		perror("Cannot read block");

		return -1;
	}

	set_bitmap(bitmap, bit_idx);

	if (block_write(block, bitmap) < 0) {
		perror("Cannot write block");

		return -1;
	}

	printf("[reset_ino] Done.\n\n");

	return 0;
}

int reset_data_block(int data_block) {
	printf("[reset_data_block] ino: %d\n", data_block);

	assert(superblock != NULL);

	assert(data_block >= superblock->d_start_blk && data_block < superblock->max_dnum);

	int num_bits_per_block = BLOCK_SIZE * 8;

	int block = superblock->d_bitmap_blk + ((data_block - superblock->d_start_blk) / num_bits_per_block);

	int bit_idx = (data_block - superblock->d_start_blk) % num_bits_per_block;

	bitmap_t bitmap = (bitmap_t)malloc(BLOCK_SIZE);

	printf("\tReading and updating bitmap from block %d at bit index %d\n", block, bit_idx);

	if (block_read(block, bitmap) < 0) {
		perror("Cannot read block");

		return -1;
	}

	set_bitmap(bitmap, bit_idx);

	if (block_write(block, bitmap) < 0) {
		perror("Cannot write block");

		return -1;
	}

	printf("[reset_data_block] Done.\n\n");

	return 0;
}

/**
 * Read inode info given inode number
 */
int read_inode(uint16_t ino, struct inode* inode) {
	printf("[read_inode] ino: %d\n", ino);

	assert(inode != NULL);
	assert(superblock != NULL);
	assert(ino < superblock->max_inum);

	uint32_t block_index = ino / BLOCK_SIZE;
	uint32_t inode_index = ino % BLOCK_SIZE;
	uint32_t offset = superblock->i_start_blk;

	printf("\tRead from block %d at index %d, offset: %d\n", block_index + offset, inode_index, offset);

	struct inode* inode_table = (struct inode*)malloc(BLOCK_SIZE);
	
	if (inode_table == NULL) {
		perror("Cannot allocate memory");

		return -1;
	}

	if (block_read(block_index + offset, inode_table) < 0) {
		perror("Cannot read block");

		free(inode_table);

		return -1;
	}

	memcpy(inode, inode_table + inode_index, sizeof(struct inode));
	
	free(inode_table);

	printf("[read_inode] Done.\n");

	return 0;
}

/**
 * Write into inode given inode number
 */
int write_inode(uint16_t ino, struct inode* inode) {
	printf("[write_inode] ino: %d\n", ino);

	assert(inode != NULL);
	assert(superblock != NULL);
	assert(ino < superblock->max_inum);

	uint32_t block_index = ino / BLOCK_SIZE;
	uint32_t inode_index = ino % BLOCK_SIZE;
	uint32_t offset = superblock->i_start_blk;
	
	printf("\tRead from block %d at index %d, offset: %d\n", superblock->i_start_blk + block_index, inode_index, offset);

	struct inode* inode_table = (struct inode*)malloc(BLOCK_SIZE);

	if (inode_table == NULL) {
		perror("Cannot allocate memory");

		return -1;
	}

	if (block_read(block_index + offset, inode_table) < 0) {
		perror("Cannot read block");
	
		free(inode_table);

		return -1;
	}

	memcpy(inode_table + inode_index, inode, sizeof(struct inode));

	if (block_write(block_index + offset, inode_table) < 0) {
		perror("Cannot write block");

		free(inode_table);

		return -1;
	}

	free(inode_table);

	return 0;
}

struct inode make_inode(uint16_t ino, uint16_t container_ino, uint32_t type, mode_t mode, int nlink) {
	assert(superblock != NULL);
	assert(ino < superblock->max_inum);
	assert(container_ino < superblock->max_inum);
	
	// For now, just accept dir or regular file or symlink
	assert(type == S_IFDIR || type == __S_IFREG || type == __S_IFLNK);
	assert(nlink >= 0);

	struct inode node;

	node.ino = ino;
	node.container_ino = container_ino;
	node.valid = 1;
	node.size = 0;
	node.type = type;
	node.mode = mode;
	node.nlink = nlink;

	node.atime = now();
	node.mtime = now();
	node.ctime = now();

	node.uid = getuid();
	node.gid = getgid();

	memset(node.directs, -1, DIRECT_PTRS_COUNT * sizeof(int));
	node.indirect_ptr = -1;

	return node;
}

/**
 * Find directory given name, return dirent struct
 * If the provided dirent is NULL, then dir_find won't fill the dirent struct
 * but still return the result of whether the item exists or not
 */
int dir_find(uint16_t ino, const char* fname, size_t name_len, struct dirent* dirent) {
	printf("[dir_find] ino: %d, fname: %s, name_len: %ld\n", ino, fname, name_len);

	assert(superblock != NULL);
	assert(fname != NULL);
	assert(name_len > 0);
	assert(ino < superblock->max_inum);
	
	struct inode dir_inode = { 0 };
	
	if (read_inode(ino, &dir_inode) < 0) {
		perror("dir_find");

		return -1;
	}

	printf("\tRead inode [%d]\n", ino);

	int num_entries_per_block = BLOCK_SIZE / sizeof(struct dirent);
	
	int total_dirents = dir_inode.size / sizeof(struct dirent);

	printf("\tNum entries per block: %d | Total: %d\n", num_entries_per_block, total_dirents);

	struct dirent* buffer = (struct dirent*)malloc(BLOCK_SIZE);

	if (buffer == NULL) {
		perror("Cannot allocate memory");

		return -1;
	}	

	int total_dirents_read = 0;

	for (int i = 0; i < DIRECT_PTRS_COUNT; ++i) {
		if (total_dirents_read == total_dirents) break;

		if (dir_inode.directs[i] < 0) continue;

		if (block_read(dir_inode.directs[i], buffer) < 0) {
			perror("Cannot read block");
			
			free(buffer);

			return -1;
		}

		for (int j = 0; j < num_entries_per_block; ++j) {
			if (total_dirents_read == total_dirents) break;

			printf("\t\tChecking item[%d]: %s at block %d\n", j, buffer[j].name, dir_inode.directs[i]);

			if (buffer[j].valid == 1 && strncmp(buffer[j].name, fname, name_len) == 0) {
				printf("\t\tFound item\n");

				if (dirent != NULL) {
					memcpy(dirent, &buffer[j], sizeof(struct dirent));
				}

				free(buffer);

				printf("[dir_find] Done.\n");

				return 0;
			}

			total_dirents_read++;
		}
	}

	free(buffer);

	printf("[dir_find] Done.\n");

	return -1;
}

/**
 * Add directory given name
 */
int dir_add(struct inode* dir_inode, uint16_t f_ino, const char* fname, size_t name_len) {
	printf("[dir_add] f_ino: %d | fname: %s | name_len: %ld\n", f_ino, fname, name_len);

	assert(superblock != NULL);
	assert(dir_inode != NULL);
	assert(f_ino < superblock->max_inum);
	assert(fname != NULL);
	assert(name_len > 0);

	if (dir_find(dir_inode->ino, fname, name_len, NULL) == 0) {
		return -EEXIST;
	}

	struct inode f_inode = { 0 };

	if (read_inode(f_ino, &f_inode) == -1) {
		perror("Cannot read inode");

		return -1;
	}
	
	struct dirent* buffer = (struct dirent*)malloc(BLOCK_SIZE);

	if (buffer == NULL) {
		perror("Cannot allocate memory");

		return -1;
	}
	
	// Find the first free slot or append it at the end
	int block_idx = 0;

	int num_dirents_per_block = BLOCK_SIZE / sizeof(struct dirent);

	for (; block_idx < DIRECT_PTRS_COUNT; ++block_idx) {
		// Add item to the first unallocated block found
		if (dir_inode->directs[block_idx] < 0) break;

		printf("\tBlock %d is available\n", dir_inode->directs[block_idx]);

		if (block_read(dir_inode->directs[block_idx], buffer) == -1) {
			perror("Cannot read block");

			free(buffer);

			return -1;
		}

		for (int i = 0; i < num_dirents_per_block; ++i) {			
			printf("\tChecking spot %d (valid=%d) at block %d\n", i, buffer[i].valid, dir_inode->directs[block_idx]);

			if (buffer[i].valid == 0) {
				printf("\tFound a free spot at %d at block %d\n", i, dir_inode->directs[block_idx]);

				// Valid free spot
				buffer[i].ino = f_ino;
				buffer[i].valid = 1;

				if (name_len >= NAME_MAX) name_len = NAME_MAX - 1;
				strncpy(buffer[i].name, fname, name_len);
				buffer[i].name[name_len] = '\0';
				buffer[i].len = name_len;

				printf("\tItem name: %s\n", buffer[i].name);
				printf("\t\tDump: ");
				dump_str(buffer[i].name, name_len + 1);

				if (block_write(dir_inode->directs[block_idx], buffer) < 0) {
					perror("Cannot write block");
					
					free(buffer);

					return -1;
				}
				
				// Update size
				dir_inode->size += sizeof(struct dirent);
				
				printf("\tUpdated parent dir size to: %u\n", dir_inode->size);

				// num nlink of dir = 2 + num sub directories
				if (f_inode.type == S_IFDIR && f_inode.ino != dir_inode->ino) {
					dir_inode->nlink++;
				}

				printf("\tUpdated parent dir %d nlink to %d\n", dir_inode->ino, dir_inode->nlink);

				if (write_inode(dir_inode->ino, dir_inode) < 0) {
					perror("Cannot write inode");

					free(buffer);

					return -1;
				}
				
				// Update link count of target ino
				// To prevent dir_add adding itself
				if (f_ino != dir_inode->ino) {
					f_inode.nlink++;

					if (write_inode(f_ino, &f_inode) == -1) {
						perror("Cannot write inode");

						free(buffer);

						return -1;
					}

					printf("\tUpdated entry ino: %d nlink to %d\n", f_inode.ino, f_inode.nlink);
				}

				free(buffer);

				printf("[dir_add] Done.\n");

				return 0;
			} else {
				printf("\tItem at spot %d is %s ino: %d\n", i, buffer[i].name, buffer[i].ino);
			}
		}
	}
	
	if (block_idx == DIRECT_PTRS_COUNT) return -ENOSPC;

	assert(dir_inode->directs[block_idx] < 0);

	int data_block_idx = get_avail_blkno();

	if (data_block_idx < 0) return -ENOSPC;

	printf("\tAssigned data block %d\n", data_block_idx);
	
	dir_inode->directs[block_idx] = data_block_idx;

	// memset the buffer to zero before fill
	memset(buffer, 0, BLOCK_SIZE);

	buffer[0].ino = f_ino;
	buffer[0].valid = 1;

	if (name_len >= NAME_MAX) name_len = NAME_MAX - 1; 
	strncpy(buffer[0].name, fname, name_len);
	buffer[0].name[name_len] = '\0';
	buffer[0].len = name_len;

	printf("\tItem name: %s\n", buffer[0].name);
	printf("\t\tDump: ");
	dump_str(buffer[0].name, name_len + 1);

	if (block_write(data_block_idx, buffer) < 0) {
		perror("Cannot write data block");

		return -1;
	}

	// Update size
	dir_inode->size += sizeof(struct dirent);

	printf("\tUpdated dir size to: %u\n", dir_inode->size);

	// num nlink of dir = 2 + num sub directories
	if (f_inode.type == S_IFDIR) {
		dir_inode->nlink++;
	}

	printf("\tUpdated parent dir %d nlink to %d\n", dir_inode->ino, dir_inode->nlink);

	if (write_inode(dir_inode->ino, dir_inode) < 0) {
		perror("Cannot write inode");

		free(buffer);

		return -1;
	}

	printf("\tWrote parent inode update\n");

	// Update link count of target ino
	if (f_ino != dir_inode->ino) {
		printf("\tf_ino = %d | dir ino = %d\n", f_ino, dir_inode->ino);

		f_inode.nlink++;

		if (write_inode(f_ino, &f_inode) == -1) {
			perror("Cannot write inode");

			free(buffer);

			return -1;
		}

		printf("\tUpdated entry ino: %d nlink to %d\n", f_inode.ino, f_inode.nlink);
	}

	free(buffer);

	printf("[dir_add] Done.\n");

	return 0;
}

/**
 * Remove an entry from a directory
 */
int dir_remove(struct inode* dir_inode, struct inode* entry_inode) {
	assert(superblock != NULL);
	assert(dir_inode != NULL);
	assert(entry_inode != NULL);
	assert(entry_inode->ino < superblock->max_inum);
	assert(dir_inode->ino != entry_inode->ino);
	
	printf("[dir_remove] parent ino: %d about to remove ino: %d\n", dir_inode->ino, entry_inode->ino);

	int num_entry = dir_inode->size / sizeof(struct dirent);

	int num_entries_per_block = BLOCK_SIZE / sizeof(struct dirent);
	
	printf("\tNum entries: %d | Num entries per block: %d\n", num_entry, num_entries_per_block);

	int entries_read = 0;

	struct dirent* buffer = (struct dirent*)malloc(BLOCK_SIZE);

	if (buffer == NULL) {
		perror("Cannot allocate memory");

		return -1;
	}

	for (int i = 0; i < DIRECT_PTRS_COUNT; ++i) {
		if (entries_read == num_entry) break;

		if (dir_inode->directs[i] < 0) continue;

		if (block_read(dir_inode->directs[i], buffer) < 0) {
			perror("Cannot read block");
			
			free(buffer);

			return -1;
		}

		for (int j = 0; j < num_entries_per_block; ++j, ++entries_read) {
			if (entries_read == num_entry) break;

			if (buffer[j].valid == 1 && buffer[j].ino == entry_inode->ino) {
				buffer[j].valid = 0; // mark as invalid or free slot
				buffer[j].name[0] = '\0';

				if (block_write(dir_inode->directs[i], buffer) < 0) {
					perror("Cannot write block");

					free(buffer);

					return -1;
				}

				dir_inode->size -= sizeof(struct dirent);

				printf("\tUpdated size of dir: %u\n", dir_inode->size);

				if (entry_inode->type == S_IFDIR) {
					dir_inode->nlink--;
				}

				printf("\tUpdated parent ino %d nlink to %d\n", dir_inode->ino, dir_inode->nlink);

				if (write_inode(dir_inode->ino, dir_inode) < 0) {
					perror("Cannot write inode");

					free(buffer);

					return -1;
				}

				// Update nlink of target inode
				entry_inode->nlink--;

				if (write_inode(entry_inode->ino, entry_inode) < 0) {
					perror("Cannot write inode");

					return -1;
				}

				printf("\tUpdated nlink of target ino: %d to be = %d\n", entry_inode->ino, entry_inode->nlink);

				printf("[dir_remove] Done.\n");

				return 0;
			}
		}
	}

	printf("\tf_ino: %d does not exist in ino: %d\n", entry_inode->ino, dir_inode->ino);

	// target does not exist
	free(buffer);

	return -1;
}

/**
 * Get inode number from the give path, save info into returned inode
 */
int get_node_by_path(const char* path, uint16_t ino, struct inode* inode) {
	printf("[get_node_by_path] path: %s | ino: %d\n", path, ino);

	assert(path != NULL);
	assert(ROOT_INO >= 0);
	assert(ino < superblock->max_inum);
	assert(inode != NULL);

	// If the given path is the root directory, just return it
	printf("\tIs this root node: %d\n", strcmp(path, "/"));

	if (strcmp(path, "/") == 0) {
		if (read_inode(ROOT_INO, inode) < 0) {
			perror("Cannot read inode");

			return -1;
		}

		return 0;
	}
	
	struct inode current = { 0 };

	// Start walking from the root node
	if (read_inode(ino, &current) < 0) {
		perror("Cannot read inode");

		return -1;
	}
	
	if (current.valid == 0) {
		perror("[get_node_by_path] Item not valid!");

		return -ENOENT; // root inode is not valid
	}

	char* path_clone = strdup(path);
	char* token = strtok(path_clone, "/");
	
	struct dirent dir_entry = { 0 };
	
	while (token) {
		// Find the token in the current directory's inode
		if (dir_find(current.ino, token, strlen(token), &dir_entry) < 0) {
			// Token not found
			perror("[get_node_by_path] Item not found!");
			
			free(path_clone);

			return -ENOENT;
		}

		// Read inode of the token, then move current to token's inode
		// a.k.a walking toward to target
		if (read_inode(dir_entry.ino, &current) < 0) {
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

	printf("[ALERT] ino: %d | size = %u\n", inode->ino, inode->size);

	free(path_clone);
		
	return 0;
}

int init_superblock() {	
	assert(superblock == NULL);

	printf("[init_superblock]\n");

	// STORATE FILE FORMAT:
	// | superblock | inode bitmap | data bitmap | inode | data |
	
	superblock = (struct superblock*)malloc(sizeof(struct superblock));

	if (superblock == NULL) {
		perror("Cannot allocate memory");

		return -1;
	}

	printf("\tAllocated memory\n");

	printf("\tCheck if the opened file has valid superblock signature\n");

	if (block_read(SUPERBLOCK_BLK_NUM, superblock) < 0) {
		perror("Cannot read block");

		return -1;
	}

	if (superblock->magic_num == MAGIC_NUM) {
		printf("\tValid superblock found. Storage file has already existed\n");

		printf("[init_superblock] Done.\n\n");

		return 0;
	}

	superblock->magic_num = MAGIC_NUM;
	superblock->max_inum = MAX_INODE_NUM;
	superblock->max_dnum = MAX_DATA_NUM;
	superblock->i_bitmap_blk = 1; // after superblock's block

	// Total blocks required to store inode bitmap
	uint16_t total_required_blocks = (int)ceil(INODE_BITMAP_BYTES / (float)BLOCK_SIZE);

	assert(total_required_blocks >= 1);

	printf("\tInode bitmap required blocks: %d\n", total_required_blocks);

	// Data bitmap block start after the last inode bitmap block
	superblock->d_bitmap_blk = superblock->i_bitmap_blk + total_required_blocks;

	// Total blocks required to store data bitmap
	total_required_blocks = (int)ceil(DATA_BITMAP_BYTES / (float)BLOCK_SIZE);

	assert(total_required_blocks >= 1);

	printf("\tData bitmap required blocks: %d\n", total_required_blocks);

	// The inode region starts after the data bitmap last block
	superblock->i_start_blk = superblock->d_bitmap_blk + total_required_blocks;

	// Total blocks required to store inode region
	total_required_blocks = (int)ceil(superblock->max_inum * sizeof(struct inode) / (float)BLOCK_SIZE);

	assert(total_required_blocks >= 1);

	printf("\tInode required blocks: %d\n", total_required_blocks);

	// The data region starts after the last block of inode region
	superblock->d_start_blk = superblock->i_start_blk + total_required_blocks;

	printf("Saving superblock...\n");

	if (block_write(SUPERBLOCK_BLK_NUM, superblock) < 0) {
		perror("Cannot write block");

		return -1;
	}

	printf("Saved superblock\n");

	printf("[init_superblock] Done.\n\n");

	return 0;
}

int init_inode_bitmap() {
	assert(superblock != NULL);
	assert(superblock->i_bitmap_blk > SUPERBLOCK_BLK_NUM);

	printf("[init_inode_bitmap]\n");

	int inode_bitmap_blocks = superblock->d_bitmap_blk - superblock->i_bitmap_blk;

	assert(inode_bitmap_blocks >= 1);

	printf("\tSaving bitmap to %d blocks\n", inode_bitmap_blocks);

	void* buffer = malloc(BLOCK_SIZE);

	if (buffer == NULL) {
		perror("Cannot allocate memory");

		return -1;
	}

	// Set all bits to zero
	memset(buffer, 0, BLOCK_SIZE);

	for (int i = 0; i < inode_bitmap_blocks; ++i) {
		if (block_write(superblock->i_bitmap_blk + i, buffer) < 0) {
			perror("Cannot write block");

			free(buffer);

			return -1;
		}
	}

	free(buffer);

	printf("\tSaved bitmap to %d blocks\n", inode_bitmap_blocks);

	printf("[init_inode_bitmap] Done.\n\n");

	return 0;
}

int init_data_bitmap() {
	assert(superblock != NULL);
	assert(superblock->d_bitmap_blk > SUPERBLOCK_BLK_NUM);
	assert(superblock->d_bitmap_blk > superblock->i_bitmap_blk);

	printf("[init_data_bitmap]\n");

	int data_bitmap_blocks = superblock->i_start_blk - superblock->d_bitmap_blk;

	assert(data_bitmap_blocks >= 1);

	printf("\tSaving bitmap to %d blocks\n", data_bitmap_blocks);

	void* buffer = malloc(BLOCK_SIZE);

	if (buffer == NULL) {
		perror("Cannot allocate memory");

		return -1;
	}

	// Set all bits in the bitmap to zero
	memset(buffer, 0, BLOCK_SIZE);

	for (int i = 0; i < data_bitmap_blocks; ++i) {
		if (block_write(superblock->d_bitmap_blk + i, buffer) < 0) {
			perror("Cannot write block");

			free(buffer);

			return -1;
		}
	}

	free(buffer);

	printf("\tSaved bitmap to %d blocks\n", data_bitmap_blocks);

	printf("[init_data_bitmap] Done.\n\n");

	return 0;
}

int init_inode_region() {
	assert(superblock != NULL);
	assert(superblock->i_start_blk > SUPERBLOCK_BLK_NUM);
	assert(superblock->i_start_blk > superblock->d_bitmap_blk);

	printf("[init_inode_region]\n");

	// Comment: it is okay to just leave this region with junk data whatever
	// but I think it is a bit better that I should set them back to all zeros to 
	// prevent unforeseen bugs and as well as it is easier to debug if I know ahead
	// of time what the state of the block is
	int inode_blocks = superblock->d_start_blk - superblock->i_start_blk;

	assert(inode_blocks >= 1);

	void* buffer = malloc(BLOCK_SIZE);

	if (buffer == NULL) {
		perror("Cannot allocate memory");

		return -1;
	}

	memset(buffer, 0, BLOCK_SIZE);

	for (int i = 0; i < inode_blocks; ++i) {
		if (block_write(superblock->i_start_blk + i, buffer) < 0) {
			perror("Cannot write block");

			free(buffer);

			return -1;
		}
	}

	printf("\tSaved inode to %d blocks\n", inode_blocks);

	printf("\tSaving root inode...\n");

	ROOT_INO = get_avail_ino();

	if (ROOT_INO < 0) {
		perror("Cannot set root ino");

		free(buffer);

		return -1;
	}

	struct inode root_inode = make_inode(ROOT_INO, ROOT_INO, S_IFDIR, 0755, 0);

	if (write_inode(ROOT_INO, &root_inode) < 0) {
		perror("Cannot write inode");

		free(buffer);

		return -1;
	}

	printf("\tSaved root inode\n");

	if (dir_add(&root_inode, ROOT_INO, ".", 1) < 0) {
		perror("Cannot add entry to root inode");

		free(buffer);

		return -1;
	}

	struct inode test_root_inode = { 0 };
	
	read_inode(ROOT_INO, &test_root_inode);

	printf("[ROOT ALERT] size = %u\n", test_root_inode.size);

	free(buffer);

	printf("[init_inode_region] Done.\n\n");

	return 0;
}

/**
 * Make file system
 * - This is where to call dev_init to first init the storage file
 * - Init superblock in the storage file
 * - And write root directory into the first inode and data block
 */
int myfs_mkfs() {
	printf("[myfs_mkfs]\n");

	assert(diskfile_path != NULL);

	dev_init(diskfile_path);

	if (init_superblock() < 0) {
		perror("Failed to init superblock");

		exit(EXIT_FAILURE);
	}

	if (init_inode_bitmap() < 0) {
		perror("Failed to init inode bitmap");

		exit(EXIT_FAILURE);
	}

	if (init_data_bitmap() < 0) {
		perror("Failed to init data bitmap");

		exit(EXIT_FAILURE);
	}

	if (init_inode_region() < 0) {
		perror("Failed to init inode region");

		exit(EXIT_FAILURE);
	}

	printf("[myfs_mkfs] Done.\n");

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

	if (myfs_mkfs() < 0) {
		perror("Failed to init MYFS");

		exit(EXIT_FAILURE);
	}

	return NULL;
}

/**
 * Destroy MYFS
 */
static void myfs_destroy(void *userdata) {
	printf("[myfs_destroy]\n");
	
	free(superblock);

	dev_close();

	printf("[myfs_destroy] Done.\n");
}

static int myfs_getattr(const char* path, struct stat *st_buf, struct fuse_file_info *fi) {
	printf("[myfs_getattr] path: %s\n", path);

	assert(path != NULL);
	assert(ROOT_INO >= 0);

	struct inode finode = { 0 };
	
	if (get_node_by_path(path, ROOT_INO, &finode) < 0) {
		return -ENOENT;
	}
	
	if (finode.valid == 0) {
		return -ENOENT;
	}

	st_buf->st_ino = finode.ino;
	st_buf->st_size = finode.size;
	st_buf->st_nlink = finode.nlink;
   	st_buf->st_mode = finode.type | finode.mode;
	st_buf->st_uid = finode.uid;
	st_buf->st_gid = finode.gid;
	st_buf->st_atim = finode.atime;
	st_buf->st_mtim = finode.mtime;
	st_buf->st_ctim = finode.ctime;

	printf("[myfs_getattr] Done.\n");

	return 0;
}

static int myfs_opendir(const char* path, struct fuse_file_info *fi) {
	printf("[myfs_opendir] path: %s\n", path);

	assert(ROOT_INO >= 0);

	struct inode dir_inode = { 0 };

	if (get_node_by_path(path, ROOT_INO, &dir_inode) < 0) {
		return -ENOENT;
	}

	if (dir_inode.valid == 0) {
		return -ENOENT;
	}

	// Save inode number of this dir into *fh struct of fuse_file_info
	fi->fh = (uint64_t)dir_inode.ino + 1;
	
	printf("[myfs_opendir] Done.\n");

	return 0;
}

static int myfs_readdir(const char* path, void* buffer, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info *fi, enum fuse_readdir_flags flags) {
	printf("[myfs_readdir] path: %s\n", path);

	assert(path != NULL);

	// Check if inode is cached with opendir
	if (fi->fh == (uint64_t)0) {
		perror("opendir is not called prior to this function call");
		return -1;
	}

	struct inode dir_inode = { 0 };

	if (read_inode(fi->fh - 1, &dir_inode) < 0) {
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
	
	struct dirent* block_buffer = (struct dirent*)malloc(BLOCK_SIZE);
	
	if (block_buffer == NULL) {
		perror("Cannt allocate memory");

		return -ENOSPC;
	}

	struct dirent entry = { 0 };

	int total_dirent_read = 0;
	
	int b = 0;
	
	// Read from direct first
	for(; b < DIRECT_PTRS_COUNT; ++b) {
		if (total_dirent_read == total_dirent) break;
		
		if (dir_inode.directs[b] < 0) continue;
		
		if (block_read(dir_inode.directs[b], block_buffer) < 0) {
			perror("Cannot read block");

			free(block_buffer);

			return -1;
		}

		for (int i = 0; i < num_dirent_per_block && i < total_dirent; ++i) {
			if (total_dirent_read == total_dirent) break;
			
			entry = block_buffer[i];

			printf("\tItem[%d]: %s\n", i, entry.name);
			printf("\t\tDump: ");
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

	printf("[myfs_readdir] Done.\n");

	return 0;	
}

static int myfs_mkdir(const char* path, mode_t mode) {
	printf("[myfs_mkdir] path: %s | mode: %o\n", path, mode);

	assert(path != NULL);
	assert(ROOT_INO >= 0);

	char *tmp1 = strdup(path);
	char *tmp2 = strdup(path);

	if (tmp1 == NULL || tmp2 == NULL) {
		perror("Failed to allocate memory for path");

		if (tmp1) free(tmp1);
		if (tmp2) free(tmp2);

		return -ENOSPC;
	}

	char *dir = strdup(dirname(tmp1));
	char *base = strdup(basename(tmp2));

	free(tmp1);
	free(tmp2);

	if (dir == NULL || base == NULL) {
		perror("Unable to extract base or dir name due to space");

		if (dir) free(dir);
		if (base) free(base);

		return -ENOSPC;
	}

	printf("\tDir %s | Base: %s\n", dir, base);

	struct inode parent_inode = { 0 };

	if (get_node_by_path(dir, ROOT_INO, &parent_inode) < 0) {
		return -ENOENT;
	}

	if (parent_inode.valid == 0) {
		free(base);
		free(dir);

		return -ENOENT;
	}
	
	// Check if the target directory already exists
	if (dir_find(parent_inode.ino, base, strlen(base), NULL) == 0) {
		free(base);
		free(dir);

		return -EEXIST;
	}

	// Get next available inode number for this new directory
	int ino = get_avail_ino();

	if (ino < 0) {
		free(base);
		free(dir);

		return -ENOSPC;
	}

	struct inode new_dir_inode = make_inode(ino, parent_inode.ino, S_IFDIR, mode, 0);

	if (write_inode(ino, &new_dir_inode) < 0) {
		perror("Cannot write inode");

		free(base);
		free(dir);

		return -1;
	}

	printf("\tWrote new dir inode\n");
	
	if (dir_add(&new_dir_inode, ino, ".", 1) < 0) {
		perror("Cannot add dirent");

		return -1;
	}

	printf("\tWrote '.' entry to new dir inode\n");
	
	if (dir_add(&new_dir_inode, parent_inode.ino, "..", 2) < 0) {
		perror("Cannot add dirent");

		return -1;
	}

	printf("\tWrote '..' entry to new dir inode\n");
	
	if (dir_add(&parent_inode, ino, base, strlen(base)) < 0) {
		perror("Cannot add dirent");

		return -1;
	}

	printf("\tWrote dir entry to parent dir inode\n");
	
	free(dir);
	free(base);

	printf("[myfs_mkdir] Done.\n");

	return 0;
}

static int myfs_create(const char* path, mode_t mode, struct fuse_file_info* fi) {
	printf("[myfs_create] path: %s | mode: %o\n", path, mode);

	assert(path != NULL);
	assert(ROOT_INO >= 0);

	char *tmp1, *tmp2;

	tmp1 = strdup(path);
	tmp2 = strdup(path);

	if (tmp1 == NULL || tmp2 == NULL) {
		perror("Cannot allocate memory");

		if (tmp1) free(tmp1);
		if (tmp2) free(tmp2);

		return -ENOSPC;
	}	

	char* base = basename(strdup(tmp1));
	char* dir = dirname(strdup(tmp2));
	
	free(tmp1);
	free(tmp2);

	if (base == NULL || dir == NULL) {
		perror("Cannot allocate memory");

		if (base) free(base);
		if (dir) free(dir);

		return -ENOSPC;
	}

	printf("\tDir: %s | Base: %s\n", dir, base);
	
	// Get parent inode and check if the target file is already exist
	struct inode parent_inode = { 0 };

	if (get_node_by_path(dir, ROOT_INO, &parent_inode) < 0) {
		free(base);
		free(dir);
		
		return -ENOENT;
	}

	if (parent_inode.valid == 0) {
		free(base);
		free(dir);

		return -ENOENT;
	}

	printf("\t[ALERT] parent ino: %d | size = %u\n", parent_inode.ino, parent_inode.size);

	// Check if the target file already exists
	if (dir_find(parent_inode.ino, base, strlen(base), NULL) == 0) {
		free(base);
		free(dir);

		return -EEXIST;
	}

	// Get the next available inode number for this file
	int ino = get_avail_ino();

	if (ino < 0) {
		free(base);
		free(dir);

		return -ENOSPC;
	}

	struct inode new_file_inode = make_inode(ino, parent_inode.ino, __S_IFREG, mode, 0);

	if (write_inode(ino, &new_file_inode) < 0) {
		perror("Cannot write inode");

		free(base);
		free(dir);

		return -1;
	}

	printf("\tWrote file inode ino: %d to parent ino: %d\n", ino, parent_inode.ino);

	if (dir_add(&parent_inode, ino, base, strlen(base)) < 0) {
		perror("Cannot add dirent entry");

		free(base);
		free(dir);

		return -1;
	}

	printf("\tAdded file entry ino: %d to parent ino: %d\n", ino, parent_inode.ino);
	
	// Save inode into cache for later use
	fi->fh = (uint64_t)ino + 1;

	printf("[myfs_create] Done.\n");
	
	return 0;
}

static int myfs_open(const char* path, struct fuse_file_info *fi) {
	printf("[myfs_open] path: %s\n", path);

	assert(path != NULL);
	assert(ROOT_INO >= 0);

	struct inode finode = { 0 };

	if (get_node_by_path(path, ROOT_INO, &finode) < 0) {
		return -ENOENT;
	}

	if (finode.valid == 0) {
		return -ENOENT;
	}

	fi->fh = (uint64_t)finode.ino + 1;

	printf("[myfs_open] Done.\n");

	return 0;
}

static int myfs_read(const char* path, char* buffer, size_t size, off_t offset, struct fuse_file_info* fi) {
	printf("[myfs_read] path: %s | size: %zu | offset: %ld\n", path, size, offset);

	assert(path != NULL);
	assert(size > 0);
	assert(offset >= 0);

	struct inode finode = { 0 };

	if (fi->fh == (uint64_t)0) {
		perror("Call open() before this operation");

		return -1;
	}

	if (read_inode(fi->fh - 1, &finode) < 0) {
		perror("Cannot read inode");

		return -1;
	}

	printf("\tRead inode with ino: %ld\n", fi->fh - 1);

	if (finode.type != __S_IFREG) {
		perror("Not a file");

		return -1;
	}

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

	printf("\tReading file (%zu) of size: %u | offset: %ld\n", finode.size, size, offset);

	size_t bytes_read = 0;
	off_t current_offset = offset;
	size_t remaining = size;
	
	void* block = malloc(BLOCK_SIZE);

	if (block == NULL) {
		perror("Cannot allocate memory");

		return -ENOSPC;
	}

	while (remaining > 0) {
		size_t block_index = current_offset / BLOCK_SIZE;
		size_t block_offset = current_offset % BLOCK_SIZE;
		size_t to_read = BLOCK_SIZE - block_offset;

		if (to_read > remaining) to_read = remaining;

		// Assume we only use direct ptr firstly
		assert(block_index < DIRECT_PTRS_COUNT);

		int data_block_num = finode.directs[block_index];

		if (data_block_num < 0) {
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

	printf("\tBytes read: %zu\n", bytes_read);

	printf("[myfs_read] Done.\n");

	return bytes_read;
}

static int myfs_write(const char* path, const char* buffer, size_t size, off_t offset, struct fuse_file_info* fi) {
	printf("[myfs_write] path: %s | size: %zu | offset: %ld\n", path, size, offset);

	assert(path != NULL);
	assert(size > 0);
	assert(offset >= 0);

	struct inode finode = { 0 };

	if (fi->fh == (uint64_t)0) {
		perror("Call open before this operation");

		return -1;
	}

	if (read_inode(fi->fh - 1, &finode) < 0) {
		perror("Cannot read inode");

		return -1;
	}

	printf("\tRead inode with ino: %ld\n", fi->fh - 1);

	if (finode.type != __S_IFREG) {
		perror("Not a file");

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
		perror("Cannot allocate memory");

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

		if (data_block_num < 0) {
			// Allocate new data block
			data_block_num = get_avail_blkno();

			if (data_block_num < 0) return -ENOSPC;

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

	if (write_inode(finode.ino, &finode) < 0) {
		perror("write_inode");

		return -1;
	}

	free(block_buffer);

	printf("\tBytes written: %zu\n", bytes_written);

	printf("[myfs_write] Done.\n");

	return bytes_written;
}

static int myfs_rmdir(const char* path) {
	assert(path != NULL);
	assert(ROOT_INO != -1);
	
	printf("[myfs_rmdir] path: %s\n", path);

	if (strcmp(path, "/") == 0) {
		perror("Cannot remove root directory");

		return -EBUSY;
	}

	struct inode dir_inode = { 0 };

	if (get_node_by_path(path, ROOT_INO, &dir_inode) < 0) {
		return -ENOENT;
	}

	// Check if this is a directory
	if (dir_inode.type != S_IFDIR) {
		return -ENOTDIR;
	}

	// Can only delete empty dir
	// Check if dir is empty
	if (dir_inode.size > 2 * sizeof(struct dirent)) {
		return -ENOTEMPTY;
	}

	printf("\tdir is a valid empty directory, can be removed\n");

	struct inode parent_inode = { 0 };

	if (read_inode(dir_inode.container_ino, &parent_inode) < 0) {
		perror("Cannot read inode");

		return -1;
	}

	printf("\tParent inode: %d\n", parent_inode.ino);

	// Remove dir entry from parent
	if (dir_remove(&parent_inode, &dir_inode) < 0) {
		perror("Cannot remove dir entry from parent");

		return -1;
	}

	// reset data block if it has any allocated data blocks
	for (int i = 0; i < DIRECT_PTRS_COUNT; ++i) {
		if (dir_inode.directs[i] < 0) continue;;

		if (reset_data_block(dir_inode.directs[i]) < 0) {
			perror("Cannot reset data block");

			return -1;
		}
	}

	if (dir_inode.indirect_ptr >= 0) {
		if (reset_data_block(dir_inode.indirect_ptr) < 0) {
			perror("Cannot reset data block");

			return -1;
		}
	}

	if (reset_ino(dir_inode.ino) < 0) {
		perror("Cannot reset inode");

		return -1;
	}

	printf("[myfs_rmdir] Done.\n\n");

	return 0;
}

static int myfs_releasedir(const char* path, struct fuse_file_info *fi) {
	// Simply remove fi->fh cache
	fi->fh = 0;

	return 0;
}

static int myfs_unlink(const char* path) {
	assert(path != NULL);
	assert(ROOT_INO != -1);

	printf("[myfs_unlink] path: %s\n", path);

	if (strcmp(path, "/") == 0) {
		perror("Cannot remove root directory");

		return -EISDIR;
	}

	struct inode f_inode = { 0 };

	if (get_node_by_path(path, ROOT_INO, &f_inode) < 0) {
		return -ENOENT;
	}

	// Check if this is a file or a softlink
	if (f_inode.type == S_IFDIR) {
		return -EISDIR;
	}

	printf("\t File is a valid file to be removed\n");

	struct inode parent_inode = { 0 };

	if (read_inode(f_inode.container_ino, &parent_inode) < 0) {
		perror("Cannot read inode");

		return -1;
	}

	printf("\tParent inode: %d\n", parent_inode.ino);

	// Remove file entry from parent dir
	if (dir_remove(&parent_inode, &f_inode) < 0) {
		perror("Cannot remove file entry from parent");

		return -1;
	}

	// Check if nlink == 0
	// If nlink is 0, remove the file content
	// Simply returns its data blocks back to the file system
	if (f_inode.nlink == 0) {
		printf("\tFile ino: %d has 0 nlink, remove its data blocks\n", f_inode.ino);

		for (int i = 0; i < DIRECT_PTRS_COUNT; ++i) {
			if (f_inode.directs[i] >= 0) {
				reset_data_block(f_inode.directs[i]);
			}
		}

		if (f_inode.indirect_ptr >= 0) reset_data_block(f_inode.indirect_ptr);
	}

	printf("[myfs_unlink] Done.\n\n");

	return 0;
}

static int myfs_truncate(const char *path, off_t size, struct fuse_file_info *fi) {
	assert(path != NULL);
	assert(size >= 0);
	
	printf("[myfs_truncate] path: %s | size: %ld\n", path, size);

	if (fi->fh == 0) {
		perror("Call open() before this operation");
		
		return -1;
	}

	struct inode f_inode = { 0 };

	if (read_inode(fi->fh - 1, &f_inode) == -1) {
		return -ENOENT;
	}

	if (f_inode.type == S_IFDIR) {
		return -EISDIR;
	}

	if (f_inode.size == size) {
		printf("\tFile size equals to requested size. Do nothing\n");

		// Do nothing, only update timestamp
		f_inode.atime = now();

		if (write_inode(f_inode.ino, &f_inode) == -1) {
			perror("Cannot write inode");

			return -1;
		}

		printf("[myfs_truncate] Done.\n\n");

		return 0;
	}

	if (f_inode.size == 0 || f_inode.size < size) {
		printf("\tFile size is 0 or expanding, set to size = %d\n", size);

		f_inode.size = size;

		f_inode.atime = now();
		f_inode.ctime = now();
		f_inode.mtime = now();

		if (write_inode(f_inode.ino, &f_inode) < 0) {
			perror("Cannot write inode");

			return -1;
		}

		printf("[myfs_truncate] Done.\n");

		return 0;
	}

	printf("\tShrinking file size of %d to %d (removing %d)\n", f_inode.size, size, f_inode.size - size);

	// Shrink
	int req_blk_idx = size / BLOCK_SIZE;
	int req_blk_offset = size % BLOCK_SIZE;

	assert(f_inode.directs[req_blk_idx] >= 0);

	printf("\tReq Blk Idx: %d | Req Blk Offset: %d\n", req_blk_idx, req_blk_offset);

	// Remove all blocks beyond req_blk_idx
	for (int i = req_blk_idx + 1; i < DIRECT_PTRS_COUNT; ++i) {
		if (f_inode.directs[i] < 0) continue;

		if (reset_data_block(f_inode.directs[i]) < 0) {
			perror("Cannot reset data block");

			return -1;
		}
	}

	printf("\tRemoved all blocks after %d\n", req_blk_idx);

	// Truncate block req_blk_idx (the rest is filled with zero)
	void* buffer = malloc(BLOCK_SIZE);

	if (buffer == NULL) {
		perror("Cannot allocate memory");

		return -1;
	}

	if (block_read(f_inode.directs[req_blk_idx], buffer) < 0) {
		perror("Cannot read block");

		free(buffer);

		return -1;
	}

	memset(buffer + req_blk_offset, 0, BLOCK_SIZE - req_blk_offset);

	printf("\tSet to 0 of data block %d from offset %d | size %d\n", f_inode.directs[req_blk_idx], req_blk_offset, BLOCK_SIZE - req_blk_offset);

	if (block_write(f_inode.directs[req_blk_idx], buffer) < 0) {
		perror("Cannot write block");
	}

	// Update size
	f_inode.size = size;

	// Update time
	f_inode.atime = now();
	f_inode.mtime = now();
	f_inode.ctime = now();

	if (write_inode(f_inode.ino, &f_inode) < 0) {
		perror("Cannot write inode");

		return -1;
	}

	printf("\tUpdated f_inode size = %u\n", f_inode.size);

	printf("[myfs_truncate] Done.\n");

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

static int myfs_symlink(const char* target, const char* link) {
	assert(target != NULL);
	assert(link != NULL);
	assert(ROOT_INO != -1);

	printf("[myfs_symlink] target: %s | link: %s\n", target, link);
	
	printf("\tCreating symlink file\n");

	char *tmp1, *tmp2;

	tmp1 = strdup(link);
	tmp2 = strdup(link);

	if (tmp1 == NULL || tmp2 == NULL) {
		perror("Cannot allocate memory");

		if (tmp1) free(tmp1);
		if (tmp2) free(tmp2);

		return -ENOSPC;
	}

	char *base = basename(strdup(tmp1));
	char *dir = dirname(strdup(tmp2));

	free(tmp1);
	free(tmp2);

	if (base == NULL || dir == NULL) {
		perror("Cannot allocate memory");

		if (base) free(base);
		if (dir) free(dir);

		return -ENOSPC;
	}

	printf("\tLink -- Dir: %s | Base: %s\n", dir, base);

	// Get parent inode and check if the target file is already exist
	struct inode parent_inode = { 0 };

	if (get_node_by_path(dir, ROOT_INO, &parent_inode) < 0) {
		free(base);
		free(dir);
		
		return -ENOENT;
	}

	if (parent_inode.valid == 0) {
		free(base);
		free(dir);

		return -ENOENT;
	}

	// Check if the target file already exists
	if (dir_find(parent_inode.ino, base, strlen(base), NULL) == 0) {
		free(base);
		free(dir);

		return -EEXIST;
	}

	// Get the next available inode number for this file
	int ino = get_avail_ino();

	if (ino < 0) {
		free(base);
		free(dir);

		return -ENOSPC;
	}

	struct inode new_file_inode = make_inode(ino, parent_inode.ino, __S_IFLNK, 0755, 0);

	if (write_inode(ino, &new_file_inode) < 0) {
		perror("Cannot write inode");

		free(base);
		free(dir);

		return -1;
	}

	printf("\tWrote file inode ino: %d to parent ino: %d\n", ino, parent_inode.ino);

	if (dir_add(&parent_inode, ino, base, strlen(base)) < 0) {
		perror("Cannot add dirent entry");

		free(base);
		free(dir);

		return -1;
	}

	printf("\tAdded file entry ino: %d to parent ino: %d\n", ino, parent_inode.ino);

	printf("\tWriting file path to symlink\n");

	size_t buffer_size = strlen(target) + 1;

	printf("\tPath size in bytes = %zu\n", buffer_size);

	// Path should have length less than a page
	if (buffer_size > BLOCK_SIZE) {
		perror("Path cannot longer than a page");

		return -ENOSPC;
	}

	int blk_idx = get_avail_blkno();

	if (blk_idx < 0) {
		return -ENOSPC;
	}

	printf("\tAssigned data block %d to symlink file\n", blk_idx);

	new_file_inode.directs[0] = blk_idx;
	new_file_inode.size += buffer_size;

	if (write_inode(new_file_inode.ino, &new_file_inode) < 0) {
		perror("Cannot write inode");

		return -1;
	}

	// Write path to block
	char* buffer = (char*)malloc(BLOCK_SIZE);

	if (buffer == NULL) {
		perror("Cannot allocate memory");

		return -ENOSPC;
	}

	memcpy(buffer, target, buffer_size);

	if (block_write(blk_idx, buffer) < 0) {
		perror("Cannot write block");

		free(buffer);

		return -1;
	}

	printf("\tWrote path to file\n");

	free(buffer);

	printf("[myfs_symlink] Done.\n");

	return 0;
}

static int myfs_link(const char* target, const char* link) {
	assert(target != NULL);
	assert(link != NULL);
	assert(ROOT_INO != -1);

	printf("[myfs_link] target: %s | link: %s\n", target, link);
	
	char *tmp1, *tmp2;

	tmp1 = strdup(link);
	tmp2 = strdup(link);

	if (tmp1 == NULL || tmp2 == NULL) {
		perror("Cannot allocate memory");

		if (tmp1) free(tmp1);
		if (tmp2) free(tmp2);

		return -ENOSPC;
	}

	char *base = basename(strdup(tmp1));
	char *dir = dirname(strdup(tmp2));

	free(tmp1);
	free(tmp2);

	if (base == NULL || dir == NULL) {
		perror("Cannot allocate memory");

		if (base) free(base);
		if (dir) free(dir);

		return -ENOSPC;
	}

	printf("\tLink -- Dir: %s | Base: %s\n", dir, base);

	struct inode parent_inode = { 0 };

	if (get_node_by_path(dir, ROOT_INO, &parent_inode) < 0) {
		free(base);
		free(dir);

		return -ENOENT;
	}

	if (parent_inode.valid == 0) {
		free(base);
		free(dir);

		return -ENOENT;
	}

	struct inode target_inode = { 0 };

	if (get_node_by_path(target, ROOT_INO, &target_inode) < 0) {
		return -ENOENT;
	}

	if (dir_add(&parent_inode, target_inode.ino, base, strlen(base)) < 0) {
		perror("Cannot add entry to directory");

		return -1;
	}

	// free(base);
	// free(dir);

	printf("[myfs_link] Done.\n");

	return 0;
}

static int myfs_readlink(const char* link, char* buffer, size_t len) {
	assert(link != NULL);
	assert(buffer != NULL);
	assert(len > 0);

	printf("[myfs_readlink] link: %s | len: %zu\n", link, len);

	struct inode link_inode = { 0 };

	if (get_node_by_path(link, ROOT_INO, &link_inode) < 0) {
		return -ENOENT;
	}

	assert(link_inode.directs[0] >= 0);

	char* blk_buffer = (char*)malloc(BLOCK_SIZE);

	if (blk_buffer == NULL) {
		perror("Cannot allocate memory");

		return -ENOSPC;
	}

	if (block_read(link_inode.directs[0], blk_buffer) < 0) {
		perror("Cannot read block");

		return -1;
	}

	memcpy(buffer, blk_buffer, len);

	free(blk_buffer);

	printf("[myfs_readlink] Done.\n");

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
	.symlink = myfs_symlink,
	.link = myfs_link,
	.readlink = myfs_readlink,
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
