#define FUSE_USE_VERSION 30
#define _GNU_SOURCE

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
#include <stdbool.h>

// Provide some simple file path extractions such as basename, filename, etc
#include <libgen.h>

#include <linux/limits.h>
#include <assert.h>

#include "block.h"
#include "myfs.h"

#define HAVE_UTIMESAT

#define ARRAY_FILL(arr, value, len) \
	for (size_t i = 0; i < len; ++i) \
		(arr)[i] = (value)

#define PERM_CAN_READ(perm) (perm & 4)
#define PERM_CAN_WRITE(perm) (perm & 2)
#define PERM_CAN_EXECUTE(perm) (perm & 1)

char diskfile_path[PATH_MAX];

struct superblock* superblock = NULL;
int ROOT_INO = 0;
bool SUPERBLOCK_EXISTED = false;

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

		return -ENOSPC;
	}

	for (int i = 0; i < inode_bitmap_blocks; ++i) {
		if (block_read(superblock->i_bitmap_blk + i, bitmap) < 0) {
			perror("Cannot read block");

			free(bitmap);

			return -EIO;
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

					return -EIO;
				}

				printf("\tSaved to block %d\n", superblock->i_bitmap_blk + i);

				// Update superblock stat
				superblock->free_ino_count--;

				if (block_write(SUPERBLOCK_BLK_NUM, superblock) < 0) {
					perror("Cannot write block");

					free(bitmap);

					return -EIO;
				}

				printf("\tUpdated superblock count of free inode. Total free inode: %d\n", superblock->free_ino_count);

				free(bitmap);

				printf("[get_avail_ino] Done.\n\n");

				return j;
			}
		}
	}

	free(bitmap);

	printf("[get_avail_ino] Done.\n\n");

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

	printf("\tReading %d blocks (%d bits) of data bitmap\n", data_bitmap_blocks, num_bits_per_blocks);

	bitmap_t bitmap = (bitmap_t)malloc(BLOCK_SIZE);

	if (bitmap == NULL) {
		perror("Cannot allocate memory");

		return -ENOSPC;
	}

	for (int i = 0; i < data_bitmap_blocks; ++i) {
		if (block_read(superblock->d_bitmap_blk + i, bitmap) < 0) {
			perror("Cannot read block");

			free(bitmap);

			return -EIO;
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

					return -EIO;
				}

				printf("\tSaved to block %d\n", superblock->d_bitmap_blk + i);

				superblock->free_blk_count--;

				if (block_write(SUPERBLOCK_BLK_NUM, superblock) < 0) {
					perror("Cannot write block");

					free(bitmap);

					return -EIO;
				}

				printf("\tUpdated superblock count of free data blocks. Total free data blocks: %d\n", superblock->free_blk_count);

				printf("\tReturn data block [%d]\n", j + superblock->d_start_blk);

				printf("[get_avail_blkno] Done.\n\n");

				free(bitmap);

				return j + superblock->d_start_blk;
			}
		}
	}

	free(bitmap);

	printf("[get_avail_blkno] Done.\n\n");

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

	if (bitmap == NULL) {
		return -ENOSPC;
	}

	printf("\tReading and updating bitmap from block %d at bit index %d\n", block, bit_idx);

	if (block_read(block, bitmap) < 0) {
		perror("Cannot read block");

		return -EIO;
	}

	set_bitmap(bitmap, bit_idx);

	if (block_write(block, bitmap) < 0) {
		perror("Cannot write block");

		return -EIO;
	}

	superblock->free_ino_count++;

	if (block_write(SUPERBLOCK_BLK_NUM, superblock) < 0) {
		perror("Cannot write block");

		free(bitmap);

		return -EIO;
	}

	printf("\tUpdated superblock count of free inode. Total free inodes: %d\n", superblock->free_ino_count);

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

	if (bitmap == NULL) {
		return -ENOSPC;
	}
	
	printf("\tReading and updating bitmap from block %d at bit index %d\n", block, bit_idx);

	if (block_read(block, bitmap) < 0) {
		perror("Cannot read block");

		return -EIO;
	}

	set_bitmap(bitmap, bit_idx);

	if (block_write(block, bitmap) < 0) {
		perror("Cannot write block");

		return -EIO;
	}

	superblock->free_blk_count++;

	if (block_write(SUPERBLOCK_BLK_NUM, superblock) < 0) {
		perror("Cannot write block");

		free(bitmap);

		return -EIO;
	}

	printf("\tUpdated superblock count of free data blocks. Total free data blocks: %d\n", superblock->free_blk_count);

	printf("[reset_data_block] Done.\n\n");

	return 0;
}

mode_t get_user_perm(mode_t mode) {
	return (mode >> 6) & 7;
}

mode_t get_group_perm(mode_t mode) {
	return (mode >> 3) & 7;
}

mode_t get_other_perm(mode_t mode) {
	return mode & 7;
}

mode_t get_perm_by_inode(uid_t uid, gid_t gid, const struct inode* inode) {
	assert(inode != NULL);

	mode_t perm;

	if (uid == inode->uid) {
		perm = get_user_perm(inode->mode);
	} else if (gid == inode->gid) {
		perm = get_group_perm(inode->mode);
	} else {
		perm = get_other_perm(inode->mode);
	}

	return perm;
}

/**
 * Read inode info given inode number
 */
int read_inode(uint16_t ino, struct inode* inode) {
	printf("[read_inode] ino: %d\n", ino);

	assert(inode != NULL);
	assert(superblock != NULL);
	assert(ino < superblock->max_inum);

	uint32_t inodes_per_block = BLOCK_SIZE / sizeof(struct inode);
	uint32_t block_index = ino / inodes_per_block;
	uint32_t inode_index = ino % inodes_per_block;
	uint32_t offset = superblock->i_start_blk;

	printf("\tRead from block %d at index %d, offset: %d\n", block_index + offset, inode_index, offset);

	struct inode* inode_table = (struct inode*)malloc(BLOCK_SIZE);
	
	if (inode_table == NULL) {
		perror("Cannot allocate memory");

		return -ENOSPC;
	}

	if (block_read(block_index + offset, inode_table) < 0) {
		perror("Cannot read block");

		free(inode_table);

		return -EIO;
	}

	memcpy(inode, inode_table + inode_index, sizeof(struct inode));
	
	free(inode_table);

	printf("\tRead from inode table of ino: %d\n", inode->ino);

	printf("[read_inode] Done.\n\n");

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

	uint32_t inodes_per_block = BLOCK_SIZE / sizeof(struct inode);
	uint32_t block_index = ino / inodes_per_block;
	uint32_t inode_index = ino % inodes_per_block;
	uint32_t offset = superblock->i_start_blk;
	
	printf("\tRead from block %d at index %d, offset: %d\n", superblock->i_start_blk + block_index, inode_index, offset);

	struct inode* inode_table = (struct inode*)malloc(BLOCK_SIZE);

	if (inode_table == NULL) {
		perror("Cannot allocate memory");

		return -ENOSPC;
	}

	printf("\tReading block %d\n", block_index + offset);

	if (block_read(block_index + offset, inode_table) < 0) {
		perror("Cannot read block");
	
		free(inode_table);

		return -EIO;
	}

	// Update ctime
	inode->ctime = now();

	memcpy(inode_table + inode_index, inode, sizeof(struct inode));

	printf("\tCopied inode\n");

	if (block_write(block_index + offset, inode_table) < 0) {
		perror("Cannot write block");

		free(inode_table);

		return -EIO;
	}

	printf("\tWrote block\n");
	
	free(inode_table);

	printf("[write_inode] Done.\n\n");

	return 0;
}

struct inode make_inode(uint16_t ino, uint16_t container_ino, uint32_t type, mode_t mode, int nlink, uid_t uid, gid_t gid) {
	assert(superblock != NULL);
	assert(ino < superblock->max_inum);
	assert(container_ino < superblock->max_inum);
	
	// For now, just accept dir or regular file or symlink
	// assert(type == S_IFDIR || type == __S_IFREG || type == __S_IFLNK);
	assert(nlink >= 0);

	struct inode node;

	node.ino = ino;
	node.container_ino = container_ino;
	node.valid = 1;
	node.size = 0;
	node.type = type;
	node.mode = type | mode;
	node.nlink = nlink;

	node.atime = now();
	node.mtime = now();
	node.ctime = now();

	node.uid = uid;
	node.gid = gid;

	ARRAY_FILL(node.directs, -1, DIRECT_PTRS_COUNT);
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

		return -ENOENT;
	}

	printf("\tRead inode [%d]\n", ino);

	int num_entries_per_block = BLOCK_SIZE / sizeof(struct dirent);
	
	int total_dirents = dir_inode.size / sizeof(struct dirent);

	printf("\tNum entries per block: %d | Total: %d\n", num_entries_per_block, total_dirents);

	struct dirent* buffer = (struct dirent*)malloc(BLOCK_SIZE);

	if (buffer == NULL) {
		perror("Cannot allocate memory");

		return -ENOSPC;
	}	

	// int total_dirents_read = 0;

	for (int i = 0; i < DIRECT_PTRS_COUNT; ++i) {
		// if (total_dirents_read == total_dirents) break;

		if (dir_inode.directs[i] < 0) continue;

		if (block_read(dir_inode.directs[i], buffer) < 0) {
			perror("Cannot read block");
			
			free(buffer);

			return -EIO;
		}

		for (int j = 0; j < num_entries_per_block; ++j) {
			// if (total_dirents_read == total_dirents) break;

			printf("\t\tChecking item[%d]: %s at block %d\n", j, buffer[j].name, dir_inode.directs[i]);

			if (buffer[j].valid == 1 && strncmp(buffer[j].name, fname, name_len) == 0) {
				printf("\t\tFound item\n");

				if (dirent != NULL) {
					memcpy(dirent, &buffer[j], sizeof(struct dirent));
				}

				free(buffer);

				printf("[dir_find] Done.\n\n");

				return 0;
			}

			// total_dirents_read++;
		}
	}

	free(buffer);

	printf("[dir_find] Done.\n\n");

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

		return -ENOENT;
	}
	
	struct dirent* buffer = (struct dirent*)malloc(BLOCK_SIZE);

	if (buffer == NULL) {
		perror("Cannot allocate memory");

		return -ENOSPC;
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

			return -EIO;
		}

		for (int i = 0; i < num_dirents_per_block; ++i) {			
			printf("\tChecking spot %d (valid=%d) at block %d\n", i, buffer[i].valid, dir_inode->directs[block_idx]);

			if (buffer[i].valid == 0) {
				printf("\tFound a free spot at %d at block %d\n", i, dir_inode->directs[block_idx]);

				// Valid free spot
				buffer[i].ino = f_ino;
				buffer[i].valid = 1;

				if (name_len > NAME_MAX) name_len = NAME_MAX - 1;
				strncpy(buffer[i].name, fname, name_len);
				buffer[i].name[name_len] = '\0';
				buffer[i].len = name_len;

				printf("\tItem name: %s\n", buffer[i].name);
				// printf("\t\tDump: ");
				// dump_str(buffer[i].name, name_len + 1);

				if (block_write(dir_inode->directs[block_idx], buffer) < 0) {
					perror("Cannot write block");
					
					free(buffer);

					return -EIO;
				}
				
				// Update size
				dir_inode->size += sizeof(struct dirent);

				// Update mtime
				dir_inode->mtime = now();
				
				printf("\tUpdated parent dir size to: %u\n", dir_inode->size);

				// num nlink of dir = 2 + num sub directories
				if (f_inode.type == S_IFDIR && f_inode.ino != dir_inode->ino) {
					dir_inode->nlink++;
				}

				printf("\tUpdated parent dir %d nlink to %d\n", dir_inode->ino, dir_inode->nlink);

				if (write_inode(dir_inode->ino, dir_inode) < 0) {
					perror("Cannot write inode");

					free(buffer);

					return -EIO;
				}
				
				// Update link count of target ino
				// To prevent dir_add adding itself
				if (f_ino != dir_inode->ino) {
					f_inode.nlink++;

					if (write_inode(f_ino, &f_inode) == -1) {
						perror("Cannot write inode");

						free(buffer);

						return -EIO;
					}

					printf("\tUpdated entry ino: %d nlink to %d\n", f_inode.ino, f_inode.nlink);
				}

				free(buffer);

				printf("[dir_add] Done.\n\n");

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

	if (name_len > NAME_MAX) name_len = NAME_MAX - 1; 
	strncpy(buffer[0].name, fname, name_len);
	buffer[0].name[name_len] = '\0';
	buffer[0].len = name_len;

	printf("\tItem name: %s\n", buffer[0].name);
	// printf("\t\tDump: ");
	// dump_str(buffer[0].name, name_len + 1);

	if (block_write(data_block_idx, buffer) < 0) {
		perror("Cannot write data block");

		return -EIO;
	}

	// Update size
	dir_inode->size += sizeof(struct dirent);

	// Update mtime
	dir_inode->mtime = now();

	printf("\tUpdated dir size to: %u\n", dir_inode->size);

	// num nlink of dir = 2 + num sub directories
	if (f_inode.type == S_IFDIR) {
		dir_inode->nlink++;
	}

	printf("\tUpdated parent dir %d nlink to %d\n", dir_inode->ino, dir_inode->nlink);

	if (write_inode(dir_inode->ino, dir_inode) < 0) {
		perror("Cannot write inode");

		free(buffer);

		return -EIO;
	}

	printf("\tWrote parent inode update\n");

	// Update link count of target ino
	if (f_ino != dir_inode->ino) {
		printf("\tf_ino = %d | dir ino = %d\n", f_ino, dir_inode->ino);

		f_inode.nlink++;

		if (write_inode(f_ino, &f_inode) == -1) {
			perror("Cannot write inode");

			free(buffer);

			return -EIO;
		}

		printf("\tUpdated entry ino: %d nlink to %d\n", f_inode.ino, f_inode.nlink);
	}

	free(buffer);

	printf("[dir_add] Done.\n\n");

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

	// int entries_read = 0;

	struct dirent* buffer = (struct dirent*)malloc(BLOCK_SIZE);

	if (buffer == NULL) {
		perror("Cannot allocate memory");

		return -ENOSPC;
	}

	for (int i = 0; i < DIRECT_PTRS_COUNT; ++i) {
		// if (entries_read == num_entry) break;

		if (dir_inode->directs[i] < 0) continue;

		if (block_read(dir_inode->directs[i], buffer) < 0) {
			perror("Cannot read block");
			
			free(buffer);

			return -EIO;
		}

		for (int j = 0; j < num_entries_per_block; ++j) {
			// if (entries_read == num_entry) break;

			if (buffer[j].valid == 1 && buffer[j].ino == entry_inode->ino) {
				buffer[j].valid = 0; // mark as invalid or free slot
				buffer[j].name[0] = '\0';

				if (block_write(dir_inode->directs[i], buffer) < 0) {
					perror("Cannot write block");

					free(buffer);

					return -EIO;
				}

				dir_inode->size -= sizeof(struct dirent);

				dir_inode->mtime = now();

				printf("\tUpdated size of dir: %u\n", dir_inode->size);

				if (entry_inode->type == S_IFDIR) {
					dir_inode->nlink--;
				}

				printf("\tUpdated parent ino %d nlink to %d\n", dir_inode->ino, dir_inode->nlink);

				if (write_inode(dir_inode->ino, dir_inode) < 0) {
					perror("Cannot write inode");

					free(buffer);

					return -EIO;
				}

				// Update nlink of target inode
				entry_inode->nlink--;

				if (write_inode(entry_inode->ino, entry_inode) < 0) {
					perror("Cannot write inode");

					return -EIO;
				}

				printf("\tUpdated nlink of target ino: %d to be = %d\n", entry_inode->ino, entry_inode->nlink);

				printf("[dir_remove] Done.\n\n");

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

	struct fuse_context* ctx = fuse_get_context();

	assert(ctx != NULL);

	uid_t uid = ctx->uid;
	gid_t gid = ctx->gid;
	
	mode_t perm;

	if (strcmp(path, "/") == 0) {
		// Check if user has permission to access root

		// Does not exist
		if (read_inode(ROOT_INO, inode) < 0) {
			perror("Cannot read inode");

			return -ENOENT;
		}

		if (uid == inode->uid) {
			perm = get_user_perm(inode->mode);
		} else if (gid == inode->gid) {
			perm = get_group_perm(inode->mode);
		} else {
			perm = get_other_perm(inode->mode);
		}

		// Check if perm has "execute" permission
		if (!PERM_CAN_EXECUTE(perm)) {
			return -EACCES;
		}

		return 0;
	}
	
	struct inode current = { 0 };

	if (read_inode(ino, &current) < 0) {
		perror("Cannot read inode");

		return -ENOENT;
	}
	
	if (current.valid == 0) {
		return -ENOENT; // root inode is not valid
	}

	char* path_clone = strdup(path);
	char* token = strtok(path_clone, "/");
	
	struct dirent dir_entry = { 0 };
	
	while (token) {
		// Check if current is dir
		if (current.type != S_IFDIR) {
			return -ENOTDIR;
		}

		// Check permission
		printf("\tToken: %s | Perm: %05o\n", token, current.mode);

		if (uid == current.uid) {
			perm = get_user_perm(current.mode);
		} else if (gid == current.gid) {
			perm = get_group_perm(current.mode);
		} else {
			perm = get_group_perm(current.mode);
		}

		// Check if perm has "execute" permission
		if (!PERM_CAN_EXECUTE(perm)) {
			free(path_clone);

			return -EACCES;
		}

		if (strlen(token) > NAME_MAX) {
			free(path_clone);

			return -ENAMETOOLONG;
		}
		
		// Find the token in the current directory's inode
		if (dir_find(current.ino, token, strlen(token), &dir_entry) < 0) {
			// Token not found
			perror("[get_node_by_path] Item not found!");
			
			free(path_clone);

			return -ENOENT;
		}

		printf("\tDir entry ino: %d\n", dir_entry.ino);

		// Read inode of the token, then move current to token's inode
		// a.k.a walking toward to target
		if (read_inode(dir_entry.ino, &current) < 0) {
			// Unable to read inode struct
			free(path_clone);

			return -ENOENT;
		}

		// Move to the next token
		token = strtok(NULL, "/");
	}

	// Copy current inode to output inode
	memcpy(inode, &current, sizeof(struct inode));

	free(path_clone);
		
	return 0;
}

int make_file(const char* path, mode_t mode, struct inode* out_inode) {
	assert(path != NULL);
	assert(out_inode != NULL);
	assert(ROOT_INO >= 0);

	printf("[make_file] path: %s | mode: %o\n", path, mode);

	char* tmp1, *tmp2;

	tmp1 = strdup(path);
	tmp2 = strdup(path);

	if (tmp1 == NULL || tmp2 == NULL) {
		perror("Cannot allocate memory");

		if (tmp1) free(tmp1);
		if (tmp2) free(tmp2);

		return -ENOSPC;
	}	

	char* base = basename(tmp1);
	char* dir = dirname(tmp2);

	if (strlen(base) > NAME_MAX) return -ENAMETOOLONG;

	// if (base == NULL || dir == NULL) {
	// 	perror("Cannot allocate memory");

	// 	if (base) free(base);
	// 	if (dir) free(dir);

	// 	return -ENOSPC;
	// }

	printf("\tDir: %s | Base: %s\n", dir, base);

	// Get parent inode and check if the target file is already exist
	struct inode parent_inode = { 0 };

	int node_res;

	if ((node_res = get_node_by_path(dir, ROOT_INO, &parent_inode)) < 0) {
		free(tmp1);
		free(tmp2);
		
		return node_res;
	}

	if (parent_inode.valid == 0) {
		free(tmp1);
		free(tmp2);

		return -ENOENT;
	}

	// Check if the target file already exists
	if (dir_find(parent_inode.ino, base, strlen(base), NULL) == 0) {
		free(tmp1);
		free(tmp2);

		return -EEXIST;
	}

	// Check if user has permission to write into parent dir
	struct fuse_context* ctx = fuse_get_context();

	assert(ctx != NULL);

	mode_t perm = get_perm_by_inode(ctx->uid, ctx->gid, &parent_inode);

	if (!PERM_CAN_WRITE(perm)) {
		return -EACCES;
	}

	// Get the next available inode number for this file
	int ino = get_avail_ino();

	if (ino < 0) {
		free(tmp1);
		free(tmp2);

		return -ENOSPC;
	}

	if (S_ISFIFO(mode)) {
		*(out_inode) = make_inode(ino, parent_inode.ino, __S_IFIFO, mode, 0, ctx->uid, ctx->gid);
	} else if (S_ISREG(mode)) {
		*(out_inode) = make_inode(ino, parent_inode.ino, __S_IFREG, mode, 0, ctx->uid, ctx->gid);
	} else if (S_ISCHR(mode)) {
		*(out_inode) = make_inode(ino, parent_inode.ino, __S_IFCHR, mode, 0, ctx->uid, ctx->gid);
	} else if (S_ISBLK(mode)) {
		*(out_inode) = make_inode(ino, parent_inode.ino, __S_IFBLK, mode, 0, ctx->uid, ctx->gid);
	} else if (S_ISSOCK(mode)) {
		*(out_inode) = make_inode(ino, parent_inode.ino, __S_IFSOCK, mode, 0, ctx->uid, ctx->gid);
	} else {
		return -EOPNOTSUPP;
	}

	// Update open count
	out_inode->open_count++;

	if (write_inode(ino, out_inode) < 0) {
		perror("Cannot write inode");

		free(tmp1);
		free(tmp2);

		return -EIO;
	}

	printf("\tWrote file inode ino: %d to parent ino: %d\n", ino, parent_inode.ino);

	if (dir_add(&parent_inode, ino, base, strlen(base)) < 0) {
		perror("Cannot add dirent entry");

		free(tmp1);
		free(tmp2);

		return -EIO;
	}

	printf("\tAdded file entry ino: %d to parent ino: %d\n", ino, parent_inode.ino);

	free(tmp1);
	free(tmp2);
	
	printf("[make_file] Done.\n\n");

	return 0;
}

int file_write(struct inode* finode, const char* buffer, size_t size, off_t offset) {
	printf("[file_write] Ino: %d | size: %zu | offset: %u\n", finode->ino, size, offset);

	if (finode->type == S_IFDIR) {
		return -EISDIR;
	} 

	if (finode->valid == 0) {
		return -ENOENT;
	}

	size_t bytes_written = 0;
	off_t current_offset = offset;
	size_t remaining = size;
	
	size_t block_index, block_offset, to_write;
	int writing_blk_num = -1;

	void* block_buffer = malloc(BLOCK_SIZE);

	if (block_buffer == NULL) {
		return -ENOSPC;
	}

	while (remaining > 0) {
		block_index = current_offset / BLOCK_SIZE;
		block_offset = current_offset % BLOCK_SIZE;
		to_write = BLOCK_SIZE - block_offset;

		if (to_write > remaining) to_write = remaining;

		if (block_index < DIRECT_PTRS_COUNT) {
			printf("\tData block inside direct ptrs\n");

			writing_blk_num = finode->directs[block_index];
			
			if (writing_blk_num < 0) {
				printf("\tWriting blk num unallocated\n");

				// Allocate new data block
				writing_blk_num = get_avail_blkno();
	
				if (writing_blk_num < 0) {
					free(block_buffer);

					return bytes_written == 0 ? -ENOSPC : bytes_written;
				}
	
				finode->directs[block_index] = writing_blk_num;

				printf("\tAssigned block %d (th)\n", writing_blk_num);
			}
		} else {
			printf("\tData block in indirect ptr region\n");

			// In indirect region
			int blk_idx = block_index - DIRECT_PTRS_COUNT;
			int num_blks_indirect = BLOCK_SIZE / sizeof(int);

			assert(blk_idx < num_blks_indirect);

			printf("\tBlk idx: %d | num_blks_indirects: %d\n", blk_idx, num_blks_indirect);

			if (finode->indirect_ptr < 0) {
				printf("\tIndirect ptr unallocated\n");

				// Allocate
				int blk = get_avail_blkno();
				
				if (blk < 0) {
					free(block_buffer);

					return bytes_written == 0 ? -ENOSPC : bytes_written;
				}

				printf("\tAssigned block: %d to indirect ptr\n", blk);

				// Initialize
				int* init_buffer = (int*)malloc(BLOCK_SIZE);

				if (init_buffer == NULL) {
					return bytes_written == 0 ? -ENOSPC : bytes_written; 
				}

				// Do not use memset as it will set every individual byte to 1
				// So the next time to read the array as an integer array
				// C will group every 4 bytes to read an int, 0x01010101 is NOT -1
				ARRAY_FILL(init_buffer, -1, num_blks_indirect);
			
				if (block_write(blk, init_buffer) < 0) {
					free(block_buffer);

					return bytes_written == 0 ? -EIO : bytes_written;  
				}

				finode->indirect_ptr = blk;

				free(init_buffer);
			}

			// Read indirect data block
			int* indirect_buffer = (int*)malloc(BLOCK_SIZE);

			if (indirect_buffer == NULL) {
				free(block_buffer);

				return bytes_written == 0 ? -ENOSPC : bytes_written;
			}

			if (block_read(finode->indirect_ptr, indirect_buffer) < 0) {
				free(block_buffer);

				return bytes_written == 0 ? -EIO : bytes_written;
			}

			if (indirect_buffer[blk_idx] == -1) {
				// Allocate
				writing_blk_num = get_avail_blkno();

				printf("\tAllocate block %d of blk_idx %d\n", writing_blk_num, blk_idx);

				if (writing_blk_num < 0) {
					free(block_buffer);

					free(indirect_buffer);

					return bytes_written == 0 ? -ENOSPC : bytes_written;
				}

				indirect_buffer[blk_idx] = writing_blk_num;
			}
		}

		assert(writing_blk_num != -1);

		printf("\tRead from block: %d\n", writing_blk_num);

		if (block_read(writing_blk_num, block_buffer) < 0) {
			free(block_buffer);

			return bytes_written == 0 ? -EIO : bytes_written;
		}

		if (to_write == BLOCK_SIZE) {
			// rewrite the whole block
			memcpy(block_buffer, buffer + bytes_written, to_write);
		} else {
			memcpy((char*)block_buffer + block_offset, buffer + bytes_written, to_write);
		}

		if (block_write(writing_blk_num, block_buffer) < 0) {
			free(block_buffer);

			return bytes_written == 0 ? -EIO : bytes_written;
		}

		printf("\tWrite to block: %d\n", writing_blk_num);

		bytes_written += to_write;
		current_offset += to_write;
		remaining -= to_write;
	}

	// Update file size in inode
	if (offset + bytes_written > finode->size) {
		finode->size = offset + bytes_written;
	}

	// Update time
	finode->mtime = now();

	if (write_inode(finode->ino, finode) < 0) {
		perror("write_inode");

		return bytes_written == 0 ? -EIO : bytes_written;
	}

	free(block_buffer);

	printf("[file_write] Done.\n\n");

	return bytes_written;
}

int file_read(struct inode* finode, const char* buffer, size_t size, off_t offset) {
	if (finode->type == S_IFDIR) {
		return -EISDIR;
	}

	if (finode->valid == 0) {
		return -ENOENT;
	}

	size_t bytes_read = 0;
	off_t current_offset = offset;
	size_t remaining = size;
	
	size_t block_index, block_offset, to_read;
	int reading_blk_num = -1;

	void* block_buffer = malloc(BLOCK_SIZE);

	if (block_buffer == NULL) {
		return -ENOSPC;
	}

	while (remaining > 0) {
		block_index = current_offset / BLOCK_SIZE;
		block_offset = current_offset % BLOCK_SIZE;
		to_read = BLOCK_SIZE - block_offset;

		if (to_read > remaining) to_read = remaining;

		if (block_index < DIRECT_PTRS_COUNT) {
			reading_blk_num = finode->directs[block_index];
		} else {
			// In indirect region
			int blk_idx = block_index - DIRECT_PTRS_COUNT;
			int num_blks_indirect = BLOCK_SIZE / sizeof(int);

			assert(blk_idx < num_blks_indirect);

			if (finode->indirect_ptr >= 0) {
				// Read indirect data block
				int* indirect_buffer = (int*)malloc(BLOCK_SIZE);

				if (indirect_buffer == NULL) {
					free(block_buffer);

					return bytes_read == 0 ? -ENOSPC : bytes_read;
				}

				if (block_read(finode->indirect_ptr, indirect_buffer) < 0) {
					free(block_buffer);
	
					return bytes_read == 0 ? -EIO : bytes_read;
				}

				reading_blk_num = indirect_buffer[blk_idx];
			}
		}

		if (reading_blk_num < 0) {
			// Hole or unallocate data region
			// return 0
			memset(buffer + bytes_read, 0, to_read);
		} else {
			if (block_read(reading_blk_num, block_buffer) < 0) {
				free(block_buffer);
	
				return bytes_read == 0 ? -EIO : bytes_read;
			}

			memcpy(buffer + bytes_read, (char*)block_buffer + block_offset, to_read);
		}

		bytes_read += to_read;
		current_offset += to_read;
		remaining -= to_read;
	}

	// Update time
	finode->atime = now();

	if (write_inode(finode->ino, finode) < 0) {
		perror("write_inode");

		return bytes_read == 0 ? -EIO: bytes_read;
	}

	free(block_buffer);

	return bytes_read;
}

int init_superblock() {	
	assert(superblock == NULL);

	printf("[init_superblock]\n");

	// STORATE FILE FORMAT:
	// | superblock | inode bitmap | data bitmap | inode | data |
	
	superblock = (struct superblock*)malloc(BLOCK_SIZE);

	if (superblock == NULL) {
		perror("Cannot allocate memory");

		return -ENOSPC;
	}

	printf("\tAllocated memory\n");

	printf("\tCheck if the opened file has valid superblock signature\n");

	if (block_read(SUPERBLOCK_BLK_NUM, superblock) < 0) {
		perror("Cannot read block");

		return -EIO;
	}

	if (superblock->magic_num == MAGIC_NUM) {
		SUPERBLOCK_EXISTED = true;

		printf("\tValid superblock found. Storage file has already existed\n");

		printf("[init_superblock] Done.\n\n");

		return 0;
	}

	superblock->magic_num = MAGIC_NUM;
	superblock->max_inum = MAX_INODE_NUM;
	superblock->max_dnum = MAX_DATA_NUM;
	superblock->i_bitmap_blk = 1; // after superblock's block
	superblock->free_blk_count = MAX_DATA_NUM;
	superblock->free_ino_count = MAX_INODE_NUM;

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

		return -EIO;
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

	printf("\tSaving bitmap to %d blocks start from %u (th) block to %u (th) block\n", inode_bitmap_blocks, superblock->i_bitmap_blk, superblock->d_bitmap_blk - 1);

	void* buffer = malloc(BLOCK_SIZE);

	if (buffer == NULL) {
		perror("Cannot allocate memory");

		return -ENOSPC;
	}

	// Set all bits to zero
	memset(buffer, 0, BLOCK_SIZE);

	for (int i = 0; i < inode_bitmap_blocks; ++i) {
		if (block_write(superblock->i_bitmap_blk + i, buffer) < 0) {
			perror("Cannot write block");

			free(buffer);

			return -EIO;
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

	printf("\tSaving bitmap to %d blocks start from %u (th) block to %u (th) block\n", data_bitmap_blocks, superblock->d_bitmap_blk, superblock->i_start_blk - 1);

	void* buffer = malloc(BLOCK_SIZE);

	if (buffer == NULL) {
		perror("Cannot allocate memory");

		return -ENOSPC;
	}

	// Set all bits in the bitmap to zero
	memset(buffer, 0, BLOCK_SIZE);

	for (int i = 0; i < data_bitmap_blocks; ++i) {
		if (block_write(superblock->d_bitmap_blk + i, buffer) < 0) {
			perror("Cannot write block");

			free(buffer);

			return -EIO;
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

	printf("\tSaving inode region to %d blocks start from %u (th) block to %u (th) block\n", inode_blocks, superblock->i_start_blk, superblock->d_start_blk - 1);

	void* buffer = malloc(BLOCK_SIZE);

	if (buffer == NULL) {
		perror("Cannot allocate memory");

		return -ENOSPC;
	}

	memset(buffer, 0, BLOCK_SIZE);

	for (int i = 0; i < inode_blocks; ++i) {
		if (block_write(superblock->i_start_blk + i, buffer) < 0) {
			perror("Cannot write block");

			free(buffer);

			return -EIO;
		}
	}

	printf("\tSaved inode to %d blocks\n", inode_blocks);

	printf("\tSaving root inode...\n");

	ROOT_INO = get_avail_ino();

	if (ROOT_INO < 0) {
		perror("Cannot set root ino");

		free(buffer);

		return -ENOSPC;
	}

	struct fuse_context* ctx = fuse_get_context();

	assert(ctx != NULL);

	struct inode root_inode = make_inode(ROOT_INO, ROOT_INO, S_IFDIR, 0755, 0, ctx->uid, ctx->gid);

	if (write_inode(ROOT_INO, &root_inode) < 0) {
		perror("Cannot write inode");

		free(buffer);

		return -EIO;
	}

	printf("\tSaved root inode\n");

	if (dir_add(&root_inode, ROOT_INO, ".", 1) < 0) {
		perror("Cannot add entry to root inode");

		free(buffer);

		return -EIO;
	}

	struct inode test_root_inode = { 0 };
	
	if (read_inode(ROOT_INO, &test_root_inode) < 0) {
		free(buffer);

		return -ENOENT;
	}

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

	if (!SUPERBLOCK_EXISTED) {
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
	}

	printf("[myfs_mkfs] Done.\n\n");

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

	printf("[myfs_destroy] Done.\n\n");
}

static int myfs_getattr(const char* path, struct stat *st_buf, struct fuse_file_info *fi) {
	printf("[myfs_getattr] path: %s\n", path);

	assert(path != NULL);
	assert(ROOT_INO >= 0);

	struct inode finode = { 0 };
	
	int node_res;
	
	if ((node_res = get_node_by_path(path, ROOT_INO, &finode)) < 0) {
		return node_res;
	}
	
	if (finode.valid == 0) {
		return -ENOENT;
	}

	st_buf->st_ino = finode.ino;
	st_buf->st_size = finode.size;
	st_buf->st_nlink = finode.nlink;
   	st_buf->st_mode = finode.mode;
	st_buf->st_uid = finode.uid;
	st_buf->st_gid = finode.gid;
	st_buf->st_atim = finode.atime;
	st_buf->st_mtim = finode.mtime;
	st_buf->st_ctim = finode.ctime;

	printf("\tPath: %s | Mode: %05o\n", path, finode.mode & 07777);

	printf("[myfs_getattr] Done.\n\n");

	return 0;
}

static int myfs_opendir(const char* path, struct fuse_file_info *fi) {
	printf("[myfs_opendir] path: %s\n", path);

	assert(ROOT_INO >= 0);

	struct inode dir_inode = { 0 };

	int node_res;

	if ((node_res = get_node_by_path(path, ROOT_INO, &dir_inode)) < 0) {
		return node_res;
	}

	if (dir_inode.valid == 0) {
		return -ENOENT;
	}

	struct fuse_context *ctx = fuse_get_context();

	assert(ctx != NULL);

	uid_t uid = ctx->uid;
	gid_t gid = ctx->gid;

	// Check permissions to open the file
	int access_mode = fi->flags & O_ACCMODE;
	int need_read = (access_mode == O_RDONLY || access_mode == O_RDWR);
	int need_write = (access_mode == O_WRONLY || access_mode == O_RDWR);

	// Extract permissions from inode
	mode_t perm = get_perm_by_inode(uid, gid, &dir_inode);

	// Check permission bit
	if (need_read && !PERM_CAN_READ(perm)) {
		return -EACCES;
	}

	if (need_write && !PERM_CAN_WRITE(perm)) {
		return -EACCES;
	}

	dir_inode.open_count++;

	if (write_inode(dir_inode.ino, &dir_inode) < 0) {
		perror("Cannot write inode");

		return -EIO;
	}

	printf("\tIno: %d -- open counts = %u\n", dir_inode.ino, dir_inode.open_count);

	// Save inode number of this dir into *fh struct of fuse_file_info
	struct file_handler* fh = malloc(sizeof(*fh));

	fh->ino = dir_inode.ino;
	fh->flags = fi->flags;

	fi->fh = (uint64_t)fh;

	printf("[myfs_opendir] Done.\n\n");

	return 0;
}

static int myfs_readdir(const char* path, void* buffer, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info *fi, enum fuse_readdir_flags flags) {
	printf("[myfs_readdir] path: %s\n", path);

	assert(path != NULL);

	// Check if inode is cached with opendir
	if (fi->fh == 0) {
		perror("opendir is not called prior to this function call");
		return -EPERM;
	}

	struct file_handler* fh = (struct file_handler*)fi->fh;

	assert(fh != NULL);

	struct inode dir_inode = { 0 };

	if (read_inode(fh->ino, &dir_inode) < 0) {
		perror("Cannot read inode");

		return -ENOENT;
	}

	if (dir_inode.valid == 0) {
		perror("Dir is not valid");
		return -ENOENT;
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

			return -EIO;
		}

		for (int i = 0; i < num_dirent_per_block && i < total_dirent; ++i) {
			if (total_dirent_read == total_dirent) break;
			
			entry = block_buffer[i];

			// printf("\t\tDump: ");
			// dump_str(entry.name, entry.len + 1);

			if (entry.valid == 1) {
				printf("\tItem[%d]: %s\n", i, entry.name);

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

	printf("[myfs_readdir] Done.\n\n");

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

	char *dir = dirname(tmp1);
	char *base = basename(tmp2);

	// if (dir == NULL || base == NULL) {
	// 	perror("Unable to extract base or dir name due to space");

	// 	if (dir) free(dir);
	// 	if (base) free(base);

	// 	return -ENOSPC;
	// }

	printf("\tDir %s | Base: %s\n", dir, base);

	struct inode parent_inode = { 0 };

	int node_res;

	if ((node_res = get_node_by_path(dir, ROOT_INO, &parent_inode)) < 0) {
		return node_res;
	}

	if (parent_inode.valid == 0) {
		free(tmp1);
		free(tmp2);

		return -ENOENT;
	}
	
	// Check if the target directory already exists
	if (dir_find(parent_inode.ino, base, strlen(base), NULL) == 0) {
		free(tmp1);
		free(tmp2);

		return -EEXIST;
	}

	// Check if user has write permission
	struct fuse_context* ctx = fuse_get_context();

	assert(ctx != NULL);

	mode_t perm = get_perm_by_inode(ctx->uid, ctx->gid, &parent_inode);

	if (!PERM_CAN_WRITE(perm)) {
		return -EACCES;
	}

	// Get next available inode number for this new directory
	int ino = get_avail_ino();

	if (ino < 0) {
		free(tmp1);
		free(tmp2);

		return -ENOSPC;
	}

	struct inode new_dir_inode = make_inode(ino, parent_inode.ino, S_IFDIR, mode, 0, ctx->uid, ctx->gid);

	if (write_inode(ino, &new_dir_inode) < 0) {
		perror("Cannot write inode");

		free(tmp1);
		free(tmp2);

		return -EIO;
	}

	printf("\tWrote new dir inode\n");
	
	if (dir_add(&new_dir_inode, ino, ".", 1) < 0) {
		perror("Cannot add dirent");

		return -EIO;
	}

	printf("\tWrote '.' entry to new dir inode\n");
	
	if (dir_add(&new_dir_inode, parent_inode.ino, "..", 2) < 0) {
		perror("Cannot add dirent");

		return -EIO;
	}

	printf("\tWrote '..' entry to new dir inode\n");
	
	if (dir_add(&parent_inode, ino, base, strlen(base)) < 0) {
		perror("Cannot add dirent");

		return -EIO;
	}

	printf("\tWrote dir entry to parent dir inode\n");
	
	free(tmp1);
	free(tmp2);

	printf("[myfs_mkdir] Done.\n\n");

	return 0;
}

static int myfs_create(const char* path, mode_t mode, struct fuse_file_info* fi) {
	printf("[myfs_create] path: %s | mode: %o\n", path, mode);

	assert(path != NULL);

	struct inode file_inode = { 0 };

	int res = make_file(path, mode, &file_inode);

	if (res < 0) return res;
	
	// Save inode into cache for later use
	struct file_handler* fh = malloc(sizeof(*fh));

	if (fh == NULL) return -ENOSPC;

	fh->ino = file_inode.ino;
	fh->flags = fi->flags;

	fi->fh = (uint64_t)fh;

	printf("[myfs_create] Done.\n\n");
	
	return 0;
}

static int myfs_open(const char* path, struct fuse_file_info *fi) {
	printf("[myfs_open] path: %s\n", path);

	assert(path != NULL);
	assert(ROOT_INO >= 0);

	struct inode finode = { 0 };

	int node_res;

	if ((node_res = get_node_by_path(path, ROOT_INO, &finode)) < 0) {
		return node_res;
	}

	if (finode.valid == 0) {
		return -ENOENT;
	}

	struct fuse_context *ctx = fuse_get_context();

	assert(ctx != NULL);

	uid_t uid = ctx->uid;
	gid_t gid = ctx->gid;

	// Check permissions to open the file
	int access_mode = fi->flags & O_ACCMODE;
	int need_read = (access_mode == O_RDONLY || access_mode == O_RDWR);
	int need_write = (access_mode == O_WRONLY || access_mode == O_RDWR);

	// Extract permissions from inode
	mode_t perm = get_perm_by_inode(uid, gid, &finode);

	// Check permission bit
	if (need_read && (perm & 4) == 0) {
		return -EACCES;
	}

	if (need_write && (perm & 2) == 0) {
		return -EACCES;
	}

	// Update open count
	finode.open_count++;

	if (write_inode(finode.ino, &finode) < 0) {
		perror("Cannot write inode");

		return -EIO;
	}

	printf("\tIno: %d -- open counts = %u\n", finode.ino, finode.open_count);

	struct file_handler* fh = malloc(sizeof(*fh));

	if (fh == NULL) return -ENOSPC;

	fh->ino = finode.ino;
	fh->flags = fi->flags;

	fi->fh = (uint64_t)fh;

	printf("[myfs_open] Done.\n\n");

	return 0;
}

static int myfs_read(const char* path, char* buffer, size_t size, off_t offset, struct fuse_file_info* fi) {
	printf("[myfs_read] path: %s | size: %zu | offset: %ld\n", path, size, offset);

	assert(path != NULL);
	assert(size > 0);
	assert(offset >= 0);

	struct inode finode = { 0 };

	if (fi->fh == 0) {
		perror("Call open() before this operation");

		return -EPERM;
	}

	struct file_handler* fh = (struct file_handler*)fi->fh;

	assert(fh != NULL);

	printf("\tFH ino: %d\n", fh->ino);

	if (read_inode(fh->ino, &finode) < 0) {
		perror("Cannot read inode");

		return -ENOENT;
	}

	printf("\tRead inode with ino: %ld\n", fh->ino);

	if (finode.type != __S_IFREG) {
		perror("Not a file");

		return -EISDIR;
	}

	if (finode.valid == 0) {
		perror("File is not valid");

		return -ENOENT;
	}

	printf("\tReading file (%zu) of size: %u | offset: %ld\n", finode.size, size, offset);

	int res;

	if ((res = file_read(&finode, buffer, size, offset)) < 0) {
		return res;
	}

	printf("\tBytes read: %zu\n", res);

	printf("[myfs_read] Done.\n\n");

	return res;
}

static int myfs_write(const char* path, const char* buffer, size_t size, off_t offset, struct fuse_file_info* fi) {
	printf("[myfs_write] path: %s | size: %zu | offset: %ld\n", path, size, offset);

	assert(path != NULL);
	assert(size > 0);
	assert(offset >= 0);

	struct inode finode = { 0 };

	if (fi->fh == 0) {
		perror("Call open() before this operation");

		return -EPERM;
	}

	struct file_handler* fh = (struct file_handler*)fi->fh;

	assert(fh != NULL);

	printf("\tFH ino: %d\n", fh->ino);

	if (read_inode(fh->ino, &finode) < 0) {
		perror("Cannot read inode");

		return -ENOENT;
	}

	printf("\tRead inode with ino: %ld\n", fh->ino);

	if (finode.type != __S_IFREG) {
		perror("Not a file");

		return -EISDIR;
	}

	if (finode.valid == 0) {
		perror("File is not valid");

		return -ENOENT;
	}

	int res = 0;

	if ((res = file_write(&finode, buffer, size, (fi->flags & O_APPEND != 0) ? finode.size : offset)) < 0) {
		return res;
	}

	printf("\tByte written: %zu\n", res);

	printf("[myfs_write] Done.\n\n");

	return res;
}

static off_t myfs_lseek(const char* path, off_t off, int whence, struct fuse_file_info *fi) {
	return -ENOTSUP;
}

static int myfs_fsync(const char* path, int datasync, struct fuse_file_info* fi) {
	return dev_fsync();
}

static int myfs_rename(const char* old_path, const char* new_path, unsigned int flag) {
	assert(old_path != NULL);
	assert(new_path != NULL);
	assert(ROOT_INO != -1);

	printf("[myfs_rename] old path: %s | new path : %s | flags = %u\n", old_path, new_path, flag);

	struct inode old = { 0 };
	struct inode old_dir = { 0 };

	int node_res;

	if ((node_res = get_node_by_path(old_path, ROOT_INO, &old)) < 0) {
		return node_res;
	}

	if (read_inode(old.container_ino, &old_dir) < 0) {
		perror("Cannot read inode");

		return -ENOENT;
	}

	if (flag != 0) {
		return -EOPNOTSUPP;
	}

	char* tmp1 = strdup(new_path);
	char* tmp2 = strdup(new_path);

	if (tmp1 == NULL || tmp2 == NULL) {
		perror("Cannot allocate memory");

		if (tmp1) free(tmp1);
		if (tmp2) free(tmp2);

		return -ENOSPC;
	}

	char* base = basename(tmp1);
	char* dir = dirname(tmp2);

	// if (base == NULL || dir == NULL) {
	// 	perror("Cannot allocate memory");

	// 	if (base) free(base);
	// 	if (dir) free(dir);

	// 	return -ENOSPC;
	// }

	if (strcmp(base, "") == 0) {
		perror("Cannot rename - target has no specified name");

		free(tmp1);
		free(tmp2);

		return -EINVAL;
	}

	printf("\t New path: %s does not exist => dir: %s | base: %s\n", old, dir, base);

	// Check if new_path already exists
	struct inode new = { 0 };

	if ((node_res = get_node_by_path(new_path, ROOT_INO, &new)) < 0) {
		if (node_res == -EACCES) {
			free(tmp1);
			free(tmp2);

			return -EACCES;
		}

		// new path does not exist
		// remove old entry
		// and move that entry to b's dir

		// Check if dir exists
		struct inode dir_inode = { 0 };

		if ((node_res = get_node_by_path(dir, ROOT_INO, &dir_inode)) < 0) {
			free(tmp1);
			free(tmp2);
			
			return node_res;
		}

		// Remove entry from old path
		if (dir_remove(&old_dir, &old) < 0) {
			perror("Cannot remove entry");

			free(tmp1);
			free(tmp2);

			return -EIO;
		}

		// Add new entry to new path
		if (dir_add(&dir_inode, old.ino, base, strlen(base)) < 0) {
			perror("Cannot add new entry");

			free(tmp1);
			free(tmp2);

			return -EIO;
		}

		free(tmp1);
		free(tmp2);

		return 0;
	}

	// new path exists
	// remove new's entry
	// make new's entry point to old's inode
	
	// Check if types are compatible
	if ((old.type == S_IFDIR && new.type != S_IFDIR) || (old.type != S_IFDIR && new.type == S_IFDIR)) {
		perror("Cannot rename from a directory to a non-directory entity");

		free(tmp1);
		free(tmp2);

		return -EISDIR;
	}

	struct inode new_dir = { 0 };

	if (read_inode(new.container_ino, &new_dir) < 0) {
		perror("Cannot read inode");

		free(tmp1);
		free(tmp2);

		return -ENOENT;
	}

	// Remove new's entry
	if (dir_remove(&new_dir, &new) < 0) {
		perror("Cannot remove entry");

		free(tmp1);
		free(tmp2);
		
		return -EIO;
	}

	// Create new now point to old's inode but in new's dir
	if (dir_add(&new_dir, old.ino, base, strlen(base)) < 0) {
		perror("Cannot add entry");

		free(tmp1);
		free(tmp2);

		return -EIO;
	}

	// Remove old's entry
	if (dir_remove(&old_dir, &old) < 0) {
		perror("Cannot remove entry");

		free(tmp1);
		free(tmp2);

		return -EIO;
	}

	free(tmp1);
	free(tmp2);

	return 0;
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

	int node_res;

	if ((node_res = get_node_by_path(path, ROOT_INO, &dir_inode)) < 0) {
		return node_res;
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

	printf("\tdir is a valid empty directory\n");

	struct inode parent_inode = { 0 };

	if (read_inode(dir_inode.container_ino, &parent_inode) < 0) {
		perror("Cannot read inode");

		return -ENOENT;
	}

	printf("\tParent inode: %d\n", parent_inode.ino);

	// Check if user has permission on parent dir to remove (write permission)
	struct fuse_context* ctx = fuse_get_context();

	assert(ctx != NULL);

	mode_t perm = get_perm_by_inode(ctx->uid, ctx->gid, &parent_inode);

	if (!PERM_CAN_WRITE(perm)) {
		return -EACCES;
	}

	// If the directory is to be "sticky", then only owner of the entry being deleted or
	// owner of the parent dir of the being deleted entry or root can perform rmdir
	if (parent_inode.mode & S_ISVTX) {
		if (ctx->uid != parent_inode.uid && ctx->uid != dir_inode.uid && ctx->uid != 0) {
			return -EPERM;
		}
	}

	// Remove dir entry from parent
	if (dir_remove(&parent_inode, &dir_inode) < 0) {
		perror("Cannot remove dir entry from parent");

		return -EIO;
	}

	// reset data block if it has any allocated data blocks
	for (int i = 0; i < DIRECT_PTRS_COUNT; ++i) {
		if (dir_inode.directs[i] < 0) continue;;

		if (reset_data_block(dir_inode.directs[i]) < 0) {
			perror("Cannot reset data block");

			return -EIO;
		}
	}

	if (dir_inode.indirect_ptr >= 0) {
		int* buf = (int*)malloc(BLOCK_SIZE);
		int num_blk = BLOCK_SIZE / sizeof(int);

		if (buf == NULL) {
			return -ENOSPC;
		}

		if (block_read(dir_inode.indirect_ptr, buf) < 0) {
			perror("Cannot read block");

			return -EIO;
		}

		for (int i = 0; i < num_blk; ++i) {
			if (buf[i] < 0) continue;

			if (reset_data_block(buf[i]) < 0) {
				perror("Cannot reset data block");

				return -EIO;
			}
		}

		printf("\tReset data block indirects\n");
	}

	if (reset_ino(dir_inode.ino) < 0) {
		perror("Cannot reset inode");

		return -EIO;
	}

	printf("[myfs_rmdir] Done.\n\n");

	return 0;
}

static int myfs_releasedir(const char* path, struct fuse_file_info *fi) {
	printf("[myfs_releasedir] path: %s\n", path);

	assert(path != NULL);
	
	struct inode finode = { 0 };

	if (fi->fh == 0) {
		perror("Call open() before this operation");

		return -EPERM;
	}

	struct file_handler* fh = (struct file_handler*)fi->fh;

	assert(fh != NULL);

	if (read_inode(fh->ino, &finode) < 0) {
		perror("Cannot read inode");

		return -ENOENT;
	}

	printf("\tRead inode with ino: %ld\n", fh->ino);

	// Update open count
	finode.open_count--;

	if (write_inode(finode.ino, &finode) < 0) {
		perror("Cannot write inode");

		return -EIO;
	}

	// Simply remove fi->fh cache
	fi->fh = 0;

	printf("[myfs_releasedir] Done.\n\n");

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

	int node_res;

	if ((node_res = get_node_by_path(path, ROOT_INO, &f_inode)) < 0) {
		return node_res;
	}

	// Check if this is a file or a softlink
	if (f_inode.type == S_IFDIR) {
		return -EISDIR;
	}

	printf("\t File is a valid file to be removed\n");

	struct inode parent_inode = { 0 };

	if (read_inode(f_inode.container_ino, &parent_inode) < 0) {
		perror("Cannot read inode");

		return -ENOENT;
	}

	printf("\tParent inode: %d\n", parent_inode.ino);

	// Remove file entry from parent dir
	if (dir_remove(&parent_inode, &f_inode) < 0) {
		perror("Cannot remove file entry from parent");

		return -234;
	}

	// Check if nlink == 0 && open count == 0
	// If nlink is 0 and open count is 0, remove the file content
	// Simply returns its data blocks back to the file system
	printf("\tIno: %d -- nlink = %u | open count = %u\n", f_inode.nlink, f_inode.open_count);
	
	if (f_inode.nlink <= 0 && f_inode.open_count <= 0) {
		printf("\tFile ino: %d has 0 nlink, remove its data blocks\n", f_inode.ino);

		for (int i = 0; i < DIRECT_PTRS_COUNT; ++i) {
			if (f_inode.directs[i] >= 0) {
				if (reset_data_block(f_inode.directs[i]) < 0) {
					perror("Cannot reset data block");

					return -EIO;
				}
			}
		}

		printf("\tReset data block directs\n");

		if (f_inode.indirect_ptr >= 0) {
			int* buf = (int*)malloc(BLOCK_SIZE);
			int num_blk = BLOCK_SIZE / sizeof(int);

			if (buf == NULL) {
				return -ENOSPC;
			}

			if (block_read(f_inode.indirect_ptr, buf) < 0) {
				perror("Cannot read block");

				return -EIO;
			}

			for (int i = 0; i < num_blk; ++i) {
				if (buf[i] < 0) continue;

				if (reset_data_block(buf[i]) < 0) {
					perror("Cannot reset data block");

					return -EIO;
				}
			}

			printf("\tReset data block indirects\n");
		}

		// reset inode
		if (reset_ino(f_inode.ino) < 0) {
			perror("Cannot reset inode");

			return -EIO;
		}
	}

	printf("[myfs_unlink] Done.\n\n");

	return 0;
}

static int myfs_truncate(const char *path, off_t size, struct fuse_file_info *fi) {
	assert(path != NULL);
	assert(size >= 0);
	assert(ROOT_INO != -1);
	
	printf("[myfs_truncate] path: %s | size: %ld\n", path, size);

	struct inode f_inode = { 0 };

	struct file_handler* fh = NULL;

	if (fi != NULL && fi->fh != 0) {
		fh = (struct file_handler*)fi->fh;

		printf("\tFH ino: %d\n", fh->ino);

		if (read_inode(fh->ino, &f_inode) == -1) {
			return -ENOENT;
		}
	} else {
		int node_res;

		if ((node_res = get_node_by_path(path, ROOT_INO, &f_inode)) < 0) {
			return node_res;
		}
	}

	// If file is opened
	if (fh != NULL) {
		int access_mode = fh->flags & O_ACCMODE;
		bool can_write = (access_mode == O_WRONLY) || (access_mode == O_RDWR);

		printf("\tO_WRONLY: %d | O_RDWR: %d\n", access_mode == O_WRONLY, access_mode == O_RDWR);
		printf("\tCan write if opened: %d\n", can_write);

		if (!can_write) {
			return -EACCES;
		}
	} else {
		struct fuse_context* ctx = fuse_get_context();

		assert(ctx != NULL);

		uid_t uid = ctx->uid;
		gid_t gid = ctx->gid;

		// Check if it has write permission
		mode_t perm;

		if (uid == f_inode.uid) {
			perm = get_user_perm(f_inode.mode);
		} else if (gid == f_inode.gid) {
			perm = get_group_perm(f_inode.mode);
		} else {
			perm = get_other_perm(f_inode.mode);
		}

		if (!PERM_CAN_WRITE(perm)) {
			return -EACCES;
		}
	}

	if (f_inode.type == S_IFDIR) {
		return -EISDIR;
	}

	uint32_t MAX_SIZE = DIRECT_PTRS_COUNT * BLOCK_SIZE + (BLOCK_SIZE / sizeof(int)) * BLOCK_SIZE;

	if (size >= MAX_SIZE) return -EFBIG;

	if (f_inode.size == size) {
		printf("\tFile size equals to requested size. Do nothing\n");

		// Do nothing, only update timestamp
		f_inode.atime = now();

		if (write_inode(f_inode.ino, &f_inode) == -1) {
			perror("Cannot write inode");

			return -EIO;
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

			return -EIO;
		}

		printf("[myfs_truncate] Done.\n\n");

		return 0;
	}

	printf("\tShrinking file size of %d to %d (removing %d)\n", f_inode.size, size, f_inode.size - size);

	// Shrink
	int start_removed_blk_offset = size % BLOCK_SIZE;
	int start_removed_blk_idx = size / BLOCK_SIZE;
	int end_removed_blk_idx = f_inode.size / BLOCK_SIZE;

	// If offset is 0, it means we gonna include removing the start block
	start_removed_blk_idx = (start_removed_blk_offset == 0) ? start_removed_blk_idx : start_removed_blk_idx + 1;

	printf("\tStart Block Index: %d | End Block Index: %d | Offset: %d\n", start_removed_blk_idx, end_removed_blk_idx, start_removed_blk_offset);

	int* indirect_buf = NULL;
	int blk_off;
	int num_blk_per_indirect = BLOCK_SIZE / sizeof(int);
	
	for (int blk = start_removed_blk_idx; blk <= end_removed_blk_idx; ++blk) {
		if (blk < DIRECT_PTRS_COUNT) {
			if (f_inode.directs[blk] < 0) continue;

			if (reset_data_block(f_inode.directs[blk]) < 0) {
				return -EIO;
			}
		} else {
			if (f_inode.indirect_ptr < 0) {
				// The data blocks are in indirect, but it is unallocated
				// so there is no need to perform data block reset
				break;
			}

			blk_off = blk - DIRECT_PTRS_COUNT;

			if (indirect_buf == NULL) {
				indirect_buf = (int*)malloc(BLOCK_SIZE);

				if (indirect_buf == NULL) {
					return -ENOSPC;
				}
			}

			if (block_read(f_inode.indirect_ptr, indirect_buf) < 0) {
				return -EIO;
			}

			if (indirect_buf[blk_off] <= 0) continue;

			if (reset_data_block(indirect_buf[blk_off]) < 0) {
				free(indirect_buf);

				return -EIO;
			}
		}
	}

	printf("\tRemoved %d blocks\n", end_removed_blk_idx - start_removed_blk_idx);

	if (start_removed_blk_offset > 0 && start_removed_blk_idx - 1 >= 0 && f_inode.directs[start_removed_blk_idx - 1] >= 0) {
		printf("\tSet 0 for the truncated block idx: %d\n", f_inode.directs[start_removed_blk_idx - 1]);

		// Truncate block req_blk_idx (the rest is filled with zero)
		void* buffer = malloc(BLOCK_SIZE);

		if (buffer == NULL) {
			perror("Cannot allocate memory");

			return -ENOSPC;
		}

		if (block_read(f_inode.directs[start_removed_blk_idx - 1], buffer) < 0) {
			perror("Cannot read block");

			free(buffer);

			return -EIO;
		}

		memset(buffer + start_removed_blk_offset, 0, BLOCK_SIZE - start_removed_blk_offset);

		printf("\tSet to 0 of data block %d from offset %d | size %d\n", f_inode.directs[start_removed_blk_idx - 1], start_removed_blk_offset, BLOCK_SIZE - start_removed_blk_offset);

		if (block_write(f_inode.directs[start_removed_blk_idx - 1], buffer) < 0) {
			perror("Cannot write block");

			free(buffer);

			return -EIO;
		}

		free(buffer);
	}

	// Update size
	f_inode.size = size;

	// Update time
	f_inode.atime = now();
	f_inode.mtime = now();

	if (write_inode(f_inode.ino, &f_inode) < 0) {
		perror("Cannot write inode");

		return -EIO;
	}

	printf("\tUpdated f_inode size = %u\n", f_inode.size);

	printf("[myfs_truncate] Done.\n\n");

	return 0;
}

static int myfs_flush(const char* path, struct fuse_file_info *fi) {
	return 0;
}

static int myfs_utimens(const char* path, const struct timespec tv[2], struct fuse_file_info* fi) {
	assert(path != NULL);
	assert(ROOT_INO != -1);

	struct inode item = { 0 };

	struct file_handler* fh = NULL;

	if (fi != NULL && fi->fh != 0) {
		fh = (struct file_handler*)fi->fh;

		assert(fh != NULL);

		if (read_inode(fh->ino, &item) < 0) {
			return -ENOENT;
		}
	} else {
		int node_res;

		if ((node_res = get_node_by_path(path, ROOT_INO, &item)) < 0) {
			return node_res;
		}
	}

	struct fuse_context* ctx = fuse_get_context();

	assert(ctx != NULL);

	bool can_write = false;
	bool owner_or_root = (ctx->uid == item.uid) || ctx->uid == 0;
	
	if (fh != NULL) {
		int access_mode = fh->flags & O_ACCMODE;
		can_write = (access_mode == O_WRONLY) || (access_mode == O_RDWR);		
		
		printf("\tPermissions from fh : can_write: %d\n", can_write);
	} else {
		mode_t perm = get_perm_by_inode(ctx->uid, ctx->gid, &item);

		can_write = PERM_CAN_WRITE(perm);

		printf("\tPermissions from path-based lookup : can_write: %d\n", can_write);
	}

	struct timespec now;

	clock_gettime(CLOCK_REALTIME, &now);

	// If times is NULL or both times are NOW
	// allowed if owner or root
	if (tv == NULL) {
		if (!owner_or_root && !can_write) return -EACCES;

		item.atime = now;
		item.mtime = now;
	} else {
		bool explicit_present = false;

		for (int i = 0; i <= 1; ++i) {
			if (tv[i].tv_nsec != UTIME_OMIT && tv[i].tv_nsec != UTIME_NOW) {
				explicit_present = true;
			}
		}

		if (!explicit_present) {
			if (!owner_or_root && !can_write) return -EACCES;

			if (tv[0].tv_nsec == UTIME_NOW) item.atime = now;
			if (tv[1].tv_nsec == UTIME_NOW) item.mtime = now;
		} else {
			if (!owner_or_root) return -EPERM;

			// Update atime
			if (tv[0].tv_nsec == UTIME_NOW) {
				item.atime = now;
			} else if (tv[0].tv_nsec != UTIME_OMIT) {
				item.atime = tv[0];
			}
			
			// Update mtime
			if (tv[1].tv_nsec == UTIME_NOW) {
				item.mtime = now;
			} else if (tv[1].tv_nsec != UTIME_OMIT) {
				item.mtime = tv[1];
			}
		}
	}

	if (write_inode(item.ino, &item) < 0) {
		perror("Cannot write inode");

		return -EIO;
	}

	return 0;
}

static int myfs_release(const char* path, struct fuse_file_info *fi) {
	printf("[myfs_release] path: %s\n", path);

	assert(path != NULL);
	
	struct inode finode = { 0 };

	if (fi->fh == 0) {
		perror("Call open() before this operation");

		return -EPERM;
	}

	struct file_handler* fh = (struct file_handler*)fi->fh;

	assert(fh != NULL);

	printf("\tFH ino: %d\n", fh->ino);

	if (read_inode(fh->ino, &finode) < 0) {
		perror("Cannot read inode");

		return -ENOENT;
	}

	printf("\tRead inode with ino: %ld | actual: %ld\n", fh->ino, finode.ino);

	// Update open count
	finode.open_count--;

	if (write_inode(finode.ino, &finode) < 0) {
		perror("Cannot write inode");

		return -EIO;
	}

	fi->fh = 0;
	
	free(fi->fh);

	printf("[myfs_release] Done.\n\n");

	return 0;
}

static int myfs_fallocate(const char* path, int mode, off_t offset, off_t len, struct fuse_file_info* fi) {
	assert(path != NULL);
	assert(ROOT_INO != -1);

	printf("[myfs_fallocate] path: %s | mode = %d | offset: %u | len: %lu\n", path, mode, offset, len);

	struct inode finode = { 0 }; 

	struct file_handler* fh = NULL;

	if (fi != NULL && fi->fh != 0) {
		fh = (struct file_handler*)fi->fh;

		assert(fh != NULL);

		printf("\tFH ino: %d\n", fh->ino);

		if (read_inode(fh->ino, &finode) < 0) {
			perror("Cannot read inode");
	
			return -ENOENT;
		}
	} else {
		int node_res;

		if ((node_res = get_node_by_path(path, ROOT_INO, &finode)) < 0) {
			return node_res;
		}
	}

	int start_blk_idx = offset / BLOCK_SIZE;
	int end_blk_idx = (offset + len) / BLOCK_SIZE;

	// Assume data size is only in DIRECT
	assert(start_blk_idx < DIRECT_PTRS_COUNT);
	assert(end_blk_idx < DIRECT_PTRS_COUNT);

	for (int i = start_blk_idx; i <= end_blk_idx; ++i) {
		if (finode.directs[i] >= 0) {
			printf("\tIno: %d | blk idx: %d | block: %d has been allocated before\n", finode.ino, i, finode.directs[i]);

			// Already assigned
			continue;
		}

		// Assign data block
		int blk = get_avail_blkno();

		if (blk < 0) {
			perror("Cannot allocate memory");

			return -ENOSPC;
		}

		finode.directs[i] = blk;

		printf("\tIno: %d | blk idx: %d | block: %d has been assigned\n", finode.ino, i, blk);
	}

	// Save changes in inode
	if (write_inode(finode.ino, &finode) < 0) {
		perror("Cannot write inode");

		return -EIO;
	}

	printf("[myfs_fallocate] Done.\n\n");

	return 0;
}

static ssize_t myfs_copy_file_range(
	const char* path_in, 
	struct fuse_file_info* fi_in, 
	off_t offset_in, 
	const char* path_out, 
	struct fuse_file_info *fi_out, 
	off_t offset_out, 
	size_t size, 
	int flags
) {
	return 0;
}

static int myfs_flock(const char* path, struct fuse_file_info *fi, int op) {
	return -EOPNOTSUPP;
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

	char *base = basename(tmp1);
	char *dir = dirname(tmp2);

	// if (base == NULL || dir == NULL) {
	// 	perror("Cannot allocate memory");

	// 	if (base) free(base);
	// 	if (dir) free(dir);

	// 	return -ENOSPC;
	// }

	printf("\tLink -- Dir: %s | Base: %s\n", dir, base);

	// Get parent inode and check if the target file is already exist
	struct inode parent_inode = { 0 };

	int node_res;

	if ((node_res = get_node_by_path(dir, ROOT_INO, &parent_inode)) < 0) {
		free(tmp1);
		free(tmp2);
		
		return node_res;
	}

	if (parent_inode.valid == 0) {
		free(tmp1);
		free(tmp2);

		return -ENOENT;
	}

	// Check if the target file already exists
	if (dir_find(parent_inode.ino, base, strlen(base), NULL) == 0) {
		free(tmp1);
		free(tmp2);

		return -EEXIST;
	}

	// Get the next available inode number for this file
	int ino = get_avail_ino();

	if (ino < 0) {
		free(tmp1);
		free(tmp2);

		return -ENOSPC;
	}

	struct fuse_context* ctx = fuse_get_context();

	assert(ctx != NULL);

	struct inode new_file_inode = make_inode(ino, parent_inode.ino, __S_IFLNK, 0755, 0, ctx->uid, ctx->gid);

	if (write_inode(ino, &new_file_inode) < 0) {
		perror("Cannot write inode");

		free(tmp1);
		free(tmp2);

		return -EIO;
	}

	printf("\tWrote file inode ino: %d to parent ino: %d\n", ino, parent_inode.ino);

	if (dir_add(&parent_inode, ino, base, strlen(base)) < 0) {
		perror("Cannot add dirent entry");

		free(tmp1);
		free(tmp2);

		return -EIO;
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
	new_file_inode.size += buffer_size - 1;

	if (write_inode(new_file_inode.ino, &new_file_inode) < 0) {
		perror("Cannot write inode");

		free(tmp1);
		free(tmp2);

		return -EIO;
	}

	// Write path to block
	char* buffer = (char*)malloc(BLOCK_SIZE);

	if (buffer == NULL) {
		perror("Cannot allocate memory");

		free(tmp1);
		free(tmp2);

		return -ENOSPC;
	}

	memcpy(buffer, target, buffer_size);

	if (block_write(blk_idx, buffer) < 0) {
		perror("Cannot write block");
		
		free(tmp1);
		free(tmp2);
		free(buffer);

		return -EIO;
	}

	printf("\tWrote path to file\n");

	free(tmp1);
	free(tmp2);
	free(buffer);

	printf("[myfs_symlink] Done.\n\n");

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

	char *base = basename(tmp1);
	char *dir = dirname(tmp2);

	// if (base == NULL || dir == NULL) {
	// 	perror("Cannot allocate memory");

	// 	if (base) free(base);
	// 	if (dir) free(dir);

	// 	return -ENOSPC;
	// }

	printf("\tLink -- Dir: %s | Base: %s\n", dir, base);

	struct inode parent_inode = { 0 };

	int node_res;

	if ((node_res = get_node_by_path(dir, ROOT_INO, &parent_inode)) < 0) {
		free(tmp1);
		free(tmp2);

		return node_res;
	}

	if (parent_inode.valid == 0) {
		free(tmp1);
		free(tmp2);

		return -ENOENT;
	}

	struct inode target_inode = { 0 };

	if ((node_res = get_node_by_path(target, ROOT_INO, &target_inode)) < 0) {
		free(tmp1);
		free(tmp2);

		return node_res;
	}

	if (dir_add(&parent_inode, target_inode.ino, base, strlen(base)) < 0) {
		perror("Cannot add entry to directory");

		free(tmp1);
		free(tmp2);

		return -EIO;
	}

	free(tmp1);
	free(tmp2);

	printf("[myfs_link] Done.\n\n");

	return 0;
}

static int myfs_readlink(const char* link, char* buffer, size_t len) {
	assert(link != NULL);
	assert(buffer != NULL);
	assert(len > 0);

	printf("[myfs_readlink] link: %s | len: %zu\n", link, len);

	struct inode link_inode = { 0 };

	int node_res;

	if ((node_res = get_node_by_path(link, ROOT_INO, &link_inode)) < 0) {
		return node_res;
	}

	if (!S_ISLNK(link_inode.mode)) {
		return -EINVAL;
	}

	// Should return a flag
	// assert(link_inode.directs[0] >= 0);
	if (link_inode.directs[0] < 0) {
		return - EIO;
	}

	char* blk_buffer = (char*)malloc(BLOCK_SIZE);

	if (blk_buffer == NULL) {
		perror("Cannot allocate memory");

		return -ENOSPC;
	}

	if (block_read(link_inode.directs[0], blk_buffer) < 0) {
		perror("Cannot read block");

		free(blk_buffer);

		return -EIO;
	}

	size_t target_len = (size_t)link_inode.size;

	if (target_len > BLOCK_SIZE) target_len = BLOCK_SIZE;

	size_t n = target_len < (len - 1) ? target_len : len - 1;

	memcpy(buffer, blk_buffer, n);
	buffer[n] = '\0';

	free(blk_buffer);

	printf("[myfs_readlink] Done.\n\n");

	return 0;
}

static int myfs_mknod(const char* path, mode_t mode, dev_t dev) {
	printf("[myfs_mknod] path: %s\n", path);

	assert(path != NULL);

	struct inode file_inode = { 0 };

	int res = make_file(path, mode, &file_inode);

	if (res < 0) return res;
	
	printf("[myfs_mknod] Done.\n\n");

	return 0;
}

static int myfs_access(const char* path, int mode) {
	assert(ROOT_INO >= 0);
	assert(path != NULL);

	printf("[myfs_access] path: %s\n", path);

	struct inode item = { 0 };

	int node_res;

	if ((node_res = get_node_by_path(path, ROOT_INO, &item)) < 0) {
		return -ENOENT;
	}

	if (item.valid == 0) {
		return -ENOENT;
	}

	printf("\tIno: %d\n", item.ino);

	if (mode == F_OK) {
		// The user wants to know if the file exists
		printf("\tRequest file exist granted\n");
		return 0;
	}

	// Get user's uid and gid from the context
	struct fuse_context *ctx = fuse_get_context();

	assert(ctx != NULL);

	uid_t uid = ctx->uid;
	gid_t gid = ctx->gid;

	printf("\tUser -- uid: %u | gid: %u\n", uid, gid);

	// Extract permissions from inode
	mode_t perm;

	if (uid == item.uid) {
		// The user who wants to access this file is the owner of this file
		perm = get_user_perm(item.mode);
	} else if (gid == item.gid) {
		// If the user who wants to access this file is not the owner of this file
		// but within the group of this file
		perm = get_group_perm(item.mode);
	} else {
		perm = get_other_perm(item.mode);
	}

	switch (mode)
	{
	case R_OK:
		// Ther user who invokes this want to know if they can read this file
		if (PERM_CAN_READ(mode)) return 0;

		break;
	case W_OK:
		// The user who invokes this want to know if they can write this file
		if (PERM_CAN_WRITE(perm)) return 0;

		break;
	case X_OK:
		// The user who invokes this want to know if they can execute this file
		if (PERM_CAN_EXECUTE(perm)) return 0;
		break;
	default:
		break;
	}

	return -EACCES;
}

static int myfs_chmod(const char* path, mode_t mode, struct fuse_file_info *fi) {
	assert(path != NULL);
	assert(ROOT_INO != -1);
	
	printf("[myfs_chmod] path: %s | Mode: %04o\n", path, mode & 07777);

	struct fuse_context* ctx = fuse_get_context();
	
	assert(ctx != NULL);

	uid_t uid = ctx->uid;
	uid_t gid = ctx->gid;

	struct inode item = { 0 };

	int node_res;

	if ((node_res = get_node_by_path(path, ROOT_INO, &item)) < 0) {
		return node_res;
	}

	printf("\tIno: %d | uid: %d | gid: %d\n", item.ino, uid, gid);

	// chmod if:
	// - user is the owner of the file
	// - user is root
	// - if setuid and setgid bits are present:
	//		- if user is not root or owner, user can chmod if they don't try to "add" setuid, setgid of permission bits
	// otherwise, disallow since they are not owner or root

	// Check if user trying to add set_uid bit in the request
	// If the file's mode already have set_uid bit, it is considered not "adding"
	// If user trying to add set_gid bit in the request, it is allowed if user belongs to gid group, otherwise disallowed
	printf("\tChecking process id: %d vs item id: %d\n", uid, item.uid);

	mode_t old_perm = item.mode & 07777;
	mode_t req_perm = mode & 07777;

	bool is_owner_or_root = uid == item.uid || uid == 0;
	bool adding_suid, adding_sgid;

	if (!is_owner_or_root) {
		adding_suid = (req_perm & S_ISUID) && !(old_perm & S_ISUID);
		adding_sgid = (req_perm & S_ISGID) && !(old_perm & S_ISGID);

		// Check if any other permission bits are changed beside suid and sgid
		mode_t changed = old_perm ^ req_perm;
		bool change_non_special = (changed & ~(S_ISUID | S_ISGID)) != 0;

		// Non-owner can never add setuid
		if (adding_suid) return -EPERM;

		// Non-owner may add setgid if they belongs to the item's group id and no the bits are changed
		if (adding_sgid) {
			// Not belong to group
			if (gid != item.gid) return -EPERM;

			// User change other bits, not allowed
			if (change_non_special) return -EPERM;
		} else {
			// Any other normal chmod by non-owner is not allowed
			if (change_non_special) return -EPERM;
		}
	}

	// If user is owner but not belongs to the item's group
	// and wish to setgid bit
	// the request is still forwarded but the setgid bit is cleared
	if ((req_perm & S_ISGID) && uid != 0 && gid != item.gid) {
		// Clear sgid bit
		req_perm &= ~S_ISGID;
	}

	// Clear suid bit if user is not root, but the requested perm has it
	if ((req_perm & S_ISUID) && uid != 0) {
		// Clear suid bit
		req_perm &= ~S_ISUID;
	}

	printf("\tCan change mode\n");

	// Keep file type bits, change permission bits
	item.mode = (item.mode & S_IFMT) | req_perm;

	if (write_inode(item.ino, &item) < 0) {
		return -EIO;
	}

	printf("\tAfter perm change: %05o | req perm: %05o\n", item.mode & 07777, req_perm);

	printf("[myfs_chmod] Done.\n\n");

	return 0;
}

static int myfs_chown(const char* path, uid_t uid, gid_t gid, struct fuse_file_info *fi) {
	assert(path != NULL);
	assert(ROOT_INO != -1);
	
	printf("[myfs_chown] path: %s | uid: %d | gid: %d\n", path, uid, gid);

	struct fuse_context* ctx = fuse_get_context();
	
	assert(ctx != NULL);

	uid_t uuid = ctx->uid;
	gid_t ggid = ctx->gid;

	printf("\tuuid: %d | ggid: %d\n", uuid, ggid);

	struct inode item = { 0 };

	int node_res;

	if ((node_res = get_node_by_path(path, ROOT_INO, &item)) < 0) {
		return node_res;
	}

	printf("\tIno: %d\n", item.ino);

	if (uuid != uid) {
		// Changing uid
		// Only root can change uid
		if (uuid != 0) return -EPERM;
	}

	if (ggid != gid) {
		// Changing gid
		// Root can change gid
		// Non-root user can change gid if:
		// - User owns the file AND the group of this item belongs to the user's groups
		// Since FUSE does not provide the list of groups that user belongs to
		// I gotta skip that condition and only check for primary group
		if (uuid != 0) {
			// If user is non-root
			if (uuid != item.uid || ggid != item.gid) {
				return -EPERM;
			}
		}
	}

	if (uid != (uid_t)-1) item.uid = uid;
	if (gid != (gid_t)-1) item.gid = gid;

	// Clear suid, sgid bits if non-root
	if (uuid != 0) {
		item.mode &= ~S_ISUID;
		item.mode &= ~S_ISGID;
	}

	if (write_inode(item.ino, &item) < 0) {
		return -EIO;
	}

	printf("[myfs_chown] Done.\n\n");

	return 0;
}

static int myfs_statfs(const char* path, struct statvfs *stat) {
	assert(path != NULL);
	assert(stat != NULL);
	assert(ROOT_INO != -1);
	assert(superblock != NULL);

	printf("[myfs_statfs] path: %s\n", path);

	struct inode item = { 0 };

	int node_res;

	if ((node_res = get_node_by_path(path, ROOT_INO, &item)) < 0) {
		return node_res;
	}

	stat->f_bsize = BLOCK_SIZE;
	stat->f_frsize = BLOCK_SIZE;
	stat->f_blocks = superblock->max_dnum;
	stat->f_namemax = NAME_MAX;
	stat->f_bfree = superblock->free_blk_count;
	
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
	.lseek = myfs_lseek,
	.fsync = myfs_fsync,
	.rename = myfs_rename,
	.rmdir = myfs_rmdir,
	.releasedir = myfs_releasedir,
	.unlink = myfs_unlink,
	.symlink = myfs_symlink,
	.link = myfs_link,
	.readlink = myfs_readlink,
	.truncate = myfs_truncate,
	.flush = myfs_flush,
	.release = myfs_release,
	.fallocate = myfs_fallocate,
	.flock = myfs_flock,
	.mknod = myfs_mknod,
	.access = myfs_access,
	.chmod = myfs_chmod,
	.chown = myfs_chown,
	.statfs = myfs_statfs,
#ifdef HAVE_UTIMESAT
	.utimens = myfs_utimens,
#endif
#ifdef HAVE_SETXATTR
	.setxattr	= myfs_setxattr,
	.getxattr	= myfs_getxattr,
	.listxattr	= myfs_listxattr,
	.removexattr	= myfs_removexattr,
#endif
#ifdef HAVE_COPY_FILE_RANGE
	.copy_file_range = myfs_copy_file_range,
#endif
#ifdef HAVE_STATX
	.statx		= myfs_statx,
#endif
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
