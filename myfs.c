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
#include <pthread.h>

// Provide some simple file path extractions such as basename, filename, etc
#include <libgen.h>

#include <linux/limits.h>
#include <assert.h>

#include "block.h"
#include "myfs.h"

#define HAVE_UTIMESAT

#define P_WRITE 'w'
#define P_READ 'r'
#define P_EXECUTE 'x'

#define P_ONLY_W "w"
#define P_ONLY_R "r"
#define P_ONLY_X "x"

// write and read
#define P_WR "wr"

// write and execute
#define P_WX "wx"

// read and execute
#define P_RE "rx"

/**
 * Helper macros
 */
/**
 * Fill an array with the given value
 */
#define ARRAY_FILL(arr, value, len) \
	for (size_t i = 0; i < len; ++i) \
		(arr)[i] = (value)

/**
 * Free the list of pointers
 */
#define FREE_ALL(...) do { \
	void *ptrs[] = { __VA_ARGS__ }; \
	for (size_t i = 0; i < sizeof(ptrs) / sizeof(ptrs[0]); i++) \
		free(ptrs[i]); \
} while (0)

#define RD_LOCK(m, op) do { \
	fprintf(thread_log_fd, "[%s] RD LOCK %s %p thread_id=%lu at %s:%d\n", \
	op, #m, (void*)(m), (unsigned long)pthread_self(), __FILE__, __LINE__); \
	fflush(thread_log_fd); \
	int rc = pthread_rwlock_rdlock((m)); \
	if (rc) { errno = rc; perror("pthread_rwlock_rdlock"); abort(); } \
} while (0)

#define WR_LOCK(m, op) do { \
	fprintf(thread_log_fd, "[%s] WR LOCK %s %p thread_id=%lu at %s:%d\n", \
	op, #m, (void*)(m), (unsigned long)pthread_self(), __FILE__, __LINE__); \
	fflush(thread_log_fd); \
	int rc = pthread_rwlock_wrlock((m)); \
	if (rc) { errno = rc; perror("pthread_rwlock_wrlock"); abort(); } \
} while (0)

#define UNLOCK(m) do { \
	fprintf(thread_log_fd, "UNLOCK %s %p thread_id=%lu at %s:%d\n", \
	#m, (void*)(m), (unsigned long)pthread_self(), __FILE__, __LINE__); \
	fflush(thread_log_fd); \
	int rc = pthread_rwlock_unlock((m)); \
	if (rc) { errno = rc; perror("pthread_rwlock_unlock"); abort(); } \
} while (0)

#define IS_STR_EMPTY(str) (strcmp(str, "") == 0)
#define IS_DIR(inode) ((inode).type == S_IFDIR)
#define IS_DIR_STICKY(inode) ((inode).mode & S_ISVTX)
#define IS_ROOT(uid) (uid == 0)

/**
 * Permission Utilities
 */
#define PERM_CAN_READ(perm) (perm & 4)
#define PERM_CAN_WRITE(perm) (perm & 2)
#define PERM_CAN_EXECUTE(perm) (perm & 1)
#define STICKY_MODE(mode) (mode & S_ISVTX)

/**
 * Locks
 */
#define MAX_INODE_LOCKS 1024
pthread_rwlock_t inode_locks[MAX_INODE_LOCKS] = {
	[0 ... MAX_INODE_LOCKS - 1] = PTHREAD_RWLOCK_INITIALIZER
};
pthread_mutex_t inode_bitmap_lock = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t data_bitmap_lock = PTHREAD_MUTEX_INITIALIZER;

char diskfile_path[PATH_MAX];

struct superblock* superblock = NULL;
int ROOT_INO = 1;
bool SUPERBLOCK_EXISTED = false;
FILE* thread_log_fd = NULL;


// --------------------- HELPER FUNCTIONS ------------------------------
/**
 * Extract user permission bits
 */
mode_t get_user_perm(mode_t mode) {
	return (mode >> 6) & 7;
}

/**
 * Extract group permission bits
 */
mode_t get_group_perm(mode_t mode) {
	return (mode >> 3) & 7;
}

/**
 * Extract other permission bits
 */
mode_t get_other_perm(mode_t mode) {
	return mode & 7;
}

mode_t get_perm_by_inode(const struct inode* inode) {
	assert(inode != NULL);

	struct fuse_context* ctx = fuse_get_context();

	assert(ctx != NULL);

	uid_t uid = ctx->uid;
	gid_t gid = ctx->gid;

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

static inline struct timespec now(void) {
	struct timespec ts;

	ts.tv_sec = time(NULL);
	ts.tv_nsec = 0;

	return ts;	
}

static int split_path(const char* path, struct path_split* out) {
	assert(path != NULL);
	assert(out != NULL);

	size_t len = strlen(path);
	char* buf = malloc(len + 1); // account for NULL-terminated character at the end

	if (buf == NULL) return -ENOMEM;

	// Since we cannot modify path (const), we memcpy it to buf
	memcpy(buf, path, len + 1);

	// Strip trailing slashes such as /a/b/, /a/b/////// -> /a/b
	while (len > 1 && buf[len - 1] == '/') buf[--len] = '\0';

	// Find the location of the last '/'
	// strrchr returns a pointer that points to the location of the last slash
	char* slash = strrchr(buf, '/');

	if (slash == NULL) {
		// There is no slash, just name
		// Then we make dir to be ".", then base is "name"
		out->buf = buf;
		out->dir = (char*)".";
		out->base = buf;

		return 0;
	}

	if (slash == buf) {
		// "/name" or "/"
		// slash and buf are both pointers point to the begining of some string
		// thus, if slash == buf, it means they are both pointing to the beginning of the string
		// so the only cases are "/name" or "/"
		// Same as above, dir is "." and base is "name" OR base is empty
		out->buf = buf;
		out->dir = (char*)".";

		// slash + 1 makes base point to the next character which is the begining of "name"
		out->base = (len == 1) ? (char*)"" : (slash + 1);

		return 0;
	}

	// In this case
	// we could have "/a/b/c"

	// slash points to the last slash
	// which mean /a/b/<HERE>c
	// changing it to NULL-terminated character will split dir and base into /a/b[\0]c
	*slash = '\0'; 
	out->buf = buf;
	out->dir = buf;
	out->base = slash + 1;

	return 0;
}

static void free_split_path(struct path_split* p) {
	if (p && p->buf) free(p->buf);
}

/**
 * Check if a given inode has the requested permissions
 * "req" is the string in format of "r" or "rw" or "w", etc
 * each letter represents READ ('r'), WRITE ('w') or EXECUTE ('x') permission
 * The function check if the given inode has the COMBINATION of permissions, not invidually
 * So while an inode may has "w" permit, does not mean it has "rw" permit
 */
static bool check_permissions(struct inode* i, const char* req) {
	assert(i != NULL);
	assert(req != NULL);

	printf("[check_permissions] ino: %ld | requested permissions: %s\n", i->ino, req);

	struct fuse_context *ctx = fuse_get_context();

	assert(ctx != NULL);

	uid_t uid = ctx->uid;
	gid_t gid = ctx->gid;

	mode_t perm = get_perm_by_inode(i);

	printf("\tPerm: %05o\n", i->mode & 07777);

	size_t len = strlen(req);

	for (size_t i = 0; i < len; i++) {
		if (req[i] == P_WRITE) {
			// Check if inode has write permission
			if (!PERM_CAN_WRITE(perm)) return false;
		} else if (req[i] == P_READ) {
			// Check if inode has read permission
			if (!PERM_CAN_READ(perm)) return false;
		} else if (req[i] == P_EXECUTE) {
			// Check if inode has execute permission
			if (!PERM_CAN_EXECUTE(perm)) return false;
		}
	}

	return true;
}

static inline pthread_rwlock_t* get_inode_lock(ino_t ino) {
	return &inode_locks[ino % MAX_INODE_LOCKS];
}
// -----------------------------------------------------------------------

/**
 * Get the first available inode number from inode bitmap
 * Also set it as "used" in the bitmap
 */
int get_avail_ino() {
	assert(superblock != NULL);

	printf("[get_avail_ino]\n");

	pthread_mutex_lock(&inode_bitmap_lock);

	int inode_bitmap_blocks = superblock->d_bitmap_blk - superblock->i_bitmap_blk;

	int num_bits_per_blocks = BLOCK_SIZE * 8; 

	assert(inode_bitmap_blocks >= 1);

	assert(num_bits_per_blocks > 0);

	printf("\tReading %d blocks (%d bits) of inode bitmap\n", inode_bitmap_blocks, num_bits_per_blocks);

	bitmap_t bitmap = (bitmap_t)malloc(BLOCK_SIZE);

	if (bitmap == NULL) {
		perror("Cannot allocate memory");

		pthread_mutex_unlock(&inode_bitmap_lock);

		return -ENOSPC;
	}

	for (int i = 0; i < inode_bitmap_blocks; ++i) {
		if (block_read(superblock->i_bitmap_blk + i, bitmap) < 0) {
			free(bitmap);

			pthread_mutex_unlock(&inode_bitmap_lock);

			perror("Cannot read block");

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

					pthread_mutex_unlock(&inode_bitmap_lock);

					return -EIO;
				}

				printf("\tSaved to block %d\n", superblock->i_bitmap_blk + i);

				// Update superblock stat
				superblock->free_ino_count--;

				if (block_write(SUPERBLOCK_BLK_NUM, superblock) < 0) {
					perror("Cannot write block");

					free(bitmap);

					pthread_mutex_unlock(&inode_bitmap_lock);

					return -EIO;
				}

				printf("\tUpdated superblock count of free inode. Total free inode: %d\n", superblock->free_ino_count);

				free(bitmap);

				pthread_mutex_unlock(&inode_bitmap_lock);

				printf("[get_avail_ino] Done.\n\n");

				return j + 1;
			}
		}
	}

	free(bitmap);

	pthread_mutex_unlock(&inode_bitmap_lock);

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

	pthread_mutex_lock(&data_bitmap_lock);

	int data_bitmap_blocks = superblock->i_start_blk - superblock->d_bitmap_blk;

	int num_bits_per_blocks = BLOCK_SIZE * 8; 

	assert(data_bitmap_blocks >= 1);

	assert(num_bits_per_blocks > 0);

	printf("\tReading %d blocks (%d bits) of data bitmap\n", data_bitmap_blocks, num_bits_per_blocks);

	bitmap_t bitmap = (bitmap_t)malloc(BLOCK_SIZE);

	if (bitmap == NULL) {
		perror("Cannot allocate memory");

		pthread_mutex_unlock(&data_bitmap_lock);

		return -ENOSPC;
	}

	for (int i = 0; i < data_bitmap_blocks; ++i) {
		if (block_read(superblock->d_bitmap_blk + i, bitmap) < 0) {
			perror("Cannot read block");

			free(bitmap);

			pthread_mutex_unlock(&data_bitmap_lock);

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

					pthread_mutex_unlock(&data_bitmap_lock);

					return -EIO;
				}

				printf("\tSaved to block %d\n", superblock->d_bitmap_blk + i);

				superblock->free_blk_count--;

				if (block_write(SUPERBLOCK_BLK_NUM, superblock) < 0) {
					perror("Cannot write block");

					free(bitmap);

					pthread_mutex_unlock(&data_bitmap_lock);

					return -EIO;
				}

				printf("\tUpdated superblock count of free data blocks. Total free data blocks: %d\n", superblock->free_blk_count);

				printf("\tReturn data block [%d]\n", j + superblock->d_start_blk);

				printf("[get_avail_blkno] Done.\n\n");

				free(bitmap);

				pthread_mutex_unlock(&data_bitmap_lock);

				return j + superblock->d_start_blk;
			}
		}
	}

	free(bitmap);

	pthread_mutex_unlock(&data_bitmap_lock);

	printf("[get_avail_blkno] Done.\n\n");

	return -1;
}

/**
 * Read inode info given inode number
 */
int read_inode(ino_t ino, struct inode* inode) {
	printf("[read_inode] ino: %ld\n", ino);

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

		return -ENOMEM;
	}

	if (block_read(block_index + offset, inode_table) < 0) {
		perror("Cannot read block");
		
		free(inode_table);

		return -EIO;
	}

	memcpy(inode, inode_table + inode_index, sizeof(struct inode));
	
	free(inode_table);

	printf("\tRead from inode table of ino: %ld\n", inode->ino);

	printf("[read_inode] Done.\n\n");

	return 0;
}

/**
 * Write into inode given inode number
 */
int write_inode(ino_t ino, struct inode* inode) {
	printf("[write_inode] ino: %ld\n", ino);

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

struct inode make_inode(ino_t ino, uint32_t type, mode_t mode, int nlink, uid_t uid, gid_t gid) {
	assert(superblock != NULL);
	assert(ino < superblock->max_inum);
	
	// For now, just accept dir or regular file or symlink
	// assert(type == S_IFDIR || type == __S_IFREG || type == __S_IFLNK);
	assert(nlink >= 0);

	struct inode node;

	node.ino = ino;
	node.valid = 1;
	node.size = 0;
	node.type = type;
	node.mode = type | (mode & 07777);
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

int reset_ino(ino_t ino) {
	printf("[reset_ino] ino: %ld\n", ino);

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

int reset_data_block(uint32_t data_block) {
	printf("[reset_data_block] ino: %ld\n", data_block);

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

/**
 * Free inode and all data blocks it owns
 */
int free_inode(ino_t ino) {
	struct inode finode = { 0 };

	int res = 0;

	if ((res = read_inode(ino, &finode)) < 0) {
		perror("Cannot read block");

		return res;
	}

	for (int i = 0; i < DIRECT_PTRS_COUNT; ++i) {
		if (finode.directs[i] >= 0) {
			if (reset_data_block(finode.directs[i]) < 0) {
				perror("Cannot reset data block");

				return -EIO;
			}
		}
	}

	if (finode.indirect_ptr >= 0) {
		int* buf = (int*)malloc(BLOCK_SIZE);
		int num_blk = BLOCK_SIZE / sizeof(int);

		if (buf == NULL) {
			return -ENOMEM;
		}

		if (block_read(finode.indirect_ptr, buf) < 0) {
			perror("Cannot read block");

			return -EIO;
		}

		for (int i = 0; i < num_blk; ++i) {
			if (buf[i] < 0) continue;

			if (reset_data_block(buf[i]) < 0) {
				printf("\treset_data_block_2\n");

				perror("Cannot reset data block");

				return -EIO;
			}
		}

		if (reset_ino(finode.ino) < 0) {
			perror("Cannot reset inode");

			return -EIO;
		}
	}

	return 0;
}

/**
 * Find directory given name, return dirent struct
 * If the provided dirent is NULL, then dir_find won't fill the dirent struct
 * but still return the result of whether the item exists or not
 */
int dir_find(ino_t ino, const char* fname, size_t name_len, struct dirent* dirent) {
	printf("[dir_find] ino: %ld, fname: %s, name_len: %ld\n", ino, fname, name_len);

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

	struct dirent* buffer = (struct dirent*)malloc(BLOCK_SIZE);

	if (buffer == NULL) {
		perror("Cannot allocate memory");

		return -ENOMEM;
	}	

	int num_entries_per_block = BLOCK_SIZE / sizeof(struct dirent);
	
	int total_dirents = dir_inode.size / sizeof(struct dirent);

	printf("\tNum entries per block: %d | Total: %d\n", num_entries_per_block, total_dirents);

	for (int i = 0; i < DIRECT_PTRS_COUNT; ++i) {
		if (dir_inode.directs[i] < 0) continue;

		if (block_read(dir_inode.directs[i], buffer) < 0) {
			perror("Cannot read block");
			
			free(buffer);

			return -EIO;
		}

		for (int j = 0; j < num_entries_per_block; ++j) {
			if (buffer[j].valid == 1) {
				printf("\t\tChecking item[%d]: %s at block %d\n", j, buffer[j].name, dir_inode.directs[i]);
				
				if (strncmp(buffer[j].name, fname, name_len) == 0) {
					printf("\t\tFound item | ino: %ld\n", buffer[j].ino);
	
					if (dirent != NULL) {
						memcpy(dirent, &buffer[j], sizeof(struct dirent));
					}
	
					free(buffer);
	
					printf("[dir_find] Done.\n\n");
	
					return 0;
				}
			}
		}
	}

	free(buffer);

	printf("\tEntry of name: %s does not exist\n", fname);

	printf("[dir_find] Done.\n\n");

	return -ENOENT;
}

/**
 * Add directory given name
 */
int dir_add(struct inode* dir_inode, ino_t f_ino, const char* fname, size_t name_len) {
	printf("[dir_add] f_ino: %ld | fname: %s | name_len: %ld\n", f_ino, fname, name_len);

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

		return -ENOMEM;
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

				if (block_write(dir_inode->directs[block_idx], buffer) < 0) {
					perror("Cannot write block");
					
					free(buffer);

					return -EIO;
				}

				// Update mtime
				dir_inode->mtime = now();
				
				if (write_inode(dir_inode->ino, dir_inode) < 0) {
					perror("Cannot write inode");

					free(buffer);

					return -EIO;
				}

				free(buffer);

				printf("[dir_add] Done.\n\n");

				return 0;
			} else {
				printf("\tItem at spot %d is %s ino: %ld\n", i, buffer[i].name, buffer[i].ino);
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

	if (block_write(data_block_idx, buffer) < 0) {
		perror("Cannot write data block");

		return -EIO;
	}

	// Update size
	dir_inode->size += BLOCK_SIZE;

	// Update mtime
	dir_inode->mtime = now();

	printf("\tUpdated dir size to: %u\n", dir_inode->size);

	if (write_inode(dir_inode->ino, dir_inode) < 0) {
		perror("Cannot write inode");

		free(buffer);

		return -EIO;
	}

	printf("\tWrote parent inode update\n");

	free(buffer);

	printf("[dir_add] Done.\n\n");

	return 0;
}

/**
 * Remove an entry from a directory
 */
int dir_remove(struct inode* dir_inode, const struct inode* entry_inode, const char* fname) {
	assert(superblock != NULL);
	assert(dir_inode != NULL);
	assert(fname != NULL);
	assert(entry_inode != NULL);
	assert(dir_inode->ino != entry_inode->ino);

	printf("[dir_remove] parent ino: %ld about to remove (-> ino: %ld): %s\n", dir_inode->ino, entry_inode->ino, fname);

	struct dirent* buffer = (struct dirent*)malloc(BLOCK_SIZE);

	if (buffer == NULL) {
		perror("Cannot allocate memory");

		return -ENOMEM;
	}

	int num_entries_per_block = BLOCK_SIZE / sizeof(struct dirent);
	
	printf("\tNum entries per block: %d\n", num_entries_per_block);

	for (int i = 0; i < DIRECT_PTRS_COUNT; ++i) {
		if (dir_inode->directs[i] < 0) continue;

		if (block_read(dir_inode->directs[i], buffer) < 0) {
			perror("Cannot read block");
			
			free(buffer);

			return -EIO;
		}

		for (int j = 0; j < num_entries_per_block; ++j) {
			if (buffer[j].valid == 1) {
				printf("\tChecking item[%d] ino: %ld - name: %s\n", j, buffer[j].ino, buffer[j].name);
			}

			if (buffer[j].valid == 1 && strcmp(buffer[j].name, fname) == 0) {
				printf("\tFound item to remove at j = [%d]\n", j);

				buffer[j].valid = 0; // mark as invalid or free slot
				buffer[j].name[0] = '\0';

				if (block_write(dir_inode->directs[i], buffer) < 0) {
					perror("Cannot write block");

					free(buffer);
					
					return -EIO;
				}

				dir_inode->mtime = now();

				if (write_inode(dir_inode->ino, dir_inode) < 0) {
					perror("Cannot write inode");

					free(buffer);

					return -EIO;
				}

				printf("[dir_remove] Done.\n\n");

				free(buffer);

				return 0;
			}
		}
	}

	printf("\tf_ino: %ld does not exist in ino: %ld\n", entry_inode->ino, dir_inode->ino);

	// target does not exist
	free(buffer);

	return -ENOENT;
}

int dir_entry_count(struct inode* dir_inode) {
	struct dirent* buffer = (struct dirent*)malloc(BLOCK_SIZE);

	if (buffer == NULL) {
		perror("Cannot allocate memory");

		return -ENOMEM;
	}

	int num_entries_per_block = BLOCK_SIZE / sizeof(struct dirent);

	int count = 0;

	for (int i = 0; i < DIRECT_PTRS_COUNT; ++i) {
		if (dir_inode->directs[i] < 0) continue;

		if (block_read(dir_inode->directs[i], buffer) < 0) {
			perror("Cannot read block");
			
			free(buffer);

			return -EIO;
		}

		for (int j = 0; j < num_entries_per_block; ++j) {
			if (buffer[j].valid == 1) count++;
		}
	}

	free(buffer);

	return count;
}

/**
 * Update ".." to point to a different ino
 */
int dir_update_dotdot(struct inode* dir_inode, struct inode* new_parent) {
	printf("[dir_update_dotdot] dir ino is: %ld | change to new parent ino: %ld\n", dir_inode->ino, new_parent->ino);

	struct dirent* buffer = (struct dirent*)malloc(BLOCK_SIZE);

	if (buffer == NULL) {
		perror("Cannot allocate memory");

		return -ENOMEM;
	}

	int num_entries_per_block = BLOCK_SIZE / sizeof(struct dirent);

	for (int i = 0; i < DIRECT_PTRS_COUNT; ++i) {
		if (dir_inode->directs[i] < 0) continue;

		if (block_read(dir_inode->directs[i], buffer) < 0) {
			perror("Cannot read block");
			
			free(buffer);

			return -EIO;
		}

		for (int j = 0; j < num_entries_per_block; ++j) {
			if (buffer[j].valid == 1) {
				printf("\t\tChecking item[%d]: %s at block %d\n", j, buffer[j].name, dir_inode->directs[i]);
				
				if (strncmp(buffer[j].name, "..", 2) == 0) {
					printf("\t\tFound item | ino: %ld\n", buffer[j].ino);
					
					if (buffer[j].ino == new_parent->ino) {
						// Nothing changes
						free(buffer);

						return 0;
					}

					// Before parent nlink before update ino
					struct inode old_parent = { 0 };

					if (read_inode(buffer[j].ino, &old_parent) < 0) {
						free(buffer);

						return -EIO;
					}

					old_parent.nlink--;

					if (write_inode(old_parent.ino, &old_parent) < 0) {
						free(buffer);

						return -EIO;
					}

					new_parent->nlink++;

					if (write_inode(new_parent->ino, new_parent) < 0) {
						free(buffer);

						return -EIO;
					}

					buffer[j].ino = new_parent->ino;

					// Update buffer
					if (block_write(dir_inode->directs[i], buffer) < 0) {
						perror("Cannot write block");

						free(buffer);

						return -EIO;
					}

					free(buffer);
					
					printf("[dir_update_dotdot] Done.\n\n");
	
					return 0;
				}
			}
		}
	}

	free(buffer);

	printf("\tCannot find '..'. Something went wrong!\n");

	printf("[dir_update_dotdot] Done.\n\n");

	return -ENOENT;
}

/**
 * Get inode number from the give path, save info into returned inode
 */
int get_node_by_path(const char* path, ino_t ino, struct inode* inode) {
	printf("[get_node_by_path] path: %s | ino: %ld\n", path, ino);

	assert(path != NULL);
	assert(ROOT_INO >= 0);
	assert(ino < superblock->max_inum);
	assert(inode != NULL);

	struct fuse_context* ctx = fuse_get_context();

	assert(ctx != NULL);

	uid_t uid = ctx->uid;
	gid_t gid = ctx->gid;
	
	mode_t perm;

	struct path_split p = { 0 };

	if (split_path(path, &p) < 0) return -ENOMEM;

	char* base = p.base;

	if (strlen(base) > NAME_MAX) {
		return -ENAMETOOLONG;
	}

	printf("\tBase: %s\n", base);

	struct inode current = { 0 };
	struct dirent dir_entry = { 0 };

	if (read_inode(ino, &current) < 0) {
		free_split_path(&p);

		return -EIO;
	}

	char* path_clone = strdup(path);

	if (path_clone == NULL) {
		free_split_path(&p);

		return -ENOMEM;
	}

	char* save_ptr;
	char* token = strtok_r(path_clone, "/", &save_ptr);
	int token_len = 0;

	while (token) {
		if (strcmp(token, base) != 0) {
			// Mean we are still in the middle of traversing

			// Check if the current token is a dir
			// Cannot traverse a file
			if (current.type != S_IFDIR) {
				free(path_clone);
				free_split_path(&p);

				return -ENOTDIR;
			}
		}

		token_len = strlen(token);

		// Check if we have "x" permission to traverse this dir
		printf("\tTraversing dir ino: %ld | current token is: %s | Perm: %05o\n", current.ino, token, current.mode);

		perm = get_perm_by_inode(&current);

		// Check if perm has "execute" bit
		if (!PERM_CAN_EXECUTE(perm) && !IS_ROOT(uid)) {
			free(path_clone);
			free_split_path(&p);

			return -EACCES;
		}

		// Now consider token
		if (token_len > NAME_MAX) {
			free(path_clone);
			free_split_path(&p);

			return -ENAMETOOLONG;
		}

		// Check if the token exists in the current dir
		if (dir_find(current.ino, token, token_len, &dir_entry) < 0) {
			// token does not exist
			perror("[get_node_by_path] Item not found!");

			free(path_clone);
			free_split_path(&p);

			return -ENOENT;
		}
		
		printf("\tDir entry ino: %ld\n", dir_entry.ino);

		// Advance current to the next
		if (read_inode(dir_entry.ino, &current) < 0) {
			free(path_clone);
			free_split_path(&p);

			return -EIO;
		}

		// Move to the next token
		token = strtok_r(NULL, "/", &save_ptr);
	}

	printf("\tino: %ld | nlink: %d\n", current.ino, current.nlink);

	// Copy current inode to output inode
	memcpy(inode, &current, sizeof(struct inode));

	free(path_clone);

	free_split_path(&p);

	printf("[get_node_by_path] Done.\n\n");
	
	return 0;
}

/**
 * Check if i is the descendant of origin
 */
bool is_descendant(const struct inode* i, const struct inode* origin) {
	// if origin is root folder
	// then it's always true
	if (origin->ino == ROOT_INO) return true;

	// walk '..' entry of i until either reached root
	struct dirent parent = { 0 };
	ino_t current_ino = i->ino;

	do {
		assert(dir_find(current_ino, "..", 2, &parent) == 0);

		if (parent.ino == origin->ino) return true;

		current_ino = parent.ino;
	} while (parent.ino != ROOT_INO);

	return false;
}

/**
 * Create a file inode
 */
int make_file(const char* path, mode_t mode, struct inode* out_inode) {
	assert(path != NULL);
	assert(out_inode != NULL);
	assert(ROOT_INO >= 0);

	printf("[make_file] path: %s | mode: %o\n", path, mode);

	pthread_rwlock_t* parent_inode_lock, *file_inode_lock;

	struct path_split p = { 0 };

	if (split_path(path, &p) < 0) return -ENOMEM;

	char* base = p.base;
	char* dir = p.dir;

	if (strlen(base) > NAME_MAX) return -ENAMETOOLONG;

	printf("\tDir: %s | Base: %s\n", dir, base);

	// Get parent inode and check if the target file is already exist
	struct inode parent_inode = { 0 };

	int node_res;

	if ((node_res = get_node_by_path(dir, ROOT_INO, &parent_inode)) < 0) {
		free_split_path(&p);
		
		return node_res;
	}

	parent_inode_lock = get_inode_lock(parent_inode.ino);

	WR_LOCK(parent_inode_lock, "make_file");

	if (parent_inode.valid == 0) {
		free_split_path(&p);

		UNLOCK(parent_inode_lock);

		return -ENOENT;
	}

	// Check if the target file already exists
	if (dir_find(parent_inode.ino, base, strlen(base), NULL) == 0) {
		free_split_path(&p);

		UNLOCK(parent_inode_lock);

		return -EEXIST;
	}

	// Check if user has permission to write into parent dir
	struct fuse_context* ctx = fuse_get_context();

	assert(ctx != NULL);

	mode_t perm = get_perm_by_inode(&parent_inode);

	if (!PERM_CAN_WRITE(perm) && ctx->uid != 0) {
		UNLOCK(parent_inode_lock);

		return -EACCES;
	}

	// Get the next available inode number for this file
	int ino = get_avail_ino();

	if (ino < 0) {
		free_split_path(&p);

		UNLOCK(parent_inode_lock);

		return -ENOSPC;
	}

	file_inode_lock = get_inode_lock(ino);

	WR_LOCK(file_inode_lock, "make_file");

	if (S_ISFIFO(mode)) {
		*(out_inode) = make_inode(ino, __S_IFIFO, mode, 1, ctx->uid, ctx->gid);
	} else if (S_ISREG(mode)) {
		*(out_inode) = make_inode(ino, __S_IFREG, mode, 1, ctx->uid, ctx->gid);
	} else if (S_ISCHR(mode)) {
		*(out_inode) = make_inode(ino, __S_IFCHR, mode, 1, ctx->uid, ctx->gid);
	} else if (S_ISBLK(mode)) {
		*(out_inode) = make_inode(ino, __S_IFBLK, mode, 1, ctx->uid, ctx->gid);
	} else if (S_ISSOCK(mode)) {
		*(out_inode) = make_inode(ino, __S_IFSOCK, mode, 1, ctx->uid, ctx->gid);
	} else {
		UNLOCK(parent_inode_lock);
		UNLOCK(file_inode_lock);

		return -EOPNOTSUPP;
	}

	// Update open count
	out_inode->open_count++;

	if (write_inode(ino, out_inode) < 0) {
		perror("Cannot write inode");

		free_split_path(&p);

		UNLOCK(parent_inode_lock);
		UNLOCK(file_inode_lock);

		return -EIO;
	}

	printf("\tWrote file inode ino: %ld to parent ino: %ld\n", ino, parent_inode.ino);

	if (dir_add(&parent_inode, ino, base, strlen(base)) < 0) {
		perror("Cannot add dirent entry");

		free_split_path(&p);

		UNLOCK(parent_inode_lock);
		UNLOCK(file_inode_lock);

		return -EIO;
	}

	printf("\tAdded file entry ino: %ld to parent ino: %ld\n", ino, parent_inode.ino);

	free_split_path(&p);

	UNLOCK(parent_inode_lock);
	UNLOCK(file_inode_lock);

	printf("[make_file] Done.\n\n");

	return 0;
}

/**
 * Write content into a file
 */
int file_write(struct inode* finode, const char* buffer, size_t size, off_t offset) {
	printf("[file_write] ino: %ld | size: %zu | offset: %u\n", finode->ino, size, offset);

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
		return -ENOMEM;
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

				return bytes_written == 0 ? -ENOMEM : bytes_written;
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

/**
 * Read content from a file
 */
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

					return bytes_read == 0 ? -ENOMEM : bytes_read;
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

		return -ENOMEM;
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

	struct inode root_inode = make_inode(ROOT_INO, S_IFDIR, 0755, 1, ctx->uid, ctx->gid);

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

	// MUST HAVE THIS
	// OTHERWISE stat() will report different inode numbers for hard links even if they are the same in FS
	// Due to getattr will ignore st_ino field if use_ino is not given
	fconfig->use_ino = 1;

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

	fclose(thread_log_fd);

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

	pthread_rwlock_t* inode_lock = get_inode_lock(finode.ino);
	
	RD_LOCK(inode_lock, "myfs_getattr");

	if (finode.valid == 0) {
		UNLOCK(inode_lock);

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

	printf("\tPath: %s | Mode: %05o | ino: %lu (assigned: %lu) | nlink: %d | dir: %d\n", path, finode.mode & 07777, (unsigned long)finode.ino, (unsigned long)st_buf->st_ino, finode.nlink, IS_DIR(finode));

	printf("[myfs_getattr] Done.\n\n");

	UNLOCK(inode_lock);

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

	pthread_rwlock_t* inode_lock = get_inode_lock(dir_inode.ino);
	
	RD_LOCK(inode_lock, "opendir");

	if (dir_inode.valid == 0) {
		UNLOCK(inode_lock);

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
	mode_t perm = get_perm_by_inode(&dir_inode);

	// Check permission bit
	if (need_read && !PERM_CAN_READ(perm) && uid != 0) {
		UNLOCK(inode_lock);

		return -EACCES;
	}

	if (need_write && !PERM_CAN_WRITE(perm) && uid != 0) {
		UNLOCK(inode_lock);

		return -EACCES;
	}

	dir_inode.open_count++;

	if (write_inode(dir_inode.ino, &dir_inode) < 0) {
		UNLOCK(inode_lock);

		perror("Cannot write inode");

		return -EIO;
	}

	printf("\tino: %ld -- open counts = %u\n", dir_inode.ino, dir_inode.open_count);

	// Save inode number of this dir into *fh struct of fuse_file_info
	struct file_handler* fh = malloc(sizeof(*fh));

	fh->ino = dir_inode.ino;
	fh->flags = fi->flags;

	fi->fh = (uint64_t)fh;

	printf("[myfs_opendir] Done.\n\n");

	UNLOCK(inode_lock);

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

	pthread_rwlock_t* inode_lock = get_inode_lock(dir_inode.ino);

	RD_LOCK(inode_lock, "readdir");

	if (dir_inode.valid == 0) {
		UNLOCK(inode_lock);

		perror("Dir is not valid");
		return -ENOENT;
	}
	
	// Figure out how many struct dirent can be put into a block
	int num_dirent_per_block = BLOCK_SIZE / sizeof(struct dirent);
	
	struct dirent* block_buffer = (struct dirent*)malloc(BLOCK_SIZE);
	
	if (block_buffer == NULL) {
		UNLOCK(inode_lock);

		perror("Cannt allocate memory");

		return -ENOSPC;
	}

	struct dirent entry = { 0 };

	int total_dirent_read = 0;
	
	int b = 0;
	
	struct stat* st_buf = (struct stat*)malloc(sizeof(struct stat));

	if (st_buf == NULL) {
		UNLOCK(inode_lock);

		return -ENOSPC;
	}

	// Read from direct first
	for(; b < DIRECT_PTRS_COUNT; ++b) {
		if (dir_inode.directs[b] < 0) continue;
		
		if (block_read(dir_inode.directs[b], block_buffer) < 0) {
			UNLOCK(inode_lock);

			perror("Cannot read block");

			free(block_buffer);

			return -EIO;
		}

		for (int i = 0; i < num_dirent_per_block; ++i) {
			entry = block_buffer[i];

			if (entry.valid == 1) {
				printf("\tItem[%d]: %s\n", i, entry.name);

				memset(st_buf, 0, sizeof(struct stat));

				st_buf->st_ino = entry.ino;

				if (filler(buffer, entry.name, st_buf, 0, 0) != 0) {
					UNLOCK(inode_lock);

					perror("filler");
					
					free(block_buffer);
					free(st_buf);

					return -ENOMEM;
				}
			}
		}
	}

	// TODO: read from indirect ptr

	free(block_buffer);
	free(st_buf);

	printf("[myfs_readdir] Done.\n\n");

	UNLOCK(inode_lock);

	return 0;	
}

static int myfs_mkdir(const char* path, mode_t mode) {
	printf("[myfs_mkdir] path: %s | mode: %o\n", path, mode);

	assert(path != NULL);
	assert(ROOT_INO >= 0);

	pthread_rwlock_t* parent_inode_lock, *dir_inode_lock;

	struct path_split ps = { 0 };

	if (split_path(path, &ps) < 0) {
		return -ENOMEM;
	}

	char *dir = ps.dir;
	char *base = ps.base;

	printf("\tDir %s | Base: %s\n", dir, base);

	struct inode parent_inode = { 0 };

	int node_res;

	if ((node_res = get_node_by_path(dir, ROOT_INO, &parent_inode)) < 0) {
		free_split_path(&ps);

		return node_res;
	}

	parent_inode_lock = get_inode_lock(parent_inode.ino);

	WR_LOCK(parent_inode_lock, "mkdir");

	if (parent_inode.valid == 0) {
		free_split_path(&ps);

		return -ENOENT;
	}
	
	// Check if the target directory already exists
	if (dir_find(parent_inode.ino, base, strlen(base), NULL) == 0) {
		free_split_path(&ps);

		return -EEXIST;
	}

	// Check if user has write permission
	struct fuse_context* ctx = fuse_get_context();

	assert(ctx != NULL);

	uid_t uid = ctx->uid;

	mode_t perm = get_perm_by_inode(&parent_inode);

	if (!PERM_CAN_WRITE(perm) && !IS_ROOT(uid)) {
		return -EACCES;
	}

	// Get next available inode number for this new directory
	int ino = get_avail_ino();

	if (ino < 0) {
		free_split_path(&ps);

		UNLOCK(parent_inode_lock);

		return -ENOSPC;
	}

	dir_inode_lock = get_inode_lock(ino);

	WR_LOCK(dir_inode_lock, "mkdir");

	struct inode new_dir_inode = make_inode(ino, S_IFDIR, mode, 2, ctx->uid, ctx->gid);

	if (write_inode(ino, &new_dir_inode) < 0) {
		free_split_path(&ps);

		UNLOCK(parent_inode_lock);
		UNLOCK(dir_inode_lock);

		perror("Cannot write inode");

		return -EIO;
	}

	printf("\tWrote new dir inode\n");
	
	if (dir_add(&new_dir_inode, ino, ".", 1) < 0) {
		free_split_path(&ps);

		UNLOCK(parent_inode_lock);
		UNLOCK(dir_inode_lock);

		perror("Cannot add dirent");

		return -EIO;
	}

	printf("\tWrote '.' entry to new dir inode\n");
	
	if (dir_add(&new_dir_inode, parent_inode.ino, "..", 2) < 0) {
		free_split_path(&ps);

		UNLOCK(parent_inode_lock);
		UNLOCK(dir_inode_lock);

		perror("Cannot add dirent");
		
		return -EIO;
	}

	printf("\tWrote '..' entry to new dir inode\n");
	
	if (dir_add(&parent_inode, ino, base, strlen(base)) < 0) {
		free_split_path(&ps);

		UNLOCK(parent_inode_lock);
		UNLOCK(dir_inode_lock);

		perror("Cannot add dirent");

		return -EIO;
	}

	printf("\tWrote dir entry to parent dir inode\n");

	// Update nlink for parent inode
	parent_inode.nlink++;

	if (write_inode(parent_inode.ino, &parent_inode) < 0) {
		free_split_path(&ps);

		UNLOCK(parent_inode_lock);
		UNLOCK(dir_inode_lock);

		return -EIO;
	}
	
	free_split_path(&ps);

	UNLOCK(parent_inode_lock);
	UNLOCK(dir_inode_lock);

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

	pthread_rwlock_t* file_inode_lock = get_inode_lock(finode.ino);

	WR_LOCK(file_inode_lock, "open");

	if (finode.valid == 0) {
		UNLOCK(file_inode_lock);

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
	mode_t perm = get_perm_by_inode(&finode);

	// Check permission bit
	if (need_read && !PERM_CAN_READ(perm)) {
		UNLOCK(file_inode_lock);

		return -EACCES;
	}

	if (need_write && !PERM_CAN_WRITE(perm)) {
		UNLOCK(file_inode_lock);

		return -EACCES;
	}

	// Update open count
	finode.open_count++;

	if (write_inode(finode.ino, &finode) < 0) {
		UNLOCK(file_inode_lock);

		perror("Cannot write inode");

		return -EIO;
	}

	printf("\tino: %ld -- open counts = %u\n", finode.ino, finode.open_count);

	struct file_handler* fh = malloc(sizeof(*fh));

	if (fh == NULL) {
		UNLOCK(file_inode_lock);

		return -ENOMEM;
	}

	fh->ino = finode.ino;
	fh->flags = fi->flags;

	fi->fh = (uint64_t)fh;

	UNLOCK(file_inode_lock);

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

	printf("\tFH ino: %ld\n", fh->ino);

	pthread_rwlock_t* file_inode_lock = get_inode_lock(fh->ino);

	WR_LOCK(file_inode_lock, "read");

	if (read_inode(fh->ino, &finode) < 0) {
		UNLOCK(file_inode_lock);

		perror("Cannot read inode");

		return -ENOENT;
	}

	printf("\tRead inode with ino: %ld\n", fh->ino);

	if (finode.type != __S_IFREG) {
		UNLOCK(file_inode_lock);

		perror("Not a file");

		return -EISDIR;
	}

	if (finode.valid == 0) {
		UNLOCK(file_inode_lock);

		perror("File is not valid");

		return -ENOENT;
	}

	printf("\tReading file (%zu) of size: %u | offset: %ld\n", finode.size, size, offset);

	int res;

	if ((res = file_read(&finode, buffer, size, offset)) < 0) {
		UNLOCK(file_inode_lock);

		return res;
	}

	UNLOCK(file_inode_lock);

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

	printf("\tFH ino: %ld\n", fh->ino);

	pthread_rwlock_t* file_inode_lock = get_inode_lock(fh->ino);

	WR_LOCK(file_inode_lock, "write");

	if (read_inode(fh->ino, &finode) < 0) {
		UNLOCK(file_inode_lock);

		perror("Cannot read inode");

		return -ENOENT;
	}

	printf("\tRead inode with ino: %ld\n", fh->ino);

	if (finode.type != __S_IFREG) {
		UNLOCK(file_inode_lock);

		perror("Not a file");

		return -EISDIR;
	}

	if (finode.valid == 0) {
		UNLOCK(file_inode_lock);

		perror("File is not valid");

		return -ENOENT;
	}

	int res = 0;

	if ((res = file_write(&finode, buffer, size, (fi->flags & O_APPEND != 0) ? finode.size : offset)) < 0) {
		UNLOCK(file_inode_lock);

		return res;
	}

	UNLOCK(file_inode_lock);

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

static int myfs_rename(const char* source_path, const char* target_path, unsigned int flag) {
	assert(source_path != NULL);
	assert(target_path != NULL);
	assert(ROOT_INO != -1);

	printf("[myfs_rename] source path: %s | target path : %s | flags = %u\n", source_path, target_path, flag);

	pthread_rwlock_t 
		*source_parent_ilock = NULL, 
		*target_parent_ilock = NULL, 
		*source_inode_ilock = NULL, 
		*target_inode_ilock = NULL;

	struct path_split source_p = { 0 };
	struct path_split target_p = { 0 };
	
	if (split_path(source_path, &source_p) < 0) return -ENOMEM;
	if (split_path(target_path, &target_p) < 0) {
		free_split_path(&source_p);
		return -ENOMEM;
	}

	char* source_dir = source_p.dir;
	char* source_base = source_p.base;

	char* target_dir = target_p.dir;
	char* target_base = target_p.base;

	if (IS_STR_EMPTY(source_base) || IS_STR_EMPTY(target_base)) {
		perror("Cannot rename - source or target has no specified name");

		free_split_path(&source_p);
		free_split_path(&target_p);

		return -EINVAL;
	}

	// Look up parents of both source and target
	struct inode source_parent = { 0 };

	if (get_node_by_path(source_dir, ROOT_INO, &source_parent) < 0) {
		free_split_path(&source_p);
		free_split_path(&target_p);

		return -ENOENT;
	}

	// Obtain lock on working inodes
	source_parent_ilock = get_inode_lock(source_parent.ino);

	// Since the parent inodes will be updated, using write lock
	WR_LOCK(source_parent_ilock, "rename");

	// Check if parent is a valid directory
	if (!IS_DIR(source_parent)) {
		free_split_path(&source_p);
		free_split_path(&target_p);

		UNLOCK(source_parent_ilock);

		return -ENOTDIR;
	}

	struct inode target_parent = { 0 };

	if (get_node_by_path(target_dir, ROOT_INO, &target_parent) < 0) {
		free_split_path(&source_p);
		free_split_path(&target_p);

		UNLOCK(source_parent_ilock);

		return -ENOENT;
	}

	// In case of two parents are the same (mv in the same directory)
	// Having another on target parent will introduce deadlock
	if (target_parent.ino != source_parent.ino) {
		target_parent_ilock = get_inode_lock(target_parent.ino);

		WR_LOCK(target_parent_ilock, "rename");	
	}

	// Check if the target parent is a valid directory
	if (!IS_DIR(target_parent)) {
		free_split_path(&source_p);
		free_split_path(&target_p);

		UNLOCK(source_parent_ilock);
		if (target_parent_ilock != NULL) UNLOCK(target_parent_ilock);

		return -ENOTDIR;
	}

	struct fuse_context* ctx = fuse_get_context();

	assert(ctx != NULL);

	uid_t uid = ctx->uid;
	gid_t gid = ctx->gid;

	// Check permissions
	// Since we want to write into source parent inode, thus we need write and execute permissions
	if (!check_permissions(&source_parent, P_WX) && !IS_ROOT(uid)) {
		free_split_path(&source_p);
		free_split_path(&target_p);

		UNLOCK(source_parent_ilock);
		if (target_parent_ilock != NULL) UNLOCK(target_parent_ilock);

		return -EACCES;
	}

	// Same as target parent inode
	if (!check_permissions(&target_parent, P_WX) && !IS_ROOT(uid)) {
		free_split_path(&source_p);
		free_split_path(&target_p);

		UNLOCK(source_parent_ilock);
		if (target_parent_ilock != NULL) UNLOCK(target_parent_ilock);

		return -EACCES;
	}

	// Find source entry, make sure it exists
	struct dirent source_entry = { 0 };

	int res = 0;

	if ((res = dir_find(source_parent.ino, source_base, strlen(source_base), &source_entry)) < 0) {
		free_split_path(&source_p);
		free_split_path(&target_p);

		UNLOCK(source_parent_ilock);
		if (target_parent_ilock != NULL) UNLOCK(target_parent_ilock);
	
		return res;
	}

	// Obtain source inode
	struct inode source_inode = { 0 };

	if ((res = read_inode(source_entry.ino, &source_inode)) < 0) {
		free_split_path(&source_p);
		free_split_path(&target_p);

		UNLOCK(source_parent_ilock);
		if (target_parent_ilock != NULL) UNLOCK(target_parent_ilock);

		return res;
	}

	source_inode_ilock = get_inode_lock(source_inode.ino);

	WR_LOCK(source_inode_ilock, "rename");

	// Check for sticky behavior
	if (IS_DIR_STICKY(source_parent)) {
		if (
			!IS_ROOT(uid) && 			// user is not the root user
			uid != source_parent.uid && // user does not own the source directory
			uid != source_inode.uid 	// user does not own the source file
		) {
			free_split_path(&source_p);
			free_split_path(&target_p);


			UNLOCK(source_parent_ilock);
			if (target_parent_ilock != NULL) UNLOCK(target_parent_ilock);
			UNLOCK(source_inode_ilock);

			return -EPERM;
		}
	}

	// Lookup destination
	struct dirent target_entry = { 0 };
	struct inode target_inode = { 0 };

	// Does the target exist in the target directory already?
	bool target_exist = false;

	if ((res = dir_find(target_parent.ino, target_base, strlen(target_base), &target_entry)) < 0) {
		if (res != -ENOENT) {
			free_split_path(&source_p);
			free_split_path(&target_p);

			UNLOCK(source_parent_ilock);
			if (target_parent_ilock != NULL) UNLOCK(target_parent_ilock);
			UNLOCK(source_inode_ilock);

			return res;
		}

		target_exist = false;
	} else {
		target_exist = true;
	}

	if (target_exist) {
		target_inode_ilock = get_inode_lock(target_inode.ino);

		WR_LOCK(target_inode_ilock, "rename");

		if ((res = read_inode(target_entry.ino, &target_inode)) < 0) {
			free_split_path(&source_p);
			free_split_path(&target_p);

			UNLOCK(source_parent_ilock);
			if (target_parent_ilock != NULL) UNLOCK(target_parent_ilock);
			UNLOCK(source_inode_ilock);
			if (target_inode_ilock != NULL) UNLOCK(target_inode_ilock);
	
			return res;
		}

		// Check for sticky behavior on the target directory
		// since we're about to removing and replace entry in this directory
		if (IS_DIR_STICKY(target_parent)) {
			if (
				!IS_ROOT(uid) &&			// user is not root
				uid != target_parent.uid &&	// user does not own the target directory
				uid != target_inode.uid		// user does not own the target entry
			) {
				free_split_path(&source_p);
				free_split_path(&target_p);
	
				UNLOCK(source_parent_ilock);
				if (target_parent_ilock != NULL) UNLOCK(target_parent_ilock);
				UNLOCK(source_inode_ilock);
				if (target_inode_ilock != NULL) UNLOCK(target_inode_ilock);

				return -EPERM;
			}
		}

		// Check for compatibility
		// you can't rename a file into a directory or vice versa
		if (IS_DIR(source_inode) && !IS_DIR(target_inode)) {
			free_split_path(&source_p);
			free_split_path(&target_p);

			UNLOCK(source_parent_ilock);
			if (target_parent_ilock != NULL) UNLOCK(target_parent_ilock);
			UNLOCK(source_inode_ilock);
			if (target_inode_ilock != NULL) UNLOCK(target_inode_ilock);

			return -ENOTDIR;
		}

		if (!IS_DIR(source_inode) && IS_DIR(target_inode)) {
			free_split_path(&source_p);
			free_split_path(&target_p);

			UNLOCK(source_parent_ilock);
			if (target_parent_ilock != NULL) UNLOCK(target_parent_ilock);
			UNLOCK(source_inode_ilock);
			if (target_inode_ilock != NULL) UNLOCK(target_inode_ilock);

			return -EISDIR;
		}

		// Since we want to replace entry and if that entry is a dir, the target directory must be empty
		if (IS_DIR(target_inode) && dir_entry_count(&target_inode) > 2) {
			free_split_path(&source_p);
			free_split_path(&target_p);

			UNLOCK(source_parent_ilock);
			if (target_parent_ilock != NULL) UNLOCK(target_parent_ilock);
			UNLOCK(source_inode_ilock);
			if (target_inode_ilock != NULL) UNLOCK(target_inode_ilock);

			return -ENOTEMPTY;
		}
	}

	// For source entry
	// If source entry is a folder, we can't move the source entry (a dir) into its own subtree
	if (IS_DIR(source_inode)) {
		// Ex: c has structure like this
		// c:
		// 	--> b
		//	--> d/e
		// we can't do "rename c -> c/d/e/<new_c>"
		if (source_parent.ino != target_parent.ino) {
			if (is_descendant(&target_parent, &source_inode)) {
				free_split_path(&source_p);
				free_split_path(&target_p);

				UNLOCK(source_parent_ilock);
				if (target_parent_ilock != NULL) UNLOCK(target_parent_ilock);
				UNLOCK(source_inode_ilock);
				if (target_inode_ilock != NULL) UNLOCK(target_inode_ilock);

				return -EINVAL;
			}
		}
	}

	// If rename cross-directory, user must own the source directory (in case of directory)
	if (IS_DIR(source_inode) && source_parent.ino != target_parent.ino) {
		if (
			!IS_ROOT(uid) &&
			uid != source_inode.uid
		) {
			free_split_path(&source_p);
			free_split_path(&target_p);

			UNLOCK(source_parent_ilock);
			if (target_parent_ilock != NULL) UNLOCK(target_parent_ilock);
			UNLOCK(source_inode_ilock);
			if (target_inode_ilock != NULL) UNLOCK(target_inode_ilock);

			return -EACCES;
		}
	}

	// All checks are good, perform rename
	if (target_exist) {
		assert(target_inode.ino != 0);

		// Remove target entry from target directory
		if ((res = dir_remove(&target_parent, &target_inode, target_base)) < 0) {
			free_split_path(&source_p);
			free_split_path(&target_p);

			UNLOCK(source_parent_ilock);
			if (target_parent_ilock != NULL) UNLOCK(target_parent_ilock);
			UNLOCK(source_inode_ilock);
			if (target_inode_ilock != NULL) UNLOCK(target_inode_ilock);

			return res;
		}

		// Update nlink
		target_inode.nlink--;

		if (write_inode(target_inode.ino, &target_inode) < 0) {
			free_split_path(&source_p);
			free_split_path(&target_p);

			UNLOCK(source_parent_ilock);
			if (target_parent_ilock != NULL) UNLOCK(target_parent_ilock);
			UNLOCK(source_inode_ilock);
			if (target_inode_ilock != NULL) UNLOCK(target_inode_ilock);

			return -EIO;
		}

		if (target_inode.nlink <= 0 && target_inode.open_count <= 0) {
			// remove inode
			if ((res = free_inode(target_inode.ino)) < 0) {
				free_split_path(&source_p);
				free_split_path(&target_p);

				UNLOCK(source_parent_ilock);
				if (target_parent_ilock != NULL) UNLOCK(target_parent_ilock);
				UNLOCK(source_inode_ilock);
				if (target_inode_ilock != NULL) UNLOCK(target_inode_ilock);

				return res;
			}
		}
	}

	uint32_t s = source_parent.size;

	// Remove source entry from source parent
	if ((res = dir_remove(&source_parent, &source_inode, source_base)) < 0) {
		free_split_path(&source_p);
		free_split_path(&target_p);

		UNLOCK(source_parent_ilock);
		if (target_parent_ilock != NULL) UNLOCK(target_parent_ilock);
		UNLOCK(source_inode_ilock);
		if (target_inode_ilock != NULL) UNLOCK(target_inode_ilock);

		return res;
	}

	// Add new entry into target parent
	uint32_t a = target_parent.size;

	if ((res = dir_add(&target_parent, source_inode.ino, target_base, strlen(target_base))) < 0) {
		free_split_path(&source_p);
		free_split_path(&target_p);

		UNLOCK(source_parent_ilock);
		if (target_parent_ilock != NULL) UNLOCK(target_parent_ilock);
		UNLOCK(source_inode_ilock);
		if (target_inode_ilock != NULL) UNLOCK(target_inode_ilock);

		return res;
	}

	// If cross directory rename
	// then update ".." to point to target dir
	if (IS_DIR(source_inode) && source_parent.ino != target_parent.ino) {
		if ((res = dir_update_dotdot(&source_inode, &target_parent)) < 0) {
			free_split_path(&source_p);
			free_split_path(&target_p);

			UNLOCK(source_parent_ilock);
			if (target_parent_ilock != NULL) UNLOCK(target_parent_ilock);
			UNLOCK(source_inode_ilock);
			if (target_inode_ilock != NULL) UNLOCK(target_inode_ilock);

			return res;
		}
	}

	free_split_path(&source_p);
	free_split_path(&target_p);

	UNLOCK(source_parent_ilock);
	if (target_parent_ilock != NULL) UNLOCK(target_parent_ilock);
	UNLOCK(source_inode_ilock);
	if (target_inode_ilock != NULL) UNLOCK(target_inode_ilock);

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

	pthread_rwlock_t* dir_inode_lock, *parent_inode_lock;

	struct inode dir_inode = { 0 };

	int node_res;

	if ((node_res = get_node_by_path(path, ROOT_INO, &dir_inode)) < 0) {
		return node_res;
	}

	dir_inode_lock = get_inode_lock(dir_inode.ino);

	WR_LOCK(dir_inode_lock, "rmdir");

	// Check if this is a directory
	if (dir_inode.type != S_IFDIR) {
		UNLOCK(dir_inode_lock);

		return -ENOTDIR;
	}

	// Can only delete empty dir
	// Check if dir is empty
	if (dir_entry_count(&dir_inode) > 2) {
		UNLOCK(dir_inode_lock);

		return -ENOTEMPTY;
	}

	printf("\tdir is a valid empty directory\n");

	struct path_split p = { 0 };

	if (split_path(path, &p) < 0) {
		UNLOCK(dir_inode_lock);

		return -ENOMEM;
	}

	char* base = p.base;
	char* dir = p.dir;

	struct inode parent_inode = { 0 };

	if ((node_res = get_node_by_path(dir, ROOT_INO, &parent_inode)) < 0) {
		perror("Cannot read inode");

		UNLOCK(dir_inode_lock);

		free_split_path(&p);

		return -ENOENT;
	}

	parent_inode_lock = get_inode_lock(parent_inode.ino);

	WR_LOCK(parent_inode_lock, "rmdir");

	printf("\tParent inode: %d\n", parent_inode.ino);

	// Check if user has permission on parent dir to remove (write permission)
	struct fuse_context* ctx = fuse_get_context();

	assert(ctx != NULL);

	mode_t perm = get_perm_by_inode(&parent_inode);

	if (!PERM_CAN_WRITE(perm) && ctx->uid != 0) {
		free_split_path(&p);

		UNLOCK(dir_inode_lock);
		UNLOCK(parent_inode_lock);

		return -EACCES;
	}

	// If the directory is to be "sticky", then only owner of the entry being deleted or
	// owner of the parent dir of the being deleted entry or root can perform rmdir
	if (parent_inode.mode & S_ISVTX) {
		if (ctx->uid != parent_inode.uid && ctx->uid != dir_inode.uid && ctx->uid != 0) {
			free_split_path(&p);

			UNLOCK(dir_inode_lock);
			UNLOCK(parent_inode_lock);

			return -EPERM;
		}
	}

	// Remove dir entry from parent
	if (dir_remove(&parent_inode, &dir_inode, base) < 0) {
		perror("Cannot remove dir entry from parent");

		free_split_path(&p);

		UNLOCK(dir_inode_lock);
		UNLOCK(parent_inode_lock);

		return -EIO;
	}

	// Update parent nlink
	parent_inode.nlink--;

	if (write_inode(parent_inode.ino, &parent_inode) < 0) {
		UNLOCK(dir_inode_lock);
		UNLOCK(parent_inode_lock);

		return -EIO;
	}

	free_split_path(&p);

	// reset data block if it has any allocated data blocks
	if (reset_ino(dir_inode.ino) < 0) {
		UNLOCK(dir_inode_lock);
		UNLOCK(parent_inode_lock);

		return -EIO;
	}

	UNLOCK(dir_inode_lock);
	UNLOCK(parent_inode_lock);

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

	pthread_rwlock_t* finode_lock = get_inode_lock(fh->ino);

	WR_LOCK(finode_lock, "releasedir");

	if (read_inode(fh->ino, &finode) < 0) {
		UNLOCK(finode_lock);

		perror("Cannot read inode");

		return -ENOENT;
	}

	printf("\tRead inode with ino: %ld\n", fh->ino);

	// Update open count
	finode.open_count--;

	if (write_inode(finode.ino, &finode) < 0) {
		UNLOCK(finode_lock);

		perror("Cannot write inode");

		return -EIO;
	}

	fi->fh = 0;

	free((void*)fi->fh);

	UNLOCK(finode_lock);

	printf("[myfs_releasedir] Done.\n\n");

	return 0;
}

static int myfs_unlink(const char* path) {
	assert(path != NULL);
	assert(ROOT_INO != -1);

	printf("[myfs_unlink] path: %s\n", path);

	if (strcmp(path, "/") == 0) {
		perror("Cannot remove root directory");

		return -EBUSY;
	}

	pthread_rwlock_t* finode_lock, *parent_inode_lock;

	struct inode f_inode = { 0 };

	int node_res;

	if ((node_res = get_node_by_path(path, ROOT_INO, &f_inode)) < 0) {
		return node_res;
	}

	finode_lock = get_inode_lock(f_inode.ino);

	WR_LOCK(finode_lock, "unlink");

	// Check if this is a file or a softlink
	if (f_inode.type == S_IFDIR) {
		UNLOCK(finode_lock);

		return -EPERM;
	}

	printf("\t File is a valid file to be removed\n");

	struct path_split p = { 0 };

	if (split_path(path, &p) < 0) {
		UNLOCK(finode_lock);

		return -ENOMEM;
	}

	char* base = p.base;
	char* dir = p.dir;

	struct inode parent_inode = { 0 };

	if (get_node_by_path(dir, ROOT_INO, &parent_inode) < 0) {
		perror("Cannot read inode");

		free_split_path(&p);

		UNLOCK(finode_lock);

		return -ENOENT;
	}

	parent_inode_lock = get_inode_lock(parent_inode.ino);

	WR_LOCK(parent_inode_lock, "unlink");

	printf("\tParent inode: %d\n", parent_inode.ino);

	// Check if have "w" permission to unlink
	// In case the parent inode has sticky bit presents, then user must own the file or own the directory or be root user
	struct fuse_context* ctx = fuse_get_context();
	
	mode_t perm = get_perm_by_inode(&parent_inode);

	if (!PERM_CAN_WRITE(perm) && ctx->uid != 0) {
		printf("\tDir does not have write permission - Perm: %05o | Owner is: %d | User is: %d\n", parent_inode.mode, parent_inode.uid, ctx->uid);

		free_split_path(&p);

		UNLOCK(finode_lock);
		UNLOCK(parent_inode_lock);

		return -EACCES;
	}

	if (STICKY_MODE(parent_inode.mode)) {
		if (ctx->uid != f_inode.uid && ctx->uid != parent_inode.uid && ctx->uid != 0) {
			free_split_path(&p);

			UNLOCK(finode_lock);
			UNLOCK(parent_inode_lock);

			return -EPERM;
		}
	}

	// Remove file entry from parent dir
	if (dir_remove(&parent_inode, &f_inode, base) < 0) { //
		perror("Cannot remove file entry from parent");

		free_split_path(&p);

		UNLOCK(finode_lock);
		UNLOCK(parent_inode_lock);

		return -EIO;
	}

	// Update nlink of f_inode
	f_inode.nlink--;

	if (write_inode(f_inode.ino, &f_inode) < 0) {
		free_split_path(&p);

		UNLOCK(finode_lock);
		UNLOCK(parent_inode_lock);
		
		return -EIO;
	}

	free_split_path(&p);

	// Check if nlink == 0 && open count == 0
	// If nlink is 0 and open count is 0, remove the file content
	// Simply returns its data blocks back to the file system
	printf("\tino: %ld -- nlink = %u | open count = %u\n", f_inode.nlink, f_inode.open_count);
	
	if (f_inode.nlink <= 0 && f_inode.open_count <= 0) {
		printf("\tFile ino: %ld has 0 nlink, remove its data blocks\n", f_inode.ino);

		for (int i = 0; i < DIRECT_PTRS_COUNT; ++i) {
			if (f_inode.directs[i] >= 0) {
				if (reset_data_block(f_inode.directs[i]) < 0) {
					printf("\treset_data_block\n");

					perror("Cannot reset data block");

					UNLOCK(finode_lock);
					UNLOCK(parent_inode_lock);

					return -EIO;
				}
			}
		}

		printf("\tReset data block directs\n");

		if (f_inode.indirect_ptr >= 0) {
			int* buf = (int*)malloc(BLOCK_SIZE);
			int num_blk = BLOCK_SIZE / sizeof(int);

			if (buf == NULL) {
				UNLOCK(finode_lock);
				UNLOCK(parent_inode_lock);

				return -ENOSPC;
			}

			if (block_read(f_inode.indirect_ptr, buf) < 0) {
				printf("\tblock_read\n");

				perror("Cannot read block");

				UNLOCK(finode_lock);
				UNLOCK(parent_inode_lock);

				return -EIO;
			}

			for (int i = 0; i < num_blk; ++i) {
				if (buf[i] < 0) continue;

				if (reset_data_block(buf[i]) < 0) {
					printf("\treset_data_block_2\n");

					perror("Cannot reset data block");

					UNLOCK(finode_lock);
					UNLOCK(parent_inode_lock);

					return -EIO;
				}
			}

			printf("\tReset data block indirects\n");
		}

		// reset inode
		if (reset_ino(f_inode.ino) < 0) {
			printf("\treset_inode\n");

			perror("Cannot reset inode");

			UNLOCK(finode_lock);
			UNLOCK(parent_inode_lock);

			return -EIO;
		}
	}

	UNLOCK(finode_lock);
	UNLOCK(parent_inode_lock);

	printf("[myfs_unlink] Done.\n\n");

	return 0;
}

static int myfs_truncate(const char *path, off_t size, struct fuse_file_info *fi) {
	assert(path != NULL);
	assert(size >= 0);
	assert(ROOT_INO != -1);
	
	printf("[myfs_truncate] path: %s | size: %ld\n", path, size);

	pthread_rwlock_t* finode_lock;

	struct inode f_inode = { 0 };

	struct file_handler* fh = NULL;

	if (fi != NULL && fi->fh != 0) {
		fh = (struct file_handler*)fi->fh;

		printf("\tFH ino: %ld\n", fh->ino);

		finode_lock = get_inode_lock(fh->ino);

		WR_LOCK(finode_lock, "truncate");

		if (read_inode(fh->ino, &f_inode) == -1) {
			UNLOCK(finode_lock);

			return -ENOENT;
		}
	} else {
		int node_res;

		if ((node_res = get_node_by_path(path, ROOT_INO, &f_inode)) < 0) {
			return node_res;
		}

		finode_lock = get_inode_lock(fh->ino);

		WR_LOCK(finode_lock, "truncate");
	}

	// If file is opened
	if (fh != NULL) {
		int access_mode = fh->flags & O_ACCMODE;
		bool can_write = (access_mode == O_WRONLY) || (access_mode == O_RDWR);

		printf("\tO_WRONLY: %d | O_RDWR: %d\n", access_mode == O_WRONLY, access_mode == O_RDWR);
		printf("\tCan write if opened: %d\n", can_write);

		if (!can_write) {
			UNLOCK(finode_lock);

			return -EACCES;
		}
	} else {
		struct fuse_context* ctx = fuse_get_context();

		assert(ctx != NULL);

		uid_t uid = ctx->uid;
		gid_t gid = ctx->gid;

		// Check if it has write permission
		mode_t perm = get_perm_by_inode(&f_inode);

		if (!PERM_CAN_WRITE(perm) && uid != 0) {
			UNLOCK(finode_lock);

			return -EACCES;
		}
	}

	if (f_inode.type == S_IFDIR) {
		UNLOCK(finode_lock);

		return -EISDIR;
	}

	uint32_t MAX_SIZE = DIRECT_PTRS_COUNT * BLOCK_SIZE + (BLOCK_SIZE / sizeof(int)) * BLOCK_SIZE;

	if (size >= MAX_SIZE) {
		UNLOCK(finode_lock);

		return -EFBIG;
	}

	if (f_inode.size == size) {
		printf("\tFile size equals to requested size. Do nothing\n");

		// Do nothing, only update timestamp
		f_inode.atime = now();

		if (write_inode(f_inode.ino, &f_inode) == -1) {
			UNLOCK(finode_lock);

			perror("Cannot write inode");

			return -EIO;
		}

		printf("[myfs_truncate] Done.\n\n");

		UNLOCK(finode_lock);

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

			UNLOCK(finode_lock);

			return -EIO;
		}

		UNLOCK(finode_lock);

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
				UNLOCK(finode_lock);

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
					UNLOCK(finode_lock);

					return -ENOSPC;
				}
			}

			if (block_read(f_inode.indirect_ptr, indirect_buf) < 0) {
				UNLOCK(finode_lock);

				return -EIO;
			}

			if (indirect_buf[blk_off] <= 0) continue;

			if (reset_data_block(indirect_buf[blk_off]) < 0) {
				free(indirect_buf);

				UNLOCK(finode_lock);

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
			UNLOCK(finode_lock);

			perror("Cannot allocate memory");

			return -ENOSPC;
		}

		if (block_read(f_inode.directs[start_removed_blk_idx - 1], buffer) < 0) {
			UNLOCK(finode_lock);

			perror("Cannot read block");

			free(buffer);

			return -EIO;
		}

		memset(buffer + start_removed_blk_offset, 0, BLOCK_SIZE - start_removed_blk_offset);

		printf("\tSet to 0 of data block %d from offset %d | size %d\n", f_inode.directs[start_removed_blk_idx - 1], start_removed_blk_offset, BLOCK_SIZE - start_removed_blk_offset);

		if (block_write(f_inode.directs[start_removed_blk_idx - 1], buffer) < 0) {
			perror("Cannot write block");

			UNLOCK(finode_lock);

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
		UNLOCK(finode_lock);

		perror("Cannot write inode");

		return -EIO;
	}

	UNLOCK(finode_lock);

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

	pthread_rwlock_t* finode_lock;

	struct inode item = { 0 };

	struct file_handler* fh = NULL;

	if (fi != NULL && fi->fh != 0) {
		fh = (struct file_handler*)fi->fh;

		assert(fh != NULL);

		finode_lock = get_inode_lock(fh->ino);

		WR_LOCK(finode_lock, "truncate");

		if (read_inode(fh->ino, &item) < 0) {
			UNLOCK(finode_lock);

			return -ENOENT;
		}
	} else {
		int node_res;

		if ((node_res = get_node_by_path(path, ROOT_INO, &item)) < 0) {
			
			return node_res;
		}

		finode_lock = get_inode_lock(item.ino);

		WR_LOCK(finode_lock, "utimens");
	}

	struct fuse_context* ctx = fuse_get_context();

	assert(ctx != NULL);

	uid_t uid = ctx->uid;
	gid_t gid = ctx->gid;

	bool can_write = false;
	bool owner_or_root = (uid == item.uid) || IS_ROOT(uid);
	
	if (fh != NULL) {
		int access_mode = fh->flags & O_ACCMODE;
		can_write = (access_mode == O_WRONLY) || (access_mode == O_RDWR);		
		
		printf("\tPermissions from fh : can_write: %d\n", can_write);
	} else {
		mode_t perm = get_perm_by_inode(&item);

		can_write = PERM_CAN_WRITE(perm);

		printf("\tPermissions from path-based lookup : can_write: %d\n", can_write);
	}

	struct timespec now;

	clock_gettime(CLOCK_REALTIME, &now);

	// If times is NULL or both times are NOW
	// allowed if owner or root
	if (tv == NULL) {
		if (!owner_or_root && !can_write) {
			UNLOCK(finode_lock);

			return -EACCES;
		}

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
			if (!owner_or_root && !can_write) {
				UNLOCK(finode_lock);

				return -EACCES;
			}

			if (tv[0].tv_nsec == UTIME_NOW) item.atime = now;
			if (tv[1].tv_nsec == UTIME_NOW) item.mtime = now;
		} else {
			if (!owner_or_root) {
				UNLOCK(finode_lock);

				return -EPERM;
			}

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
		UNLOCK(finode_lock);

		perror("Cannot write inode");

		return -EIO;
	}

	UNLOCK(finode_lock);

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

	printf("\tFH ino: %ld\n", fh->ino);

	pthread_rwlock_t* finode_lock = get_inode_lock(fh->ino);

	WR_LOCK(finode_lock, "release");

	if (read_inode(fh->ino, &finode) < 0) {
		UNLOCK(finode_lock);

		perror("Cannot read inode");

		return -ENOENT;
	}

	printf("\tRead inode with ino: %ld | actual: %ld\n", fh->ino, finode.ino);

	// Update open count
	finode.open_count--;

	if (write_inode(finode.ino, &finode) < 0) {
		UNLOCK(finode_lock);

		perror("Cannot write inode");

		return -EIO;
	}
	
	free((void*)fi->fh);

	fi->fh = 0;

	UNLOCK(finode_lock);

	printf("[myfs_release] Done.\n\n");

	return 0;
}

static int myfs_fallocate(const char* path, int mode, off_t offset, off_t len, struct fuse_file_info* fi) {
	assert(path != NULL);
	assert(ROOT_INO != -1);

	printf("[myfs_fallocate] path: %s | mode = %d | offset: %lu | len: %lu\n", path, mode, offset, len);

	pthread_rwlock_t* finode_lock;

	struct inode finode = { 0 }; 

	struct file_handler* fh = NULL;

	if (fi != NULL && fi->fh != 0) {
		fh = (struct file_handler*)fi->fh;

		assert(fh != NULL);

		printf("\tFH ino: %ld\n", fh->ino);

		finode_lock = get_inode_lock(fh->ino);

		WR_LOCK(finode_lock, "fallocate");

		if (read_inode(fh->ino, &finode) < 0) {
			UNLOCK(finode_lock);

			perror("Cannot read inode");
	
			return -ENOENT;
		}
	} else {
		int node_res;

		if ((node_res = get_node_by_path(path, ROOT_INO, &finode)) < 0) {
			return node_res;
		}

		finode_lock = get_inode_lock(finode.ino);

		WR_LOCK(finode_lock, "fallocate");
	}

	int start_blk_idx = offset / BLOCK_SIZE;
	int end_blk_idx = (offset + len) / BLOCK_SIZE;
	int blk, offset_indirect, num_blks_indirect = BLOCK_SIZE / sizeof(int);

	// Assume data size is only in DIRECT
	assert(start_blk_idx < DIRECT_PTRS_COUNT);
	assert(end_blk_idx < DIRECT_PTRS_COUNT);

	int* indirect_buffer = NULL;

	for (int i = start_blk_idx; i <= end_blk_idx; ++i) {
		if (i < DIRECT_PTRS_COUNT) {
			printf("\tAssigning data block in DIRECT region of ino: %ld\n", finode.ino);

			// Region in DIRECT
			if (finode.directs[i] >= 0) {
				printf("\tIno: %ld | blk idx: %d | block: %d has been allocated before\n", finode.ino, i, finode.directs[i]);
	
				// Already assigned
				continue;
			}

			// Assign data block
			blk = get_avail_blkno();

			if (blk < 0) {
				UNLOCK(finode_lock);

				perror("Cannot allocate memory");

				return -ENOSPC;
			}

			finode.directs[i] = blk;

			printf("\tIno: %ld | blk idx: %d | block: %d has been assigned\n", finode.ino, i, blk);
		} else {
			offset_indirect = i - DIRECT_PTRS_COUNT;

			assert(offset_indirect >= 0 && offset_indirect < num_blks_indirect);

			if (finode.indirect_ptr < 0) {
				// Allocate block for indirect pointer
				int blk = get_avail_blkno();

				if (blk < 0) {
					UNLOCK(finode_lock);

					return -ENOSPC;
				}

				finode.indirect_ptr = blk;
			}

			if (indirect_buffer == NULL) {
				// Read data block of indirect ptr
				indirect_buffer = (int*)malloc(BLOCK_SIZE);

				if (indirect_buffer == NULL) {
					UNLOCK(finode_lock);

					return -ENOMEM;
				}

				if (block_read(finode.indirect_ptr, indirect_buffer) < 0) {
					free(indirect_buffer);

					UNLOCK(finode_lock);

					return -EIO;
				}
			}

			// Check if data block has been assigned before
			if (indirect_buffer[offset_indirect] <= 0) {
				// Not yet assigned
				blk = get_avail_blkno();

				if (blk < 0) {
					free(indirect_buffer);

					UNLOCK(finode_lock);

					return -ENOSPC;
				}

				indirect_buffer[offset_indirect] = blk;
			}
		}
	}

	if (indirect_buffer != NULL) {
		// Data is written into indirect, save change
		assert(finode.indirect_ptr > 0);

		if (block_write(finode.indirect_ptr, indirect_buffer) < 0) {
			free(indirect_buffer);

			UNLOCK(finode_lock);

			return -EIO;
		}
	}

	// Save changes in inode
	if (write_inode(finode.ino, &finode) < 0) {
		perror("Cannot write inode");

		UNLOCK(finode_lock);

		return -EIO;
	}

	UNLOCK(finode_lock);

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
	return -EOPNOTSUPP;
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

	struct path_split ps = { 0 };

	if (split_path(link, &ps) < 0) {
		return -ENOMEM;
	}

	char *base = ps.base;
	char *dir = ps.dir;

	printf("\tLink -- Dir: %s | Base: %s\n", dir, base);

	pthread_rwlock_t* parent_inode_lock, *file_inode_lock;

	// Get parent inode and check if the target file is already exist
	struct inode parent_inode = { 0 };

	int node_res;

	if ((node_res = get_node_by_path(dir, ROOT_INO, &parent_inode)) < 0) {
		free_split_path(&ps);
		
		return node_res;
	}

	parent_inode_lock = get_inode_lock(parent_inode.ino);

	WR_LOCK(parent_inode_lock, "symlink");

	if (parent_inode.valid == 0) {
		UNLOCK(parent_inode_lock);

		free_split_path(&ps);

		return -ENOENT;
	}

	// Check if the target file already exists
	if (dir_find(parent_inode.ino, base, strlen(base), NULL) == 0) {
		UNLOCK(parent_inode_lock);

		free_split_path(&ps);

		return -EEXIST;
	}

	// Get the next available inode number for this file
	int ino = get_avail_ino();

	if (ino < 0) {
		free_split_path(&ps);

		UNLOCK(parent_inode_lock);

		return -ENOSPC;
	}

	file_inode_lock = get_inode_lock(ino);

	WR_LOCK(file_inode_lock, "symlink");

	struct fuse_context* ctx = fuse_get_context();

	assert(ctx != NULL);

	uid_t uid = ctx->uid;

	mode_t perm = get_perm_by_inode(&parent_inode);

	if (!PERM_CAN_WRITE(perm) && !IS_ROOT(uid)) {
		UNLOCK(parent_inode_lock);
		UNLOCK(file_inode_lock);

		return -EACCES;
	}

	struct inode new_file_inode = make_inode(ino, __S_IFLNK, 0755, 1, ctx->uid, ctx->gid);

	if (write_inode(ino, &new_file_inode) < 0) {
		perror("Cannot write inode");

		free_split_path(&ps);

		UNLOCK(parent_inode_lock);
		UNLOCK(file_inode_lock);

		return -EIO;
	}

	printf("\tWrote file inode ino: %ld to parent ino: %ld\n", ino, parent_inode.ino);

	if (dir_add(&parent_inode, ino, base, strlen(base)) < 0) {
		perror("Cannot add dirent entry");

		free_split_path(&ps);

		UNLOCK(parent_inode_lock);
		UNLOCK(file_inode_lock);

		return -EIO;
	}

	printf("\tAdded file entry ino: %ld to parent ino: %ld\n", ino, parent_inode.ino);

	printf("\tWriting file path to symlink\n");

	size_t buffer_size = strlen(target) + 1;

	printf("\tPath size in bytes = %zu\n", buffer_size);

	// Path should have length less than a page
	if (buffer_size > BLOCK_SIZE) {
		perror("Path cannot longer than a page");

		free_split_path(&ps);

		UNLOCK(parent_inode_lock);
		UNLOCK(file_inode_lock);

		return -ENOSPC;
	}

	int blk_idx = get_avail_blkno();

	if (blk_idx < 0) {
		free_split_path(&ps);

		UNLOCK(parent_inode_lock);
		UNLOCK(file_inode_lock);

		return -ENOSPC;
	}

	printf("\tAssigned data block %d to symlink file\n", blk_idx);

	new_file_inode.directs[0] = blk_idx;
	new_file_inode.size += buffer_size - 1;

	if (write_inode(new_file_inode.ino, &new_file_inode) < 0) {
		perror("Cannot write inode");

		free_split_path(&ps);

		UNLOCK(parent_inode_lock);
		UNLOCK(file_inode_lock);

		return -EIO;
	}

	// Write path to block
	char* buffer = (char*)malloc(BLOCK_SIZE);

	if (buffer == NULL) {
		perror("Cannot allocate memory");

		free_split_path(&ps);

		UNLOCK(parent_inode_lock);
		UNLOCK(file_inode_lock);

		return -ENOSPC;
	}

	memcpy(buffer, target, buffer_size);

	if (block_write(blk_idx, buffer) < 0) {
		perror("Cannot write block");
		
		free_split_path(&ps);

		free(buffer);

		UNLOCK(parent_inode_lock);
		UNLOCK(file_inode_lock);

		return -EIO;
	}

	printf("\tWrote path to file\n");

	free_split_path(&ps);

	free(buffer);

	UNLOCK(parent_inode_lock);
	UNLOCK(file_inode_lock);

	printf("[myfs_symlink] Done.\n\n");

	return 0;
}

static int myfs_link(const char* target, const char* link) {
	assert(target != NULL);
	assert(link != NULL);
	assert(ROOT_INO != -1);

	printf("[myfs_link] target: %s | link: %s\n", target, link);
	
	struct path_split link_path = { 0 };

	if (split_path(link, &link_path) < 0) return -ENOMEM;

	char *base = link_path.base;

	char *dir = link_path.dir;

	printf("\tLink -- Dir: %s | Base: %s\n", dir, base);

	pthread_rwlock_t* parent_inode_lock, *target_inode_lock;

	struct inode parent_inode = { 0 };

	int node_res;

	if ((node_res = get_node_by_path(dir, ROOT_INO, &parent_inode)) < 0) {
		free_split_path(&link_path);

		return node_res;
	}

	parent_inode_lock = get_inode_lock(parent_inode.ino);

	WR_LOCK(parent_inode_lock, "link");

	if (parent_inode.valid == 0) {
		free_split_path(&link_path);

		UNLOCK(parent_inode_lock);

		return -ENOENT;
	}

	// Check if we have write permission or root user
	struct fuse_context* ctx = fuse_get_context();

	assert(ctx != NULL);

	mode_t perm = get_perm_by_inode(&parent_inode);

	if (!PERM_CAN_WRITE(perm) && ctx->uid != 0) {
		free_split_path(&link_path);

		UNLOCK(parent_inode_lock);

		return -EACCES;
	}

	struct inode target_inode = { 0 };

	if ((node_res = get_node_by_path(target, ROOT_INO, &target_inode)) < 0) {
		free_split_path(&link_path);

		UNLOCK(parent_inode_lock);

		return node_res;
	}

	target_inode_lock = get_inode_lock(target_inode.ino);

	WR_LOCK(target_inode_lock, "link");

	printf("\tTarget ino for hard link is: %ld\n", target_inode.ino);

	if (dir_add(&parent_inode, target_inode.ino, base, strlen(base)) < 0) {
		perror("Cannot add entry to directory");

		free_split_path(&link_path);

		UNLOCK(parent_inode_lock);
		UNLOCK(target_inode_lock);

		return -EIO;
	}

	// Update target nlink
	target_inode.nlink++;

	if (write_inode(target_inode.ino, &target_inode) < 0) {
		free_split_path(&link_path);
		
		UNLOCK(parent_inode_lock);
		UNLOCK(target_inode_lock);
		
		return -EIO;
	}

	free_split_path(&link_path);

	UNLOCK(parent_inode_lock);
	UNLOCK(target_inode_lock);

	printf("[myfs_link] Done.\n\n");

	return 0;
}

static int myfs_readlink(const char* link, char* buffer, size_t len) {
	assert(link != NULL);
	assert(buffer != NULL);
	assert(len > 0);

	printf("[myfs_readlink] link: %s | len: %zu\n", link, len);

	pthread_rwlock_t* link_inode_lock;

	struct inode link_inode = { 0 };

	int node_res;

	if ((node_res = get_node_by_path(link, ROOT_INO, &link_inode)) < 0) {
		return node_res;
	}

	link_inode_lock = get_inode_lock(link_inode.ino);

	RD_LOCK(link_inode_lock, "readlink");

	if (!S_ISLNK(link_inode.mode)) {
		UNLOCK(link_inode_lock);

		return -EINVAL;
	}

	// Should return a flag
	// assert(link_inode.directs[0] >= 0);
	if (link_inode.directs[0] < 0) {
		UNLOCK(link_inode_lock);

		return - EIO;
	}

	char* blk_buffer = (char*)malloc(BLOCK_SIZE);

	if (blk_buffer == NULL) {
		UNLOCK(link_inode_lock);

		perror("Cannot allocate memory");

		return -ENOSPC;
	}

	if (block_read(link_inode.directs[0], blk_buffer) < 0) {
		perror("Cannot read block");

		UNLOCK(link_inode_lock);

		free(blk_buffer);

		return -EIO;
	}

	size_t target_len = (size_t)link_inode.size;

	if (target_len > BLOCK_SIZE) target_len = BLOCK_SIZE;

	size_t n = target_len < (len - 1) ? target_len : len - 1;

	memcpy(buffer, blk_buffer, n);

	buffer[n] = '\0';

	free(blk_buffer);

	UNLOCK(link_inode_lock);

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

	pthread_rwlock_t* finode_lock;

	struct inode item = { 0 };

	int node_res;

	if ((node_res = get_node_by_path(path, ROOT_INO, &item)) < 0) {
		return -ENOENT;
	}

	finode_lock = get_inode_lock(item.ino);

	RD_LOCK(finode_lock, "access");

	if (item.valid == 0) {
		UNLOCK(finode_lock);

		return -ENOENT;
	}

	printf("\tIno: %ld\n", item.ino);

	if (mode == F_OK) {
		// The user wants to know if the file exists
		printf("\tRequest file exist granted\n");

		UNLOCK(finode_lock);

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
		if (PERM_CAN_READ(mode)) {
			UNLOCK(finode_lock);
			return 0;
		}

		break;
	case W_OK:
		// The user who invokes this want to know if they can write this file
		if (PERM_CAN_WRITE(perm)) {
			UNLOCK(finode_lock);
			return 0;
		}

		break;
	case X_OK:
		// The user who invokes this want to know if they can execute this file
		if (PERM_CAN_EXECUTE(perm)) {
			UNLOCK(finode_lock);
			return 0;
		}
		break;
	default:
		break;
	}

	UNLOCK(finode_lock);

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

	pthread_rwlock_t* finode_lock;

	struct inode item = { 0 };

	int node_res;

	if ((node_res = get_node_by_path(path, ROOT_INO, &item)) < 0) {
		return node_res;
	}

	finode_lock = get_inode_lock(item.ino);

	WR_LOCK(finode_lock, "chmod");

	printf("\tIno: %ld | uid: %d | gid: %d\n", item.ino, uid, gid);

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
		if (adding_suid) {
			UNLOCK(finode_lock);

			return -EPERM;
		}

		// Non-owner may add setgid if they belongs to the item's group id and no the bits are changed
		if (adding_sgid) {
			// Not belong to group
			if (gid != item.gid) {
				UNLOCK(finode_lock);
	
				return -EPERM;
			}

			// User change other bits, not allowed
			if (change_non_special) {
				UNLOCK(finode_lock);
	
				return -EPERM;
			}
		} else {
			// Any other normal chmod by non-owner is not allowed
			if (change_non_special) {
				UNLOCK(finode_lock);
	
				return -EPERM;
			}
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
		UNLOCK(finode_lock);

		return -EIO;
	}

	UNLOCK(finode_lock);

	printf("\tAfter perm change: %05o | req perm: %05o\n", item.mode & 07777, req_perm);

	printf("[myfs_chmod] Done.\n\n");

	return 0;
}

static int myfs_chown(const char* path, uid_t uid, gid_t gid, struct fuse_file_info *fi) {
	assert(path != NULL);
	assert(ROOT_INO != -1);
	
	printf("[myfs_chown] path: %s | uid: %d | gid: %d\n", path, uid, gid);

	pthread_rwlock_t* finode_lock;

	struct fuse_context* ctx = fuse_get_context();
	
	assert(ctx != NULL);

	uid_t uuid = ctx->uid;
	gid_t ggid = ctx->gid;

	struct inode item = { 0 };

	int node_res;

	if ((node_res = get_node_by_path(path, ROOT_INO, &item)) < 0) {
		return node_res;
	}

	finode_lock = get_inode_lock(item.ino);

	WR_LOCK(finode_lock, "chown");

	if (uid != (uid_t)-1 && uid != item.uid) {
		// User wish to change uid
		// Only root can change uid
		if (!IS_ROOT(uuid)) {
			UNLOCK(finode_lock);

			return -EPERM;
		}
	}

	if (gid != (gid_t)-1 && gid != item.gid) {
		// User wish to change gid

		// Root can change gid
		// Non-root user can change gid if:
		// - User owns the file AND the group of this item belongs to the user's groups
		// Since FUSE does not provide the list of groups that user belongs to
		// I gotta skip that condition and only check for primary group
		
		if (!IS_ROOT(uuid)) {
			if (uuid != item.uid || ggid != item.gid) {
				UNLOCK(finode_lock);

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
		UNLOCK(finode_lock);

		return -EIO;
	}

	UNLOCK(finode_lock);

	printf("[myfs_chown] Done.\n\n");

	return 0;
}

static int myfs_statfs(const char* path, struct statvfs *stat) {
	assert(path != NULL);
	assert(stat != NULL);
	assert(ROOT_INO != -1);
	assert(superblock != NULL);

	printf("[myfs_statfs] path: %s\n", path);

	pthread_rwlock_t* finode_lock;

	struct inode item = { 0 };

	int node_res;

	if ((node_res = get_node_by_path(path, ROOT_INO, &item)) < 0) {
		return node_res;
	}

	finode_lock = get_inode_lock(item.ino);

	RD_LOCK(finode_lock, "statfs");

	stat->f_bsize = BLOCK_SIZE;
	stat->f_frsize = BLOCK_SIZE;
	stat->f_blocks = superblock->max_dnum;
	stat->f_namemax = NAME_MAX;
	stat->f_bfree = superblock->free_blk_count;

	UNLOCK(finode_lock);

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
	int fd = open("/home/myfs-thread.log", O_CREAT | O_WRONLY | O_TRUNC);

	if (fd <= 0) {
		perror("open");

		exit(EXIT_FAILURE);
	}

	thread_log_fd = fdopen(fd, "w");

	if (!thread_log_fd) {
		perror("fdopen");
		
		close(fd);

		exit(EXIT_FAILURE);
	}

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
