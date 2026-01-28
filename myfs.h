#include <linux/limits.h>
#include <sys/stat.h>
#include <unistd.h>

/* Fallback for environments where S_IFDIR is not exposed  */
#ifndef S_IFDIR
#define S_IFDIR 0040000
#endif

#ifndef _MYFS_H_
#define _MYFS_H_

#define ENABLE_DEBUG_PRINTF

#ifdef ENABLE_DEBUG_PRINTF
#define printf(...) printf(__VA_ARGS__)
#else
#define printf(...)
#endif

#define SUPERBLOCK_BLK_NUM 0

#define MAGIC_NUM 0x1234

// Maximum number of inodes in inode region
#define MAX_INODE_NUM 1024

// Maximum number of data blocks in data region
// Each data block occupies one page
// Beware that the total number of inodes + data + inode bitmap (one page) + data bitmap (one page) + superblock (one page) must be <= the size of file
#define MAX_DATA_NUM 244140 // For 10GB file

#define INODE_BITMAP_BYTES ((MAX_INODE_NUM + 7) / 8) // in bytes
#define DATA_BITMAP_BYTES ((MAX_DATA_NUM + 7) / 8) // in bytes													 									  
#define DIRECT_PTRS_COUNT 12

struct superblock {
	uint16_t magic_num;			// magic number used to identify if a storage file is valid
	uint16_t max_inum; 			// max number of inodes
	uint16_t max_dnum; 			// max number of data blocks
	uint32_t i_bitmap_blk; 		// start block of inode bitmap
	uint32_t d_bitmap_blk; 		// start block of data bitmap
	uint32_t i_start_blk; 		// start block of inode region					  					  			
	uint32_t d_start_blk;		// start block of data region
	uint32_t free_blk_count;	// number of free data blocks
	uint32_t free_ino_count;	// number of free inode
};

struct inode {
	uint16_t ino;				// inode number
	uint16_t container_ino;		// inode number of parent
	uint16_t valid;				// bit check if inode is valid
	uint32_t size;				// size of the file
	uint32_t type;				// type of the file
	mode_t mode;

	// Note that file content deletion only happens when link count = 0 AND open_count = 0
	uint32_t nlink;				// link count
	uint32_t open_count;		// keep track of how many processes are opening this inode
	
	uint32_t uid;				// user id
	uint32_t gid;				// group id
	struct timespec atime;				// last access time
	struct timespec mtime;				// last modification time
	struct timespec ctime;				// last modification to inode time
	int directs[DIRECT_PTRS_COUNT];
	int indirect_ptr;
};

struct dirent {
	uint16_t ino;				// inode number
	uint16_t valid;				// bit check if directory entry is valid
	char name[NAME_MAX + 1];		// maximum bytes for file name
	uint16_t len;				// length of file name actually
};

struct file_handler {
	uint16_t ino;
	int flags;	
};

/**
 * bitmap operations
 */
typedef unsigned char* bitmap_t;

static inline void set_bitmap(bitmap_t b, int i) {
	b[i / 8] |= 1 << (i & 7);
}

static inline void unset_bitmap(bitmap_t b, int i) {
	b[i / 8] &= ~(1 << (i & 7));
}

static inline uint8_t get_bitmap(bitmap_t b, int i) {
	return b[i / 8] & (1 << (i & 7)) ? 1 : 0;
}

#endif
