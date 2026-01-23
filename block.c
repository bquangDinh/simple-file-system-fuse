// Provide functions to open, read, close file along with FLAGS such as O_CREAT, O_RDWR, etc..
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <assert.h>

#include "block.h"

#define DISK_SIZE 32 * 1024 * 1024 // 32MB

// Pointer to the diskfile
int diskfile = -1;

void dev_init(const char* diskfile_path) {
	if (dev_open(diskfile_path) == -1) {
		perror("Init diskfile failed");
		exit(EXIT_FAILURE);
	}

	printf("Truncate file %s to be %d bytes\n", diskfile_path, DISK_SIZE);

	// Set this file to be the size of DISK_SIZE
	if (ftruncate(diskfile, DISK_SIZE) == -1) {
		perror("Failed to truncate file");
		exit(EXIT_FAILURE);
	}
}

int dev_open(const char* diskfile_path) {
	if (diskfile != -1) {
		printf("Disk file is already opened\n");

		// Already opened
		return 0;
	}

	
	// O_RDWR: open file for read and write
	// S_IRUSR | S_IWUSR: owner of this file can read and write
	diskfile = open(diskfile_path, O_CREAT | O_RDWR, S_IRUSR | S_IWUSR);

	if (diskfile < 0) {
		perror("disk open failed");
		return -1;
	}

	return 0;
}

void dev_close() {
	assert(diskfile > 0);

	if (close(diskfile) < 0) {
		perror("Close diskfile failed");
		exit(EXIT_FAILURE);
	}
}

int block_read(const int block_num, void* buf) {
	assert(diskfile > 0);

	int read_bytes = pread(diskfile, buf, BLOCK_SIZE, block_num * BLOCK_SIZE);

	if (read_bytes <= 0) {
		perror("block_read failed");
		return -1;
	}

	return read_bytes;
}

int block_write(const int block_num, const void* buf) {
	assert(diskfile > 0);

	int write_bytes = pwrite(diskfile, buf, BLOCK_SIZE, block_num * BLOCK_SIZE);

	if (write_bytes <= 0) {
		perror("block write failed to write a block");
		return -1;
	}

	return write_bytes;
}

int dev_fsync() {
	assert(diskfile != -1);

	return fsync(diskfile);
}
