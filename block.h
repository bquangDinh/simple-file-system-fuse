#ifndef _BLOCK_H_
#define _BLOCK_H_

#define BLOCK_SIZE 4096

/**
 * Init a virtual storage for MYFS, just a file that represents a storage. All files and directories created will be stored here
 */
void dev_init(const char* diskfile_path);

/**
 * Open the storage file
 */
int dev_open(const char* diskfile_path);

/**
 * Close the storage file
 */
void dev_close();

/**
 * Read a block, store its data into buffer
 */
int block_read(const int block_num, void* buf);

/**
 * Write data into a block from the given buffer
 */
int block_write(const int block_num, const void* buf);

#endif
