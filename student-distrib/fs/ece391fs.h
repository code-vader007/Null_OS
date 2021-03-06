#ifndef _ECE391FS_H_
#define _ECE391FS_H_

#include "../lib/lib.h"
#include "unified_fs.h"

#define ECE391FS_FILE_TYPE_RTC 0
#define ECE391FS_FILE_TYPE_FOLDER 1
#define ECE391FS_FILE_TYPE_FILE 2

#define ECE391FS_MAX_FILENAME_LEN 32
#define ECE391FS_MAX_FILE_COUNT 63

#define ECE391FS_BLOCK_SIZE 4096

typedef struct {
    char name[ECE391FS_MAX_FILENAME_LEN];
    uint32_t type;
    uint32_t inode;
    uint8_t reserved[24];
} ece391fs_file_info_t;
typedef ece391fs_file_info_t dentry_t;  

typedef struct {
    uint32_t num_dir_entries;
    uint32_t num_inodes;
    uint32_t num_data_blocks;
    uint8_t reserved[52];
    ece391fs_file_info_t file[ECE391FS_MAX_FILE_COUNT];
} ece391fs_bootblk_t;

typedef struct {
    uint32_t size;
    uint32_t data[ECE391FS_BLOCK_SIZE / 4 - 1];
} ece391fs_inode_t;

typedef struct {
    uint32_t data[ECE391FS_BLOCK_SIZE / 4];
} ece391fs_data_block_t;

int32_t ece391fs_init(uint32_t module_start, uint32_t module_end);
int32_t ece391fs_is_initialized();
int32_t ece391fs_size(uint32_t inode_idx);
int32_t read_dentry_by_name(const char* fname, ece391fs_file_info_t* file_info);
int32_t read_dentry_by_index(uint32_t index, ece391fs_file_info_t* file_info);
int32_t read_data(uint32_t inode, uint32_t offset, char* buf, uint32_t length);
int32_t read_dir(uint32_t offset, char* buf, uint32_t length);
void ece391fs_print_file_info(ece391fs_file_info_t* file_info);

// Temporary functions for CP2
int32_t file_open(int32_t* inode, char* filename);
int32_t file_read(int32_t* inode, uint32_t* offset, char* buf, uint32_t len);
int32_t file_write(int32_t* inode, uint32_t* offset, const char* buf, uint32_t len);
int32_t file_close(int32_t* inode);
int32_t dir_open(int32_t* inode, char* filename);
int32_t dir_read(int32_t* inode, uint32_t* offset, char* buf, uint32_t len);
int32_t dir_write(int32_t* inode, uint32_t* offset, const char* buf, uint32_t len);
int32_t dir_close(int32_t* inode);

// Unified FS definition
extern unified_fs_interface_t ece391fs_file_if;
extern unified_fs_interface_t ece391fs_dir_if;

#endif
