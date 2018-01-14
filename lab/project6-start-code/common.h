#ifndef P6_COMMON
#define P6_COMMON

#include <fuse.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <time.h>
#include <sys/stat.h>

// Maybe you need the pthread locks or speedup by multi-threads or background GC in task2
// check if your $(CC) add -lfuse -pthread to $(CFLAGS) automatically, if not add them manually.
#include <pthread.h>

#include "disk.h"
#include "logging.h"

#define DISK_ROOT "/home/yuan-hang/Dev/os/project6-start-code/disk.img"

#define MAX_DIRECT_NUM 12
#define DIRECT_BLOCK_BYTES (MAX_DIRECT_NUM * (int) sizeof(int))
#define MAX_INDIRECT_NUM (BLOCK_SIZE / (int) sizeof(int))
#define MAX_FILENAME_LEN 256
#define MAX_PATH_LEN 4096
#define MAX_OPEN_FILE 65536

#define P6FS_MAGIC 0x20180110
#define PARTITION_SIZE 4000000000
#define BYTES_PER_INODE 16384
#define MAX_INODE (PARTITION_SIZE / BYTES_PER_INODE)
#define BLOCK_SIZE 4096
#define TOTAL_BLOCKS (PARTITION_SIZE / BLOCK_SIZE)
// NOTE: 1 block should be enough for any directory inode
#define MAX_DENTRY (BLOCK_SIZE / (int) sizeof(struct dentry))
#define MAX_FILE_SIZE (DIRECT_BLOCK_BYTES + MAX_INDIRECT_NUM * BLOCK_SIZE)

#define BLOCK_MAP_NARRAY (TOTAL_BLOCKS / sizeof(unsigned long long) + 1)
#define INODE_MAP_NARRAY (MAX_INODE / sizeof(unsigned long long) + 1)

#define SUPERBLOCK_SECTOR_NUM 0
#define BLOCK_BITMAP_SECTOR_NUM 1
#define INODE_BITMAP_SECTOR_NUM 65
#define INODE_TABLE_SECTOR_NUM 67 // 8192 blocks * 128B
#define DATABLOCK_SECTOR_NUM 8259
#define SUPERBLOCK_BK_SECTOR_NUM (PARTITION_SIZE / SECTOR_SIZE - 1) // 4*10^9B=976562 blks or 2^32B=1048576 blks?

#define ISREG 0
#define ISDIR 1
#define ISLNK 2

// See: https://stackoverflow.com/questions/2525310/how-to-define-and-work-with-an-array-of-bits-in-c
#define set_bit(A, k)     ( *(A + (k/32)) |= (1 << (k%32)) )
#define clear_bit(A, k)   ( *(A + (k/32)) &= ~(1 << (k%32)) )            
#define test_bit(A, k)    ( *(A + (k/32)) & (1 << (k%32)) )

/*   on-disk data structure   */
struct superblock_t{
    int magic_number;               // filesystem magic number
    int size;                       // size of the entire filesystem
    
    int inode_table;                // offset of inode table
    int inode_map;                  // offset of inode bitmap
    int total_inode_cnt;            // total number of inodes
    int free_inode_cnt;             // number of free inodes

    int block_map;                  // offset of datablock bitmap
    int total_block_cnt;            // total number of datablocks
    int free_block_cnt;             // number of free datablocks
};

struct inode_t{
    int sector;                     // inode table sector in disk
    int size;                       // file size in bytes
    int type;                       // directory or file?
    mode_t mode;                    // permission mode
    unsigned int link_count;        // link counter

    int block[MAX_DIRECT_NUM];      // direct blocks
    int indirect_table;             // indirect blocks

    time_t ctime;                   // creation time
    time_t atime;                   // access time
    time_t mtime;                   // modification time

    uid_t uid;
    gid_t gid;
};


struct dentry{
    char filename[MAX_FILENAME_LEN];
    int inode_num;
};

/*  in-memory data structure   */

struct superblock{
    struct superblock_t *sb;
    pthread_mutex_t lock;
};

struct inode{
    struct inode_t *inode;
    pthread_mutex_t lock;
};

/*Your file handle structure, should be kept in <fuse_file_info>->fh
 (uint64_t see fuse_common.h), and <fuse_file_info> used in all file operations  */
struct file_info{
    int fd;         // file descriptor number
    int flags;      // open flags
    int inode_num;  // inode number
    int used;       // whether this descriptor is occupied
    int rd;         // readable
    int wr;         // writable
    int app;        // append mode
};


//Interf.  See "fuse.h" <struct fuse_operations>
//You need to implement all the interfaces except optional ones

//dir operations
int p6fs_mkdir(const char *path, mode_t mode);
int p6fs_rmdir(const char *path);
int p6fs_readdir(const char *path, void *buf, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info *fileInfo);
int p6fs_opendir(const char *path, struct fuse_file_info *fileInfo);//optional
int p6fs_releasedir(const char *path, struct fuse_file_info *fileInfo);//optional
int p6fs_fsyncdir(const char *path, int datasync, struct fuse_file_info *fileInfo);//optional


//file operations
int p6fs_mknod(const char *path, mode_t mode, dev_t dev);
int p6fs_symlink(const char *path, const char *link);
int p6fs_link(const char *path, const char *newpath);
int p6fs_unlink(const char *path);
int p6fs_readlink(const char *path, char *link, size_t size);//optional

int p6fs_open(const char *path, struct fuse_file_info *fileInfo);
int p6fs_read(const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *fileInfo);
int p6fs_write(const char *path, const char *buf, size_t size, off_t offset, struct fuse_file_info *fileInfo);
int p6fs_truncate(const char *path, off_t newSize);
int p6fs_flush(const char *path, struct fuse_file_info *fileInfo);//optional
int p6fs_fsync(const char *path, int datasync, struct fuse_file_info *fi);//optional
int p6fs_release(const char *path, struct fuse_file_info *fileInfo);


int p6fs_getattr(const char *path, struct stat *statbuf);
int p6fs_utime(const char *path, struct utimbuf *ubuf);//optional
int p6fs_chmod(const char *path, mode_t mode); //optional
int p6fs_chown(const char *path, uid_t uid, gid_t gid);//optional

int p6fs_rename(const char *path, const char *newpath);
int p6fs_statfs(const char *path, struct statvfs *statInfo);
void* p6fs_init(struct fuse_conn_info *conn);
void p6fs_destroy(void* private_data);//optional

#endif
