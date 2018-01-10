#include "common.h"

// ISSUES
// 01/10: did not check for too many files
// when creating new dentry;
// did not check if a file is busy

/*define global variables here*/
struct superblock fs_superblock;
struct superblock_t sblk;
struct inode inode_table[MAX_INODE];
struct inode_t ino[MAX_INODE];

struct dentry root;
struct file_info fd_table[MAX_OPEN_FILE];

unsigned long long block_bitmap[BLOCK_MAP_NARRAY];
unsigned long long inode_bitmap[INODE_MAP_NARRAY];
pthread_mutex_t block_bitmap_lock, inode_bitmap_lock;

/*
 Use linear table or other data structures as you need.
 
 // keep your root dentry and/or root data block
 // do path parse from your filesystem  ROOT<@mount point>
*/

/* helper functions */

// modify bitmap while flushing to disk
// maintain consistency between disk and memory
void set_bitmap(unsigned long long *bitmap, int i, int offset)
{
    set_bit(bitmap, i);
    device_write_sector((unsigned char *)(bitmap + i / sizeof(unsigned long long)), offset + i / SECTOR_SIZE);
    device_flush();
}

void clear_bitmap(unsigned long long *bitmap, int i, int offset)
{
    clear_bit(bitmap, i);
    device_write_sector((unsigned char *)(bitmap + i / sizeof(unsigned long long)), offset + i / SECTOR_SIZE);
    device_flush();
}

void flush_inode(int i)
{
    device_write_sector((unsigned char *)(inode_table[i].inode), SECTOR_SIZE);
    device_flush();
}

// mount an existing filesystem
void mount(struct superblock_t *sblock)
{
    // initialize in-memory structure
    if (!(pthread_mutex_init(&fs_superblock.lock, NULL) ||
          pthread_mutex_init(&block_bitmap_lock, NULL) ||
          pthread_mutex_init(&inode_bitmap_lock, NULL)))
    {
        printf("Lock initialization failed\n");
        exit(-1);
    }
    fs_superblock.sb = &sblk;

    int i;
    for (i = 0; i < MAX_INODE; ++i)
    {
        inode_table[i].inode = &ino[i];
        if (!(pthread_mutex_init(&(inode_table[i].lock), NULL)))
        {
            printf("Lock initialization failed\n");
            exit(-1);
        }
    }

    // deserialize superblock
    memcpy(&(fs_superblock.sb), sblock, sizeof(struct superblock_t));
    // deserialize bitmap and inode table
    unsigned char buf[SECTOR_SIZE], *dst = block_bitmap;
    for (i = BLOCK_BITMAP_SECTOR_NUM; i < INODE_BITMAP_SECTOR_NUM; ++i)
    {
        device_read_sector(buf, i);
        memcpy(dst, buf, SECTOR_SIZE);
        dst += SECTOR_SIZE;
    }

    dst = inode_bitmap;
    for (i = INODE_BITMAP_SECTOR_NUM; i < INODE_TABLE_SECTOR_NUM; ++i)
    {
        device_read_sector(buf, i);
        memcpy(dst, buf, SECTOR_SIZE);
        dst += SECTOR_SIZE;
    }

    dst = inode_table;
    for (i = INODE_TABLE_SECTOR_NUM; i < DATABLOCK_SECTOR_NUM; ++i)
    {
        device_read_sector(buf, i);
        memcpy(dst, buf, SECTOR_SIZE);
        dst += SECTOR_SIZE;
    }
}

// make a fresh filesystem on device
void mkfs()
{
    struct superblock_t sblock;

    // create superblock
    sblock.magic_number = P6FS_MAGIC;
    sblock.size = PARTITION_SIZE;
    sblock.total_block_cnt = TOTAL_BLOCKS;
    sblock.total_inode_cnt = MAX_INODE;
    // reserve an inode and a dentry block for the mountpoint
    sblock.free_inode_cnt = MAX_INODE - 1;
    sblock.free_block_cnt = TOTAL_BLOCKS - 1;
    sblock.block_map = SECTOR_SIZE * BLOCK_BITMAP_SECTOR_NUM;
    sblock.inode_table = SECTOR_SIZE * INODE_TABLE_SECTOR_NUM;
    sblock.inode_map = SECTOR_SIZE * INODE_BITMAP_SECTOR_NUM;
    // write new superblock to device
    device_write_sector((unsigned char *)&sblock, SUPERBLOCK_SECTOR_NUM);
    device_write_sector((unsigned char *)&sblock, SUPERBLOCK_BK_SECTOR_NUM);
    device_flush();

    // create inode entries and bitmaps
    // TODO: missing mode initialization
    struct fuse_context *fuse_con = fuse_get_context();
    uid_t uid = fuse_con->uid;
    gid_t gid = fuse_con->gid;

    struct inode_t root_inode = {.size = BLOCK_SIZE, .type = ISDIR,
                                 //.mode = ..., .uid = uid, .gid = gid,
                                 .link_count = 2,
                                 .block[0] = DATABLOCK_SECTOR_NUM,
                                 .indirect_table = -1,
                                 .ctime = time(NULL),
                                 .atime = time(NULL),
                                 .mtime = time(NULL)};
    device_write_sector((unsigned char *)&root_inode, INODE_TABLE_SECTOR_NUM);
    device_flush();

    unsigned char buf[SECTOR_SIZE] = {0};
    int i;
    for (i = BLOCK_BITMAP_SECTOR_NUM; i < INODE_TABLE_SECTOR_NUM; ++i)
    {
        device_write_sector(buf, i);
        device_flush();
    }

    buf[0] = 0x1 << 7;
    device_write_sector(buf, INODE_BITMAP_SECTOR_NUM);
    device_write_sector(buf, BLOCK_BITMAP_SECTOR_NUM);
    device_flush();

    // create root structure
    // NOTE: the mountpoint dentry always occupies the first datablock
    struct dentry root_entries[2] = {
        {.filename = ".", .inode_num = 0},
        {.filename = "..", .inode_num = 0},
    };
    unsigned char buf[SECTOR_SIZE];
    // NOTE: workaround; invalidate the rest of the sector
    memset(buf, -1, sizeof(buf));
    memcpy(buf, root_entries, sizeof(struct dentry) * 2);
    device_write_sector(buf, DATABLOCK_SECTOR_NUM);
    device_flush();

    // initialize file descriptor table
    for (i = 0; i < MAX_OPEN_FILE; ++i)
    {
        fd_table[i].fd = i;
        fd_table[i].flags = 0;
        fd_table[i].inode_num = -1;
        fd_table[i].used = 0;
    }

    mount(&sblock);
}

// look up a given file from dentry block
int lookup_file(int blk, const char *filename)
{
    /* read block from device */
    unsigned char buf[SECTOR_SIZE];
    device_read_sector(buf, blk);

    int i;
    char *p = buf;
    struct dentry *dp = (struct dentry *)p;
    for (i = 0; i < MAX_DENTRY; ++i, dp += sizeof(struct dentry))
    {
        if (!strcmp(filename, dp->filename) && dp->inode_num != -1)
            return dp->inode_num;
    }
    return -1;
}

// returns the inode number to a given path
// returns -1 if not found
int inode_from_path(const char *path)
{
    if (strcmp(path, "/"))
        return -1;
    char path_cp[MAX_PATH_LEN];
    strcpy(path_cp, path);
    int depth = 0;
    char *p = strtok(path_cp, '/');
    while (p)
    {
        ++depth;
        p = strtok(path_cp, '/');
    }
    unsigned char buf[SECTOR_SIZE];
    // read root dentry
    device_read_sector(buf, DATABLOCK_SECTOR_NUM);
    memcpy(&root, buf, sizeof(struct dentry));

    // look up inode and dentry alternately
    memset(buf, 0, sizeof(buf));
    int dentry_blkn, inode_num = 0;
    struct inode_t *inode;

    strcpy(path_cp, path);
    char *p = strtok(path_cp, '/');
    while (p)
    {
        // TODO: EACCES permission check
        /* /home/yuan-hang/... */
        inode = inode_table[inode_num].inode;
        // check inode type
        if (inode->type == ISDIR)
        {
            dentry_blkn = inode->block[0];
            if ((inode_num = lookup_file(dentry_blkn, p)) == -1)
                return -ENOENT;
        }
        // destination reached: symlink or regular file
        else if (inode->type == ISLNK)
        {
            // read link path from block
            device_read_sector(buf, inode->block[0]);
            inode_num = inode_from_path(buf);
            if (inode_num < 0)
                return inode_num;
        }
        else if (inode->type == ISREG)
        {
            // encountered a non-directory during traverse
            if (depth > 0)
                return -ENOTDIR;
            return inode_num;
        }
        depth--;
        p = strtok(path_cp, '/');
    }

    return inode_num; // default: root
}

// returns the parent inode to a given path
// returns -1 if not found
int dentry_from_path(const char *path)
{
    char path_cp[MAX_FILENAME_LEN];
    strcpy(path_cp, path);
    char *last = strrchr(path_cp, '/');
    *last = '\0';
    
    return inode_from_path(path_cp);
}

// data block access
void read_blocks(struct inode_t *ino, char *buf)
{
    int file_sz = ino->size, blocks = file_sz / BLOCK_SIZE;
    int n_direct, n_indirect;
    if (blocks > MAX_DIRECT_NUM)
    {
        n_direct = MAX_DIRECT_NUM;
        n_indirect = file_sz / BLOCK_SIZE - MAX_DIRECT_NUM;
    }
    else
    {
        n_direct = file_sz / BLOCK_SIZE;
        n_indirect = 0;
    }
    int i;
    // check for reading beyond
    for (i = 0; i < n_direct; ++i)
    {
    }
    for (i = 0; i < n_indirect; ++i)
    {
    }
}

void write_blocks(struct inode_t *ino, char *buf) {

}

void recycle_blocks(struct inode_t *ino, int new_size)
{
}

// allocate space for ino so that it has at least new_size bytes
int alloc_blocks(struct inode_t *ino, int new_size)
{

}

// FUSE operation implementations

/* Create a directory with the given name.
  The directory permissions are encoded in mode. */
int p6fs_mkdir(const char *path, mode_t mode)
{
    /* do path parse here
      create dentry and update your index */
    int inode_num = inode_from_path(path);
    if (inode_num >= 0)
        return -EEXIST;
    int parent_ino = dentry_from_path(path);
    if (parent_ino < 0)
        return parent_ino;
    // dentry block no.
    int parent_blk = inode_table[parent_ino].inode->block[0];
    // allocate inode
    // TODO: less fragmentation?
    pthread_mutex_lock(&inode_bitmap_lock);
    int i, has_free_ino = 0;
    unsigned char buf[SECTOR_SIZE];
    memset(buf, -1, sizeof(buf));
    for (i = 0; i < MAX_INODE; ++i)
    {
        if (!test_bit(inode_bitmap, i))
        {
            has_free_ino = 1;
            pthread_mutex_lock(&inode_table[i].lock);
            set_bitmap(inode_bitmap, i, INODE_BITMAP_SECTOR_NUM);
            struct inode_t *inode = inode_table[i].inode;
            inode->ctime = time(NULL);
            inode->mtime = time(NULL);
            inode->atime = time(NULL);
            inode->mode = mode;
            inode->type = ISDIR;
            inode->size = BLOCK_SIZE;
            inode->link_count = 2;
            // allocate dentry block
            pthread_mutex_lock(&block_bitmap_lock);
            int j, has_free_blk = 0;
            for (j = 0; j < TOTAL_BLOCKS; ++j)
                if (test_bit(block_bitmap, j))
                {
                    struct dentry entries[2] = {
                        {.filename = ".", .inode_num = i},
                        {.filename = "..", .inode_num = parent_ino},
                    };
                    set_bitmap(block_bitmap, j, BLOCK_BITMAP_SECTOR_NUM);
                    // invalidate other directory entries
                    // write dentry block to device
                    memcpy(buf, entries, sizeof(struct dentry) * 2);
                    device_write_sector(buf, DATABLOCK_SECTOR_NUM + j * SECTOR_SIZE);
                    device_flush();
                    has_free_blk = 1;
                    break;
                }
            pthread_mutex_unlock(&block_bitmap_lock);
            if (!has_free_blk)
                return -ENOSPC;
            inode->block[0] = DATABLOCK_SECTOR_NUM + j;
            inode->indirect_table = -1;
            flush_inode(i);
            pthread_mutex_unlock(&inode_table[i].lock);

            break;
        }
    }
    inode_num = i;
    pthread_mutex_unlock(&inode_bitmap_lock);
    if (!has_free_ino)
        return -ENOMEM;
    // allocate dentry for parent
    char *last = strrchr(path, '/') + 1;
    memset(buf, 0, sizeof(buf));
    device_read_sector(buf, parent_blk);
    char *p = buf;
    struct dentry *dp = (struct dentry *)p;
    for (i = 0; i < MAX_DENTRY; ++i, dp += sizeof(struct dentry))
    {
        if (dp->inode_num == -1)
        {
            strcpy(dp->filename, last);
            dp->inode_num = inode_num;
            device_write_sector(buf, parent_blk);
            device_flush();
            return 0;
        }
    }
}

/* Remove the given directory. This should succeed only
if the directory is empty (except for "." and ".."). */
int p6fs_rmdir(const char *path)
{
    int inode_num = inode_from_path(path);
    if (inode_num < 0)
        return inode_num;

    // check if directory is empty
    struct inode_t *inode = inode_table[inode_num].inode;
    unsigned char buf[SECTOR_SIZE];
    device_read_sector(buf, inode->block[0]);

    int i;
    char *p = buf;
    struct dentry *dp = (struct dentry *)p;
    for (i = 0; i < MAX_DENTRY; ++i, dp += sizeof(struct dentry))
    {
        if (dp->inode_num == -1 || i == 0 || i == 1)
            continue;
        else
            return -ENOTEMPTY;
    }
    // free directory inode and dentry in parent
    int parent_ino = dentry_from_path(path);
    int parent_blk = inode_table[parent_ino].inode->block[0];
    device_read_sector(buf, parent_blk);
    p = buf;
    dp = (struct dentry *)p;
    for (i = 0; i < MAX_DENTRY; ++i, dp += sizeof(struct dentry))
    {
        if (inode_num == dp->inode_num)
        {
            dp->inode_num = -1;
            pthread_mutex_lock(&(inode_table[inode_num].lock));
            memset(inode_table[inode_num].inode, 0, sizeof(struct inode_t));
            flush_inode(inode_num);
            pthread_mutex_lock(&inode_bitmap_lock);
            clear_bitmap(inode_bitmap, inode_num, INODE_BITMAP_SECTOR_NUM);
            pthread_mutex_unlock(&inode_bitmap_lock);
            pthread_mutex_unlock(&(inode_table[inode_num].lock));

            return 0;
        }
    }
}

// Return one or more directory entries (struct dentry) to the caller.
int p6fs_readdir(const char *path, void *buf, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info *fileInfo)
{
    /*
    - Find the first directory entry following the given offset (see below).
    - Optionally, create a struct stat that describes the file as for getattr (but FUSE only looks at st_ino and the file-type bits of st_mode).
    - Call the filler function with arguments of buf, the null-terminated filename, the address of your struct stat (or NULL if you have none), and the offset of the next directory entry.
    - If filler returns nonzero, or if there are no more files, return 0.
    - Find the next file in the directory.
    - Go back to step 2.
    */
    int inode_num = inode_from_path(path);
    if (inode_num < 0)
        return inode_num;

    struct inode_t *inode = inode_table[inode_num].inode;
    unsigned char buf[SECTOR_SIZE];
    device_read_sector(buf, inode->block[0]);

    int i, ret;
    char *p = buf;
    struct dentry *dp = (struct dentry *)p;
    for (i = 0; i < MAX_DENTRY; ++i, dp += sizeof(struct dentry))
    {
        if (dp->inode_num == -1)
            continue;
        if (ret = filler(buf, dp->filename, NULL, 0))
            return 0;
    }
    return 0;
}

//optional
//int p6fs_opendir(const char *path, struct fuse_file_info *fileInfo)
//int p6fs_releasedir(const char *path, struct fuse_file_info *fileInfo)
//int p6fs_fsyncdir(const char *path, int datasync, struct fuse_file_info *fileInfo)

// Make a special (device) file, FIFO, or socket.
// NOTE: we implement regular files
int p6fs_mknod(const char *path, mode_t mode, dev_t dev)
{
    /* do path parse here
    create file */
    int inode_num = inode_from_path(path);
    if (inode_num >= 0)
        return -EEXIST;
    int parent_ino = dentry_from_path(path);
    if (parent_ino < 0)
        return parent_ino;
    int parent_blk = inode_table[parent_ino].inode->block[0];
    // allocate inode
    // TODO: less fragmentation?
    pthread_mutex_lock(&inode_bitmap_lock);
    int i, has_free_ino = 0;
    for (i = 0; i < MAX_INODE; ++i)
    {
        if (!test_bit(inode_bitmap, i))
        {
            has_free_ino = 1;
            pthread_mutex_lock(&inode_table[i].lock);
            set_bitmap(inode_bitmap, i, INODE_BITMAP_SECTOR_NUM);
            struct inode_t *inode = inode_table[i].inode;
            inode->ctime = time(NULL);
            inode->mtime = time(NULL);
            inode->atime = time(NULL);
            inode->mode = mode;
            inode->type = ISREG;
            inode->size = BLOCK_SIZE;
            inode->link_count = 1;
            // allocate data block
            pthread_mutex_lock(&block_bitmap_lock);
            int j, has_free_blk = 0;
            for (j = 0; j < TOTAL_BLOCKS; ++j)
                if (test_bit(block_bitmap, j))
                {
                    set_bitmap(block_bitmap, j, BLOCK_BITMAP_SECTOR_NUM);
                    has_free_blk = 1;
                    break;
                }
            pthread_mutex_unlock(&block_bitmap_lock);
            if (!has_free_blk)
                return -ENOSPC;
            inode->block[0] = DATABLOCK_SECTOR_NUM + j;
            inode->indirect_table = -1;
            flush_inode(i);
            pthread_mutex_unlock(&inode_table[i].lock);

            break;
        }
    }
    inode_num = i;
    pthread_mutex_unlock(&inode_bitmap_lock);
    if (!has_free_ino)
        return -ENOMEM;
    // allocate dentry
    char *last = strrchr(path, '/') + 1;
    unsigned char buf[SECTOR_SIZE];
    device_read_sector(buf, parent_blk);
    char *p = buf;
    struct dentry *dp = (struct dentry *)p;
    for (i = 0; i < MAX_DENTRY; ++i, dp += sizeof(struct dentry))
    {
        if (dp->inode_num == -1)
        {
            strcpy(dp->filename, last);
            dp->inode_num = inode_num;
            device_write_sector(buf, parent_blk);
            device_flush();
            return 0;
        }
    }
}

// If path is a symbolic link, fill link with its target, up to size.
int p6fs_readlink(const char *path, char *link, size_t size)
{
    int inode_num = inode_from_path(path);
    if (inode_num < 0)
        return inode_num;
    struct inode_t *inode = inode_table[inode_num].inode;
    if (inode->type != ISLNK || size < 0)
        return -EINVAL;

    unsigned char buf[SECTOR_SIZE];
    memset(buf, 0, sizeof(buf));
    device_read_sector(buf, inode->block[0]);
}

// Create a symbolic link named "link" which, when evaluated, will lead to "path".
int p6fs_symlink(const char *path, const char *link)
{
    int inode_num = inode_from_path(link);
    if (inode_num >= 0)
        return -EEXIST;
    int parent_ino = dentry_from_path(link);
    if (parent_ino < 0)
        return parent_ino;
    int parent_blk = inode_table[parent_ino].inode->block[0];
    // allocate inode
    // TODO: less fragmentation?
    pthread_mutex_lock(&inode_bitmap_lock);
    int i, has_free_ino = 0;
    unsigned char buf[SECTOR_SIZE];
    memset(buf, 0, sizeof(buf));
    strcpy(buf, path);
    for (i = 0; i < MAX_INODE; ++i)
    {
        if (!test_bit(inode_bitmap, i))
        {
            has_free_ino = 1;
            pthread_mutex_lock(&inode_table[i].lock);
            set_bitmap(inode_bitmap, i, INODE_BITMAP_SECTOR_NUM);
            struct inode_t *inode = inode_table[i].inode;
            inode->ctime = time(NULL);
            inode->mtime = time(NULL);
            inode->atime = time(NULL);
            // TODO: inode->mode = ...;
            inode->type = ISLNK;
            inode->size = strlen(path);
            inode->link_count = 1;
            // allocate data block
            pthread_mutex_lock(&block_bitmap_lock);
            int j, has_free_blk = 0;
            for (j = 0; j < TOTAL_BLOCKS; ++j)
                if (test_bit(block_bitmap, j))
                {
                    set_bitmap(block_bitmap, j, BLOCK_BITMAP_SECTOR_NUM);
                    has_free_blk = 1;
                    break;
                }
            pthread_mutex_unlock(&block_bitmap_lock);
            if (!has_free_blk)
                return -ENOSPC;
            inode->block[0] = DATABLOCK_SECTOR_NUM + j;
            inode->indirect_table = -1;
            flush_inode(i);
            pthread_mutex_unlock(&inode_table[i].lock);

            device_write_sector(buf, inode->block[0]);
            device_flush();

            break;
        }
    }
    inode_num = i;
    pthread_mutex_unlock(&inode_bitmap_lock);
    if (!has_free_ino)
        return -ENOMEM;
    // allocate dentry
    char *last = strrchr(link, '/') + 1;
    device_read_sector(buf, parent_blk);
    char *p = buf;
    struct dentry *dp = (struct dentry *)p;
    for (i = 0; i < MAX_DENTRY; ++i, dp += sizeof(struct dentry))
    {
        if (dp->inode_num == -1)
        {
            strcpy(dp->filename, last);
            dp->inode_num = inode_num;
            device_write_sector(buf, parent_blk);
            device_flush();
            return 0;
        }
    }
}

// Create a hard link between "path" and "newpath".
int p6fs_link(const char *path, const char *newpath)
{
    int inode_num = inode_from_path(newpath);
    if (inode_num >= 0)
        return -EEXIST;
    inode_num = inode_from_path(path);
    if (inode_num < 0)
        return inode_num;
    int parent_blk = dentry_from_path(newpath);
    if (parent_blk < 0)
        return parent_blk;
    parent_blk = inode_table[dentry_from_path(path)].inode->block[0];
    // increment link count
    struct inode_t *inode = inode_table[inode_num].inode;
    // cannot create hard link to directory
    if (inode->type == ISDIR)
        return -EISDIR;
    ++inode->link_count;

    // allocate dentry
    unsigned char buf[SECTOR_SIZE];
    char *last = strrchr(newpath, '/') + 1;
    device_read_sector(buf, parent_blk);
    int i;
    char *p = buf;
    struct dentry *dp = (struct dentry *)p;
    for (i = 0; i < MAX_DENTRY; ++i, dp += sizeof(struct dentry))
    {
        if (dp->inode_num == -1)
        {
            strcpy(dp->filename, last);
            dp->inode_num = inode_num;
            device_write_sector(buf, parent_blk);
            device_flush();
            return 0;
        }
    }
}

// Remove (delete) the given file, symbolic link, hard link, or special node.
int p6fs_unlink(const char *path)
{
    int inode_num = inode_from_path(path);
    if (inode_num < 0)
        return inode_num;
    struct inode_t *inode = inode_table[inode_num].inode;
    if (inode->type == ISDIR)
        return -EISDIR;

    // remove dentry and free inode
    unsigned char buf[SECTOR_SIZE];
    int parent_blk = dentry_from_path(path);
    parent_blk = inode_table[dentry_from_path(path)].inode->block[0];
    device_read_sector(buf, parent_blk);
    int i;
    char *p = buf;
    struct dentry *dp = (struct dentry *)p;
    for (i = 0; i < MAX_DENTRY; ++i, dp += sizeof(struct dentry))
    {
        if (inode_num == dp->inode_num)
        {
            dp->inode_num = -1;
            break;
        }
    }
    // removing a hard link
    if (inode->type == ISLNK)
    {
        inode->link_count--;
        flush_inode(inode_num);
    }
    // removing a symlink or regular file
    else
    {
        pthread_mutex_lock(&(inode_table[inode_num].lock));
        memset(inode, 0, sizeof(struct inode_t));
        flush_inode(inode_num);
        pthread_mutex_lock(&inode_bitmap_lock);
        clear_bitmap(inode_bitmap, inode_num, INODE_BITMAP_SECTOR_NUM);
        pthread_mutex_unlock(&inode_bitmap_lock);
        pthread_mutex_unlock(&(inode_table[inode_num].lock));
    }

    return 0;
}

/* Open a file. Check for existence and permissions and return either
success or an error code. */
int p6fs_open(const char *path, struct fuse_file_info *fileInfo)
{
    /*
  Implemention Example:
  S1: look up and get dentry of the path
  S2: create file handle! Do NOT lookup in read() or write() later
  */
    int inode_num = inode_from_path(path);
    if (inode_num < 0)
        return inode_num;

    inode_table[inode_num].inode->atime = time(NULL);
    // assign and init your file handle
    struct file_info *fi = NULL;
    int i;
    for (i = 0; i < MAX_OPEN_FILE; ++i)
    {
        if (!fd_table[i].used)
        {
            fd_table[i].used = 1;
            fi = &fd_table[i];
            break;
        }
    }
    if (!fi)
        return -ENFILE;

    // TODO: how is this useful in any sense?
    /*
    struct fuse_context *fuse_con = fuse_get_context();
    fuse_con->private_data = malloc(...);
    */

    // check open flags, such as O_RDONLY
    // O_CREATE is transformed to mknod() + open() by fuse, so no need to create file here
    if ((fileInfo->flags & 3) == O_RDONLY)
        fi->rd = 1;
    if ((fileInfo->flags & 3) == O_WRONLY)
        fi->wr = 1;
    if ((fileInfo->flags & 3) == O_APPEND)
        fi->app = 1;
    if ((fileInfo->flags & 3) == O_RDWR)
    {
        fi->rd = 1;
        fi->wr = 1;
    }
    fi->inode_num = inode_num;

    fileInfo->fh = (uint64_t)fi;
    return 0;
}

/* Read size bytes from the given file into the buffer buf,
  beginning offset bytes into the file. Returns the number of
  bytes transferred, or 0 if offset was at or beyond the end of the file. */
int p6fs_read(const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *fileInfo)
{
    /* get inode from file handle and do operation */
    struct file_info *fi = (struct file_info *)fileInfo;
    int inode_num = inode_from_path(path);
    if (inode_num < 0)
        return inode_num;
    // check permission
    if (fi->rd == 0)
        return -EACCES;

    struct inode_t *inode = inode_table[inode_num].inode;
    if (offset >= inode->size)
        return 0;

    // access direct and indirect blocks
    read_blocks(inode, buf);
    return inode->size;
}

// Returns the number of bytes transferred.
int p6fs_write(const char *path, const char *buf, size_t size, off_t offset, struct fuse_file_info *fileInfo)
{
    /* get inode from file handle and do operation */
    struct file_info *fi = (struct file_info *)fileInfo;
    int inode_num = inode_from_path(path);
    if (inode_num < 0)
        return inode_num;
    struct inode_t *inode = inode_table[inode_num].inode;
    // check flags
    if (fi->wr == 0)
        return -EACCES;
    else if (fi->app == 0)
        offset = inode->size;
    int new_size = offset + size, ret;
    if (new_size > inode->size)
        if (ret = alloc_blocks(inode, new_size) == -1)
            return -ENOSPC;
    write_blocks(inode, buf);
    fi->inode_num = inode_num;

    return size;
}

// Truncate or extend the given file so that it is precisely newSize bytes long.
int p6fs_truncate(const char *path, off_t newSize)
{
    int inode_num = inode_from_path(path);
    if (inode_num < 0)
        return inode_num;
    struct inode_t *inode = inode_table[inode_num].inode;
    if (inode->size == newSize)
        return;
    else if (inode->size > newSize)
        recycle_blocks(inode, newSize);
    else
    {
        int ret;
        if (ret = alloc_blocks(inode, newSize) == -1)
            return -ENOSPC;
    }
    inode->size = newSize;
    flush_inode(inode_num);

    return 0;
}

//optional
//p6fs_flush(const char *path, struct fuse_file_info *fileInfo)
//int p6fs_fsync(const char *path, int datasync, struct fuse_file_info *fi)
int p6fs_release(const char *path, struct fuse_file_info *fileInfo)
{
    /* release fd */
    int inode_num = inode_from_path(path);
    if (inode_num < 0)
        return inode_num;
    int i;
    for (i = 0; i < MAX_OPEN_FILE; i++)
    {
        if (fd_table[i].inode_num == inode_num && fd_table[i].used)
        {
            fd_table[i].inode_num = -1;
            fd_table[i].used = 0;
            return 0;
        }
    }

    return -EBADF;
}

int p6fs_getattr(const char *path, struct stat *statbuf)
{
    /* stat() file or directory */
    int inode_num = inode_from_path(path);
    if (inode_num < 0)
        return inode_num;

    memset(statbuf, 0, sizeof(stat));
    struct inode_t *inode = inode_table[inode_num].inode;
    statbuf->st_nlink = inode->link_count;
    statbuf->st_size = inode->size;
    if (inode->type == ISDIR)
        // TODO: permissions, | inode->mode...
        statbuf->st_mode = S_IFDIR;
    else if (inode->type == ISREG)
        statbuf->st_mode = S_IFREG;
    else
        statbuf->st_mode = S_IFLNK;
    statbuf->st_mtime = inode->mtime;
    statbuf->st_atime = inode->atime;
    statbuf->st_ctime = inode->ctime;

    return 0;
}

int p6fs_utime(const char *path, struct utimbuf *ubuf)
{
    int inode_num = inode_from_path(path);
    if (inode_num < 0)
        return inode_num;
    struct inode_t *inode = inode_table[inode_num].inode;
    struct fuse_context *fuse_con = fuse_get_context();
    uid_t current_uid = fuse_con->uid;
    if (current_uid == inode->uid ||)
    {
        if (ubuf == NULL)
        {
            inode->atime = time(NULL);
            inode->mtime = time(NULL);
        }
        else
        {
            inode->atime = ubuf->actime;
            inode->mtime = ubuf->modtime;
        }
    }

    return 0;
}

/* Change the mode (permissions) of the given object to the given new permissions.
  Only the permissions bits of mode should be examined. */
int p6fs_chmod(const char *path, mode_t mode)
{
    // TODO
    int inode_num = inode_from_path(path);
    if (inode_num < 0)
        return inode_num;

    struct fuse_context *fuse_con = fuse_get_context();
    uid_t uid = fuse_con->uid;
    gid_t gid = fuse_con->gid;

    pthread_mutex_lock(&inode_table[inode_num].lock);
    struct inode_t *inode = inode_table[inode_num].inode;
    inode->mode = mode;
    flush_inode(inode_num);
    pthread_mutex_unlock(&inode_table[inode_num].lock);

    return 0;
}

int p6fs_chown(const char *path, uid_t uid, gid_t gid)
{
    int inode_num = inode_from_path(path);
    if (inode_num < 0)
        return inode_num;

    struct inode_t *inode = inode_table[inode_num].inode;
    if (inode->type == ISDIR)
        return -EISDIR;

    struct fuse_context *fuse_con = fuse_get_context();
    uid_t current_uid = fuse_con->uid;
    unsigned char buf[SECTOR_SIZE];
    if (current_uid != inode->uid)
        return -EPERM;
    else
    {
        // if path refers to a symlink, find the real file
        while (inode->type == ISLNK)
        {
            memset(buf, 0, sizeof(buf));
            device_read_sector(buf, inode->block[0]);
            inode_num = inode_from_path(buf);
            inode = inode_table[inode_num].inode;
        }
        inode->uid = uid;
        inode->gid = gid;
        inode->ctime = time(NULL);
        flush_inode(inode_num);
    }

    return 0;
}

int p6fs_rename(const char *path, const char *newpath)
{
    // find corresponding dentry and rename
    // write info back to disk
    int inode_num = inode_from_path(path);
    if (inode_num < 0)
        return inode_num;
    inode_num = inode_from_path(newpath);
    if (inode_num >= 0)
        return -EEXIST;
    if (strstr(path, newpath))
        return -EINVAL;

    int parent_blk = dentry_from_path(path);
    if (parent_blk < 0)
        return parent_blk;
    parent_blk = inode_table[dentry_from_path(path)].inode->block[0];
    char name[MAX_FILENAME_LEN], newname[MAX_FILENAME_LEN];
    char *last = strrchr(path, '/');
    if (last == NULL)
        // cannot rename root directory
        return -EINVAL;
    else
        last += 1;
    strcpy(name, last);

    last = strrchr(newpath, '/') + 1;
    strcpy(newname, last);

    // iterate through all dentry items
    unsigned char buf[SECTOR_SIZE];
    device_read_sector(buf, parent_blk);
    int i;
    char *p = buf;
    struct dentry *dp = (struct dentry *)p;
    for (i = 0; i < MAX_DENTRY; ++i, dp += sizeof(struct dentry))
    {
        if (dp->inode_num == -1)
            continue;
        if (!strcmp(name, dp->filename))
        {
            strcpy(&(dp->filename), newname);
            return 0;
        }
    }
    return -ENOENT;
}

// Return statistics about the filesystem.
int p6fs_statfs(const char *path, struct statvfs *statInfo)
{
    if (strcmp(path, "/"))
        return -ENOENT;
    /* print fs status and statistics */
    statInfo->f_bsize = BLOCK_SIZE;
    statInfo->f_frsize = BLOCK_SIZE;
    statInfo->f_blocks = fs_superblock.sb->total_block_cnt;
    statInfo->f_bfree = fs_superblock.sb->free_block_cnt;
    statInfo->f_bavail = fs_superblock.sb->free_block_cnt;
    statInfo->f_files = fs_superblock.sb->total_inode_cnt;
    statInfo->f_ffree = fs_superblock.sb->free_inode_cnt;
    statInfo->f_favail = fs_superblock.sb->free_inode_cnt;

    return 0;
}

void *p6fs_init(struct fuse_conn_info *conn)
{
    /* init fs: create or rebuild memory structures. */
    unsigned char buf[SECTOR_SIZE];
    struct superblock_t sblock_buf;

    if (device_open(DISK_ROOT) == -1)
    {
        printf("DISK: Failed to open disk\n");
        exit(-1);
    }

    device_read_sector(buf, SUPERBLOCK_SECTOR_NUM);
    memcpy(&sblock_buf, buf, sizeof(struct superblock_t));

    // check if there is an existing filesystem
    int exist = 0;
    if (sblock_buf.magic_number == P6FS_MAGIC)
        exist = 1;
    else
    {
        device_read_sector(buf, SUPERBLOCK_BK_SECTOR_NUM);
        memcpy(&sblock_buf, buf, sizeof(struct superblock_t));
        if (sblock_buf.magic_number == P6FS_MAGIC)
        {
            exist = 1;
            // CHKDSK: fix superblock
            device_write_sector(buf, SUPERBLOCK_SECTOR_NUM);
            device_flush();
        }
    }

    if (exist)
        mount(&sblock_buf);
    else
        mkfs();

    /* the fuse_context is a global variable, you can use it in
     all file operation, and you could also get uid, gid and pid
     from it. */
    return NULL;
}

void p6fs_destroy(void *private_data)
{
    /*
     flush data to disk
     free memory
    */
    // free(private_data);
    device_close();
    logging_close();
}
