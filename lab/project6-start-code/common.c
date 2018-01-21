#include "common.h"
#include "md5.h"

// KNOWN ISSUES
// 01/21: Technically, metadata should be flushed back
// to disk upon an fsync() operation, not instantly.
// Also, it seems FUSE ignores the ino returned by getattr.
// 01/20: The parent dentry block is not locked, so let's
// keep our fingers crossed that another make operation
// won't take our dentry space away.
// 01/10: Did not check if a file is busy.

/* define global variables here */
struct superblock fs_superblock;
struct superblock_t sblk;
struct inode inode_table[MAX_INODE];
struct inode_t inode_info[MAX_INODE];

struct dentry root;
struct file_info fd_table[MAX_OPEN_FILE];

unsigned long long block_bitmap[BLOCK_MAP_NARRAY] = {0};
unsigned long long inode_bitmap[INODE_MAP_NARRAY] = {0};
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
    unsigned char buf[SECTOR_SIZE];
    set_bit(bitmap, i);
    memcpy(buf, bitmap + i / SECTOR_SIZE, SECTOR_SIZE);
    device_write_sector(buf, offset + i / SECTOR_SIZE);
    device_flush();
}

void clear_bitmap(unsigned long long *bitmap, int i, int offset)
{
    unsigned char buf[SECTOR_SIZE];
    clear_bit(bitmap, i);
    memcpy(buf, bitmap + i / SECTOR_SIZE, SECTOR_SIZE);
    device_write_sector(buf, offset + i / SECTOR_SIZE);
    device_flush();
}

void flush_inode(int ino)
{
    unsigned char buf[SECTOR_SIZE] = {0};
    memcpy(buf, inode_table[ino].inode, sizeof(struct inode_t));
    device_write_sector(buf, INODE_TABLE_SECTOR_NUM + ino);
    device_flush();
}

void flush_superblock()
{
    unsigned char buf[SECTOR_SIZE] = {0};
    memcpy(buf, &sblk, sizeof(struct superblock_t));
    device_write_sector(buf, SUPERBLOCK_SECTOR_NUM);
    device_flush();
    device_write_sector(buf, SUPERBLOCK_BK_SECTOR_NUM);
    device_flush();
}

// mount an existing filesystem
void mountp6fs(struct superblock_t *sblock)
{
	DEBUG("Mounting P6FS...")
    // initialize in-memory structure
    if ((pthread_mutex_init(&fs_superblock.lock, NULL) ||
         pthread_mutex_init(&block_bitmap_lock, NULL) ||
         pthread_mutex_init(&inode_bitmap_lock, NULL)))
    {
        ERR("Block and bitmap lock initialization failed")
        exit(-1);
    }
    fs_superblock.sb = &sblk;

    int i;
    for (i = 0; i < MAX_INODE; ++i)
    {
        inode_table[i].inode = &inode_info[i];
        if (pthread_mutex_init(&inode_table[i].lock, NULL))
        {
            ERR("i-node table lock initialization failed")
            exit(-1);
        }
    }

    // deserialize superblock
    memcpy(fs_superblock.sb, sblock, sizeof(struct superblock_t));
    // deserialize bitmap and inode table
    unsigned char buf[SECTOR_SIZE], *dst_c = (unsigned char *)block_bitmap;
    for (i = BLOCK_BITMAP_SECTOR_NUM; i < INODE_BITMAP_SECTOR_NUM; ++i)
    {
        device_read_sector(buf, i);
        memcpy(dst_c, buf, SECTOR_SIZE);
        dst_c += SECTOR_SIZE;
    }

    dst_c = (unsigned char *)inode_bitmap;
    for (i = INODE_BITMAP_SECTOR_NUM; i < INODE_TABLE_SECTOR_NUM; ++i)
    {
        device_read_sector(buf, i);
        memcpy(dst_c, buf, SECTOR_SIZE);
        dst_c += SECTOR_SIZE;
    }

    struct inode_t *dst_ino = inode_info;
    for (i = INODE_TABLE_SECTOR_NUM; i < DATABLOCK_SECTOR_NUM; ++i)
    {
        device_read_sector(buf, i);
        memcpy(dst_ino, buf, sizeof(struct inode_t));
        dst_ino++;
    }

    // initialize file descriptor table
    for (i = 0; i < MAX_OPEN_FILE; ++i)
    {
        fd_table[i].fd = i;
        fd_table[i].flags = 0;
        fd_table[i].ino = -1;
        fd_table[i].used = 0;
    }
    DEBUG("P6FS mounted.")
}

// make a fresh filesystem on device
void mkp6fs()
{
    struct superblock_t sblock;
    unsigned char buf[SECTOR_SIZE] = {0};

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
    memcpy(buf, &sblock, sizeof(struct superblock_t));
    device_write_sector(buf, SUPERBLOCK_SECTOR_NUM);
    device_flush();
    device_write_sector(buf, SUPERBLOCK_BK_SECTOR_NUM);
    device_flush();

    // clear entire bitmap but the first bit
    memset(buf, 0, sizeof(buf));
    int i;
    for (i = BLOCK_BITMAP_SECTOR_NUM; i < INODE_TABLE_SECTOR_NUM; ++i)
    {
        device_write_sector(buf, i);
        device_flush();
    }

    set_bitmap(block_bitmap, 0, BLOCK_BITMAP_SECTOR_NUM);
    set_bitmap(inode_bitmap, 0, INODE_BITMAP_SECTOR_NUM);

    // create root structure
    // NOTE: the mountpoint dentry always occupies the first datablock
    struct dentry root_entries[2] = {
        {.filename = ".", .ino = 0},
        {.filename = "..", .ino = 0},
    };
    // NOTE: workaround; invalidate the rest of the sector
    memset(buf, -1, sizeof(buf));
    memcpy(buf, root_entries, sizeof(root_entries));
    device_write_sector(buf, DATABLOCK_SECTOR_NUM);
    device_flush();

    mountp6fs(&sblock);
    // allocate root inode
    struct fuse_context *fuse_con = fuse_get_context();
    uid_t uid = fuse_con->uid;
    gid_t gid = fuse_con->gid;
    struct inode_t root_inode = {.size = BLOCK_SIZE,
                                 .mode = S_IFDIR | 0755,
                                 .uid = uid,
                                 .gid = gid,
                                 .link_count = 2,
                                 .block[0] = DATABLOCK_SECTOR_NUM,
                                 .indirect_table = -1,
                                 .ctime = time(NULL),
                                 .atime = time(NULL),
                                 .mtime = time(NULL)};
    memcpy(inode_table[0].inode, &root_inode, sizeof(struct inode_t));
    flush_inode(0);
    DEBUG("P6FS build complete.")
}

// look up a given file from dentry block
int lookup_file(int blk, const char *filename)
{
    /* read block from device */
	DEBUG("Looking for %s in dentry blk at sector %d", filename, blk)
    unsigned char buf[SECTOR_SIZE];
    device_read_sector(buf, blk);

    int i;
    struct dentry *dp = (struct dentry *)buf;
    for (i = 0; i < MAX_DENTRY; ++i, ++dp)
    {
        if (!strcmp(filename, dp->filename) && dp->ino != -1)
            return dp->ino;
    }
    return -1;
}

// returns the inode number to a given path
// returns -1 if not found
int inode_from_path(const char *path)
{
    if (path[0] != '/')
        return -1;
    char path_cp[MAX_PATH_LEN];
    strcpy(path_cp, path);
    int depth = 0;
    DEBUG("Parsing path: %s", path)
    char *p = strtok(path_cp, "/");
    while (p)
    {
        ++depth;
        p = strtok(NULL, "/");
    }
    unsigned char buf[SECTOR_SIZE];
    // read root dentry
    device_read_sector(buf, DATABLOCK_SECTOR_NUM);
    memcpy(&root, buf, sizeof(struct dentry));

    // look up inode and dentry alternately
    memset(buf, 0, sizeof(buf));
    int dentry_blkn, ino = 0;
    struct inode_t *inode;

    struct fuse_context *fuse_con = fuse_get_context();
    uid_t current_uid = fuse_con->uid;
    gid_t current_gid = fuse_con->uid;
    strcpy(path_cp, path);
    p = strtok(path_cp, "/");
    while (p)
    {
        inode = inode_table[ino].inode;
        // check permission
        if (!((inode->mode & S_IROTH) ||
            (inode->mode & S_IRUSR && current_uid == inode->uid) ||
            (inode->mode & S_IRGRP && current_gid == inode->gid)))
            return -EACCES;
        // check inode type
        if (S_ISDIR(inode->mode))
        {
            dentry_blkn = inode->block[0];
            if ((ino = lookup_file(dentry_blkn, p)) == -1)
                return -ENOENT;
			DEBUG("Found file %s in directory", p)
        }
        // destination reached: symlink or regular file
        // FUSE takes care of symbolic links automatically
        else if (S_ISREG(inode->mode))
        {
            // encountered a non-directory during traverse
            if (depth > 0)
                return -ENOTDIR;
            return ino;
        }
        DEBUG("Accessing %s: ino of %s is %d", path, p, ino)
        depth--;
        p = strtok(NULL, "/");
    }

    return ino;
}

// returns the parent inode to a given path
// returns -1 if not found
int dentry_from_path(const char *path)
{
    char path_cp[MAX_FILENAME_LEN];
    strcpy(path_cp, path);
    char *last = strrchr(path_cp, '/');
    if (last == path_cp)
        return 0;
    *last = '\0';

    return inode_from_path(path_cp);
}

// data block access
void read_blocks(int ino, char *buf, off_t offset, size_t size)
{
    struct inode_t *inode = inode_table[ino].inode;
    int dir_st_block = offset / BLOCK_SIZE;
    int dir_st_off = offset % BLOCK_SIZE;
    int file_end = offset + size;
    int dir_st_sz = (file_end > BLOCK_SIZE) ? BLOCK_SIZE - dir_st_off : size;
    int indir_sz = file_end - DIRECT_BLOCK_BYTES;
    int dir_ed_block = (indir_sz > 0) ? MAX_DIRECT_NUM :
                        (file_end / BLOCK_SIZE + (file_end % BLOCK_SIZE ? 1 : 0));
    // copy the first direct block with offset
    unsigned char dbuf[SECTOR_SIZE];
    char *dst = buf;
    device_read_sector(dbuf, inode->block[dir_st_block]);
    DEBUG("Read block content: %s, up to %d bytes", dbuf + dir_st_off, dir_st_sz)
    memcpy(dst, dbuf + dir_st_off, dir_st_sz);
    dst += dir_st_sz;
    // copy other direct blocks
    int i;
    for (i = dir_st_block + 1; i < dir_ed_block; ++i)
    {
        device_read_sector(dbuf, inode->block[i]);
        memcpy(dst, dbuf, SECTOR_SIZE);
        dst += SECTOR_SIZE;
    }
    // copy indirect blocks
    if (indir_sz)
    {
        // read indirect block table
        unsigned char tbuf[SECTOR_SIZE];
        device_read_sector(tbuf, inode->indirect_table);
        int *p = (int *)tbuf;
        int nindir = indir_sz / BLOCK_SIZE + (indir_sz % BLOCK_SIZE ? 1 : 0);
        for (i = 0; i < nindir; ++i)
        {
            device_read_sector(dbuf, p[i]);
            if (i == nindir - 1)
                memcpy(dst, dbuf, indir_sz % BLOCK_SIZE);
            else
                memcpy(dst, dbuf, SECTOR_SIZE);
            dst += SECTOR_SIZE;
        }
    }
    return;
}

// precondition: enough space allocated
void write_blocks(int ino, const char *buf, off_t offset, size_t size)
{
    DEBUG("ino %d, offset %d, size %d", ino, offset, size)
    struct inode_t *inode = inode_table[ino].inode;
    int dir_st_block = offset / BLOCK_SIZE;
    int dir_st_off = offset % BLOCK_SIZE;
    int file_end = offset + size;
    int dir_st_sz = (file_end > BLOCK_SIZE) ? BLOCK_SIZE - dir_st_off : size;
    int indir_sz = (file_end > DIRECT_BLOCK_BYTES) ? file_end - DIRECT_BLOCK_BYTES : 0;
    int dir_ed_block = (indir_sz > 0) ? MAX_DIRECT_NUM :
                        (file_end / BLOCK_SIZE + (file_end % BLOCK_SIZE ? 1 : 0));
    // write the first direct block with an offset
    unsigned char dbuf[SECTOR_SIZE];
    char *src = buf;
    device_read_sector(dbuf, inode->block[dir_st_block]);
    memcpy(dbuf + dir_st_off, src, dir_st_sz);
    DEBUG("Write direct block at #%d with offset %d, size %d", inode->block[dir_st_block], dir_st_off, dir_st_sz)
    device_write_sector(dbuf, inode->block[dir_st_block]);
    device_flush();
    src += dir_st_sz;
    // write other direct blocks
    int i;
    for (i = dir_st_block + 1; i < dir_ed_block; ++i)
    {
        if (i == dir_ed_block - 1 && indir_sz < 0)
            // to prevent overflow on *buf
            memcpy(dbuf, src, file_end % BLOCK_SIZE);
        else
            memcpy(dbuf, src, SECTOR_SIZE);
        device_write_sector(dbuf, inode->block[i]);
        src += SECTOR_SIZE;
    }
    // write indirect blocks
    if (indir_sz)
    {
        DEBUG("Writing indirect blocks, since indir_sz = %d", indir_sz)
        // read indirect block table
        unsigned char tbuf[SECTOR_SIZE];
        device_read_sector(tbuf, inode->indirect_table);
        int *p = (int *)tbuf;
        int nindir = indir_sz / BLOCK_SIZE + (indir_sz % BLOCK_SIZE ? 1 : 0);
        for (i = 0; i < nindir; ++i)
        {
            if (i == nindir - 1) {
                memset(dbuf, 0, sizeof(dbuf));
                memcpy(dbuf, src, indir_sz % BLOCK_SIZE);
            }
            else
                memcpy(dbuf, src, SECTOR_SIZE);
            device_write_sector(dbuf, p[i]);
            device_flush();
            src += SECTOR_SIZE;
        }
    }
    return;
}

// precondition: size of ino > new_size
void recycle_blocks(int ino, int new_size)
{
    struct inode_t *inode = inode_table[ino].inode;
    // recycle rear blocks
    // modify block bitmap, no need to zero the blocks
    int nblocks_old = (inode->size / BLOCK_SIZE) + (inode->size % BLOCK_SIZE ? 1 : 0);
    int nblocks = (new_size / BLOCK_SIZE) + (new_size % BLOCK_SIZE ? 1 : 0);
    // reducing mutex overhead
    if (nblocks_old == nblocks)
        return;
    // starting with the first indirect block to recycle
    // no need to lock block bitmap since we are releasing the resources
    pthread_mutex_lock(&inode_table[ino].lock);
    int i;
    for (i = nblocks; i < MAX_INDIRECT_NUM; ++i) {
        clear_bitmap(block_bitmap, inode->block[i], BLOCK_BITMAP_SECTOR_NUM);
        inode->block[i] = -1;
    }
    int nindir_old = nblocks_old - MAX_INDIRECT_NUM;
    if (nindir_old >= 0)
    {
        int nindir = nblocks - MAX_INDIRECT_NUM;
        if (nindir < 0)
            nindir = 0;
        unsigned char tbuf[SECTOR_SIZE];
        device_read_sector(tbuf, inode->indirect_table);
        int i, *p = (int *)tbuf;
        for (i = nindir; i < nindir_old; ++i)
            clear_bitmap(block_bitmap, p[i], BLOCK_BITMAP_SECTOR_NUM);
        if (nblocks <= MAX_INDIRECT_NUM)
        {
            clear_bitmap(block_bitmap, inode->indirect_table, BLOCK_BITMAP_SECTOR_NUM);
            inode->indirect_table = -1;
        }
    }
    inode->size = new_size;
    pthread_mutex_unlock(&inode_table[ino].lock);

    return;
}

// allocate space for ino so that it has at least new_size bytes
int alloc_blocks(int ino, int new_size)
{
    struct inode_t *inode = inode_table[ino].inode;
    if (new_size > MAX_FILE_SIZE)
        return -EFBIG;
    int i;
    int ndir, nindir;
    int nblocks_old = inode->size / BLOCK_SIZE + (inode->size % BLOCK_SIZE ? 1 : 0),
        nblocks = new_size / BLOCK_SIZE + (new_size % BLOCK_SIZE ? 1 : 0);
    int new_blocks = nblocks - nblocks_old;
    pthread_mutex_lock(&inode_table[ino].lock);
    pthread_mutex_lock(&block_bitmap_lock);
    int indir_blk = -1;
    if (inode->size <= DIRECT_BLOCK_BYTES && new_size <= DIRECT_BLOCK_BYTES) {
        ndir = new_blocks;
        nindir = 0;
    }
    else if (inode->size <= DIRECT_BLOCK_BYTES && new_size > DIRECT_BLOCK_BYTES) {
        // allocate indirect table block
        int found = 0;
        for (i = 0; i < TOTAL_BLOCKS; ++i)
            if (!test_bit(block_bitmap, i)) {
                indir_blk = i;
                found = 1;
                break;
            }
        if (!found) {
            pthread_mutex_unlock(&block_bitmap_lock);
            pthread_mutex_unlock(&inode_table[ino].lock);
            return -ENOSPC;
        }
    }
    else if (inode->size >= DIRECT_BLOCK_BYTES) {
        ndir = 0;
        nindir = new_blocks;
    }
    // allocate datablocks
    int nalloc = 0;
    int table[MAX_INDIRECT_NUM];
    for (i = 0; i < TOTAL_BLOCKS; ++i)
        // if there aren't enough, cancel selection
        if (!test_bit(block_bitmap, i))
        {
            table[nalloc++] = i;
            if (nalloc == new_blocks)
                break;
        }
    DEBUG("Allocated %d / %d block(s)", nalloc, new_blocks)
    if (nalloc < new_blocks)
    {
        pthread_mutex_unlock(&block_bitmap_lock);
        pthread_mutex_unlock(&inode_table[ino].lock);
        return -ENOSPC;
    }
    else
    {
        pthread_mutex_lock(&fs_superblock.lock);
        // allocate new direct blocks
        for (i = 0; i < ndir; ++i)
        {
            inode->block[nblocks_old + i] = DATABLOCK_SECTOR_NUM + table[i];
            DEBUG("Direct block #%d pointing to sector %d", nblocks_old + i, inode->block[nblocks_old + i])
        }
        if (nindir > 0)
        {
            unsigned char tbuf[SECTOR_SIZE] = {0};
            int *p = (int *)tbuf;
            // allocate indirect table block, if needed
            if (indir_blk > 0) {
                set_bitmap(block_bitmap, indir_blk, BLOCK_BITMAP_SECTOR_NUM);
                inode->indirect_table = DATABLOCK_SECTOR_NUM + indir_blk;
                --fs_superblock.sb->free_block_cnt;
                DEBUG("Allocated indirect table block at sector %d", indir_blk)
            }
            else
                // read pre-existing indirect table
                device_read_sector(tbuf, inode->indirect_table);
            // allocate new indirect blocks
            int table_offset = (indir_blk > 0) ? 0 : nblocks_old - MAX_DIRECT_NUM;
            int new_offset = nblocks - MAX_DIRECT_NUM;
            int j;
            for (i = table_offset, j = ndir; i < new_offset; ++i, ++j) {
                p[i] = DATABLOCK_SECTOR_NUM + table[j];
                DEBUG("Indirect table entry #%d: sector %d", i, p[i])
            }
            device_write_sector(tbuf, inode->indirect_table);
            device_flush();
        }
        for (i = 0; i < new_blocks; ++i)
            set_bitmap(block_bitmap, table[i], BLOCK_BITMAP_SECTOR_NUM);
        DEBUG("Bitmap updated.")
        fs_superblock.sb->free_block_cnt -= new_blocks;
        flush_superblock();
        pthread_mutex_unlock(&fs_superblock.lock);
        inode->size = new_size;
        flush_inode(ino);
    }
    pthread_mutex_unlock(&block_bitmap_lock);
    pthread_mutex_unlock(&inode_table[ino].lock);
    return 0;
}

// FUSE operation implementations

/* Create a directory with the given name.
  The directory permissions are encoded in mode. */
int p6fs_mkdir(const char *path, mode_t mode)
{
    /* do path parse here
      create dentry and update your index */
    int ino = inode_from_path(path);
    if (ino >= 0)
        return -EEXIST;
    int parent_ino = dentry_from_path(path);
    if (parent_ino < 0)
        return parent_ino;
    // dentry block no.
    int parent_blk = inode_table[parent_ino].inode->block[0];
    // find free i-node
    // NOTE: once we lock the bitmap, the free i-node will not be snatched
    pthread_mutex_lock(&inode_bitmap_lock);
    int i, has_free_ino = 0;
    for (i = 0; i < MAX_INODE; ++i)
    {
        if (!test_bit(inode_bitmap, i))
        {
            has_free_ino = 1;
            break;
        }
    }
    if (!has_free_ino) {
        pthread_mutex_unlock(&inode_bitmap_lock);
        return -ENOMEM;
    }
    ino = i;
    // allocate dentry block
    pthread_mutex_lock(&block_bitmap_lock);
    int has_free_blk = 0;
    for (i = 0; i < TOTAL_BLOCKS; ++i)
        if (!test_bit(block_bitmap, i))
        {
            has_free_blk = 1;
            break;
        }
    if (!has_free_blk) {
        pthread_mutex_unlock(&block_bitmap_lock);
        pthread_mutex_unlock(&inode_bitmap_lock);
        return -ENOSPC;
    }
    int dentry_blkn = i;
    // add a dentry in parent folder
    int has_free_entry = 0;
    char *last = strrchr(path, '/') + 1;
    unsigned char buf[SECTOR_SIZE];
    device_read_sector(buf, parent_blk);
    struct dentry *dp = (struct dentry *)buf;
    for (i = 0; i < MAX_DENTRY; ++i, ++dp)
    {
        if (dp->ino == -1)
        {
            has_free_entry = 1;
            break;
        }
    }
    if (!has_free_entry) {
        pthread_mutex_unlock(&block_bitmap_lock);
        pthread_mutex_unlock(&inode_bitmap_lock);
        return -ENOSPC;
    }
    set_bitmap(block_bitmap, dentry_blkn, BLOCK_BITMAP_SECTOR_NUM);
    pthread_mutex_unlock(&block_bitmap_lock);

    // ".." gives the parent folder another hard link
    pthread_mutex_lock(&inode_table[parent_ino].lock);
    ++inode_table[parent_ino].inode->link_count;
    flush_inode(parent_ino);
    pthread_mutex_unlock(&inode_table[parent_ino].lock);

    // allocate inode
    set_bitmap(inode_bitmap, ino, INODE_BITMAP_SECTOR_NUM);
    pthread_mutex_unlock(&inode_bitmap_lock);
    pthread_mutex_lock(&inode_table[ino].lock);
    struct inode_t *inode = inode_table[ino].inode;
    struct fuse_context *fuse_con = fuse_get_context();
    uid_t uid = fuse_con->uid;
    gid_t gid = fuse_con->gid;
    inode->ctime = time(NULL);
    inode->mtime = time(NULL);
    inode->atime = time(NULL);
    inode->mode = S_IFDIR | mode;
    inode->size = BLOCK_SIZE;
    inode->link_count = 2;
    inode->block[0] = DATABLOCK_SECTOR_NUM + dentry_blkn;
    inode->indirect_table = -1;
    inode->uid = uid;
    inode->gid = gid;
    flush_inode(ino);
    pthread_mutex_unlock(&inode_table[ino].lock);
    
    // add dentry to parent folder
    strcpy(dp->filename, last);
    dp->ino = ino;
    device_write_sector(buf, parent_blk);
    device_flush();
    // write dentry block to device
    // invalidate other directory entries
    memset(buf, -1, sizeof(buf));
    struct dentry default_entries[2] = {
                {.filename = ".", .ino = ino},
                {.filename = "..", .ino = parent_ino},
            };
    memcpy(buf, default_entries, sizeof(default_entries));
    device_write_sector(buf, DATABLOCK_SECTOR_NUM + dentry_blkn);
    device_flush();
    pthread_mutex_lock(&fs_superblock.lock);
    --fs_superblock.sb->free_block_cnt;
    --fs_superblock.sb->free_inode_cnt;
    flush_superblock();
    pthread_mutex_unlock(&fs_superblock.lock);
    DEBUG("Created new directory with i-node %d, dentry blk #%d", ino, dentry_blkn)

    return 0;
}

/* Remove the given directory. This should succeed only
if the directory is empty (except for "." and ".."). */
int p6fs_rmdir(const char *path)
{
    if (!strcmp(path, ".") || !strcmp(path, ".."))
        return -EINVAL;
    int ino = inode_from_path(path);
    if (ino < 0)
        return ino;

    // check if directory is empty
    struct inode_t *inode = inode_table[ino].inode;
    unsigned char buf[SECTOR_SIZE];
    device_read_sector(buf, inode->block[0]);

    int i;
    struct dentry *dp = (struct dentry *)buf;
    for (i = 0; i < MAX_DENTRY; ++i, ++dp)
    {
        if (dp->ino == -1 || i == 0 || i == 1)
            continue;
        else
            return -ENOTEMPTY;
    }
    // free dentry block
    clear_bitmap(block_bitmap, inode->block[0], DATABLOCK_SECTOR_NUM);
    // free directory inode and remove dentry in parent
    pthread_mutex_lock(&inode_table[ino].lock);
    pthread_mutex_lock(&inode_bitmap_lock);
    pthread_mutex_lock(&fs_superblock.lock);
    int parent_ino = dentry_from_path(path);
    int parent_blk = inode_table[parent_ino].inode->block[0];
    device_read_sector(buf, parent_blk);
    dp = (struct dentry *)buf;
    for (i = 0; i < MAX_DENTRY; ++i, ++dp)
    {
        if (ino == dp->ino)
        {
            dp->ino = -1;
            break;
        }
    }
    device_write_sector(buf, parent_blk);
    device_flush();
    clear_bitmap(inode_bitmap, ino, INODE_BITMAP_SECTOR_NUM);
    ++fs_superblock.sb->free_inode_cnt;
    ++fs_superblock.sb->free_block_cnt;
    flush_superblock();
    pthread_mutex_unlock(&fs_superblock.lock);
    pthread_mutex_unlock(&inode_bitmap_lock);
    pthread_mutex_unlock(&inode_table[ino].lock);
    DEBUG("Directory %s removed", path)

    return 0;
}

// Return one or more directory entries (struct dentry) to the caller.
int p6fs_readdir(const char *path, void *buf, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info *fileInfo)
{
    INFO("Listing directory %s", path)
    int dir_ino = inode_from_path(path);
    if (dir_ino < 0)
        return dir_ino;

    struct inode_t *dir_inode = inode_table[dir_ino].inode;
    unsigned char dbuf[SECTOR_SIZE];
    // a directory block should take no more than a sector
    device_read_sector(dbuf, dir_inode->block[0]);

    int i, ret;
    struct dentry *dp = (struct dentry *)dbuf;
    struct stat stbuf;
    for (i = 0; i < MAX_DENTRY; ++i, dp++)
    {
        if (dp->ino == -1)
            continue;
        stbuf.st_mode = inode_table[dp->ino].inode->mode;
        stbuf.st_ino = dp->ino;
        if ((ret = filler(buf, dp->filename, &stbuf, 0)))
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
    /* essentialy the same as mkdir and symlink */
    int ino = inode_from_path(path);
    if (ino >= 0)
        return -EEXIST;
    int parent_ino = dentry_from_path(path);
    if (parent_ino < 0)
        return parent_ino;
    // dentry block no.
    int parent_blk = inode_table[parent_ino].inode->block[0];
    // find free i-node
    pthread_mutex_lock(&inode_bitmap_lock);
    int i, has_free_ino = 0;
    for (i = 0; i < MAX_INODE; ++i)
    {
        if (!test_bit(inode_bitmap, i))
        {
            has_free_ino = 1;
            break;
        }
    }
    if (!has_free_ino) {
        pthread_mutex_unlock(&inode_bitmap_lock);
        return -ENOMEM;
    }
    ino = i;
    // add a dentry in parent folder
    int has_free_entry = 0;
    char *last = strrchr(path, '/') + 1;
    unsigned char buf[SECTOR_SIZE];
    device_read_sector(buf, parent_blk);
    struct dentry *dp = (struct dentry *)buf;
    for (i = 0; i < MAX_DENTRY; ++i, ++dp)
    {
        if (dp->ino == -1)
        {
            has_free_entry = 1;
            break;
        }
    }
    if (!has_free_entry) {
        pthread_mutex_unlock(&inode_bitmap_lock);
        return -ENOSPC;
    }

    // allocate inode
    set_bitmap(inode_bitmap, ino, INODE_BITMAP_SECTOR_NUM);
    pthread_mutex_unlock(&inode_bitmap_lock);
    pthread_mutex_lock(&inode_table[ino].lock);
    struct inode_t *inode = inode_table[ino].inode;
    struct fuse_context *fuse_con = fuse_get_context();
    uid_t uid = fuse_con->uid;
    gid_t gid = fuse_con->gid;
    inode->ctime = time(NULL);
    inode->mtime = time(NULL);
    inode->atime = time(NULL);
    inode->mode = S_IFREG | mode;
    inode->size = 0;
    inode->link_count = 1;
    memset(inode->block, -1, sizeof(inode->block));
    inode->indirect_table = -1;
    inode->uid = uid;
    inode->gid = gid;
    flush_inode(ino);
    pthread_mutex_unlock(&inode_table[ino].lock);
    
    // add dentry to parent folder
    strcpy(dp->filename, last);
    dp->ino = ino;
    device_write_sector(buf, parent_blk);
    device_flush();
    pthread_mutex_lock(&fs_superblock.lock);
    --fs_superblock.sb->free_inode_cnt;
    flush_superblock();
    pthread_mutex_unlock(&fs_superblock.lock);
    DEBUG("Created new file %s with i-node %d", path, ino)

    return 0;
}

// If path is a symbolic link, fill link with its target, up to size.
int p6fs_readlink(const char *path, char *link, size_t size)
{
    int ino = inode_from_path(path);
    if (ino < 0)
        return ino;
    struct inode_t *inode = inode_table[ino].inode;
    if (!(S_ISLNK(inode->mode)))
        return -EINVAL;

    unsigned char buf[SECTOR_SIZE];
    memset(buf, 0, sizeof(buf));
    device_read_sector(buf, inode->block[0]);
    memcpy(link, buf, size);

    return 0;
}

// Create a symbolic link named "link" which, when evaluated, will lead to "path".
int p6fs_symlink(const char *path, const char *link)
{
    // NOTE: FUSE does not allow auto overwrite over existing symlinks
    int ino = inode_from_path(link);
    if (ino > 0)
        return -EEXIST;
    int parent_ino = dentry_from_path(link);
    if (parent_ino < 0)
        return parent_ino;
    int parent_blk = inode_table[parent_ino].inode->block[0];

    int i, dentry_blkn;
    // allocate inode and data block
    pthread_mutex_lock(&inode_bitmap_lock);
    int has_free_ino = 0;
    for (i = 0; i < MAX_INODE; ++i)
    {
        if (!test_bit(inode_bitmap, i))
        {
            has_free_ino = 1;
            break;
        }
    }
    if (!has_free_ino) {
        pthread_mutex_unlock(&inode_bitmap_lock);
        return -ENOMEM;
    }
    ino = i;
    // allocate dentry block
    pthread_mutex_lock(&block_bitmap_lock);
    int has_free_blk = 0;
    for (i = 0; i < TOTAL_BLOCKS; ++i)
        if (!test_bit(block_bitmap, i))
        {
            has_free_blk = 1;
            break;
        }
    if (!has_free_blk) {
        pthread_mutex_unlock(&block_bitmap_lock);
        pthread_mutex_unlock(&inode_bitmap_lock);
        return -ENOSPC;
    }
    dentry_blkn = i;
    
    // add a dentry in parent folder
    int has_free_entry = 0;
    char *last = strrchr(link, '/') + 1;
    unsigned char buf[SECTOR_SIZE];
    device_read_sector(buf, parent_blk);
    struct dentry *dp = (struct dentry *)buf;
    for (i = 0; i < MAX_DENTRY; ++i, ++dp)
    {
        if (dp->ino == -1)
        {
            has_free_entry = 1;
            break;
        }
    }
    if (!has_free_entry)
    {
        pthread_mutex_unlock(&block_bitmap_lock);
        pthread_mutex_unlock(&inode_bitmap_lock);
        return -ENOSPC;
    }
    else
    {
        set_bitmap(block_bitmap, dentry_blkn, BLOCK_BITMAP_SECTOR_NUM);
        pthread_mutex_unlock(&block_bitmap_lock);
        set_bitmap(inode_bitmap, ino, INODE_BITMAP_SECTOR_NUM);
        pthread_mutex_unlock(&inode_bitmap_lock);
        pthread_mutex_lock(&inode_table[ino].lock);
        struct inode_t *inode = inode_table[ino].inode;
        struct fuse_context *fuse_con = fuse_get_context();
        uid_t uid = fuse_con->uid;
        gid_t gid = fuse_con->gid;
        inode->ctime = time(NULL);
        inode->mtime = time(NULL);
        inode->atime = time(NULL);
        inode->mode = S_IFLNK | 0777;
        inode->size = strlen(path);
        inode->link_count = 1;
        inode->block[0] = DATABLOCK_SECTOR_NUM + dentry_blkn;
        inode->indirect_table = -1;
        inode->uid = uid;
        inode->gid = gid;
        flush_inode(ino);
        pthread_mutex_unlock(&inode_table[ino].lock);

        // add dentry to parent folder
        strcpy(dp->filename, last);
        dp->ino = ino;
        device_write_sector(buf, parent_blk);
        device_flush();
        // write symlink data
        memset(buf, 0, sizeof(buf));
        strcpy((char *)buf, path);
        device_write_sector(buf, inode->block[0]);
        device_flush();
        pthread_mutex_lock(&fs_superblock.lock);
        --fs_superblock.sb->free_block_cnt;
        --fs_superblock.sb->free_inode_cnt;
        flush_superblock();
        pthread_mutex_unlock(&fs_superblock.lock);
        DEBUG("Created symlink with i-node %d: %s -> %s", ino, link, path)
    }

    return 0;
}

// Create a hard link between "path" and "newpath".
int p6fs_link(const char *path, const char *newpath)
{
    int ino = inode_from_path(newpath);
    if (ino >= 0)
        return -EEXIST;
    ino = inode_from_path(path);
    if (ino < 0)
        return ino;
    int parent_blk = dentry_from_path(newpath);
    if (parent_blk < 0)
        return parent_blk;
    parent_blk = inode_table[dentry_from_path(path)].inode->block[0];
    struct inode_t *inode = inode_table[ino].inode;
    // cannot create hard link to directory
    if (S_ISDIR(inode->mode))
        return -EISDIR;
    
    int has_free_entry = 0;
    unsigned char buf[SECTOR_SIZE];
    char *last = strrchr(newpath, '/') + 1;
    device_read_sector(buf, parent_blk);
    int i;
    struct dentry *dp = (struct dentry *)buf;
    for (i = 0; i < MAX_DENTRY; ++i, ++dp)
    {
        if (dp->ino == -1)
        {
            has_free_entry = 1;
            break;
        }
    }
    if (!has_free_entry)
        return -ENOSPC;
    else
    {
        // increment link count
        ++inode->link_count;
        // add dentry
        strcpy(dp->filename, last);
        dp->ino = ino;
        device_write_sector(buf, parent_blk);
        device_flush();
    }
    return 0;
}

// Remove (delete) the given file, symbolic link, hard link, or special node.
int p6fs_unlink(const char *path)
{
    int ino = inode_from_path(path);
    if (ino < 0)
        return ino;
    struct inode_t *inode = inode_table[ino].inode;
    if (S_ISDIR(inode->mode))
        return -EISDIR;

    // delete dentry
    char *last = strrchr(path, '/') + 1;
    unsigned char buf[SECTOR_SIZE];
    int parent_blk = dentry_from_path(path);
    parent_blk = inode_table[dentry_from_path(path)].inode->block[0];
    device_read_sector(buf, parent_blk);

    int i;
    struct dentry *dp = (struct dentry *)buf;
    for (i = 0; i < MAX_DENTRY; ++i, ++dp)
    {
        if (!strcmp(last, dp->filename))
        {
            dp->ino = -1;
            break;
        }
    }
    device_write_sector(buf, parent_blk);
    device_flush();
    // free inode
    // hard links are not distinguishable
    pthread_mutex_lock(&inode_table[ino].lock);
    pthread_mutex_lock(&fs_superblock.lock);
    pthread_mutex_lock(&inode_bitmap_lock);
    if (--inode->link_count == 0) {
        clear_bitmap(inode_bitmap, ino, INODE_BITMAP_SECTOR_NUM);
        ++fs_superblock.sb->free_inode_cnt;
        flush_superblock();
        recycle_blocks(ino, 0);
    }
    flush_inode(ino);
    pthread_mutex_unlock(&inode_bitmap_lock);
    pthread_mutex_unlock(&fs_superblock.lock);
    pthread_mutex_unlock(&inode_table[ino].lock);

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
    int ino = inode_from_path(path);
    if (ino < 0)
        return ino;

    struct inode_t *inode = inode_table[ino].inode;
    inode->atime = time(NULL);
    // assign and init your file handle
    struct file_info *fi = NULL;
    int i;
    for (i = 0; i < MAX_OPEN_FILE; ++i)
    {
        if (!fd_table[i].used)
        {
            fd_table[i].used = 1;
            fd_table[i].ino = ino;
            fi = &fd_table[i];
            break;
        }
    }
    if (!fi)
        return -ENFILE;

    struct fuse_context *fuse_con = fuse_get_context();
    uid_t current_uid = fuse_con->uid;
    gid_t current_gid = fuse_con->uid;

    // check open flags, such as O_RDONLY
    // O_CREATE is transformed to mknod() + open() by fuse, so no need to create file here
    if ((fileInfo->flags & O_RDONLY) == O_RDONLY) {
        if (!((inode->mode & S_IROTH) ||
            (inode->mode & S_IRUSR && current_uid == inode->uid) ||
            (inode->mode & S_IRGRP && current_gid == inode->gid)))
            return -EACCES;
        fi->rd = 1;
    }
    if ((fileInfo->flags & O_WRONLY) == O_WRONLY) {
        if (!((inode->mode & S_IWOTH) ||
            (inode->mode & S_IWUSR && current_uid == inode->uid) ||
            (inode->mode & S_IWGRP && current_gid == inode->gid)))
            return -EACCES;
        fi->wr = 1;
    }
        
    if ((fileInfo->flags & O_APPEND) == O_APPEND) {
        if (!((inode->mode & S_IWOTH) ||
            (inode->mode & S_IWUSR && current_uid == inode->uid) ||
            (inode->mode & S_IWGRP && current_gid == inode->gid)))
            return -EACCES;
        fi->app = 1;
    }
    if ((fileInfo->flags & O_RDWR) == O_RDWR)
    {
        if (!((inode->mode & (S_IROTH | S_IWOTH)) ||
            (inode->mode & (S_IRUSR | S_IWUSR) && current_uid == inode->uid) ||
            (inode->mode & (S_IRGRP | S_IWGRP) && current_gid == inode->gid)))
            return -EACCES;
        fi->rd = 1;
        fi->wr = 1;
    }

    fileInfo->fh = (uint64_t)fi;
    return 0;
}

/* Read size bytes from the given file into the buffer buf,
  beginning offset bytes into the file. Returns the number of
  bytes transferred, or 0 if offset was at or beyond the end of the file. */
int p6fs_read(const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *fileInfo)
{
    /* get inode from file handle and do operation */
    struct file_info *fi = (struct file_info *)fileInfo->fh;
    int ino = fi->ino;
    struct inode_t *inode = inode_table[ino].inode;
    DEBUG("Initiating read: ino %d, offset %d, size %d", ino, offset, size)
    if (offset >= inode->size)
        return 0;

    // access direct and indirect blocks
    read_blocks(ino, buf, offset, size);
    return size;
}

// Returns the number of bytes transferred.
int p6fs_write(const char *path, const char *buf, size_t size, off_t offset, struct fuse_file_info *fileInfo)
{
    DEBUG("Write initiated: file %s, size %d, offset %d", path, size, offset)
    /* get inode from file handle and do operation */
    struct file_info *fi = (struct file_info *)fileInfo->fh;
    int ino = fi->ino;
    struct inode_t *inode = inode_table[ino].inode;
    if (fi->app)
        offset = inode->size;
    int new_size = offset + size;
    int ret;
    if (new_size > inode->size)
        if ((ret = alloc_blocks(ino, new_size)) < 0)
            // either file is too large or device has no free space
            return ret;
    write_blocks(ino, buf, offset, size);
    return size;
}

// Truncate or extend the given file so that it is precisely newSize bytes long.
int p6fs_truncate(const char *path, off_t newSize)
{
    int ino = inode_from_path(path);
    if (ino < 0)
        return ino;
    struct inode_t *inode = inode_table[ino].inode;
    if (inode->size == newSize)
        return 0;
    else if (inode->size > newSize)
        recycle_blocks(ino, newSize);
    else
    {
        int ret;
        if ((ret = alloc_blocks(ino, newSize)) == -1)
            return -ENOSPC;
    }
    flush_inode(ino);

    return 0;
}

//optional
//p6fs_flush(const char *path, struct fuse_file_info *fileInfo)
//int p6fs_fsync(const char *path, int datasync, struct fuse_file_info *fi)

/* release is called when FUSE is completely done with a file;
  at that point, you can free up any temporarily allocated data structures. */
int p6fs_release(const char *path, struct fuse_file_info *fileInfo)
{
    /* release fd */
    struct file_info *fi = (struct file_info *)fileInfo->fh;
    fd_table[fi->fd].ino = -1;
    fd_table[fi->fd].used = 0;

    return 0;
}

int p6fs_getattr(const char *path, struct stat *statbuf)
{
    /* stat() file or directory */
    int ino = inode_from_path(path);
    if (ino < 0)
        return ino;

    memset(statbuf, 0, sizeof(stat));
    struct inode_t *inode = inode_table[ino].inode;
    statbuf->st_ino = ino + 1;
    statbuf->st_nlink = inode->link_count;
    statbuf->st_size = inode->size;
    statbuf->st_mode = inode->mode;
    statbuf->st_mtime = inode->mtime;
    statbuf->st_atime = inode->atime;
    statbuf->st_ctime = inode->ctime;

    return 0;
}

int p6fs_utime(const char *path, struct utimbuf *ubuf)
{
    int ino = inode_from_path(path);
    if (ino < 0)
        return ino;
    struct inode_t *inode = inode_table[ino].inode;
    struct fuse_context *fuse_con = fuse_get_context();
    uid_t current_uid = fuse_con->uid;

    if (current_uid != inode->uid) {
        if (ubuf == NULL)
            return -EACCES;
        else
            return -EPERM;
    }
    else
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
    int ino = inode_from_path(path);
    if (ino < 0)
        return ino;

    struct fuse_context *fuse_con = fuse_get_context();
    uid_t uid = fuse_con->uid;

    struct inode_t *inode = inode_table[ino].inode;
    if (uid != inode->uid)
        return -EPERM;
    else {
        pthread_mutex_lock(&inode_table[ino].lock);
        inode->mode &= ~ALLPERMS;
        inode->mode |= (mode & ALLPERMS);
        inode->ctime = time(NULL);
        flush_inode(ino);
        pthread_mutex_unlock(&inode_table[ino].lock);
    }

    return 0;
}

int p6fs_chown(const char *path, uid_t uid, gid_t gid)
{
    int ino = inode_from_path(path);
    if (ino < 0)
        return ino;

    struct inode_t *inode = inode_table[ino].inode;
    struct fuse_context *fuse_con = fuse_get_context();
    uid_t current_uid = fuse_con->uid;
    if (current_uid != inode->uid)
        return -EPERM;
    else
    {
        pthread_mutex_lock(&inode_table[ino].lock);
        inode->uid = uid;
        inode->gid = gid;
        inode->ctime = time(NULL);
        flush_inode(ino);
        pthread_mutex_unlock(&inode_table[ino].lock);
    }

    return 0;
}

int p6fs_rename(const char *path, const char *newpath)
{
    // find corresponding dentry and rename
    // write info back to disk
    int ino = inode_from_path(path);
    if (ino < 0)
        return ino;
    ino = inode_from_path(newpath);
    if (ino >= 0)
        return -EEXIST;
    if (strstr(path, newpath))
        return -EINVAL;

    int parent_blk = dentry_from_path(path);
    parent_blk = inode_table[dentry_from_path(path)].inode->block[0];
    char name[MAX_FILENAME_LEN], newname[MAX_FILENAME_LEN];
    char *last = strrchr(path, '/') + 1;
    if (*last == '\0' || *last == '.')
        return -EINVAL;
    strcpy(name, last);

    last = strrchr(newpath, '/') + 1;
    strcpy(newname, last);

    // iterate through all dentry items
    unsigned char buf[SECTOR_SIZE];
    device_read_sector(buf, parent_blk);
    int i;
    struct dentry *dp = (struct dentry *)buf;
    for (i = 0; i < MAX_DENTRY; ++i, ++dp)
    {
        if (dp->ino == -1)
            continue;
        if (!strcmp(name, dp->filename))
        {
            strcpy(dp->filename, newname);
            device_write_sector(buf, parent_blk);
            device_flush();
            return 0;
        }
    }
    return -ENOENT;
}

// Return statistics about the filesystem.
int p6fs_statfs(const char *path, struct statvfs *statInfo)
{
    if (path[0] != '/')
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
    statInfo->f_flag = 0;
    statInfo->f_namemax = MAX_FILENAME_LEN;

    return 0;
}

void *p6fs_init(struct fuse_conn_info *conn)
{
    /* init fs: create or rebuild memory structures. */
    unsigned char buf[SECTOR_SIZE];
    struct superblock_t sblock_buf;

    if (device_open(DISK_ROOT) == -1)
    {
        ERR("Failed to open disk")
        exit(-1);
    }
    device_read_sector(buf, SUPERBLOCK_SECTOR_NUM);
    memcpy(&sblock_buf, buf, sizeof(struct superblock_t));

    // check if there is an existing filesystem
    int exist = 0;
    if (sblock_buf.magic_number == P6FS_MAGIC)
    {
        exist = 1;
        INFO("Found P6FS filesystem on disk %s", DISK_ROOT)
        char md5_orig[33], md5_backup[33];
        strcpy(md5_orig, digestMemory(buf, sizeof(struct superblock_t)));
        DEBUG("Superblock #1 MD5: %s", md5_orig)
        INFO("Verifying superblock checksum")
        device_read_sector(buf, SUPERBLOCK_BK_SECTOR_NUM);
        strcpy(md5_backup, digestMemory(buf, sizeof(struct superblock_t)));
        DEBUG("Superblock #2 MD5: %s", md5_backup)
        if (!strcmp(md5_orig, md5_backup))
            INFO("Checksum test passed")
        else
            ERR("Checksum test failed, rebuilding superblock")
            // TODO: rebuild superblock
    }
    else
    {
        // use backup superblock
        memcpy(&sblock_buf, buf, sizeof(struct superblock_t));
        if (sblock_buf.magic_number == P6FS_MAGIC)
        {
            exist = 1;
            INFO("Using backup superblock at sector %d", SUPERBLOCK_BK_SECTOR_NUM)
            // CHKDSK: fix superblock
            device_write_sector(buf, SUPERBLOCK_SECTOR_NUM);
            device_flush();
        }
    }

    if (exist)
        mountp6fs(&sblock_buf);
    else
    {
        INFO("Creating filesystem on %s", DISK_ROOT)
        mkp6fs();
    }

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
