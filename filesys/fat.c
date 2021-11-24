#include "filesys/fat.h"

#include <stdio.h>
#include <string.h>

#include "devices/disk.h"
#include "filesys/filesys.h"
#include "filesys/directory.h"
#include "threads/malloc.h"
#include "threads/synch.h"

/* Should be less than DISK_SECTOR_SIZE */
struct fat_boot {
    unsigned int magic;
    unsigned int sectors_per_cluster; /* Fixed to 1 */
    unsigned int total_sectors;
    unsigned int fat_start;
    unsigned int fat_sectors; /* Size of FAT in sectors. */
    unsigned int root_dir_cluster;
};

/* FAT FS */
struct fat_fs {
    struct fat_boot bs;
    unsigned int *fat;
    unsigned int fat_length;
    disk_sector_t data_start;
    cluster_t last_clst;
    struct lock write_lock;
};

static struct fat_fs *fat_fs;

void fat_boot_create(void);
void fat_fs_init(void);

void fat_init(void) {
    fat_fs = calloc(1, sizeof(struct fat_fs));
    if (fat_fs == NULL)
        PANIC("FAT init failed");

    // Read boot sector from the disk
    unsigned int *bounce = malloc(DISK_SECTOR_SIZE);
    if (bounce == NULL)
        PANIC("FAT init failed");
    disk_read(filesys_disk, FAT_BOOT_SECTOR, bounce);
    memcpy(&fat_fs->bs, bounce, sizeof(fat_fs->bs));
    free(bounce);

    // Extract FAT info
    if (fat_fs->bs.magic != FAT_MAGIC)
        fat_boot_create();
    fat_fs_init();
}

void fat_open(void) {
    fat_fs->fat = calloc(fat_fs->fat_length, sizeof(cluster_t));
    if (fat_fs->fat == NULL)
        PANIC("FAT load failed");

    // Load FAT directly from the disk
    uint8_t *buffer = (uint8_t *)fat_fs->fat;
    off_t bytes_read = 0;
    off_t bytes_left = sizeof(fat_fs->fat);
    const off_t fat_size_in_bytes = fat_fs->fat_length * sizeof(cluster_t);
    for (unsigned i = 0; i < fat_fs->bs.fat_sectors; i++) {
        bytes_left = fat_size_in_bytes - bytes_read;
        if (bytes_left >= DISK_SECTOR_SIZE) {
            disk_read(filesys_disk, fat_fs->bs.fat_start + i,
                      buffer + bytes_read);
            bytes_read += DISK_SECTOR_SIZE;
        } else {
            uint8_t *bounce = malloc(DISK_SECTOR_SIZE);
            if (bounce == NULL)
                PANIC("FAT load failed");
            disk_read(filesys_disk, fat_fs->bs.fat_start + i, bounce);
            memcpy(buffer + bytes_read, bounce, bytes_left);
            bytes_read += bytes_left;
            free(bounce);
        }
    }
}

void fat_close(void) {
    // Write FAT boot sector
    uint8_t *bounce = calloc(1, DISK_SECTOR_SIZE);
    if (bounce == NULL)
        PANIC("FAT close failed");
    memcpy(bounce, &fat_fs->bs, sizeof(fat_fs->bs));
    disk_write(filesys_disk, FAT_BOOT_SECTOR, bounce);
    free(bounce);

    // Write FAT directly to the disk
    uint8_t *buffer = (uint8_t *)fat_fs->fat;
    off_t bytes_wrote = 0;
    off_t bytes_left = sizeof(fat_fs->fat);
    const off_t fat_size_in_bytes = fat_fs->fat_length * sizeof(cluster_t);
    for (unsigned i = 0; i < fat_fs->bs.fat_sectors; i++) {
        bytes_left = fat_size_in_bytes - bytes_wrote;
        if (bytes_left >= DISK_SECTOR_SIZE) {
            disk_write(filesys_disk, fat_fs->bs.fat_start + i,
                       buffer + bytes_wrote);
            bytes_wrote += DISK_SECTOR_SIZE;
        } else {
            bounce = calloc(1, DISK_SECTOR_SIZE);
            if (bounce == NULL)
                PANIC("FAT close failed");
            memcpy(bounce, buffer + bytes_wrote, bytes_left);
            disk_write(filesys_disk, fat_fs->bs.fat_start + i, bounce);
            bytes_wrote += bytes_left;
            free(bounce);
        }
    }
}

void fat_create(void) {
    // Create FAT boot
    fat_boot_create();
    fat_fs_init();

    // Create FAT table
    fat_fs->fat = calloc(fat_fs->fat_length, sizeof(cluster_t));
    if (fat_fs->fat == NULL)
        PANIC("FAT creation failed");

    // Set up ROOT_DIR_CLST
    fat_put(ROOT_DIR_CLUSTER, EOChain);

    // Fill up ROOT_DIR_CLUSTER region with 0
    if (!dir_create(cluster_to_sector(ROOT_DIR_CLUSTER), 16))
        PANIC("FAT create failed due to OOM");
}

void fat_boot_create(void) {
    unsigned int fat_sectors =
        (disk_size(filesys_disk) - 1) / (DISK_SECTOR_SIZE / sizeof(cluster_t) * SECTORS_PER_CLUSTER + 1) + 1;
    fat_fs->bs = (struct fat_boot){
        .magic = FAT_MAGIC,
        .sectors_per_cluster = SECTORS_PER_CLUSTER,
        .total_sectors = disk_size(filesys_disk),
        .fat_start = 1,
        .fat_sectors = fat_sectors,
        .root_dir_cluster = ROOT_DIR_CLUSTER,
    };
}

void fat_fs_init(void) {
    /* TODO: Your code goes here. */
    fat_fs->fat_length = disk_size(filesys_disk) - fat_fs->bs.fat_sectors - 1;
    fat_fs->data_start = (disk_sector_t)(fat_fs->bs.fat_start + fat_fs->bs.fat_sectors);
    fat_fs->last_clst = (cluster_t)(fat_fs->bs.root_dir_cluster + 1);
    lock_init(&fat_fs->write_lock);
}

/*----------------------------------------------------------------------------*/
/* FAT handling                                                               */
/*----------------------------------------------------------------------------*/

// helper function
static cluster_t find_empty() {
    cluster_t fat_length = (cluster_t)fat_fs->fat_length;
    for (cluster_t tmp = fat_fs->bs.root_dir_cluster + 1; tmp < fat_length; ++tmp) {
        if (fat_get(tmp) == 0) {
            return tmp;
        }
    }
    return 0;
}

/* Allocates CNT consecutive sectors from the free map and stores
 * the first into *SECTORP.
 * Returns true if successful, false if all sectors were
 * available. (replacing free_map_allocate())*/
bool fat_allocate(size_t cnt, disk_sector_t *sectorp) {    
    if(cnt == 0)
        return true;
    
    cluster_t first = fat_create_chain(0);
    if (first == 0)
        return false;

    cluster_t clst = first;
    for (size_t i = 0; i < cnt - 1; i++) {
        clst = fat_create_chain(clst);
        if (clst == 0) {
            fat_remove_chain(first, 0);
            return false;
        }
    }
    *sectorp = cluster_to_sector(first);

    return true;
}

/* Add a cluster to the chain.
 * If CLST is 0, start a new chain.
 * Returns 0 if fails to allocate a new cluster. */
// Add new cluster to the tail of chain
cluster_t
fat_create_chain(cluster_t clst) {
    /* TODO: Your code goes here. */
    // find empty slot
    cluster_t empty_clst;
    if (fat_fs->last_clst >= fat_fs->fat_length) {
        empty_clst = find_empty();
        if (empty_clst == 0) {
            return 0;
        }
    } else {
        empty_clst = fat_fs->last_clst++;
    }

    // update fat
    if (clst == 0) {
        fat_put(empty_clst, EOChain);
    } else {
        cluster_t tmp;
        for (tmp = clst; fat_get(tmp) != EOChain; tmp = fat_get(tmp))
            ;
        fat_put(tmp, empty_clst);
        fat_put(empty_clst, EOChain);
    }

    return empty_clst;
}

/* Remove the chain of clusters starting from CLST.
 * If PCLST is 0, assume CLST as the start of the chain. */
void fat_remove_chain(cluster_t clst, cluster_t pclst) {
    /* TODO: Your code goes here. */
    cluster_t tmp = clst;
    while (fat_get(tmp) != EOChain && fat_get(tmp) != 0) {
        cluster_t next = fat_get(tmp);
        fat_put(tmp, 0);
        tmp = next;
    }

    if (pclst != 0) {
        fat_put(pclst, EOChain);
    }
}

/* Update a value in the FAT table. */
void fat_put(cluster_t clst, cluster_t val) {
    /* TODO: Your code goes here. */
    fat_fs->fat[clst] = val;
}

/* Fetch a value in the FAT table. */
cluster_t
fat_get(cluster_t clst) {
    /* TODO: Your code goes here. */
    return (cluster_t)fat_fs->fat[clst];
}

/* Covert a cluster # to a sector number. */
disk_sector_t
cluster_to_sector(cluster_t clst) {
    /* TODO: Your code goes here. */
    return (disk_sector_t)(fat_fs->data_start + clst - 1);
}

/* Covert a cluster # to a sector number. */
cluster_t
sector_to_cluster(disk_sector_t sect) {
    /* TODO: Your code goes here. */
    return (cluster_t)(sect - fat_fs->data_start + 1);
}
