/* anon.c: Implementation of page for non-disk image (a.k.a. anonymous page). */

#include <bitmap.h>

#include "devices/disk.h"
#include "threads/mmu.h"
#include "vm/vm.h"

/* DO NOT MODIFY BELOW LINE */
static struct disk *swap_disk;
static struct bitmap *disk_bitmap;
static struct lock bitmap_lock;
static bool anon_swap_in(struct page *page, void *kva);
static bool anon_swap_out(struct page *page);
static void anon_destroy(struct page *page);

extern struct list lru;

/* DO NOT MODIFY this struct */
static const struct page_operations anon_ops = {
    .swap_in = anon_swap_in,
    .swap_out = anon_swap_out,
    .destroy = anon_destroy,
    .type = VM_ANON,
};

/* Initialize the data for anonymous pages */
void vm_anon_init(void) {
    /* TODO: Set up the swap_disk. */
    swap_disk = disk_get(1, 1);
    disk_bitmap = bitmap_create((size_t)disk_size(swap_disk));
    lock_init(&bitmap_lock);
}

/* Initialize the file mapping */
bool anon_initializer(struct page *page, enum vm_type type, void *kva) {
    /* Set up the handler */
    page->operations = &anon_ops;

    struct anon_page *anon_page = &page->anon;
    anon_page->sec_no = SIZE_MAX;
    anon_page->thread = thread_current();

	return true;
}

/* Swap in the page by read contents from the swap disk. */
static bool
anon_swap_in(struct page *page, void *kva) {
    struct anon_page *anon_page = &page->anon;

    if (anon_page->sec_no == SIZE_MAX)
        return false;

    lock_acquire(&bitmap_lock);
    bool check = bitmap_contains(disk_bitmap, anon_page->sec_no, 8, false);
    lock_release(&bitmap_lock);
    if (check) {
        return false;
    }

    for (int i = 0; i < 8; i++) {
        disk_read(swap_disk, anon_page->sec_no + i, kva + i * DISK_SECTOR_SIZE);
    }

    lock_acquire(&bitmap_lock);
    bitmap_set_multiple(disk_bitmap, anon_page->sec_no, 8, false);
    lock_release(&bitmap_lock);

    return true;
}

/* Swap out the page by writing contents to the swap disk. */
static bool
anon_swap_out(struct page *page) {
    struct anon_page *anon_page = &page->anon;

    lock_acquire(&bitmap_lock);
    disk_sector_t sec_no = (disk_sector_t)bitmap_scan_and_flip(disk_bitmap, 0, 8, false);
    lock_release(&bitmap_lock);
    if (sec_no == BITMAP_ERROR)
        return false;

    anon_page->sec_no = sec_no;

    for (int i = 0; i < 8; i++) {
        disk_write(swap_disk, sec_no + i, page->frame->kva + i * DISK_SECTOR_SIZE);
    }

    pml4_clear_page(anon_page->thread->pml4, page->va);
    pml4_set_dirty(anon_page->thread->pml4, page->va, false);
    page->frame = NULL;

    return true;
}

/* Destroy the anonymous page. PAGE will be freed by the caller. */
static void
anon_destroy(struct page *page) {
    struct anon_page *anon_page = &page->anon;

    if (page->frame != NULL) {
        list_remove(&(page->frame->lru_elem));
		free(page->frame);
    }
	if(anon_page->sec_no != SIZE_MAX)
		bitmap_set_multiple(disk_bitmap, anon_page->sec_no, 8, false);
	
}
