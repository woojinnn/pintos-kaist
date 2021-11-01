#ifndef VM_FILE_H
#define VM_FILE_H
#include "filesys/file.h"
#include "vm/vm.h"

struct page;
enum vm_type;

struct file_page {
    struct page *page;

    struct file *file;
    void *start;
    size_t length;
    off_t ofs;

    size_t page_read_bytes;
    size_t page_zero_bytes;

    struct list_elem file_elem;
};

struct mmap_aux {
    struct file *file;
    void *start;
    size_t length;
    off_t ofs;
    size_t page_read_bytes;
    size_t page_zero_bytes;
};

void vm_file_init(void);
bool file_backed_initializer(struct page *page, enum vm_type type, void *kva);
void *do_mmap(void *addr, size_t length, int writable,
              struct file *file, off_t offset);
void do_munmap(void *va);
#endif
