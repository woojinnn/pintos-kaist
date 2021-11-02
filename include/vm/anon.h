#ifndef VM_ANON_H
#define VM_ANON_H
#include "vm/vm.h"
#include "devices/disk.h"

struct page;
enum vm_type;

struct anon_page {
    disk_sector_t sec_no;
    struct thread *thread;
};

void vm_anon_init (void);
bool anon_initializer (struct page *page, enum vm_type type, void *kva);

#endif
