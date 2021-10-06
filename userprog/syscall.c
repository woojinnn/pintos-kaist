#include "userprog/syscall.h"

#include <stdio.h>
#include <syscall-nr.h>

#include "intrinsic.h"
#include "threads/flags.h"
#include "threads/interrupt.h"
#include "threads/loader.h"
#include "threads/thread.h"
#include "userprog/gdt.h"

/* helper function for syscall_handler */
static void validate_usr_addr(void *addr);
static void get_argument(uintptr_t *rsp, uintptr_t *arg, int count);

/* System calls */
static void sys_halt(void);
static void sys_exit(int status);
static tid_t fork(const char *thread_name, struct intr_frame *f);
static tid_t sys_exec(const char *cmd_line);
static int sys_wait(tid_t pid);
static bool sys_create(const char *file, unsigned initial_size);
static bool sys_remove(const char *file);
static int sys_open(const char *file);
static int sys_filesize(int fd);
static int sys_read(int fd, void *buffer, unsigned size);
static int sys_write(int fd, const void *buffer, unsigned size);
static void sys_seek(int fd, unsigned position);
static unsigned sys_tell(int fd);
static void sys_close(int fd);

void syscall_entry(void);
void syscall_handler(struct intr_frame *);

#define SET_RAX(f, val) (f->R.rax = (uint64_t)val)

/* System call.
 *
 * Previously system call services was handled by the interrupt handler
 * (e.g. int 0x80 in linux). However, in x86-64, the manufacturer supplies
 * efficient path for requesting the system call, the `syscall` instruction.
 *
 * The syscall instruction works by reading the values from the the Model
 * Specific Register (MSR). For the details, see the manual. */

#define MSR_STAR 0xc0000081         /* Segment selector msr */
#define MSR_LSTAR 0xc0000082        /* Long mode SYSCALL target */
#define MSR_SYSCALL_MASK 0xc0000084 /* Mask for the eflags */

struct lock filesys_lock;

void syscall_init(void) {
    write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48 |
                            ((uint64_t)SEL_KCSEG) << 32);
    write_msr(MSR_LSTAR, (uint64_t)syscall_entry);

    /* The interrupt service rountine should not serve any interrupts
	 * until the syscall_entry swaps the userland stack to the kernel
	 * mode stack. Therefore, we masked the FLAG_FL. */
    write_msr(MSR_SYSCALL_MASK,
              FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);

    lock_init(&filesys_lock);
}

void validate_usr_addr(void *addr) {
    if (is_kernel_vaddr(addr)) {
        sys_exit(-1);
        NOT_REACHED();
    }
}

void get_argument(uintptr_t *rsp, uintptr_t *arg, int count) {
    printf("%x\n", *rsp);
    for (int tmp = 0; tmp < count; ++tmp) {
        validate_usr_addr(*rsp);
        arg[tmp] = *(uintptr_t *)*rsp;
        *rsp += sizeof(uintptr_t);
    }
}

void check_bad_ptr(void *addr) {
    if (addr == NULL)
        sys_exit(-1);

    validate_usr_addr(addr);
    if (pml4_get_page(thread_current()->pml4, addr) == NULL)
        sys_exit(-1);
}

/* The main system call interface */
void syscall_handler(struct intr_frame *f) {
    // TODO: Your implementation goes here.
    uint64_t args[3] = {f->R.rdi, f->R.rsi, f->R.rdx};

    switch ((int)(f->R.rax)) {
        case SYS_HALT:
            sys_halt();
            break;

        case SYS_EXIT:
            sys_exit((int)args[0]);
            break;

        case SYS_FORK:
            SET_RAX(f, sys_fork((char *)args[0], f));
            break;

        case SYS_EXEC:
            SET_RAX(f, sys_exec((char *)args[0]));
            break;

        case SYS_WAIT:
            SET_RAX(f, sys_wait((tid_t)args[0]));
            break;

        case SYS_CREATE:
            SET_RAX(f, sys_create((char *)args[0], (unsigned)args[1]));
            break;

        case SYS_REMOVE:
            SET_RAX(f, sys_remove((char *)args[0]));
            break;

        case SYS_OPEN:
            SET_RAX(f, sys_open((char *)args[0]));
            break;

        case SYS_FILESIZE:
            SET_RAX(f, sys_filesize((int)args[0]));
            break;

        case SYS_READ:
            SET_RAX(f, sys_read((int)args[0], (void *)args[1], (unsigned)args[2]));
            break;

        case SYS_WRITE:
            SET_RAX(f, sys_write((int)args[0], (void *)args[1], (unsigned)args[2]));
            break;

        case SYS_SEEK:
            sys_seek((int)args[0], (unsigned)args[1]);
            break;

        case SYS_TELL:
            SET_RAX(f, sys_tell((int)args[0]));
            break;

        case SYS_CLOSE:
            sys_close((int)args[0]);
            break;

        default:
            thread_exit();
    }
}

/* System calls */
void sys_halt(void) {
    power_off();
    NOT_REACHED();
}

void sys_exit(int status) {
    struct thread *curr = thread_current();
    thread_current()->exit_status = status;
    thread_exit();
}

tid_t sys_fork(const char *thread_name, struct intr_frame *f) {
    check_bad_ptr(thread_name);

    return process_fork(thread_name, f);
}

int sys_exec(const char *cmd_line) {
    check_bad_ptr(cmd_line);

    void *cmd_copy;
    cmd_copy = palloc_get_page(0);
    if (cmd_copy == NULL)
        return -1;
    cmd_copy += 0x8000000000;
    strlcpy(cmd_copy, cmd_line, PGSIZE);

    // create child process
    process_exec(cmd_copy);
    // sys_exit(-1);
    return -1;
}

int sys_wait(tid_t pid) {
    int status = process_wait(pid);
    return status;
}

bool sys_create(const char *file, unsigned initial_size) {
    check_bad_ptr(file);

    return filesys_create(file, initial_size);
}

bool sys_remove(const char *file) {
    // check validity
    check_bad_ptr(file);

    return filesys_remove(file);
}

int sys_open(const char *file) {
    check_bad_ptr(file);

    if (*file == '\0')
        return -1;

    void *f = filesys_open(file);

    if (f == NULL)
        return -1;
    f += 0x8000000000;

    return process_add_file(f);
}

int sys_filesize(int fd) {
    void *f = process_get_file(fd);

    if (f == NULL)
        return -1;
    f += 0x8000000000;

    return (int)file_length(f);
}

int sys_read(int fd, void *buffer, unsigned size) {
    check_bad_ptr(buffer);
    lock_acquire(&filesys_lock);

    int read;

    if (fd == 0) {
        read = input_getc();
        lock_release(&filesys_lock);
        return read;
    }

    if (fd == 1) {
        lock_release(&filesys_lock);
        sys_exit(-1);
    }

    void *f = process_get_file(fd);

    if (f == NULL) {
        lock_release(&filesys_lock);
        sys_exit(-1);
    } else {
        f += 0x8000000000;
        read = (int)file_read(f, buffer, (off_t)size);
    }
    lock_release(&filesys_lock);
    return read;
}

int sys_write(int fd, const void *buffer, unsigned size) {
    check_bad_ptr(buffer);
    lock_acquire(&filesys_lock);

    if (fd == 1) {
        putbuf(buffer, size);
        lock_release(&filesys_lock);
        return size;
    }

    if (fd == 0) {
        lock_release(&filesys_lock);
        sys_exit(-1);
    }

    void *f = process_get_file(fd);

    if (f == NULL) {
        lock_release(&filesys_lock);
        sys_exit(-1);
    }

    f += 0x8000000000;

    void *inode = file_get_inode(f);  // for debugging

    int written = (int)file_write(f, buffer, (off_t)size);
    lock_release(&filesys_lock);
    return written;
}

void sys_seek(int fd, unsigned position) {
    void *f = process_get_file(fd);

    if (f == NULL)
        return;

    f += 0x8000000000;
    file_seek(f, (off_t)position);
}

unsigned sys_tell(int fd) {
    void *f = process_get_file(fd);

    if (f == NULL)
        return -1;

    f += 0x8000000000;
    return (unsigned)file_tell(f);
}

void sys_close(int fd) {
    if (process_close_file(fd) == false)
        sys_exit(-1);
}