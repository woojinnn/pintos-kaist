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
// static pid_t fork (const char *thread_name);
static tid_t sys_exec(const char *cmd_line);
// static int sys_wait (pid_t pid);
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

void syscall_init(void) {
    write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48 |
                            ((uint64_t)SEL_KCSEG) << 32);
    write_msr(MSR_LSTAR, (uint64_t)syscall_entry);

    /* The interrupt service rountine should not serve any interrupts
	 * until the syscall_entry swaps the userland stack to the kernel
	 * mode stack. Therefore, we masked the FLAG_FL. */
    write_msr(MSR_SYSCALL_MASK,
              FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);
}

void validate_usr_addr(void *addr) {
    if ((uintptr_t)addr >= (uintptr_t)KERN_BASE) {
        printf("validate_usr_addr error\n");
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

        case SYS_CREATE:
            sys_create((char *)args[0], (unsigned)args[1]);
            break;

        case SYS_REMOVE:
            sys_remove((char *)args[0]);
            break;

        case SYS_EXEC:
            sys_exec((char *)args[0]);
            break;

        case SYS_WRITE:
            sys_write((int)args[0], (void *)args[1], (unsigned)args[2]);
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
    thread_current()->exit_status = status;
    thread_exit();
}

// pid_t sys_fork (const char *thread_name){}
tid_t sys_exec(const char *cmd_line) {
    // create child process
    process_create_initd(cmd_line);

    struct thread *child = list_entry(list_back(&(thread_current()->childs)), struct thread, child_elem);

    // wait for child process to load
    sema_down(&(child->load_sema));

    // child process' load fail
    if (!child->process_load)
        return -1;

    return child->tid;
}

// int sys_wait (pid_t pid){}
bool sys_create(const char *file, unsigned initial_size) {
    return filesys_create(file, initial_size);
}

bool sys_remove(const char *file) {
    return filesys_remove(file);
}

int sys_open(const char *file) {}
int sys_filesize(int fd) {}
int sys_read(int fd, void *buffer, unsigned size) {}

int sys_write(int fd, const void *buffer, unsigned size) {
    if (fd == 1) {
        putbuf(buffer, size);
        return size;
    }
}

void sys_seek(int fd, unsigned position) {}
unsigned sys_tell(int fd) {}
void sys_close(int fd) {}