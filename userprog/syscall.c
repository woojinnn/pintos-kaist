#include "userprog/syscall.h"

#include <stdio.h>
#include <syscall-nr.h>

#include "filesys/directory.h"
#include "filesys/inode.h"
#include "intrinsic.h"
#include "threads/flags.h"
#include "threads/interrupt.h"
#include "threads/loader.h"
#include "threads/thread.h"
#include "userprog/gdt.h"

/* helper function for syscall_handler */
static struct page *validate_usr_addr(void *addr);
static void get_argument(uintptr_t *rsp, uintptr_t *arg, int count);
static char **parse_directory(const char *name);
static struct dir *find_target_dir(const char **path);

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
static int sys_dup2(int oldfd, int newfd);
static void *sys_mmap(void *addr, size_t length, int writable, int fd, off_t offset);
static void sys_munmap(void *addr);
static bool sys_chdir(const char *dir);
static bool sys_mkdir(const char *dir);
static bool sys_readdir(int fd, char *name);
static bool sys_isdir(int fd);
static int sys_inumber(int fd);
static int sys_symlink(const char *target, const char *linkpath);

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

extern struct lock filesys_lock;
extern uint64_t stdin_file;
extern uint64_t stdout_file;

struct sym_map {
    char *target;
    char *linkpath;
    struct list_elem sym_elem;
};

extern struct list sym_list;

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

struct page *validate_usr_addr(void *addr) {
    if (is_kernel_vaddr(addr)) {
        sys_exit(-1);
        NOT_REACHED();
    }
    return spt_find_page(&thread_current()->spt, addr);
}

void validate_buffer(void *buffer, size_t size, bool to_write) {
    if (buffer == NULL)
        sys_exit(-1);

    void *start_addr = pg_round_down(buffer);
    void *end_addr = pg_round_down(buffer + size);

    ASSERT(start_addr <= end_addr);
    for (void *addr = end_addr; addr >= start_addr; addr -= PGSIZE) {
        struct page *pg = validate_usr_addr(addr);
        if (pg == NULL) {
            sys_exit(-1);
        }

        if (pg->writable == false && to_write == true) {
            sys_exit(-1);
        }
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

    if (validate_usr_addr(addr) == NULL)
        sys_exit(-1);

    if (pml4_get_page(thread_current()->pml4, addr) == NULL)
        sys_exit(-1);
}

// to free: free(directories[0]) and then free(directories). directories[0] is not used except when freeing.
static char **parse_directory(const char *name) {
    char *name_copied = (char *)malloc((strlen(name) + 1) * sizeof(char));
    char **directories = (char **)calloc(128, sizeof(char *));
    strlcpy(name_copied, name, strlen(name) + 1);
    directories[0] = name_copied;

    int argc = 1;
    char *tmp;
    char *token = strtok_r(name_copied, "/", &tmp);
    while (token != NULL) {
        directories[argc] = token + 0x8000000000;
        argc++;
        token = strtok_r(NULL, "/", &tmp);
    }

    return directories;
}

/* The main system call interface */
void syscall_handler(struct intr_frame *f) {
    // TODO: Your implementation goes here.
    uint64_t args[5] = {f->R.rdi, f->R.rsi, f->R.rdx, f->R.r10, f->R.r8};
    thread_current()->user_rsp = f->rsp;

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

        case SYS_DUP2:
            SET_RAX(f, sys_dup2((int)args[0], (int)args[1]));
            break;

        case SYS_MMAP:
            SET_RAX(f, sys_mmap((void *)args[0], (size_t)args[1], (int)args[2], (int)args[3], (off_t)args[4]));
            break;

        case SYS_MUNMAP:
            sys_munmap((void *)args[0]);
            break;

            /* Change the current directory. */
        case SYS_CHDIR:
            SET_RAX(f, sys_chdir((const char *)args[0]));
            break;

        /* Create a directory. */
        case SYS_MKDIR:
            SET_RAX(f, sys_mkdir((const char *)args[0]));
            break;

            /* Reads a directory entry. */
        case SYS_READDIR:
            SET_RAX(f, sys_readdir((int)args[0], (char *)args[1]));
            break;

            /* Tests if a fd represents a directory. */
        case SYS_ISDIR:
            SET_RAX(f, sys_isdir((int)args[0]));
            break;

            /* Returns the inode number for a fd. */
        case SYS_INUMBER:
            SET_RAX(f, sys_inumber((int)args[0]));
            break;

            /* Returns the inode number for a fd. */
        case SYS_SYMLINK:
            SET_RAX(f, sys_symlink((const char *)args[0], (const char *)args[1]));
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

    lock_acquire(&filesys_lock);
    tid_t fork_result = process_fork(thread_name, f);
    lock_release(&filesys_lock);

    return fork_result;
}

int sys_exec(const char *cmd_line) {
    check_bad_ptr(cmd_line);

    void *cmd_copy;
    cmd_copy = palloc_get_page(0);
    if (cmd_copy == NULL)
        return -1;

    strlcpy(cmd_copy, cmd_line, PGSIZE);

    // create child process
    process_exec(cmd_copy);
    sys_exit(-1);
}

int sys_wait(tid_t pid) {
    int status = process_wait(pid);
    return status;
}

static struct dir *find_target_dir(const char **path) {
    struct dir *curr_dir;
    struct inode *target_inode;
    if (path[0][0] == '/' || thread_current()->current_dir == NULL) {
        curr_dir = dir_open_root();
    } else {
        curr_dir = dir_reopen(thread_current()->current_dir);
    }

    int j;
    for (j = 0; path[j] != NULL; j++)
        ;

    for (int i = 1; i < j - 1; i++) {
        if (dir_lookup(curr_dir, path[i], &target_inode)) {
            if (!inode_is_dir(target_inode)) {
                return NULL;
            }
            dir_close(curr_dir);
            curr_dir = dir_open(target_inode);
        } else
            return NULL;
    }

    return dir_reopen(curr_dir);
}

bool sys_create(const char *file, unsigned initial_size) {
    check_bad_ptr(file);

    if (*file == '\0')
        return false;

    if (file[strlen(file) - 1] == '/')
        return false;

    char **path = parse_directory(file);
    struct dir *current_dir = thread_current()->current_dir;
    struct dir *target_dir = find_target_dir(path);
    struct inode *target_inode;
    if (target_dir == NULL)
        return false;
    thread_current()->current_dir = target_dir;

    int i;
    for (i = 1; path[i] != NULL; i++)
        ;
    char *file_name = path[i - 1];

    if (dir_lookup(target_dir, file_name, &target_inode)) {
        thread_current()->current_dir = current_dir;
        dir_close(target_dir);
        return false;
    }

    lock_acquire(&filesys_lock);
    bool create_result = filesys_create(file_name, initial_size);
    lock_release(&filesys_lock);

    thread_current()->current_dir = current_dir;
    dir_close(target_dir);

    struct list_elem *tmp;
    struct list_elem *next_tmp;
    char *prev_link = file;
    for (tmp = list_begin(&sym_list); tmp != list_end(&sym_list); tmp = next_tmp) {
        struct sym_map *tmp_sym = list_entry(tmp, struct sym_map, sym_elem);
        next_tmp = list_next(tmp);
        if (strcmp(prev_link, tmp_sym->target) == 0) {
            list_remove(tmp);
            sys_symlink(tmp_sym->target, tmp_sym->linkpath);
            prev_link = tmp_sym->linkpath;
            free(tmp_sym->target);
            free(tmp_sym);
        }
    }

    return create_result;
}

bool sys_remove(const char *file) {
    // check validity
    check_bad_ptr(file);

    if (!strcmp(file, "/")) {
        return false;
    }

    char **path = parse_directory(file);
    struct dir *current_dir = thread_current()->current_dir;
    struct dir *target_dir = find_target_dir(path);
    struct inode *target_inode;
    if (target_dir == NULL)
        return false;
    thread_current()->current_dir = target_dir;

    int i;
    for (i = 0; path[i] != NULL; i++)
        ;

    char *file_name = path[i - 1];

    if (!dir_lookup(target_dir, file_name, &target_inode)) {
        thread_current()->current_dir = current_dir;
        dir_close(target_dir);
        return false;
    }

    if (current_dir != NULL && dir_get_inode(current_dir) == target_inode) {
        thread_current()->current_dir = current_dir;
        return false;
    }

    if (current_dir != NULL && dir_get_inode(get_parent_dir(current_dir)) == target_inode) {
        thread_current()->current_dir = current_dir;
        return false;
    }

    lock_acquire(&filesys_lock);
    bool remove_result = filesys_remove(file_name);
    lock_release(&filesys_lock);

    thread_current()->current_dir = current_dir;
    dir_close(target_dir);
    return remove_result;
}

int sys_open(const char *file) {
    check_bad_ptr(file);

    if (*file == '\0')
        return -1;

    struct file_unioned *file_unioned = (struct file_unioned *)malloc(sizeof(struct file_unioned));
    if (!strcmp(file, "/")) {
        file_unioned->dir = dir_open_root();
        file_unioned->file = NULL;
        return process_add_file(file_unioned);
    }

    char **path = parse_directory(file);
    struct dir *current_dir = thread_current()->current_dir;
    struct dir *target_dir = find_target_dir(path);
    struct inode *target_inode;
    if (target_dir == NULL)
        return -1;
    thread_current()->current_dir = target_dir;

    int i;
    for (i = 0; path[i] != NULL; i++)
        ;
    char *file_name = path[i - 1];

    void *f;
    if (dir_lookup(target_dir, file_name, &target_inode)) {
        if (inode_is_dir(target_inode)) {
            lock_acquire(&filesys_lock);
            f = dir_open(target_inode);
            if (get_parent_dir(f) == NULL)
                set_parent_dir(f, dir_open_root());
            lock_release(&filesys_lock);
            if (f == NULL) {
                goto open_error;
            }
            file_unioned->dir = (struct dir *)f;
            file_unioned->file = NULL;
        } else if (!inode_is_dir(target_inode) && file[strlen(file) - 1] == '/') {
            goto open_error;
        } else {
            lock_acquire(&filesys_lock);
            f = filesys_open(file_name);
            lock_release(&filesys_lock);

            if (f == NULL) {
                goto open_error;
            }

            f += 0x8000000000;
            file_unioned->file = (struct file *)f;
            file_unioned->dir = NULL;
        }
    } else {
        goto open_error;
    }

    thread_current()->current_dir = current_dir;
    dir_close(target_dir);

    return process_add_file(file_unioned);

open_error:
    thread_current()->current_dir = current_dir;
    dir_close(target_dir);
    return -1;
}

int sys_filesize(int fd) {
    void *f = process_get_file(fd);

    if (f == NULL)
        return -1;
    f += 0x8000000000;

    struct file_unioned *file = (struct file_unioned *)f;

    if (file->file == NULL)
        return -1;

    lock_acquire(&filesys_lock);
    int length_result = (int)file_length(file->file);
    lock_release(&filesys_lock);
    return length_result;
}

int sys_read(int fd, void *buffer, unsigned size) {
    struct thread *curr = thread_current();
    validate_buffer(buffer, size, true);
    lock_acquire(&filesys_lock);
    
    int read;

    void *f = process_get_file(fd);
    if (f == NULL) {
        lock_release(&filesys_lock);
        sys_exit(-1);
    }

    f += 0x8000000000;
    struct file_unioned *file = (struct file_unioned *)f;

    if (f == (void *)&stdin_file) {
        read = input_getc();
        lock_release(&filesys_lock);
        return read;
    }

    if (f == (void *)&stdout_file) {
        lock_release(&filesys_lock);
        sys_exit(-1);
    }

    if (file->file == NULL) {
        lock_release(&filesys_lock);
        sys_exit(-1);
    }

    read = (int)file_read(file->file, buffer, (off_t)size);

    lock_release(&filesys_lock);
    return read;
}

int sys_write(int fd, const void *buffer, unsigned size) {
    validate_buffer(buffer, size, false);
    lock_acquire(&filesys_lock);

    struct thread *curr = thread_current();

    void *f = process_get_file(fd);
    if (f == NULL) {
        lock_release(&filesys_lock);
        sys_exit(-1);
    }

    f += 0x8000000000;
    struct file_unioned *file = (struct file_unioned *)f;

    if (f == (void *)&stdout_file) {
        putbuf(buffer, size);
        lock_release(&filesys_lock);
        return size;
    }

    if (f == (void *)&stdin_file) {
        lock_release(&filesys_lock);
        sys_exit(-1);
    }

    if (file->file == NULL) {
        lock_release(&filesys_lock);
        return -1;
    }

    int written = (int)file_write(file->file, buffer, (off_t)size);
    lock_release(&filesys_lock);
    return written;
}

void sys_seek(int fd, unsigned position) {
    void *f = process_get_file(fd);

    if (f == NULL)
        return;
    f += 0x8000000000;
    struct file_unioned *file = (struct file_unioned *)f;

    if (file->file == NULL)
        return -1;

    lock_acquire(&filesys_lock);
    file_seek(file->file, (off_t)position);
    lock_release(&filesys_lock);
}

unsigned sys_tell(int fd) {
    void *f = process_get_file(fd);

    if (f == NULL)
        return -1;

    f += 0x8000000000;
    struct file_unioned *file = (struct file_unioned *)f;

    if (file->file == NULL)
        return -1;

    lock_acquire(&filesys_lock);
    unsigned tell_result = (unsigned)file_tell(file->file);
    lock_release(&filesys_lock);
    return tell_result;
}

void sys_close(int fd) {
    if (process_close_file(fd) == false)
        sys_exit(-1);
}

int sys_dup2(int oldfd, int newfd) {
    struct thread *current = thread_current();
    void *old_f = process_get_file(oldfd);

    if (old_f == NULL)
        return -1;

    if (newfd < 0)
        return -1;

    if (oldfd == newfd)
        return newfd;

    // extend fd table if required (newfd >= current->next_fd)
    if (newfd >= current->next_fd) {
        void *old_fd_table = current->fd_table;
        current->fd_table = (struct file **)realloc(current->fd_table, sizeof(struct file *) * (newfd + 1));
        if (current->fd_table == NULL) {
            current->fd_table = old_fd_table;
            sys_exit(-1);
        }

        for (int i = current->next_fd; i <= newfd; i++)
            current->fd_table[i] = NULL;

        current->next_fd = newfd + 1;
    }

    // close newfd contents
    if (process_get_file(newfd) != NULL)
        process_close_file(newfd);

    current->fd_table[newfd] = current->fd_table[oldfd];

    return newfd;
}

void *sys_mmap(void *addr, size_t length, int writable, int fd, off_t offset) {
    if (addr == NULL)
        return NULL;

    if (offset % PGSIZE != 0)
        return NULL;

    if (is_kernel_vaddr(addr))
        return NULL;

    if (is_kernel_vaddr((size_t)addr + length))
        return NULL;

    if ((long)length <= 0)
        return NULL;

    if (addr != pg_round_down(addr))
        return NULL;

    void *start_addr = pg_round_down(addr);
    void *end_addr = pg_round_down(addr + length);
    ASSERT(start_addr <= end_addr);
    for (void *addr = end_addr; addr >= start_addr; addr -= PGSIZE) {
        struct page *pg = validate_usr_addr(addr);
        if (pg != NULL) {
            return NULL;
        }
    }

    void *f = process_get_file(fd);
    if (f == NULL)
        return NULL;

    f += 0x8000000000;
    struct file_unioned *file = (struct file_unioned *)f;

    if ((f == &stdin_file) || (f == &stdout_file))
        return NULL;

    if (file->file == NULL)
        return -1;

    off_t file_len = file_length(file->file);
    if (file_len == 0)
        return NULL;

    if (file_len <= offset)
        return NULL;

    struct thread *curr_thraed = thread_current();
    file_len = file_len < length ? file_len : length;
    lock_acquire(&filesys_lock);
    void *success = do_mmap(addr, (size_t)file_len, writable, file->file, offset);
    lock_release(&filesys_lock);

    return success;
}

void sys_munmap(void *addr) {
    if (addr == NULL)
        return;

    if (is_kernel_vaddr(addr))
        return;

    struct thread *curr_thread = thread_current();
    struct page *page = spt_find_page(&(curr_thread->spt), addr);
    if (page == NULL)
        return;

    if (page->operations->type != VM_FILE)
        return;

    if (addr != page->file.start)
        return;

    do_munmap(addr);
    return;
}

bool sys_chdir(const char *dir) {
    check_bad_ptr(dir);

    if (*dir == '\0')
        return false;

    if (!strcmp(dir, "/")) {
        thread_current()->current_dir = dir_open_root();
        return true;
    }

    if (!strcmp(dir, ".")) {
        return true;
    }

    if (!strcmp(dir, "..")) {
        thread_current()->current_dir = get_parent_dir(thread_current()->current_dir);
        return true;
    }

    char **path = parse_directory(dir);
    struct dir *target_dir = find_target_dir(path);
    struct inode *target_inode;
    if (target_dir == NULL)
        return false;

    int i;
    for (i = 1; path[i] != NULL; i++)
        ;
    char *file_name = path[i - 1];

    if (!dir_lookup(target_dir, file_name, &target_inode)) {
        dir_close(target_dir);
        return false;
    }

    thread_current()->current_dir = dir_open(target_inode);
    if (get_parent_dir(thread_current()->current_dir) == NULL)
        set_parent_dir(thread_current()->current_dir, dir_open_root());
    return true;
}
bool sys_mkdir(const char *dir) {
    check_bad_ptr(dir);

    if (*dir == '\0')
        return false;

    char **path = parse_directory(dir);
    struct dir *current_dir = thread_current()->current_dir;
    struct dir *target_dir = find_target_dir(path);
    struct inode *target_inode;
    if (target_dir == NULL)
        return false;
    thread_current()->current_dir = target_dir;

    int i;
    for (i = 1; path[i] != NULL; i++)
        ;
    char *file_name = path[i - 1];

    if (dir_lookup(target_dir, file_name, &target_inode)) {
        thread_current()->current_dir = current_dir;
        dir_close(target_dir);
        return false;
    }

    disk_sector_t inode_sector = 0;
    fat_allocate(1, &inode_sector);

    lock_acquire(&filesys_lock);
    bool create_result = dir_create(inode_sector, 16);
    if (create_result)
        dir_add(target_dir, file_name, inode_sector);
    lock_release(&filesys_lock);

    thread_current()->current_dir = current_dir;
    dir_close(target_dir);

    return create_result;
}

bool sys_readdir(int fd, char *name) {
    check_bad_ptr(name);
    void *f = process_get_file(fd);

    if (f == NULL)
        return -1;

    f += 0x8000000000;
    struct file_unioned *file = (struct file_unioned *)f;

    if (file->dir == NULL)
        return false;

    return dir_readdir(file->dir, name);
}

bool sys_isdir(int fd) {
    void *f = process_get_file(fd);

    if (f == NULL)
        return -1;

    f += 0x8000000000;
    struct file_unioned *file = (struct file_unioned *)f;

    return file->dir != NULL;
}

int sys_inumber(int fd) {
    void *f = process_get_file(fd);

    if (f == NULL)
        return -1;

    f += 0x8000000000;
    struct file_unioned *file = (struct file_unioned *)f;

    if (file->file != NULL)
        return (int)inode_get_inumber(file_get_inode(file->file));

    else if (file->dir != NULL)
        return (int)inode_get_inumber(dir_get_inode(file->dir));

    return -1;
}

int sys_symlink(const char *target, const char *linkpath) {
    // check_bad_ptr(target);
    // check_bad_ptr(linkpath);

    if (*target == '\0')
        return -1;

    if (*linkpath == '\0')
        return -1;

    char **link_path = parse_directory(linkpath);
    struct dir *link_target_dir = find_target_dir(link_path);
    if (link_target_dir == NULL)
        return -1;

    int i;
    for (i = 1; link_path[i] != NULL; i++)
        ;
    char *link_name = link_path[i - 1];

    char **path = parse_directory(target);
    struct dir *target_dir = find_target_dir(path);
    struct inode *target_inode;
    if (target_dir == NULL)
        return -1;

    for (i = 1; path[i] != NULL; i++)
        ;
    char *file_name = path[i - 1];

    if (!dir_lookup(target_dir, file_name, &target_inode)) {
        struct sym_map *sym_map = (struct sym_map *)malloc(sizeof(struct sym_map));
        char *target_cp = malloc(sizeof(strlen(target)) + 1);
        char *link_cp = malloc(sizeof(strlen(linkpath)) + 1);
        strlcpy(target_cp, target, strlen(target) + 1);
        strlcpy(link_cp, linkpath, strlen(linkpath) + 1);
        sym_map->target = target_cp;
        sym_map->linkpath = link_cp;
        list_push_back(&sym_list, &sym_map->sym_elem);
        dir_close(target_dir);
        return 0;
    }

    dir_add(link_target_dir, link_name, inode_get_inumber(target_inode));
    return 0;
}
