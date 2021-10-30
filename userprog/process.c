#include "userprog/process.h"

#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "intrinsic.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/mmu.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/gdt.h"
#include "userprog/tss.h"
#ifdef VM
#include "vm/vm.h"
#endif

struct lock filesys_lock;
struct lock dead_lock;
struct lock process_lock;

uint64_t stdin_file;
uint64_t stdout_file;

static void process_cleanup(void);
static bool load(const char *file_name, struct intr_frame *if_);
static void initd(void *f_name);
static void __do_fork(void *);
static void argument_stack(char **argv, int argc, uintptr_t *rsp_addr);
static void set_arg_reg(struct intr_frame *_if, int argc, char *argv_0);

static struct thread *get_child_process(tid_t pid);
static void remove_child_process(struct thread *cp);

int process_add_file(struct file *f);
struct file *process_get_file(int fd);
bool process_close_file(int fd);

/* General process initializer for initd and other process. */
static void
process_init(void) {
    struct thread *current = thread_current();
    current->fd_table = (struct file **)realloc(current->fd_table, sizeof(struct file *) * 2);
    if (current->fd_table == NULL) {
        current->exit_status = -1;
        thread_exit();
    }
    current->fd_table[0] = (struct file *)&stdin_file;
    current->fd_table[1] = (struct file *)&stdout_file;
}

/* Starts the first userland program, called "initd", loaded from FILE_NAME.
 * The new thread may be scheduled (and may even exit)
 * before process_create_initd() returns. Returns the initd's
 * thread id, or TID_ERROR if the thread cannot be created.
 * Notice that THIS SHOULD BE CALLED ONCE. */
tid_t process_create_initd(const char *file_name) {
    char *fn_copy;
    tid_t tid;

    /* Make a copy of FILE_NAME.
	 * Otherwise there's a race between the caller and load(). */
    fn_copy = palloc_get_page(0);
    if (fn_copy == NULL)
        return TID_ERROR;
    strlcpy(fn_copy, file_name, PGSIZE);

    /* Create a new thread to execute FILE_NAME. */
    char *tmp;
    tid = thread_create(strtok_r(file_name, " ", &tmp), PRI_DEFAULT, initd, fn_copy);

    struct thread *child = get_child_process(tid);
    child->is_user_thread = true;
    sema_down(&(child->load_sema));

    if (tid == TID_ERROR)
        palloc_free_page(fn_copy);
    return tid;
}

/* A thread function that launches first user process. */
static void
initd(void *f_name) {
#ifdef VM
    supplemental_page_table_init(&thread_current()->spt);
#endif

    process_init();

    if (process_exec(f_name) < 0)
        PANIC("Fail to launch initd\n");
    NOT_REACHED();
}

/* Clones the current process as `name`. Returns the new process's thread id, or
 * TID_ERROR if the thread cannot be created. */
tid_t process_fork(const char *name, struct intr_frame *if_) {
    /* Clone current thread to new thread.*/
    struct intr_frame *copied_if = (struct intr_frame *)malloc(sizeof(struct intr_frame));
    if (copied_if == NULL)
        return TID_ERROR;
    memcpy(copied_if, if_, sizeof(struct intr_frame));

    tid_t child_tid = thread_create(name,
                                    PRI_DEFAULT, __do_fork, (void *)copied_if);
    if (child_tid == TID_ERROR) {
        free(copied_if);
        return child_tid;
    }

    struct thread *child = get_child_process(child_tid);
    sema_down(&(child->load_sema));

    if (thread_current()->child_do_fork_success == false) {
        return TID_ERROR;
    }
    return child_tid;
}

#ifndef VM
/* Duplicate the parent's address space by passing this function to the
 * pml4_for_each. This is only for the project 2. */
static bool
duplicate_pte(uint64_t *pte, void *va, void *aux) {
    struct thread *current = thread_current();
    struct thread *parent = (struct thread *)aux;
    void *parent_page;
    void *newpage;
    bool writable;

    /* 1. TODO: If the parent_page is kernel page, then return immediately. */
    if (is_kernel_vaddr(va))
        return true;

    /* 2. Resolve VA from the parent's page map level 4. */
    parent_page = pml4_get_page(parent->pml4, va);

    /* 3. TODO: Allocate new PAL_USER page for the child and set result to
	 *    TODO: NEWPAGE. */
    newpage = palloc_get_page(PAL_USER);
    if (newpage == NULL)
        return false;

    /* 4. TODO: Duplicate parent's page to the new page and
	 *    TODO: check whether parent's page is writable or not (set WRITABLE
	 *    TODO: according to the result). */
    memcpy(newpage, parent_page, PGSIZE);
    writable = is_writable(pte);

    /* 5. Add new page to child's page table at address VA with WRITABLE
	 *    permission. */
    if (!pml4_set_page(current->pml4, va, newpage, writable)) {
        /* 6. TODO: if fail to insert page, do error handling. */
        pml4_destroy(current->pml4);
        current->exit_status = -1;
        palloc_free_page(newpage);
        return false;
    }
    return true;
}
#endif

/* A thread function that copies parent's execution context.
 * Hint) parent->tf does not hold the userland context of the process.
 *       That is, you are required to pass second argument of process_fork to
 *       this function. */
static void
__do_fork(void *aux) {
    struct intr_frame if_;
    struct thread *current = thread_current();
    struct thread *parent = current->parent;
    /* TODO: somehow pass the parent_if. (i.e. process_fork()'s if_) */
    struct intr_frame *parent_if = (struct intr_frame *)aux;
    bool succ = true;

    current->is_user_thread = parent->is_user_thread;

    /* 1. Read the cpu context to local stack. */
    memcpy(&if_, parent_if, sizeof(struct intr_frame));
    free(aux);

    current->tf = if_;

    /* 2. Duplicate PT */
    current->pml4 = pml4_create();
    if (current->pml4 == NULL)
        goto error;

    process_activate(current);
#ifdef VM
    supplemental_page_table_init(&current->spt);
    if (!supplemental_page_table_copy(&current->spt, &parent->spt))
        goto error;
#else
    if (!pml4_for_each(parent->pml4, duplicate_pte, parent))
        goto error;
#endif

    /* TODO: Your code goes here.
	 * TODO: Hint) To duplicate the file object, use `file_duplicate`
	 * TODO:       in include/filesys/file.h. Note that parent should not return
	 * TODO:       from the fork() until this function successfully duplicates
	 * TODO:       the resources of parent.*/
    process_init();

    current->next_fd = parent->next_fd;
    current->fd_table = (struct file **)realloc(current->fd_table, sizeof(struct file *) * current->next_fd);
    if (current->fd_table == NULL) {
        goto error;
    }

    // Note that files is allocated with parent's "fd table" length.
    current->files = (struct file **)realloc(current->files, parent->next_fd * sizeof(struct file *));
    if (current->files == NULL) {
        goto error;
    }

    for (int i = 0; i < parent->next_fd; i++) {
        struct file *parent_file = parent->fd_table[i];
        if (parent_file == NULL) {
            current->fd_table[i] = NULL;
            continue;
        }

        if (parent_file == (struct file *)&stdin_file || parent_file == (struct file *)&stdout_file) {
            current->fd_table[i] = parent_file;
            continue;
        }

        struct file *file_duplicated = file_duplicate(parent->fd_table[i]);
        if (file_duplicated == NULL) {
            current->next_fd = i;
            goto error;
        }
        current->fd_table[i] = file_duplicated;
        current->files[current->next_file] = file_duplicated;
        current->next_file++;
    }

    parent->child_do_fork_success = true;
    sema_up(&(current->load_sema));

    current->tf.R.rax = 0;  // return 0 for child

    /* Finally, switch to the newly created process. */
    if (succ)
        do_iret(&(current->tf));
error:
    parent->child_do_fork_success = false;
    sema_up(&current->load_sema);
    current->exit_status = -1;
    thread_exit();
}

void argument_stack(char **argv, int argc, uintptr_t *rsp) {
    int tmp = argc - 1;
    int size;
    while (tmp >= 0) {
        size = strlen(argv[tmp]) + 1;  // add 1 for NULL
        *rsp -= size;
        strlcpy((char *)*rsp, argv[tmp], size);
        tmp--;
    }

    uintptr_t dst = ((*rsp >> 3) << 3);

    while (*rsp != dst) {
        (*rsp)--;
        *(uint8_t *)*rsp = (uint8_t)0;
    }

    *rsp -= sizeof(char *);
    *(char **)*rsp = NULL;

    tmp = argc - 1;
    uint64_t len_sum = 0;
    while (tmp >= 0) {
        *rsp -= sizeof(char *);
        len_sum += strlen(argv[tmp]) + 1;
        *(char **)*rsp = (char *)((uintptr_t)USER_STACK - (uintptr_t)len_sum);
        tmp--;
    }

    *rsp -= sizeof(void (*)());
    *(uintptr_t *)*rsp = (uintptr_t)0;
}

void set_arg_reg(struct intr_frame *_if, int argc, char *argv_0) {
    _if->R.rdi = (uint64_t)argc;
    _if->R.rsi = (uint64_t)(_if->rsp + sizeof(uintptr_t));
}

/* Switch the current execution context to the f_name.
 * Returns -1 on fail. */
int process_exec(void *f_name) {
    char *file_name = f_name;
    bool success;

    /* We cannot use the intr_frame in the thread structure.
	 * This is because when current thread rescheduled,
	 * it stores the execution information to the member. */
    struct intr_frame _if;
    _if.ds = _if.es = _if.ss = SEL_UDSEG;
    _if.cs = SEL_UCSEG;
    _if.eflags = FLAG_IF | FLAG_MBS;

    int argc = 0;
    char *argv[128] = {0};
    char *tmp;
    char *token = strtok_r(file_name, " ", &tmp);
    while (token != NULL) {
        argv[argc] = token;
        argc++;
        token = strtok_r(NULL, " ", &tmp);
    }
    argv[argc] = NULL;

    /* We first kill the current context */
    process_cleanup();

    /* And then load the binary */
    success = load((char *)argv[0], &_if);

    sema_up(&(thread_current()->load_sema));

    if (success) {
        thread_current()->process_load = true;
        argument_stack(argv, argc, (uintptr_t *)(&(_if.rsp)));
        set_arg_reg(&_if, argc, argv[0]);
    }

    /* If load failed, quit. */
    palloc_free_page(file_name);
    if (!success)
        return -1;

    /* Start switched process. */
    do_iret(&_if);
    NOT_REACHED();
}

/* Waits for thread TID to die and returns its exit status.  If
 * it was terminated by the kernel (i.e. killed due to an
 * exception), returns -1.  If TID is invalid or if it was not a
 * child of the calling process, or if process_wait() has already
 * been successfully called for the given TID, returns -1
 * immediately, without waiting.
 *
 * This function will be implemented in problem 2-2.  For now, it
 * does nothing. */
int process_wait(tid_t child_tid) {
    /* XXX: Hint) The pintos exit if process_wait (initd), we recommend you
	 * XXX:       to add infinite loop here before
	 * XXX:       implementing the process_wait. */
    struct thread *child = get_child_process(child_tid);
    if (child != NULL) {
        sema_down(&(child->exit_sema));
    }

    struct thread *curr = thread_current();

    struct list_elem *tmp;
    struct dead_child *tmp_info;
    int status;

    lock_acquire(&dead_lock);
    for (tmp = list_begin(&curr->dead_childs); tmp != list_end(&curr->dead_childs); tmp = list_next(tmp)) {
        tmp_info = list_entry(tmp, struct dead_child, dead_elem);
        if (tmp_info->tid == child_tid) {
            status = tmp_info->exit_status;
            tmp_info->exit_status = -1;
            lock_release(&dead_lock);
            return status;
        }
    }
    lock_release(&dead_lock);

    if (child == NULL) {
        // there is no such child_tid
        // same as sys_exit(-1)
        curr->exit_status = -1;
        thread_exit();
    }

    return child->exit_status;
}

/* Exit the process. This function is called by thread_exit (). */
void process_exit(void) {
    struct thread *curr = thread_current();
    /* TODO: Your code goes here.
	 * TODO: Implement process termination message (see
	 * TODO: project2/process_termination.html).
	 * TODO: We recommend you to implement process resource cleanup here. */
    curr->process_exit = true;
    struct thread *parent = curr->parent;

    lock_acquire(&dead_lock);
    while (!list_empty(&(curr->dead_childs))) {
        struct dead_child *tmp = list_entry(list_pop_front(&(curr->dead_childs)), struct dead_child, dead_elem);
        free(tmp);
    }
    lock_release(&dead_lock);

    if (curr->file_executing != NULL) {
        file_close(curr->file_executing);
    }

    if (curr->fd_table != NULL) {
        if (curr->files != NULL) {
            for (int i = 0; i < curr->next_file; ++i) {
                file_close(curr->files[i]);
            }
            free(curr->files);
        }
        free(curr->fd_table);
    }

    if (curr->is_user_thread == true)
        printf("%s: exit(%d)\n", curr->name, curr->exit_status);

    struct dead_child *dead = (struct dead_child *)malloc(sizeof(struct dead_child));
    if (dead != NULL) {
        dead->tid = curr->tid;
        dead->exit_status = curr->exit_status;
        lock_acquire(&dead_lock);
        list_push_front(&(parent->dead_childs), &(dead->dead_elem));
        lock_release(&dead_lock);
    }

    lock_acquire(&process_lock);
    list_remove(&(curr->child_elem));
    lock_release(&process_lock);

    process_cleanup();
    sema_up(&(curr->exit_sema));
}

/* Free the current process's resources. */
static void
process_cleanup(void) {
    struct thread *curr = thread_current();

#ifdef VM
    supplemental_page_table_kill(&curr->spt);

#endif

    uint64_t *pml4;
    /* Destroy the current process's page directory and switch back
	 * to the kernel-only page directory. */
    pml4 = curr->pml4;
    if (pml4 != NULL) {
        /* Correct ordering here is crucial.  We must set
		 * cur->pagedir to NULL before switching page directories,
		 * so that a timer interrupt can't switch back to the
		 * process page directory.  We must activate the base page
		 * directory before destroying the process's page
		 * directory, or our active page directory will be one
		 * that's been freed (and cleared). */
        curr->pml4 = NULL;
        pml4_activate(NULL);
        pml4_destroy(pml4);
    }
}

/* Sets up the CPU for running user code in the nest thread.
 * This function is called on every context switch. */
void process_activate(struct thread *next) {
    /* Activate thread's page tables. */
    pml4_activate(next->pml4);

    /* Set thread's kernel stack for use in processing interrupts. */
    tss_update(next);
}

int process_add_file(struct file *f) {
    struct thread *curr = thread_current();
    curr->next_file++;
    void *old_files = curr->files;
    curr->files = (struct file **)realloc(curr->files, curr->next_file * sizeof(struct file *));
    if (curr->files == NULL) {
        curr->files = old_files;
        curr->next_file--;
        return -1;
    }
    curr->files[curr->next_file - 1] = f;

    for (int i = 0; i < curr->next_fd; i++) {
        if (curr->fd_table[i] == NULL) {
            curr->fd_table[i] = f;
            return i;
        }
    }
    curr->next_fd++;
    void *old_fd_table = curr->fd_table;
    curr->fd_table = (struct file **)realloc(curr->fd_table, curr->next_fd * sizeof(struct file *));
    if (curr->fd_table == NULL) {
        curr->fd_table = old_fd_table;
        curr->next_fd--;
        return -1;
    }
    curr->fd_table[curr->next_fd - 1] = f;
    return curr->next_fd - 1;
}

struct file *process_get_file(int fd) {
    if (fd < 0)
        return NULL;

    struct thread *curr = thread_current();
    if (fd >= curr->next_fd || curr->fd_table[fd] == NULL)
        return NULL;

    return curr->fd_table[fd];
}

bool process_close_file(int fd) {
    struct thread *curr = thread_current();
    struct file *f = process_get_file(fd);

    if (f == NULL) {
        return false;
    }

    curr->fd_table[fd] = NULL;

    return true;
}

/* We load ELF binaries.  The following definitions are taken
 * from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
#define EI_NIDENT 16

#define PT_NULL 0           /* Ignore. */
#define PT_LOAD 1           /* Loadable segment. */
#define PT_DYNAMIC 2        /* Dynamic linking info. */
#define PT_INTERP 3         /* Name of dynamic loader. */
#define PT_NOTE 4           /* Auxiliary info. */
#define PT_SHLIB 5          /* Reserved. */
#define PT_PHDR 6           /* Program header table. */
#define PT_STACK 0x6474e551 /* Stack segment. */

#define PF_X 1 /* Executable. */
#define PF_W 2 /* Writable. */
#define PF_R 4 /* Readable. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
 * This appears at the very beginning of an ELF binary. */
struct ELF64_hdr {
    unsigned char e_ident[EI_NIDENT];
    uint16_t e_type;
    uint16_t e_machine;
    uint32_t e_version;
    uint64_t e_entry;
    uint64_t e_phoff;
    uint64_t e_shoff;
    uint32_t e_flags;
    uint16_t e_ehsize;
    uint16_t e_phentsize;
    uint16_t e_phnum;
    uint16_t e_shentsize;
    uint16_t e_shnum;
    uint16_t e_shstrndx;
};

struct ELF64_PHDR {
    uint32_t p_type;
    uint32_t p_flags;
    uint64_t p_offset;
    uint64_t p_vaddr;
    uint64_t p_paddr;
    uint64_t p_filesz;
    uint64_t p_memsz;
    uint64_t p_align;
};

/* Abbreviations */
#define ELF ELF64_hdr
#define Phdr ELF64_PHDR

static bool setup_stack(struct intr_frame *if_);
static bool validate_segment(const struct Phdr *, struct file *);
static bool load_segment(struct file *file, off_t ofs, uint8_t *upage,
                         uint32_t read_bytes, uint32_t zero_bytes,
                         bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
 * Stores the executable's entry point into *RIP
 * and its initial stack pointer into *RSP.
 * Returns true if successful, false otherwise. */
static bool
load(const char *file_name, struct intr_frame *if_) {
    struct thread *t = thread_current();
    struct ELF ehdr;
    struct file *file = NULL;
    off_t file_ofs;
    bool success = false;
    int i;

    /* Allocate and activate page directory. */
    t->pml4 = pml4_create();
    if (t->pml4 == NULL)
        goto done;
    process_activate(thread_current());

    /* Open executable file. */
    lock_acquire(&filesys_lock);
    file = filesys_open(file_name);
    lock_release(&filesys_lock);
    if (file == NULL) {
        printf("load: %s: open failed\n", file_name);
        goto done;
    }

    /* Read and verify executable header. */
    if (file_read(file, &ehdr, sizeof ehdr) != sizeof ehdr || memcmp(ehdr.e_ident, "\177ELF\2\1\1", 7) || ehdr.e_type != 2 || ehdr.e_machine != 0x3E  // amd64
        || ehdr.e_version != 1 || ehdr.e_phentsize != sizeof(struct Phdr) || ehdr.e_phnum > 1024) {
        printf("load: %s: error loading executable\n", file_name);
        goto done;
    }

    /* Read program headers. */
    file_ofs = ehdr.e_phoff;
    for (i = 0; i < ehdr.e_phnum; i++) {
        struct Phdr phdr;

        if (file_ofs < 0 || file_ofs > file_length(file))
            goto done;
        file_seek(file, file_ofs);

        if (file_read(file, &phdr, sizeof phdr) != sizeof phdr)
            goto done;
        file_ofs += sizeof phdr;
        switch (phdr.p_type) {
            case PT_NULL:
            case PT_NOTE:
            case PT_PHDR:
            case PT_STACK:
            default:
                /* Ignore this segment. */
                break;
            case PT_DYNAMIC:
            case PT_INTERP:
            case PT_SHLIB:
                goto done;
            case PT_LOAD:
                if (validate_segment(&phdr, file)) {
                    bool writable = (phdr.p_flags & PF_W) != 0;
                    uint64_t file_page = phdr.p_offset & ~PGMASK;
                    uint64_t mem_page = phdr.p_vaddr & ~PGMASK;
                    uint64_t page_offset = phdr.p_vaddr & PGMASK;
                    uint32_t read_bytes, zero_bytes;
                    if (phdr.p_filesz > 0) {
                        /* Normal segment.
						 * Read initial part from disk and zero the rest. */
                        read_bytes = page_offset + phdr.p_filesz;
                        zero_bytes = (ROUND_UP(page_offset + phdr.p_memsz, PGSIZE) - read_bytes);
                    } else {
                        /* Entirely zero.
						 * Don't read anything from disk. */
                        read_bytes = 0;
                        zero_bytes = ROUND_UP(page_offset + phdr.p_memsz, PGSIZE);
                    }
                    if (!load_segment(file, file_page, (void *)mem_page,
                                      read_bytes, zero_bytes, writable))
                        goto done;
                } else
                    goto done;
                break;
        }
    }

    /* Set up stack. */
    if (!setup_stack(if_))
        goto done;

    /* Start address. */
    if_->rip = ehdr.e_entry;

    /* TODO: Your code goes here.
	 * TODO: Implement argument passing (see project2/argument_passing.html). */
    success = true;

done:
    /* We arrive here whether the load is successful or not. */
    if (file != NULL) {
        t->file_executing = file;
        lock_acquire(&filesys_lock);
        file_deny_write(file);
        lock_release(&filesys_lock);
    }
    return success;
}

/* Checks whether PHDR describes a valid, loadable segment in
 * FILE and returns true if so, false otherwise. */
static bool
validate_segment(const struct Phdr *phdr, struct file *file) {
    /* p_offset and p_vaddr must have the same page offset. */
    if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK))
        return false;

    /* p_offset must point within FILE. */
    if (phdr->p_offset > (uint64_t)file_length(file))
        return false;

    /* p_memsz must be at least as big as p_filesz. */
    if (phdr->p_memsz < phdr->p_filesz)
        return false;

    /* The segment must not be empty. */
    if (phdr->p_memsz == 0)
        return false;

    /* The virtual memory region must both start and end within the
	   user address space range. */
    if (!is_user_vaddr((void *)phdr->p_vaddr))
        return false;
    if (!is_user_vaddr((void *)(phdr->p_vaddr + phdr->p_memsz)))
        return false;

    /* The region cannot "wrap around" across the kernel virtual
	   address space. */
    if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
        return false;

    /* Disallow mapping page 0.
	   Not only is it a bad idea to map page 0, but if we allowed
	   it then user code that passed a null pointer to system calls
	   could quite likely panic the kernel by way of null pointer
	   assertions in memcpy(), etc. */
    if (phdr->p_vaddr < PGSIZE)
        return false;

    /* It's okay. */
    return true;
}

struct thread *get_child_process(tid_t pid) {
    struct thread *curr = thread_current();
    lock_acquire(&process_lock);
    for (struct list_elem *tmp = list_begin(&curr->childs); tmp != list_end(&curr->childs); tmp = list_next(tmp)) {
        struct thread *child = list_entry(tmp, struct thread, child_elem);
        if (child->tid == pid) {
            lock_release(&process_lock);
            return child;
        }
    }
    lock_release(&process_lock);
    return NULL;
}

#ifndef VM
/* Codes of this block will be ONLY USED DURING project 2.
 * If you want to implement the function for whole project 2, implement it
 * outside of #ifndef macro. */

/* load() helpers. */
static bool install_page(void *upage, void *kpage, bool writable);

/* Loads a segment starting at offset OFS in FILE at address
 * UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
 * memory are initialized, as follows:
 *
 * - READ_BYTES bytes at UPAGE must be read from FILE
 * starting at offset OFS.
 *
 * - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.
 *
 * The pages initialized by this function must be writable by the
 * user process if WRITABLE is true, read-only otherwise.
 *
 * Return true if successful, false if a memory allocation error
 * or disk read error occurs. */
static bool
load_segment(struct file *file, off_t ofs, uint8_t *upage,
             uint32_t read_bytes, uint32_t zero_bytes, bool writable) {
    ASSERT((read_bytes + zero_bytes) % PGSIZE == 0);
    ASSERT(pg_ofs(upage) == 0);
    ASSERT(ofs % PGSIZE == 0);

    file_seek(file, ofs);
    while (read_bytes > 0 || zero_bytes > 0) {
        /* Do calculate how to fill this page.
		 * We will read PAGE_READ_BYTES bytes from FILE
		 * and zero the final PAGE_ZERO_BYTES bytes. */
        size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
        size_t page_zero_bytes = PGSIZE - page_read_bytes;

        /* Get a page of memory. */
        uint8_t *kpage = palloc_get_page(PAL_USER);
        if (kpage == NULL)
            return false;

        /* Load this page. */
        if (file_read(file, kpage, page_read_bytes) != (int)page_read_bytes) {
            palloc_free_page(kpage);
            return false;
        }
        memset(kpage + page_read_bytes, 0, page_zero_bytes);

        /* Add the page to the process's address space. */
        if (!install_page(upage, kpage, writable)) {
            printf("fail\n");
            palloc_free_page(kpage);
            return false;
        }

        /* Advance. */
        read_bytes -= page_read_bytes;
        zero_bytes -= page_zero_bytes;
        upage += PGSIZE;
    }
    return true;
}

/* Create a minimal stack by mapping a zeroed page at the USER_STACK */
static bool
setup_stack(struct intr_frame *if_) {
    uint8_t *kpage;
    bool success = false;

    kpage = palloc_get_page(PAL_USER | PAL_ZERO);
    if (kpage != NULL) {
        success = install_page(((uint8_t *)USER_STACK) - PGSIZE, kpage, true);
        if (success)
            if_->rsp = USER_STACK;
        else
            palloc_free_page(kpage);
    }
    return success;
}

/* Adds a mapping from user virtual address UPAGE to kernel
 * virtual address KPAGE to the page table.
 * If WRITABLE is true, the user process may modify the page;
 * otherwise, it is read-only.
 * UPAGE must not already be mapped.
 * KPAGE should probably be a page obtained from the user pool
 * with palloc_get_page().
 * Returns true on success, false if UPAGE is already mapped or
 * if memory allocation fails. */
static bool
install_page(void *upage, void *kpage, bool writable) {
    struct thread *t = thread_current();

    /* Verify that there's not already a page at that virtual
	 * address, then map our page there. */
    return (pml4_get_page(t->pml4, upage) == NULL && pml4_set_page(t->pml4, upage, kpage, writable));
}
#else
/* From here, codes will be used after project 3.
 * If you want to implement the function for only project 2, implement it on the
 * upper block. */
struct load_segment_aux {
    struct file *file;
    off_t ofs;
    size_t page_read_bytes;
    size_t page_zero_bytes;
};

static bool
lazy_load_segment(struct page *page, void *aux) {
    /* TODO: Load the segment from the file */
    /* TODO: This called when the first page fault occurs on address VA. */
    /* TODO: VA is available when calling this function. */
    struct load_segment_aux *info = (struct load_segment_aux *)aux;
    if (file_read_at(info->file, page->va, info->page_read_bytes, info->ofs) == info->page_read_bytes)
        return false;

    if (memset((page->va) + info->page_read_bytes, 0, info->page_zero_bytes) == (page->va) + info->page_read_bytes)
        return true;

    return false;
}

/* Loads a segment starting at offset OFS in FILE at address
 * UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
 * memory are initialized, as follows:
 *
 * - READ_BYTES bytes at UPAGE must be read from FILE
 * starting at offset OFS.
 *
 * - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.
 *
 * The pages initialized by this function must be writable by the
 * user process if WRITABLE is true, read-only otherwise.
 *
 * Return true if successful, false if a memory allocation error
 * or disk read error occurs. */

static bool
load_segment(struct file *file, off_t ofs, uint8_t *upage,
             uint32_t read_bytes, uint32_t zero_bytes, bool writable) {
    ASSERT((read_bytes + zero_bytes) % PGSIZE == 0);
    ASSERT(pg_ofs(upage) == 0);
    ASSERT(ofs % PGSIZE == 0);

    while (read_bytes > 0 || zero_bytes > 0) {
        /* Do calculate how to fill this page.
		 * We will read PAGE_READ_BYTES bytes from FILE
		 * and zero the final PAGE_ZERO_BYTES bytes. */
        size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
        size_t page_zero_bytes = PGSIZE - page_read_bytes;

        /* TODO: Set up aux to pass information to the lazy_load_segment. */
        struct load_segment_aux *aux = (struct load_segment_aux *)malloc(sizeof(struct load_segment_aux));
        aux->file = file;
        aux->ofs = ofs;
        aux->page_read_bytes = page_read_bytes;
        aux->page_zero_bytes = page_zero_bytes;

        if (!vm_alloc_page_with_initializer(VM_ANON, upage,
                                            writable, lazy_load_segment, (void *)aux))
            return false;

        /* Advance. */
        read_bytes -= page_read_bytes;
        zero_bytes -= page_zero_bytes;
        upage += PGSIZE;
        ofs += PGSIZE;
    }
    return true;
}

/* Create a PAGE of stack at the USER_STACK. Return true on success. */
static bool
setup_stack(struct intr_frame *if_) {
    bool success = false;
    void *stack_bottom = (void *)(((uint8_t *)USER_STACK) - PGSIZE);

    /* TODO: Map the stack on stack_bottom and claim the page immediately.
	 * TODO: If success, set the rsp accordingly.
	 * TODO: You should mark the page is stack. */
    /* TODO: Your code goes here */
    success = vm_alloc_page(VM_ANON, stack_bottom, true);
    if (success) {
        struct page *pg = spt_find_page(&thread_current()->spt, stack_bottom);
        pg->is_stack = true;

        if(vm_claim_page(stack_bottom))
            if_->rsp = (uintptr_t)USER_STACK;
    }

    return success;
}
#endif /* VM */
