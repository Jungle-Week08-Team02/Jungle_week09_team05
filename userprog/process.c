#include "userprog/process.h"
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
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef VM
#include "userprog/syscall.h"
#include "vm/vm.h"
#endif

static void process_cleanup(void);
static bool load(const char *file_name, struct intr_frame *if_);
static void initd(void *f_name);
static void __do_fork(void *);

/* General process initializer for initd and other process. */
static void process_init(void) { struct thread *current = thread_current(); }

/* 초기 사용자 프로그램을 생성하고 실행하는 함수입니다.
 * 이 함수는 커맨드 라인에서 입력받은 명령어를 파싱하여 프로그램을 실행합니다.
 * 프로그램 실행을 위해 새로운 스레드를 생성하고, 프로그램의 이름과 인자를 전달합니다.
 * 성공 시 생성된 스레드의 TID를 반환하고, 실패 시 TID_ERROR를 반환합니다.
 * 이 함수는 Pintos의 첫 번째 사용자 프로세스를 시작하는 데 사용됩니다. */
tid_t process_create_initd(const char *file_name) {
    char *fn_copy; // 파일 이름 복사본
    tid_t tid;     // 스레드 ID

    /* FILE_NAME의 복사본을 만듭니다.
     * 그렇지 않으면 호출자와 load() 사이에 경쟁 상태가 발생할 수 있습니다. */
    fn_copy = palloc_get_page(0); // 페이지 할당

    if (fn_copy == NULL) // 할당 실패
        return TID_ERROR;

    strlcpy(fn_copy, file_name, PGSIZE); // 파일 이름 복사

    /* fn_copy를 이용해 실행 파일명만 추출 */
    char *save_ptr; // 토크나이저의 위치를 추적하는 데 사용되는 변수
    char *prog_name = strtok_r(
        fn_copy, " ", // 공백을 기준으로 입력한 문자열을 분리하여 토크나이징을 진행
        &save_ptr); // 토크나이저의 위치를 추적하는 데 사용되는 변수

    if (prog_name == NULL) {       // 토크나이징 실패
        palloc_free_page(fn_copy); // 할당 해제
        return TID_ERROR;          // 스레드 ID 반환
    }

    /* 두 번째 fn_copy는 전체 커맨드라인을 보존하기 위한 것 */
    char *fn_copy2 = palloc_get_page(0); // 페이지 할당
    if (fn_copy2 == NULL) {              // 할당 실패
        palloc_free_page(fn_copy);       // 할당 해제
        return TID_ERROR;                // 스레드 ID 반환
    }
    strlcpy(fn_copy2, fn_copy, PGSIZE); // 파일 이름 복사

    /* prog_name으로 스레드를 생성하고 fn_copy2를 인자로 전달 */
    tid = thread_create(prog_name, PRI_DEFAULT, initd, fn_copy2); // 스레드 생성

    /* 첫 번째 복사본은 이제 필요 없음 */
    palloc_free_page(fn_copy); // 할당 해제

    if (tid == TID_ERROR)           // 스레드 생성 실패
        palloc_free_page(fn_copy2); // 할당 해제

    return tid; // 스레드 ID 반환
}

/* A thread function that launches first user process. */
static void initd(void *f_name) {
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
tid_t process_fork(const char *name, struct intr_frame *if_ UNUSED) {
    /* Clone current thread to new thread.*/
    struct thread *current = thread_current();
    memcpy(&current->parent_if, &if_, sizeof(struct intr_frame));

    tid_t tid = thread_create(name, PRI_DEFAULT, __do_fork, current);
    if (tid == TID_ERROR)
        return TID_ERROR;

    struct thread *child = get_child_process(tid);

    sema_down(&child->load_sema);

    return tid;
}

struct thread *get_child_process(int pid) {
    struct thread *current = thread_current();
    struct list *child_list = &current->child_list;

    for (struct list_elem *e = list_begin(child_list); e != list_end(child_list);
         e = list_next(e)) {
        struct thread *child = list_entry(e, struct thread, elem);
        if (child->tid == pid)
            return child;
    }
    return NULL;
}

#ifndef VM
/* Duplicate the parent's address space by passing this function to the
 * pml4_for_each. This is only for the project 2. */
static bool duplicate_pte(uint64_t *pte, void *va, void *aux) {
    struct thread *current = thread_current();
    struct thread *parent = (struct thread *)aux;
    void *parent_page;
    void *newpage;
    bool writable;

    /* 1. 부모 페이지가 커널 페이지인 경우 즉시 리턴 */
    if (is_kernel_vaddr(va))
        return true;

    /* 2. 부모의 페이지 맵 레벨 4에서 VA 해석 */
    parent_page = pml4_get_page(parent->pml4, va);
    if (parent_page == NULL)
        return false;

    /* 3. 자식을 위한 새로운 PAL_USER 페이지 할당 */
    newpage = palloc_get_page(PAL_USER);
    if (newpage == NULL)
        return false;

    /* 4. 부모의 페이지를 새 페이지로 복제하고 쓰기 가능 여부 확인 */
    memcpy(newpage, parent_page, PGSIZE);
    writable = is_writable(pte);

    /* 5. WRITABLE 권한으로 VA 주소에 새 페이지를 자식의 페이지 테이블에 추가 */
    if (!pml4_set_page(current->pml4, va, newpage, writable)) {
        /* 6. 페이지 삽입 실패 시 에러 처리 */
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
static void __do_fork(void *aux) {
    struct intr_frame if_;
    struct thread *parent = (struct thread *)aux;
    struct thread *current = thread_current();
    /* TODO: somehow pass the parent_if. (i.e. process_fork()'s if_) */
    struct intr_frame *parent_if = &parent->parent_if;
    bool succ = true;

    /* 1. Read the cpu context to local stack. */
    memcpy(&if_, parent_if, sizeof(struct intr_frame));
    if_.R.rax = 0; // 자식 프로세스 리턴값은 0

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
    for (int i = 0; i < FDT_COUNT_LIMIT; i++) {
        struct file *file = parent->fdt[i];

        if (file == NULL)
            continue;
        if (file > 2)
            file = file_duplicate(file);
        current->fdt[i] = file;
    }
    current->next_fd = parent->next_fd;

    sema_up(&current->load_sema);
    process_init();

    /* Finally, switch to the newly created process. */
    if (succ)
        do_iret(&if_);
error:
    sema_up(&current->load_sema);
    thread_exit();
}

/* 현재 실행 컨텍스트를 f_name으로 전환합니다.
 * 실패 시 -1을 반환합니다. */
int process_exec(void *f_name) {
    char *file_name = f_name; // 파일 이름
    bool success;             // 성공 여부

    /* 스레드 구조체의 intr_frame을 사용할 수 없습니다.
     * 현재 스레드가 재스케줄링될 때 실행 정보를 멤버에 저장하기 때문입니다. */
    struct intr_frame _if;                // 인트러프 프레임
    _if.ds = _if.es = _if.ss = SEL_UDSEG; // 데이터 세그먼트 설정
    _if.cs = SEL_UCSEG;                   // 코드 세그먼트 설정
    _if.eflags = FLAG_IF | FLAG_MBS;      // 플래그 설정

    /* 현재 컨텍스트를 종료합니다. */
    process_cleanup(); // 프로세스 정리

    /* 명령행 인자 파싱을 위한 변수들 */
    char *ptr;
    char *argv[64]; // 포인터 배열로 수정
    int argc = 0;

    /* 토큰화 */
    char *token = strtok_r(file_name, " ", &ptr);

    while (token != NULL && argc < 64) { // 토큰이 유효하고 인자 수가 64 미만인 경우
        argv[argc++] = token;            // 인자 배열에 토큰 추가
        token = strtok_r(NULL, " ", &ptr); // 다음 토큰 파싱
    }

    /* 실행 파일 로드 */
    success = load(argv[0], &_if); // 첫 번째 인자를 실행 파일 이름으로 사용

    /* 로드 실패 시 종료 */
    if (!success) {
        palloc_free_page(file_name); // 페이지 해제
        return -1;
    }

    /* 인자 스택 설정 */
    argument_stack(argv, argc, &_if.rsp); // rsp만 전달
    printf("rsp: %lx\n", _if.rsp);
    palloc_free_page(file_name);

    // hex_dump(_if.rsp, _if.rsp, USER_STACK - _if.rsp, true);

    /* 전환된 프로세스를 시작합니다. */
    do_iret(&_if); // 인트러프 프레임 전환
    NOT_REACHED(); // 도달할 수 없는 코드
}

/* 스레드 TID가 종료될 때까지 기다리고 해당 스레드의 종료 상태를 반환합니다.
 * 커널에 의해 종료된 경우(예외로 인해 강제 종료된 경우) -1을 반환합니다.
 * TID가 유효하지 않거나 호출한 프로세스의 자식이 아닌 경우,
 * 또는 해당 TID에 대해 process_wait()가 이미 성공적으로 호출된 경우
 * 기다리지 않고 즉시 -1을 반환합니다.
 *
 * 이 함수는 문제 2-2에서 구현될 예정입니다. 현재는 아무 동작도 하지 않습니다. */
int process_wait(tid_t child_tid UNUSED) {
    struct thread *child = get_child_process(child_tid);

    if (child == NULL)
        return -1;

    sema_down(&child->wait_sema);
    list_remove(&child->elem);
    sema_up(&child->exit_sema);

    return child->exit_status;
}

/* Exit the process. This function is called by thread_exit (). */
void process_exit(void) {
    struct thread *curr = thread_current();

    // 파일 디스크립터 테이블이 NULL이 아닌 경우에만 처리
    if (curr->fdt != NULL) {
        for (int i = 2; i < FDT_COUNT_LIMIT; i++)
            close(i);
        palloc_free_page(curr->fdt);
    }

    // running_file이 NULL이 아닌 경우에만 처리
    if (curr->running_file != NULL)
        file_close(curr->running_file);

    process_cleanup();

    sema_up(&curr->wait_sema);
    sema_down(&curr->exit_sema);
}

/* Free the current process's resources. */
static void process_cleanup(void) {
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
                         uint32_t read_bytes, uint32_t zero_bytes, bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
 * Stores the executable's entry point into *RIP
 * and its initial stack pointer into *RSP.
 * Returns true if successful, false otherwise. */
static bool load(const char *file_name, struct intr_frame *if_) {
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
    file = filesys_open(file_name);
    if (file == NULL) {
        printf("load: %s: open failed\n", file_name);
        goto done;
    }

    /* Read and verify executable header. */
    if (file_read(file, &ehdr, sizeof ehdr) != sizeof ehdr ||
        memcmp(ehdr.e_ident, "\177ELF\2\1\1", 7) || ehdr.e_type != 2 ||
        ehdr.e_machine != 0x3E // amd64
        || ehdr.e_version != 1 || ehdr.e_phentsize != sizeof(struct Phdr) ||
        ehdr.e_phnum > 1024) {
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
                    zero_bytes =
                        (ROUND_UP(page_offset + phdr.p_memsz, PGSIZE) - read_bytes);
                } else {
                    /* Entirely zero.
                     * Don't read anything from disk. */
                    read_bytes = 0;
                    zero_bytes = ROUND_UP(page_offset + phdr.p_memsz, PGSIZE);
                }
                if (!load_segment(file, file_page, (void *)mem_page, read_bytes,
                                  zero_bytes, writable))
                    goto done;
            } else
                goto done;
            break;
        }
    }

    t->running_file = file;
    file_deny_write(file);

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
    file_close(file);
    return success;
}

/* Checks whether PHDR describes a valid, loadable segment in
 * FILE and returns true if so, false otherwise. */
static bool validate_segment(const struct Phdr *phdr, struct file *file) {
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
static bool load_segment(struct file *file, off_t ofs, uint8_t *upage,
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
static bool setup_stack(struct intr_frame *if_) {
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
static bool install_page(void *upage, void *kpage, bool writable) {
    struct thread *t = thread_current();

    /* Verify that there's not already a page at that virtual
     * address, then map our page there. */
    return (pml4_get_page(t->pml4, upage) == NULL &&
            pml4_set_page(t->pml4, upage, kpage, writable));
}
#else
/* From here, codes will be used after project 3.
 * If you want to implement the function for only project 2, implement it on the
 * upper block. */

static bool lazy_load_segment(struct page *page, void *aux) {
    /* TODO: Load the segment from the file */
    /* TODO: This called when the first page fault occurs on address VA. */
    /* TODO: VA is available when calling this function. */
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
static bool load_segment(struct file *file, off_t ofs, uint8_t *upage,
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
        void *aux = NULL;
        if (!vm_alloc_page_with_initializer(VM_ANON, upage, writable, lazy_load_segment,
                                            aux))
            return false;

        /* Advance. */
        read_bytes -= page_read_bytes;
        zero_bytes -= page_zero_bytes;
        upage += PGSIZE;
    }
    return true;
}

/* Create a PAGE of stack at the USER_STACK. Return true on success. */
static bool setup_stack(struct intr_frame *if_) {
    bool success = false;
    void *stack_bottom = (void *)(((uint8_t *)USER_STACK) - PGSIZE);

    /* TODO: Map the stack on stack_bottom and claim the page immediately.
     * TODO: If success, set the rsp accordingly.
     * TODO: You should mark the page is stack. */
    /* TODO: Your code goes here */

    return success;
}
#endif /* VM */

/* 사용자 프로그램의 명령행 인자를 스택에 설정하는 함수입니다.
 *
 * 이 함수는 다음과 같은 순서로 스택을 구성합니다:
 * 1. 인자 문자열들을 스택의 맨 위에서부터 역순으로 저장합니다.
 * 2. 8바이트 정렬을 위해 필요한 패딩을 추가합니다.
 * 3. argv[argc]에 해당하는 NULL 포인터를 추가합니다.
 * 4. argv 배열의 각 인자에 대한 포인터를 역순으로 저장합니다.
 * 5. 가짜 리턴 주소를 추가하여 스택 프레임을 완성합니다.
 *
 * @param argv 명령행 인자 문자열 배열
 * @param argc 명령행 인자의 개수
 * @param rsp 스택 포인터의 주소
 */
void argument_stack(char **argv, int argc, void **rsp) {
    // Save argument strings (character by character)
    for (int i = argc - 1; i >= 0; i--) {
        int argv_len = strlen(argv[i]);
        for (int j = argv_len; j >= 0; j--) {
            char argv_char = argv[i][j];
            (*rsp)--;
            **(char **)rsp = argv_char; // 1 byte
        }
        argv[i] = *(char **)rsp; // 리스트에 rsp 주소 넣기
    }

    // Word-align padding
    int pad = (int)*rsp % 8;
    for (int k = 0; k < pad; k++) {
        (*rsp)--;
        **(uint8_t **)rsp = 0;
    }

    // Pointers to the argument strings
    (*rsp) -= 8;
    **(char ***)rsp = 0;

    for (int i = argc - 1; i >= 0; i--) {
        (*rsp) -= 8;
        **(char ***)rsp = argv[i];
    }

    // Return address
    (*rsp) -= 8;
    **(void ***)rsp = 0;
}

/* 새로운 파일을 프로세스의 파일 디스크립터 테이블에 추가하는 함수입니다.
 * 성공 시 할당된 파일 디스크립터를 반환하고, 실패 시 -1을 반환합니다.
 *
 * 이 함수는 다음과 같은 작업을 수행합니다:
 * 1. 현재 사용 가능한 가장 작은 파일 디스크립터를 찾습니다.
 * 2. 파일을 파일 디스크립터 테이블에 추가합니다.
 * 3. 할당된 파일 디스크립터를 반환합니다. */
int process_add_file(struct file *f) {
    struct thread *t = thread_current();
    struct file **fdt = t->fdt;

    // 사용 가능한 가장 작은 파일 디스크립터를 찾습니다
    while (t->next_fd < FDT_COUNT_LIMIT && fdt[t->next_fd])
        t->next_fd++;

    // 파일 디스크립터 테이블이 가득 찼는지 확인
    if (t->next_fd >= FDT_COUNT_LIMIT)
        return -1;

    // 파일을 테이블에 추가하고 파일 디스크립터 반환
    fdt[t->next_fd] = f;
    return t->next_fd++;
}

/* 파일 디스크립터를 통해 파일을 반환하는 함수입니다. */
struct file *process_get_file(int fd) {
    struct thread *t = thread_current();
    struct file **fdt = t->fdt;

    if (fd < 0 || fd >= t->next_fd)
        return NULL;

    return fdt[fd];
}

/* 파일 디스크립터 테이블에서 파일을 제거하는 함수입니다.
 * 
 * 이 함수는 다음과 같은 조건을 검사합니다:
 * 1. fd가 2보다 작은 경우 (표준 입출력은 닫을 수 없음)
 * 2. fd가 FDT_COUNT_LIMIT보다 크거나 같은 경우 (배열 범위 초과)
 * 
 * 유효한 fd인 경우 해당 위치의 파일 포인터를 NULL로 설정합니다. */
void process_close_file(int fd) {
    struct thread *t = thread_current();
    struct file **fdt = t->fdt;

    // 표준 입출력이거나 최대 제한을 넘는 경우 처리하지 않음
    if (fd < 2 || fd >= FDT_COUNT_LIMIT)
        return;

    fdt[fd] = NULL;
}
