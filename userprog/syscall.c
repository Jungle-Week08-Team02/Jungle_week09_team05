#include "userprog/syscall.h"
#include "intrinsic.h"
#include "threads/flags.h"
#include "threads/interrupt.h"
#include "threads/loader.h"
#include "threads/thread.h"
#include "userprog/gdt.h"
#include <stdio.h>
#include <syscall-nr.h>

void syscall_entry(void);
void syscall_handler(struct intr_frame *);
void check_address(void *);
void halt(void);
void exit(int);
bool create(const char *, unsigned);
bool remove(const char *);
int open(const char *);
int filesize(int);
int read(int, void *, unsigned);
int write(int, const void *, unsigned);
void seek(int, unsigned);
unsigned tell(int);
void close(int);
tid_t fork(const char *);
int exec(const char *);
int wait(tid_t);

/* 시스템 콜.
 *
 * 이전에는 시스템 콜 서비스가 인터럽트 핸들러에 의해 처리되었습니다
 * (예: 리눅스의 int 0x80). 하지만 x86-64에서는 제조사가
 * 시스템 콜을 요청하기 위한 효율적인 경로인 `syscall` 명령어를 제공합니다.
 * syscall 명령어는 Model Specific Register(MSR)로부터 값을 읽어
 * 동작합니다. 자세한 내용은 매뉴얼을 참조하세요. */

#define MSR_STAR 0xc0000081         /* Segment selector msr */
#define MSR_LSTAR 0xc0000082        /* Long mode SYSCALL target */
#define MSR_SYSCALL_MASK 0xc0000084 /* Mask for the eflags */

void syscall_init(void) {
    write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48 | ((uint64_t)SEL_KCSEG) << 32);
    write_msr(MSR_LSTAR, (uint64_t)syscall_entry);

    /* 인터럽트 서비스 루틴은 syscall_entry가 유저랜드 스택을 커널 모드 스택으로
     * 교체할 때까지 어떠한 인터럽트도 처리하지 않아야 합니다.
     * 따라서 FLAG_FL을 마스킹했습니다. */
    write_msr(MSR_SYSCALL_MASK,
              FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);
}

/* 시스템 콜 인터페이스의 메인 함수 */
void syscall_handler(struct intr_frame *f UNUSED) {
    /* 시스템 콜 핸들러 함수입니다.
     * rax 레지스터에 저장된 시스템 콜 번호에 따라 적절한 시스템 콜을 처리합니다.
     * 각 시스템 콜은 인자의 개수가 다르며, 해당 인자들은 rdi, rsi, rdx 등의 레지스터를
     * 통해 전달됩니다. */

    switch (f->R.rax) {
    case SYS_HALT:
        halt();
        break;

    case SYS_EXIT:
        exit(f->R.rdi);
        break;

    case SYS_FORK:
        f->R.rax = fork(f->R.rdi);
        break;

    case SYS_EXEC:
        f->R.rax = exec(f->R.rdi);
        break;

    case SYS_WAIT:
        f->R.rax = wait(f->R.rdi);
        break;

    case SYS_CREATE:
        f->R.rax = create(f->R.rdi, f->R.rsi);
        break;

    case SYS_REMOVE:
        f->R.rax = remove(f->R.rdi);
        break;

    case SYS_OPEN:
        f->R.rax = open(f->R.rdi);
        break;

    case SYS_FILESIZE:
        f->R.rax = filesize(f->R.rdi);
        break;

    case SYS_READ:
        f->R.rax = read(f->R.rdi, f->R.rsi, f->R.rdx);
        break;

    case SYS_WRITE:
        f->R.rax = write(f->R.rdi, f->R.rsi, f->R.rdx);
        break;

    case SYS_SEEK:
        seek(f->R.rdi, f->R.rsi);
        break;

    case SYS_TELL:
        f->R.rax = tell(f->R.rdi);
        break;

    case SYS_CLOSE:
        close(f->R.rdi);
        break;
    }
}

/* 주소 유효성 검사 함수
 *
 * 사용자가 제공한 포인터가 유효한 주소를 가리키는지 검사합니다.
 * 다음과 같은 경우 프로세스를 종료시킵니다:
 * 1. 포인터가 NULL인 경우
 * 2. 포인터가 커널 영역을 가리키는 경우
 *
 * 이 함수는 시스템 콜에서 사용자가 제공한 모든 포인터에 대해
 * 반드시 호출되어야 하며, 잘못된 메모리 접근으로 인한
 * 커널 패닉을 방지하는 역할을 합니다.
 */
void check_address(void *addr) {
    if (addr == NULL)
        exit(-1);
    if (!is_user_vaddr(addr))
        exit(-1);
}

/* 시스템을 종료하는 시스템 콜입니다.
 * 이 함수는 운영체제를 종료하고 Pintos를 중단시킵니다.
 * 일반적으로 운영체제의 정상적인 종료를 위해 사용되며,
 * 이 함수가 호출되면 시스템이 즉시 종료됩니다. */
void halt(void) { power_off(); }

/* 파일을 생성하는 시스템 콜입니다.
 * file: 생성할 파일의 이름
 * initial_size: 파일의 초기 크기
 * 성공하면 true, 실패하면 false를 반환합니다. */
bool create(const char *file, unsigned initial_size) {
    check_address(file);
    return filesys_create(file, initial_size);
}

/* 파일을 삭제하는 시스템 콜입니다.
 * file: 삭제할 파일의 이름
 * 성공하면 true, 실패하면 false를 반환합니다. */
bool remove(const char *file) {
    check_address(file);
    return filesys_remove(file);
}

/* 파일을 여는 시스템 콜입니다.
 * file: 열 파일의 이름
 * 성공하면 파일 디스크립터를, 실패하면 -1을 반환합니다. */
int open(const char *file) {
    check_address(file);
    struct file *f = filesys_open(file);
    if (f == NULL)
        return -1;

    int fd = process_add_file(f);
    if (fd == -1)
        file_close(f);

    return fd;
}

/* 현재 프로세스를 종료하는 시스템 콜입니다.
 * status: 종료 상태 코드
 * 이 함수는 현재 실행 중인 프로세스를 종료하고 부모 프로세스에게 status를 반환합니다.
 * 프로세스가 열었던 모든 파일은 자동으로 닫히며, 프로세스의 모든 자원이 해제됩니다.
 * 이 함수는 절대 반환되지 않습니다. */
void exit(int status) {
    struct thread *curr = thread_current();
    curr->exit_status = status;
    printf("%s: exit(%d)\n", thread_name(), status);
    thread_exit();
}

/* 현재 프로세스를 복제하는 시스템 콜입니다.
 * thread_name: 새로 생성될 스레드의 이름
 * 이 함수는 현재 프로세스의 복사본을 생성합니다.
 * 자식 프로세스는 부모 프로세스의 메모리와 파일 디스크립터를 복사하여 가지게 됩니다.
 * 성공하면 자식 프로세스의 pid를, 실패하면 -1을 반환합니다. */
tid_t fork(const char *thread_name) {
    check_address(thread_name);
    return process_fork(thread_name, NULL);
}

/* 새로운 프로그램을 실행하는 시스템 콜입니다.
 * file: 실행할 프로그램의 이름
 * 이 함수는 현재 프로세스를 새로운 프로그램으로 대체합니다.
 * 현재 프로세스의 메모리 공간은 새로운 프로그램으로 완전히 대체되며,
 * 성공하면 -1을 절대 반환하지 않고, 실패하면 -1을 반환합니다. */
int exec(const char *file) {
    check_address(file);

    char *fn_copy = palloc_get_page(0);

    if (fn_copy == NULL)
        return -1;

    strlcpy(fn_copy, file, PGSIZE);

    if (process_exec(fn_copy) == -1)
        return -1;

    NOT_REACHED();

    return 0;
}

/* 자식 프로세스가 종료될 때까지 대기하는 시스템 콜입니다.
 * pid: 대기할 자식 프로세스의 pid
 * 이 함수는 지정된 자식 프로세스가 종료될 때까지 현재 프로세스의 실행을 중단합니다.
 * 자식 프로세스가 정상적으로 종료되면 해당 프로세스의 종료 상태를 반환하고,
 * 자식이 비정상 종료되거나 잘못된 pid가 전달되면 -1을 반환합니다. */
int wait(tid_t pid) { return process_wait(pid); }

/* 파일의 크기를 반환하는 시스템 콜입니다.
 * fd: 파일 디스크립터
 * 성공하면 파일 크기를, 실패하면 -1을 반환합니다. */
int filesize(int fd) {
    struct file *f = process_get_file(fd);
    if (f == NULL)
        return -1;
    return file_length(f);
}

/* 파일에서 데이터를 읽는 시스템 콜입니다.
 * fd: 파일 디스크립터
 * buffer: 읽은 데이터를 저장할 버퍼
 * size: 읽을 바이트 수
 * 성공하면 실제로 읽은 바이트 수를, 실패하면 -1을 반환합니다. */
int read(int fd, void *buffer, unsigned size) {
    check_address(buffer);
    if (fd == 0) {
        for (unsigned i = 0; i < size; i++) {
            if (((char *)buffer)[i] == '\0')
                break;
        }
        return size;
    }

    struct file *f = process_get_file(fd);
    if (f == NULL)
        return -1;
    return file_read(f, buffer, size);
}

/* 파일에 데이터를 쓰는 시스템 콜입니다.
 * fd: 파일 디스크립터
 * buffer: 쓸 데이터가 있는 버퍼
 * size: 쓸 바이트 수
 * 성공하면 실제로 쓴 바이트 수를, 실패하면 -1을 반환합니다. */
int write(int fd, const void *buffer, unsigned size) {
    check_address(buffer);
    if (fd == 1) {
        putbuf(buffer, size);
        return size;
    }

    struct file *f = process_get_file(fd);
    if (f == NULL)
        return -1;
    return file_write(f, buffer, size);
}

/* 파일 내 읽기/쓰기 위치를 이동하는 시스템 콜입니다.
 * fd: 파일 디스크립터
 * position: 이동할 위치 */
void seek(int fd, unsigned position) {
    struct file *f = process_get_file(fd);
    if (f != NULL)
        file_seek(f, position);
}

/* 파일 내 현재 읽기/쓰기 위치를 반환하는 시스템 콜입니다.
 * fd: 파일 디스크립터
 * 성공하면 현재 위치를, 실패하면 -1을 반환합니다. */
unsigned tell(int fd) {
    struct file *f = process_get_file(fd);
    if (f == NULL)
        return -1;
    return file_tell(f);
}

/* 파일을 닫는 시스템 콜입니다.
 * fd: 파일 디스크립터 */
void close(int fd) {
    struct file *f = process_get_file(fd);
    if (f != NULL) {
        process_close_file(fd);
        file_close(f);
    }
}
