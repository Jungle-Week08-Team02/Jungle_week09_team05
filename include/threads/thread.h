#ifndef THREADS_THREAD_H
#define THREADS_THREAD_H

#include "threads/interrupt.h"
#include "threads/synch.h"
#include <debug.h>
#include <list.h>
#include <stdint.h>
#ifdef VM
#include "vm/vm.h"
#endif

/* States in a thread's life cycle. */
enum thread_status {
    THREAD_RUNNING, /* Running thread. */
    THREAD_READY,   /* Not running but ready to run. */
    THREAD_BLOCKED, /* Waiting for an event to trigger. */
    THREAD_DYING    /* About to be destroyed. */
};

/* Thread identifier type.
   You can redefine this to whatever type you like. */
typedef int tid_t;
#define TID_ERROR ((tid_t) - 1) /* Error value for tid_t. */

/* Thread priorities. */
#define PRI_MIN 0      /* Lowest priority. */
#define PRI_DEFAULT 31 /* Default priority. */
#define PRI_MAX 63     /* Highest priority. */

/* 파일 디스크립터 테이블의 크기 */
#define FDT_PAGES 2
#define FDT_COUNT_LIMIT 128

// *************************************************************************************//
#define NICE_DEFAULT 0
#define RECENT_CPU_DEFAULT 0
#define LOAD_AVG_DEFAULT 0
// *************************************************************************************//

/* A kernel thread or user process.
 *
 * Each thread structure is stored in its own 4 kB page.  The
 * thread structure itself sits at the very bottom of the page
 * (at offset 0).  The rest of the page is reserved for the
 * thread's kernel stack, which grows downward from the top of
 * the page (at offset 4 kB).  Here's an illustration:
 *
 *      4 kB +---------------------------------+
 *           |          kernel stack           |
 *           |                |                |
 *           |                |                |
 *           |                V                |
 *           |         grows downward          |
 *           |                                 |
 *           |                                 |
 *           |                                 |
 *           |                                 |
 *           |                                 |
 *           |                                 |
 *           |                                 |
 *           |                                 |
 *           +---------------------------------+
 *           |              magic              |
 *           |            intr_frame           |
 *           |                :                |
 *           |                :                |
 *           |               name              |
 *           |              status             |
 *      0 kB +---------------------------------+
 *
 * The upshot of this is twofold:
 *
 *    1. First, `struct thread' must not be allowed to grow too
 *       big.  If it does, then there will not be enough room for
 *       the kernel stack.  Our base `struct thread' is only a
 *       few bytes in size.  It probably should stay well under 1
 *       kB.
 *
 *    2. Second, kernel stacks must not be allowed to grow too
 *       large.  If a stack overflows, it will corrupt the thread
 *       state.  Thus, kernel functions should not allocate large
 *       structures or arrays as non-static local variables.  Use
 *       dynamic allocation with malloc() or palloc_get_page()
 *       instead.
 *
 * The first symptom of either of these problems will probably be
 * an assertion failure in thread_current(), which checks that
 * the `magic' member of the running thread's `struct thread' is
 * set to THREAD_MAGIC.  Stack overflow will normally change this
 * value, triggering the assertion. */
/* The `elem' member has a dual purpose.  It can be an element in
 * the run queue (thread.c), or it can be an element in a
 * semaphore wait list (synch.c).  It can be used these two ways
 * only because they are mutually exclusive: only a thread in the
 * ready state is on the run queue, whereas only a thread in the
 * blocked state is on a semaphore wait list. */
struct thread {
    /* Owned by thread.c. */
    tid_t tid;                 /* Thread identifier. */
    enum thread_status status; /* Thread state. */
    char name[16];             /* Name (for debugging purposes). */
    int priority;              /* Priority. */
    int init_priority;         /* 해당 스레드의 '원래' Priority. */
    int nice;                  /* nice값: 클수록 CPU 양보 ↑ */
    int recent_cpu; /* 해당 스레드가 최근 얼마나 많은 CPU time을 사용 했는지 */
    struct list donations; /* 해당 스레드가 가지고 있는 lock을 필요로 하는 스레드들 */
    struct list_elem d_elem; /* donations 리스트를 쓰기 위한 리스트 요소 */
    struct lock *wait_on_lock; /* 해당 스레드가 기다리고 있는 lock을 가리키는 포인터 */

    /* Shared between thread.c and synch.c. */
    struct list_elem elem;    /* List element. */
    struct list_elem allelem; /* List element. */

    int exit_status; /* 해당 스레드의 종료 상태 */
    struct file **fdt; /* 해당 스레드가 열었던 파일들을 가리키는 포인터 배열 */
    int next_fd;                 /* 다음에 할당할 파일 디스크립터 */
    struct intr_frame parent_if; /* 부모 스레드의 intr_frame */
    struct list child_list; /* 해당 스레드의 자식 스레드들을 가리키는 리스트 */
    struct list_elem child_elem; /* child_list를 쓰기 위한 리스트 요소 */

    struct semaphore load_sema; /* 해당 스레드의 자식 스레드들이 모두 종료될 때까지 기다리는 세마포어 */
    struct semaphore wait_sema; /* 해당 스레드가 기다리고 있는 lock을 가리키는 세마포어 */
    struct semaphore exit_sema; /* 해당 스레드가 종료될 때까지 기다리는 세마포어 */

    struct file *running_file; /* 해당 스레드가 현재 실행 중인 파일 */

#ifdef USERPROG
    /* Owned by userprog/process.c. */
    uint64_t *pml4; /* Page map level 4 */
#endif
#ifdef VM
    /* Table for whole virtual memory owned by thread. */
    struct supplemental_page_table spt;
#endif

    /* Owned by thread.c. */
    struct intr_frame tf; /* Information for switching */
    unsigned magic;       /* Detects stack overflow. */

    int64_t wake_tick; /* 스레드가 깨어날 시각*/
};

/* If false (default), use round-robin scheduler.
   If true, use multi-level feedback queue scheduler.
   Controlled by kernel command-line option "-o mlfqs". */
extern bool thread_mlfqs;

void thread_init(void);
void thread_start(void);

void thread_tick(void);
void thread_print_stats(void);

typedef void thread_func(void *aux);
tid_t thread_create(const char *name, int priority, thread_func *, void *);

void thread_block(void);
void thread_unblock(struct thread *);

struct thread *thread_current(void);
tid_t thread_tid(void);
const char *thread_name(void);

void thread_exit(void) NO_RETURN;
void thread_yield(void);

int thread_get_priority(void);
void thread_set_priority(int);

int thread_get_nice(void);
void thread_set_nice(int);
int thread_get_recent_cpu(void);
int thread_get_load_avg(void);

void do_iret(struct intr_frame *tf);

/* 여기서 부터 구현 함수 */
// *************************************************************************************//
void thread_sleep(int64_t);
void thread_awake(int64_t);
bool thread_wake_tick_cmp(const struct list_elem *, const struct list_elem *, void *);
bool cmp_thread_priority(const struct list_elem *, const struct list_elem *, void *);
bool cmp_delem_priority(const struct list_elem *, const struct list_elem *, void *);
void schedule_by_priority();
void do_donate();
void remove_with_rock(struct lock *);
void re_dona_priority();
void mlfqs_calc_priority(struct thread *);
void mlfqs_calc_recent_cpu(struct thread *);
void mlfqs_calc_load_avg();
void mlfqs_incr_recent_cpu();
void mlfqs_recalc_recent_cpu();
void mlfqs_recalc_priority();
// *************************************************************************************//
#endif /* threads/thread.h */
