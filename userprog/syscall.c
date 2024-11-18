#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"

/* Project 2 : System Call 구현 */
#include <string.h>
#include "filesys/file.h"
#include "threads/mmu.h"
#include "threads/palloc.h"
#include "userprog/process.h"
/*******************************/

void syscall_entry (void);
void syscall_handler (struct intr_frame *);

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

void
syscall_init (void) {
	write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48  |
			((uint64_t)SEL_KCSEG) << 32);
	write_msr(MSR_LSTAR, (uint64_t) syscall_entry);

	/* The interrupt service rountine should not serve any interrupts
	 * until the syscall_entry swaps the userland stack to the kernel
	 * mode stack. Therefore, we masked the FLAG_FL. */
	write_msr(MSR_SYSCALL_MASK,
			FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);
}

/* The main system call interface */
void
syscall_handler (struct intr_frame *f UNUSED) {

	int syscall_num = f->R.rax;

	switch (syscall_num)
	{
		case SYS_HALT:
			halt();
			break;
		
		case SYS_EXIT:
			exit(-1);
			break;
		
		case SYS_FORK:
			f->R.rax = fork(f->R.rdi);
			break;
		
		case SYS_EXEC:
			f->R.rax = exec(f->R.rdi);
			break;
		
		case SYS_WAIT:
			f->R.rax = process_wait(f->R.rdi);
			break;
		
		case SYS_CREATE:
			/* code */
			break;
		
		case SYS_REMOVE:
			/* code */
			break;
		
		case SYS_OPEN:
			/* code */
			break;
		
		default:
			exit(-1);
	}

	printf ("system call!\n");
	thread_exit ();
}

#ifndef VM
/* Project 2 : System Call 구현 */
void check_address(void *addr){
	struct thread *curr = thread_current();

	if (is_kernel_vaddr(addr) || addr == NULL || pml4_get_page(curr->pml4, addr) == NULL)
		exit(-1);
}
#else
/* Project 3: Anonymous Page */
#endif

/* Project 2 : System Call 구현 */
void halt(void) {
	power_off();
}

void exit (int status) {
	struct thread *curr = thread_current();
	curr->exit_status = status;

	printf("%s: exit(%d).\n", curr->name, curr->exit_status);

	thread_exit();
}

tid_t fork(const char * thread_name) {
	check_address(thread_name);

	return process_fork(thread_name, NULL);
}

int exec (const char *cmd_line){
	check_address(cmd_line);
	off_t size = strlen(cmd_line) + 1;
	char *cmd_copy = palloc_get_page(PAL_ZERO);

	if (cmd_copy == NULL)
		return -1;

	memcpy(cmd_copy, cmd_line, size);

	return process_exec(cmd_copy); 
}

int wait (tid_t tid){
	return process_wait(tid);
}