#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

/* Project 2. System Call fdt에 사용할 기본 입출력 상수 */
#define STDIN 0x1
#define STDOUT 0x2
#define STDERR 0x3

#include "threads/thread.h"

tid_t process_create_initd (const char *file_name);
tid_t process_fork (const char *name, struct intr_frame *if_);
int process_exec (void *f_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (struct thread *next);
void argument_stack(char **parse, int count, void **rsp);
struct thread *get_child_process(int pid);

#endif /* userprog/process.h */
