#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include "threads/thread.h"

/* define prototype of initializing syscall */
void syscall_init (void);

/* define prototype of checking valid user's virtual address space */
void check_user_address(void* esp);

/* define prototype of system call implementation */
void sys_halt(void);
void sys_exit(int status);
tid_t sys_exec(const char *file_name);
int sys_wait(tid_t pid);
int sys_read(int fd, void *buffer, unsigned size);
int sys_write(int fd, const void *buffer, unsigned size);
int fibonacci(int n);
int max_of_four_int(int a,int b,int c,int d);

#endif /* userprog/syscall.h */
