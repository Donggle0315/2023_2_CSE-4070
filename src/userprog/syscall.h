#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include "threads/thread.h"
#include "lib/user/syscall.h"

/* define prototype of initializing syscall */
void syscall_init (void);

/* define prototype of checking valid user's virtual address space */
void check_user_address(void* esp);

/* define prototype of system call implementation */
/* proj #1 */
void sys_halt(void);
void sys_exit(int status);
tid_t sys_exec(const char *file_name);
int sys_wait(tid_t pid);
int sys_read(int fd, void *buffer, unsigned size);
int sys_write(int fd, const void *buffer, unsigned size);
int fibonacci(int n);
int max_of_four_int(int a,int b,int c,int d);
/* proj #2 */
bool sys_create(const char *filename, unsigned filesize);
bool sys_remove(const char *filename);
int sys_open(const char *filename);
void sys_close(int fd);
int sys_filesize(int fd);
void sys_seek(int fd, unsigned offset);
unsigned sys_tell(int fd);
/* proj #4 */
mapid_t mmap(int fd, void *addr);
void munmap(mapid_t mapid);
void munmap_all(void);
void vm_file_write(struct file *file, void *kaddr, size_t read_bytes, size_t offset);


#endif /* userprog/syscall.h */
