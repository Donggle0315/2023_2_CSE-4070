#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "userprog/process.h"
#include "devices/input.h"
#include "threads/vaddr.h"
#include "devices/shutdown.h"

static void syscall_handler (struct intr_frame *);
// void check_user_address(void* esp);
// void sys_halt(void);
// void sys_exit(int status);
// pid_t sys_exec(const char *file_name);
// int sys_wait(pid_t pid);
// int sys_read(int fd, void *buffer, unsigned size);
// int sys_write(int fd, const void *buffer, unsigned size);


void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  //printf ("system call!\n");
  void *esp = f->esp; //stack pointer
  check_user_address((void*)esp); //check if it is user space
  uint32_t sys_num = *(uint32_t*)esp; //스택에서 syscall number 찾는 걸로 바꿔야 함

  switch(sys_num){
    case SYS_HALT:
      sys_halt();
      break;
    case SYS_EXIT:
      check_user_address((void*)esp+4);
      sys_exit(*(int*)(esp+4));
      break;
    case SYS_EXEC:
      check_user_address((void*)esp+4);
      f->eax = (uint32_t)sys_exec((const char*)*(uint32_t*)(esp+4));
      break;
    case SYS_WAIT:
      check_user_address((void*)esp+4);
      f->eax = (uint32_t)sys_wait((tid_t)*(uint32_t*)(esp+4));
      break;
    case SYS_READ:
      check_user_address((void*)esp+4);
      check_user_address((void*)esp+8);
      check_user_address((void*)esp+12);
      f->eax = (uint32_t)sys_read((int)*(uint32_t*)(esp+4),(void*)*(uint32_t*)(esp+8),(unsigned)*(uint32_t*)(esp+12));
      break;
    case SYS_WRITE:
      check_user_address((void*)esp+4);
      check_user_address((void*)esp+8);
      check_user_address((void*)esp+12);
      f->eax = (uint32_t)sys_write(*(uint32_t*)(esp+4),(void*)*(uint32_t*)(esp+8),(unsigned)*(uint32_t*)(esp+12));
      break;
    case SYS_FIBONACCI:
      check_user_address((void*)esp+4);
      f->eax = (uint32_t)fibonacci((int)*(uint32_t*)(esp+4));
      break;
    case SYS_MAX_OF_FOUR_INT:
      check_user_address((void*)esp+4);
      check_user_address((void*)esp+8);
      check_user_address((void*)esp+12);
      check_user_address((void*)esp+16);
      f->eax = (uint32_t)max_of_four_int((int)*(uint32_t*)(esp+4),(int)*(uint32_t*)(esp+8),(int)*(uint32_t*)(esp+12),(int)*(uint32_t*)(esp+16));
      break;

  }

  //thread_exit ();
}

void check_user_address(void *addr){
  if(!is_user_vaddr(addr)){
    sys_exit(-1);
  }
}

void sys_halt(){
  //terminate Pintos
  shutdown_power_off();
}

void sys_exit(int status){
  //terminate the current user program, storing exit status
  printf("%s: exit(%d)\n",thread_name(), status);
  thread_current() -> exit_status = status;
  thread_exit();
}

tid_t sys_exec(const char *file_name){
  //create child process to execute
  return process_execute(file_name);
}

int sys_wait(tid_t pid){
  //wait while child process finishes its work, returning child's exit status
  return process_wait(pid);
}

int sys_read(int fd, void *buffer, unsigned size){
  //STD_IN
  if(fd == 0){
    unsigned offset = 0;
    //read characters until null or < size
    while(offset < size){
      if(!input_getc()) break;
      offset++;
    }
    return offset;
  }
  return -1;//fail
}

int sys_write(int fd, const void *buffer, unsigned size){
  //STD_OUT
  if(fd == 1){
    //write characters into buffer
    putbuf(buffer, size);
    return size;
  }
  return -1;//fail
}

int fibonacci(int n){
  //return fibonacci number of integer n
  if(n < 0) return 0;
  if(n <= 0) return n;

  int a = 0;
  int b = 1;
  int c = 0;

  for(int i=2; i<=n; i++){
    c = a + b;
    a = b;
    b = c;
  }

  return c;
}

int max_of_four_int(int a, int b, int c, int d){
  //return maximum number
  int ans = a;
  ans = (ans < b) ? b : ans;
  ans = (ans < c) ? c : ans;
  ans = (ans < d) ? d : ans;
  return ans;
}