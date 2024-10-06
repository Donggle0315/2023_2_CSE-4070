#include "userprog/syscall.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "userprog/process.h"
#include "userprog/pagedir.h"
#include "threads/malloc.h"
#include "devices/input.h"
#include "threads/vaddr.h"
#include "devices/shutdown.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "vm/page.h"
#include "vm/frame.h"


static void syscall_handler (struct intr_frame *);
struct lock load_file_lock;

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init(&load_file_lock); //lock for file synchronization
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  //printf ("system call!\n");
  void *esp = f->esp; //stack pointer
  check_user_address((void*)esp); //check if it is user space
  uint32_t sys_num = *(uint32_t*)esp; //get syscall number
  
  switch(sys_num){
    /* proj #1 */
    case SYS_HALT:
      sys_halt();
      break;

    case SYS_EXIT:
      check_user_address((void*)esp+4);
      sys_exit(*(int*)(esp+4));
      break;

    case SYS_EXEC:
      check_user_address((void*)esp+4);
      check_valid_string((void*)esp+4);
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
      check_valid_buffer((void*)*(uint32_t*)(esp+8), (unsigned)*((uint32_t*)(esp+12)), false); //check the buffer is valid vaddr
      f->eax = sys_read((int)*(uint32_t*)(esp+4),(void*)*(uint32_t*)(esp+8),(unsigned)*(uint32_t*)(esp+12));
      break;

    case SYS_WRITE:
      check_user_address((void*)esp+4);
      check_user_address((void*)esp+8);
      check_user_address((void*)esp+12);
      check_valid_buffer((void*)*(uint32_t*)(esp+8), (unsigned)*((uint32_t*)(esp+12)), true); //check the buffer is valid vaddr
      f->eax = sys_write(*(uint32_t*)(esp+4),(void*)*(uint32_t*)(esp+8),(unsigned)*(uint32_t*)(esp+12));
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

    /* proj #2 */
    case SYS_CREATE:
      check_user_address((void*)esp+4);
      check_user_address((void*)esp+8);
      check_valid_string((void*)esp+4);
      f->eax = (uint32_t)sys_create((const char*)*(uint32_t*)(esp+4),(unsigned)*(uint32_t*)(esp+8));
      break;

    case SYS_REMOVE:
      check_user_address((void*)esp+4);
      check_valid_string((void*)esp+4);
      f->eax = (uint32_t)sys_remove((const char*)*(uint32_t*)(esp+4));
      break;

    case SYS_OPEN:
      check_user_address((void*)esp+4);
      check_valid_string((void*)esp+4);
      f->eax = (uint32_t)sys_open((const char*)*(uint32_t*)(esp+4));
      break;

    case SYS_CLOSE:
      check_user_address((void*)esp+4);
      sys_close((int)*(uint32_t*)(esp+4));
      break;

    case SYS_FILESIZE:
      check_user_address((void*)esp+4);
      check_valid_string((void*)esp+4);
      f->eax = (uint32_t)sys_filesize((int)*(uint32_t*)(esp+4));
      break;

    case SYS_SEEK:
      check_user_address((void*)esp+4);
      sys_seek((int)*(uint32_t*)(esp+4),(unsigned)*(uint32_t*)(esp+8));
      break;

    case SYS_TELL:
      check_user_address((void*)esp+4);
      f->eax = sys_tell((int)*(uint32_t*)(esp+4));
      break;
    
    /* proj #4 */
    case SYS_MMAP:
      check_user_address((void*)esp+4);
      check_user_address((void*)esp+8);
      check_valid_string((void*)esp+8);
      f->eax = mmap(*(uint32_t*)(esp+4), (void*)*(uint32_t*)(esp+8));
      break;
    
    case SYS_MUNMAP:
      check_user_address((void*)esp+4);
      munmap(*(uint32_t*)(esp+4));
      break;
  }
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

  /* close current thread's all open file descriptors */
  for(int i=2; i<128; i++){
    if(thread_current()->fd_list[i]){
      file_close(thread_current()->fd_list[i]);
      thread_current()->fd_list[i] = NULL;
    }
  }
  thread_exit();
}

//create child process to execute
tid_t sys_exec(const char *file_name){
  return process_execute(file_name);
}

//wait while child process finishes its work, returning child's exit status
int sys_wait(tid_t pid){
  return process_wait(pid);
}

int sys_read(int fd, void *buffer, unsigned size){
  unsigned offset = 0;
  lock_acquire(&load_file_lock); //lock for file sychronization

  if(!is_user_vaddr(buffer)) {
    lock_release(&load_file_lock);
    sys_exit(-1); //exception handling for read-bad-ptr
  }

  if(fd == 0){//STD_IN
    //read characters until null or < size
    while(offset < size){
      if(!input_getc()) break;
      offset++;
    }
    lock_release(&load_file_lock);
    return offset;
  }
  else if(2 <= fd && fd < 128){//FILE_IN
    struct file *cur_file = thread_current()->fd_list[fd];
    if(!cur_file) {
      lock_release(&load_file_lock);
      sys_exit(-1);
    }
    offset = file_read(cur_file,buffer,size);
    lock_release(&load_file_lock);
    return offset;
  }
  else{
    lock_release(&load_file_lock);
    return -1;
  }
}

int sys_write(int fd, const void *buffer, unsigned size){
  lock_acquire(&load_file_lock);

  if(fd == 1){//STD_OUT
    //write characters into buffer
    putbuf(buffer, size);
    lock_release(&load_file_lock);
    return size;
  }
  else if(2 <= fd && fd < 128){
    struct file *cur_file = thread_current()->fd_list[fd];
    if(!cur_file) {
      lock_release(&load_file_lock);
      sys_exit(-1);
    }
    //lock_acquire(&load_file_lock);
    int w_size = file_write(cur_file, buffer, size);
    lock_release(&load_file_lock);
    return w_size;
  }
  else{
    lock_release(&load_file_lock);
    return -1;//fail
  }
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

bool sys_create(const char *file, unsigned initial_size){
  if(!file) sys_exit(-1);
  lock_acquire(&load_file_lock);
  bool result = filesys_create(file, initial_size);
  lock_release(&load_file_lock);
  return result;
}

bool sys_remove(const char *file){
  if(!file) sys_exit(-1);
  lock_acquire(&load_file_lock);
  bool result = filesys_remove(file);
  lock_release(&load_file_lock);
  return result;
}

int sys_open(const char *filename){
  if(!filename) sys_exit(-1);

  lock_acquire(&load_file_lock);//synchronization for same file open
  struct file *open_file = filesys_open(filename);

  //no such file
  if(!open_file) {
    lock_release(&load_file_lock);
    return -1;
  }
  int empty_fd;
  for(empty_fd = 2; empty_fd < 128; empty_fd++){
    if(!thread_current()->fd_list[empty_fd]){
      if(!strcmp(thread_current()->name, filename)) file_deny_write(open_file);
      thread_current()->fd_list[empty_fd] = open_file;
      break;
    }
  }
  
  // no empty element in file descriptor
  lock_release(&load_file_lock);

  if(empty_fd == 128) return -1;
  
  return empty_fd;
}

void sys_close(int fd){
  struct file *cur_file = thread_current()->fd_list[fd];

  if(!cur_file) sys_exit(-1);

  file_close(cur_file);
  thread_current()->fd_list[fd] = NULL;
}

int sys_filesize(int fd){
  struct file *cur_file = thread_current()->fd_list[fd];
  if(!cur_file) sys_exit(-1);

  return (int)file_length(cur_file);
}

void sys_seek(int fd, unsigned position){
  struct file *cur_file = thread_current()->fd_list[fd];
  if(!cur_file) sys_exit(-1);

  file_seek(cur_file, position);
}

unsigned sys_tell(int fd){
  struct file *cur_file = thread_current()->fd_list[fd];
  if(!cur_file) sys_exit(-1);

  return file_tell(cur_file);
}

//mapping file with fd to virtual address which is sorted by page size
mapid_t mmap(int fd, void *addr) {
  struct thread *t = thread_current();

  if((fd == 0) || 
     (fd == 1) || 
     (addr == NULL) || 
     (pg_ofs(addr) % PGSIZE != 0) || 
     (t->fd_list[fd] == NULL)) return -1;//invalid conditions
  
  struct mmap_file *mmap_file_elem = (struct mmap_file*)malloc(sizeof(struct mmap_file));
  if (mmap_file_elem == NULL) return -1;

  mmap_file_elem->mapid = t->cur_mapid;//assign mapid
  (t->cur_mapid)++;
  mmap_file_elem->file = file_reopen(t->fd_list[fd]); //reopen and map file
  list_init(&mmap_file_elem->vm_entry_list);
  list_push_back(&t->mmap_list, &mmap_file_elem->elem);

  size_t read_bytes = file_length(mmap_file_elem->file);
  size_t zero_bytes = PGSIZE - read_bytes % PGSIZE;
  off_t ofs = 0;

  if(read_bytes <= 0) return -1; //file size is 0
  while(read_bytes > 0 || zero_bytes > 0) { //divide by page size
    //invalid conditions
    if(find_vm_entry(addr)) return -1;
    struct vm_entry *vm_entry_elem = (struct vm_entry*)malloc(sizeof(struct vm_entry));
    if(vm_entry_elem == NULL) return -1;

    size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
    size_t page_zero_bytes = PGSIZE - page_read_bytes;
    //set vm_entry variables and insert to hash table
    vm_entry_elem->type = VM_FILE;
    vm_entry_elem->vaddr = pg_round_down(addr);
    vm_entry_elem->writable = true;
    vm_entry_elem->is_loaded = false;
    vm_entry_elem->file = mmap_file_elem->file;
    vm_entry_elem->offset = ofs;
    vm_entry_elem->read_bytes = read_bytes;
    vm_entry_elem->zero_bytes = zero_bytes;
    insert_vm_page_table(&t->vm_page_table, vm_entry_elem);
    list_push_back(&mmap_file_elem->vm_entry_list, &vm_entry_elem->mmap_elem);

    //re-calculate file information
    read_bytes -= page_read_bytes;
    zero_bytes -= page_zero_bytes;
    ofs += page_read_bytes;
    addr += PGSIZE;
  }

  return mmap_file_elem->mapid;
}

//destory file mapping by using mapid
void munmap(mapid_t mapid) {
  struct thread *t = thread_current();
  //visit mmap list
  for(struct list_elem *cur = list_begin(&t->mmap_list);
      cur != list_end(&t->mmap_list);){
        struct mmap_file *mmap_file_elem = list_entry(cur,struct mmap_file, elem);
        if(mmap_file_elem == NULL) {
          cur = list_next(cur);
          continue;
        }
        if(mmap_file_elem->mapid == mapid) { //find target mapid
          //visit target mapid's vm_entries
          for(struct list_elem *cur_map = list_begin(&mmap_file_elem->vm_entry_list);
              cur_map != list_end(&mmap_file_elem->vm_entry_list);
              ){
                struct vm_entry *vm_entry_elem = list_entry(cur_map, struct vm_entry, mmap_elem);
                if(vm_entry_elem == NULL) {
                  cur_map = list_next(cur_map);
                  continue;
                }
                if(vm_entry_elem->is_loaded == false) {
                  cur_map = list_remove(&vm_entry_elem->mmap_elem);
                  continue;
                }
                void *paddr = pagedir_get_page(t->pagedir, vm_entry_elem->vaddr);
                //if dirty bit is 1, write data to file before destroying page
                if(pagedir_is_dirty(t->pagedir, vm_entry_elem->vaddr)){
                  lock_acquire(&load_file_lock);
                  file_write_at(vm_entry_elem->file, vm_entry_elem->vaddr, vm_entry_elem->read_bytes, vm_entry_elem->offset);
                  lock_release(&load_file_lock);
                }
                //destory page table entry
                free_page(paddr);
                cur_map = list_remove(&vm_entry_elem->mmap_elem);
              }
          //remove mmap_file
          if(mmap_file_elem->file != NULL) file_close(mmap_file_elem->file);
          cur = list_remove(&mmap_file_elem->elem);
          free(mmap_file_elem);
        }
        else{
          cur = list_next(cur);
        }
  }
}

//ummap all file mapping in current threads
void munmap_all() {
  struct thread *t = thread_current();
  for(struct list_elem *cur = list_begin(&t->mmap_list);
      cur != list_end(&t->mmap_list);){
        struct mmap_file *mmap_file_elem = list_entry(cur,struct mmap_file, elem);
        for(struct list_elem *cur_map = list_begin(&mmap_file_elem->vm_entry_list);
            cur_map != list_end(&mmap_file_elem->vm_entry_list);){
              struct vm_entry *vm_entry_elem = list_entry(cur_map, struct vm_entry, mmap_elem);
              if(vm_entry_elem == NULL || vm_entry_elem->is_loaded == false) {
                cur_map = list_remove(&vm_entry_elem->mmap_elem); 
                continue;
              }
              void *paddr = pagedir_get_page(t->pagedir, vm_entry_elem->vaddr);
              if(pagedir_is_dirty(t->pagedir, vm_entry_elem->vaddr)){
                lock_acquire(&load_file_lock);
                file_write_at(vm_entry_elem->file, vm_entry_elem->vaddr, vm_entry_elem->read_bytes, vm_entry_elem->offset);
                lock_release(&load_file_lock);
              }
              free_page(paddr);
              cur_map = list_remove(&vm_entry_elem->mmap_elem);
        }
        
        if(mmap_file_elem->file != NULL) file_close(mmap_file_elem->file);
        cur = list_remove(&mmap_file_elem->elem);
        free(mmap_file_elem);
  }
}

//write data in buffer to file with size from files's offset
void vm_file_write(struct file *file, void *kaddr, size_t read_bytes, size_t offset) {
  lock_acquire(&load_file_lock);
  file_write_at(file, kaddr, read_bytes, offset);
  lock_release(&load_file_lock);
}
