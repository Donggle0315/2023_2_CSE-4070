#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/tss.h"
#include "userprog/syscall.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/malloc.h"
#include "vm/page.h"
#include "vm/frame.h"
#include "vm/swap.h"

static thread_func start_process NO_RETURN;
static bool load (const char *cmdline, void (**eip) (void), void **esp);
static void parseAndInsertArgumentIntoStack(const char *file_name, void **esp);
bool findLoadFailedEntry(struct thread* current);
bool handle_mm_fault(struct vm_entry *vm_entry_elem);

/* Starts a new thread running a user program loaded from
   FILENAME.  The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   thread id, or TID_ERROR if the thread cannot be created. */
tid_t
process_execute (const char *file_name) 
{
  char *fn_copy;
  tid_t tid;

  /* Make a copy of FILE_NAME.
     Otherwise there's a race between the caller and load(). */
  fn_copy = palloc_get_page (0);
  
  char command_title[128];
  int idx = 0;
  strlcpy(command_title, file_name, strlen(file_name)+1);

  /* store file_name[0] in command_title and check if a open file is a valid file */
  while((command_title[idx] != ' ') && command_title[idx]){
    idx++;
  }
  command_title[idx] = 0;

  if(filesys_open(command_title)==NULL){
    //invalid file return NULL -> exit(-1)
		return -1;
	}

  if (fn_copy == NULL){
    return TID_ERROR;
  }
  strlcpy (fn_copy, file_name, PGSIZE);

  /* Create a new thread to execute FILE_NAME. */
  tid = thread_create (command_title, PRI_DEFAULT, start_process, fn_copy);
  
  //complete load child thread. ready to load another loading
  sema_down(&(thread_current()->load_sema));
  
  if (tid == TID_ERROR){
    palloc_free_page (fn_copy); 
  }


  //if load fail child exist, then wait for it
  if(findLoadFailedEntry(thread_current())){
    return process_wait(tid);
  }

  return tid;
}

bool findLoadFailedEntry(struct thread* current){
  for(struct list_elem *cur = list_begin(&(current->child_process));
      cur != list_end(&(current->child_process));
      cur = list_next(cur)){
        struct thread * cur_thread = list_entry(cur, struct thread, child_process_element);
        if(!cur_thread->is_loaded){
          return true;
        }
      }
  return false;
}

/* A thread function that loads a user process and starts it
   running. */
static void
start_process (void *file_name_)
{
  char *file_name = file_name_;
  struct intr_frame if_;
  bool success;

  /* proj #4 */
  //initialize hash table to store vm_entries
  init_vm_page_table(&thread_current()->vm_page_table);
  /* Initialize interrupt frame and load executable. */
  memset (&if_, 0, sizeof if_);
  if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
  if_.cs = SEL_UCSEG;
  if_.eflags = FLAG_IF | FLAG_MBS;
    
  success = load (file_name, &if_.eip, &if_.esp);

  //notice that loading is complete to parent process
  sema_up(&(thread_current()->parent->load_sema));

  /* If load failed, quit. */ 
  palloc_free_page (file_name);
  if (!success) {
    thread_current()->is_loaded = false;
    //thread_exit ();
    sys_exit(-1); //reaped by parent waiting function
  }
  
  /* Start the user process by simulating a return from an
     interrupt, implemented by intr_exit (in
     threads/intr-stubs.S).  Because intr_exit takes all of its
     arguments on the stack in the form of a `struct intr_frame',
     we just point the stack pointer (%esp) to our stack frame
     and jump to it. */
  asm volatile ("movl %0, %%esp; jmp intr_exit" : : "g" (&if_) : "memory");
  NOT_REACHED ();
}

/* Waits for thread TID to die and returns its exit status.  If
   it was terminated by the kernel (i.e. killed due to an
   exception), returns -1.  If TID is invalid or if it was not a
   child of the calling process, or if process_wait() has already
   been successfully called for the given TID, returns -1
   immediately, without waiting.

   This function will be implemented in problem 2-2.  For now, it
   does nothing. */
int
process_wait (tid_t child_tid UNUSED) 
{
  //temporaly infinite loop to remain waiting
  // while(1){
    
  // }

  if(child_tid == TID_ERROR) {
    return -1;
  }
  for(struct list_elem *cur = list_begin(&(thread_current()->child_process));
      cur != list_end(&(thread_current()->child_process));
      cur = list_next(cur)){
        struct thread *cur_thread = list_entry(cur, struct thread, child_process_element);
        if(cur_thread->tid == child_tid){
          sema_down(&(cur_thread->child_exit_sema));
          list_remove(&(cur_thread->child_process_element));
          sema_up(&(cur_thread->child_wait_sema));

          return cur_thread->exit_status;
        }
  }
  return -1;
}

/* Free the current process's resources. */
void
process_exit (void)
{
  struct thread *cur = thread_current ();
  uint32_t *pd;

  /* proj #4 */
  munmap_all(); //destory all file mapping before thread_exit
  destroy_vm_page_table(&cur->vm_page_table); //destory hash table and vm_entries

  /* Destroy the current process's page directory and switch back
     to the kernel-only page directory. */
  pd = cur->pagedir;
  if (pd != NULL) 
    {
      /* Correct ordering here is crucial.  We must set
         cur->pagedir to NULL before switching page directories,
         so that a timer interrupt can't switch back to the
         process page directory.  We must activate the base page
         directory before destroying the process's page
         directory, or our active page directory will be one
         that's been freed (and cleared). */
      cur->pagedir = NULL;
      pagedir_activate (NULL);
      pagedir_destroy (pd);
    }
  /* notice that child process is dead to parent process */
  sema_up(&(cur->child_exit_sema));
  /* notice that it is ready to access(write) parent's child list */
  sema_down(&(cur->child_wait_sema));
  //debug_backtrace_all();
}

/* Sets up the CPU for running user code in the current
   thread.
   This function is called on every context switch. */
void
process_activate (void)
{
  struct thread *t = thread_current ();

  /* Activate thread's page tables. */
  pagedir_activate (t->pagedir);

  /* Set thread's kernel stack for use in processing
     interrupts. */
  tss_update ();
}

/* We load ELF binaries.  The following definitions are taken
   from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
typedef uint16_t Elf32_Half;

/* For use with ELF types in printf(). */
#define PE32Wx PRIx32   /* Print Elf32_Word in hexadecimal. */
#define PE32Ax PRIx32   /* Print Elf32_Addr in hexadecimal. */
#define PE32Ox PRIx32   /* Print Elf32_Off in hexadecimal. */
#define PE32Hx PRIx16   /* Print Elf32_Half in hexadecimal. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
   This appears at the very beginning of an ELF binary. */
struct Elf32_Ehdr
  {
    unsigned char e_ident[16];
    Elf32_Half    e_type;
    Elf32_Half    e_machine;
    Elf32_Word    e_version;
    Elf32_Addr    e_entry;
    Elf32_Off     e_phoff;
    Elf32_Off     e_shoff;
    Elf32_Word    e_flags;
    Elf32_Half    e_ehsize;
    Elf32_Half    e_phentsize;
    Elf32_Half    e_phnum;
    Elf32_Half    e_shentsize;
    Elf32_Half    e_shnum;
    Elf32_Half    e_shstrndx;
  };

/* Program header.  See [ELF1] 2-2 to 2-4.
   There are e_phnum of these, starting at file offset e_phoff
   (see [ELF1] 1-6). */
struct Elf32_Phdr
  {
    Elf32_Word p_type;
    Elf32_Off  p_offset;
    Elf32_Addr p_vaddr;
    Elf32_Addr p_paddr;
    Elf32_Word p_filesz;
    Elf32_Word p_memsz;
    Elf32_Word p_flags;
    Elf32_Word p_align;
  };

/* Values for p_type.  See [ELF1] 2-3. */
#define PT_NULL    0            /* Ignore. */
#define PT_LOAD    1            /* Loadable segment. */
#define PT_DYNAMIC 2            /* Dynamic linking info. */
#define PT_INTERP  3            /* Name of dynamic loader. */
#define PT_NOTE    4            /* Auxiliary info. */
#define PT_SHLIB   5            /* Reserved. */
#define PT_PHDR    6            /* Program header table. */
#define PT_STACK   0x6474e551   /* Stack segment. */

/* Flags for p_flags.  See [ELF3] 2-3 and 2-4. */
#define PF_X 1          /* Executable. */
#define PF_W 2          /* Writable. */
#define PF_R 4          /* Readable. */

static bool setup_stack (void **esp);
static bool validate_segment (const struct Elf32_Phdr *, struct file *);
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
                          uint32_t read_bytes, uint32_t zero_bytes,
                          bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */
bool
load (const char *file_name, void (**eip) (void), void **esp) 
{
  struct thread *t = thread_current ();
  struct Elf32_Ehdr ehdr;
  struct file *file = NULL;
  off_t file_ofs;
  bool success = false;
  int i;
  
  /* Allocate and activate page directory. */
  t->pagedir = pagedir_create ();
  if (t->pagedir == NULL) 
    goto done;
  process_activate ();

  /* store file_name[0] in command_title */
  char command_title[64];
  int idx = 0;
  strlcpy(command_title, file_name, strlen(file_name)+1);
  while(command_title[idx] != ' ' && command_title[idx]){
    idx++;
  }
  command_title[idx] = 0;


  /* Open executable file. */
  file = filesys_open(command_title);
  if (file == NULL) 
    {
      printf ("load: %s: open failed\n", file_name);
      goto done; 
    }

  /* Read and verify executable header. */
  if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr
      || memcmp (ehdr.e_ident, "\177ELF\1\1\1", 7)
      || ehdr.e_type != 2
      || ehdr.e_machine != 3
      || ehdr.e_version != 1
      || ehdr.e_phentsize != sizeof (struct Elf32_Phdr)
      || ehdr.e_phnum > 1024) 
    {
      printf ("load: %s: error loading executable\n", file_name);
      goto done; 
    }

  /* Read program headers. */
  file_ofs = ehdr.e_phoff;
  for (i = 0; i < ehdr.e_phnum; i++) 
    {
      struct Elf32_Phdr phdr;

      if (file_ofs < 0 || file_ofs > file_length (file))
        goto done;
      file_seek (file, file_ofs);

      if (file_read (file, &phdr, sizeof phdr) != sizeof phdr)
        goto done;
      file_ofs += sizeof phdr;
      switch (phdr.p_type) 
        {
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
          if (validate_segment (&phdr, file)) 
            {
              bool writable = (phdr.p_flags & PF_W) != 0;
              uint32_t file_page = phdr.p_offset & ~PGMASK;
              uint32_t mem_page = phdr.p_vaddr & ~PGMASK;
              uint32_t page_offset = phdr.p_vaddr & PGMASK;
              uint32_t read_bytes, zero_bytes;
              if (phdr.p_filesz > 0)
                {
                  /* Normal segment.
                     Read initial part from disk and zero the rest. */
                  read_bytes = page_offset + phdr.p_filesz;
                  zero_bytes = (ROUND_UP (page_offset + phdr.p_memsz, PGSIZE)
                                - read_bytes);
                }
              else 
                {
                  /* Entirely zero.
                     Don't read anything from disk. */
                  read_bytes = 0;
                  zero_bytes = ROUND_UP (page_offset + phdr.p_memsz, PGSIZE);
                }
              if (!load_segment (file, file_page, (void *) mem_page,
                                 read_bytes, zero_bytes, writable))
                goto done;
            }
          else
            goto done;
          break;
        }
    }

  /* Set up stack. */
  if (!setup_stack (esp)) 
    goto done;
  
  /* Start address. */
  *eip = (void (*) (void)) ehdr.e_entry;

  /* parse argument and pass argument into stack */
  parseAndInsertArgumentIntoStack(file_name, esp);
  
  success = true;

 done:
  /* We arrive here whether the load is successful or not. */
  file_close (file);
  return success;
}

/* load() helpers. */

static bool install_page (void *upage, void *kpage, bool writable);

/* Checks whether PHDR describes a valid, loadable segment in
   FILE and returns true if so, false otherwise. */
static bool
validate_segment (const struct Elf32_Phdr *phdr, struct file *file) 
{
  /* p_offset and p_vaddr must have the same page offset. */
  if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK)) 
    return false; 

  /* p_offset must point within FILE. */
  if (phdr->p_offset > (Elf32_Off) file_length (file)) 
    return false;

  /* p_memsz must be at least as big as p_filesz. */
  if (phdr->p_memsz < phdr->p_filesz) 
    return false; 

  /* The segment must not be empty. */
  if (phdr->p_memsz == 0)
    return false;
  
  /* The virtual memory region must both start and end within the
     user address space range. */
  if (!is_user_vaddr ((void *) phdr->p_vaddr))
    return false;
  if (!is_user_vaddr ((void *) (phdr->p_vaddr + phdr->p_memsz)))
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

/* Loads a segment starting at offset OFS in FILE at address
   UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
   memory are initialized, as follows:

        - READ_BYTES bytes at UPAGE must be read from FILE
          starting at offset OFS.

        - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.

   The pages initialized by this function must be writable by the
   user process if WRITABLE is true, read-only otherwise.

   Return true if successful, false if a memory allocation error
   or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
              uint32_t read_bytes, uint32_t zero_bytes, bool writable) 
{
  struct file *re_file = file_reopen(file);
  ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
  ASSERT (pg_ofs (upage) == 0);
  ASSERT (ofs % PGSIZE == 0);

  file_seek (file, ofs);
  while (read_bytes > 0 || zero_bytes > 0) 
    {
      /* Calculate how to fill this page.
         We will read PAGE_READ_BYTES bytes from FILE
         and zero the final PAGE_ZERO_BYTES bytes. */
      size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
      size_t page_zero_bytes = PGSIZE - page_read_bytes;

      /* delete part of loading memory on the process's vitual address space for proj #4 */
      // /* Get a page of memory. */
      // uint8_t *kpage = palloc_get_page (PAL_USER);
      // if (kpage == NULL)
      //   return false;

      // /* Load this page. */
      // if (file_read (file, kpage, page_read_bytes) != (int) page_read_bytes)
      //   {
      //     palloc_free_page (kpage);
      //     return false; 
      //   }
      // memset (kpage + page_read_bytes, 0, page_zero_bytes);

      // /* Add the page to the process's address space. */
      // if (!install_page (upage, kpage, writable)) 
      //   {
      //     palloc_free_page (kpage);
      //     return false; 
      //   }

      /* proj #4 */
      /* assign vm_entry, initialze field value, insert hash table */
      struct vm_entry *vm_entry_elem = (struct vm_entry *)malloc(sizeof(struct vm_entry));
      if(vm_entry_elem == NULL) return false;

      vm_entry_elem->type = VM_BIN; //binary data
      vm_entry_elem->vaddr = pg_round_down(upage); //get VPN
      vm_entry_elem->writable = writable; 
      vm_entry_elem->is_loaded = false; //not loaded on memory yet
      vm_entry_elem->file = re_file;
      vm_entry_elem->offset = ofs;
      vm_entry_elem->read_bytes = page_read_bytes;
      vm_entry_elem->zero_bytes = page_zero_bytes;
      
      if(insert_vm_page_table(&thread_current()->vm_page_table, vm_entry_elem) == false) return false;
      
      /* Advance. */
      read_bytes -= page_read_bytes;
      zero_bytes -= page_zero_bytes;
      ofs += page_read_bytes;
      upage += PGSIZE;
    }
  return true;
}

/* Create a minimal stack by mapping a zeroed page at the top of
   user virtual memory. */
static bool
setup_stack (void **esp) 
{
  struct page *kpage;
  bool success = false;
  kpage = alloc_page (PAL_USER | PAL_ZERO);
  

  if (kpage != NULL) 
    {
      success = install_page (pg_round_down(((uint8_t *) PHYS_BASE) - PGSIZE), kpage->kaddr, true);
      if (success) {
        *esp = PHYS_BASE;
      }
      else{
        //palloc_free_page (kpage);
        free_page(kpage->kaddr);
        return false;
      }
    }
  /* proj #4 */
  /* assign vm_entry, initialze field value, insert hash table */
  struct vm_entry* vm_entry_elem = (struct vm_entry*)malloc(sizeof(struct vm_entry));
  if(vm_entry_elem == NULL) {
    free_page(kpage->kaddr);
    return false;
  }
  vm_entry_elem->type = VM_ANON;
  vm_entry_elem->vaddr = pg_round_down(((uint8_t *)PHYS_BASE) - PGSIZE);
  vm_entry_elem->is_loaded = true;
  vm_entry_elem->writable = true;
  kpage->vm_entry = vm_entry_elem;

  success = insert_vm_page_table(&thread_current()->vm_page_table, vm_entry_elem);

  return success;
}

/* Adds a mapping from user virtual address UPAGE to kernel
   virtual address KPAGE to the page table.
   If WRITABLE is true, the user process may modify the page;
   otherwise, it is read-only.
   UPAGE must not already be mapped.
   KPAGE should probably be a page obtained from the user pool
   with palloc_get_page().
   Returns true on success, false if UPAGE is already mapped or
   if memory allocation fails. */
static bool
install_page (void *upage, void *kpage, bool writable)
{
  struct thread *t = thread_current ();

  /* Verify that there's not already a page at that virtual
     address, then map our page there. */
  return (pagedir_get_page (t->pagedir, upage) == NULL
          && pagedir_set_page (t->pagedir, upage, kpage, writable));
}

static void parseAndInsertArgumentIntoStack(const char* file_name, void** esp){
  /* parse file name */
  int argument_num = 0;
  int argument_idx = 0;
  int file_idx = 0;
  char parsed_command[24][64];
 
  //remove heading blank
  while(file_name[file_idx] && file_name[file_idx] == ' '){
    file_idx++;
  }
  //parsing file_name into parsed command
  while(1){
    if((file_name[file_idx] == ' ' || !file_name[file_idx]) && file_name[file_idx-1] != ' '){
      parsed_command[argument_num][argument_idx++] = 0;
      argument_num++;
      argument_idx = 0;
    }
    else if(file_name[file_idx] != ' '){
      parsed_command[argument_num][argument_idx++] = file_name[file_idx];
    }
    
    if(!file_name[file_idx]) break;

    file_idx++;
  }
  
  parsed_command[argument_num][0] = '\0';

  /* passing arguments into the stack */

  //pass arguments
  int len = 0;
  uint32_t addr_list[30]; //store argument's address in the stack
  for(int i = argument_num-1; i>=0; i--){
    len += (strlen(parsed_command[i])+1);
    for(int j=strlen(parsed_command[i]); j>=0; j--){
      *esp = *esp -1;
      **(char **)esp = parsed_command[i][j];
      
    }
    addr_list[argument_num-1-i] = (uint32_t)*esp;
  }

  // word alignment
  if(len%4){
    *esp -= (4-(len%4));
  }

  //pass addresses of arguments
  *esp -= 4;
  **(uint32_t**)esp = 0;
  for(int i = 0; i<argument_num; i++){
    *esp = *esp -4;
    **(uint32_t**)esp = (uint32_t)addr_list[i];
  }

  //pass address of addresses of arguments
  *esp -= 4;
  **(uint32_t**)esp = *(uint32_t*)esp+4;

  //pass argument_num(int)
  *esp -= 4;
  **(uint32_t**)esp = (uint32_t)argument_num;
  
  //pass fake return address
  *esp -= 4;
  **(uint32_t**)esp = 0;
  
  //hex_dump(*esp, *esp, 100, true);
}

bool handle_mm_fault(struct vm_entry *vm_entry_elem) {
  //vm_entry is none or not loaded
  if (vm_entry_elem == NULL) return false;
  if (vm_entry_elem->is_loaded == true) return false;

  //allocate page
  struct page *new_page = alloc_page(PAL_USER);
  if (new_page == NULL) return false;
  if (new_page->kaddr == NULL) return false;
  new_page->vm_entry = vm_entry_elem;

  switch (vm_entry_elem->type) {
    case VM_BIN:
      if (load_file(new_page->kaddr, vm_entry_elem) == false) { //load data from file to physical memory
        free_page(new_page->kaddr);
        return false;
      }
      break;
    case VM_FILE:
      if (load_file(new_page->kaddr, vm_entry_elem) == false) {//load data from file to physical memory
        free_page(new_page->kaddr);
        return false;
      }
      break;      
    case VM_ANON:
      swap_in(vm_entry_elem->swap_slot, new_page->kaddr); //swapping from swap space to physical memory
      break;
    default:
      return false;
      break;
  }

  //mapping virtual page to physical page
  if(install_page(vm_entry_elem->vaddr, new_page->kaddr, vm_entry_elem->writable)) {
    vm_entry_elem->is_loaded = true; //complete to load
    return true;
  }
  else {
    free_page(new_page->kaddr);
    return false;
  }
}

//expand stack area
bool expand_stack (void *addr) {
  struct page *page_elem = alloc_page(PAL_USER);
  if (page_elem == NULL) return false;
  struct vm_entry *vm_entry_elem = (struct vm_entry*)malloc(sizeof(struct vm_entry));
  if(vm_entry_elem == NULL) return false;

  vm_entry_elem->type = VM_ANON;
  vm_entry_elem->vaddr = pg_round_down(addr);
  vm_entry_elem->is_loaded = true;
  vm_entry_elem->writable = true;
  page_elem->vm_entry = vm_entry_elem;

  if(insert_vm_page_table(&thread_current()->vm_page_table, vm_entry_elem) &&
     install_page(vm_entry_elem->vaddr, page_elem->kaddr, vm_entry_elem->writable)) {
      return true;
  }
  else{
    free_page(page_elem->kaddr);
    free(vm_entry_elem);
    return false;
  }
}
//check if the stack can grow or not
bool verify_stack (void *sp, void **esp) {
  unsigned size_8_mb = 1<<23;
  int stack_limit_range = 32;
  if((unsigned)esp - (unsigned)sp > stack_limit_range) return false; //if the difference btw stack pointer and access address is more than 32 bits
  if(PHYS_BASE - pg_round_down(sp) > size_8_mb) return false;//if grow limit is more than 1MB
  return true;
}