#ifndef VM_PAGE_H
#define VM_PAGE_H

#include "lib/kernel/hash.h"
#include "lib/kernel/list.h"
#include "threads/thread.h"
#include "filesys/file.h"
#include "vm/page.h"

#define VM_BIN      0 //load data from binary file
#define VM_FILE     1 //load data from mapped file
#define VM_ANON     2 //load data from swap area

//one vm_entry per one page.
//store information of page, assigned when first loaded on program.
struct vm_entry {
    uint8_t type; //VM_BIN, VM_FILE, VM_ANON type
    void *vaddr; //virtual page number managed by vm_entry
    bool writable; //can write on its address

    bool is_loaded; //is loaded on physical memory
    struct file* file; //file mapped to virtual address

    struct list_elem mmap_elem; //element of a mmap list

    size_t offset; //file offset to read
    size_t read_bytes; //data size writen in virtual page
    size_t zero_bytes; //left bytes size of page with 0

    size_t swap_slot; //swap slot in swapping
    struct hash_elem elem; //element of hash table
};

struct mmap_file {
    int mapid; //mapping id which mmap() returns
    struct file *file; //mapping file object
    struct list vm_entry_list; //all vm_entries relevant to mmap file
    struct list_elem elem; //struct for chaining mmap files
};

struct page {
    void *kaddr; //page's physical address
    struct vm_entry *vm_entry; //vm_entry pointer mapped with kaddr
    struct thread *thread; //thread pointer which uses kaddr
    struct list_elem lru; //field for chaining
};



void init_vm_page_table (struct hash *vm_page_table);
unsigned vm_page_table_hash_func (const struct hash_elem *e, void *aux);
bool vm_page_table_less_func (const struct hash_elem *a, const struct hash_elem *b, void *aux UNUSED);
bool insert_vm_page_table (struct hash *vm_page_table, struct vm_entry *vm_page_table_entry);
bool delete_vm_page_table (struct hash *vm_page_table, struct vm_entry *vm_page_talbe_entry);
struct vm_entry *find_vm_entry (const void *vaddr);
void destroy_vm_page_table (struct hash *vm_page_table);
void vm_page_destroy (struct hash_elem *e, void *aux);
void check_valid_string(const void *str);
void check_valid_buffer(void *buffer, unsigned size, bool write);
bool load_file(void *paddr, struct vm_entry *vm_entry_elem);

#endif