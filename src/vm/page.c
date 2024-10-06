#include "vm/page.h"
#include "vm/frame.h"
#include "userprog/syscall.h"
#include "userprog/pagedir.h"
#include <string.h>
#include "lib/kernel/list.h"
#include "threads/malloc.h"
#include "userprog/pagedir.h"
#include "threads/vaddr.h"
#include "filesys/file.h"


void init_vm_page_table (struct hash *vm_page_table) {
    //initailize hash table. called in start_process when a new thread creates.
    hash_init(vm_page_table, vm_page_table_hash_func, vm_page_table_less_func, NULL);
}

unsigned vm_page_table_hash_func (const struct hash_elem *e, void *aux) {
    //find hash value of vm_entry->vaddr
    struct vm_entry *vm_entry_elem = hash_entry(e, struct vm_entry, elem);
    return hash_int((int)vm_entry_elem->vaddr);
}

bool vm_page_table_less_func (const struct hash_elem *a, const struct hash_elem *b, void *aux UNUSED) {
    //sort hash elements by vaddr
    return hash_entry(a, struct vm_entry, elem)->vaddr < hash_entry(b, struct vm_entry, elem)->vaddr;
}

bool insert_vm_page_table (struct hash *vm_page_table, struct vm_entry *vm_page_table_entry) {
    //insert vm_entry into the hash table
    if(hash_insert(vm_page_table, &vm_page_table_entry->elem) != NULL) {
        return false;
    }
    return true;
}

bool delete_vm_page_table (struct hash *vm_page_table, struct vm_entry *vm_page_table_entry) {
    //delete vm_entry from the hash table
    if(hash_delete(vm_page_table, &vm_page_table_entry->elem) != NULL) {
        free(vm_page_table_entry);
        return true;
    }
    return false;
}

struct vm_entry *find_vm_entry (const void *vaddr) {
    //find vm_entry from hash_table with vaddr
    struct vm_entry vm_entry_elem;
    vm_entry_elem.vaddr = pg_round_down(vaddr);//get virtual page number of virtual address
    struct hash_elem *vm_hash_elem = hash_find(&thread_current()->vm_page_table, &vm_entry_elem.elem);
    if(vm_hash_elem != NULL) {//success to find
        return hash_entry(vm_hash_elem, struct vm_entry, elem);
    }
    return NULL;//fail to find
}

void destroy_vm_page_table (struct hash *vm_page_table) {
    //free hash table
    hash_destroy(vm_page_table, vm_page_destroy);
}

void vm_page_destroy (struct hash_elem *e, void *aux) {
    //destroy bucket lists of hash table and vm_entries
    struct vm_entry *vm_entry_elem = hash_entry(e, struct vm_entry, elem);
    if(vm_entry_elem->is_loaded) {
        free_page(pagedir_get_page(thread_current()->pagedir, vm_entry_elem->vaddr));
    }
    free(vm_entry_elem);
}

//check if the string's address is valid virtual address
void check_valid_string(const void *str) {
    int size = strlen(str);
    for (int i = 0; i < size; i++) {
        if(is_user_vaddr(str+i) == false) sys_exit(-1); //kernel vaddr
        if(find_vm_entry(str+i) == NULL) sys_exit(-1); //check if the vm_entry of vaddr is existed
    }
}

//check if the buffer's address is valid virtual address
void check_valid_buffer(void *buffer, unsigned size, bool write) {
    for(int i = 0; i < (int)size; i++) {
        if(is_user_vaddr(buffer+i) == false) sys_exit(-1);//kernel vaddr
        if(find_vm_entry(buffer+i) == NULL) sys_exit(-1); //check if the vm_entry of vaddr is existed
        if((!write == true) && (find_vm_entry(buffer+i)->writable == false)) sys_exit(-1); //check if writing is performed on the writeable address.
    }
}

//load a page from disk to physical memory
bool load_file(void *kaddr, struct vm_entry *vm_entry_elem) {
    if(file_read_at(vm_entry_elem->file, kaddr, vm_entry_elem->read_bytes, vm_entry_elem->offset) == (int)vm_entry_elem->read_bytes) { //read data on physical memory
        memset(kaddr + vm_entry_elem->read_bytes, 0, vm_entry_elem->zero_bytes); //fill with 0 in non-written area.
        return true;
    }
    return false;
}