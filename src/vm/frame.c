#include "vm/frame.h"
#include "threads/palloc.h"
#include "threads/malloc.h"

//initialize LRU algorithm related data structure
void lru_list_init(void) {
    list_init(&lru_list);
    lock_init(&lru_list_lock);
    lru_clock = NULL;
}

//insert user page to tail of LRU list
void add_page_to_lru_list(struct page* page) {
    if(page == NULL) return;
    lock_acquire(&lru_list_lock);
    list_push_back(&lru_list, &page->lru);
    lock_release(&lru_list_lock);

}

//delete user page from LRU list
void del_page_from_lru_list(struct page* page) {
    if(page == NULL) return;
    list_remove(&page->lru);
}

//allocate user page
struct page *alloc_page(enum palloc_flags flags) {
    void *addr = palloc_get_page(flags);//allocate physical page

    while(addr == NULL) {//if the physical memory is full
        evict_page_lru_policy(); //evict a page in physical memory by using second chance algorithm
        addr = palloc_get_page(flags); //re-allocate physical page
    }

    //assign and initialize page
    struct page *page = (struct page*) malloc(sizeof(struct page));
    if(page == NULL) sys_exit(-1);
    page->kaddr = addr;
    page->thread = thread_current();
    page->vm_entry = NULL;

    add_page_to_lru_list(page);

    return page;
}

void free_page(void *kaddr) {
    lock_acquire(&lru_list_lock);
    //visit lru list to find a page with kaddr
    for(struct list_elem *cur = list_begin(&lru_list);
        cur != list_end(&lru_list);
        cur = list_next(cur)){
            struct page *cur_page = list_entry(cur, struct page, lru);
            if(cur_page->kaddr == kaddr) { //find a target page -> destroy it
                pagedir_clear_page(cur_page->thread->pagedir, cur_page->vm_entry->vaddr);
                palloc_free_page(cur_page->kaddr);
                del_page_from_lru_list(cur_page);
                free(cur_page);
                break;                
            }
        }
    lock_release(&lru_list_lock);
}

void evict_page_lru_policy() {
    struct page *target_page = NULL;
    struct list_elem *cur_page = NULL;

    while(1) {
        lock_acquire(&lru_list_lock);
        lru_clock = get_lru_clock(cur_page); // find clock hands for checking eviction
        if (lru_clock == NULL) {
            lock_release(&lru_list_lock);   
            return;
        }
        target_page = list_entry(lru_clock, struct page, lru); //get target page
        lock_release(&lru_list_lock);

        if (pagedir_is_accessed(target_page->thread->pagedir, target_page->vm_entry->vaddr)) { //access bit is 1
            pagedir_set_accessed(target_page->thread->pagedir, target_page->vm_entry->vaddr, false); //give a chance to stay(set access bit 0)
        } 
        else {//access bit is 0 (already given a chance)
            break;
        }

        lock_acquire(&lru_list_lock);
        cur_page = lru_clock;
        lru_clock = list_next(lru_clock);
        lock_release(&lru_list_lock);
    }

    switch (target_page->vm_entry->type) {
        case VM_BIN:
            //if the data is changed, dirty bit is 1. -> convert to VM_ANON and swap out it
            if (pagedir_is_dirty(target_page->thread->pagedir, target_page->vm_entry->vaddr)) {
                target_page->vm_entry->type = VM_ANON;
                target_page->vm_entry->swap_slot = swap_out(target_page->kaddr);
            }
            break;
        case VM_FILE:
            //if the data is changed, dirty bit is 1. -> write data to file
            if (pagedir_is_dirty(target_page->thread->pagedir, target_page->vm_entry->vaddr)) {
                vm_file_write(target_page->vm_entry->file, target_page->kaddr, target_page->vm_entry->read_bytes, target_page->vm_entry->offset);
            }
            break;
        case VM_ANON:
            //it must be swap out
            target_page->vm_entry->swap_slot = swap_out(target_page->kaddr);
            break;
        default:
            sys_exit(-1);
    }
    //evict from the physical memory
    target_page->vm_entry->is_loaded = false;
    free_page(target_page->kaddr);
}

struct list_elem *get_lru_clock(struct list_elem *cur_elem) {
    if(list_empty(&lru_list)) return NULL; //list is empty
    if(lru_clock == NULL) return list_begin(&lru_list); //cur_elem is null -> direct to first elem
    if((cur_elem != NULL) && (list_begin(&lru_list) == list_end(&lru_list))) return NULL; //no elem to direct the next
    if((cur_elem != NULL) && (list_end(&lru_list) == lru_clock)) return list_begin(&lru_list);//cur_elem is last elem -> direct to first elem
    return lru_clock;
}