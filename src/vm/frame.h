#ifndef FRAME_H
#define FRAME_H

#include "vm/page.h"
#include "vm/swap.h"
#include "threads/synch.h"
#include "threads/palloc.h"
#include "userprog/pagedir.h"

struct list lru_list;//list for managing physical pages allocated to processes
struct lock lru_list_lock;
struct list_elem *lru_clock;//clock hand for second chance algorithms

/* initialize, insert, delete LRU list */
void lru_list_init(void);
void add_page_to_lru_list(struct page* page);
void del_page_from_lru_list(struct page* page);

struct page *alloc_page(enum palloc_flags flags);
void free_page(void *kaddr);
struct list_elem *get_lru_clock(struct list_elem *cur_elem);
void evict_page_lru_policy(void);

#endif