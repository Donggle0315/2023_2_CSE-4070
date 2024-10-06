#ifndef SWAP_H
#define SWAP_H

#include "threads/synch.h"
#include "devices/block.h"
#include "lib/kernel/bitmap.h"
#include "userprog/syscall.h"

struct lock swap_lock;
struct block *swap_block; //swap space
uint8_t *swap_array; //array for checking whether the index is empty or full

void swap_init(void);
void swap_in(size_t used_index, void *kaddr);
size_t swap_out(void *kaddr);

#endif