#include "vm/swap.h"
#include "devices/block.h"
#include "vm/page.h"
#include "threads/vaddr.h"
#include "threads/malloc.h"

//initialize swap area
void swap_init() {
    lock_init(&swap_lock);
    //allocate swap area
    swap_block = block_get_role(BLOCK_SWAP);
    if(swap_block == NULL) return;
    //allocate swap array to check if there is a page or not
    swap_array = malloc(sizeof(uint8_t)*(block_size(swap_block) * BLOCK_SECTOR_SIZE) / PGSIZE);
    if(swap_array == NULL) return;
    
    for (int i = 0; i < (int)((block_size(swap_block) * BLOCK_SECTOR_SIZE) / PGSIZE); i++) {
        swap_array[i] = 0;//all swap area is empty(=0)
    }
}

//copy data stored at used_index of swap area to kaddr
void swap_in(size_t used_index, void *kaddr) {
    lock_acquire(&swap_lock);
    if(swap_array[used_index] == 0) { //swap area is empty
        lock_release(&swap_lock);
        sys_exit(-1);
    }

    //copy swap area to physical memory
    for(int i = 0; i < (int)(PGSIZE / BLOCK_SECTOR_SIZE); i++) {
        block_read(swap_block, used_index * PGSIZE / BLOCK_SECTOR_SIZE + i, kaddr + BLOCK_SECTOR_SIZE * i);
    }
    swap_array[used_index] = 0;//set swap area is empty
    lock_release(&swap_lock);
}

//store page of kaddr into swap area
size_t swap_out(void *kaddr) {
    lock_acquire(&swap_lock);
    int i;

    //find the empty swap area
    for(i = 0; i < (int)(block_size(swap_block) * BLOCK_SECTOR_SIZE / PGSIZE); i++) {
        if(swap_array[i] == 0) break;
    }
    //swap space is full
    if(i >= (int)(block_size(swap_block) * BLOCK_SECTOR_SIZE / PGSIZE)) {
        //i = SIZE_MAX;
        sys_exit(-1);
    }
    else {
        //copy page to swap area
        for(int j = 0; j < (int)(PGSIZE / BLOCK_SECTOR_SIZE); j++) {
            block_write(swap_block, i * PGSIZE / BLOCK_SECTOR_SIZE + j, kaddr + BLOCK_SECTOR_SIZE * j);
        }
        swap_array[i] = 1;//set swap area is full
    }

    lock_release(&swap_lock);
    return (size_t)i;
}