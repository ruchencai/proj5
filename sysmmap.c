#include "types.h"
#include "defs.h"
#include "param.h"
#include "stat.h"
#include "mmu.h"
#include "proc.h"
#include "fs.h"
#include "spinlock.h"
#include "sleeplock.h"
#include "fcntl.h"
#include "mmap.h"
#include "memlayout.h"
#include "file.h"

// Check if the virtual address is valid and free
int 
check_va_free(struct mmapinfo *mmaps, uint start_addr, uint end_addr) {

  if (start_addr < 0x60000000 || end_addr > KERNBASE) {
    return 0;
  }

  int i;
  for (i = 0; i < NMMAP; i++) {  // Max num of mmap = 32 (in param.h)
    if (mmaps[i].valid) {
      uint map_start = (uint)mmaps[i].va;
      uint map_end = PGROUNDUP((uint)mmaps[i].va + mmaps[i].length);
      // Check whether overlapped with existing mappings
      if ((map_start <= start_addr && end_addr - 1 <= map_end - 1) ||
          (start_addr <= map_start && map_start <= end_addr - 1) ||
          (start_addr <= map_end - 1 && map_end - 1 <= end_addr - 1)) {
        return 0;
      } 
    }
  }
  
  return 1;
}

// Find the virtual address that satisfies length
int 
get_va_free(struct mmapinfo *mmaps, int length, void **start_addr, void **end_addr) {
  length = PGROUNDUP(length);
  // search start from the beginning of user space (0x60000000)
  {
    uint last_end = 0x60000000;
    uint now_begin = KERNBASE + 1;
    if (mmaps[0].valid) {
      // hardcode for low addr
      now_begin = (uint)mmaps[0].va;
    }
    if (now_begin - last_end >= length) {
      *start_addr = (void *)last_end;
      *end_addr = (void *)last_end + length;
      return 1;
    }
  }
  // check between existing mappings
  int i;
  for (i = 0; i < NMMAP; i++) {
    if (mmaps[i].valid) {
      void *map_end = 0;
      void *map_start = mmaps[i].va + PGROUNDUP(mmaps[i].length);
      if (i + 1 == NMMAP || mmaps[i + 1].valid == 0) {
        map_end = (void*)KERNBASE + 1;
      }
      else {
        map_end = mmaps[i + 1].va;
      }
      if ((uint)(map_end - map_start) >= length) {
        *start_addr = map_start;
        *end_addr = map_start + length;
        return 1;
      }
    }
  }
  // no free space found
  return 0;
}

void record_mapping(struct proc * curproc, void* vstart, uint length, int prot, int flags, int fd, int offset) {
    struct mmapinfo minfo;
    minfo.va = vstart;
    minfo.length = length;
    minfo.prot = prot;
    minfo.flags = flags;
    minfo.valid = 1;
    minfo.fd = fd;
    minfo.offset = offset;

    int inserti = NMMAP; // Initialize to an invalid index.

    // find the insertion point
    for (int i = 0; i < NMMAP; i++) {
        if (!curproc->mmaps[i].valid) {
            inserti = i;
            break;
        } else if (curproc->mmaps[i].va >= vstart) {
            inserti = i;
            break;
        }
    }

    if (inserti == NMMAP) {
        panic("Out of mmap slots");
    }

    // insert
    for (int i = NMMAP - 2; i >= inserti; i--) {
      curproc->mmaps[i + 1] = curproc->mmaps[i];
    }

    // Insert new mapping
    curproc->mmaps[inserti] = minfo;
}

int fdalloc(struct file *f) {
  struct proc *curproc = myproc();
  for (int fd = 0; fd < NOFILE; fd++) {
    if (curproc->ofile[fd] == 0) {
      curproc->ofile[fd] = f;
      f->ref++;
      return fd;
    }
  }
  return -1; // No free file descriptors
}

void * 
file_backed_mmap(struct proc *p, struct file *f, uint addr, int offset, int prot, int ispriva, int flags, int fd) {
  // Lock the inode to read file size safely.
  ilock(f->ip);
  int remaining_size = f->ip->size - offset; // size of the file after offset
  iunlock(f->ip);
  cprintf("f->ip->size: %d\n", f->ip->size);
  cprintf("ispriva: %d\n", ispriva);

  if (remaining_size <= 0) return (void *)-1;

  // page-align the address
  int length = PGROUNDUP(remaining_size);
  addr = PGROUNDUP(addr);  

  // find free address space in the process memory
  void *vstart = (void *)addr;
  void *vend = 0;
  if (get_va_free(p->mmaps, length, &vstart, &vend) == 0) {
    return (void *)-1;  // no free address space
  }

  // lazy allocate, not loading file contents yet
  for (int i = 0; i < remaining_size; i += PGSIZE) {
    // set pte with appropriate flags, if private, mark as copy-on-write
    pte_t *pte = walkpgdir(p->pgdir, (void *)(vstart + i), 1);
    if (pte == 0) {
      return (void *)-1; 
    }

    if (ispriva) {
      // mark as read only innitially, when need to write, trigger page fault 
      *pte = (*pte & ~PTE_W) | PTE_U;
    } else {
      // not private, set as specified
      *pte = (*pte & ~0xFFF);
       *pte |= PTE_U;
        if (prot & PROT_WRITE) {
            *pte |= PTE_W;
        }
    }
  }

  filedup(f); // Increment the ref count

  // Update new mapping info
  record_mapping(p, vstart, length, prot, flags, fd, offset);
cprintf("vstart: %x\n", vstart);
cprintf("vend: %x\n", vend);
char *mem = (char*) vstart;
for (int i = 0; i < length; i++) {
  cprintf("char at index: %d\n", i);
        cprintf("%02hhx ", mem[i]);  // Print each byte in hex
        if ((i + 1) % 16 == 0)  // After every 16 bytes, print a new line
            cprintf("\n");
    }
    cprintf("\n");
  return (void *)vstart;

  // // Allocate mmapinfo in the process structure for the new memory mapping.
  // struct mmapinfo *mi = 0;
  // for (int i = 0; i < NMMAP; i++) {
  //   if (!p->mmaps[i].valid) {
  //     mi = &p->mmaps[i];
  //     break;
  //   }
  // }
  // if (mi == NULL) {
  //   return (void *)-1;  // No space for new mapping.
  // }

  // // Setup the mmapinfo structure.
  // mi->va = (char *)addr;
  // mi->length = length;
  // mi->prot = prot;
  // mi->flags = ispriva ? MAP_PRIVATE : MAP_SHARED;
  // mi->fd = fdalloc(f); // Increment the ref count of the file.
  // if (mi->fd < 0) {
  //   return (void *)-1;  // No free file descriptors
  // }

  // mi->offset = offset;
  // mi->valid = 1;

}

// free pages for error handling
void free_pages(struct proc *curproc, void *vstart, uint pgcount) {
  uint i;
  void *curva;
  pte_t *pte;
  char *curpa;

  for (i = 0; i < pgcount; i++) {
    curva = vstart + i * PGSIZE;
    pte = walkpgdir(curproc->pgdir, curva, 0);
    if (pte != NULL && (*pte & PTE_P) != 0) {
      curpa = P2V(PTE_ADDR(*pte));
      kfree(curpa);
      *pte = 0;
    }
  }
}

void *handle_error(struct proc *curproc, void *mem, void *vstart, uint pgcount) {
  kfree(mem);
  free_pages(curproc, vstart, pgcount);
  return (void*)-1;
}

void inc_ref_count(char *pa) {
  pte_t *pte = walkpgdir(myproc()->pgdir, pa, 0);
  if (pte && (*pte & PTE_P)) {
    (*pte)++; // increment ref count
  }
}

// get ref count of a page
int ref_count(char *pa) {
  pte_t *pte = walkpgdir(myproc()->pgdir, pa, 0);
  if (pte && (*pte & PTE_P)) {
    return *pte;
  }
  return -1;
}

void dec_ref_count(char *pa) {
  pte_t *pte = walkpgdir(myproc()->pgdir, pa, 0);
  if (pte && (*pte & PTE_P)) {
    (*pte)--; // decrement ref count
  }
}

// helper function for copy from parent to child in fork()
void copy_mmaps(struct proc *parent, struct proc *child) {

  for (int i = 0; i < NMMAP; i++) {
    if (parent->mmaps[i].valid) {
      // copy the mmapinfo struct
      child->mmaps[i] = parent->mmaps[i];

      // if private, set as copy-on-write
      if (parent->mmaps[i].flags & MAP_PRIVATE) {
        for (uint j = 0; j < child->mmaps[i].length; j += PGSIZE) {
          uint va = (uint)child->mmaps[i].va + j;

          // Find the page table entry for the virtual address
          pte_t *pte = walkpgdir(parent->pgdir, (void *)va, 0);
          if (pte && (*pte & PTE_P)) {
            // Mark the parent's page as read-only
            *pte &= ~PTE_W;
            // Update the PTE in both parent and child's page tables
            pte_t *child_pte = walkpgdir(child->pgdir, (void *)va, 1);
            if (child_pte) {
              *child_pte = *pte;
            }
          }
        }
        // page fault will be caused when attempting to write
      } else {
        // if shared, increment the ref count of the file and copy as they are
        //filedup(child->ofile[child->mmaps[i].fd]);
        for (uint j = 0; j < parent->mmaps[i].length; j += PGSIZE) {
          uint va = (uint)parent->mmaps[i].va + j;
          pte_t *pte = walkpgdir(parent->pgdir, (void *)va, 0);
          if (pte && (*pte & PTE_P)) {
            // increment ref count of the page
            char *pa = P2V(PTE_ADDR(*pte));
            inc_ref_count(pa);
          }
        }
      }
    }
  }
}


// void *mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset)
void *
sys_mmap(void) {
  void* va;
  int iva;
  int length, prot, flags, fd, offset;

  if (argint(0, &iva) < 0 || argint(1, &length) < 0 || argint(2, &prot) < 0 || argint(3, &flags) < 0 || argint(4, &fd) < 0 || argint(5, &offset) < 0 ) {
    return (void*)-1;
  }
    
  va = (void*) iva;  // Starting address for the mapping if MAP_FIXED

  struct proc *curproc = myproc();
  if (length <= 0) {
    return (void*)-1;
  }

  if ((uint)va % PGSIZE != 0) {  // Start address must be page-aligned
    return (void*)-1;
  }
    
  if ((flags & MAP_ANONYMOUS) != MAP_ANONYMOUS) {
    if(curproc->ofile[fd] == 0){
      return (void*)-1;
    }
  }

  int isshared = (flags & MAP_SHARED) == MAP_SHARED;
  int ispriva = (flags & MAP_PRIVATE) == MAP_PRIVATE;

  if (isshared + ispriva != 1) {
    return (void*)-1;
  }

  if (isshared && curproc->ofile[fd]->writable == 0 && (prot & PROT_WRITE) == PROT_WRITE) {
    return (void*)-1;
  }

  if (curproc->mmaps[NMMAP - 1].valid) {
    return (void*)-1;
  }

  void *vstart = va;
  void *vend = va + PGROUNDUP(length);

  // FIXED
  if ((flags & MAP_FIXED) == MAP_FIXED) {
    if (check_va_free(curproc->mmaps, (uint)vstart, (uint)vend) == 0) {
      return (void*)-1;
    }
  }
  else {
    if (get_va_free(curproc->mmaps, length, &vstart, &vend) == 0) {
      return (void*)-1;
    }
  }

  // ANONYMOUS
  if (flags & MAP_ANONYMOUS) {
    int pagesz = PGROUNDUP(length) / PGSIZE;
   
    for (int i = 0; i < pagesz; i++) {
      void* mem = kalloc();
      if (mem == 0) {
        --i;
        break;
      }
      memset(mem, 0, PGSIZE);

      if (isshared) {
        // from vm.c
        if (mappages(curproc->pgdir, vstart + i * PGSIZE, PGSIZE, V2P(mem), PTE_W | PTE_U) < 0)
          return handle_error(curproc, mem, vstart, i);
      } else {
        // implement private
        if (mappages(curproc->pgdir, vstart + i * PGSIZE, PGSIZE, V2P(mem), PTE_W | PTE_U | PTE_P) < 0)
          return handle_error(curproc, mem, vstart, i);
      }
    }

    // Update new mapping info
    record_mapping(curproc, vstart, length, prot, flags, fd, offset);

    return vstart;
  } else {
    // file backed
    struct file *f = curproc->ofile[fd];
    if (f == 0) {
      return (void*)-1;
    }

    vstart = file_backed_mmap(curproc, f, (uint)va, offset, prot, ispriva, flags, fd);

    fileclose(f);
  }

 return vstart;
}

int do_munmap(struct proc *curproc, void *addr, size_t length) {
  if (length <= 0 || (uint)addr % PGSIZE != 0) {
    return -1; 
  }

  struct mmapinfo *mmaps = curproc->mmaps;
  int i;
  for (i = 0; i < NMMAP; i++) {
    if (mmaps[i].valid && addr >= mmaps[i].va && addr < (mmaps[i].va + mmaps[i].length)) {
      int unmapped_pages = 0;
      int target_pages = PGROUNDUP(length) / PGSIZE;
      void *va = addr;

      while (unmapped_pages < target_pages) {
        pte_t *pte = walkpgdir(curproc->pgdir, va, 0);
        if (pte && *pte & PTE_P) {
          char *pa = P2V(PTE_ADDR(*pte));
          if (mmaps[i].flags & MAP_ANONYMOUS) { 
            kfree(pa);
          } else {
            // filebacked -> write back to file
            struct file *f = curproc->ofile[mmaps[i].fd];
            
            if (mmaps[i].flags & MAP_SHARED) { 
              if (*pte & PTE_W) {
                // write back to file if modified
                filewrite(f, pa, PGSIZE);
              }
            } else if (mmaps[i].flags & MAP_PRIVATE) { // dont write back
              kfree(pa);
            }
          }
          *pte = 0; 
          
          va += PGSIZE; // move to the next page
          unmapped_pages++; 
        } else {
          return -1;
        }
      }
      // invalidate the mapping info if the whole range has been unmapped
      if ((uint)va == ((uint)mmaps[i].va + PGROUNDUP(mmaps[i].length))) {
        mmaps[i].valid = 0;
      }

      return 0; 
    }
  }

  return -1; 
}

// int munmap(void *addr, size_t length)
int sys_munmap(void) {

  int iva, length;
  if (argint(0, &iva) < 0 || argint(1, &length) < 0) {
    return -1;
  }

  void *va = (void*)iva;
  struct proc *curproc = myproc();

  if (length <= 0){
    return -1;
  }

  return do_munmap(curproc, va, length);
}

struct mmapinfo* find_mapping(struct proc *curproc, uint faulting_address) {
   
    for (int i = 0; i < NMMAP; i++) {
      cprintf("curproc->mmaps[i].va: %d\n", curproc->mmaps[i].va);
      cprintf("curproc->mmaps[i].length: %d\n", curproc->mmaps[i].length);
      cprintf("faulting_address: %d\n", faulting_address);
        if (curproc->mmaps[i].valid) {
            uint start = (uint)curproc->mmaps[i].va;
            uint end = start + curproc->mmaps[i].length;
            if (faulting_address >= start && faulting_address < end) {
              cprintf("&curproc->mmaps[i]: %x\n", &curproc->mmaps[i]);
                return &curproc->mmaps[i]; // found the mapping with the faulting address
            }
        }
    }
    return NULL; 
}

void
page_fault_handler(uint page_fault_addr) {
  struct proc *curproc = myproc();

  if (curproc == 0) 
    return;

  if (page_fault_addr < 0x60000000 || page_fault_addr > KERNBASE) {
    goto segfault;
  }

  // check if the faulting address is within a cow region
  cprintf("page fault address: %x\n", page_fault_addr);
  struct mmapinfo *mi = find_mapping(curproc, page_fault_addr);
  cprintf("mi: %x\n", mi);
  if (mi && (mi->flags & MAP_PRIVATE)) {
    // allocate a new page in cow region
    char *mem1 = kalloc();
    if (!mem1) {
      panic("Out of memory");
    }

    // get original page
    pte_t *pte = walkpgdir(curproc->pgdir, (void *)page_fault_addr, 0);
    if (!pte) {
      panic("Page table entry not found, COW page fault");
    }
    char *original_page = P2V(PTE_ADDR(*pte));

    // copy the original page to the new page
    memmove(mem1, original_page, PGSIZE);

    // map the new page to the faulting address
    if (mappages(curproc->pgdir, (void *)page_fault_addr, PGSIZE, V2P(mem1), PTE_W | PTE_U) < 0) {
      panic("mappages failed, COW page fault");
    }

    // decrease the ref count of the original page if necessary
    if (ref_count(original_page) == 1) {
      kfree(original_page);
    } else {
      dec_ref_count(original_page);
    }
  } 

  // handles growsup
  void *mem;
  struct mmapinfo *mmaps = curproc->mmaps;
  for (int i = 0; i < NMMAP; i++) {
    if (mmaps[i].valid && ((mmaps[i].flags & MAP_PRIVATE) == MAP_PRIVATE)) {
      uint map_start = (uint)mmaps[i].va;
      uint map_end = PGROUNDUP((uint)mmaps[i].va + mmaps[i].length);
      if (page_fault_addr >= map_start && page_fault_addr < map_end) {
        uint offset = page_fault_addr - map_start;
        uint page_index = offset / PGSIZE;
        uint page_offset = offset % PGSIZE;
        uint page_addr = map_start + page_index * PGSIZE;
        pte_t *pte = walkpgdir(curproc->pgdir, (void *)page_addr, 0);
        if (pte == 0) {
          goto segfault;
        }
        if ((*pte & PTE_P) == 0) {
          goto segfault;
        }
        if ((*pte & PTE_W) == 0) {
          // copy on write
          mem = kalloc();
          if (mem == 0) {
            cprintf("kalloc failed\n");
            curproc->killed = 1;
            return;
          }
          memset(mem, 0, PGSIZE);
          memmove(mem, (void *)(P2V(PTE_ADDR(*pte)) + page_offset), PGSIZE - page_offset);
          if (mappages(curproc->pgdir, (void *)page_addr, PGSIZE, V2P(mem), PTE_W | PTE_U) < 0) {
            kfree(mem);
            cprintf("mmappages failed\n");
            curproc->killed = 1;
            return;
          }
          return;
        }
        else {
          goto segfault;
        }
      }
    }
  }


  int i, growsup_index = -1;
  // check if it's protect page
  for (i = 0; i < NMMAP; i++) {
    if (mmaps[i].valid && ((mmaps[i].flags & MAP_GROWSUP) == MAP_GROWSUP)) {
      uint map_end = PGROUNDUP((uint)mmaps[i].va + mmaps[i].length);
      // growsup and have one page left
      if (page_fault_addr >= map_end && page_fault_addr < map_end + PGSIZE 
        && (((i + 1 == NMMAP || mmaps[i + 1].valid == 0) && map_end + PGSIZE < KERNBASE) || (map_end + PGSIZE < (uint)mmaps[i + 1].va))) {
        growsup_index = i;
	break;
      }
    }
  }

  if (growsup_index >= 0) 
    goto growsup;
  else 
    goto segfault;

growsup:
  mem = kalloc();
  if (mem == 0) {
    cprintf("kalloc failed\n");
    curproc->killed = 1;
    return;
  }
  memset(mem, 0, PGSIZE);
  if (mappages(curproc->pgdir, mmaps[growsup_index].va + PGROUNDUP(mmaps[growsup_index].length),
      PGSIZE, V2P(mem), PTE_W | PTE_U) < 0) {
    kfree(mem);
    cprintf("mmappages failed\n");
    curproc->killed = 1;
    return;
  }
  mmaps[growsup_index].length += PGSIZE; 
  return;

segfault:
  cprintf("Segmentation Fault\n");
  curproc->killed = 1;
  return;
}
