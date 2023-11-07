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

  if (start_addr <= 0x60000000 || end_addr > KERNBASE) {
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

// file-backed mapping
int file_backed_mmap(struct proc *p, struct file *f, uint addr, int offset, int prot) {
  int remaining_size = f->ip->size - offset;  // Remaining size should consider the offset
  
  // Allocate in the unit of pages
  for (int i = 0; i < remaining_size; i += PGSIZE) {
    // Calculate the size to map for this iteration
    int map_size = (remaining_size - i > PGSIZE) ? PGSIZE : (remaining_size - i);

    // Allocate a page and clear it
    char *tmp = kalloc();
    if (!tmp)
      return -1;  
    memset(tmp, 0, PGSIZE);

    // Copy file content into the allocated page
    ilock(f->ip);  // Lock the inode before accessing the file

    int read_size = map_size;  // Amount of file content to read into the page
    int bytes_read = readi(f->ip, tmp, offset + i, read_size);  
    if (bytes_read < 0) {
      iunlock(f->ip);
      kfree(tmp);  
      return -1;
    }

    iunlock(f->ip);  

    // Map the page into the user proc
    if (mappages(p->pgdir, (void *)(addr + i), PGSIZE, V2P(tmp), prot) < 0) {
      kfree(tmp); 
      return -1;
    }

    remaining_size -= map_size;
  }

  return 0;  
}

int file_backed_private_mmap(struct proc *p, struct file *f, uint addr, int offset, int prot) {
    // Assume 'size' is the length to be mapped
    int size = f->ip->size - offset;  
    if (size <= 0) return -1;

    // Iterate over the file in page-sized chunks
    for (int i = 0; i < size; i += PGSIZE) {
        char *mem = kalloc();  // Allocate a new page
        if (!mem) return -1;  // Allocation failed

        memset(mem, 0, PGSIZE);
        ilock(f->ip);
        int read_bytes = readi(f->ip, mem, offset + i, PGSIZE);
        iunlock(f->ip);

        if (read_bytes < 0) {
            kfree(mem);  // Read failed, free allocated memory
            return -1;
        }

        if (mappages(p->pgdir, (void *)(addr + i), PGSIZE, V2P(mem), prot) < 0) {
            kfree(mem);  // Mapping failed, free allocated memory
            return -1;
        }
    }
    return 0;
}

// TODO: implement copy_map function to copy from parent to child here. only call this function in fork
	

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

  // TODO: alloc mmaps 
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
        if (mappages(curproc->pgdir, vstart + i * PGSIZE, PGSIZE, V2P(mem), PTE_W | PTE_U) < 0) {
          // free allocated memory
          kfree(mem);
          while(--i > 0) {
            void * curva = vstart + i * PGSIZE;
            pte_t *pte = walkpgdir(curproc->pgdir, curva, 0);
            if(pte && (*pte & PTE_P)) {
              char *curpa = P2V(PTE_ADDR(*pte));
              kfree(curpa);
            }
          }
          return (void*)-1;
        }
      } else {
        // TODO: handle private
        // get pte, curva = faulting_va <- retrieve from page fault handler
        // uint old_pa = PTE_ADDR(*pte);
        // void *new_page = kalloc();
        // if (new_page == 0) {
        //     return -1;
        // }

        // Copy the contents of the old page to the new page
        // memmove(new_page, P2V(old_pa), PGSIZE);

        // .. update pte and invalidate tlb!
      }
    }
  } else {
    // file backed
    struct file *f = curproc->ofile[fd];
    filedup(f);

    if (isshared) {
      // TODO: edit file_backed_mmap!
      // Directly map the file pages into the process's address space
      if (file_backed_mmap(curproc, f, (uint)va, offset, prot) == -1) {
        fileclose(f);
        return (void*)-1;
      }
    } else { 
      if (file_backed_private_mmap(curproc, f, (uint)va, offset, prot) == -1) {
        fileclose(f);
        return (void*)-1;
      }
    }

    fileclose(f);
  }

  // TODO: handle MAP_PRIVATE and MAP_GROWSUP
  if (flags & MAP_GROWSUP) {}


  // Update new mapping info
  struct mmapinfo minfo;
  minfo.va = vstart;
  minfo.length = length;
  minfo.prot = prot;
  minfo.flags = flags;
  minfo.valid = 1;
  minfo.fd = fd;
  minfo.offset = offset;

  int inserti = 0;
  for (int i = 0; i < NMMAP; i++) {
    if (!curproc->mmaps[i].valid || curproc->mmaps[i].va >= vstart) {
        inserti = i;
        break;
    }
  }
  // insert
  for (int i = NMMAP - 2; i >= inserti; i--) {
    curproc->mmaps[i + 1] = curproc->mmaps[i];
  }

  // Insert new mapping
  curproc->mmaps[inserti] = minfo;
 
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
            // For anonymous mappings, no need to write back.
            kfree(pa);
          } else {
            // For file-backed mappings, write back if necessary.
            struct file *f = curproc->ofile[mmaps[i].fd];
            if (mmaps[i].flags & MAP_SHARED) {
              filewrite(f, pa, PGSIZE); // Handle partial write-backs and errors appropriately.
            }
            kfree(pa);
          }
          *pte = 0; // Invalidate the PTE.
          // Consider flushing the TLB here if necessary.
          va += PGSIZE; // Move to the next page.
          unmapped_pages++;
        } else {
          // Handle the error appropriately if the PTE was expected to be present.
          return -1;
        }
      }
      // Invalidate the mapping info if the whole range has been unmapped.
      if (va == (mmaps[i].va + mmaps[i].length)) {
        mmaps[i].valid = 0;
      }
      return 0; // Success.
    }
  }

  return -1; // Address not found in mappings.
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