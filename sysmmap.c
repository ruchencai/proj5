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

// get file from fd
struct file* get_file(struct proc *p, int fd) {
  if (fd < 0 || fd >= NOFILE || p->ofile[fd] == 0) {
    return 0;
  }
  return p->ofile[fd];
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

  // TODO: alloc mmaps 
  if (curproc->mmaps[NMMAP - 1].valid) {
    return (void*)-1;
  }

  void *vstart = va;
  void *vend = va + PGROUNDUP(length);
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

  // TODO: not lazy alloc yet
  int pagesz = PGROUNDUP(length) / PGSIZE;
  int i;
  for (i = 0; i < pagesz; i++) {
    void* mem = kalloc();
    if (mem == 0) {
      --i;
      break;
    }
    memset(mem, 0, PGSIZE);
    // from vm.c
    if (mappages(curproc->pgdir, vstart + i * PGSIZE, PGSIZE, V2P(mem), PTE_W | PTE_U) < 0) {
      break;
    }
  } 
  // alloc fail
  if (i != pagesz){
    cprintf("mmap alloc page fail %d / %d", i + 1, pagesz);
    while(i >= 0) {
      void * curva = vstart + i * PGSIZE;
      pte_t *pte = walkpgdir(curproc->pgdir, curva, 0);
      char *curpa = P2V(PTE_ADDR(*pte));
      kfree(curpa);
      --i;
    }
    return (void*)-1;
  }

  // Update new mapping info
  struct mmapinfo minfo;
  minfo.va = vstart;
  minfo.length = length;
  minfo.prot = prot;
  minfo.flags = flags;
  minfo.valid = 1;
  minfo.fd = fd;
  minfo.offset = offset;

  if ((flags & MAP_ANONYMOUS) != MAP_ANONYMOUS) {
    filedup(curproc->ofile[fd]);
  }
  int inserti;
  for (i = 0, inserti = 0; i < NMMAP; i++, inserti++) {
    if (curproc->mmaps[i].valid) {
      if (curproc->mmaps[i].va >= vstart)
        break;
    }
    else break;
  }
  // insert
  for (i = NMMAP - 2; i >= inserti; i--) {
     memmove(&curproc->mmaps[i + 1], &curproc->mmaps[i], sizeof(struct mmapinfo)); 
  }
  memmove(&curproc->mmaps[inserti], &minfo, sizeof(struct mmapinfo)); 








  // file-backed mapping
  if (!(flags & MAP_ANONYMOUS)) {
    // get file object
    struct file *f = curproc->ofile[fd];
    if(f==0)
      return (void*) -1;

    // get inode from file, calculate end of file position
    ilock(f->ip);
    uint fend; 
    if (offset + length > f->ip->size)
      fend = f->ip->size;
    else 
      fend = offset + length;

    // lazy alloc
    for (int j = 0; j < pagesz; j++) {
      uint file_offset = offset + i* PGSIZE;
      
      if (file_offset < fend) {
        if (mappages(curproc->pgdir, vstart + i * PGSIZE, PGSIZE, 0, PTE_W | PTE_U))
          break;
      }
    }

    iunlock(f->ip);
  }

  // handle page fault in trap.c

  // handle MAP_PRIVATE and MAP_GROWSUP

  if (flags & MAP_PRIVATE) {}
  if (flags & MAP_GROWSUP) {}


 


  if (flags & MAP_PRIVATE) {} (void*)vstart;
}

// int munmap(void *addr, size_t length)
int
sys_munmap(void) {
  int iva;
  void* va;
  int length;

  if (argint(0, &iva) < 0 || argint(1, &length) < 0) {
    return -1;
  }

  va = (void*)iva;
  struct proc *curproc = myproc();

  if (length <= 0){
    return -1;
  }

  struct mmapinfo *mmaps = curproc->mmaps;
  struct file *f;
  // TODO: only can unmap va == mmap.va
  int i;
  for (i = 0; i < NMMAP; i++) {
    if (mmaps[i].valid && mmaps[i].va == va) {
      void *map_start = mmaps[i].va;

        if (length > mmaps[i].length) {
          return -1;
	      }

        // get file to write back to
        f = get_file(curproc, mmaps[i].fd);
        if (f==0)
          return -1;

        int pagesz = PGROUNDUP(length) / PGSIZE;
        int j;
        for (j = 0; j < pagesz; j++) {
          void * curva = va + j * PGSIZE;
          pte_t *pte = walkpgdir(curproc->pgdir, curva, 0);

          // if page dirty, write back to file
          if (filewrite(f, P2V(PTE_ADDR(*pte)), PGSIZE) != PGSIZE) 
            return -1;
          
          // free page
          char *curpa = P2V(PTE_ADDR(*pte));
          kfree(curpa);
          *pte = 0;
        }

        // mark mapping as invalid
        mmaps[i].valid = 0;
        if (--f->ref == 0) 
          fclose(f);

        return 0;
      
    }
  }

  return -1;
}
