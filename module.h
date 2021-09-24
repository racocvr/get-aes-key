#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include <signal.h>
#include <sys/epoll.h>
#include <errno.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <dirent.h>
#include <glob.h>

#include <link.h>
#include <elf.h>
#include <fcntl.h>
#include <dlfcn.h>
#include <sys/mman.h>

int compare(const char *s1, const char *s2) {
    while(*s1 && *s2) {
      if(*s1 != *s2) {
        return 0;
      }
      s1++; s2++;
    }
    return *s2 == 0;
}

const char* _strstr(const char *s1, const char *s2) {
    while (*s1) {
      if((*s1 == *s2) && compare(s1, s2)) return s1;
      s1++;
    }
    return NULL;
}

int _strcmp(const char *str1, const char *str2) {
    while (*str1 && *str2) {
      if(*str1 != *str2) break;
      str1++; str2++;
    }
    return (int)*str1 - (int)*str2;
}

// return pointer to program header
static Elf32_Phdr *elf_get_phdr(void *base, int type) {
    int        i;
    Elf32_Ehdr *ehdr;
    Elf32_Phdr *phdr;
    
    // sanity check on base and type
    if(base == NULL || type == PT_NULL) return NULL;
    
    // ensure this some semblance of ELF header
    if(*(uint32_t*)base != 0x464c457f) return NULL;
    
    // ok get offset to the program headers
    ehdr=(Elf32_Ehdr*)base;
    phdr=(Elf32_Phdr*)(base + ehdr->e_phoff);
    
    // search through list to find requested type
    for(i=0; i<ehdr->e_phnum; i++) {
      // if found
      if(phdr[i].p_type == type) {
        // return pointer to it
        return &phdr[i];
      }
    }
    // return NULL if not found
    return NULL;
}

static uint32_t elf_get_delta(void *base) {
    Elf32_Phdr *phdr;
    uint64_t   low;
    
    // get pointer to PT_LOAD header
    // first should be executable
    phdr = elf_get_phdr(base, PT_LOAD);
    
    if(phdr != NULL) {
      low = phdr->p_vaddr;
    }
    return (uint32_t)base - low;
}

// return pointer to first dynamic type found
static Elf32_Dyn *elf_get_dyn(void *base, int tag) {
    Elf32_Phdr *dynamic;
    Elf32_Dyn  *entry;
    
    // 1. obtain pointer to DYNAMIC program header
    dynamic = elf_get_phdr(base, PT_DYNAMIC);

    if(dynamic != NULL) {
      entry = (Elf32_Dyn*)(dynamic->p_vaddr + elf_get_delta(base));
      // 2. obtain pointer to type
      while(entry->d_tag != DT_NULL) {
        if(entry->d_tag == tag) {
          return entry;
        }
        entry++;
      }
    }
    return NULL;
}

static uint32_t hex2bin(const char hex[]) {
    uint32_t r=0;
    char     c;
    int      i;
    
    for(i=0; i<16; i++) {
      c = hex[i];
      if(c >= '0' && c <= '9') { 
        c = c - '0';
      } else if(c >= 'a' && c <= 'f') {
        c = c - 'a' + 10;
      } else if(c >= 'A' && c <= 'F') {
        c = c - 'A' + 10;
      } else break;
      r *= 16;
      r += c;
    }
    return r;
}

static int read_line(int fd, char *buf, int buflen) {
    int  len;
    
    if(buflen==0) return 0;
    
    for(len=0; len < (buflen - 1); len++) {
      // read a byte. exit on error
      if(!_read(fd, &buf[len], 1)) break;
      // exit loop when new line found
      if(buf[len] == '\n') {
        buf[len] = 0;
        break;
      }
    }
    return len;
}

static int is_exec(char line[]) {
    char *s = line;
    
    // find the first space
    // but ensure we don't skip newline or null terminator
    while(*s && *s != '\n' && *s != ' ') s++;
    
    // space?
    if(*s == ' ') {
      do {
        s++; // skip 1
        // execute flag?
        if(*s == 'x') return 1;
      // until we reach null terminator, newline or space
      } while (*s && *s != '\n' && *s != ' ');
    }
    return 0;
}

static void *get_module_handle(const char *module) {
    int  maps;
    void *base=NULL, *start_addr;
    char line[PATH_MAX];
    int  str[8], len;
	    
    // 1. open /proc/self/maps
    maps = _open("/proc/self/maps", O_RDONLY, 0);
    if(!maps) return NULL;	
	    
    // 2. until EOF or libc found
    for(;;) {
      // 3. read a line
      len = read_line(maps, line, BUFSIZ);
      if(len == 0) break;
      // 4. remove last character
      line[len] = 0;
      // if permissions disallow execution, skip it
      if(!is_exec(line)) {
        continue;
      }
      start_addr = (void*)hex2bin(line);
      // 5. first address should be the base of host process
      // if no module is requested, return this address
      if(module == 0) {
        base = start_addr;
        break;
      }
      // 6. check if module name is in line
      if(_strstr(line, module)) {
        base = start_addr;
        break;
      }
    }
    _close(maps);
    return base;
}

static uint32_t elf_hash(const uint8_t *name) {
    uint32_t h = 0, g;
    
    while (*name) {
      h = (h << 4) + *name++;
      g = h & 0xf0000000;
      if (g)
        h ^= g >> 24;
      h &= ~g;
    }
    return h;
}

static void *elf_lookup(
  const char *name, 
  uint32_t *hashtab, 
  Elf32_Sym *sym, 
  const char *str) 
{
    uint32_t  idx;
    uint32_t  nbuckets = hashtab[0];
    uint32_t* buckets  = &hashtab[2];
    uint32_t* chains   = &buckets[nbuckets];
    
    for(idx = buckets[elf_hash(name) % nbuckets]; 
        idx != 0; 
        idx = chains[idx]) 
    {
      // does string match for this index?
      if(!_strcmp(name, sym[idx].st_name + str))
        // return address of function
        return (void*)sym[idx].st_value;
    }
    return NULL;
}

#define ELFCLASS_BITS 32

static uint32_t gnu_hash(const uint8_t *name) {
    uint32_t h = 5381;

    for(; *name; name++) {
      h = (h << 5) + h + *name;
    }
    return h;
}

struct gnu_hash_table {
    uint32_t nbuckets;
    uint32_t symoffset;
    uint32_t bloom_size;
    uint32_t bloom_shift;
    uint32_t bloom[1];
    uint32_t buckets[1];
    uint32_t chain[1];
};

static void* gnu_lookup(
    const char* name,          /* symbol to look up */
    const void* hash_tbl,      /* hash table */
    const Elf32_Sym* symtab,   /* symbol table */
    const char* strtab         /* string table */
) {
    struct gnu_hash_table *hashtab = (struct gnu_hash_table*)hash_tbl;
    const uint32_t  namehash    = gnu_hash(name);

    const uint32_t  nbuckets    = hashtab->nbuckets;
    const uint32_t  symoffset   = hashtab->symoffset;
    const uint32_t  bloom_size  = hashtab->bloom_size;
    const uint32_t  bloom_shift = hashtab->bloom_shift;
    
    const uint32_t* bloom       = (void*)&hashtab->bloom;
    const uint32_t* buckets     = (void*)&bloom[bloom_size];
    const uint32_t* chain       = &buckets[nbuckets];

    uint32_t word = bloom[(namehash / ELFCLASS_BITS) % bloom_size];
    uint32_t mask = 0
        | (uint32_t)1 << (namehash % ELFCLASS_BITS)
        | (uint32_t)1 << ((namehash >> bloom_shift) % ELFCLASS_BITS);

    if ((word & mask) != mask) {
        return NULL;
    }

    uint32_t symix = buckets[namehash % nbuckets];
    if (symix < symoffset) {
        return NULL;
    }

    /* Loop through the chain. */
    for (;;) {
        const char* symname = strtab + symtab[symix].st_name;
        const uint32_t hash = chain[symix - symoffset];        
        if (namehash|1 == hash|1 && _strcmp(name, symname) == 0) {
            return (void*)symtab[symix].st_value;
        }
        if(hash & 1) break;
        symix++;
    }
    return 0;
}

static void *get_proc_address(void *module, const char *name) {
    Elf32_Dyn  *symtab, *strtab, *hash;
    Elf32_Sym  *syms;
    char       *strs;
    void       *addr = NULL;
    
    // 1. obtain pointers to string and symbol tables
    strtab = elf_get_dyn(module, DT_STRTAB);
    symtab = elf_get_dyn(module, DT_SYMTAB);
    
    if(strtab == NULL || symtab == NULL) return NULL;
    
    // 2. load virtual address of string and symbol tables
    strs = (char*)strtab->d_un.d_ptr;
    syms = (Elf32_Sym*)symtab->d_un.d_ptr;
    
    // 3. try obtain the ELF hash table
    hash = elf_get_dyn(module, DT_HASH);
    
    // 4. if we have it, lookup symbol by ELF hash
    if(hash != NULL) {
      addr = elf_lookup(name, (void*)hash->d_un.d_ptr, syms, strs);
    } else {
      // if we don't, try obtain the GNU hash table
      hash = elf_get_dyn(module, DT_GNU_HASH);
      if(hash != NULL) {
        addr = gnu_lookup(name, (void*)hash->d_un.d_ptr, syms, strs);
      }
    }
    // 5. did we find symbol? add base address and return
    if(addr != NULL) {
		Elf32_Phdr *phdr = elf_get_phdr(module, PT_LOAD);		
		addr = phdr != NULL ? (void*)((uint32_t)module + addr - phdr->p_vaddr) : 0;
    }
	
    return addr;
}