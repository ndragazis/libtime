#define _GNU_SOURCE
#include <link.h>
#undef _GNU_SOURCE
#include <stdlib.h>
#include <stdio.h>
#include <gelf.h>
#include <elf.h>
#include <string.h>
#include <time.h>
#include <sys/auxv.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <ctype.h>
#include <dlfcn.h>

#include "common.h"
#include "logging.h"


/*
 * Adapted from FreeBSD source (sys/sys/time.h)
 *
 * Operations on timespecs
 */
#define timespecclear(tvp)      ((tvp)->tv_sec = (tvp)->tv_nsec = 0)
#define timespeccmp(tvp, cmp, uvp)                              \
        (((tvp)->tv_sec == (uvp)->tv_sec) ?                     \
            ((tvp)->tv_nsec cmp (uvp)->tv_nsec) :               \
            ((tvp)->tv_sec cmp (uvp)->tv_sec))
#define timespecsub(vvp, uvp)                                   \
        do {                                                    \
                if (timespeccmp(vvp, >, uvp)) {                 \
                        (vvp)->tv_sec -= (uvp)->tv_sec;         \
                        (vvp)->tv_nsec -= (uvp)->tv_nsec;       \
                        if ((vvp)->tv_nsec < 0) {               \
                                (vvp)->tv_sec--;                \
                                (vvp)->tv_nsec += 1000000000;   \
                        }                                       \
                } else {                                        \
                        timespecclear(vvp);                     \
                }                                               \
        } while (0)


char *symbol;
void *ret_addr;
char *executable;
uintptr_t symbol_addr;
struct timespec __start, __end;

/*
 * Return nonzero if 'str' ends with 'suffix', zero otherwise.
 */
int strendswith(const char *str, const char *suffix)
{
        size_t str_len = strlen(str);
        size_t suffix_len = strlen(suffix);

	if (suffix_len > str_len) {
		return 0;
	}
	return strcmp(str + str_len - suffix_len, suffix) == 0;
}

/*
 * Measure and print the execution latency of a function.
 *
 * This is the universal latency wrapper. It can measure the latency of
 * any function that adheres to the calling conventions of the
 * System V x86_64 ABI:
 *
 * https://refspecs.linuxbase.org/elf/x86_64-abi-0.99.pdf
 * https://eli.thegreenplace.net/2011/09/06/stack-frame-layout-on-x86-64
 * https://wiki.osdev.org/Calling_Conventions
 *
 * It works as follows:
 *
 * 1.  Restore rbp to the stack frame of the calling function.
 * 2.  Pop the return address from the stack and save it for later use.
 * 3.  Save the 6 general-purpose registers destined for argument
 *     passing. These contain the arguments for the real function.
 * 4.  Get a timestamp.
 * 5.  Restore the 6 argument registers.
 * 6.  Call the real function.
 * 7.  When call finishes, save the rax and rdx registers which contain
 *     the return values.
 * 8.  Get another timestamp.
 * 9.  Calculate the latency based on the two timestamps.
 * 10. Print the latency.
 * 11. Restore rax and rdx.
 * 12. Jump to the return address.
 *
 */
static void print_latency(void)
{
	/*
	 * Restore rbp.
	 */
	__asm__ volatile
	(
	   "popq %rbp\n\t"
	);

	/*
	 * Pop the return address.
	 * Save it in a global variable so that we can restore it later.
	 */
	__asm__ volatile
	(
	    "popq %[from]\n\t"
	    : [from] "=m" (ret_addr)
	    : /* No inputs. */
	    : "memory"
	);

	/*
	 * Save the 6 registers that are used for argument passing.
	 * These contain the arguments for the real function.
	 */
	__asm__ volatile
	(
	   "pushq %rdi\n\t"
	   "pushq %rsi\n\t"
	   "pushq %rdx\n\t"
	   "pushq %rcx\n\t"
	   "pushq %r8\n\t"
	   "pushq %r9\n\t"
	);

	ensure(clock_gettime(CLOCK_MONOTONIC, &__start) == 0);

	/*
	 * Restore the 6 registers for argument passing before calling
	 * the real function.
	 */
	__asm__ volatile
	(
	   "popq %r9\n\t"
	   "popq %r8\n\t"
	   "popq %rcx\n\t"
	   "popq %rdx\n\t"
	   "popq %rsi\n\t"
	   "popq %rdi\n\t"
	);

	/*
	 * Call the real function. At this point, the state of the stack
	 * is *exactly* the same as before entering the current
	 * function. The only difference is that we have changed the
	 * return address that is on top of the stack so that the real
	 * function will return here and not to the caller function.
	 * The return address is pushed transparently by the "callq"
	 * assembly instruction below.
	 */
	__asm__ volatile
	(
	    "callq *%[real_symbol]\n\t"
	    : /* No outputs. */
	    : [real_symbol] "m" (symbol_addr)
	    : "memory"
	);

	/*
	 * Save the rax and rdx registers. In the x86_64 ABI these are
	 * the registers that are used for the return values.
	 */
	__asm__ volatile
	(
	   "pushq %rax\n\t"
	   "pushq %rdx\n\t"
	);

	/*
	 * At this point, the state of the stack is as if we have
	 * returned to the caller function. We are at the caller's stack
	 * at this point. So, we have to print the latency and return
	 * with "jmpq". We can't let the function return normally (i.e.,
	 * will "ret" because, in this case, it would try to restore the
	 * ebp and esp pointers which are already fixed. Also, it would
	 * try to pop the return address from the stack, so we would
	 * first have to push the return address to the stack.
	 */

	ensure(clock_gettime(CLOCK_MONOTONIC, &__end) == 0);
	timespecsub(&__end, &__start);
	if (__end.tv_sec > 0) {
		pr_info("Waited for %s for %ld sec and %ld"
		        " nsec\n", symbol, __end.tv_sec, __end.tv_nsec);
	} else {
		pr_info("Waited for %s for %ld nsec\n", symbol,
			__end.tv_nsec);
	}

	/*
	 * Restore the rax and rdx registers and jump to the return
	 * address.
	 */
	__asm__ volatile
	(
	    "movq %[to], %%rcx\n\t"
	    "popq %%rdx\n\t"
	    "popq %%rax\n\t"
	    "jmp *%%rcx\n\t"
	    : /* No outputs. */
	    : [to] "m" (ret_addr)
	    : "memory"
	);
}
#if 0
/*
 * Print timestamps prior to and after the execution of a function.
 */
static void print_timestamps()
{

}
#endif
static char *parse_symbol_name(void)
{
	return getenv("SYMBOL");
}

static char *phdr_type_to_str(ElfW(Word) phdr_type)
{
	if (phdr_type == PT_LOAD)
		return "PT_LOAD";
	else if (phdr_type == PT_DYNAMIC)
		return "PT_DYNAMIC";
	else if (phdr_type == PT_INTERP)
		return "PT_INTERP";
	else if (phdr_type == PT_NOTE)
		return "PT_NOTE";
	else if (phdr_type == PT_SHLIB)
		return "PT_SHLIB";
	else if (phdr_type == PT_PHDR)
		return "PT_PHDR";
	else if (phdr_type == PT_TLS)
		return "PT_TLS";
	else if (phdr_type == PT_GNU_EH_FRAME)
		return "PT_GNU_EH_FRAME";
	else if (phdr_type == PT_GNU_STACK)
		return "PT_GNU_STACK";
	else if (phdr_type == PT_GNU_RELRO)
		return "PT_GNU_RELRO";
	else
		return "Invalid Program Header type";

}

static char *dyn_entry_tag_to_str(ElfW(Sword) dyn_tag)
{
	if (dyn_tag == DT_NULL)
		return "DT_NULL";
	else if (dyn_tag == DT_NEEDED)
		return "DT_NEEDED";
	else if (dyn_tag == DT_PLTRELSZ)
		return "DT_PLTRELSZ";
	else if (dyn_tag == DT_PLTGOT)
		return "DT_PLTGOT";
	else if (dyn_tag == DT_HASH)
		return "DT_HASH";
	else if (dyn_tag == DT_STRTAB)
		return "DT_STRTAB";
	else if (dyn_tag == DT_SYMTAB)
		return "DT_SYMTAB";
	else if (dyn_tag == DT_RELA)
		return "DT_RELA";
	else if (dyn_tag == DT_RELASZ)
		return "DT_RELASZ";
	else if (dyn_tag == DT_RELAENT)
		return "DT_RELAENT";
	else if (dyn_tag == DT_STRSZ)
		return "DT_STRSZ";
	else if (dyn_tag == DT_SYMENT)
		return "DT_SYMENT";
	else if (dyn_tag == DT_INIT)
		return "DT_INIT";
	else if (dyn_tag == DT_FINI)
		return "DT_FINI";
	else if (dyn_tag == DT_SONAME)
		return "DT_SONAME";
	else if (dyn_tag == DT_RPATH)
		return "DT_RPATH";
	else if (dyn_tag == DT_SYMBOLIC)
		return "DT_SYMBOLIC";
	else if (dyn_tag == DT_REL)
		return "DT_REL";
	else if (dyn_tag == DT_RELSZ)
		return "DT_RELSZ";
	else if (dyn_tag == DT_RELENT)
		return "DT_RELENT";
	else if (dyn_tag == DT_PLTREL)
		return "DT_PLTREL";
	else if (dyn_tag == DT_DEBUG)
		return "DT_DEBUG";
	else if (dyn_tag == DT_TEXTREL)
		return "DT_TEXTREL";
	else if (dyn_tag == DT_JMPREL)
		return "DT_JMPREL";
	else if (dyn_tag == DT_BIND_NOW)
		return "DT_BIND_NOW";
	else if (dyn_tag == DT_INIT_ARRAY)
		return "DT_INIT_ARRAY";
	else if (dyn_tag == DT_FINI_ARRAY)
		return "DT_FINI_ARRAY";
	else if (dyn_tag == DT_INIT_ARRAYSZ)
		return "DT_INIT_ARRAYSZ";
	else if (dyn_tag == DT_FINI_ARRAYSZ)
		return "DT_FINI_ARRAYSZ";
	else if (dyn_tag == DT_RUNPATH)
		return "DT_RUNPATH";
	else if (dyn_tag == DT_FLAGS)
		return "DT_FLAGS";
	else if (dyn_tag == DT_FLAGS_1)
		return "DT_FLAGS_1";
	else if (dyn_tag == DT_ENCODING)
		return "DT_ENCODING";
	else if (dyn_tag == DT_PREINIT_ARRAY)
		return "DT_PREINIT_ARRAY";
	else if (dyn_tag == DT_PREINIT_ARRAYSZ)
		return "DT_PREINIT_ARRAYSZ";
	else if (dyn_tag == DT_NUM)
		return "DT_NUM";
	else if (dyn_tag == DT_GNU_HASH)
		return "DT_GNU_HASH";
	else if (dyn_tag == DT_VERSYM)
		return "DT_VERSYM";
	else if (dyn_tag == DT_RELACOUNT)
		return "DT_RELACOUNT";
	else if (dyn_tag == DT_RELCOUNT)
		return "DT_RELCOUNT";
	else if (dyn_tag == DT_VERDEF)
		return "DT_VERDEF";
	else if (dyn_tag == DT_VERDEFNUM)
		return "DT_VERDEFNUM";
	else if (dyn_tag == DT_VERNEED)
		return "DT_VERNEED";
	else if (dyn_tag == DT_VERNEEDNUM)
		return "DT_VERNEEDNUM";
	else if (dyn_tag >= DT_LOOS && dyn_tag <= DT_HIOS)
		return "OS-specific Dynamic Entry type";
	else if (dyn_tag >= DT_LOPROC && dyn_tag <= DT_HIPROC)
		return "Processor-specific Dynamic Entry type";
	else
		return "Invalid Dynamic Entry type";
}

char *sym_name_from_symtab(uint64_t symtab_idx, ElfW(Addr) symtab_addr, ElfW(Addr) strtab_addr)
{
	ElfW(Sym) *sym = ((ElfW(Sym) *)symtab_addr) + symtab_idx;
	uint32_t strtab_idx = sym->st_name;
	/* Ensure that the symbol has a name. */
	ensure(strtab_idx != 0);
	/* Ensure that this is a function or it has no type. */
	ensure(GELF_ST_TYPE(sym->st_info) & STT_FUNC ||
	       GELF_ST_TYPE(sym->st_info) == STT_NOTYPE);
	/*
	 * Ensure that this is an undefined symbol.
	 *
	 * The st_shndx holds the section header index, that is an index
	 * into the section header table. It can also take some special
	 * index values: SHN_ABS, SHN_COMMON, SHN_UNDEF, SHN_XINDEX.
	 *
	 * The st_value holds either alignment constraints for symbols
	 * whose section index is SHN_COMMON, or a section offset (from
	 * the beginning of the section that st_shndx identifies) for
	 * defined symbols.
	 *
	 * In our case here, we expect this symbol to be an undefined
	 * symbol, so the st_value must be zero and the st_shndx must be
	 * SHN_UNDEF.
	 *
	 * Source for the above:
	 * https://refspecs.linuxbase.org/elf/gabi4+/ch4.symtab.html
	 */
	//if (sym->st_value != 0 || sym->st_shndx != SHN_UNDEF)
	//	return NULL;

	/*
	 * Find the name from the string table. The string table is an
	 * array of NULL-terminated strings. The indexes stored in the
	 * symbol table are just byte offsets in the string table.
	 */
	return ((char *)strtab_addr) + strtab_idx;
}

static void read_string(int fd, char *buf, char terminating_char)
{
	int pos = -1;
	do {
		ensure(read(fd, &buf[++pos], 1) == 1);
	} while (buf[pos] != terminating_char);
}

static char *trimspaceprefix(char *str)
{
	while (isspace(*str))
		str++;

	return str;
}

static int has_write_permissions(uintptr_t page_addr)
{
	int ret;
	int pos;
	int maps_fd;
	char buf[1024];
	int is_writable;
	char *invalid_char;
	char permissions[5];
	char device[6];
	char pathname[1024];
	unsigned long start_addr, end_addr, offset, inode;

	is_writable = 0;

	maps_fd = open("/proc/self/maps", O_RDONLY);
	if (maps_fd < 0) {
		pr_debug("open(\"/proc/self/maps\", O_RDONLY) failed"
			" with %d (%s)\n", errno, strerror(errno));
		exit(1);
	}

	while (1) {

		/* Read start address for the mapping. */
		read_string(maps_fd, buf, '-');
		start_addr = strtoul(buf, &invalid_char, 16);
		//pr_debug("Invalid char: %c\n", *invalid_char);
		ensure(*invalid_char == '-');

		/* Read end address for the mapping. */
		read_string(maps_fd, buf, ' ');
		end_addr = strtoul(buf, &invalid_char, 16);
		//pr_debug("Invalid char: %c\n", *invalid_char);
		ensure(*invalid_char == ' ');

		/* Read the permissions for the mapping (including the space. */
		ensure(read(maps_fd, permissions, 5) == 5);
		ensure(permissions[4] == ' ');
		permissions[4] = '\0';

		/* Read the offset. */
		read_string(maps_fd, buf, ' ');
		offset = strtoul(buf, &invalid_char, 16);
		ensure(*invalid_char == ' ');

		/* Read the device (including the space). */
		ensure(read(maps_fd, device, 6) == 6);
		ensure(device[5] == ' ');
		device[5] = '\0';

		/* Read the inode. */
		read_string(maps_fd, buf, ' ');
		inode = strtoul(buf, &invalid_char, 16);
		ensure(*invalid_char == ' ');

		/* Read the pathname. */
		pos = -1;
		do {
			ret = read(maps_fd, &pathname[++pos], 1);
		} while (pathname[pos] != '\n' && ret != 0);
		pathname[pos] = '\0';

		if (page_addr < start_addr || page_addr >= end_addr)
			continue;

		pr_debug("matching mapping:\naddr range: [0x%lx-0x%lx],"
		        " permissions: %s, offset: %lu, device: %s,"
			" inode: %lu, pathname: %s\n", start_addr,
			end_addr, permissions, offset, device, inode,
			trimspaceprefix(pathname));

		/* Check if the mapping has W permissions. */
		for (int i = 0; i < 5; i++) {
			if (permissions[i] == 'w') {
				is_writable = 1;
				goto out;
			}
		}
		break;
	}

out:
	close(maps_fd);
	return is_writable;
}

static int hijack_undefined_symbol_references(struct dl_phdr_info *info, size_t size, void *data)
{
	const char *pathname;
	char *symbol = (char *)data;
	/* Program header for DYNAMIC segment. */
	const ElfW(Phdr) *dynamic_phdr = NULL;
	/* Address of DYNAMIC segment. */
	ElfW(Addr) dynamic_seg_addr;
	/* Size of DYNAMIC segment. */
	int __attribute__((unused)) dynamic_seg_size;
	ElfW(Dyn) *dyn_entry;
	/* Address of PLT relocation table. */
	ElfW(Addr) jmprel_addr = 0;
	/* Size of PLT relocation table. */
	int jmprel_size = 0;
	/* Type of PLT relocations. */
	int __attribute__((unused)) jmprel_type;
	/* Size in bytes of each relocation entry. */
	int jmprel_entry_size = 0;
	int dyn_flags = 0;
	int dyn_flags_1 = 0;
	/* Address of dynamic symbol table. */
	ElfW(Addr) symtab_addr = 0;
	/* Address of string table. */
	ElfW(Addr) strtab_addr = 0;
	ElfW(Addr) got_addr = 0;
	int relro_enabled = 0;
	int bind_now_enabled = 0;

	pathname = *info->dlpi_name != '\0' ? info->dlpi_name : executable;

	if (strendswith(pathname, "libtime.so")) {
		pr_debug("Skipping object libtime.so\n");
		return 0;
	}

	pr_debug("Inspecting object: %s\n", pathname);
	pr_debug("Base address of the object: %lx\n", info->dlpi_addr);

	/*
	 * Go over the list of segments in the Program Header Table.
	 * Find the program header for the dynamic segment.
	 * If there is no dynamic segment, i.e., this is a static
	 * executable, then we cannot hijack any symbol.
	 */
	pr_debug("Inspecting Program Headers...\n");
	for (int i = 0; i < info->dlpi_phnum; i++) {
	        char *phdr_type = phdr_type_to_str(info->dlpi_phdr[i].p_type);
		pr_debug("Program Header Type: %s\n", phdr_type);
		if (info->dlpi_phdr[i].p_type == PT_DYNAMIC) {
			/*
			 * We found the program header for the dynamic
			 * segment.
			 */
			dynamic_phdr = &info->dlpi_phdr[i];
		} else if (info->dlpi_phdr[i].p_type == PT_GNU_RELRO) {
			/* This object has RELRO enabled.*/
			pr_debug("This object has RELRO enabled.\n");
			relro_enabled = 1;
		}
	}
	if (relro_enabled == 0)
		pr_debug("This object has RELRO disabled.\n");

	if (dynamic_phdr == NULL) {
		/*
		 * This object does not contain any dynamic segment,
		 * i.e., it is a static object. We cannot hijack any
		 * symbols.
		 */
		pr_error("Object %s does not contain a dynamic"
			" segment, i.e. it is a static object. libtime"
			" can be used only for dynamic objects.\n",
			pathname);
		exit(1);
	}

	/*
	 * Find the address and size of the dynamic segment in program's
	 * memory.
	 */
	dynamic_seg_addr = info->dlpi_addr + dynamic_phdr->p_vaddr;
	dynamic_seg_size = dynamic_phdr->p_memsz;

	/*
	 * Inspect the entries in the dynamic segment and find the
	 * relocations for the PLT.
	 * https://docs.oracle.com/cd/E23824_01/html/819-0690/chapter6-42444.html
	 */
	pr_debug("Inspecting the entries in the Dynamic Segment...\n");
	dyn_entry = (ElfW(Dyn) *)dynamic_seg_addr;
	while (1) {
		if (dyn_entry->d_tag == DT_JMPREL) {
			/* Get the address of the PLT relocations. */
			jmprel_addr = dyn_entry->d_un.d_ptr;
			if (jmprel_addr < info->dlpi_addr)
				/*
				 * Make the address absolute (necessary
				 * for musl dynamic linker).
				 */
				jmprel_addr += info->dlpi_addr;
		} else if (dyn_entry->d_tag == DT_PLTRELSZ)
			/* Get the total size of the PLT relocations. */
			jmprel_size = dyn_entry->d_un.d_val;
		else if (dyn_entry->d_tag == DT_PLTREL)
			/* Get the type of PLT relocations. */
			jmprel_type = dyn_entry->d_un.d_val;
		else if (dyn_entry->d_tag == DT_RELENT ||
			dyn_entry->d_tag == DT_RELAENT)
			/* Get the size in bytes of each relocation entry. */
			jmprel_entry_size = dyn_entry->d_un.d_val;
		else if (dyn_entry->d_tag == DT_SYMTAB) {
			/* Get the address of the dynamic symbol table. */
			symtab_addr = dyn_entry->d_un.d_ptr;
			if (symtab_addr < info->dlpi_addr)
				symtab_addr += info->dlpi_addr;
		} else if (dyn_entry->d_tag == DT_STRTAB) {
			/* Get the address of the string table. */
			strtab_addr = dyn_entry->d_un.d_ptr;
			if (strtab_addr < info->dlpi_addr)
			strtab_addr += info->dlpi_addr;
		} else if (dyn_entry->d_tag == DT_FLAGS)
			/* Get the flags. */
			dyn_flags = dyn_entry->d_un.d_val;
		else if (dyn_entry->d_tag == DT_FLAGS_1)
			/* Get the flags. */
			dyn_flags_1 = dyn_entry->d_un.d_val;
		else if (dyn_entry->d_tag == DT_NULL)
			break;
		pr_debug("Dynamic Entry Type: %s\n", dyn_entry_tag_to_str(dyn_entry->d_tag));
		dyn_entry++;
	}

	if (jmprel_addr == 0 || jmprel_size == 0 || jmprel_entry_size == 0) {
		pr_debug("Missing information from the dynamic"
			" segment. Skip this object.\n");
		return 0;
	}

	if ((dyn_flags & DF_BIND_NOW) || (dyn_flags_1 & DF_1_NOW) ||
		(getenv("LD_BIND_NOW") != NULL)) {
		pr_debug("This object has BIND_NOW enabled.\n");
		bind_now_enabled = 1;
	}

	/*
	 * Now we know where the relocation entries for the PLT are
	 * located. Find the relocation entry for the symbol in
	 * question.
	 * (see section "Relocation entries" in "man 5 elf")
	 *
	 * Note that relocations are architecture-specific and the
	 * following code works for x86_64 relocations. For the
	 * definition of the x86_64 relocation types, have a look at
	 * this document:
	 * https://refspecs.linuxbase.org/elf/x86_64-abi-0.99.pdf
	 */
	pr_debug("Inspecting the relocations for the PLT...\n");
	pr_debug("Entering the loop\n");
	uint64_t symtab_idx;
	for (int i = 0; i < (jmprel_size / jmprel_entry_size); i++) {
		pr_debug("jmprel_addr: %lx, i: %d\n", jmprel_addr, i);
		ElfW(Rel) *rel = (void *)jmprel_addr + i*jmprel_entry_size;
		pr_debug("Relocation entry: type: %ld\n", GELF_R_TYPE(rel->r_info));
		/* Skip relocations that are not of type JUMP_SLOT. */
		if (GELF_R_TYPE(rel->r_info) != R_X86_64_JUMP_SLOT)
			continue;
		/* Get the symbol table index for this relocation. */
		symtab_idx = GELF_R_SYM(rel->r_info);
		/*
		 * Find the symbol name from the entry in the symbol
		 * table.
		 */
		char *symname = sym_name_from_symtab(symtab_idx,
				symtab_addr, strtab_addr);
		if (symname == NULL)
			continue;
		pr_debug("Symbol name for this relocation entry: %s\n", symname);

		/* Check if this is the symbol we are looking for. */
		if (strcmp(symname, symbol) != 0)
			/*
			 * This is not our symbol. Move on to the next
			 * one.
			 */
			continue;

		/*
		 * This is our symbol. Save the virtual address of
		 * its GOT entry.
		 */
		pr_debug("We found a GOT entry for our symbol in this object!\n");
		got_addr = info->dlpi_addr + rel->r_offset;
		break;
		/*
		 * TODO: If this is a RELA PLT, make sure that the addend is
		 * zero. The addend should always be zero for JUMP_SLOT
		 * relocation types.
		 */
	}

	pr_debug("GOT address: %lx, index in the dynamic symbol table"
		" (.dynsym): %ld\n", got_addr, symtab_idx);

	if (got_addr == 0) {
		/*
		 * The current object has no undefined references to the
		 * symbol in question.
		 */
		return 0;
	}

	/*
	 * Change the address in the GOT entry so that it points to our
	 * latency wrapper function. But should I store an absolute
	 * address or just an offset?
	 *
	 * This involves the following steps:
	 * 1. Save the current value of the GOT entry. This should be
	 *    the address of the real symbol (assuming that the dynamic
	 *    linker has resolved all relocations at startup).
	 * 2. If RELRO is enabled for this object, assign write
	 *    permissions to the corresponding memory page so that we
	 *    can overwite this GOT entry. If RELRO is disabled for this
	 *    object, then write permissions should already be there and
	 *    we can just ignore this step and step (4).
	 * 3. Overwrite the GOT entry with our latency wrapper function.
	 * 4. If RELRO is enabled for this object, remove the write
	 *    permissions from the memory page. Otherwise, ignore this
	 *    step.
	 */

	/* 1. Save the current value of the GOT entry. */
	if (!bind_now_enabled) {
		pr_debug("Object %s uses lazy binding."
			" Finding the symbol address with dlsym...\n",
			pathname);
		symbol_addr = (uintptr_t) dlsym(RTLD_NEXT, symbol);
		if (symbol_addr == 0) {
			pr_error("%s\n", dlerror());
			exit(EXIT_FAILURE);
		}
		pr_debug("Symbol address: %lx\n", symbol_addr);
	} else {
		symbol_addr = *((uintptr_t *)got_addr);
	}

	/*
	 * 2. If RELRO is enabled:
	 *    Check if RELRO is indeed enforced, i.e., if the memory
	 *    page does not have W permissions. If not, assign W
	 *    permissions to the memory page.
	 */
	int pagesize = getpagesize();
	void *page_addr = (void *)(got_addr - (got_addr % pagesize));
	/* Check if the memory page has W permissions. */
	if (has_write_permissions((uintptr_t)page_addr)) {
		pr_debug("Page already has W permissions.\n");
		relro_enabled = 0;
	}
	/* Assign W permissions to the memory page if necessary. */
	if (relro_enabled) {
		pr_debug("Setting RW permissions for page %lx...\n", (uintptr_t)page_addr);
		ensure(mprotect(page_addr, pagesize, PROT_READ | PROT_WRITE) == 0);
	}

	/* 3. Overwrite the GOT entry with our latency wrapper function. */
	*((uintptr_t *)got_addr) = (uintptr_t)print_latency;
	pr_debug("And we just hacked it!"
	        " [real symbol addr: %lx, wrapper symbol addr: %lx]\n",
		(uintptr_t)symbol_addr, (uintptr_t)print_latency);

	/*
	 * 4. If RELRO is enabled, remove the write permissions from the
	 *    memory page.
	 */
	if (relro_enabled) {
		pr_debug("Setting R permissions for page %lx...\n", (uintptr_t)page_addr);
		ensure(mprotect(page_addr, pagesize, PROT_READ) == 0);
	}

	return 0;
}

void find_symbol(char *symbol)
{
	pr_debug("Traversing the loaded objects...\n");
	dl_iterate_phdr(hijack_undefined_symbol_references, symbol);
}

__attribute__ ((constructor)) static void hijack_symbol(void)
{
	int debug = 0;
	char *debug_str = getenv("DEBUG");
	char *output_str = getenv("OUTPUT");
	if (debug_str != NULL)
		debug = 1;
	setup_logging(debug, output_str);

	symbol = parse_symbol_name();
	if (symbol == NULL) {
		pr_error("No symbols to measure.\n");
		return;
	}

	/* Find name of executable. We will need it for later. */
	executable = (char *)getauxval(AT_EXECFN);
	ensure(executable != 0);

	/* Find address of symbol. */
	find_symbol(symbol);
}
