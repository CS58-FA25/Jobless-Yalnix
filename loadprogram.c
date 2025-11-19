#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <ykernel.h>
#include <load_info.h>

/*
 * ==>> #include anything you need for your kernel here
 */
#include "kernel.h"
#include "memory.h"

/*
 *  Load a program into an existing address space.  The program comes from
 *  the Linux file named "name", and its arguments come from the array at
 *  "args", which is in standard argv format.  The argument "proc" points
 *  to the process or PCB structure for the process into which the program
 *  is to be loaded. 
 */

/*
 * ==>> Declare the argument "proc" to be a pointer to the PCB of 
 * ==>> the current process. 
 */
int LoadProgram(char *name, char *args[], PCB* proc) 
{
    int fd;
    struct load_info li;
    int i;
    char *cp;
    char **cpp;
    char *cp2;
    int argcount;
    int size;
    int text_pg1;
    int data_pg1;
    int data_npg;
    int stack_npg;
    long segment_size;
    char *argbuf;

    /*
     * Open the executable file 
     */
    if ((fd = open(name, O_RDONLY)) < 0) {
        TracePrintf(0, "LoadProgram: can't open file '%s'\n", name);
        return ERROR;
    }

    if (LoadInfo(fd, &li) != LI_NO_ERROR) {
        TracePrintf(0, "LoadProgram: '%s' not in Yalnix format\n", name);
        close(fd);
        return ERROR;
    }

    if (li.entry < VMEM_1_BASE) {
        TracePrintf(0, "LoadProgram: '%s' not linked for Yalnix\n", name);
        close(fd);
        return ERROR;
    }

    /*
     * Figure out in what region 1 page the different program sections
     * start and end
     */
    text_pg1 = (li.t_vaddr - VMEM_1_BASE) >> PAGESHIFT;
    data_pg1 = (li.id_vaddr - VMEM_1_BASE) >> PAGESHIFT;
    data_npg = li.id_npg + li.ud_npg;

    /*
     *  Figure out how many bytes are needed to hold the arguments on
     *  the new stack that we are building.  Also count the number of
     *  arguments, to become the argc that the new "main" gets called with.
     */
    size = 0;
    for (i = 0; args[i] != NULL; i++) {
        TracePrintf(3, "counting arg %d = '%s'\n", i, args[i]);
        size += strlen(args[i]) + 1;
    }
    argcount = i;

    TracePrintf(2, "LoadProgram: argsize %d, argcount %d\n", size, argcount);
    
    /*
     *  The arguments will get copied starting at "cp", and the argv
     *  pointers to the arguments (and the argc value) will get built
     *  starting at "cpp".  The value for "cpp" is computed by subtracting
     *  off space for the number of arguments (plus 3, for the argc value,
     *  a NULL pointer terminating the argv pointers, and a NULL pointer
     *  terminating the envp pointers) times the size of each,
     *  and then rounding the value *down* to a double-word boundary.
     */
    cp = ((char *)VMEM_1_LIMIT) - size;

    cpp = (char **)(((int)cp - ((argcount + 3 + POST_ARGV_NULL_SPACE) * sizeof(void *))) & ~7);

    /*
     * Compute the new stack pointer, leaving INITIAL_STACK_FRAME_SIZE bytes
     * reserved above the stack pointer, before the arguments.
     */
    cp2 = (char*)cpp - INITIAL_STACK_FRAME_SIZE;

    TracePrintf(1, "prog_size %d, text %d data %d bss %d pages\n",
                li.t_npg + data_npg, li.t_npg, li.id_npg, li.ud_npg);

    /* 
     * Compute how many pages we need for the stack */
    stack_npg = (VMEM_1_LIMIT - DOWN_TO_PAGE(cp2)) >> PAGESHIFT;

    TracePrintf(1, "LoadProgram: heap_size %d, stack_size %d\n",
                li.t_npg + data_npg, stack_npg);

    /* leave at least one page between heap and stack */
    if (stack_npg + data_pg1 + data_npg >= (VMEM_1_SIZE / PAGESIZE)) {
        TracePrintf(0, "LoadProgram: stack would overlap heap\n");
        close(fd);
        return ERROR;
    }

    /*
     * This completes all the checks before we proceed to actually load
     * the new program.  From this point on, we are committed to either
     * loading succesfully or killing the process.
     */

    /*
     * Set the new stack pointer value in the process's UserContext
     */

    /* 
     * ==>> (rewrite the line below to match your actual data structure) 
     */
    proc->user_context.sp = cp2;

    /*
     * Now save the arguments in a separate buffer in region 0, since
     * we are about to blow away all of region 1.
     */
    cp2 = argbuf = (char *)malloc(size);

    /* 
     * ==>> You should perhaps check that malloc returned valid space 
     */
    if (argbuf == NULL) {
        TracePrintf(0, "LoadProgram: failed to allocate argument buffer\n");
        close(fd);
        return ERROR;
    }

    for (i = 0; args[i] != NULL; i++) {
        TracePrintf(3, "saving arg %d = '%s'\n", i, args[i]);
        strcpy(cp2, args[i]);
        cp2 += strlen(cp2) + 1;
    }

    /*
     * Set up the page tables for the process so that we can read the
     * program into memory.  Get the right number of physical pages
     * allocated, and set them all to writable.
     */

    /* ==>> Throw away the old region 1 virtual address space by
     * ==>> current process by walking through the R1 page table and,
     * ==>> for every valid page, free the pfn and mark the page invalid.
     */
    int num_pages = VMEM_1_SIZE / PAGESIZE;
    for (int vpn = 0; vpn < num_pages; vpn++) {
        if (proc->region1_ptbr[vpn].valid) {
            FreeFrame(proc->region1_ptbr[vpn].pfn);
            proc->region1_ptbr[vpn].valid = 0;
        }
    }

    /*
     * ==>> Then, build up the new region1.  
     * ==>> (See the LoadProgram diagram in the manual.)
     */

    /*
     * ==>> First, text. Allocate "li.t_npg" physical pages and map them starting at
     * ==>> the "text_pg1" page in region 1 address space.
     * ==>> These pages should be marked valid, with a protection of
     * ==>> (PROT_READ | PROT_WRITE).
     */
    for (int i = 0; i < li.t_npg; i++) {
        int pfn = AllocateFrame();
        if (pfn == ERROR) {
            TracePrintf(0, "LoadProgram: out of memory for text segment\n");
            free(argbuf);
            close(fd);
            return ERROR;
        }
        MapPage(proc->region1_ptbr, text_pg1 + i, pfn, PROT_READ | PROT_WRITE);
    }

    /*
     * ==>> Then, data. Allocate "data_npg" physical pages and map them starting at
     * ==>> the  "data_pg1" in region 1 address space.
     * ==>> These pages should be marked valid, with a protection of
     * ==>> (PROT_READ | PROT_WRITE).
     */
    for (int i = 0; i < data_npg; i++) {
        int pfn = AllocateFrame();
        if (pfn == ERROR) {
            TracePrintf(0, "LoadProgram: out of memory for data segment\n");
            free(argbuf);
            close(fd);
            return ERROR;
        }
        MapPage(proc->region1_ptbr, data_pg1 + i, pfn, PROT_READ | PROT_WRITE);
    }

    /* 
     * ==>> Then, stack. Allocate "stack_npg" physical pages and map them to the top
     * ==>> of the region 1 virtual address space.
     * ==>> These pages should be marked valid, with a
     * ==>> protection of (PROT_READ | PROT_WRITE).
     */
    int stack_start_vpn = (VMEM_1_SIZE / PAGESIZE) - stack_npg;
    for (int i = 0; i < stack_npg; i++) {
        int pfn = AllocateFrame();
        if (pfn == ERROR) {
            TracePrintf(0, "LoadProgram: out of memory for stack\n");
            free(argbuf);
            close(fd);
            return ERROR;
        }
        MapPage(proc->region1_ptbr, stack_start_vpn + i, pfn, PROT_READ | PROT_WRITE);
    }

    /*
     * ==>> (Finally, make sure that there are no stale region1 mappings left in the TLB!)
     */
    FlushRegion1TLB();

    /*
     * All pages for the new address space are now in the page table.  
     */

    /*
     * Read the text from the file into memory.
     */
    lseek(fd, li.t_faddr, SEEK_SET);
    segment_size = li.t_npg << PAGESHIFT;
    
    for (int i = 0; i < li.t_npg; i++) {
        int pfn = proc->region1_ptbr[text_pg1 + i].pfn;
        char* page_data = (char*)(pfn << PAGESHIFT);
        int bytes_to_read = PAGESIZE;
        if (read(fd, page_data, bytes_to_read) != bytes_to_read) {
            TracePrintf(0, "LoadProgram: failed to read text segment\n");
            free(argbuf);
            close(fd);
            return ERROR;
        }
    }

    /*
     * Read the data from the file into memory.
     */
    lseek(fd, li.id_faddr, 0);
    segment_size = li.id_npg << PAGESHIFT;

    for (int i = 0; i < li.id_npg; i++) {
        int pfn = proc->region1_ptbr[data_pg1 + i].pfn;
        char* page_data = (char*)(pfn << PAGESHIFT);
        int bytes_to_read = PAGESIZE;
        if (read(fd, page_data, bytes_to_read) != bytes_to_read) {
            TracePrintf(0, "LoadProgram: failed to read data segment\n");
            free(argbuf);
            close(fd);
            return ERROR;
        }
    }

    close(fd);			/* we've read it all now */

    /*
     * ==>> Above, you mapped the text pages as writable, so this code could write
     * ==>> the new text there.
     *
     * ==>> But now, you need to change the protections so that the machine can execute
     * ==>> the text.
     *
     * ==>> For each text page in region1, change the protection to (PROT_READ | PROT_EXEC).
     * ==>> If any of these page table entries is also in the TLB, 
     * ==>> you will need to flush the old mapping. 
     */
    for (int i = 0; i < li.t_npg; i++) {
        proc->region1_ptbr[text_pg1 + i].prot = PROT_READ | PROT_EXEC;
    }
    FlushRegion1TLB();
  
    /*
     * Zero out the uninitialized data area
     */
    for (int i = li.id_npg; i < data_npg; i++) {
        int pfn = proc->region1_ptbr[data_pg1 + i].pfn;
        char* page_data = (char*)(pfn << PAGESHIFT);
        memset(page_data, 0, PAGESIZE);
    }

    /*
     * Set the entry point in the process's UserContext
     */

    /* 
     * ==>> (rewrite the line below to match your actual data structure) 
     */
    proc->user_context.pc = (void*)li.entry;

    /*
     * Now, finally, build the argument list on the new stack.
     */

    proc->user_context.regs[0] = argcount;
    
    proc->user_context.regs[1] = (int)cpp;

    free(argbuf);

    TracePrintf(1, "LoadProgram: successfully loaded %s\n", name);
    TracePrintf(1, "  entry point: 0x%p\n", proc->user_context.pc);
    TracePrintf(1, "  stack pointer: 0x%p\n", proc->user_context.sp);
    TracePrintf(1, "  argc: %d\n", argcount);

    return SUCCESS;
}
