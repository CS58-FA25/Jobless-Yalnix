#include "kernel.h"
#include "memory.h"
#include "process.h"

void InitializeMemorySubsystem(unsigned int pmem_size) {
    // Step 1: Calculate total number of physical memory frames
    kernel_state.total_frames = pmem_size / PAGESIZE;
    
    // Step 2: Allocate bitmap for tracking free or used frames
    int bitmap_size = (kernel_state.total_frames + 7) / 8;
    kernel_state.free_frame_bitmap = (unsigned long*)malloc(bitmap_size);
    if (kernel_state.free_frame_bitmap == NULL) {
        TracePrintf(0, "Failed to allocate frame bitmap\n");
        Halt();
    }
    
    // Step 3: Initialize all frames as free (set as 1)
    memset(kernel_state.free_frame_bitmap, 0xFF, bitmap_size);
    kernel_state.used_frames = 0;
    
    // Step 4: Build initial page table for Region 0
    BuildInitialRegion0PageTable();
    
    // Step 5: Set initial kernel heap break pointer
    kernel_brk = (void*)((GET_ORIG_KERNEL_BRK_PAGE() << PAGESHIFT) + VMEM_0_BASE);
    
    TracePrintf(1, "Memory subsystem initialized: %d frames, kernel brk at %p\n",
                kernel_state.total_frames, kernel_brk);
}

void BuildInitialRegion0PageTable() {
    // Step 1: Allocate memory for Region 0 page table entries
    kernel_state.region0_ptlr = VMEM_0_SIZE / PAGESIZE;
    kernel_state.region0_ptbr = (pte_t*)malloc(kernel_state.region0_ptlr * sizeof(pte_t));
    if (kernel_state.region0_ptbr == NULL) {
        TracePrintf(0, "Failed to allocate Region 0 page table\n");
        Halt();
    }
    
    // Get build-provided values from yalnix.h
    int first_kernel_text_page = GET_FIRST_KERNEL_TEXT_PAGE();
    int first_kernel_data_page = GET_FIRST_KERNEL_DATA_PAGE(); 
    int orig_kernel_brk_page = GET_ORIG_KERNEL_BRK_PAGE();
    
    TracePrintf(1, "Kernel pages: text=%d, data=%d, brk=%d\n",
                first_kernel_text_page, first_kernel_data_page, orig_kernel_brk_page);
    
    // Step 2: Initialize all page table entries as invalid
    for (int vpn = 0; vpn < kernel_state.region0_ptlr; vpn++) {
        kernel_state.region0_ptbr[vpn].valid = 0;
        kernel_state.region0_ptbr[vpn].pfn = 0;
        kernel_state.region0_ptbr[vpn].prot = 0;
    }

    // Step 3: Create identity mapping for kernel text, data, and heap regions
    // Map kernel text region (read-only, executable)
    for (int vpn = first_kernel_text_page; vpn < first_kernel_data_page; vpn++) {
        kernel_state.region0_ptbr[vpn].valid = 1;
        kernel_state.region0_ptbr[vpn].pfn = vpn;  // Identity mapping
        kernel_state.region0_ptbr[vpn].prot = PROT_READ | PROT_EXEC;
        MarkFrameUsed(vpn);
        TracePrintf(2, "Mapped kernel text: VPN %d -> PFN %d (READ|EXEC)\n", vpn, vpn);
    }
    
    // Map kernel data/heap region (read-write)
    for (int vpn = first_kernel_data_page; vpn < orig_kernel_brk_page; vpn++) {
        kernel_state.region0_ptbr[vpn].valid = 1;
        kernel_state.region0_ptbr[vpn].pfn = vpn;  // Identity mapping
        kernel_state.region0_ptbr[vpn].prot = PROT_READ | PROT_WRITE;
        MarkFrameUsed(vpn);
        TracePrintf(2, "Mapped kernel data: VPN %d -> PFN %d (READ|WRITE)\n", vpn, vpn);
    }

    // Step 4: Map kernel virtual pages to same physical frames
    // Set up kernel stack area (initially unmapped - will be mapped per-process)
    int kernel_stack_vpn = (KERNEL_STACK_BASE - VMEM_0_BASE) >> PAGESHIFT;
    int kernel_stack_pages = KERNEL_STACK_MAXSIZE / PAGESIZE;
    
    for (int i = 0; i < kernel_stack_pages; i++) {
        kernel_state.region0_ptbr[kernel_stack_vpn + i].valid = 0;  // Unmapped initially
        TracePrintf(2, "Kernel stack page %d (VPN %d) initially unmapped\n", 
                   i, kernel_stack_vpn + i);
    }
    
    // Set up red zone below kernel stack (unmapped to catch stack overflows)
    int red_zone_vpn = kernel_stack_vpn - 1;
    kernel_state.region0_ptbr[red_zone_vpn].valid = 0;
    TracePrintf(2, "Red zone at VPN %d (unmapped)\n", red_zone_vpn);
    
    TracePrintf(1, "Region 0 page table complete:\n");
    TracePrintf(1, "  - Text:   VPN [%d, %d) -> READ|EXEC\n", 
                first_kernel_text_page, first_kernel_data_page);
    TracePrintf(1, "  - Data:   VPN [%d, %d) -> READ|WRITE\n", 
                first_kernel_data_page, orig_kernel_brk_page);
    TracePrintf(1, "  - Stack:  VPN [%d, %d) -> per-process mapping\n",
                kernel_stack_vpn, kernel_stack_vpn + kernel_stack_pages);
}

pte_t* CreateEmptyPageTable(int num_pages) {
    // Step 1: Allocate memory for page table structure
    pte_t* page_table = (pte_t*)malloc(num_pages * sizeof(pte_t));
    if (page_table == NULL) return NULL;
    
    // Step 2: Initialize all entries as invalid/unmapped
    for (int i = 0; i < num_pages; i++) {
        page_table[i].valid = 0;
        page_table[i].pfn = 0;
        page_table[i].prot = 0;
    }
    
    return page_table;
}

pte_t* CopyPageTable(pte_t* src, int num_pages) {
    // Step 1: Create new empty page table
    pte_t* dest = CreateEmptyPageTable(num_pages);
    if (dest == NULL) return NULL;
    
    // Step 2: Copy valid mappings from source to destination
    for (int vpn = 0; vpn < num_pages; vpn++) {
        if (src[vpn].valid) {
            // For fork(), we need to copy-on-write or duplicate the frame
            // For now, implement copy-on-write by marking both pages as read-only
            dest[vpn].valid = 1;
            dest[vpn].pfn = src[vpn].pfn;  // Share the same frame
            dest[vpn].prot = PROT_READ;     // Mark as read-only for CoW
            
            // Mark source as read-only too
            src[vpn].prot = PROT_READ;
            
            TracePrintf(2, "Copied mapping: VPN %d -> PFN %d (READ-ONLY for CoW)\n", 
                        vpn, src[vpn].pfn);
        }
    }
    
    return dest;
}

void MapPage(pte_t* page_table, int vpn, int pfn, int prot) {
    // Set up page table entry with mapping information
    page_table[vpn].valid = 1;
    page_table[vpn].pfn = pfn;
    page_table[vpn].prot = prot;
    
    TracePrintf(2, "Mapped VPN %d to PFN %d with prot 0x%x\n", vpn, pfn, prot);
}

void UnmapPage(pte_t* page_table, int vpn) {
    // Step 1: Check if page is currently mapped
    if (page_table[vpn].valid) {
        // Step 2: Clear the page table entry
        page_table[vpn].valid = 0;
        page_table[vpn].pfn = 0;
        page_table[vpn].prot = 0;
        TracePrintf(2, "Unmapped VPN %d\n", vpn);
    }
}

int IsPageMapped(pte_t* page_table, int vpn) {
    return page_table[vpn].valid;  // Return 1 if page is mapped/valid
}

int AllocateFrame() {
    // Step 1: Search for first free frame in the bitmap
        // Step 2: Mark frame as used and update counters
        // Return allocated frame number
    for (int pfn = 0; pfn < kernel_state.total_frames; pfn++) {
        if (IsFrameFree(pfn)) {
            MarkFrameUsed(pfn);
            kernel_state.used_frames++;
            TracePrintf(3, "Allocated frame %d, used: %d/%d\n",
                       pfn, kernel_state.used_frames, kernel_state.total_frames);
            return pfn;
        }
    }
    
    // Step 3: No free frames available, then out of memory
    TracePrintf(0, "No free frames available! Used: %d/%d\n",
               kernel_state.used_frames, kernel_state.total_frames);
    return ERROR;
}

void FreeFrame(int pfn) {
    // Validate frame number
    if (pfn < 0 || pfn >= kernel_state.total_frames) {
        TracePrintf(0, "FreeFrame: invalid frame %d\n", pfn);
        return;
    }
    MarkFrameFree(pfn);
    kernel_state.used_frames--;
    TracePrintf(3, "Freed frame %d, used: %d/%d\n",
                pfn, kernel_state.used_frames, kernel_state.total_frames);
}

// Bitmap operations for frame tracking
int IsFrameFree(int pfn) {
    
    // Step 1: Calculate byte and bit position in bitmap
    if (pfn < 0 || pfn >= kernel_state.total_frames) return 0;

    int byte_index = pfn / 8;
    int bit_index = pfn % 8;
    
    // Step 2: Check if the corresponding bit is set
    return (kernel_state.free_frame_bitmap[byte_index] >> bit_index) & 1;
}

void MarkFrameUsed(int pfn) {
    if (pfn < 0 || pfn >= kernel_state.total_frames) return;
    
    // Step 1: Calculate byte and bit position
    int byte_index = pfn / 8;
    int bit_index = pfn % 8;
    
    // Step 2: Clear the bit (0 = used, 1 = free)
    kernel_state.free_frame_bitmap[byte_index] &= ~(1 << bit_index);
}

void MarkFrameFree(int pfn) {
    if (pfn < 0 || pfn >= kernel_state.total_frames) return;
    
    // Step 1: Calculate byte and bit position
    int byte_index = pfn / 8;
    int bit_index = pfn % 8;
    
    // Step 2: Set the bit (1 = free)
    kernel_state.free_frame_bitmap[byte_index] |= (1 << bit_index);
}

int* AllocateKernelStackFrames() {
    // Step 1: Calculate number of frames needed for kernel stack
    int num_frames = KERNEL_STACK_MAXSIZE / PAGESIZE;
    int* frames = (int*)malloc(num_frames * sizeof(int));
    if (frames == NULL) return NULL;
    
    // Step 2: Allocate physical frames for kernel stack
    for (int i = 0; i < num_frames; i++) {
        frames[i] = AllocateFrame();
        if (frames[i] == ERROR) {
            // Clean up already allocated frames
            for (int j = 0; j < i; j++) {
                FreeFrame(frames[j]);
            }
            free(frames);
            return NULL;
        }
    }
    
    return frames;
}

void FreeKernelStackFrames(int* frames) {
    if (frames == NULL) return;
    
    // Step 1: Free all physical frames used by kernel stack
    int num_frames = KERNEL_STACK_MAXSIZE / PAGESIZE;
    for (int i = 0; i < num_frames; i++) {
        if (frames[i] != ERROR) {
            FreeFrame(frames[i]);
        }
    }
    
    // Step 2: Free the frames array itself
    free(frames);
}

void CopyKernelStack(PCB* src, PCB* dest) {
    if (src == NULL || dest == NULL) {
        TracePrintf(0, "CopyKernelStack: NULL PCB\n");
        return;
    }
    
    TracePrintf(2, "CopyKernelStack: copying from PID %d to new process\n", src->pid);
    
    // Find kernel stack VPN in Region 0
    int kernel_stack_vpn = (KERNEL_STACK_BASE - VMEM_0_BASE) >> PAGESHIFT;
    int num_frames = KERNEL_STACK_MAXSIZE / PAGESIZE;
    
    // Save current kernel stack mappings
    pte_t saved_ptes[num_frames];
    int current_kstack_frames[num_frames];
 
    for (int i = 0; i < num_frames; i++) {
        int vpn = kernel_stack_vpn + i;
        saved_ptes[i] = kernel_state.region0_ptbr[vpn];
        
        // Get current process's kernel stack frames
        if (src->kernel_stack_frames[i] != ERROR) {
            current_kstack_frames[i] = src->kernel_stack_frames[i];
        } else {
            current_kstack_frames[i] = ERROR;
        }
    }
    
    // Temporarily map source process's kernel stack for reading
    for (int i = 0; i < num_frames; i++) {
        int vpn = kernel_stack_vpn + i;
        if (current_kstack_frames[i] != ERROR) {
            kernel_state.region0_ptbr[vpn].valid = 1;
            kernel_state.region0_ptbr[vpn].pfn = current_kstack_frames[i];
            kernel_state.region0_ptbr[vpn].prot = PROT_READ;
        }
    }
    
    // Flush TLB to apply new mappings
    WriteRegister(REG_TLB_FLUSH, TLB_FLUSH_KSTACK);
    
    // Read from source kernel stack
    void* src_stack_base = (void*)KERNEL_STACK_BASE;
    
    // Temporarily map destination process's kernel stack for writing
    for (int i = 0; i < num_frames; i++) {
        int vpn = kernel_stack_vpn + i;
        if (dest->kernel_stack_frames[i] != ERROR) {
            kernel_state.region0_ptbr[vpn].valid = 1;
            kernel_state.region0_ptbr[vpn].pfn = dest->kernel_stack_frames[i];
            kernel_state.region0_ptbr[vpn].prot = PROT_READ | PROT_WRITE;
        }
    }
    
    // Flush TLB again to apply destination mappings
    WriteRegister(REG_TLB_FLUSH, TLB_FLUSH_KSTACK);
    
    // Write to destination kernel stack
    void* dest_stack_base = (void*)KERNEL_STACK_BASE;
    memcpy(dest_stack_base, src_stack_base, KERNEL_STACK_MAXSIZE);
    
    TracePrintf(2, "Copied %d bytes of kernel stack\n", KERNEL_STACK_MAXSIZE);
    
    // Restore original kernel stack mappings
    for (int i = 0; i < num_frames; i++) {
        int vpn = kernel_stack_vpn + i;
        kernel_state.region0_ptbr[vpn] = saved_ptes[i];
    }
    
    // Final TLB flush to restore original state
    WriteRegister(REG_TLB_FLUSH, TLB_FLUSH_KSTACK);
    
    TracePrintf(1, "CopyKernelStack: completed successfully\n");
}

void SwitchKernelStackMapping(PCB* pcb) {
    if (pcb == NULL) return;
    
    // Step 1: Calculate kernel stack virtual page number
    int kernel_stack_vpn = (KERNEL_STACK_BASE - VMEM_0_BASE) >> PAGESHIFT;
    int kernel_stack_pages = KERNEL_STACK_MAXSIZE / PAGESIZE;
    
    // Step 2: Map new process's kernel stack frames into kernel page table
    for (int i = 0; i < kernel_stack_pages; i++) {
        if (pcb->kernel_stack_frames[i] != ERROR) {
            MapPage(kernel_state.region0_ptbr, 
                    kernel_stack_vpn + i, 
                    pcb->kernel_stack_frames[i], 
                    PROT_READ | PROT_WRITE);
        }
    }
    
    // Step 3: Flush TLB entries for kernel stack region to avoid stale mappings
    WriteRegister(REG_TLB_FLUSH, TLB_FLUSH_KSTACK);
}

void FlushTLBEntry(void* vaddr) {
    WriteRegister(REG_TLB_FLUSH, (unsigned int)vaddr);
}

void FlushRegion1TLB() {
    WriteRegister(REG_TLB_FLUSH, TLB_FLUSH_1);
}

void FlushAllTLB() {
    WriteRegister(REG_TLB_FLUSH, TLB_FLUSH_ALL);
}

int HandleMemoryTrap(UserContext* uctxt) {
    PCB* current = kernel_state.current_process;
    void* fault_addr = uctxt->addr;  // Address that caused the fault
    
    // Step 1: Check if fault occurred in user space (Region 1)
    if (fault_addr >= (void*)VMEM_1_BASE && fault_addr < (void*)VMEM_1_LIMIT) {
        // Step 2: Check if this is a stack growth fault (access below stack pointer)
        if (fault_addr < current->user_context.sp) {
            return GrowUserStack(current, fault_addr);
        }
    }
    
    // Step 3: Invalid memory access - cannot handle this fault
    TracePrintf(0, "Process %d: invalid memory access at %p (sp=%p)\n",
                current->pid, fault_addr, current->user_context.sp);
    return ERROR;
}

int GrowUserStack(PCB* pcb, void* fault_addr) {
    // Step 1: Calculate virtual page number of fault address
    int vpn = ((unsigned int)fault_addr - VMEM_1_BASE) >> PAGESHIFT;
    
    // Step 2: Check if physical memory is available
    int pfn = AllocateFrame();
    if (pfn == ERROR) {
        TracePrintf(0, "GrowUserStack: no free frames for stack growth\n");
        return ERROR;
    }
    
    // Step 3: Check red zone - ensure stack doesn't grow into heap
    void* stack_bottom = (void*)(VMEM_1_LIMIT - PAGESIZE); // Start with one page
    if (fault_addr >= pcb->user_heap_break) {
        TracePrintf(0, "GrowUserStack: stack would grow into heap\n");
        FreeFrame(pfn);
        return ERROR;
    }
    
    // Step 4: Allocate physical frame and map it to fault address
    MapPage(pcb->region1_ptbr, vpn, pfn, PROT_READ | PROT_WRITE);
    
    // Step 5: Flush TLB entry to ensure new mapping takes effect
    FlushTLBEntry(fault_addr);
    
    TracePrintf(1, "Grew user stack for process %d at VPN %d\n", pcb->pid, vpn);
    return SUCCESS;
}

int GrowUserHeap(PCB* pcb, void* addr) {
    if (pcb == NULL || addr == NULL) return ERROR;
    
    // Round up to page boundary
    void* new_brk = UP_TO_PAGE(addr);
    void* current_brk = pcb->user_heap_break;
    
    TracePrintf(2, "GrowUserHeap: process %d, current brk %p, new brk %p\n",
                pcb->pid, current_brk, new_brk);
    
    // Check if we're shrinking (not typically allowed)
    if (new_brk < current_brk) {
        TracePrintf(0, "GrowUserHeap: attempt to shrink user heap\n");
        return ERROR;
    }
    // Check if new break would collide with stack
    if (new_brk >= pcb->user_context.sp) {
        TracePrintf(0, "GrowUserHeap: heap would grow into stack\n");
        return ERROR;
    }
    
    // Map pages between current break and new break
    int current_vpn = ((unsigned int)current_brk - VMEM_1_BASE) >> PAGESHIFT;
    int new_vpn = ((unsigned int)new_brk - VMEM_1_BASE) >> PAGESHIFT;
    
    for (int vpn = current_vpn; vpn < new_vpn; vpn++) {
        int pfn = AllocateFrame();
        if (pfn == ERROR) {
            TracePrintf(0, "GrowUserHeap: out of memory at VPN %d\n", vpn);
            // Clean up any pages we already allocated
            for (int i = current_vpn; i < vpn; i++) {
                UnmapPage(pcb->region1_ptbr, i);
            }
            return ERROR;
        }
        
        MapPage(pcb->region1_ptbr, vpn, pfn, PROT_READ | PROT_WRITE);
        TracePrintf(2, "Mapped user heap page: VPN %d -> PFN %d\n", vpn, pfn);
    }
    
    // Update user heap break
    pcb->user_heap_break = new_brk;
    
    // Flush TLB for the new mappings
    FlushRegion1TLB();
    
    return SUCCESS;
}

int GrowKernelHeap(void* addr) {
    if (addr == NULL) return ERROR;
    
    // Round up to page boundary
    void* new_brk = UP_TO_PAGE(addr);
    void* current_brk = kernel_state.kernel_brk;
    
    TracePrintf(2, "GrowKernelHeap: current brk %p, new brk %p\n",
                current_brk, new_brk);
    
    // Check if we're shrinking (not typically allowed)
    if (new_brk < current_brk) {
        TracePrintf(0, "GrowKernelHeap: attempt to shrink kernel heap\n");
        return ERROR;
    }
    
    // Map pages between current break and new break in Region 0
    int current_vpn = ((unsigned int)current_brk - VMEM_0_BASE) >> PAGESHIFT;
    int new_vpn = ((unsigned int)new_brk - VMEM_0_BASE) >> PAGESHIFT;
    
    for (int vpn = current_vpn; vpn < new_vpn; vpn++) {
        int pfn = AllocateFrame();
        if (pfn == ERROR) {
            TracePrintf(0, "GrowKernelHeap: out of memory at VPN %d\n", vpn);
            // Clean up any pages we already allocated
            for (int i = current_vpn; i < vpn; i++) {
                UnmapPage(kernel_state.region0_ptbr, i);
            }
            return ERROR;
        }
        
        MapPage(kernel_state.region0_ptbr, vpn, pfn, PROT_READ | PROT_WRITE);
        TracePrintf(2, "Mapped kernel heap page: VPN %d -> PFN %d\n", vpn, pfn);
    }
    
    // Update kernel heap break
    kernel_state.kernel_brk = new_brk;
    
    return SUCCESS;
}

