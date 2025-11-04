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
    for (int i = 0; i < num_pages; i++) {
        if (src[i].valid) {
            dest[i].valid = 1;
            dest[i].pfn = src[i].pfn;
            dest[i].prot = src[i].prot;
            
            // Mark frame as used (in real implementation, use reference counting)
            MarkFrameUsed(src[i].pfn);
        }
    }
    
    return dest;
}

void MapPage(pte_t* page_table, int vpn, int pfn, int prot) {
    // Set up page table entry with mapping information
}

void UnmapPage(pte_t* page_table, int vpn) {
    // Step 1: Check if page is currently mapped
    
    // Step 2: If so, clear the page table entry and free the physical frame for reuse
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
    // Validate frame number and mark as free
    if (pfn >= 0 && pfn < kernel_state.total_frames) {
        MarkFrameFree(pfn);
        kernel_state.used_frames--;
        TracePrintf(3, "Freed frame %d, used: %d/%d\n",
                   pfn, kernel_state.used_frames, kernel_state.total_frames);
    }
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
    // Step 1: Calculate byte and bit position
    
    // Step 2: Clear the bit
}

void MarkFrameFree(int pfn) {
    // Step 1: Calculate byte and bit position

    // Step 2: Set the bit
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
    // Step 1: Free all physical frames used by kernel stack
    
    // Step 2: Free the frames array itself
    free(frames);
}

void SwitchKernelStackMapping(PCB* pcb) {
    // Step 1: Calculate kernel stack virtual page number
    if (pcb == NULL) return;
    
    int kernel_stack_vpn = (KERNEL_STACK_BASE - VMEM_0_BASE) >> PAGESHIFT;
    int num_frames = KERNEL_STACK_MAXSIZE / PAGESIZE;
    
    // Step 2: Map new process's kernel stack frames into kernel page table
    for (int i = 0; i < num_frames; i++) {
        int vpn = kernel_stack_vpn + i;
        if (pcb->kernel_stack_frames[i] != ERROR) {
            kernel_state.region0_ptbr[vpn].valid = 1;
            kernel_state.region0_ptbr[vpn].pfn = pcb->kernel_stack_frames[i];
            kernel_state.region0_ptbr[vpn].prot = PROT_READ | PROT_WRITE;
        } else {
            kernel_state.region0_ptbr[vpn].valid = 0;
        }
    }
   
    // Step 3: Flush TLB entries for kernel stack region to avoid stale mappings
    
    //Not used in checkpoint3
    //WriteRegister(REG_TLB_FLUSH, TLB_FLUSH_KSTACK);
}

void FlushTLBEntry(void* vaddr) {
    // Flush single TLB entry for specific virtual address
}

void FlushRegion1TLB() {
    // Flush all TLB entries for Region 1 (user space)
}

void FlushAllTLB() {
    // Flush entire TLB
}

int HandleMemoryTrap(UserContext* uctxt) {
    PCB* current = kernel_state.current_process;
    void* fault_addr = uctxt->addr;  // Address that caused the fault
    // Step 1: Check if fault occurred in user space (Region 1)
        // Step 2: Check if this is a stack growth fault (access below stack pointer)
    return GrowUserStack(current, fault_addr);
    
    // Step 3: Invalid memory access - cannot handle this fault
    TracePrintf(0, "Process %d: invalid memory access at %p (sp=%p)\n",
                current->pid, fault_addr, current->user_context.sp);
    return ERROR;
}

int GrowUserStack(PCB* pcb, void* fault_addr) {
    // Step 1: Calculate virtual page number of fault address
    
    // Step 2: Check if physical memory is available
    return ERROR;
    
    
    // Step 3: Check red zone - ensure stack doesn't grow into heap
    return ERROR;
    
    
    // Step 4: Allocate physical frame and map it to fault address
    return ERROR;
    
    // Step 5: Flush TLB entry to ensure new mapping takes effect
    return SUCCESS;
}

int GrowUserHeap(PCB* pcb, void* addr) {
    // Placeholder for user heap growth implementation
    // Would map pages between current heap break and new address
    return SUCCESS;
}

int GrowKernelHeap(void* addr) {
    // Placeholder for kernel heap growth implementation
    return SUCCESS;
}

