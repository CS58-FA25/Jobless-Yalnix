#include "kernel.h"
#include "memory.h"
#include "process.h"

void InitializeMemorySubsystem(unsigned int pmem_size) {
    // Step 1: Calculate total number of physical memory frames
    
    // Step 2: Allocate bitmap for tracking free or used frames
    
    // Step 3: Initialize all frames as free (set as 1)
    
    // Step 4: Build initial page table for Region 0
    
    // Step 5: Set initial kernel heap break pointer
}

void BuildInitialRegion0PageTable() {
    // Step 1: Allocate memory for Region 0 page table entries
    
    // Step 2: Initialize all page table entries as invalid
    
    // Step 3: Create identity mapping for kernel text, data, and heap regions
    
    // Step 4: Map kernel virtual pages to same physical frames
}

pte_t* CreateEmptyPageTable(int num_pages) {
    // Step 1: Allocate memory for page table structure
    pte_t* page_table = (pte_t*)malloc(num_pages * sizeof(pte_t));
    if (page_table == NULL) return NULL;
    
    // Step 2: Initialize all entries as invalid/unmapped
    
    return page_table;
}

pte_t* CopyPageTable(pte_t* src, int num_pages) {
    // Step 1: Create new empty page table
    pte_t* dest = CreateEmptyPageTable(num_pages);
    if (dest == NULL) return NULL;
    
    // Step 2: Copy valid mappings from source to destination
    
    
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
    return pfn;
    // Step 3: No free frames available, then out of memory
    return ERROR;
}

void FreeFrame(int pfn) {
    // Validate frame number and mark as free
}

// Bitmap operations for frame tracking
int IsFrameFree(int pfn) {
    
    // Step 1: Calculate byte and bit position in bitmap
    
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
    
    return frames;
}

void FreeKernelStackFrames(int* frames) {
    // Step 1: Free all physical frames used by kernel stack
    
    // Step 2: Free the frames array itself
    free(frames);
}

void SwitchKernelStackMapping(PCB* pcb) {
    // Step 1: Calculate kernel stack virtual page number
    
    // Step 2: Map new process's kernel stack frames into kernel page table
   
    // Step 3: Flush TLB entries for kernel stack region to avoid stale mappings
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
