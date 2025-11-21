#ifndef MEMORY_H
#define MEMORY_H

#include <ykernel.h>

#define MAX_TEMP_MAPPINGS 2

typedef struct {
    int active;
    pte_t saved_mapping;
    int vpn;
} TempMapping;

// Memory management functions
void InitializeMemorySubsystem(unsigned int pmem_size);
void BuildInitialRegion0PageTable();
int HandleMemoryTrap(UserContext* uctxt);
int GrowUserStack(PCB* pcb, void* fault_addr);
int GrowUserHeap(PCB* pcb, void* addr);
int GrowKernelHeap(void* addr);

// Frame allocation
void MarkKernelFramesAsUsed();
int IsFrameFree(int pfn);
void MarkFrameUsed(int pfn);
void MarkFrameFree(int pfn);
int AllocateFrame();
void FreeFrame(int pfn);
int FindFreeFrame();

// Page table operations
void MapPage(pte_t* page_table, int vpn, int pfn, int prot);
void UnmapPage(pte_t* page_table, int vpn);
int IsPageMapped(pte_t* page_table, int vpn);
pte_t* CreateEmptyPageTable(int num_pages);
pte_t* CopyPageTable(pte_t* src, int num_pages);
void CopyKernelStack(PCB* src, PCB* dest);
void SwitchKernelStackMapping(PCB* pcb);

// TLB management
void FlushTLBEntry(void* vaddr);
void FlushRegion1TLB();
void FlushAllTLB();

// Kernel stack management
int* AllocateKernelStackFrames();
void FreeKernelStackFrames(int* frames);

// Temporary frame mapping (for loading programs, etc.)
void* MapFrameTemporary(int pfn, int prot, int slot);
void UnmapFrameTemporary(int slot);
void InitializeTempMappings(void);

// Temporary page VPNs for mapping
#define TEMP_PAGE_VPN ((KERNEL_STACK_BASE - VMEM_0_BASE) >> PAGESHIFT) - 1
#define TEMP_PAGE_VPN_2 ((KERNEL_STACK_BASE - VMEM_0_BASE) >> PAGESHIFT) - 2

#endif
