#ifndef MEMORY_H
#define MEMORY_H

#include <ykernel.h>

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

#endif
