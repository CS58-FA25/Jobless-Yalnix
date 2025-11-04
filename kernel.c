#include "kernel.h"
#include "memory.h"
#include "process.h"
#include "traps.h"



void KernelStart(char* cmd_args[], unsigned int pmem_size, UserContext* uctxt) {
    
    TracePrintf(1, "Kernel starting...\n");
    
    // Initialize kernel globals
    memset(&kernel_state, 0, sizeof(KernelState));

    // Initialize kernel heap tracking
    kernel_state.original_kernel_brk = (void*)((GET_ORIG_KERNEL_BRK_PAGE() << PAGESHIFT) + VMEM_0_BASE);
    kernel_state.kernel_brk = kernel_state.original_kernel_brk;
    kernel_state.vm_enabled = 0;
    
    TracePrintf(1, "Initial kernel break: %p\n", kernel_state.kernel_brk);
    
    // Phase 1: Memory initialization
    InitializeMemorySubsystem(pmem_size);
    
    // Phase 2: Enable virtual memory
    WriteRegister(REG_PTBRO, (unsigned int)kernel_state.region0_ptbr);
    WriteRegister(REG_PTLRO, kernel_state.region0_ptlr);
    WriteRegister(REG_VM_ENABLE, 1);
    vm_enabled = 1;
    TracePrintf(1, "Virtual memory enabled\n");

    // Phase 3: Interrupt system
    InitializeInterruptVectorTable();
    WriteRegister(REG_VECTOR_BASE, (unsigned int)interrupt_vector_table);
    
    // Phase 4: Create idle process
    kernel_state.idle_process = CreateIdleProcess(uctxt);
    if (kernel_state.idle_process == NULL) {
        TracePrintf(0, "Failed to create idle process\n");
        Halt();
    }
    
    kernel_state.current_process = kernel_state.idle_process;
    kernel_state.ready_queue = kernel_state.idle_process;
    
    // Phase 5: Create init process
    char* init_program = (cmd_args[0] != NULL) ? cmd_args[0] : "init";
    kernel_state.init_process = CreateInitProcess(init_program, cmd_args);
    
    if (kernel_state.init_process == NULL) {
        TracePrintf(0, "Failed to create init process, halting\n");
        Halt();
    }
    
    TracePrintf(1, "Leaving KernelStart, starting scheduler\n");
    
    // Return to user mode (idle process)
    SaveUserContext(uctxt, &kernel_state.current_process->user_context);
    SetupProcessMemoryMapping(kernel_state.current_process);
}

int SetKernelBrk(void* addr) {
    if (addr == NULL) {
        TracePrintf(0, "SetKernelBrk: NULL address\n");
        return ERROR;
    }
    
    // Round up to page boundary
    void* new_brk = UP_TO_PAGE(addr);
    
    TracePrintf(2, "SetKernelBrk: requested %p, rounded to %p, current brk %p, VM enabled: %d\n",
                addr, new_brk, kernel_state.kernel_brk, kernel_state.vm_enabled);
    
    // Check if we're shrinking the heap (typically not allowed)
    if (new_brk < kernel_state.kernel_brk) {
        TracePrintf(1, "SetKernelBrk: attempt to shrink kernel heap from %p to %p\n",
                   kernel_state.kernel_brk, new_brk);
        return ERROR;
    }
    
    // If not growing, just update and return
    if (new_brk == kernel_state.kernel_brk) {
        return SUCCESS;
    }
    
    if (!kernel_state.vm_enabled) {
        // Pre-VM: Just track the new break value
        // Validate that we're not growing beyond what we initially mapped
        void* max_pre_vm_brk = (void*)((GET_ORIG_KERNEL_BRK_PAGE() << PAGESHIFT) + VMEM_0_BASE);
        
        if (new_brk > max_pre_vm_brk) {
            TracePrintf(0, "SetKernelBrk: pre-VM heap growth beyond initial mapping: %p > %p\n",
                       new_brk, max_pre_vm_brk);
            return ERROR;
        }
        
        kernel_state.kernel_brk = new_brk;
        TracePrintf(2, "SetKernelBrk: pre-VM update to %p\n", kernel_state.kernel_brk);
        return SUCCESS;
    }
    
    // Post-VM: Call memory.c to actually map the new pages
    return GrowKernelHeap(new_brk);

}

// Keep the CPU busy when there's no other process to run
void DoIdle(void) {
    while (1) {
        TracePrintf(2, "Idle process running\n");
        Pause();  // Wait for next interrupt
    }
}
