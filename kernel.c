#include "kernel.h"
#include "memory.h"
#include "process.h"
#include "traps.h"


KernelState kernel_state;
int vm_enabled = 0;
void* kernel_brk = NULL;

void KernelStart(char* cmd_args[], unsigned int pmem_size, UserContext* uctxt) {
    
    TracePrintf(1, "Kernel starting...\n");
    
    // Initialize kernel globals
    memset(&kernel_state, 0, sizeof(KernelState));
    
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
    // Adjust the kernel break to the specified address
    // Return 0 on success, -1 on failure
    return 0;
}

// Keep the CPU busy when there's no other process to run
void DoIdle(void) {
    while (1) {
        TracePrintf(2, "Idle process running\n");
        Pause();  // Wait for next interrupt
    }
}
