#include "kernel.h"
#include "memory.h"
#include "process.h"
#include "traps.h"


KernelState kernel_state;
int vm_enabled = 0;
void* kernel_brk = NULL;

void KernelStart(char* cmd_args[], unsigned int pmem_size, UserContext* uctxt) {
    
    // Initialize kernel globals
    // Phase 1: Memory initialization
    // Phase 2: Enable virtual memory
    // Phase 3: Interrupt system
    // Phase 4: Create idle process
    // Phase 5: Create init process
    
    // Return to user mode at specified context
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
