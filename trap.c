#include "kernel.h"
#include "memory.h"
#include "process.h"
#include "traps.h"

// Global interrupt vector table which stores function pointers for all trap handlers
void (*interrupt_vector_table[TRAP_VECTOR_SIZE])(UserContext*);

void InitializeInterruptVectorTable() {
    // Step 1: Set all entries to default handler as fallback
    for (int i = 0; i < TRAP_VECTOR_SIZE; i++) {
        interrupt_vector_table[i] = DefaultTrapHandler;
    }
    
    // Step 2: Register specific handlers for known trap types
}

void HandleTrapKernel(UserContext* uctxt) {
    // Step 1: Save current user context to process control block
    
    // Step 2: Extract system call number from context and log
    
    // Step 3: Dispatch to appropriate system call handler and handle unknown system call with error
    
    // Step 4: Restore updated user context before returning to user mode
}

void HandleTrapClock(UserContext* uctxt) {
    // Step 1: Save current process context
    
    // Step 2: If current process is valid running process, move to ready queue
    
    // Step 3: Invoke scheduler to select next process
    
    // Step 4: Restore context of newly scheduled process
}

void HandleTrapMemory(UserContext* uctxt) {
    // Step 1: Attempt to handle memory fault (e.g., page fault, heap growth)
    
    // Step 2: If successful, log and continue execution
       
    // If HandleMemoryTrap returns ERROR, the process may be terminated
}
