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
    interrupt_vector_table[TRAP_KERNEL] = HandleTrapKernel;
    interrupt_vector_table[TRAP_CLOCK] = HandleTrapClock;
    
    TracePrintf(1, "Interrupt vector table initialized\n");
}

void HandleTrapKernel(UserContext* uctxt) {
    // Step 1: Save current user context to process control block
    SaveUserContext(&kernel_state.current_process->user_context, uctxt);
    // Step 2: Extract system call number from context and log
    int syscall_num = uctxt->code;
        TracePrintf(2, "Syscall %d from process %d\n", syscall_num, kernel_state.current_process->pid);
    // Step 3: Dispatch to appropriate system call handler and handle unknown system call with error
    switch (syscall_num) {
        case SYS_FORK:
            SyscallFork(uctxt);
            break;
        case SYS_EXEC:
            SyscallExec(uctxt);
            break;
        case SYS_EXIT:
            SyscallExit(uctxt);
            break;
        case SYS_WAIT:
            SyscallWait(uctxt);
            break;
        case SYS_GETPID:
            SyscallGetPid(uctxt);
            break;
        case SYS_BRK:
            SyscallBrk(uctxt);
            break;
        case SYS_DELAY:
            SyscallDelay(uctxt);
            break;
        case SYS_TTY_READ:
            SyscallTtyRead(uctxt);
            break;
        case SYS_TTY_WRITE:
            SyscallTtyWrite(uctxt);
            break;
        default:
            TracePrintf(0, "Unknown syscall: %d\n", syscall_num);
            uctxt->regs[0] = ERROR;
            break;
    }
    // Step 4: Restore updated user context before returning to user mode
    RestoreUserContext(uctxt, &kernel_state.current_process->user_context);
}

void HandleTrapClock(UserContext* uctxt) {
    // Step 1: Save current process context
    SaveUserContext(&kernel_state.current_process->user_context, uctxt);
    // Step 2: If current process is valid running process, move to ready queue
    TracePrintf(2, "Clock trap, scheduling next process\n");
    // Step 3: Invoke scheduler to select next process
    Schedule();
    // Step 4: Restore context of newly scheduled process
    RestoreUserContext(uctxt, &kernel_state.current_process->user_context);
}

void DefaultTrapHandler(UserContext* uctxt) {
    // This IS the "this trap is not yet handled" handler
    TracePrintf(TRACE_TRAP, "UNHANDLED TRAP: type %d, code 0x%x, addr 0x%x\n",
                uctxt->type, uctxt->code, uctxt->addr);
    
    // For development, you might want different behavior:
    switch (uctxt->type) {
        case TRAP_MEMORY:
            TracePrintf(TRACE_ERROR, "Memory trap not yet implemented!\n");
            break;
        case TRAP_ILLEGAL:
            TracePrintf(TRACE_ERROR, "Illegal instruction trap not yet implemented!\n");
            break;
        case TRAP_MATH:
            TracePrintf(TRACE_ERROR, "Math trap not yet implemented!\n");
            break;
        case TRAP_TTY_TRANSMIT:
            TracePrintf(TRACE_ERROR, "TTY transmit trap not yet implemented!\n");
            break;
        case TRAP_TTY_RECEIVE:
            TracePrintf(TRACE_ERROR, "TTY receive trap not yet implemented!\n");
            break;
        default:
            TracePrintf(TRACE_ERROR, "Unknown trap type %d not yet implemented!\n", uctxt->type);
            break;
    }
    
    // For now, terminate the process for safety
    TerminateCurrentProcess(ERROR_UNHANDLED_TRAP);
}

void HandleTrapMemory(UserContext* uctxt) {
    // Step 1: Attempt to handle memory fault (e.g., page fault, heap growth)
    
    // Step 2: If successful, log and continue execution
       
    // If HandleMemoryTrap returns ERROR, the process may be terminated
}

void SyscallGetPid(UserContext* uctxt) {
    // GetPid has no arguments, just returns the current process ID
    uctxt->regs[0] = kernel_state.current_process->pid;
    TracePrintf(2, "GetPid: returning PID %d\n", uctxt->regs[0]);
}

void SyscallDelay(UserContext* uctxt) {
    int clock_ticks = uctxt->regs[0];  
    
    TracePrintf(2, "Delay: process %d delaying for %d ticks\n", 
                kernel_state.current_process->pid, clock_ticks);
    
    // Validate argument
    if (clock_ticks < 0) {
        uctxt->regs[0] = ERROR;
        TracePrintf(0, "Delay: invalid tick count %d\n", clock_ticks);
        return;
    }
    
    // If delay is 0, return immediately
    if (clock_ticks == 0) {
        uctxt->regs[0] = SUCCESS;
        return;
    }
    
    // Set up delay tracking in PCB
    PCB* current = kernel_state.current_process;
    current->delay_remaining = clock_ticks;
    current->state = PROCESS_BLOCKED;
    
    // Add to delay queue (you'll need to implement this)
    AddToDelayQueue(current);
    
    TracePrintf(1, "Delay: process %d blocked for %d ticks\n", 
                current->pid, clock_ticks);
    
    // Schedule another process
    Schedule();
    
    // When we resume, the delay has completed
    uctxt->regs[0] = SUCCESS;
}

void SyscallBrk(UserContext* uctxt) {
    void* addr = (void*)uctxt->regs[0];  // First argument
    PCB* current = kernel_state.current_process;
    
    TracePrintf(2, "Brk: process %d requesting brk at %p\n", 
                current->pid, addr);
    
    // Validate address is in Region 1
    if (addr < VMEM_1_BASE || addr >= VMEM_1_LIMIT) {
        uctxt->regs[0] = ERROR;
        TracePrintf(0, "Brk: address %p outside Region 1\n", addr);
        return;
    }
    
    // Round up to page boundary
    void* new_brk = UP_TO_PAGE(addr);
    
    // Handle the brk request
    int result = GrowUserHeap(current, new_brk);
    uctxt->regs[0] = result;
    
    if (result == SUCCESS) {
        TracePrintf(1, "Brk: process %d heap now ends at %p\n", 
                    current->pid, current->user_heap_break);
    } else {
        TracePrintf(0, "Brk: failed to grow heap to %p\n", new_brk);
    }
}
