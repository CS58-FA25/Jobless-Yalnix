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
