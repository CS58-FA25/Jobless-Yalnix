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
    interrupt_vector_table[TRAP_MEMORY] = HandleTrapMemory;
    interrupt_vector_table[TRAP_ILLEGAL] = HandleTrapIllegal;
    interrupt_vector_table[TRAP_MATH] = HandleTrapMath;
    interrupt_vector_table[TRAP_TTY_TRANSMIT] = HandleTrapTtyTransmit;
    interrupt_vector_table[TRAP_TTY_RECEIVE] = HandleTrapTtyReceive;
    
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
    PCB* current = kernel_state.current_process;
    if (current->state == PROCESS_RUNNING) {
        current->state = PROCESS_READY;
        AddToReadyQueue(current);
    }
    
    TracePrintf(2, "Clock trap, scheduling next process\n");
    // Step 3: Invoke scheduler to select next process
    Schedule();
    // Step 4: Restore context of newly scheduled process
    RestoreUserContext(uctxt, &kernel_state.current_process->user_context);
}

void HandleTrapMemory(UserContext* uctxt) {
    // Save context immediately (per handout Section 2.5)
    SaveUserContext(&kernel_state.current_process->user_context, uctxt);
    PCB* current = kernel_state.current_process;
    void* fault_addr = (void*)uctxt->addr;
    
    TracePrintf(2, "Memory trap for process %d at address %p\n", current->pid, fault_addr);
    
    int result = ERROR;
    
    // Step 1: Attempt to handle memory fault (e.g., page fault, heap growth)
    unsigned long current_sp = current->user_context.regs[29];  // Typical SP register (r29 in MIPS-like)
    if (fault_addr < current_sp && fault_addr >= VMEM_1_BASE) {  // Stack fault
        result = GrowUserStack(current, fault_addr);
    } 
    // Check if fault is in user heap region (grows up from data end to user_heap_break)
    else if (fault_addr >= VMEM_1_BASE && fault_addr < (void*)current->user_heap_break + PAGE_SIZE) {  // Heap fault
        result = GrowUserHeap(current, fault_addr);
    } else {
        TracePrintf(0, "Invalid memory fault address %p for process %d\n", fault_addr, current->pid);
        result = ERROR;
    }
    
    // Step 2: If successful, log and continue execution
    // If HandleMemoryTrap returns ERROR, the process may be terminated
    if (result == SUCCESS) {
        TracePrintf(1, "Handled memory trap successfully for process %d\n", current->pid);
        // Flush TLB for the faulted region if needed (per handout Section 2.2.5)
        FlushRegion1TLB();
    } else {
        TracePrintf(0, "Failed to handle memory trap for process %d, terminating\n", current->pid);
        TerminateProcess(current, ERROR_MEMORY_TRAP);  // Assume ERROR_MEMORY_TRAP defined in kernel.h
        Schedule();  // Schedule next process after termination
    }

    // Restore context to continue execution
    RestoreUserContext(uctxt, &current->user_context);
}

void HandleTrapIllegal(UserContext* uctxt) {
    SaveUserContext(&kernel_state.current_process->user_context, uctxt);
    TracePrintf(0, "Illegal instruction trap for process %d\n", kernel_state.current_process->pid);
    TerminateProcess(kernel_state.current_process, ERROR_ILLEGAL_INSTRUCTION);
    RestoreUserContext(uctxt, &kernel_state.current_process->user_context);  // Or schedule after term
}

void HandleTrapMath(UserContext* uctxt) {
    SaveUserContext(&kernel_state.current_process->user_context, uctxt);
    TracePrintf(0, "Math trap for process %d\n", kernel_state.current_process->pid);
    TerminateProcess(kernel_state.current_process, ERROR_MATH_TRAP);
    RestoreUserContext(uctxt, &kernel_state.current_process->user_context);
}

void HandleTrapTtyTransmit(UserContext* uctxt) {
    // Handle async TTY transmit complete
    // Wake up any blocked process waiting on this TTY
    SaveUserContext(&kernel_state.current_process->user_context, uctxt);
    
    // Implement TTY queue wakeup
    TracePrintf(1, "TTY transmit complete trap\n");
    RestoreUserContext(uctxt, &kernel_state.current_process->user_context);
}

void HandleTrapTtyReceive(UserContext* uctxt) {
    // Handle async TTY receive ready
    SaveUserContext(&kernel_state.current_process->user_context, uctxt);
    
    // Implement TTY input buffer handling
    TracePrintf(1, "TTY receive ready trap\n");
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
    SaveUserContext(&kernel_state.current_process->user_context, uctxt);
    TerminateProcess(kernel_state.current_process, ERROR_UNHANDLED_TRAP);
    Schedule();
    RestoreUserContext(uctxt, &kernel_state.current_process->user_context);
    
}

void SyscallFork(UserContext* uctxt) {
    PCB* parent = kernel_state.current_process;
    PCB* child = CreatePCB();
    if (!child) {
        uctxt->regs[0] = ERROR;
        return;
    }
    
    // Copy parent context and memory (per process.h)
    CopyKernelStack(parent, child);
    SetupProcessMemoryMapping(child);  // From kernel.h
    child->parent = parent;
    AddChildProcess(parent, child);
    AddToReadyQueue(child);
    
    uctxt->regs[0] = child->pid;  // Child PID to parent
    TracePrintf(1, "Fork: parent %d created child %d\n", parent->pid, child->pid);
}

void SyscallExec(UserContext* uctxt) {
    // Requires file system access; for now, terminate on error
    char* program = (char*)uctxt->regs[0];
    if (!ValidateUserString(program)) {
        uctxt->regs[0] = ERROR;
        return;
    }
    // Implement ELF loading, reset memory, etc.
    TracePrintf(0, "Exec: %s not fully implemented\n", program);
    uctxt->regs[0] = SUCCESS;  // Placeholder
}

void SyscallExit(UserContext* uctxt) {
    int status = uctxt->regs[0];
    TerminateProcess(kernel_state.current_process, status);
    Schedule();  // Won't return here

    // Unreachable code here
    //TracePrintf(0, "should not reach here!\n");
    //helper_abort("SyscallExit failure");
}

void SyscallWait(UserContext* uctxt) {
    // Wait for child
    PCB* parent = kernel_state.current_process;
    PCB* child = FindZombieChild(parent);
    if (child) {
        uctxt->regs[0] = child->exit_status;
        FreePCB(child);  // Reclaim
        RemoveChildProcess(parent, child);
    } else {
        // Block parent
        parent->state = PROCESS_BLOCKED;
        Schedule();
        uctxt->regs[0] = SUCCESS;  // Set on wakeup
    }
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

void SyscallTtyRead(UserContext* uctxt) {
    // Read from TTY, block if no input
    // Use TtyReceive hardware call
    uctxt->regs[0] = SUCCESS;  // Placeholder
}

void SyscallTtyWrite(UserContext* uctxt) {
    // Write to TTY asynchronously
    // Use TtyTransmit, handle buffer validation
    if (!ValidateUserPointer((void*)uctxt->regs[1], uctxt->regs[2], READ)) {  // buf, len
        uctxt->regs[0] = ERROR;
        return;
    }
    uctxt->regs[0] = SUCCESS;  // Placeholder
}
