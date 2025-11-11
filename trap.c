#include "kernel.h"
#include "memory.h"
#include "process.h"
#include "traps.h"

// Global interrupt vector table which stores function pointers for all trap handlers
void (*interrupt_vector_table[TRAP_VECTOR_SIZE])(UserContext*);

#define UP_TO_PAGE(addr) ((((unsigned long)(addr) + PAGESIZE - 1) / PAGESIZE) * PAGESIZE)
#define DOWN_TO_PAGE(addr) (((unsigned long)(addr) / PAGESIZE) * PAGESIZE)

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
    if(kernel_state.current_process->state == PROCESS_RUNNING){
        RestoreUserContext(uctxt, &kernel_state.current_process->user_context);
    }
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
    if (fault_addr >= (void*)VMEM_1_BASE && fault_addr < (void*)VMEM_1_LIMIT) {
        // Check if this is a stack growth fault
        if ((unsigned long)fault_addr < current->user_context.sp) {
            result = GrowUserStack(current, fault_addr);
        } 
        // Check if this is a heap growth fault
        else if ((unsigned long)fault_addr >= (unsigned long)current->user_heap_break && 
                 (unsigned long)fault_addr < (unsigned long)current->user_heap_break + PAGESIZE) {
            result = GrowUserHeap(current, UP_TO_PAGE(fault_addr));
        }
    }
    
    // Step 2: If successful, log and continue execution
    // If HandleMemoryTrap returns ERROR, the process may be terminated
    if (result == SUCCESS) {
        TracePrintf(1, "Handled memory trap successfully for process %d\n", current->pid);
        // Flush TLB for the faulted region if needed 
        FlushTLBEntry(fault_addr);
    } else {
        TracePrintf(0, "Failed to handle memory trap for process %d, terminating\n", current->pid);
        TerminateProcess(current, ERROR);
        Schedule();  // Schedule next process after termination
        return;
    }

    // Restore context to continue execution
    RestoreUserContext(uctxt, &current->user_context);
}

void HandleTrapIllegal(UserContext* uctxt) {
    SaveUserContext(&kernel_state.current_process->user_context, uctxt);
    TracePrintf(0, "Illegal instruction trap for process %d\n", kernel_state.current_process->pid);
    TerminateProcess(kernel_state.current_process, ERROR);
    Schedule();
}

void HandleTrapMath(UserContext* uctxt) {
    SaveUserContext(&kernel_state.current_process->user_context, uctxt);
    TracePrintf(0, "Math trap for process %d\n", kernel_state.current_process->pid);
    TerminateProcess(kernel_state.current_process, ERROR);
    Schedule();
}

void HandleTrapTtyTransmit(UserContext* uctxt) {
    // Handle async TTY transmit complete
    // Wake up any blocked process waiting on this TTY
    SaveUserContext(&kernel_state.current_process->user_context, uctxt);
    TracePrintf(1, "TTY transmit complete trap\n");
    
    // Implement TTY queue wakeup
    if (tty_id >= 0 && tty_id < NUM_TERMINALS && tty_states[tty_id]) {
        TtyState* tty = tty_states[tty_id];
        tty->transmit_busy = 0;
        
        // Wake up process waiting on this TTY transmission
        if (tty->transmit_waiting) {
            PCB* waiting = tty->transmit_waiting;
            tty->transmit_waiting = NULL;
            waiting->state = PROCESS_READY;
            AddToReadyQueue(waiting);
            TracePrintf(1, "Woke up process %d waiting on TTY %d transmit\n", waiting->pid, tty_id);
        }
    }

    RestoreUserContext(uctxt, &kernel_state.current_process->user_context);
}

void HandleTrapTtyReceive(UserContext* uctxt) {
    // Handle async TTY receive ready
    SaveUserContext(&kernel_state.current_process->user_context, uctxt);
    TracePrintf(1, "TTY receive ready trap\n");
    
    // Implement TTY input buffer handling
    if (tty_id >= 0 && tty_id < NUM_TERMINALS && tty_states[tty_id]) {
        TtyState* tty = tty_states[tty_id];
        char input_buffer[TERMINAL_MAX_LINE];
        
        // Read incoming data
        int len = TtyReceive(tty_id, input_buffer, TERMINAL_MAX_LINE);
        if (len > 0) {
            // Store received data in buffer
            TtyBuffer* new_buffer = (TtyBuffer*)malloc(sizeof(TtyBuffer));
            if (new_buffer) {
                memcpy(new_buffer->buffer, input_buffer, len);
                new_buffer->length = len;
                new_buffer->read_pos = 0;
                new_buffer->write_pos = len;
                new_buffer->next = tty->input_buffers;
                tty->input_buffers = new_buffer;
                
                TracePrintf(1, "TTY %d received %d bytes of input\n", tty_id, len);
                
                // Wake up process waiting to read from this TTY
                if (tty->read_waiting) {
                    PCB* waiting = tty->read_waiting;
                    tty->read_waiting = NULL;
                    waiting->state = PROCESS_READY;
                    AddToReadyQueue(waiting);
                    TracePrintf(1, "Woke up process %d waiting on TTY %d read\n", waiting->pid, tty_id);
                }
            }
        }
    }

    RestoreUserContext(uctxt, &kernel_state.current_process->user_context);
}

void DefaultTrapHandler(UserContext* uctxt) {
    // This IS the "this trap is not yet handled" handler
    TracePrintf(TRACE_TRAP, "UNHANDLED TRAP: type %d, code 0x%x, addr 0x%x\n",
                uctxt->type, uctxt->code, uctxt->addr);
    
    
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
    TerminateProcess(kernel_state.current_process, ERROR);
    Schedule();
    RestoreUserContext(uctxt, &kernel_state.current_process->user_context);
    
}

int ValidateUserString(char* str) {
    if (str == NULL) return 0;
    
    char* current = str;
    while (1) {
        if (!ValidateUserPointer(current, 1, PROT_READ)) {
            return 0;
        }
        if (*current == '\0') {
            break;
        }
        current++;
    }
    return 1;
}

int ValidateUserPointer(void* ptr, int len, int access_type) {
    // Basic Region 1 validation
    if (ptr < (void*)VMEM_1_BASE || (char*)ptr + len > (void*)VMEM_1_LIMIT) {
        return 0;
    }
    
    // COMPLETED: Page table permission checking
    PCB* current = kernel_state.current_process;
    if (current == NULL || current->region1_ptbr == NULL) {
        return 0;
    }
    
    // Check each page in the range
    unsigned long start_addr = (unsigned long)ptr;
    unsigned long end_addr = start_addr + len;
    unsigned long current_page = DOWN_TO_PAGE(start_addr);
    
    while (current_page < end_addr) {
        int vpn = (current_page - VMEM_1_BASE) >> PAGESHIFT;
        
        // Check if page is mapped
        if (vpn < 0 || vpn >= (VMEM_1_SIZE / PAGESIZE) || 
            !current->region1_ptbr[vpn].valid) {
            return 0;
        }
        
        // Check permissions
        if ((access_type & PROT_READ) && !(current->region1_ptbr[vpn].prot & PROT_READ)) {
            return 0;
        }
        if ((access_type & PROT_WRITE) && !(current->region1_ptbr[vpn].prot & PROT_WRITE)) {
            return 0;
        }
        
        current_page += PAGESIZE;
    }
    
    return 1;
}

void SyscallFork(UserContext* uctxt) {
    PCB* parent = kernel_state.current_process;
    PCB* child = CreatePCB();
    
    if (!child) {
        uctxt->regs[0] = ERROR;
        return;
    }
    
    // Copy parent context and memory (per process.h)
    child->pid = helper_new_pid(child->region1_ptbr);
    child->parent = parent;
    
    CopyKernelStack(parent, child);
    SetupProcessMemoryMapping(child);  
    
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
    PCB* current = kernel_state.current_process;
    
    TracePrintf(1, "Exit: process %d exiting with status %d\n", current->pid, status);
    TerminateProcess(current, status);
    Schedule();  // Won't return here

    // Unreachable code here
    //TracePrintf(0, "should not reach here!\n");
    //helper_abort("SyscallExit failure");
}

void SyscallWait(UserContext* uctxt) {
    PCB* parent = kernel_state.current_process;
    int* status_ptr = (int*)uctxt->regs[1];
    
    // Validate status pointer if provided
    if (status_ptr != NULL && !ValidateUserPointer(status_ptr, sizeof(int), PROT_WRITE)) {
        uctxt->regs[0] = ERROR;
        return;
    }
    
    PCB* child = FindZombieChild(parent);
    
    if (child) {
        // Found a zombie child
        uctxt->regs[0] = child->pid;
        if (status_ptr != NULL) {
            // COMPLETED: Write status to user memory
            *status_ptr = child->exit_status;
        }
        FreePCB(child);
    } else if (parent->children == NULL) {
        // No children at all
        uctxt->regs[0] = ERROR;
    } else {
        // Has children but none are zombies - block
        parent->state = PROCESS_BLOCKED;
        parent->waiting_for_child = 1;
        Schedule();
        // When we resume, a child has exited
        child = FindZombieChild(parent);
        if (child) {
            uctxt->regs[0] = child->pid;
            if (status_ptr != NULL) {
                *status_ptr = child->exit_status;
            }
            FreePCB(child);
        } else {
            uctxt->regs[0] = ERROR;
        }
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
    int tty_id = uctxt->regs[0];
    void* buf = (void*)uctxt->regs[1];
    int len = uctxt->regs[2];
    PCB* current = kernel_state.current_process;
    
    if (!ValidateUserPointer(buf, len, PROT_WRITE)) {
        uctxt->regs[0] = ERROR;
        return;
    }
    
    if (tty_id < 0 || tty_id >= NUM_TERMINALS || !tty_states[tty_id]) {
        uctxt->regs[0] = ERROR;
        return;
    }
    
    TtyState* tty = tty_states[tty_id];
    
    // Check if we have buffered input
    if (tty->input_buffers) {
        TtyBuffer* buffer = tty->input_buffers;
        int bytes_to_copy = (buffer->length - buffer->read_pos) < len ? 
                           (buffer->length - buffer->read_pos) : len;
        
        // Copy data to user buffer
        memcpy(buf, buffer->buffer + buffer->read_pos, bytes_to_copy);
        buffer->read_pos += bytes_to_copy;
        
        // Remove buffer if fully read
        if (buffer->read_pos >= buffer->length) {
            tty->input_buffers = buffer->next;
            free(buffer);
        }
        
        uctxt->regs[0] = bytes_to_copy;
        TracePrintf(1, "TTY read: process %d read %d bytes from TTY %d\n", 
                    current->pid, bytes_to_copy, tty_id);
    } else {
        // No data available - block the process
        tty->read_waiting = current;
        current->state = PROCESS_BLOCKED;
        Schedule();
        // When we resume, try reading again
        SyscallTtyRead(uctxt); // Recursive call to handle the now-available data
    }
}

void SyscallTtyWrite(UserContext* uctxt) {
    int tty_id = uctxt->regs[0];
    void* buf = (void*)uctxt->regs[1];
    int len = uctxt->regs[2];
    PCB* current = kernel_state.current_process;
    
    if (!ValidateUserPointer(buf, len, PROT_READ)) {
        uctxt->regs[0] = ERROR;
        return;
    }
    
    if (tty_id < 0 || tty_id >= NUM_TERMINALS || !tty_states[tty_id]) {
        uctxt->regs[0] = ERROR;
        return;
    }
    
    TtyState* tty = tty_states[tty_id];
    
    // Check if TTY is busy
    if (tty->transmit_busy) {
        // TTY is busy - block the process
        tty->transmit_waiting = current;
        current->state = PROCESS_BLOCKED;
        Schedule();
        // When we resume, try writing again
        SyscallTtyWrite(uctxt); // Recursive call
        return;
    }
    
    // Allocate kernel buffer and copy data
    char* kernel_buf = (char*)malloc(len);
    if (!kernel_buf) {
        uctxt->regs[0] = ERROR;
        return;
    }
    
    // Copy data from user space to kernel buffer
    for (int i = 0; i < len; i++) {
        // Validate each byte individually
        if (!ValidateUserPointer((char*)buf + i, 1, PROT_READ)) {
            free(kernel_buf);
            uctxt->regs[0] = ERROR;
            return;
        }
        kernel_buf[i] = ((char)buf + i);
    }
    
    // Start transmission
    tty->transmit_busy = 1;
    TtyTransmit(tty_id, kernel_buf, len);
    
    // Note: kernel_buf will be freed when transmission completes in HandleTrapTtyTransmit
    uctxt->regs[0] = len;
    TracePrintf(1, "TTY write: process %d writing %d bytes to TTY %d\n", 
                current->pid, len, tty_id);
}
