#include <stdlib.h>
#include <string.h>

#include "kernel.h"
#include "memory.h"
#include "process.h"
#include "trap.h"

static char** CopyUserArguments(char** user_args);
static void FreeKernelArguments(char** args);
static void DestroyPartialPCB(PCB* pcb);

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
    int raw_code = uctxt->code;
    int syscall_num = raw_code & YALNIX_MASK;
    TracePrintf(2, "Syscall vector=0x%x (id=%d) from PID %d\n",
                raw_code, syscall_num, kernel_state.current_process->pid);

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
            TracePrintf(0, "Unknown syscall code 0x%x (id=%d)\n",
                        raw_code, syscall_num);
            uctxt->regs[0] = ERROR;
            break;
    }
    // Step 4: Restore updated user context before returning to user mode
    if(kernel_state.current_process != NULL && kernel_state.current_process->state == PROCESS_RUNNING){
        RestoreUserContext(uctxt, &kernel_state.current_process->user_context);
    }
}

void HandleTrapClock(UserContext* uctxt) {
    TracePrintf(2, "Clock tick\n");
    
    // Save context
    SaveUserContext(&kernel_state.current_process->user_context, uctxt);
    
    // Handle delay queue: Decrement and move ready to ready_queue
    PCB* delayed = kernel_state.delay_queue;
    PCB* prev = NULL;
    while (delayed != NULL) {
        delayed->delay_remaining--;
        PCB* next_delayed = delayed->next;
        if (delayed->delay_remaining <= 0) {
            // Ready: Remove from delay, add to ready
            if (prev) prev->next = next_delayed;
            else kernel_state.delay_queue = next_delayed;
            delayed->next = NULL;
            delayed->state = PROCESS_READY;
            AddToReadyQueue(delayed);
            TracePrintf(2, "Delay expired for PID %d\n", delayed->pid);
        } else {
            prev = delayed;
        }
        delayed = next_delayed;
    }
    
    // RR: Always schedule (quantum=1 tick)
    Schedule();

    // Resume whichever process the scheduler picked
    if (kernel_state.current_process != NULL) {
        RestoreUserContext(uctxt, &kernel_state.current_process->user_context);
    }
}

void HandleTrapMemory(UserContext* uctxt) {
    // Save context immediately
    SaveUserContext(&kernel_state.current_process->user_context, uctxt);
    PCB* current = kernel_state.current_process;
    void* fault_addr = (void*)uctxt->addr;

    TracePrintf(2, "Memory trap for process %d at address %p\n", current->pid, fault_addr);

    unsigned long fault = (unsigned long)fault_addr;
    unsigned long sp = (unsigned long)current->user_context.sp;
    unsigned long heap_brk = (unsigned long)current->user_heap_break;

    int result = ERROR;

    if (fault >= (unsigned long)VMEM_1_BASE && fault < (unsigned long)VMEM_1_LIMIT) {
        unsigned long abs_diff = (fault > sp) ? (fault - sp) : (sp - fault);
        int near_stack = (abs_diff <= PAGESIZE);
        int near_heap = (fault >= heap_brk) && (fault < heap_brk + PAGESIZE);
        int vpn = (fault - VMEM_1_BASE) >> PAGESHIFT;
        int max_vpn = VMEM_1_SIZE / PAGESIZE;
        int page_valid = 1;
        if (vpn >= 0 && vpn < max_vpn && current->region1_ptbr != NULL) {
            page_valid = current->region1_ptbr[vpn].valid;
        }

        if (!page_valid && near_stack) {
            result = GrowUserStack(current, fault_addr);
        } else if (!page_valid && near_heap) {
            unsigned long fault_plus = fault + 1;
            void* new_brk = (void*)UP_TO_PAGE(fault_plus);
            result = GrowUserHeap(current, new_brk);
        }
    }
    
    // Step 2: If successful, log and continue execution
    // If HandleMemoryTrap returns ERROR, the process may be terminated
    if (result == SUCCESS) {
        TracePrintf(1, "Handled memory trap successfully for process %d\n", current->pid);
        // Flush TLB for the faulted region if needed 
        FlushTLBEntry(fault_addr);

        // Restore context to continue execution in the same process
        RestoreUserContext(uctxt, &current->user_context);
        return;
    }

    TracePrintf(0, "Failed to handle memory trap for process %d, terminating\n", current->pid);
    TerminateProcess(current, ERROR);

    // Switch to another runnable process (or idle) and resume there instead
    Schedule();
    if (kernel_state.current_process != NULL) {
        RestoreUserContext(uctxt, &kernel_state.current_process->user_context);
    }
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

    int tty_id = uctxt->code;

    TracePrintf(1, "TTY transmit complete trap for terminal %d\n", tty_id);
    
    // Implement TTY queue wakeup
    if (tty_id >= 0 && tty_id < NUM_TERMINALS) {
        TtyState* tty = kernel_state.terminals[tty_id];
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

    int tty_id = uctxt->code;

    TracePrintf(1, "TTY receive ready trap for terminal %d\n", tty_id);
    
    // Implement TTY input buffer handling
    if (tty_id >= 0 && tty_id < NUM_TERMINALS) {
        TtyState* tty = kernel_state.terminals[tty_id];
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
    TracePrintf(2, "UNHANDLED TRAP: type %d, code 0x%x, addr 0x%x\n",
                uctxt->vector, uctxt->code, uctxt->addr);
    
    
    switch (uctxt->vector) {
        case TRAP_MEMORY:
            TracePrintf(0, "Memory trap not yet implemented!\n");
            break;
        case TRAP_ILLEGAL:
            TracePrintf(0, "Illegal instruction trap not yet implemented!\n");
            break;
        case TRAP_MATH:
            TracePrintf(0, "Math trap not yet implemented!\n");
            break;
        case TRAP_TTY_TRANSMIT:
            TracePrintf(0, "TTY transmit trap not yet implemented!\n");
            break;
        case TRAP_TTY_RECEIVE:
            TracePrintf(0, "TTY receive trap not yet implemented!\n");
            break;
        default:
            TracePrintf(0, "Unknown trap type %d not yet implemented!\n", uctxt->vector);
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
    return 1;
}

int ValidateUserPointer(void* ptr, int len, int access_type) {
    // Basic Region 1 validation
    unsigned long ptr_addr = (unsigned long)ptr;
    if (ptr_addr < (unsigned long)VMEM_1_BASE || ptr_addr + len > (unsigned long)VMEM_1_LIMIT) {
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
    
    return 1;
}

void SyscallFork(UserContext* uctxt) {
    PCB* parent = kernel_state.current_process;
    PCB* child = CreatePCB();

    if (child == NULL) {
        uctxt->regs[0] = ERROR;
        return;
    }

    child->kernel_stack_frames = AllocateKernelStackFrames();
    if (child->kernel_stack_frames == NULL) {
        DestroyPartialPCB(child);
        uctxt->regs[0] = ERROR;
        return;
    }

    child->region1_ptbr = CreateEmptyPageTable(VMEM_1_SIZE / PAGESIZE);
    if (child->region1_ptbr == NULL) {
        DestroyPartialPCB(child);
        uctxt->regs[0] = ERROR;
        return;
    }

    int pid = helper_new_pid(child->region1_ptbr);
    if (pid < 0) {
        DestroyPartialPCB(child);
        uctxt->regs[0] = ERROR;
        return;
    }
    child->pid = pid;

    if (CloneRegion1AddressSpace(parent, child) == ERROR) {
        DestroyPartialPCB(child);
        uctxt->regs[0] = ERROR;
        return;
    }

    child->user_heap_break = parent->user_heap_break;
    memcpy(&child->user_context, &parent->user_context, sizeof(UserContext));
    child->user_context.regs[0] = 0;
    child->state = PROCESS_READY;
    child->kernel_context_valid = 0;
    CopyKernelStack(parent, child);

    AddChildProcess(parent, child);
    AddToReadyQueue(child);

    uctxt->regs[0] = child->pid;
    TracePrintf(1, "Fork: parent %d created child %d\n", parent->pid, child->pid);
}

void SyscallExec(UserContext* uctxt) {
    char* user_program = (char*)uctxt->regs[0];
    char** user_args = (char**)uctxt->regs[1];

    if (!ValidateUserString(user_program)) {
        uctxt->regs[0] = ERROR;
        return;
    }

    char* program_copy = (char*)malloc(strlen(user_program) + 1);
    if (program_copy == NULL) {
        uctxt->regs[0] = ERROR;
        return;
    }
    strcpy(program_copy, user_program);

    char** kernel_args = CopyUserArguments(user_args);
    if (kernel_args == NULL) {
        free(program_copy);
        uctxt->regs[0] = ERROR;
        return;
    }

    PCB* current = kernel_state.current_process;
    int rc = LoadProgram(program_copy, kernel_args, current);

    FreeKernelArguments(kernel_args);

    if (rc == SUCCESS) {
        free(program_copy);
        return;  // Never returns to old user context
    }

    if (rc == KILL) {
        TracePrintf(0, "Exec fatal error loading %s, terminating PID %d\n",
                    program_copy, current->pid);
        free(program_copy);
        TerminateProcess(current, ERROR);
        Schedule();
        return;
    }

    free(program_copy);
    uctxt->regs[0] = ERROR;
}

void SyscallExit(UserContext* uctxt) {
    int status = uctxt->regs[0];
    PCB* current = kernel_state.current_process;
    TracePrintf(1, "SYS_EXIT: PID %d with status %d\n", current->pid, status);

    TerminateProcess(current, status);

    if (current == kernel_state.init_process) {
        TracePrintf(0, "Init exited (status %d). Halting kernel as required.\n", status);
        kernel_state.init_process = NULL;
        Halt();
    }

    Schedule();  // Won't return here

    // Unreachable code here
    TracePrintf(0, "SYS_EXIT: Unexpected return\n");
    Halt();
}

void SyscallWait(UserContext* uctxt) {
    PCB* parent = kernel_state.current_process;
    int* status_ptr = (int*)uctxt->regs[1];
    
    // Validate status pointer if provided
    if (status_ptr != NULL && !ValidateUserPointer(status_ptr, sizeof(int), PROT_WRITE)) {
        uctxt->regs[0] = ERROR;
        return;
    }
    
    while (1) {
        PCB* child = FindZombieChild(parent);
        if (child != NULL) {
            if (status_ptr != NULL) {
                *status_ptr = child->exit_status;
            }
            uctxt->regs[0] = child->pid;
            parent->waiting_for_child = 0;
            FreePCB(child);
            return;
        }

        if (parent->children == NULL) {
            parent->waiting_for_child = 0;
            uctxt->regs[0] = ERROR;
            return;
        }

        parent->waiting_for_child = 1;
        parent->state = PROCESS_BLOCKED;
        Schedule();
    }
}

static void DestroyPartialPCB(PCB* pcb) {
    if (pcb == NULL) {
        return;
    }

    if (pcb->kernel_stack_frames != NULL) {
        FreeKernelStackFrames(pcb->kernel_stack_frames);
        pcb->kernel_stack_frames = NULL;
    }

    ReleaseRegion1Frames(pcb);
    if (pcb->region1_ptbr != NULL) {
        free(pcb->region1_ptbr);
        pcb->region1_ptbr = NULL;
    }

    if (pcb->pid >= 0) {
        helper_retire_pid(pcb->pid);
        pcb->pid = -1;
    }

    free(pcb);
}

static char** CopyUserArguments(char** user_args) {
    if (user_args == NULL) {
        char** empty = (char**)malloc(sizeof(char*));
        if (empty == NULL) {
            return NULL;
        }
        empty[0] = NULL;
        return empty;
    }

    int count = 0;
    while (1) {
        if (!ValidateUserPointer(user_args + count, sizeof(char*), PROT_READ)) {
            return NULL;
        }
        char* arg_ptr = user_args[count];
        if (arg_ptr == NULL) {
            break;
        }
        if (!ValidateUserString(arg_ptr)) {
            return NULL;
        }
        count++;
    }

    char** kernel_args = (char**)malloc((count + 1) * sizeof(char*));
    if (kernel_args == NULL) {
        return NULL;
    }

    for (int i = 0; i <= count; i++) {
        kernel_args[i] = NULL;
    }

    for (int i = 0; i < count; i++) {
        char* src = user_args[i];
        size_t len = strlen(src) + 1;
        kernel_args[i] = (char*)malloc(len);
        if (kernel_args[i] == NULL) {
            FreeKernelArguments(kernel_args);
            return NULL;
        }
        memcpy(kernel_args[i], src, len);
    }
    kernel_args[count] = NULL;
    return kernel_args;
}

static void FreeKernelArguments(char** args) {
    if (args == NULL) {
        return;
    }
    for (int i = 0; args[i] != NULL; i++) {
        free(args[i]);
    }
    free(args);
}

void SyscallGetPid(UserContext* uctxt) {
    // GetPid has no arguments, just returns the current process ID
    uctxt->regs[0] = kernel_state.current_process->pid;
    TracePrintf(2, "GetPid: process %d returning PID %d\n", 
                kernel_state.current_process->pid, uctxt->regs[0]);
}

void SyscallDelay(UserContext* uctxt) {
    int ticks = (int)uctxt->regs[0];  // User arg
    PCB* current = kernel_state.current_process;

    TracePrintf(1, "Delay: PID %d requested %d ticks\n", current->pid, ticks);
    TracePrintf(1, "Delay regs: [%d %d %d %d %d %d %d %d], code=0x%x\n",
                uctxt->regs[0], uctxt->regs[1], uctxt->regs[2], uctxt->regs[3],
                uctxt->regs[4], uctxt->regs[5], uctxt->regs[6], uctxt->regs[7],
                uctxt->code);

    if (ticks <= 0) {
        uctxt->regs[0] = 0;
        return;
    }

    current->delay_remaining = ticks;
    current->state = PROCESS_BLOCKED;
    AddToDelayQueue(current);
    uctxt->regs[0] = 0;  // Success
    Schedule();  // Switch away until timer wakes us
    TracePrintf(1, "Delay: PID %d completed %d ticks\n", current->pid, ticks);
}


void SyscallBrk(UserContext* uctxt) {
    void* addr = (void*)uctxt->regs[0];
    PCB* current = kernel_state.current_process;
    if (addr == NULL) {
        uctxt->regs[0] = (int)current->user_heap_break;
        TracePrintf(2, "Brk: PID %d queried break -> %p\n", current->pid, current->user_heap_break);
        return;
    }
    int result = GrowUserHeap(current, addr);
    if (result == SUCCESS) {
        uctxt->regs[0] = (int)current->user_heap_break;
    } else {
        uctxt->regs[0] = ERROR;
    }
    TracePrintf(2, "Brk: PID %d to %p -> %p\n", current->pid, addr, current->user_heap_break);
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
    
    if (tty_id < 0 || tty_id >= NUM_TERMINALS || !kernel_state.terminals[tty_id]) {
        uctxt->regs[0] = ERROR;
        return;
    }
    
    TtyState* tty = kernel_state.terminals[tty_id];
    
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
    
    if (tty_id < 0 || tty_id >= NUM_TERMINALS || !kernel_state.terminals[tty_id]) {
        uctxt->regs[0] = ERROR;
        return;
    }
    
    TtyState* tty = kernel_state.terminals[tty_id];
    
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
        kernel_buf[i] = ((char*)buf)[i];
    }
    
    // Start transmission
    tty->transmit_busy = 1;
    TtyTransmit(tty_id, kernel_buf, len);
    
    // Note: kernel_buf will be freed when transmission completes in HandleTrapTtyTransmit
    uctxt->regs[0] = len;
    TracePrintf(1, "TTY write: process %d writing %d bytes to TTY %d\n", 
                current->pid, len, tty_id);
}
