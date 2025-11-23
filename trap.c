#include <stdlib.h>
#include <string.h>

#include "kernel.h"
#include "memory.h"
#include "process.h"
#include "trap.h"

static char** CopyUserArguments(char** user_args);
static void FreeKernelArguments(char** args);
static void DestroyPartialPCB(PCB* pcb);
static void EnqueueReadWaiter(TtyState* tty, PCB* pcb);
static PCB* DequeueReadWaiter(TtyState* tty);
static void EnqueueWriteRequest(TtyState* tty, TtyWriteRequest* req);
static void TryLaunchTransmit(TtyState* tty);
static void StartTransmitChunk(TtyState* tty, TtyWriteRequest* req);
static KernelLock* AllocateKernelLock(int* out_id);
static KernelLock* LookupKernelLock(int lock_id);
static void EnqueueLockWaiter(KernelLock* lock, PCB* pcb);
static PCB* DequeueLockWaiter(KernelLock* lock);
static int AcquireKernelLock(KernelLock* lock, PCB* current);
static int ReleaseKernelLock(KernelLock* lock, PCB* current);
static KernelCvar* AllocateKernelCvar(int* out_id);
static KernelCvar* LookupKernelCvar(int cvar_id);
static void EnqueueCvarWaiter(KernelCvar* cvar, PCB* pcb);
static PCB* DequeueCvarWaiter(KernelCvar* cvar);

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
    PCB* current = kernel_state.current_process;
    if (current == NULL) {
        TracePrintf(0, "HandleTrapKernel: no current process\n");
        return;
    }

    // Step 1: Save current user context to process control block
    SaveUserContext(&current->user_context, uctxt);
    UserContext* active_ctx = &current->user_context;

    // Step 2: Extract system call number from context and log
    int raw_code = active_ctx->code;
    int syscall_num = raw_code & YALNIX_MASK;
    TracePrintf(2, "Syscall vector=0x%x (id=%d) from PID %d\n",
                raw_code, syscall_num, current->pid);

    // Step 3: Dispatch to appropriate system call handler and handle unknown system call with error
    switch (syscall_num) {
        case SYS_FORK:
            SyscallFork(active_ctx);
            break;
        case SYS_EXEC:
            SyscallExec(active_ctx);
            break;
        case SYS_EXIT:
            SyscallExit(active_ctx);
            break;
        case SYS_WAIT:
            SyscallWait(active_ctx);
            break;
        case SYS_GETPID:
            SyscallGetPid(active_ctx);
            break;
        case SYS_BRK:
            SyscallBrk(active_ctx);
            break;
        case SYS_DELAY:
            SyscallDelay(active_ctx);
            break;
        case SYS_TTY_READ:
            SyscallTtyRead(active_ctx);
            break;
        case SYS_TTY_WRITE:
            SyscallTtyWrite(active_ctx);
            break;
        case SYS_LOCK_INIT:
            SyscallLockInit(active_ctx);
            break;
        case SYS_LOCK_ACQUIRE:
            SyscallLockAcquire(active_ctx);
            break;
        case SYS_LOCK_RELEASE:
            SyscallLockRelease(active_ctx);
            break;
        case SYS_CVAR_INIT:
            SyscallCvarInit(active_ctx);
            break;
        case SYS_CVAR_WAIT:
            SyscallCvarWait(active_ctx);
            break;
        case SYS_CVAR_SIGNAL:
            SyscallCvarSignal(active_ctx);
            break;
        case SYS_CVAR_BROADCAST:
            SyscallCvarBroadcast(active_ctx);
            break;
        default:
            TracePrintf(0, "Unknown syscall code 0x%x (id=%d)\n",
                        raw_code, syscall_num);
            active_ctx->regs[0] = ERROR;
            break;
    }
    // Step 4: Restore updated user context before returning to user mode
    if (kernel_state.current_process != NULL &&
        kernel_state.current_process->state == PROCESS_RUNNING) {
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
        if (tty == NULL || tty->write_head == NULL) {
            TracePrintf(0, "TTY %d transmit trap with no pending request\n", tty_id);
            tty->transmit_busy = 0;
            tty->active_chunk = 0;
        } else {
            TtyWriteRequest* req = tty->write_head;
            req->sent += tty->active_chunk;
            TracePrintf(2, "TTY %d completed chunk %d/%d\n",
                        tty_id, req->sent, req->length);

            if (req->sent < req->length) {
                StartTransmitChunk(tty, req);
            } else {
                tty->write_head = req->next;
                if (tty->write_head == NULL) {
                    tty->write_tail = NULL;
                }
                tty->transmit_busy = 0;
                tty->active_chunk = 0;
                PCB* owner = req->owner;
                if (owner) {
                    owner->state = PROCESS_READY;
                    owner->next = NULL;
                    AddToReadyQueue(owner);
                    TracePrintf(1, "TTY %d completed write for PID %d (%d bytes)\n",
                                tty_id, owner->pid, req->length);
                }
                free(req->buffer);
                free(req);
                TryLaunchTransmit(tty);
            }
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
        if (tty == NULL) {
            RestoreUserContext(uctxt, &kernel_state.current_process->user_context);
            return;
        }

        TtyLine* line = (TtyLine*)malloc(sizeof(TtyLine));
        char fallback[TERMINAL_MAX_LINE];
        char* target = line ? line->data : fallback;
        int len = TtyReceive(tty_id, target, TERMINAL_MAX_LINE);
        int enqueued_line = 0;
        if (!line) {
            TracePrintf(0, "TTY %d dropped input (out of memory)\n", tty_id);
        } else if (len >= 0) {
            line->length = len;
            line->consumed = 0;
            line->next = NULL;
            if (tty->input_head == NULL) {
                tty->input_head = line;
                tty->input_tail = line;
            } else {
                tty->input_tail->next = line;
                tty->input_tail = line;
            }
            TracePrintf(1, "TTY %d buffered %d bytes of input\n", tty_id, len);
            enqueued_line = 1;
        } else {
            free(line);
        }

        if (enqueued_line) {
            PCB* reader = DequeueReadWaiter(tty);
            if (reader) {
                reader->state = PROCESS_READY;
                reader->next = NULL;
                AddToReadyQueue(reader);
                TracePrintf(1, "TTY %d woke reader PID %d\n", tty_id, reader->pid);
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
    child->kernel_stack_copied = 0;
    child->kernel_clone_source = parent;

    AddChildProcess(parent, child);
    AddToReadyQueue(child);

    uctxt->regs[0] = child->pid;
    TracePrintf(1, "Fork: parent %d created child %d\n", parent->pid, child->pid);

    // Yield immediately so the child snapshots the current kernel stack/context
    // before the parent executes additional syscalls (e.g., Wait) that would
    // otherwise mutate the clone source and confuse lazy copy logic.
    Schedule();
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

static void EnqueueReadWaiter(TtyState* tty, PCB* pcb) {
    if (tty == NULL || pcb == NULL) {
        return;
    }
    pcb->next = NULL;
    if (tty->read_wait_head == NULL) {
        tty->read_wait_head = pcb;
        tty->read_wait_tail = pcb;
    } else {
        tty->read_wait_tail->next = pcb;
        tty->read_wait_tail = pcb;
    }
}

static PCB* DequeueReadWaiter(TtyState* tty) {
    if (tty == NULL || tty->read_wait_head == NULL) {
        return NULL;
    }
    PCB* pcb = tty->read_wait_head;
    tty->read_wait_head = pcb->next;
    if (tty->read_wait_head == NULL) {
        tty->read_wait_tail = NULL;
    }
    pcb->next = NULL;
    return pcb;
}

static void EnqueueWriteRequest(TtyState* tty, TtyWriteRequest* req) {
    if (tty == NULL || req == NULL) {
        return;
    }
    req->next = NULL;
    if (tty->write_head == NULL) {
        tty->write_head = req;
        tty->write_tail = req;
    } else {
        tty->write_tail->next = req;
        tty->write_tail = req;
    }
}

static void StartTransmitChunk(TtyState* tty, TtyWriteRequest* req) {
    if (tty == NULL || req == NULL) {
        return;
    }
    int remaining = req->length - req->sent;
    if (remaining <= 0) {
        return;
    }
    int chunk = remaining > TERMINAL_MAX_LINE ? TERMINAL_MAX_LINE : remaining;
    tty->transmit_busy = 1;
    tty->active_chunk = chunk;
    TracePrintf(2, "TTY %d transmitting %d bytes (remaining %d)\n",
                tty->tty_id, chunk, remaining);
    TtyTransmit(tty->tty_id, req->buffer + req->sent, chunk);
}

static void TryLaunchTransmit(TtyState* tty) {
    if (tty == NULL || tty->transmit_busy) {
        return;
    }
    if (tty->write_head == NULL) {
        return;
    }
    StartTransmitChunk(tty, tty->write_head);
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

    // When Schedule returns immediately, we are running a *different* process
    // (who shouldn't continue executing this syscall). Only resume the
    // completion path when the original process is scheduled again.
    if (kernel_state.current_process != current) {
        return;
    }

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
    
    if (len <= 0) {
        uctxt->regs[0] = 0;
        return;
    }

    if (!ValidateUserPointer(buf, len, PROT_WRITE)) {
        uctxt->regs[0] = ERROR;
        return;
    }
    
    if (tty_id < 0 || tty_id >= NUM_TERMINALS || !kernel_state.terminals[tty_id]) {
        uctxt->regs[0] = ERROR;
        return;
    }
    
    TtyState* tty = kernel_state.terminals[tty_id];

    TracePrintf(1, "TTY read: PID %d requested %d bytes from TTY %d\n",
                current->pid, len, tty_id);

    int copied = 0;
    while (copied < len) {
        TtyLine* line = tty->input_head;
        if (line == NULL) {
            if (copied > 0) {
                break;
            }
            TracePrintf(1, "TTY read: PID %d blocking on TTY %d\n",
                        current->pid, tty_id);
            EnqueueReadWaiter(tty, current);
            current->state = PROCESS_BLOCKED;
            Schedule();
            continue;
        }

        int available = line->length - line->consumed;
        if (available <= 0) {
            int eof_line = (line->length == 0);
            tty->input_head = line->next;
            if (tty->input_head == NULL) {
                tty->input_tail = NULL;
            }
            free(line);
            if (eof_line && copied == 0) {
                TracePrintf(1, "TTY read: PID %d saw EOF on TTY %d\n",
                            current->pid, tty_id);
                uctxt->regs[0] = 0;
                return;
            }
            continue;
        }

        int remaining = len - copied;
        int to_copy = available < remaining ? available : remaining;
        memcpy((char*)buf + copied, line->data + line->consumed, to_copy);
        line->consumed += to_copy;
        copied += to_copy;

        if (line->consumed >= line->length) {
            tty->input_head = line->next;
            if (tty->input_head == NULL) {
                tty->input_tail = NULL;
            }
            free(line);
        }

        // TTY reads are line-oriented: return after delivering data from one line
        break;
    }

    TracePrintf(1, "TTY read: PID %d copied %d bytes from TTY %d\n",
                current->pid, copied, tty_id);
    uctxt->regs[0] = copied;
}

void SyscallTtyWrite(UserContext* uctxt) {
    int tty_id = uctxt->regs[0];
    void* buf = (void*)uctxt->regs[1];
    int len = uctxt->regs[2];
    PCB* current = kernel_state.current_process;
    
    if (len <= 0) {
        uctxt->regs[0] = 0;
        return;
    }

    if (!ValidateUserPointer(buf, len, PROT_READ)) {
        uctxt->regs[0] = ERROR;
        return;
    }
    
    if (tty_id < 0 || tty_id >= NUM_TERMINALS || !kernel_state.terminals[tty_id]) {
        uctxt->regs[0] = ERROR;
        return;
    }
    
    TtyState* tty = kernel_state.terminals[tty_id];

    char* kernel_buf = (char*)malloc(len);
    if (!kernel_buf) {
        uctxt->regs[0] = ERROR;
        return;
    }
    memcpy(kernel_buf, buf, len);

    TtyWriteRequest* req = (TtyWriteRequest*)malloc(sizeof(TtyWriteRequest));
    if (!req) {
        free(kernel_buf);
        uctxt->regs[0] = ERROR;
        return;
    }

    req->owner = current;
    req->buffer = kernel_buf;
    req->length = len;
    req->sent = 0;
    req->next = NULL;

    EnqueueWriteRequest(tty, req);
    TryLaunchTransmit(tty);

    current->state = PROCESS_BLOCKED;
    Schedule();

    TracePrintf(1, "TTY write: PID %d completed %d bytes to TTY %d\n",
                current->pid, len, tty_id);
    uctxt->regs[0] = len;
}

void SyscallLockInit(UserContext* uctxt) {
    int* user_ptr = (int*)uctxt->regs[0];
    if (user_ptr == NULL ||
        !ValidateUserPointer(user_ptr, sizeof(int), PROT_WRITE)) {
        uctxt->regs[0] = ERROR;
        return;
    }

    int lock_id = -1;
    KernelLock* lock = AllocateKernelLock(&lock_id);
    if (lock == NULL) {
        uctxt->regs[0] = ERROR;
        return;
    }

    *user_ptr = lock_id;
    uctxt->regs[0] = 0;
}

void SyscallLockAcquire(UserContext* uctxt) {
    int lock_id = uctxt->regs[0];
    KernelLock* lock = LookupKernelLock(lock_id);
    if (lock == NULL) {
        uctxt->regs[0] = ERROR;
        return;
    }

    PCB* current = kernel_state.current_process;
    int rc = AcquireKernelLock(lock, current);
    uctxt->regs[0] = rc;
}

void SyscallLockRelease(UserContext* uctxt) {
    int lock_id = uctxt->regs[0];
    KernelLock* lock = LookupKernelLock(lock_id);
    if (lock == NULL) {
        uctxt->regs[0] = ERROR;
        return;
    }

    PCB* current = kernel_state.current_process;
    int rc = ReleaseKernelLock(lock, current);
    uctxt->regs[0] = rc;
}

void SyscallCvarInit(UserContext* uctxt) {
    int* user_ptr = (int*)uctxt->regs[0];
    if (user_ptr == NULL ||
        !ValidateUserPointer(user_ptr, sizeof(int), PROT_WRITE)) {
        uctxt->regs[0] = ERROR;
        return;
    }

    int cvar_id = -1;
    KernelCvar* cvar = AllocateKernelCvar(&cvar_id);
    if (cvar == NULL) {
        uctxt->regs[0] = ERROR;
        return;
    }

    *user_ptr = cvar_id;
    uctxt->regs[0] = 0;
}

void SyscallCvarSignal(UserContext* uctxt) {
    int cvar_id = uctxt->regs[0];
    KernelCvar* cvar = LookupKernelCvar(cvar_id);
    if (cvar == NULL) {
        uctxt->regs[0] = ERROR;
        return;
    }

    PCB* waiter = DequeueCvarWaiter(cvar);
    if (waiter != NULL) {
        waiter->state = PROCESS_READY;
        AddToReadyQueue(waiter);
    }

    uctxt->regs[0] = 0;
}

void SyscallCvarBroadcast(UserContext* uctxt) {
    int cvar_id = uctxt->regs[0];
    KernelCvar* cvar = LookupKernelCvar(cvar_id);
    if (cvar == NULL) {
        uctxt->regs[0] = ERROR;
        return;
    }

    PCB* waiter = NULL;
    while ((waiter = DequeueCvarWaiter(cvar)) != NULL) {
        waiter->state = PROCESS_READY;
        AddToReadyQueue(waiter);
    }

    uctxt->regs[0] = 0;
}

void SyscallCvarWait(UserContext* uctxt) {
    int cvar_id = uctxt->regs[0];
    int lock_id = uctxt->regs[1];
    KernelCvar* cvar = LookupKernelCvar(cvar_id);
    KernelLock* lock = LookupKernelLock(lock_id);
    PCB* current = kernel_state.current_process;

    if (cvar == NULL || lock == NULL || current == NULL) {
        uctxt->regs[0] = ERROR;
        return;
    }

    if (lock->owner_pid != current->pid) {
        uctxt->regs[0] = ERROR;
        return;
    }

    EnqueueCvarWaiter(cvar, current);
    current->waiting_on_lock_id = lock->id;

    if (ReleaseKernelLock(lock, current) == ERROR) {
        uctxt->regs[0] = ERROR;
        return;
    }

    current->state = PROCESS_BLOCKED;
    Schedule();

    int rc = AcquireKernelLock(lock, current);
    if (rc != 0) {
        TracePrintf(0,
                    "CvarWait reacquire failed: lock=%d owner=%d in_use=%d rc=%d pid=%d\n",
                    lock ? lock->id : -1,
                    lock ? lock->owner_pid : -1,
                    lock ? lock->in_use : 0,
                    rc,
                    current ? current->pid : -1);
    }
    uctxt->regs[0] = rc;
}

static KernelLock* AllocateKernelLock(int* out_id) {
    for (int i = 0; i < MAX_KERNEL_LOCKS; i++) {
        KernelLock* lock = &kernel_state.locks[i];
        if (!lock->in_use) {
            lock->in_use = 1;
            lock->id = i + 1;
            lock->owner_pid = -1;
            lock->wait_head = NULL;
            lock->wait_tail = NULL;
            if (out_id) {
                *out_id = lock->id;
            }
            return lock;
        }
    }
    return NULL;
}

static KernelLock* LookupKernelLock(int lock_id) {
    if (lock_id <= 0 || lock_id > MAX_KERNEL_LOCKS) {
        return NULL;
    }
    KernelLock* lock = &kernel_state.locks[lock_id - 1];
    return lock->in_use ? lock : NULL;
}

static void EnqueueLockWaiter(KernelLock* lock, PCB* pcb) {
    if (lock == NULL || pcb == NULL) {
        return;
    }
    pcb->next = NULL;
    if (lock->wait_tail == NULL) {
        lock->wait_head = pcb;
        lock->wait_tail = pcb;
    } else {
        lock->wait_tail->next = pcb;
        lock->wait_tail = pcb;
    }
}

static PCB* DequeueLockWaiter(KernelLock* lock) {
    if (lock == NULL || lock->wait_head == NULL) {
        return NULL;
    }
    PCB* pcb = lock->wait_head;
    lock->wait_head = pcb->next;
    if (lock->wait_head == NULL) {
        lock->wait_tail = NULL;
    }
    pcb->next = NULL;
    return pcb;
}

static int AcquireKernelLock(KernelLock* lock, PCB* current) {
    if (lock == NULL || current == NULL) {
        return ERROR;
    }

    if (!lock->in_use) {
        return ERROR;
    }

    if (lock->owner_pid == current->pid) {
        if (current->waiting_on_lock_id == lock->id) {
            current->waiting_on_lock_id = -1;
            return 0;
        }
        return ERROR;
    }

    while (lock->owner_pid != -1) {
        if (current->waiting_on_lock_id != lock->id) {
            EnqueueLockWaiter(lock, current);
            current->waiting_on_lock_id = lock->id;
        }
        current->state = PROCESS_BLOCKED;
        Schedule();
        if (!lock->in_use) {
            return ERROR;
        }
    }

    current->waiting_on_lock_id = -1;
    lock->owner_pid = current->pid;
    return 0;
}

static int ReleaseKernelLock(KernelLock* lock, PCB* current) {
    if (lock == NULL || current == NULL || !lock->in_use) {
        return ERROR;
    }
    if (lock->owner_pid != current->pid) {
        return ERROR;
    }

    lock->owner_pid = -1;

    PCB* waiter = DequeueLockWaiter(lock);
    if (waiter != NULL) {
        waiter->waiting_on_lock_id = -1;
        waiter->state = PROCESS_READY;
        AddToReadyQueue(waiter);
    }

    return 0;
}

static KernelCvar* AllocateKernelCvar(int* out_id) {
    for (int i = 0; i < MAX_KERNEL_CVARS; i++) {
        KernelCvar* cvar = &kernel_state.cvars[i];
        if (!cvar->in_use) {
            cvar->in_use = 1;
            cvar->id = i + 1;
            cvar->wait_head = NULL;
            cvar->wait_tail = NULL;
            if (out_id) {
                *out_id = cvar->id;
            }
            return cvar;
        }
    }
    return NULL;
}

static KernelCvar* LookupKernelCvar(int cvar_id) {
    if (cvar_id <= 0 || cvar_id > MAX_KERNEL_CVARS) {
        return NULL;
    }
    KernelCvar* cvar = &kernel_state.cvars[cvar_id - 1];
    return cvar->in_use ? cvar : NULL;
}

static void EnqueueCvarWaiter(KernelCvar* cvar, PCB* pcb) {
    if (cvar == NULL || pcb == NULL) {
        return;
    }
    pcb->next = NULL;
    if (cvar->wait_tail == NULL) {
        cvar->wait_head = pcb;
        cvar->wait_tail = pcb;
    } else {
        cvar->wait_tail->next = pcb;
        cvar->wait_tail = pcb;
    }
}

static PCB* DequeueCvarWaiter(KernelCvar* cvar) {
    if (cvar == NULL || cvar->wait_head == NULL) {
        return NULL;
    }
    PCB* pcb = cvar->wait_head;
    cvar->wait_head = pcb->next;
    if (cvar->wait_head == NULL) {
        cvar->wait_tail = NULL;
    }
    pcb->next = NULL;
    return pcb;
}
