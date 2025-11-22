#include "kernel.h"
#include "memory.h"
#include "process.h"
#include "trap.h"

static PCB* CreateUserProcess(const char* tag, char* program, char** args) {
    TracePrintf(1, "%s: starting for %s\n", tag, program ? program : "<null>");

    PCB* pcb = CreatePCB();
    if (pcb == NULL) {
        return NULL;
    }

    pcb->kernel_stack_frames = AllocateKernelStackFrames();
    if (pcb->kernel_stack_frames == NULL) {
        FreePCB(pcb);
        return NULL;
    }

    pcb->region1_ptbr = CreateEmptyPageTable(VMEM_1_SIZE / PAGESIZE);
    if (pcb->region1_ptbr == NULL) {
        FreePCB(pcb);
        return NULL;
    }

    int pid = helper_new_pid(pcb->region1_ptbr);
    if (pid < 0) {
        FreePCB(pcb);
        return NULL;
    }
    pcb->pid = pid;

    if (LoadProgram(program, args, pcb) == ERROR) {
        FreePCB(pcb);
        return NULL;
    }

    pcb->state = PROCESS_READY;

    TracePrintf(1, "%s: PID %d ready (PC=%p, SP=%p)\n",
                tag, pcb->pid, pcb->user_context.pc, pcb->user_context.sp);
    return pcb;
}

PCB* CreatePCB() {
    // Allocate and initialize a new PCB
    PCB* pcb = (PCB*)malloc(sizeof(PCB));
    if (pcb == NULL) return NULL;
    memset(pcb, 0, sizeof(PCB));
    InitializePCB(pcb);

    pcb->pid = -1; // Will be set later

    return pcb;
}

void InitializePCB(PCB* pcb) {
    if (pcb == NULL) return;

    pcb->state = PROCESS_READY;
    pcb->pid = -1;
    pcb->kernel_stack_size = KERNEL_STACK_MAXSIZE;
    pcb->kernel_context_valid = 0;
    pcb->user_heap_break = (void*)VMEM_1_BASE;  // Start of Region 1
    pcb->parent = NULL;
    pcb->children = NULL;
    pcb->siblings = NULL;
    pcb->next = NULL;
    pcb->exit_status = 0;
    pcb->is_zombie = 0;
    pcb->waiting_for_child = 0; 
    pcb->delay_remaining = 0;
}

void FreePCB(PCB* pcb) {
    if (pcb == NULL) return;
    
    TracePrintf(2, "Freeing PCB for process %d\n", pcb->pid);
    
    // Free kernel stack frames
    if (pcb->kernel_stack_frames != NULL) {
        FreeKernelStackFrames(pcb->kernel_stack_frames);
        pcb->kernel_stack_frames = NULL;
    }
    
    ReleaseRegion1Frames(pcb);
    if (pcb->region1_ptbr != NULL) {
        free(pcb->region1_ptbr);
        pcb->region1_ptbr = NULL;
    }
    
    // Remove from parent's children list
    if (pcb->parent != NULL) {
        RemoveChildProcess(pcb->parent, pcb);
    }
    
    // Orphan any children
    OrphanChildren(pcb);
    
    // Retire the PID with helper
    helper_retire_pid(pcb->pid);

    free(pcb);
}

PCB* CreateIdleProcess(char* program, char** args) {
    return CreateUserProcess("CreateIdleProcess", program, args);
}

PCB* CreateInitProcess(char* program, char** args) {
    return CreateUserProcess("CreateInitProcess", program, args);
}

void AddToReadyQueue(PCB* pcb) {
    if (pcb == NULL) return;
    pcb->next = NULL;
    if (kernel_state.ready_queue == NULL) {
        kernel_state.ready_queue = pcb;
        kernel_state.ready_queue_tail = pcb;
    } else {
        kernel_state.ready_queue_tail->next = pcb;
        kernel_state.ready_queue_tail = pcb;
    }
    TracePrintf(2, "Added PID %d to ready queue\n", pcb->pid);
}

void ProcessDelayQueue(void) {
    PCB* prev = NULL;
    PCB* current = kernel_state.delay_queue;
    
    while (current != NULL) {
        // Decrement the delay counter
        current->delay_remaining--;
        
        TracePrintf(3, "ProcessDelayQueue: PID %d has %d ticks remaining\n",
                   current->pid, current->delay_remaining);
        
        // Check if delay has expired
        if (current->delay_remaining <= 0) {
            // Remove from delay queue
            PCB* next = current->next;
            
            if (prev == NULL) {
                kernel_state.delay_queue = next;
            } else {
                prev->next = next;
            }
            
            // Move to ready queue
            current->state = PROCESS_READY;
            current->next = NULL;
            AddToReadyQueue(current);
            
            TracePrintf(1, "Delay expired for process %d, moved to ready queue\n",
                       current->pid);
            
            current = next;
        } else {
            prev = current;
            current = current->next;
        }
    }
}

void AddToDelayQueue(PCB* pcb) {
    if (pcb == NULL) return;
    pcb->next = kernel_state.delay_queue;
    kernel_state.delay_queue = pcb;
    TracePrintf(2, "Added PID %d to delay queue\n", pcb->pid);
}

PCB* RemoveFromReadyQueue() {
    PCB* front = kernel_state.ready_queue;
    if (front != NULL) {
        kernel_state.ready_queue = front->next;
        if (kernel_state.ready_queue == NULL) {
            kernel_state.ready_queue_tail = NULL;
        }
        front->next = NULL;
        TracePrintf(2, "Removed PID %d from ready queue\n", front->pid);
    }
    return front;
}

void TerminateProcess(PCB* pcb, int exit_status) {
    if (pcb == NULL) return;
    TracePrintf(1, "Terminating process %d with exit status %d\n", 
                pcb->pid, exit_status);
    
    // Set process state and exit status
    pcb->state = PROCESS_ZOMBIE;
    pcb->exit_status = exit_status;
    pcb->is_zombie = 1;
    
    // Orphan children to init (or null if init missing)
    OrphanChildren(pcb);

    // Add to zombie list for parent to collect
    pcb->next = kernel_state.zombie_list;
    kernel_state.zombie_list = pcb;
    
    // Cleanup: release Region 1 frames, but keep page table allocated until wait() reaps
    ReleaseRegion1Frames(pcb);
    
    // Clear user page table registers and flush TLB to prevent lingering mappings
    if (kernel_state.current_process == pcb) {
        WriteRegister(REG_PTBR1, 0);
        WriteRegister(REG_PTLR1, 0);
        FlushAllTLB();
    }
    
    // Wake parent waiting in Wait
    if (pcb->parent && pcb->parent->waiting_for_child) {
        pcb->parent->waiting_for_child = 0;
        if (pcb->parent->state == PROCESS_BLOCKED) {
            pcb->parent->state = PROCESS_READY;
            AddToReadyQueue(pcb->parent);
        }
    }

    // Note: Do NOT free kernel stack or PCB yet -- wait for wait() to reap and call FreePCB
    TracePrintf(1, "PID %d terminated: resources freed, added to zombie list\n", pcb->pid);
}

void Schedule() {
    TracePrintf(2, "=== Schedule Called ===\n");
    PCB* current = kernel_state.current_process;
    if (current) {
        TracePrintf(2, "Current: PID=%d, state=%d\n", current->pid, current->state);
    }
    
    // If current running, move to ready (unless blocked/zombie)
    if (current && current->state == PROCESS_RUNNING && current != kernel_state.idle_process) {
        current->state = PROCESS_READY;
        AddToReadyQueue(current);
    }
    
    // Pick next from ready
    PCB* next = RemoveFromReadyQueue();
    if (next == NULL) {
        // Fallback to idle
        next = kernel_state.idle_process;
        if (next == NULL) {
            TracePrintf(0, "Schedule: No idle, halting\n");
            Halt();
        }
        TracePrintf(2, "Fallback to idle PID %d\n", next->pid);
    }
    
    // Dispatch
    Dispatch(next);
    TracePrintf(2, "Next: PID=%d\n", next->pid);
}

void Dispatch(PCB* next_process) {
    if (next_process == NULL) {
        TracePrintf(0, "Dispatch: NULL next_process, halting\n");
        Halt();
        return;
    }

    PCB* previous = kernel_state.current_process;
    if (previous == next_process) {
        if (next_process != NULL) {
            next_process->state = PROCESS_RUNNING;
        }
        TracePrintf(2, "Dispatch: Already running PID %d, no switch\n",
                    previous ? previous->pid : -1);
        return;
    }

    TracePrintf(1, "Dispatch: Switching from PID %d to PID %d\n", 
                (previous ? previous->pid : -1), next_process->pid);

    kernel_state.current_process = next_process;
    next_process->state = PROCESS_RUNNING;

    // Set up memory mapping (PTBR1/PTLR1 for user; 0 for kernel/idle)
    SetupProcessMemoryMapping(next_process);

    if (KernelContextSwitch(KCSwitch, previous, next_process) < 0) {
        TracePrintf(0, "Dispatch: KernelContextSwitch failed for PID %d\n", next_process->pid);
        Halt();
    }
}

KernelContext* KCSwitch(KernelContext* kc_in, void* curr_pcb_p, void* next_pcb_p) {
    PCB* curr_pcb = (PCB*)curr_pcb_p;
    PCB* next_pcb = (PCB*)next_pcb_p;
    
    if (next_pcb == NULL) {
        TracePrintf(0, "KCSwitch: next process is NULL\n");
        return kc_in;
    }

    TracePrintf(1, "KCSwitch: saving PID %d, loading PID %d\n",
                curr_pcb ? curr_pcb->pid : -1,
                next_pcb->pid);

    if (curr_pcb != NULL && kc_in != NULL) {
        memcpy(&curr_pcb->kernel_context, kc_in, sizeof(KernelContext));
        curr_pcb->kernel_context_valid = 1;
    }

    if (!next_pcb->kernel_context_valid) {
        if (kc_in == NULL) {
            TracePrintf(0, "KCSwitch: cannot initialize PID %d without kc_in\n", next_pcb->pid);
            return kc_in;
        }

        TracePrintf(1, "KCSwitch: initializing kernel context for PID %d\n", next_pcb->pid);
        memcpy(&next_pcb->kernel_context, kc_in, sizeof(KernelContext));
        CopyKernelStack(curr_pcb, next_pcb);
        next_pcb->kernel_context_valid = 1;
    }

    SwitchKernelStackMapping(next_pcb);

    return &next_pcb->kernel_context;
}

void SaveUserContext(UserContext* dest, UserContext* src) {
    // Save user context from src to dest
    if (dest == NULL || src == NULL) return;
    memcpy(dest, src, sizeof(UserContext));
}

void RestoreUserContext(UserContext* dest, UserContext* src) {
    if (dest == NULL || src == NULL) {
        TracePrintf(0, "RestoreUserContext: NULL pointers\n");
        return;
    }
    TracePrintf(2, "RestoreUserContext: copying from %p to %p\n", src, dest);
    memcpy(dest, src, sizeof(UserContext));
}

void SetupProcessMemoryMapping(PCB* pcb) {
    if (pcb == NULL) {
        return;
    }

    TracePrintf(2, "SetupProcessMemoryMapping: PID %d (PTBR1=0x%p)\n",
                pcb->pid, pcb->region1_ptbr);

    if (pcb->region1_ptbr != NULL) {
        WriteRegister(REG_PTBR1, (unsigned int)pcb->region1_ptbr);
        WriteRegister(REG_PTLR1, VMEM_1_SIZE / PAGESIZE);
        TracePrintf(2, "  User mapping -> PTLR1=%d\n", VMEM_1_SIZE / PAGESIZE);
    } else {
        WriteRegister(REG_PTBR1, 0);
        WriteRegister(REG_PTLR1, 0);
        TracePrintf(2, "  Kernel-only mapping (Region 1 disabled)\n");
    }

    FlushAllTLB();
    TracePrintf(2, "  TLB flushed\n");
}

// Process relationship management
void AddChildProcess(PCB* parent, PCB* child) {
    if (parent == NULL || child == NULL) return;
    
    child->parent = parent;
    child->siblings = parent->children;
    parent->children = child;
    
    TracePrintf(2, "Process %d is now child of process %d\n", 
                child->pid, parent->pid);
}

void RemoveChildProcess(PCB* parent, PCB* child) {
    if (parent == NULL || child == NULL) return;
    
    PCB* prev = NULL;
    PCB* current = parent->children;
    
    // Traverse to find child
    while (current != NULL && current != child) {
        prev = current;
        current = current->siblings;
    }
    
    // Remove from list
    if (current != NULL) {
        if (prev == NULL) {
            parent->children = current->siblings;
        } else {
            prev->siblings = current->siblings;
        }
        child->parent = NULL;
        child->siblings = NULL;
    }
}

void OrphanChildren(PCB* parent) {
    if (parent == NULL) return;
    PCB* child = parent->children;
    parent->children = NULL;

    while (child != NULL) {
        PCB* next = child->siblings;
        if (kernel_state.init_process != NULL && child != kernel_state.init_process) {
            child->parent = kernel_state.init_process;
            child->siblings = kernel_state.init_process->children;
            kernel_state.init_process->children = child;
        } else {
            child->parent = NULL;
            child->siblings = NULL;
        }
        child = next;
    }
}

PCB* FindZombieChild(PCB* parent) {
    if (parent == NULL) return NULL;
    
    PCB* zombie = kernel_state.zombie_list;
    PCB* prev = NULL;
    
    // Search for a zombie child of the given parent
    while (zombie != NULL) {
        if (zombie->parent == parent) {
            // Found a zombie child - remove from zombie list and return it
            if (prev == NULL) {
                kernel_state.zombie_list = zombie->next;
            } else {
                prev->next = zombie->next;
            }
            zombie->next = NULL;
            return zombie;
        }
        prev = zombie;
        zombie = zombie->next;
    }
    
    // No zombie child found
    return NULL;
}

