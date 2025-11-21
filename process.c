#include "kernel.h"
#include "memory.h"
#include "process.h"
#include "trap.h"



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
    
    // Free Region 1 page table and all mapped frames
    if (pcb->region1_ptbr != NULL) {
        // Free all mapped frames in Region 1
        int num_pages = VMEM_1_SIZE / PAGESIZE;
        for (int vpn = 0; vpn < num_pages; vpn++) {
            if (pcb->region1_ptbr[vpn].valid) {
                FreeFrame(pcb->region1_ptbr[vpn].pfn);
            }
        }
        
        // Free the page table itself
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

PCB* CreateIdleProcess(UserContext* uctxt) {
    PCB* idle = CreatePCB();
    if (idle == NULL) return NULL;
    
    // Create Region 1 page table
    idle->region1_ptbr = CreateEmptyPageTable(VMEM_1_SIZE / PAGESIZE);
    if (idle->region1_ptbr == NULL) {
        free(idle);
        return NULL;
    }
    
    // Allocate kernel stack
    idle->kernel_stack_frames = AllocateKernelStackFrames();
    if (idle->kernel_stack_frames == NULL) {
        free(idle->region1_ptbr);
        free(idle);
        return NULL;
    }

    // Set up a simple user stack in Region 1
    int user_stack_vpn = (VMEM_1_LIMIT - PAGESIZE - VMEM_1_BASE) >> PAGESHIFT;
    int user_stack_pfn = AllocateFrame();
    if (user_stack_pfn == ERROR) {
        FreeKernelStackFrames(idle->kernel_stack_frames);
        free(idle->region1_ptbr);
        free(idle);
        return NULL;
    }

    MapPage(idle->region1_ptbr, user_stack_vpn, user_stack_pfn, PROT_READ | PROT_WRITE);
    
    // Set up user context to run a simple loop in user mode
    memcpy(&idle->user_context, uctxt, sizeof(UserContext));
    
    // Use the original entry point from uctxt, but make sure it's valid
    // If the original PC is in kernel space, set a safe user space address
    if ((unsigned long)idle->user_context.pc < (unsigned long)VMEM_1_BASE) {
        // Original PC is in kernel space, set a safe user space address
        idle->user_context.pc = (void*)VMEM_1_BASE;  // Start of user space
    }
    
    idle->user_context.sp = (void*)(VMEM_1_LIMIT - sizeof(void*));  // Top of user stack
    
    // Get PID
    idle->pid = helper_new_pid(idle->region1_ptbr);
    idle->state = PROCESS_READY;
    
    TracePrintf(1, "Created idle process PID %d\n", idle->pid);
    TracePrintf(1, "Idle PC: 0x%p, SP: 0x%p\n", 
                idle->user_context.pc, idle->user_context.sp);
    
    return idle;
}

PCB* CreateInitProcess(char* program, char** args) {
    TracePrintf(1, "CreateInitProcess: starting\n");

    PCB* init = CreatePCB();
    if (init == NULL) return NULL;

    // Allocate kernel stack
    init->kernel_stack_frames = AllocateKernelStackFrames();
    if (init->kernel_stack_frames == NULL) {
        FreePCB(init);
        return NULL;
    }
    
    // Create empty Region 1 page table
    init->region1_ptbr = CreateEmptyPageTable(VMEM_1_SIZE / PAGESIZE);
    if (init->region1_ptbr == NULL) {
        FreePCB(init);
        return NULL;
    }

    // Get PID
    init->pid = helper_new_pid(init->region1_ptbr);

    // Load the program - this sets up user_context.pc and user_context.sp
    if (LoadProgram(program, args, init) == ERROR) {
        helper_retire_pid(init->pid);
        FreePCB(init);
        return NULL;
    }

    // initialize kernel context
    memset(&init->kernel_context, 0, sizeof(KernelContext));
    // Set up any initial kernel context values as needed
    
    init->state = PROCESS_READY;
    
    TracePrintf(1, "Created init process PID %d\n", init->pid);
    TracePrintf(1, "  PC: 0x%p, SP: 0x%p\n", 
                init->user_context.pc, init->user_context.sp);
    return init;
}

void AddToReadyQueue(PCB* pcb) {
    if (pcb == NULL) return;
    // Add the PCB to the end of the ready queue

    TracePrintf(2, "AddToReadyQueue: adding PID=%d\n", pcb->pid);

    pcb->state = PROCESS_READY;
    pcb->next = NULL;
    
    if (kernel_state.ready_queue == NULL) {
        kernel_state.ready_queue = pcb;
        TracePrintf(2, "  Added to first of queue\n");
    } else {
        PCB* current = kernel_state.ready_queue;
        while (current->next != NULL) {
            current = current->next;
        }
        current->next = pcb;
        TracePrintf(2, "  Added to end of queue\n");
    }
    
    TracePrintf(2, "Added process %d to ready queue\n", pcb->pid);
    TracePrintf(2, "Queue after adding PID=%d:\n", pcb->pid);
    PCB* temp = kernel_state.ready_queue;
    while (temp != NULL) {
        TracePrintf(2, "  PID=%d\n", temp->pid);
        temp = temp->next;
    }
}

void AddToDelayQueue(PCB* pcb) {
    if (pcb == NULL) return;
    
    // Add the PCB to the delay queue
    pcb->next = NULL;
    
    if (kernel_state.delay_queue == NULL) {
        kernel_state.delay_queue = pcb;
    } else {
        PCB* current = kernel_state.delay_queue;
        while (current->next != NULL) {
            current = current->next;
        }
        current->next = pcb;
    }
    
    TracePrintf(1, "Added process %d to delay queue\n", 
                pcb->pid);
}

PCB* RemoveFromReadyQueue() {
    // Remove and return the first PCB from the ready queue
    PCB* pcb = kernel_state.ready_queue;

    if (pcb != NULL) {
        kernel_state.ready_queue = pcb->next;
        pcb->next = NULL;
        TracePrintf(2, "Removed process %d from ready queue\n", pcb->pid);

        TracePrintf(2, "Remaining queue:\n");
        PCB* temp = kernel_state.ready_queue;
        while (temp != NULL) {
            TracePrintf(2, "  PID=%d\n", temp->pid);
            temp = temp->next;
        }
    } else {
        TracePrintf(2, "Ready queue is empty\n");
    }
    return pcb;
}

void TerminateProcess(PCB* pcb, int exit_status) {
    if (pcb == NULL) return;
    
    TracePrintf(1, "Terminating process %d with exit status %d\n", 
                pcb->pid, exit_status);
    
    // Set process state and exit status
    pcb->state = PROCESS_ZOMBIE;
    pcb->exit_status = exit_status;
    pcb->is_zombie = 1;
    
    // Add to zombie list for parent to collect
    pcb->next = kernel_state.zombie_list;
    kernel_state.zombie_list = pcb;
    
    // Notify parent if waiting
    if (pcb->parent != NULL && pcb->parent->state == PROCESS_BLOCKED) {
        // Check if parent is waiting for this child
        // This would require checking the parent's wait state
        // For now, just mark that a child has terminated
        TracePrintf(2, "Process %d has terminated, parent %d may be waiting\n",
                    pcb->pid, pcb->parent->pid);
    }
    
    // If this is the init process and it's exiting, halt the system
    if (pcb == kernel_state.init_process) {
        TracePrintf(0, "Init process exiting, halting system\n");
        Halt();
    }
    
    // If this is the current process, schedule another one
    if (pcb == kernel_state.current_process) {
        TracePrintf(2, "Terminating current process, scheduling next\n");
        Schedule();
    }
}

void Schedule() {
    PCB* current = kernel_state.current_process;
    PCB* next = RemoveFromReadyQueue();
    
    TracePrintf(1, "=== Schedule Called ===\n");
    TracePrintf(1, "Current process: PID=%d, state=%d\n", 
                current ? current->pid : -1, current ? current->state : -1);
    TracePrintf(1, "Next process from queue: PID=%d\n", next ? next->pid : -1);

    // If no ready process, switch to idle
    if (next == NULL) {
        TracePrintf(2, "No ready processes, keeping current process\n");
        return;
    }
    
    // If next process does not match current, conduct context switch
    if (next != current) {
        // If current is not idle and still runnable, re-add to ready queue
        if (current != NULL && current->state == PROCESS_RUNNING) {
            current->state = PROCESS_READY;
            AddToReadyQueue(current);
        }
        
        // Dispatch the next process
        Dispatch(next);
        TracePrintf(0, "ERROR: Returned from Dispatch()! Context switch failed.\n");
    } else{
        TracePrintf(1, "Schedule: staying with current process %d\n", current->pid);
    }
}

void Dispatch(PCB* next_process) {
    PCB* old_process = kernel_state.current_process;

    TracePrintf(1, "=== Dispatch Called ===\n");
    TracePrintf(1, "Old process: PID=%d\n", old_process ? old_process->pid : -1);
    TracePrintf(1, "Next process: PID=%d, PC=0x%p, SP=0x%p\n", 
                next_process->pid, next_process->user_context.pc, 
                next_process->user_context.sp);

    kernel_state.current_process = next_process;
    next_process->state = PROCESS_RUNNING;
    
    TracePrintf(1, "Dispatching from process %d to process %d\n",
                old_process ? old_process->pid : -1, 
                next_process->pid);
    
    // This includes both Region 0 (kernel stack) and Region 1 (user space)
    
    // Set up Region 0 mapping (kernel) - this should already be set correctly
    WriteRegister(REG_PTBR0, (unsigned int)kernel_state.region0_ptbr);
    WriteRegister(REG_PTLR0, kernel_state.region0_ptlr);
    
    // Set up Region 1 mapping (user) for the new process
    WriteRegister(REG_PTBR1, (unsigned int)next_process->region1_ptbr);
    WriteRegister(REG_PTLR1, VMEM_1_SIZE / PAGESIZE);
    
    int kernel_stack_vpn = (KERNEL_STACK_BASE - VMEM_0_BASE) >> PAGESHIFT;
    int kernel_stack_pages = KERNEL_STACK_MAXSIZE / PAGESIZE;
    
    for (int i = 0; i < kernel_stack_pages; i++) {
        if (next_process->kernel_stack_frames[i] != ERROR) {
            kernel_state.region0_ptbr[kernel_stack_vpn + i].valid = 1;
            kernel_state.region0_ptbr[kernel_stack_vpn + i].pfn = next_process->kernel_stack_frames[i];
            kernel_state.region0_ptbr[kernel_stack_vpn + i].prot = PROT_READ | PROT_WRITE;
            TracePrintf(3, "Dispatch: mapped kernel stack VPN %d to PFN %d\n", 
                       kernel_stack_vpn + i, next_process->kernel_stack_frames[i]);
        }
    }

    // Flush TLB for both regions to avoid stale mappings
    WriteRegister(REG_TLB_FLUSH, TLB_FLUSH_ALL);
    
    TracePrintf(1, "Dispatching to process %d: PC=0x%p, SP=0x%p\n",
                next_process->pid, next_process->user_context.pc, 
                next_process->user_context.sp);

    // Perform context switch
    int rc = KernelContextSwitch(KCSwitch, old_process, next_process);
    if (rc == ERROR) {
        TracePrintf(0, "KernelContextSwitch failed\n");
        Halt();
    }
}

KernelContext* KCCopy(KernelContext* kc_in, void* new_pcb_p, void* not_used) {
    PCB* new_pcb = (PCB*)new_pcb_p;
    TracePrintf(1, "KCCopy: starting for new process PID %d\n", new_pcb->pid);

    // Copy kernel context
    memcpy(&new_pcb->kernel_context, kc_in, sizeof(KernelContext));
    TracePrintf(2, "KCCopy: copied kernel context for process %d\n", new_pcb->pid);
    
    CopyKernelStack(kernel_state.current_process, new_pcb);
    
    TracePrintf(1, "KCCopy: completed\n");
    
    return kc_in;
}

KernelContext* KCSwitch(KernelContext* kc_in, void* curr_pcb_p, void* next_pcb_p) {
    PCB* curr_pcb = (PCB*)curr_pcb_p;
    PCB* next_pcb = (PCB*)next_pcb_p;
    
    TracePrintf(1, "KCSwitch: saving context of %d, restoring context of %d\n",
                curr_pcb ? curr_pcb->pid : -1, 
                next_pcb ? next_pcb->pid : -1);

    // Save current context
    if (curr_pcb != NULL) {
        memcpy(&curr_pcb->kernel_context, kc_in, sizeof(KernelContext));
        TracePrintf(2, "KCSwitch: saved kernel context for process %d\n", curr_pcb->pid);
    }

    TracePrintf(1, "KCSwitch: returning context for process %d\n", next_pcb->pid);
    TracePrintf(1, "KCSwitch: user context - PC=0x%p, SP=0x%p\n",
                next_pcb->user_context.pc, next_pcb->user_context.sp);

    // Return the new process's kernel context
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
    TracePrintf(2, "  PC: 0x%p, SP: 0x%p\n", src->pc, src->sp);
    
    memcpy(dest, src, sizeof(UserContext));
    
    TracePrintf(2, "RestoreUserContext: completed\n");
}

void SetupProcessMemoryMapping(PCB* pcb) {
    if (pcb == NULL) return;
    
    // Set up Region 0 mapping (kernel)
    WriteRegister(REG_PTBR0, (unsigned int)kernel_state.region0_ptbr);
    WriteRegister(REG_PTLR0, kernel_state.region0_ptlr);
    
    // Set up Region 1 mapping (user)
    WriteRegister(REG_PTBR1, (unsigned int)pcb->region1_ptbr);
    WriteRegister(REG_PTLR1, VMEM_1_SIZE / PAGESIZE);
    
    // Flush TLB for Region 1
    WriteRegister(REG_TLB_FLUSH, TLB_FLUSH_1);
    
    TracePrintf(2, "Setup memory mapping for process %d\n", pcb->pid);
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
    
    // Set all children parent to NULL
    PCB* child = parent->children;
    while (child != NULL) {
        child->parent = NULL;
        child = child->siblings;
    }
    parent->children = NULL;
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
