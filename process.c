#include "kernel.h"
#include "memory.h"
#include "process.h"

PCB* CreatePCB() {
    // Allocate and initialize a new PCB
    PCB* pcb = (PCB*)malloc(sizeof(PCB));
    if (pcb == NULL) return NULL;
    memset(pcb, 0, sizeof(PCB));
    InitializePCB(pcb);
    return pcb;
}

void InitializePCB(PCB* pcb) {
    if (pcb == NULL) return;
    pcb->state = PROCESS_READY;
    pcb->pid = -1;
    pcb->kernel_stack_size = KERNEL_STACK_MAXSIZE;
    pcb->user_heap_break = (void*)VMEM_1_BASE;  // Start of Region 1
}

void FreePCB(PCB* pcb) {
    if (pcb == NULL) return;
    
    // Free kernel stack frames
    
    // Free Region 1 page table and all mapped frames
    
    // Remove from parent's children list
    
    // Orphan any children
    OrphanChildren(pcb);
    
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
    // Set up user stack in Region 1 (one page)
    int user_stack_vpn = (VMEM_1_LIMIT - PAGESIZE - VMEM_1_BASE) >> PAGESHIFT;
    int user_stack_pfn = AllocateFrame();
    if (user_stack_pfn == ERROR) {
        free(idle->region1_ptbr);
        free(idle);
        return NULL;
    }

    MapPage(idle->region1_ptbr, user_stack_vpn, user_stack_pfn, PROT_READ | PROT_WRITE);
    // Set up user context
    memcpy(&idle->user_context, uctxt, sizeof(UserContext));
    idle->user_context.sp = VMEM_1_LIMIT - sizeof(void*);  // Top of user stack
    idle->user_context.pc = (void*)DoIdle;
    // Allocate kernel stack
    idle->kernel_stack_frames = AllocateKernelStackFrames();
    if (idle->kernel_stack_frames == NULL) {
        FreeFrame(user_stack_pfn);
        free(idle->region1_ptbr);
        free(idle);
        return NULL;
    }
    // Get PID
    idle->pid = helper_new_pid(idle->region1_ptbr);
    idle->state = PROCESS_READY;
    
    TracePrintf(1, "Created idle process PID %d\n", idle->pid);
    // Return the created idle process
    return idle;
}

PCB* CreateInitProcess(char* program, char** args) {
    PCB* init = CreatePCB();
    if (init == NULL) return NULL;
    
    // Allocate kernel stack
    init->kernel_stack_frames = AllocateKernelStackFrames();
    if (init->kernel_stack_frames == NULL) {
        FreePCB(init);
        return NULL;
    }
    
    // Use KernelContextSwitch to clone current process context
    int rc = KernelContextSwitch(KCCopy, init, NULL);
    if (rc == ERROR) {
        TracePrintf(0, "Failed to clone process for init\n");
        FreePCB(init);
        return NULL;
    }
    
    // Create empty Region 1 page table
    init->region1_ptbr = CreateEmptyPageTable(VMEM_1_SIZE / PAGESIZE);
    if (init->region1_ptbr == NULL) {
        FreePCB(init);
        return NULL;
    }
    
    // Load the executable into Region 1 (placeholder - would use LoadProgram)
    // if (LoadProgram(program, args, init) == ERROR) {
    //     FreePCB(init);
    //     return NULL;
    // }
    
    // Set up initial user context for init
    init->user_context.sp = VMEM_1_LIMIT - sizeof(void*);
    init->user_context.pc = (void*)VMEM_1_BASE;  // Start of program
    
    // Get PID
    init->pid = helper_new_pid(init->region1_ptbr);
    init->state = PROCESS_READY;
    
    TracePrintf(1, "Created init process PID %d\n", init->pid);
    return init;
}

void AddToReadyQueue(PCB* pcb) {
    if (pcb == NULL) return;
    // Add the PCB to the end of the ready queue
}

PCB* RemoveFromReadyQueue() {
    // Remove and return the first PCB from the ready queue
    return NULL;
}

void TerminateProcess(PCB* pcb, int exit_status) {
    
    // Add to zombie list for parent to collect
    
    // Notify parent if waiting
    
    // If this is the current process, schedule another one
    if (pcb == kernel_state.current_process) {
        Schedule();
    }
}

void Schedule() {
    PCB* current = kernel_state.current_process;
    PCB* next = RemoveFromReadyQueue();
    
    // If no ready process, switch to idle
    
    // If next process does not match current, conduct context switch
    // If current is not idle and still runnable, re-add to ready queue
    // Dispatch the next process
}

void Dispatch(PCB* next_process) {
    PCB* old_process = kernel_state.current_process;
    kernel_state.current_process = next_process;
    
    // Context switch between old_process and next_process
    
    // Perform context switch
    
    // After switch: setup new process memory mapping
    SetupProcessMemoryMapping(next_process);
}

KernelContext* KCCopy(KernelContext* kc_in, void* new_pcb_p, void* not_used) {
    PCB* new_pcb = (PCB*)new_pcb_p;
    
    // Copy kernel context
    
    // Copy kernel stack
    
    return kc_in;
}

KernelContext* KCSwitch(KernelContext* kc_in, void* curr_pcb_p, void* next_pcb_p) {
    PCB* curr_pcb = (PCB*)curr_pcb_p;
    PCB* next_pcb = (PCB*)next_pcb_p;
    
    // Save current context
    
    // Switch kernel stack mapping
    
    // Return new context
    return &next_pcb->kernel_context;
}

void SaveUserContext(UserContext* dest, UserContext* src) {
    // Save user context from src to dest
}

void RestoreUserContext(UserContext* dest, UserContext* src) {
    // Restore user context from src to dest
}

void SetupProcessMemoryMapping(PCB* pcb) {
    if (pcb == NULL) return;
    
    // Set up Region 0 mapping (kernel)
}

// Process relationship management
void AddChildProcess(PCB* parent, PCB* child) {
    if (parent == NULL || child == NULL) return;
    
    child->parent = parent;
    child->siblings = parent->children;
    parent->children = child;
}

void RemoveChildProcess(PCB* parent, PCB* child) {
    if (parent == NULL || child == NULL) return;
    
    PCB* prev = NULL;
    PCB* current = parent->children;
    
    // Traverse to find child
    // Remove from list
}


void OrphanChildren(PCB* parent) {
    if (parent == NULL) return;
    
    // Set all children parent to NULL
}

PCB* FindZombieChild(PCB* parent) {
    if (parent == NULL) return NULL;
    
    PCB* zombie = kernel_state.zombie_list;
    PCB* prev = NULL;
    
    // Search for a zombie child of the given parent
    // If found, remove from zombie list and return it
    // Else return NULL
    return NULL;
}
