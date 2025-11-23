#include "kernel.h"
#include "memory.h"
#include "process.h"
#include "trap.h"

// Global variable
static TtyState terminal_states[NUM_TERMINALS];
KernelState kernel_state;

void KernelStart(char* cmd_args[], unsigned int pmem_size, UserContext* uctxt) {
    
    TracePrintf(1, "Kernel starting...\n");
    
    // Initialize kernel globals
    memset(&kernel_state, 0, sizeof(KernelState));

    // Initialize all queues
    kernel_state.ready_queue = NULL;
    kernel_state.delay_queue = NULL;      // ADD THIS
    kernel_state.zombie_list = NULL;      // ADD THIS
    kernel_state.current_process = NULL;
    kernel_state.idle_process = NULL;
    kernel_state.init_process = NULL;
    kernel_state.ready_queue_tail = NULL;

    // Initialize kernel heap tracking
    kernel_state.original_kernel_brk = (void*)((GET_ORIG_KERNEL_BRK_PAGE() << PAGESHIFT) + VMEM_0_BASE);
    kernel_state.kernel_brk = kernel_state.original_kernel_brk;
    kernel_state.vm_enabled = 0;
    
    TracePrintf(1, "Initial kernel break: %p\n", kernel_state.kernel_brk);
    
    // Phase 1: Memory initialization
    InitializeMemorySubsystem(pmem_size);
    BuildInitialRegion0PageTable();
    TracePrintf(1, "Region 0 page table built\n");

    // Phase 2: Enable virtual memory
    int kernel_stack_vpn = (KERNEL_STACK_BASE - VMEM_0_BASE) >> PAGESHIFT;
    TracePrintf(1, "Final verification before enabling VM:\n");
    for (int i = 0; i < (KERNEL_STACK_MAXSIZE / PAGESIZE); i++) {
        int vpn = kernel_stack_vpn + i;
        TracePrintf(1, "  VPN %d: valid=%d, prot=0x%x\n",
                   vpn, kernel_state.region0_ptbr[vpn].valid,
                   kernel_state.region0_ptbr[vpn].prot);
    }

    WriteRegister(REG_PTBR0, (unsigned int)kernel_state.region0_ptbr);
    WriteRegister(REG_PTLR0, kernel_state.region0_ptlr);
    WriteRegister(REG_VM_ENABLE, 1);
    kernel_state.vm_enabled = 1;
    TracePrintf(1, "Virtual memory enabled\n");

    // Phase 3: Interrupt system
    InitializeInterruptVectorTable();
    WriteRegister(REG_VECTOR_BASE, (unsigned int)interrupt_vector_table);
    
    char* init_program = (cmd_args[0] != NULL) ? cmd_args[0] : "src/init";
    char* idle_program = (cmd_args[1] != NULL) ? cmd_args[1] : "src/idle";

    char* init_args[] = {init_program, NULL};
    char* idle_args[] = {idle_program, NULL};

    // Phase 4: Create idle process FIRST
    kernel_state.idle_process = CreateIdleProcess(idle_program, idle_args);
    if (kernel_state.idle_process == NULL) {
        TracePrintf(0, "Failed to create idle process\n");
        Halt();
    }
    TracePrintf(1, "Created idle process PID %d\n", kernel_state.idle_process->pid);

    // Phase 5: Create init process
    kernel_state.init_process = CreateInitProcess(init_program, init_args);
    if (kernel_state.init_process == NULL) {
        TracePrintf(0, "Failed to create init process\n");
        Halt();
    }
    AddToReadyQueue(kernel_state.init_process);
    TracePrintf(1, "Created and loaded init process PID %d\n", kernel_state.init_process->pid);
    
    // Terminals
    InitializeTerminals();
    
    // Initial dispatch
    Schedule();
    if (kernel_state.current_process == NULL) {
        TracePrintf(0, "No initial process\n");
        Halt();
    }
    RestoreUserContext(uctxt, &kernel_state.current_process->user_context);
    TracePrintf(1, "Leaving KernelStart, switching to PID %d (PC=0x%p, SP=0x%p)\n",
                kernel_state.current_process->pid, uctxt->pc, uctxt->sp);
}

int SetKernelBrk(void* addr) {
    if (addr == NULL) {
        TracePrintf(0, "SetKernelBrk: NULL address\n");
        return ERROR;
    }
    
    // Round up to page boundary
    void* new_brk = (void*)UP_TO_PAGE(addr);
    
    TracePrintf(2, "SetKernelBrk: requested %p, rounded to %p, current brk %p, VM enabled: %d\n",
                addr, new_brk, kernel_state.kernel_brk, kernel_state.vm_enabled);
    
    // Check if we're shrinking the heap (typically not allowed)
    if (new_brk < kernel_state.kernel_brk) {
        TracePrintf(1, "SetKernelBrk: attempt to shrink kernel heap from %p to %p\n",
                   kernel_state.kernel_brk, new_brk);
        return ERROR;
    }
    
    // If not growing, just update and return
    if (new_brk == kernel_state.kernel_brk) {
        return SUCCESS;
    }
    
    if (!kernel_state.vm_enabled) {
        // Pre-VM: Just track the new break value
        // Validate that we're not growing beyond what we initially mapped
        void* max_pre_vm_brk = (void*)((GET_ORIG_KERNEL_BRK_PAGE() << PAGESHIFT) + VMEM_0_BASE);
        
        if (new_brk > max_pre_vm_brk) {
            TracePrintf(0, "SetKernelBrk: pre-VM heap growth beyond initial mapping: %p > %p\n",
                       new_brk, max_pre_vm_brk);
            return ERROR;
        }
        
        kernel_state.kernel_brk = new_brk;
        TracePrintf(2, "SetKernelBrk: pre-VM update to %p\n", kernel_state.kernel_brk);
        return SUCCESS;
    }
    
    // Post-VM: Call memory.c to actually map the new pages
    return GrowKernelHeap(new_brk);

}

void InitializeTerminals(void) {
    for (int i = 0; i < NUM_TERMINALS; i++) {
        terminal_states[i].tty_id = i;
        terminal_states[i].transmit_busy = 0;
        terminal_states[i].active_chunk = 0;
        terminal_states[i].write_head = NULL;
        terminal_states[i].write_tail = NULL;
        terminal_states[i].input_head = NULL;
        terminal_states[i].input_tail = NULL;
        terminal_states[i].read_wait_head = NULL;
        terminal_states[i].read_wait_tail = NULL;
        kernel_state.terminals[i] = &terminal_states[i];
    }
    TracePrintf(1, "Initialized %d terminals\n", NUM_TERMINALS);
}

TtyState* GetTerminalState(int tty_id) {
    if (tty_id < 0 || tty_id >= NUM_TERMINALS) {
        return NULL;
    }
    return &terminal_states[tty_id];
}

int ValidateTerminalId(int tty_id) {
    return (tty_id >= 0 && tty_id < NUM_TERMINALS);
}
