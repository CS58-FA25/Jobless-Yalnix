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
    kernel_state.next_pid = 0;

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
    
    // Phase 4: Create init process
    char* init_program = (cmd_args[0] != NULL) ? cmd_args[0] : "init";
    PCB* init_process = CreateInitProcess(init_program, cmd_args);
    
    if (init_process == NULL) {
        TracePrintf(0, "Failed to create init process, halting\n");
        Halt();
    }

    // Set init as current process
    kernel_state.current_process = init_process;
    init_process->state = PROCESS_RUNNING;

    TracePrintf(1, "Created init process PID %d\n", init_process->pid);
    TracePrintf(1, "Init PC: 0x%p, SP: 0x%p\n", 
                init_process->user_context.pc, init_process->user_context.sp);
    
    // CRITICAL: Set up memory mapping for init process before switching
    WriteRegister(REG_PTBR0, (unsigned int)kernel_state.region0_ptbr);
    WriteRegister(REG_PTLR0, kernel_state.region0_ptlr);
    WriteRegister(REG_PTBR1, (unsigned int)init_process->region1_ptbr);
    WriteRegister(REG_PTLR1, VMEM_1_SIZE / PAGESIZE);
    WriteRegister(REG_TLB_FLUSH, TLB_FLUSH_ALL);
    
    TracePrintf(1, "Memory mapping set up for init process\n");
    TracePrintf(1, "PTBR1: 0x%p\n", init_process->region1_ptbr);
    
    TracePrintf(1, "Leaving KernelStart, switching to init process\n");

    // Switch directly to init process (no scheduler, no idle)
    memcpy(uctxt, &init_process->user_context, sizeof(UserContext));
    
    TracePrintf(1, "Context copied, returning to user mode\n");
    TracePrintf(1, "User mode PC: 0x%p, SP: 0x%p\n", uctxt->pc, uctxt->sp);

    return;
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
        terminal_states[i].transmit_busy = 0;
        terminal_states[i].transmit_waiting = NULL;
        terminal_states[i].read_waiting = NULL;
        terminal_states[i].input_buffers = NULL;
        terminal_states[i].transmit_buffer = NULL;
        terminal_states[i].transmit_length = 0;
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

// Keep the CPU busy when there's no other process to run
void DoIdle(void) {
    while (1) {
        TracePrintf(1, "Idle process running\n");
        Pause();  // Wait for next interrupt
    }
}
