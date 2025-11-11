#ifndef KERNEL_H
#define KERNEL_H

#include <ykernel.h>

// Process states
#define PROCESS_READY     0
#define PROCESS_RUNNING   1
#define PROCESS_BLOCKED   2
#define PROCESS_ZOMBIE    3

// Error codes
#define ERROR -1
#define SUCCESS 0

// Process Control Block
typedef struct PCB {
    int pid;
    UserContext user_context;
    KernelContext kernel_context;
    pte_t* region1_ptbr;
    int* kernel_stack_frames;
    int kernel_stack_size;
    void* user_heap_break;
    struct PCB* parent;
    struct PCB* children;
    struct PCB* siblings;
    struct PCB* next;
    int state;
    int exit_status;
    int is_zombie;
} PCB;

// Kernel global state
typedef struct KernelState {
    PCB* current_process;
    PCB* ready_queue;
    PCB* delay_queue;
    PCB* idle_process;
    PCB* init_process;
    PCB* zombie_list;
    
    // Memory management
    unsigned long* free_frame_bitmap;
    int total_frames;
    int used_frames;
    
    // Page tables
    pte_t* region0_ptbr;
    int region0_ptlr;
    
    // Process management
    int next_pid;
    
    // Terminal management
    struct terminal terminals[NUM_TERMINALS];
} KernelState;

// Global kernel state
extern KernelState kernel_state;
extern int vm_enabled;
extern void* kernel_brk;

// Function declarations
void KernelStart(char* cmd_args[], unsigned int pmem_size, UserContext* uctxt);
int SetKernelBrk(void* addr);

// Process management
PCB* CreatePCB();
void InitializePCB(PCB* pcb);
void FreePCB(PCB* pcb);
PCB* CreateIdleProcess(UserContext* uctxt);
PCB* CreateInitProcess(char* program, char** args);
void AddToReadyQueue(PCB* pcb);
PCB* RemoveFromReadyQueue();
void TerminateProcess(PCB* pcb, int exit_status);
PCB* FindPCB(int pid);
void AddChildProcess(PCB* parent, PCB* child);
void RemoveChildProcess(PCB* parent, PCB* child);
void OrphanChildren(PCB* parent);
PCB* FindZombieChild(PCB* parent);

// Scheduling
void Schedule();
void Dispatch(PCB* next_process);
void YieldCPU();

// Context management
void SaveUserContext(UserContext* dest, UserContext* src);
void RestoreUserContext(UserContext* dest, UserContext* src);
void CopyKernelStack(PCB* src, PCB* dest);

// Context switching
KernelContext* KCCopy(KernelContext* kc_in, void* new_pcb_p, void* not_used);
KernelContext* KCSwitch(KernelContext* kc_in, void* curr_pcb_p, void* next_pcb_p);

// Helper functions
void InitializeInterruptVectorTable();
void SetupProcessMemoryMapping(PCB* pcb);
void DoIdle(void);

#endif
