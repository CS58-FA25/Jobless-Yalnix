#ifndef KERNEL_H
#define KERNEL_H

#include <ykernel.h>

// Process states
#define PROCESS_READY     0
#define PROCESS_RUNNING   1
#define PROCESS_BLOCKED   2
#define PROCESS_ZOMBIE    3

#define MAX_KERNEL_LOCKS   128
#define MAX_KERNEL_CVARS   128

typedef struct KernelLock KernelLock;
typedef struct KernelCvar KernelCvar;


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
    int waiting_for_child;
    int delay_remaining;
    int kernel_context_valid;
    int kernel_stack_copied;
    struct PCB* kernel_clone_source;
    int waiting_on_lock_id;
} PCB;

struct KernelLock {
    int id;
    int in_use;
    int owner_pid;
    PCB* wait_head;
    PCB* wait_tail;
};

struct KernelCvar {
    int id;
    int in_use;
    PCB* wait_head;
    PCB* wait_tail;
};

// Pending write issued by a process
typedef struct TtyWriteRequest {
    PCB* owner;
    char* buffer;        // Region 0 copy of user data
    int length;          // Total bytes to write
    int sent;            // Bytes already transmitted
    struct TtyWriteRequest* next;
} TtyWriteRequest;

// Buffered input line waiting for readers
typedef struct TtyLine {
    char data[TERMINAL_MAX_LINE];
    int length;
    int consumed;
    struct TtyLine* next;
} TtyLine;

// TTY state structure
typedef struct TtyState {
    int tty_id;
    int transmit_busy;
    int active_chunk;                // Bytes in-flight for current request
    TtyWriteRequest* write_head;     // FIFO of pending writes
    TtyWriteRequest* write_tail;
    TtyLine* input_head;             // FIFO of received lines
    TtyLine* input_tail;
    PCB* read_wait_head;             // FIFO of blocked readers
    PCB* read_wait_tail;
} TtyState;

// Kernel global state
typedef struct KernelState {
    PCB* current_process;
    PCB* ready_queue;
    PCB* ready_queue_tail;
    PCB* delay_queue;
    PCB* idle_process;
    PCB* init_process;
    PCB* zombie_list;
    
    // Memory management
    unsigned char* free_frame_bitmap;
    int total_frames;
    int used_frames;
    
    // Page tables
    pte_t* region0_ptbr;
    int region0_ptlr;

    // Kernel heap management
    void* kernel_brk;              // Current kernel break
    void* original_kernel_brk;     // Break at VM enable time
    int vm_enabled;                // Virtual memory enabled flag
    
    // Terminal management
    TtyState* terminals[NUM_TERMINALS];

    // Synchronization primitives
    KernelLock locks[MAX_KERNEL_LOCKS];
    KernelCvar cvars[MAX_KERNEL_CVARS];
} KernelState;

// Global kernel state
extern KernelState kernel_state;

// Build-provided functions from yalnix.h
/*
extern int _first_kernel_text_page;
extern int _first_kernel_data_page;
extern int _orig_kernel_brk_page;
extern unsigned long GET_ORIG_KERNEL_BRK_PAGE(void);
extern int GET_FIRST_KERNEL_TEXT_PAGE(void);
extern int GET_FIRST_KERNEL_DATA_PAGE(void);
*/

extern int _orig_kernel_brk_page;
#define GET_ORIG_KERNEL_BRK_PAGE() (_orig_kernel_brk_page)
extern int _first_kernel_text_page;  
#define GET_FIRST_KERNEL_TEXT_PAGE() (_first_kernel_text_page)
extern int _first_kernel_data_page;
#define GET_FIRST_KERNEL_DATA_PAGE() (_first_kernel_data_page)


// Function declarations
void KernelStart(char* cmd_args[], unsigned int pmem_size, UserContext* uctxt);
int SetKernelBrk(void* addr);

// Process management
PCB* CreatePCB();
void InitializePCB(PCB* pcb);
void FreePCB(PCB* pcb);
PCB* CreateIdleProcess(char* program, char** args);
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
KernelContext* KCSwitch(KernelContext* kc_in, void* curr_pcb_p, void* next_pcb_p);

// Terminal management functions
void InitializeTerminals(void);
TtyState* GetTerminalState(int tty_id);
int ValidateTerminalId(int tty_id);

// Helper functions
void InitializeInterruptVectorTable();
void SetupProcessMemoryMapping(PCB* pcb);

// Load program
int LoadProgram(char *program, char **args, PCB *init_pcb);

#endif
