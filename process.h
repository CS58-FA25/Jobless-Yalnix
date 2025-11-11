#ifndef PROCESS_H
#define PROCESS_H

#include <ykernel.h>

// Process management
PCB* CreatePCB();
void InitializePCB(PCB* pcb);
void FreePCB(PCB* pcb);
PCB* FindPCB(int pid);
void AddChildProcess(PCB* parent, PCB* child);
void RemoveChildProcess(PCB* parent, PCB* child);
void OrphanChildren(PCB* parent);
PCB* FindZombieChild(PCB* parent);

// Creating a process
PCB* CreateIdleProcess(UserContext* uctxt);
PCB* CreateInitProcess(char* program, char** args);

// Scheduling
void Schedule();
void Dispatch(PCB* next_process);

// Queue management
void AddToReadyQueue(PCB* pcb);
void AddToDelayQueue(PCB* pcb);
PCB* RemoveFromReadyQueue();
void TerminateProcess(PCB* pcb, int exit_status);

// Context management
void SaveUserContext(UserContext* dest, UserContext* src);
void RestoreUserContext(UserContext* dest, UserContext* src);
void CopyKernelStack(PCB* src, PCB* dest);
KernelContext* KCCopy(KernelContext* kc_in, void* new_pcb_p, void* not_used);
KernelContext* KCSwitch(KernelContext* kc_in, void* curr_pcb_p, void* next_pcb_p);

#endif
