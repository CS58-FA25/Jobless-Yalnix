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

// Scheduling
void Schedule();
void Dispatch(PCB* next_process);

// Context management
void SaveUserContext(UserContext* dest, UserContext* src);
void RestoreUserContext(UserContext* dest, UserContext* src);
void CopyKernelStack(PCB* src, PCB* dest);

#endif
