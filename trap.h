#ifndef TRAPS_H
    #define TRAPS_H

    #include <ykernel.h>

    // Syscall numbers (low byte of YALNIX_* codes)
    #define SYS_FORK        (YALNIX_FORK & YALNIX_MASK)
    #define SYS_EXEC        (YALNIX_EXEC & YALNIX_MASK)
    #define SYS_EXIT        (YALNIX_EXIT & YALNIX_MASK)
    #define SYS_WAIT        (YALNIX_WAIT & YALNIX_MASK)
    #define SYS_GETPID      (YALNIX_GETPID & YALNIX_MASK)
    #define SYS_BRK         (YALNIX_BRK & YALNIX_MASK)
    #define SYS_DELAY       (YALNIX_DELAY & YALNIX_MASK)
    #define SYS_TTY_READ    (YALNIX_TTY_READ & YALNIX_MASK)
    #define SYS_TTY_WRITE   (YALNIX_TTY_WRITE & YALNIX_MASK)

    // Global interrupt vector table
    extern void (*interrupt_vector_table[TRAP_VECTOR_SIZE])(UserContext*);

    // Initialization
    void InitializeInterruptVectorTable(void);

    // Trap handlers
    void HandleTrapKernel(UserContext* uctxt);
    void HandleTrapClock(UserContext* uctxt);
    void HandleTrapMemory(UserContext* uctxt);
    void HandleTrapIllegal(UserContext* uctxt);
    void HandleTrapMath(UserContext* uctxt);
    void HandleTrapTtyTransmit(UserContext* uctxt);
    void HandleTrapTtyReceive(UserContext* uctxt);
    void DefaultTrapHandler(UserContext* uctxt);

    // Syscall handlers
    void SyscallFork(UserContext* uctxt);
    void SyscallExec(UserContext* uctxt);
    void SyscallExit(UserContext* uctxt);
    void SyscallWait(UserContext* uctxt);
    void SyscallGetPid(UserContext* uctxt);
    void SyscallBrk(UserContext* uctxt);
    void SyscallDelay(UserContext* uctxt);
    void SyscallTtyRead(UserContext* uctxt);
    void SyscallTtyWrite(UserContext* uctxt);

    // Helper functions
    int ValidateUserPointer(void* ptr, int len, int access_type);
    int ValidateUserString(char* str);
    int IsUserPageMapped(void* vaddr);
    int HasUserPagePermissions(void* vaddr, int access_type);

    #endif

