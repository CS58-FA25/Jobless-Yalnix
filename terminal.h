#ifndef TERMINAL_H
#define TERMINAL_H

#include <ykernel.h>

// TTY buffer for storing input lines
typedef struct TtyBuffer {
    char buffer[TERMINAL_MAX_LINE];
    int length;
    int read_pos;
    int write_pos;
    struct TtyBuffer* next;
} TtyBuffer;

// TTY state structure
typedef struct TtyState {
    int transmit_busy;           // Whether TTY is currently transmitting
    PCB* transmit_waiting;       // Process waiting for transmit completion
    PCB* read_waiting;           // Process waiting for input
    TtyBuffer* input_buffers;    // Linked list of input buffers
    char* transmit_buffer;       // Current transmit buffer
    int transmit_length;         // Current transmit length
} TtyState;

// Terminal management functions
void InitializeTerminals(void);
TtyState* GetTerminalState(int tty_id);
int ValidateTerminalId(int tty_id);

#endif
