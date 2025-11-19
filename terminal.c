#include "kernel.h"
#include "terminal.h"

// Global terminal states
static TtyState terminal_states[NUM_TERMINALS];

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
