#include <yuser.h>

// Debug-friendly idle loop: emits periodic traces but never exits so the kernel
// always has a fallback runnable process.

#define IDLE_TRACE_INTERVAL 100
#define IDLE_MAX_ITERATIONS 500

int main(int argc, char** argv) {
    int iterations = 0;
    TracePrintf(0, "Idle process started (PID %d)\n", GetPid());

    while (1) {
        Pause();  // Wait for the next interrupt before looping again
        iterations++;

        if (iterations % IDLE_TRACE_INTERVAL == 0) {
            TracePrintf(0, "Idle: iter %d\n", iterations);
        }

        if (iterations >= IDLE_MAX_ITERATIONS) {
            TracePrintf(0, "Idle: reached %d iterations, resetting counter\n",
                        iterations);
            iterations = 0;
        }
    }

    return 0;
}
