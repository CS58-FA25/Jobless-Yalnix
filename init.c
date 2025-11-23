#include <yuser.h>

int main(int argc, char** argv) {
    TracePrintf(0, "Init process started! PID: %d\n", GetPid());
    
    int counter = 0;
    while (1) {
        TracePrintf(0, "Init: counter = %d\n", counter++);
        Delay(2);  
        if(counter >= 10){
            TracePrintf(0, "Init: reached 10 iterations, exiting loop.\n");
            break;  // Prevent infinite loop during testing
        }
    }
    
    return 0;
}
