#include <stdio.h>

#define MAX_CACHE_SIZE 8192 //8KB
#define REPEAT 1024

void f(){
    char buf[MAX_CACHE_SIZE];
    register int s = 0;

    for (register int j = 0; j < REPEAT; j++){
        for(register int i = 0; i < MAX_CACHE_SIZE; i++){
            s += buf[i]; //This should perform a single load
        }
    }

    printf("Result: %d\n", s);

}

int main(int argc, char **argv){
    f();
    return 0;
}