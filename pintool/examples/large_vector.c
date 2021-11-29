#include <stdio.h>
#include <stdlib.h>

#define MAX_CACHE_SIZE 8192 //8KB

void f(){
    /* Too big to store on the stack, but thats alright */
    register char *buf = (char *)malloc(sizeof(char)*MAX_CACHE_SIZE*1024*10);
    register int s = 0;

    for(register int i = 0; i < MAX_CACHE_SIZE; i++){
        s += *buf; //This should perform a single load
        buf++; /* This is so buf is not loaded to the cache, and instead is represented with an incrementing register */
    }

    printf("Result: %d\n", s); /* This should yield 0 now, as heap is initialized to 0 on ubuntu */

}

int main(int argc, char **argv){
    f();
    return 0;
}