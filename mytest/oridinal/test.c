#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>

#define ARRAY1_SIZE 16
int array1[16];
uint8_t array2[256 * 512];
uint8_t temp = 0;

void victim_function(size_t x) {
    if (x < ARRAY1_SIZE) {
        temp &= array2[array1[x] * 512];
    }
}

int main(int argc, char **argv) {
    if (argc != 2) {
        printf("USAGE: %s <index>\n", argv[0]);
        exit(1);
    }

    int index = atoi(argv[1]);
    victim_function(index);
    return 0;
}
