#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <pthread.h>
#include <assert.h>
#include <ctype.h>

#include "hash_functions.h"

#define KEEP 16            // Use only the first 16 bytes of each hash
#define THREAD_COUNT 10    // Number of worker threads

// Structure for a hashed password from the file
struct cracked {
    unsigned char bin[KEEP]; // Binary hash (first 16 bytes)
    char *pass;              // Matching common password (if found)
    char *alg;               // Which algorithm gave the match
    int index;               // Order index of the common password that matched
};

// Function pointer type for the hash functions
typedef unsigned char *(*hash_func)(unsigned char *, unsigned int);

// List of hash functions and their names
int num_algs = 4;
hash_func funcs[4] = { calculate_md5, calculate_sha1, calculate_sha256, calculate_sha512 };
char *alg_names[4] = { "MD5", "SHA1", "SHA256", "SHA512" };

// Array for hashed passwords of type cracked
struct cracked *cracked_arr = NULL;
// Number of elements in cracke_arr
int num_hashed = 0;
// Array of common passwords
char **common_pass = NULL;
// Number of common passwords in common_pass
int num_common = 0;

// This is counter used to determine what password to grab next
int work_index = 0;
// This is a lock for work_index to ensure that the threads dont
// create a race condition while attempting to increment it
pthread_mutex_t work_mutex = PTHREAD_MUTEX_INITIALIZER;

// This is an array of mutexes. There is one 
// mutex per cracked entry to update matches safely
pthread_mutex_t *cracked_mutexes = NULL;

// This function converts 2 hex characters into one byte
// We are doing this because working with binary data is faster
// than working with hex data
unsigned char hex2byte(char first, char second) {
	unsigned char firstValue, secondValue;
    // Convert the first hex character to its numerical value.
    if (first >= '0' && first <= '9') {
        firstValue = first - '0';
    } else {
        firstValue = toupper(first) - 'A' + 10;
    }
    // Convert the second hex character to its numerical value.
    if (second >= '0' && second <= '9') {
        secondValue = second - '0';
    } else {
        secondValue = toupper(second) - 'A' + 10;
    }
	// Move the first hex character to the upper 4 bits
    unsigned char firstShifted = firstValue << 4;  
	// Combine with the second hex character
	unsigned char combinedByte = firstShifted | secondValue;  
	return combinedByte;
}

// Worker thread function: Each thread grabs the next common password,
// computes its hash with all algorithms, and compares with all preloaded hashes.
void *worker() {
    while (1) {
        int idx;
        pthread_mutex_lock(&work_mutex);
		// If all passwords are done, break out of the while loop
        if (work_index >= num_common) {
			// Release the worker lock
            pthread_mutex_unlock(&work_mutex);
            break;
        }
		// Get the current work index and increment it
        idx = work_index;
        work_index++;
		// Unlock and leave critical section
        pthread_mutex_unlock(&work_mutex);
        
		// Get the common password at the work index
        char *pwd = common_pass[idx];
		// Get the length of this password
        unsigned int len = (unsigned int) strlen(pwd);
        
        // For each algorithm, compute the hash of the current password
        for (int i = 0; i < num_algs; i++) {
			// Call the hash function
            unsigned char *digest = funcs[i]((unsigned char *)pwd, len);
            // Compare the first KEEP bytes directly using memcmp
            for (int j = 0; j < num_hashed; j++) {
                if (memcmp(digest, cracked_arr[j].bin, KEEP) == 0) {
                    pthread_mutex_lock(&cracked_mutexes[j]);
                    // If no match found yet, or if this password came earlier, update
                    if (cracked_arr[j].pass == NULL || idx < cracked_arr[j].index) {
						// If there is already a match stored, free it
                        if (cracked_arr[j].pass)
                            free(cracked_arr[j].pass);
						// Save this password, algorithm, and index to the cracked_arr
                        cracked_arr[j].pass = strdup(pwd);
                        cracked_arr[j].alg = alg_names[i];
                        cracked_arr[j].index = idx;
                    }
                    pthread_mutex_unlock(&cracked_mutexes[j]);
                }
            }
            free(digest);
        }
    }
    return NULL;
}

void crack_hashed_passwords(char *pass_list, char *hashed_list, char *output) {
    FILE *fp;
    char hex_hash[2*KEEP+1];
	int count;
    
    // Load the hashed passwords
    fp = fopen(hashed_list, "r");
    assert(fp != NULL);
    count = 0;
    while (fscanf(fp, "%s", hex_hash) == 1)
        count++;
    rewind(fp);
    
	// Allocate space for cracked_arr
    cracked_arr = malloc(count * sizeof(struct cracked));
    assert(cracked_arr != NULL);
	// Itereate through the file of hashed passwords
    for (int i = 0; i < count; i++) {
        fscanf(fp, "%s", hex_hash);
        // Convert hex string to binary array
        for (int j = 0; j < KEEP; j++) {
            cracked_arr[i].bin[j] = hex2byte(hex_hash[2*j], hex_hash[2*j+1]);
        }
		// Initialize its struct values
        cracked_arr[i].pass = NULL;
        cracked_arr[i].alg = NULL;
        cracked_arr[i].index = INT_MAX;
    }
    fclose(fp);
	// Store the number of hashed passwords
    num_hashed = count;
    
    // Allocate and initialize one mutex per hashed entry
    cracked_mutexes = malloc(num_hashed * sizeof(pthread_mutex_t));
    assert(cracked_mutexes != NULL);
    for (int i = 0; i < num_hashed; i++) {
        pthread_mutex_init(&cracked_mutexes[i], NULL);
    }
    
    // Load the common passwords
    fp = fopen(pass_list, "r");
    assert(fp != NULL);
    count = 0;
    char temp_pass[256];
    while (fscanf(fp, "%s", temp_pass) == 1)
		count++;
    rewind(fp);
    
	// Allocate space for the list of common passwords
    common_pass = malloc(count * sizeof(char *));
    assert(common_pass != NULL);
	// Store the common passwords
    for (int i = 0; i < count; i++) {
        fscanf(fp, "%s", temp_pass);
        common_pass[i] = strdup(temp_pass);
    }
    fclose(fp);
	// Store the number of common passwords
    num_common = count;
    
    //  Create worker threads
    int num_threads = THREAD_COUNT;
    pthread_t threads[num_threads];
    work_index = 0;
    
	// Create all of our threads and then join all of our threads
    for (int i = 0; i < num_threads; i++) {
        pthread_create(&threads[i], NULL, worker, NULL);
    }
    for (int i = 0; i < num_threads; i++) {
        pthread_join(threads[i], NULL);
    }
    
    // Write the output in the same order as hashed_list
    fp = fopen(output, "w");
    assert(fp != NULL);
    for (int i = 0; i < num_hashed; i++) {
        if (cracked_arr[i].pass == NULL){
            fprintf(fp, "not found\n");
		}
        else{
            fprintf(fp, "%s:%s\n", cracked_arr[i].pass, cracked_arr[i].alg);
		}
    }
    fclose(fp);
    
    // Free the all of the allocated memory
    for (int i = 0; i < num_hashed; i++) {
        pthread_mutex_destroy(&cracked_mutexes[i]);
        free(cracked_arr[i].pass);
    }
    free(cracked_mutexes);
    free(cracked_arr);
    for (int i = 0; i < num_common; i++) {
        free(common_pass[i]);
    }
    free(common_pass);
}