#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <pthread.h>
#include <assert.h>
#include <ctype.h>
#include "hash_functions.h"

#define KEEP 16  // Only use the first 16 bytes of each hash
#define THREADS 10  // Maximum number of worker threads

// This structure stores one hashed password from the hashed file.
// It stores the binary version (first KEEP bytes), the matching common password (if found),
// the algorithm name used, and the index (order) of the common password that matched.
struct cracked {
    unsigned char bin[KEEP];
    char *pass;
    char *alg;
    int index;  // lower means earlier in file
};

// Function pointer for hash functions.
typedef unsigned char * (*hash_func)(unsigned char *, unsigned int);

// List of hash functions and names.
int num_algs = 4;
hash_func funcs[4] = { calculate_md5, calculate_sha1, calculate_sha256, calculate_sha512 };
char *alg_names[4] = { "MD5", "SHA1", "SHA256", "SHA512" };

// Global arrays and counts.
struct cracked *cracked_arr = NULL;  // from hashed file
int num_cracked = 0;

char **all_pass = NULL;   // common passwords from file
int num_pass = 0;

// Global index and mutex for dynamic distribution.
int curr = 0;
pthread_mutex_t curr_mutex = PTHREAD_MUTEX_INITIALIZER;

// One mutex per cracked entry.
pthread_mutex_t *cracked_mutexes = NULL;

// This is a helper function that converts two hex chars to a byte.
unsigned char hex2byte(char a, char b) {
    unsigned char A = (a >= '0' && a <= '9') ? a - '0' : (toupper(a) - 'A' + 10);
    unsigned char B = (b >= '0' && b <= '9') ? b - '0' : (toupper(b) - 'A' + 10);
    return (A << 4) | B;
}

// Worker thread function. Each thread grabs the next available common password
// and computes its hash using all 4 algorithms, then compares the binary hash to each stored hash.
void *worker(void *arg) {
    (void)arg;  // Unused
    while (1) {
        int i;
        // Get the next index
        pthread_mutex_lock(&curr_mutex);
        if (curr >= num_pass) {
            pthread_mutex_unlock(&curr_mutex);
            break;
        }
        i = curr++;
        pthread_mutex_unlock(&curr_mutex);

        char *p = all_pass[i];
        unsigned int len = (unsigned int) strlen(p);
        for (int a = 0; a < num_algs; a++) {
            unsigned char *d = funcs[a]((unsigned char *)p, len);
            // Compare this binary digest (first KEEP bytes) to each hash.
            for (int j = 0; j < num_cracked; j++) {
                if (memcmp(d, cracked_arr[j].bin, KEEP) == 0) {
                    pthread_mutex_lock(&cracked_mutexes[j]);
                    // If no match yet or if this one came earlier.
                    if (cracked_arr[j].pass == NULL || i < cracked_arr[j].index) {
                        if (cracked_arr[j].pass)
                            free(cracked_arr[j].pass);
                        cracked_arr[j].pass = strdup(p);
                        cracked_arr[j].alg = alg_names[a];
                        cracked_arr[j].index = i;
                    }
                    pthread_mutex_unlock(&cracked_mutexes[j]);
                }
            }
            free(d);
        }
    }
    return NULL;
}

void crack_hashed_passwords(char *pass_file, char *hash_file, char *out_file) {
    FILE *fp;
    char buf[2*KEEP + 1];

    // Load hashed passwords.
    fp = fopen(hash_file, "r");
    assert(fp);
    num_cracked = 0;
    while (fscanf(fp, "%s", buf) == 1)
        num_cracked++;
    rewind(fp);
    cracked_arr = malloc(num_cracked * sizeof(struct cracked));
    assert(cracked_arr);
    for (int i = 0; i < num_cracked; i++) {
        fscanf(fp, "%s", buf);
        for (int j = 0; j < KEEP; j++) {
            cracked_arr[i].bin[j] = hex2byte(buf[2*j], buf[2*j+1]);
        }
        cracked_arr[i].pass = NULL;
        cracked_arr[i].alg = NULL;
        cracked_arr[i].index = INT_MAX;
    }
    fclose(fp);

    // Create one mutex per hashed entry.
    cracked_mutexes = malloc(num_cracked * sizeof(pthread_mutex_t));
    assert(cracked_mutexes);
    for (int i = 0; i < num_cracked; i++) {
        pthread_mutex_init(&cracked_mutexes[i], NULL);
    }

    // Load common passwords.
    fp = fopen(pass_file, "r");
    assert(fp);
    num_pass = 0;
    char temp[256];
    while (fscanf(fp, "%s", temp) == 1)
        num_pass++;
    rewind(fp);
    all_pass = malloc(num_pass * sizeof(char *));
    assert(all_pass);
    for (int i = 0; i < num_pass; i++) {
        fscanf(fp, "%s", temp);
        all_pass[i] = strdup(temp);
    }
    fclose(fp);

    // Create worker threads (use THREADS or fewer if not enough passwords).
    int nthreads = THREADS;
    if (num_pass < nthreads)
        nthreads = num_pass;
    pthread_t threads[nthreads];
    curr = 0;
    for (int i = 0; i < nthreads; i++) {
        pthread_create(&threads[i], NULL, worker, NULL);
    }
    for (int i = 0; i < nthreads; i++) {
        pthread_join(threads[i], NULL);
    }

    // Write output in the same order as the hash file.
    fp = fopen(out_file, "w");
    assert(fp);
    for (int i = 0; i < num_cracked; i++) {
        if (cracked_arr[i].pass == NULL)
            fprintf(fp, "not found\n");
        else
            fprintf(fp, "%s:%s\n", cracked_arr[i].pass, cracked_arr[i].alg);
    }
    fclose(fp);

    // Cleanup.
    for (int i = 0; i < num_cracked; i++) {
        pthread_mutex_destroy(&cracked_mutexes[i]);
        free(cracked_arr[i].pass);
    }
    free(cracked_mutexes);
    free(cracked_arr);
    for (int i = 0; i < num_pass; i++)
        free(all_pass[i]);
    free(all_pass);
}