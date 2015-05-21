#ifndef TEST_UTILS_H
#define TEST_UTILS_H

#include "greatest.h"

#include <fts.h>
#include <stdbool.h>
#include <sys/stat.h>
#include <sys/types.h>

#define TEST_TRIEFORT_PATH "__triefort_test_dir"
#define TEST_TRIE_WIDTH 2
#define TEST_TRIE_DEPTH 2
#define TEST_HASH_LEN 20
#define TEST_HASH_NAME "testhash"
#define TEST_MAX_KEY_LEN 16

int recursive_remove(const char * const path);
bool dir_exists(const char * const path);
bool file_exists(const char * const path);

int test_hasher(
    void * hash, const size_t hashlen,
    const void * buffer, const size_t bufferlen);

int create_test_triefort(void);
void destroy_triefort(void);
int open_test_triefort(struct triefort ** fort);
int open_test_triefort_with_data(
    struct triefort ** fort,
    char * key,
    char * buffer,
    void * hash);

bool buffer_all_null(void * buffer, size_t len);

void print_hash(void * hash, size_t hashlen);

extern const struct triefort_cfg testcfg;
extern const struct triefort_hash_cfg hashcfg;

#endif /* TEST_UTILS_H */
