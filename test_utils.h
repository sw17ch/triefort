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

int recursive_remove(const char * const path);
bool dir_exists(const char * const path);
bool file_exists(const char * const path);

int test_hasher(
    void * hash, const size_t hashlen,
    const void * buffer, const size_t bufferlen);

int create_test_triefort(void);
void destroy_triefort(void);
int open_test_triefort(struct triefort ** fort);

bool buffer_all_null(void * buffer, size_t len);

extern const struct triefort_cfg testcfg;
extern const struct triefort_hash_cfg hashcfg;

#endif /* TEST_UTILS_H */
