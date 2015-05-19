#include "triefort.h"
#include "test_utils.h"

#include <stdbool.h>

const struct triefort_cfg testcfg = {
    .depth = TEST_TRIE_DEPTH,
    .width = TEST_TRIE_WIDTH,
    .hash_len = TEST_HASH_LEN,
    .hash_name = TEST_HASH_NAME,
};

const struct triefort_hash_cfg hashcfg = {
  .fn_name = TEST_HASH_NAME,
  .hasher = test_hasher,
};

int recursive_remove(const char * const path) {
  int e = 0;

  if (dir_exists(path)) {
    FTSENT * ent;
    const char * const ptrs[] = { path, 0 };
    const int fts_options = FTS_NOCHDIR | FTS_PHYSICAL | FTS_XDEV;
    FTS * fts = fts_open((char * const *)ptrs, fts_options, NULL);

    while((ent = fts_read(fts)) && 0 == e) {
      switch(ent->fts_info) {
      case FTS_NS: case FTS_DNR: case FTS_ERR:
        fprintf(stderr, "%s: fts_read error: %s\n",
            ent->fts_accpath, strerror(ent->fts_errno));
        e = ent->fts_errno;
        break;
      case FTS_D: case FTS_DC: case FTS_DOT: case FTS_NSOK:
        break;
      case FTS_DP: case FTS_F: case FTS_SL: case FTS_SLNONE: case FTS_DEFAULT:
        if (0 != remove(ent->fts_accpath)) {
          fprintf(stderr, "Unable to remove %s. %s\n",
              ent->fts_accpath,
              strerror(ent->fts_errno));
          e = ent->fts_errno;
        }
        break;
      }
    }
    fts_close(fts);
  }

  return e;
}

bool dir_exists(const char * const path) {
  struct stat s;

  if (0 == stat(path, &s)) {
    if (S_ISDIR(s.st_mode)) {
      return true;
    }
  }

  return false;
}

bool file_exists(const char * const path) {
  struct stat s;

  if (0 == stat(path, &s)) {
    if (S_ISREG(s.st_mode)) {
      return true;
    }
  }

  return false;
}

/* This is just a trivial hashing function for test purposes. In real
 * circumstances, you'd use something else. */
int test_hasher(void * hash, const size_t hashlen,
                       const void * buffer, const size_t bufferlen) {
  uint8_t * hashb = hash;
  const uint8_t * bufferb = buffer;

  memset(hash, 0xFF, hashlen);

  uint8_t sum = 0;

  for (size_t i = 0; i < bufferlen; i++) {
    sum += bufferb[i];
    hashb[i % hashlen] += sum;
  }

  for (size_t i = 0; i < hashlen; i++) {
    fprintf(stderr, "%02x", hashb[i]);
  }
  fprintf(stderr,"\n");

  return 0;
}

int create_test_triefort(void) {
  destroy_triefort();

  enum triefort_status s = triefort_init(TEST_TRIEFORT_PATH, &testcfg);
  ASSERT_EQ_FMT(triefort_ok, s, "%d");

  PASS();
}

void destroy_triefort(void) {
  recursive_remove(TEST_TRIEFORT_PATH);
}

bool buffer_all_null(void * buffer, size_t len) {
  uint8_t * bufferb = buffer;

  for (size_t i = 0; i < len; i++) {
    if (0 != bufferb[i]) {
      return false;
    }
  }

  return true;
}
