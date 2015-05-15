#include "greatest.h"
#include "triefort.h"

#include <assert.h>
#include <errno.h>
#include <fts.h>
#include <stdbool.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define TEST_TRIEFORT_PATH "__triefort_test_dir"

static int recursive_remove(const char * const path);
static bool dir_exists(const char * const path);
static bool file_exists(const char * const path);

static int test_hasher(
    void * hash, const size_t hashlen,
    const void * buffer, const size_t bufferlen);

static int create_test_triefort(void);
static void destroy_triefort(void);

const struct triefort_cfg testcfg = {
    .depth = 4,
    .hash_len = 20,
    .hash_name = "testhash",
};

const struct triefort_hash_cfg hashcfg = {
  .fn_name = "testhash",
  .hasher = test_hasher,
};

TEST triefort_init__creates_triefort_at_path(void) {
  CHECK_CALL(create_test_triefort());
  ASSERT(dir_exists(TEST_TRIEFORT_PATH));
  PASS();
}

TEST triefort_init__creates_triefort_config_under_path(void) {
  CHECK_CALL(create_test_triefort());
  ASSERT(file_exists(TEST_TRIEFORT_PATH "/config"));
  PASS();
}

TEST triefort_open__is_okay_when_triefort_exists(void) {
  CHECK_CALL(create_test_triefort());

  struct triefort * fort = NULL;
  enum triefort_status s = triefort_open(&fort, &hashcfg, TEST_TRIEFORT_PATH);
  ASSERT_EQ_FMT(triefort_ok, s, "%d");

  PASS();
}

SUITE(suite_triefort) {
  RUN_TEST(triefort_init__creates_triefort_at_path);
  RUN_TEST(triefort_init__creates_triefort_config_under_path);
  RUN_TEST(triefort_open__is_okay_when_triefort_exists);
}

GREATEST_MAIN_DEFS();

int main(int argc, char * argv[]) {
  GREATEST_MAIN_BEGIN();
  RUN_SUITE(suite_triefort);
  GREATEST_MAIN_END();
}

static int recursive_remove(const char * const path) {
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

static bool dir_exists(const char * const path) {
  struct stat s;

  if (0 == stat(path, &s)) {
    if (S_ISDIR(s.st_mode)) {
      return true;
    }
  }

  return false;
}

static bool file_exists(const char * const path) {
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
static int test_hasher(void * hash, const size_t hashlen,
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

static int create_test_triefort(void) {
  destroy_triefort();

  enum triefort_status s = triefort_init(TEST_TRIEFORT_PATH, &testcfg);
  ASSERT_EQ_FMT(triefort_ok, s, "%d");

  PASS();
}

static void destroy_triefort(void) {
  recursive_remove(TEST_TRIEFORT_PATH);
}

