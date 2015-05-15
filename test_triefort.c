#include "greatest.h"
#include "triefort.h"
#include "triefort_internal_types.h"

#include <errno.h>
#include <fts.h>
#include <stdbool.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define TEST_TRIEFORT_PATH "__triefort_test_dir"
#define TEST_TRIE_WIDTH 2
#define TEST_TRIE_DEPTH 4
#define TEST_HASH_LEN 20
#define TEST_HASH_NAME "testhash"

static int recursive_remove(const char * const path);
static bool dir_exists(const char * const path);
static bool file_exists(const char * const path);

static int test_hasher(
    void * hash, const size_t hashlen,
    const void * buffer, const size_t bufferlen);

static int create_test_triefort(void);
static void destroy_triefort(void);

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

TEST triefort_init__validates_the_config(void) {
  struct triefort_cfg badcfg = {
      .depth = 0,
      .width = TEST_TRIE_WIDTH,
      .hash_len = TEST_HASH_LEN,
      .hash_name = TEST_HASH_NAME,
  };

  ASSERT_EQ_FMT(
      triefort_err_invalid_config,
      triefort_init(TEST_TRIEFORT_PATH, &badcfg),
      "%d");

  badcfg.depth = 1;
  badcfg.width = 0;

  ASSERT_EQ_FMT(
      triefort_err_invalid_config,
      triefort_init(TEST_TRIEFORT_PATH, &badcfg),
      "%d");

  badcfg.depth = 2;
  badcfg.width = 1;
  badcfg.hash_len = 1;

  ASSERT_EQ_FMT(
      triefort_err_invalid_config,
      triefort_init(TEST_TRIEFORT_PATH, &badcfg),
      "%d");

  PASS();
}

TEST triefort_open__is_okay_when_triefort_exists(void) {
  CHECK_CALL(create_test_triefort());

  struct triefort * fort = NULL;
  enum triefort_status s = triefort_open(&fort, &hashcfg, TEST_TRIEFORT_PATH);
  ASSERT_EQ_FMT(triefort_ok, s, "%d");

  PASS();
}

TEST triefort_open__populates_internal_config(void) {
  CHECK_CALL(create_test_triefort());

  struct triefort * fort = NULL;
  enum triefort_status s = triefort_open(&fort, &hashcfg, TEST_TRIEFORT_PATH);
  ASSERT_EQ_FMT(triefort_ok, s, "%d");

  ASSERT_EQ_FMT(fort->cfg.depth, TEST_TRIE_DEPTH, "%u");
  ASSERT_EQ_FMT(fort->cfg.hash_len, TEST_HASH_LEN, "%u");
  ASSERT_STR_EQ(TEST_HASH_NAME, fort->cfg.hash_name);

  PASS();
}

TEST triefort_open__checks_hash_names(void) {
  const struct triefort_hash_cfg hashcfg = {
    .fn_name = "BAD_" TEST_HASH_NAME,
    .hasher = test_hasher,
  };

  CHECK_CALL(create_test_triefort());

  struct triefort * fort = NULL;
  enum triefort_status s = triefort_open(&fort, &hashcfg, TEST_TRIEFORT_PATH);
  ASSERT_EQ_FMT(triefort_err_hash_name_mismatch, s, "%d");
  ASSERT(NULL == fort);

  PASS();
}

TEST triefort_close__runs_without_segfaulting(void) {
  CHECK_CALL(create_test_triefort());

  struct triefort * fort = NULL;
  enum triefort_status s = triefort_open(&fort, &hashcfg, TEST_TRIEFORT_PATH);
  ASSERT_EQ_FMT(triefort_ok, s, "%d");

  triefort_close(fort);

  PASS();
}

TEST triefort_destroy__removes_the_triefort(void) {
  CHECK_CALL(create_test_triefort());
  enum triefort_status s = triefort_destroy(TEST_TRIEFORT_PATH);
  ASSERT_EQ_FMT(triefort_ok, s, "%d");
  ASSERT_FALSE(dir_exists(TEST_TRIEFORT_PATH));

  PASS();
}

TEST triefort_destroy__tries_to_make_sure_the_dir_is_a_triefort(void) {
  if (0 != mkdir("__non_triefort_path", 0755)) {
    FAIL();
  }

  enum triefort_status s = triefort_destroy("__non_triefort_path");
  ASSERT_EQ_FMT(triefort_err_not_a_triefort, s, "%d");
  ASSERT(dir_exists("__non_triefort_path"));
  recursive_remove("__non_triefort_path");

  PASS();
}

TEST triefort_config_get__retrieves_the_triefort_config(void) {
  CHECK_CALL(create_test_triefort());

  enum triefort_status s;
  struct triefort_cfg cfg = { 0, 0, 0, { 0 } };
  struct triefort * fort = NULL;

  s = triefort_open(&fort, &hashcfg, TEST_TRIEFORT_PATH);
  ASSERT_EQ_FMT(triefort_ok, s, "%d");

  s = triefort_config_get(fort, &cfg);
  ASSERT_EQ_FMT(triefort_ok, s, "%d");

  ASSERT_EQ_FMT(TEST_TRIE_DEPTH, cfg.depth, "%d");
  ASSERT_EQ_FMT(TEST_TRIE_WIDTH, cfg.width, "%d");
  ASSERT_EQ_FMT(TEST_HASH_LEN, cfg.hash_len, "%d");
  ASSERT_STR_EQ(TEST_HASH_NAME, cfg.hash_name);

  PASS();
}

SUITE(suite_triefort) {
  RUN_TEST(triefort_init__creates_triefort_at_path);
  RUN_TEST(triefort_init__creates_triefort_config_under_path);
  RUN_TEST(triefort_init__validates_the_config);
  RUN_TEST(triefort_open__is_okay_when_triefort_exists);
  RUN_TEST(triefort_open__populates_internal_config);
  RUN_TEST(triefort_open__checks_hash_names);
  RUN_TEST(triefort_close__runs_without_segfaulting);
  RUN_TEST(triefort_destroy__removes_the_triefort);
  RUN_TEST(triefort_destroy__tries_to_make_sure_the_dir_is_a_triefort);
  RUN_TEST(triefort_config_get__retrieves_the_triefort_config);
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

