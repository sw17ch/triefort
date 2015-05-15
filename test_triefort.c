#include "greatest.h"
#include "triefort.h"

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

const struct triefort_cfg testcfg = {
    .depth = 4,
    .hash_len = 20,
    .hash_name = "testhash",
};

TEST triefort_init__creates_triefort_at_path(void) {
  enum triefort_status s;

  s = triefort_init(TEST_TRIEFORT_PATH, &testcfg);
  ASSERT_EQ_FMT(triefort_ok, s, "%d");

  ASSERT(dir_exists(TEST_TRIEFORT_PATH));
  PASS();
}

TEST triefort_init__creates_triefort_config_under_path(void) {
  enum triefort_status s;

  s = triefort_init(TEST_TRIEFORT_PATH, &testcfg);
  ASSERT_EQ_FMT(triefort_ok, s, "%d");

  ASSERT(file_exists(TEST_TRIEFORT_PATH "/config"));
  PASS();
}

SUITE(suite_triefort) {
  recursive_remove(TEST_TRIEFORT_PATH);
  RUN_TEST(triefort_init__creates_triefort_config_under_path);
  recursive_remove(TEST_TRIEFORT_PATH);
  RUN_TEST(triefort_init__creates_triefort_at_path);
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
