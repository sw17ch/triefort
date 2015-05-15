#include "greatest.h"
#include "triefort.h"

#include <fts.h>
#include <stdio.h>
#include <errno.h>

static const char * const test_triefort_path = "__triefort_test_dir";

int recursive_remove(const char * const path);

SUITE(triefort_suite) {
}

GREATEST_MAIN_DEFS();

int main(int argc, char * argv[]) {
  GREATEST_MAIN_BEGIN();
  RUN_SUITE(triefort_suite);
  recursive_remove(test_triefort_path);
  GREATEST_MAIN_END();
}

int recursive_remove(const char * const path) {
  int e = 0;
  const char * const ptrs[] = { path, 0 };

  FTS * fts = fts_open((char * const *)ptrs, FTS_NOCHDIR | FTS_PHYSICAL | FTS_XDEV, NULL);
  if (0 != errno) {
    e = errno;
    fprintf(stderr, "ERROR: %s\n", strerror(e));
  } else {
    FTSENT * ent;
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
  }
  fts_close(fts);
  return e;
}
