#ifndef TRIEFORT_INTERNAL_TYPES_H
#define TRIEFORT_INTERNAL_TYPES_H

#include "triefort.h"

#include "sds.h"

#include <fts.h>
#include <stdbool.h>

struct triefort {
  /* Path from the root to the triefort. */
  sds path;

  /* Hash function configuration. */
  const struct triefort_hash_cfg * hcfg;

  /* Triefort configuration. */
  struct triefort_cfg cfg;
};

struct triefort_iter {
  const struct triefort * fort;
  void * hash;
  bool done;

  FTS * fts;
  FTSENT * ent;
};

#endif /* TRIEFORT_INTERNAL_TYPES_H */
