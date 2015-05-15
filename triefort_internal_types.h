#ifndef TRIEFORT_INTERNAL_TYPES_H
#define TRIEFORT_INTERNAL_TYPES_H

#include "triefort.h"

struct triefort {
  /* Path from the root to the triefort. */
  const char * path;

  /* Hash function configuration. */
  const struct triefort_hash_cfg * hcfg;

  /* Triefort configuration. */
  struct triefort_cfg cfg;
};

struct triefort_iter;

#endif /* TRIEFORT_INTERNAL_TYPES_H */
