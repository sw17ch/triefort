#include "triefort.h"
#include "triefort_internal_types.h"

#include <errno.h>
#include <fts.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define S enum triefort_status
#define TF struct triefort
#define CFG struct triefort_cfg
#define HCFG struct triefort_hash_cfg
#define INFO struct triefort_info
#define ITER struct triefort_iter

#define PANIC() do { \
  fprintf(stderr, "PANIC: %s:%d\n", __FILE__, __LINE__); \
  return triefort_err_PANIC; \
} while(0)
#define PANIC_IF(COND) do { if (COND) { PANIC(); } } while(0)
#define CHECK_CALL(CALL) do { \
  S s; if (triefort_ok != (s = (CALL))) { return s; } \
} while(0)

#define NULLCHK(ARG) do { \
  if (NULL == ARG) { return triefort_err_NULL_PTR; } \
} while(0)

#define DIRMODE ( \
   (S_IRUSR | S_IWUSR | S_IXUSR) | \
   (S_IRGRP |           S_IXGRP) | \
   (S_IROTH |           S_IXOTH)   \
  )

static S store_cfg(const CFG * const cfg, const char * const path);
static S load_cfg(CFG * const cfg, const char * const path);
static bool validate_cfg(const CFG * const cfg);
static bool dir_exists(const char * const path);
static bool file_exists(const char * const path);
static int recursive_remove(const char * const path);
static S mk_trie_dirs(const TF * const fort, void * hash, size_t hashlen, char ** path);
static char * mk_hash_str(const void * const hash, const size_t hashlen);
static S write_file(const char * const filename, const void * const data, const size_t datalen);
static char * trie_path(const TF * const fort, const void * const hash);

S triefort_init(const char * const path, const CFG * const cfg) {
  if (0 == validate_cfg(cfg)) {
    return triefort_err_invalid_config;
  }

  if (0 != mkdir(path, DIRMODE)) {
    int e = errno;

    if (EEXIST == e) {
      fprintf(stderr, "PATH ALREADY EXISTS: %s\n", path);
      return triefort_err_path_already_exists;
    } else {
      return triefort_err_path_could_not_be_created;
    }
  }

  const char * oldcwd = getcwd(NULL, 0);
  {
    PANIC_IF(chdir(path) != 0);
    CHECK_CALL(store_cfg(cfg, "config"));
    PANIC_IF(chdir(oldcwd) != 0);
  }
  free((void*)oldcwd);

  return triefort_ok;
}

S triefort_open(TF ** const fort, const HCFG * const hashcfg, const char * const path) {
  NULLCHK(fort);
  NULLCHK(hashcfg);
  NULLCHK(path);

  const char * oldcwd = getcwd(NULL, 0);
  {
    if (0 != chdir(path)) {
      return triefort_err_not_a_triefort;
    }

    *fort = calloc(1, sizeof(**fort));
    TF * f = *fort;

    f->path = getcwd(NULL, 0);
    f->hcfg = hashcfg;
    CHECK_CALL(load_cfg(&f->cfg, "config"));

    PANIC_IF(chdir(oldcwd) != 0);
  }
  free((void *)oldcwd);

  S s = triefort_ok;

  if (!validate_cfg(&(*fort)->cfg)) {
    s = triefort_err_invalid_config;
  }

  if (0 != strcmp(hashcfg->fn_name, (*fort)->cfg.hash_name)) {
    s = triefort_err_hash_name_mismatch;
  }

  if (triefort_ok != s) {
    free(*fort);
    *fort = NULL;
  }

  return s;
}

S triefort_close(TF * fort) {
  NULLCHK(fort);
  NULLCHK(fort->path);

  free((void *)fort->path);
  free(fort);

  return triefort_ok;
}

S triefort_destroy(char * const path) {
  S s = triefort_ok;

  char * oldcwd = getcwd(NULL, 0);
  {
    if (dir_exists(path)) {
      PANIC_IF(chdir(path) != 0);

      if (!file_exists("config")) {
        s = triefort_err_not_a_triefort;
      }

      PANIC_IF(chdir(oldcwd) != 0);
    } else {
      return triefort_err_not_a_triefort;
    }

    if (s == triefort_ok) {
      if (0 != recursive_remove(path)) {
        s = triefort_err_path_could_not_be_destroyed;
      }
    }
  }
  free((void *)oldcwd);

  return s;
}

S triefort_config_get(TF * const fort, const CFG ** cfg) {
  NULLCHK(fort);
  NULLCHK(cfg);

  *cfg = &fort->cfg;

  return triefort_ok;
}

S triefort_put(TF * fort,
    void * const buffer, const size_t bufferlen,
    void * const hash) {
  NULLCHK(fort);
  NULLCHK(buffer);
  NULLCHK(hash);

  const size_t hashlen = fort->cfg.hash_len;
  triefort_hasher_fn * hfn = fort->hcfg->hasher;

  if (0 != hfn(hash, hashlen, buffer, bufferlen)) {
    return triefort_err_hasher_error;
  }

  char * data_path = NULL;
  PANIC_IF(triefort_ok != mk_trie_dirs(fort, hash, hashlen, &data_path));
  char * old_dir = getcwd(NULL,0);
  PANIC_IF(0 != chdir(data_path));
  {
    CHECK_CALL(write_file("triefort.data", buffer, bufferlen));
  }
  PANIC_IF(0 != chdir(old_dir));
  free(old_dir);
  free(data_path);

  return triefort_ok;
}

S triefort_put_with_key(TF * fort,
    void * const key, const size_t keylen,
    void * const buffer, const size_t bufferlen,
    void * const hash) {
  NULLCHK(fort);
  NULLCHK(key);
  NULLCHK(buffer);
  NULLCHK(hash);

  triefort_hasher_fn * hfn = fort->hcfg->hasher;
  const size_t hashlen = fort->cfg.hash_len;

  if (0 != hfn(hash, hashlen, key, keylen)) {
    return triefort_err_hasher_error;
  }

  char * data_path = NULL;
  PANIC_IF(triefort_ok != mk_trie_dirs(fort, hash, hashlen, &data_path));
  char * old_dir = getcwd(NULL,0);
  PANIC_IF(0 != chdir(data_path));
  {
    CHECK_CALL(write_file("triefort.key", key, keylen));
    CHECK_CALL(write_file("triefort.data", buffer, bufferlen));
  }
  PANIC_IF(0 != chdir(old_dir));
  free(old_dir);
  free(data_path);

  return triefort_ok;
}

S triefort_info(const TF * const fort, const void * const hash, INFO ** const info) {
  char * path = trie_path(fort, hash);
  free(path);

  *info = NULL;

  return triefort_ok;
}

void triefort_info_free(INFO * const info) {
  if (info) {
    free(info);
  }
}

static S store_cfg(const CFG * const cfg, const char * const path) {
  NULLCHK(cfg);
  NULLCHK(path);

  FILE * cfghdl = fopen(path, "w");
  if (NULL == cfghdl) {
    return triefort_err_config_could_not_be_created;
  } else {
    PANIC_IF(1 != fwrite(&cfg->depth, sizeof(cfg->depth), 1, cfghdl));
    PANIC_IF(1 != fwrite(&cfg->width, sizeof(cfg->width), 1, cfghdl));
    PANIC_IF(1 != fwrite(&cfg->hash_len, sizeof(cfg->hash_len), 1, cfghdl));
    PANIC_IF(1 != fwrite(&cfg->max_key_len, sizeof(cfg->max_key_len), 1, cfghdl));

    size_t nlen = strnlen(cfg->hash_name, sizeof(cfg->hash_name) - 1);
    uint8_t nlenb = nlen;

    PANIC_IF(1 != fwrite(&nlenb, sizeof(nlenb), 1, cfghdl));
    PANIC_IF(nlen != fwrite(&cfg->hash_name, 1, nlen, cfghdl));
    fclose(cfghdl);
  }

  return triefort_ok;
}

static S load_cfg(CFG * const cfg, const char * const path) {
  NULLCHK(cfg);
  NULLCHK(path);

  FILE * cfghdl = fopen(path, "r");
  if (NULL == cfghdl) {
    return triefort_err_config_could_not_be_opened;
  } else {
    PANIC_IF(1 != fread(&cfg->depth, sizeof(cfg->depth), 1, cfghdl));
    PANIC_IF(1 != fread(&cfg->width, sizeof(cfg->width), 1, cfghdl));
    PANIC_IF(1 != fread(&cfg->hash_len, sizeof(cfg->hash_len), 1, cfghdl));
    PANIC_IF(1 != fread(&cfg->max_key_len, sizeof(cfg->max_key_len), 1, cfghdl));
    uint8_t nlenb = 0;
    PANIC_IF(1 != fread(&nlenb, sizeof(nlenb), 1, cfghdl));
    PANIC_IF(nlenb != fread(&cfg->hash_name, 1, nlenb, cfghdl));
    fclose(cfghdl);
  }

  return triefort_ok;
}

static bool validate_cfg(const CFG * const cfg) {
  NULLCHK(cfg);

  bool valid = ((cfg->depth > 0) &
                (cfg->width > 0) &
                (cfg->hash_len >= (cfg->depth * cfg->width)));

  return valid;
}

static bool dir_exists(const char * const path) {
  NULLCHK(path);

  struct stat s;

  if (0 == stat(path, &s)) {
    if (S_ISDIR(s.st_mode)) {
      return true;
    }
  }

  return false;
}

static bool file_exists(const char * const path) {
  NULLCHK(path);

  struct stat s;

  if (0 == stat(path, &s)) {
    if (S_ISREG(s.st_mode)) {
      return true;
    }
  }

  return false;
}

static int recursive_remove(const char * const path) {
  if (NULL == path) { return 0; }

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

static S mk_trie_dirs(const TF * const fort, void * hash, size_t hashlen, char ** path) {
  const char * old_dir = getcwd(NULL, 0);
  PANIC_IF(0 != chdir(fort->path));

  size_t dir_str_len = (fort->cfg.width * 2) + 1;
  char * dir_str = calloc(1, dir_str_len);
  uint8_t * hashb = hash;
  for (size_t i = 0; i < fort->cfg.depth; i++) {
    for (size_t j = 0; j < fort->cfg.width; j++) {
      char * strpos = &dir_str[j * 2];
      size_t hashix = (i * fort->cfg.width) + j;
      snprintf(strpos, 3, "%02x", hashb[hashix]);
    }
    if (dir_exists(dir_str)) {
      continue;
    } else {
      PANIC_IF(0 != mkdir(dir_str, DIRMODE));
    }
    PANIC_IF(0 != chdir(dir_str));
  }
  free(dir_str);

  char * hash_str = mk_hash_str(hash, hashlen);
  if (!dir_exists(hash_str)) {
    PANIC_IF(0 != mkdir(hash_str, DIRMODE));
  }
  PANIC_IF(0 != chdir(hash_str));
  free(hash_str);

  if (path) {
    *path = getcwd(NULL,0);
  }

  PANIC_IF(0 != chdir(old_dir));
  free((void *)old_dir);

  return triefort_ok;
}

static char * trie_path(const TF * const fort, const void * const hash) {
  const uint8_t * const hashb = hash;
  const char * const fpath = fort->path;
  const size_t fpath_len = strlen(fpath);
  const size_t width = fort->cfg.width;
  const size_t depth = fort->cfg.depth;
  const size_t hashlen = fort->cfg.hash_len;
  const char * const hashstr = mk_hash_str(hash, hashlen);

  size_t path_len = fpath_len + 1 +                 // path and trailing slash
                    ((width * 2) * depth) + depth + // node and trailing slash for each node
                    (hashlen * 2) +                 // hash itself
                    1;                              // trailing null

  char * path = calloc(1, path_len);

  snprintf(path, fpath_len + 2, "%s/", fpath);
  size_t path_pos = fpath_len + 1;

  for (size_t i = 0; i < depth; i++) {
    for (size_t j = 0; j < width; j++) {
      char * strpos = &path[path_pos + (j * 2)];
      size_t hashix = (i * fort->cfg.width) + j;
      snprintf(strpos, 3, "%02x", hashb[hashix]);
      printf("path: %s\n", path);
    }
    path_pos += (width * 2);
    path[path_pos] = '/';
    path_pos += 1;
  }

  snprintf(&path[path_pos], (hashlen * 2) + 1, "%s", hashstr);

  free((void*)hashstr);

  return path;
}

static char * mk_hash_str(const void * const hash, const size_t hashlen) {
  char * hs = calloc(1, (hashlen * 2) + 1);
  const uint8_t * const hashb = hash;

  for (size_t i = 0; i < hashlen; i++) {
    char * h = &hs[i * 2];
    snprintf(h, 3, "%02x", hashb[i]);
  }

  return hs;
}

static S write_file(const char * const filename, const void * const data, const size_t datalen) {
  S s;

  if (file_exists(filename)) {
    s = triefort_err_path_already_exists;
  } else {
    FILE * fh = fopen(filename, "w");
    PANIC_IF(NULL == fh);
    size_t wlen = fwrite(data, datalen, 1, fh);
    if (wlen != 1) {
      s = triefort_err_write_error;
    }
  }

  return triefort_ok;
}
