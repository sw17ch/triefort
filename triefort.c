#include "triefort.h"
#include "triefort_internal_types.h"

#include "sds.h"

#include <errno.h>
#include <fts.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <unistd.h>

#define S enum triefort_status
#define TF struct triefort
#define CFG struct triefort_cfg
#define HCFG struct triefort_hash_cfg
#define INFO struct triefort_info
#define ITER struct triefort_iter

#define PANIC() do { \
  fprintf(stderr, "PANIC: %s:%d\n", __FILE__, __LINE__); \
  exit(-254); \
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
static S mk_trie_dirs(const TF * const fort, void * hash, size_t hashlen, sds * path);
static char * mk_hash_str(const void * const hash, const size_t hashlen);
static void mk_hash_from_hex_str(const char * const str, void * const hash, const size_t hashlen);
static S write_file(const char * const filename, const void * const data, const size_t datalen);
static sds trie_dir_path(const TF * const fort, const void * const hash, const char * filename);
static sds sgetcwd(void);
static S mk_info_from_path(const TF * const fort, sds path, const void * const hash, INFO ** info);

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

  sds cfgpath = sgetcwd();
  cfgpath = sdscat(cfgpath, "/");
  cfgpath = sdscat(cfgpath, path);
  cfgpath = sdscat(cfgpath, "/config");

  S s = triefort_ok;
  s = store_cfg(cfg, cfgpath);

  sdsfree(cfgpath);

  return s;
}

S triefort_open(TF ** const fort, const HCFG * const hashcfg, const char * const path) {
  NULLCHK(fort);
  NULLCHK(hashcfg);
  NULLCHK(path);

  S s;

  sds fortpath = sdsnew(path);
  sds cfgpath = sdsdup(fortpath);
  cfgpath = sdscat(cfgpath, "/config");

  if (!dir_exists(fortpath)) {
    s = triefort_err_not_a_triefort;
  } else if (!file_exists(cfgpath)) {
    s = triefort_err_not_a_triefort;
  } else {
    *fort = calloc(1, sizeof(**fort));
    TF * f = *fort;

    f->path = fortpath; // *fort takes ownership of `fortpath`
    f->hcfg = hashcfg;

    if (triefort_ok == (s = load_cfg(&f->cfg, cfgpath))) {
      if (!validate_cfg(&(*fort)->cfg)) {
        s = triefort_err_invalid_config;
      }

      if (0 != strncmp(hashcfg->fn_name, (*fort)->cfg.hash_name, MAX_LEN_HASH_NAME)) {
        s = triefort_err_hash_name_mismatch;
      }

      if (triefort_ok != s) {
        triefort_close(*fort);
        *fort = NULL;
      }
    }
  }

  sdsfree(cfgpath);

  return s;
}

S triefort_close(TF * fort) {
  NULLCHK(fort);
  NULLCHK(fort->path);

  sdsfree(fort->path);
  free(fort);

  return triefort_ok;
}

S triefort_destroy(char * const path) {
  S s = triefort_ok;

  sds spath = sdsnew(path);
  spath = sdscat(spath, "/config");

  if (!file_exists(spath)) {
    s = triefort_err_not_a_triefort;
  } else {
    if (0 != recursive_remove(path)) {
      s = triefort_err_path_could_not_be_destroyed;
    }
  }

  sdsfree(spath);

  return s;
}

S triefort_config_get(TF * const fort, const CFG ** cfg) {
  NULLCHK(fort);
  NULLCHK(cfg);

  *cfg = &fort->cfg;

  return triefort_ok;
}

S triefort_put(TF * fort,
    const void * const buffer, const size_t bufferlen,
    void * const hash) {
  NULLCHK(fort);
  NULLCHK(buffer);
  NULLCHK(hash);

  const size_t hashlen = fort->cfg.hash_len;
  triefort_hasher_fn * hfn = fort->hcfg->hasher;

  if (0 != hfn(hash, hashlen, buffer, bufferlen)) {
    return triefort_err_hasher_error;
  }

  sds sdata_path = NULL;
  PANIC_IF(triefort_ok != mk_trie_dirs(fort, hash, hashlen, &sdata_path));
  sdata_path = sdscat(sdata_path, "/triefort.data");

  S s = triefort_ok;

  if (file_exists(sdata_path)) {
    s = triefort_err_hash_already_exists;
  } else {
    if (!file_exists(sdata_path)) {
      s = write_file(sdata_path, buffer, bufferlen);
    }
  }

  sdsfree(sdata_path);

  return s;
}

S triefort_put_with_key(TF * fort,
    const void * const key, const size_t keylen,
    const void * const buffer, const size_t bufferlen,
    void * const hash) {
  NULLCHK(fort);
  NULLCHK(key);
  NULLCHK(buffer);
  NULLCHK(hash);

  if (keylen > fort->cfg.max_key_len) {
    return triefort_err_key_too_long;
  }

  triefort_hasher_fn * hfn = fort->hcfg->hasher;
  const size_t hashlen = fort->cfg.hash_len;

  if (0 != hfn(hash, hashlen, key, keylen)) {
    return triefort_err_hasher_error;
  }

  S s;
  sds dir_path = NULL;
  PANIC_IF(triefort_ok != mk_trie_dirs(fort, hash, hashlen, &dir_path));

  sds skey_path = sdsdup(dir_path);
  sds sdata_path = sdsdup(dir_path);

  sdata_path = sdscat(sdata_path, "/triefort.data");
  skey_path = sdscat(skey_path, "/triefort.key");

  if (file_exists(sdata_path)) {
    s = triefort_err_hash_already_exists;
  } else {
    s = write_file(skey_path, key, keylen);
    if (triefort_ok == s) {
      s = write_file(sdata_path, buffer, bufferlen);
    }
  }

  sdsfree(skey_path);
  sdsfree(sdata_path);
  sdsfree(dir_path);

  return s;
}

S triefort_info(const TF * const fort, const void * const hash, INFO ** const info) {
  NULLCHK(fort);
  NULLCHK(hash);
  NULLCHK(info);

  sds path = trie_dir_path(fort, hash, NULL);

  S s = mk_info_from_path(fort, path, hash, info);

  sdsfree(path);

  return s;
}

S triefort_info_with_key(
    const TF * const fort,
    const void * const key,
    const size_t keylen,
    INFO ** const info) {
  NULLCHK(fort);
  NULLCHK(key);
  NULLCHK(info);

  void * hash = calloc(1, fort->cfg.hash_len);
  PANIC_IF(0 != fort->hcfg->hasher(hash, fort->cfg.hash_len, key, keylen));
  S s = triefort_info(fort, hash, info);
  free(hash);

  return s;
}

void triefort_info_free(INFO * const info) {
  if (info) {
    if (info->key) { free(info->key); }
    free(info->hash);
    free(info);
  }
}

S triefort_get_stream(TF * const fort, const void * const hash, FILE ** const hdl) {
  NULLCHK(fort);
  NULLCHK(hash);
  NULLCHK(hdl);

  S s = triefort_ok;

  sds path_data = trie_dir_path(fort, hash, "triefort.data");
  if (file_exists(path_data)) {
    *hdl = fopen(path_data,"rb");
  } else {
    *hdl = NULL;
    s = triefort_err_hash_does_not_exist;
  }

  sdsfree(path_data);

  return s;
}

S triefort_get_stream_with_key(
    TF * const fort,
    const void * const key,
    const size_t keylen,
    FILE ** const hdl) {
  NULLCHK(fort);
  NULLCHK(key);
  NULLCHK(hdl);

  void * hash = calloc(1, fort->cfg.hash_len);
  PANIC_IF(0 != fort->hcfg->hasher(hash, fort->cfg.hash_len, key, keylen));
  S s = triefort_get_stream(fort, hash, hdl);
  free(hash);

  return s;
}

S triefort_stream_close(TF * const fort, FILE * const hdl) {
  (void)fort;
  if (NULL != hdl) {
    fclose(hdl);
  }

  return triefort_ok;
}

S triefort_get(TF * const fort, void * hash, void * buffer, size_t bufferlen, size_t * readlen) {
  NULLCHK(fort);
  NULLCHK(hash);
  NULLCHK(buffer);
  NULLCHK(readlen);

  FILE * stream = NULL;

  CHECK_CALL(triefort_get_stream(fort, hash, &stream));
  *readlen = fread(buffer, 1, bufferlen, stream);
  fclose(stream);

  return triefort_ok;
}

S triefort_get_with_key(TF * const fort, void * key, size_t keylen, void * buffer, size_t bufferlen, size_t * readlen) {
  NULLCHK(fort);
  NULLCHK(key);
  NULLCHK(buffer);
  NULLCHK(readlen);

  void * hash = calloc(1, fort->cfg.hash_len);
  PANIC_IF(0 != fort->hcfg->hasher(hash, fort->cfg.hash_len, key, keylen));
  S s = triefort_get(fort, hash, buffer, bufferlen, readlen);
  free(hash);

  return s;
}

S triefort_drop(TF * const fort, const void * const hash) {
  NULLCHK(fort);
  NULLCHK(hash);

  sds path = trie_dir_path(fort, hash, NULL);

  if (dir_exists(path)) {
    recursive_remove(path);
    return triefort_ok;
  } else {
    return triefort_err_hash_does_not_exist;
  }
}

S triefort_drop_with_key(TF * const fort, const void * const key, const size_t keylen) {
  NULLCHK(fort);
  NULLCHK(key);

  void * hash = calloc(1, fort->cfg.hash_len);
  PANIC_IF(0 != fort->hcfg->hasher(hash, fort->cfg.hash_len, key, keylen));
  S s = triefort_drop(fort, hash);
  free(hash);
  return s;
}

S triefort_exists(TF * const fort, const void * const hash) {
  NULLCHK(fort);
  NULLCHK(hash);

  sds path = trie_dir_path(fort, hash, NULL);

  if (dir_exists(path)) {
    return triefort_ok;
  } else {
    return triefort_err_hash_does_not_exist;
  }
}

S triefort_exists_with_key(TF * const fort, const void * const key, const size_t keylen) {
  NULLCHK(fort);
  NULLCHK(key);

  void * hash = calloc(1, fort->cfg.hash_len);
  PANIC_IF(0 != fort->hcfg->hasher(hash, fort->cfg.hash_len, key, keylen));
  S s = triefort_exists(fort, hash);
  free(hash);
  return s;
}

S triefort_iter_create(TF * const fort, ITER ** const iter) {
  NULLCHK(fort);
  NULLCHK(iter);

  *iter = calloc(1, sizeof(**iter));
  ITER * it = *iter;

  it->fort = fort;
  it->hash = calloc(1, fort->cfg.hash_len);
  it->fts = NULL;
  it->ent = NULL;

  return triefort_iter_reset(it);
}

S triefort_iter_next(ITER * const iter) {
  FTSENT * ent;
  int e = 0;

  while((ent = fts_read(iter->fts))) {
    switch(ent->fts_info) {
    case FTS_NS: case FTS_DNR: case FTS_ERR:
      fprintf(stderr, "%s: fts_read error: %s\n",
          ent->fts_accpath, strerror(ent->fts_errno));
      e = ent->fts_errno;
      break;
    case FTS_F:  case FTS_DC: case FTS_DOT:    case FTS_NSOK:
    case FTS_DP: case FTS_SL: case FTS_SLNONE: case FTS_DEFAULT:
      break;
    case FTS_D:
      // We've found a directory at our level.
      // TODO: probably more validation. Maybe?
      if (ent->fts_level == iter->fort->cfg.depth + 1) {
        iter->ent = ent;
        mk_hash_from_hex_str(
            iter->ent->fts_name,
            iter->hash,
            iter->fort->cfg.hash_len);
        return triefort_ok;
      }
      break;
    }
  }

  iter->ent = NULL;
  iter->done = true;

  return triefort_err_iterator_done;
}

void triefort_iter_free(ITER * const iter) {
  if (NULL != iter) {
    fts_close(iter->fts);
    free(iter->hash);
    free(iter);
  }
}

bool triefort_iter_is_done(ITER * iter) {
  return iter->done;
}

S triefort_iter_hash(ITER * const iter, void * const hash) {
  if (iter->done) {
    return triefort_err_iterator_done;
  } else {
    memcpy(hash, iter->hash, iter->fort->cfg.hash_len);
    return triefort_ok;
  }
}

S triefort_iter_data(ITER * const iter, void * buffer, size_t bufferlen, size_t * readlen) {
  if (iter->done) {
    return triefort_err_iterator_done;
  }

  sds data_path = sdsnew(iter->ent->fts_path);
  data_path = sdscat(data_path, "/triefort.data");
  {
    FILE * fh = fopen(data_path, "rb");
    *readlen = fread(buffer, 1, bufferlen, fh);
    fclose(fh);
  }
  sdsfree(data_path);

  return triefort_ok;
}

S triefort_iter_key(ITER * const iter, void * key, size_t keylen, size_t * readlen) {
  if (iter->done) {
    return triefort_err_iterator_done;
  }

  sds key_path = sdsnew(iter->ent->fts_path);
  key_path = sdscat(key_path, "/triefort.key");
  {
    FILE * fh = fopen(key_path, "rb");
    *readlen = fread(key, 1, keylen, fh);
    fclose(fh);
  }
  sdsfree(key_path);

  return triefort_ok;
}

S triefort_iter_reset(ITER * iter) {
  const char * const ptrs[] = { iter->fort->path, 0 };
  const int fts_options = FTS_NOCHDIR | FTS_PHYSICAL | FTS_XDEV;

  if (NULL != iter->fts) { fts_close(iter->fts); }
  iter->done = false;
  iter->fts = fts_open((char * const *)ptrs, fts_options, NULL);
  iter->ent = NULL;

  return triefort_iter_next(iter);
}

S triefort_iter_info(ITER * iter, INFO ** info) {
  NULLCHK(iter);
  NULLCHK(info);

  sds path = sdsnew(iter->ent->fts_path);
  S s = mk_info_from_path(iter->fort, path, iter->hash, info);
  sdsfree(path);

  return s;
}

static S store_cfg(const CFG * const cfg, const char * const path) {
  NULLCHK(cfg);
  NULLCHK(path);

  FILE * cfghdl = fopen(path, "wb");
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

  FILE * cfghdl = fopen(path, "rb");
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

static S mk_trie_dirs(const TF * const fort, void * hash, size_t hashlen, sds * path) {
  *path = sdsnew(fort->path);
  *path = sdscat(*path, "/");

  char dir_node[(fort->cfg.width * 2) + 2];

  uint8_t * hashb = hash;
  for (size_t i = 0; i < fort->cfg.depth; i++) {
    for (size_t j = 0; j < fort->cfg.width; j++) {
      char * strpos = &dir_node[j * 2];
      size_t hashix = (i * fort->cfg.width) + j;

      snprintf(strpos, sizeof(dir_node), "%02x/", hashb[hashix]);
    }
    *path = sdscat(*path, dir_node);

    if (dir_exists(*path)) {
      continue;
    } else {
      PANIC_IF(0 != mkdir(*path, DIRMODE));
    }
  }

  sds hash_str = mk_hash_str(hash, hashlen);
  *path = sdscatsds(*path, hash_str);
  sdsfree(hash_str);

  if (!dir_exists(*path)) {
    PANIC_IF(0 != mkdir(*path, DIRMODE));
  }

  return triefort_ok;
}

static sds trie_dir_path(const TF * const fort, const void * const hash, const char * filename) {
  const size_t width = fort->cfg.width;
  const size_t depth = fort->cfg.depth;
  const size_t hashlen = fort->cfg.hash_len;
  const uint8_t * const hashb = hash;
  char dir_node[(width * 2) + 2];
  sds path = sdsdup(fort->path);

  for (size_t i = 0; i < depth; i++) {
    path = sdscat(path, "/");
    for (size_t j = 0; j < width; j++) {
      char * strpos = &dir_node[j * 2];
      size_t hashix = (i * width) + j;
      snprintf(strpos, 3, "%02x", hashb[hashix]);
    }
    path = sdscat(path, dir_node);
  }
  path = sdscat(path, "/");

  sds shash = mk_hash_str(hash, hashlen);
  path = sdscat(path, shash);
  sdsfree(shash);

  if (NULL != filename) {
    path = sdscat(path, "/");
    path = sdscat(path, filename);
  }

  return path;
}

static sds mk_hash_str(const void * const hash, const size_t hashlen) {
  const uint8_t * const hashb = hash;
  char node[3] = { 0 };
  sds hs = sdsempty();

  for (size_t i = 0; i < hashlen; i++) {
    snprintf(node, sizeof(node), "%02x", hashb[i]);
    hs = sdscat(hs, node);
  }

  return hs;
}

static void mk_hash_from_hex_str(const char * const str, void * const hash, const size_t hashlen) {
  size_t slen = strlen(str);
  if (slen % 2 == 1) { return; }

  uint8_t * hashb = hash;

  for (size_t i = 0; i < hashlen; i++) {
    size_t pos = i * 2;

    if ((pos + 1) < slen) {
      sscanf(&str[pos], "%02hhx", &hashb[i]);
    }
  }
}

static S write_file(const char * const filename, const void * const data, const size_t datalen) {
  S s;

  if (file_exists(filename)) {
    s = triefort_err_path_already_exists;
  } else {
    FILE * fh = fopen(filename, "wb");
    PANIC_IF(NULL == fh);
    size_t wlen = fwrite(data, datalen, 1, fh);
    if (wlen != 1) {
      s = triefort_err_write_error;
    }
    fclose(fh);
  }

  return triefort_ok;
}

static sds sgetcwd(void) {
  char * c = getcwd(NULL,0);
  sds s = sdsnew(c);
  free(c);
  return s;
}

static S mk_info_from_path(const TF * const fort, sds path, const void * const hash, INFO ** info) {
  sds data_path = sdsdup(path);
  sds key_path = sdsdup(path);

  data_path = sdscat(data_path, "/triefort.data");
  key_path = sdscat(key_path, "/triefort.key");

  if (file_exists(data_path)) {
    struct stat s;
    PANIC_IF(0 != stat(data_path, &s));

    *info = calloc(1, sizeof(**info));
    INFO * inf = *info;

    inf->hash = calloc(1, fort->cfg.hash_len);
    memcpy(inf->hash, hash, fort->cfg.hash_len);
    inf->hashlen = fort->cfg.hash_len;
    inf->length = s.st_size;

    if (file_exists(key_path)) {
      FILE * kh = fopen(key_path, "rb");
      PANIC_IF(NULL == kh);
      PANIC_IF(0 != fstat(fileno(kh), &s));

      inf->keylen = s.st_size;
      inf->key = calloc(1, s.st_size);
      PANIC_IF(1 != fread(inf->key, s.st_size, 1, kh));
      fclose(kh);
    } else {
      inf->keylen = 0;
      inf->key = NULL;
    }
  }

  sdsfree(data_path);
  sdsfree(key_path);

  return triefort_ok;
}
