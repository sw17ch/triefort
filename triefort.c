#include "triefort.h"
#include "triefort_internal_types.h"

#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define S enum triefort_status
#define TF struct triefort
#define CFG struct triefort_cfg
#define HCFG struct triefort_hash_cfg
#define ITER struct triefort_iter

#define PANIC() do { \
  fprintf(stderr, "PANIC: %s:%d\n", __FILE__, __LINE__); \
  return triefort_err_PANIC; \
} while(0)
#define PANIC_IF(COND) do { if (COND) { PANIC(); } } while(0)
#define CHECK_CALL(CALL) do { S s; if (triefort_ok != (s = (CALL))) { return s; } } while(0) 

static S store_cfg(const CFG * const cfg, const char * const path);
static S load_cfg(CFG * const cfg, const char * const path);

S triefort_init(const char * const path, const CFG * const cfg) {
  int mode = (S_IRUSR | S_IWUSR | S_IXUSR) |
             (S_IRGRP |           S_IXGRP) |
             (S_IROTH |           S_IXOTH);

  if (0 != mkdir(path, mode)) {
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
  assert(fort);
  assert(hashcfg);
  assert(path);

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

  return triefort_ok;
}

void triefort_close(TF * fort) {
  assert(fort);
  assert(fort->path);

  free((void *)fort->path);
  free(fort);
}

static S store_cfg(const CFG * const cfg, const char * const path) {
  FILE * cfghdl = fopen(path, "w");
  if (NULL == cfghdl) {
    return triefort_err_config_could_not_be_created;
  } else {
    PANIC_IF(1 != fwrite(&cfg->depth, sizeof(cfg->depth), 1, cfghdl));
    PANIC_IF(1 != fwrite(&cfg->hash_len, sizeof(cfg->hash_len), 1, cfghdl));

    size_t nlen = strnlen(cfg->hash_name, sizeof(cfg->hash_name) - 1);
    uint8_t nlenb = nlen;
    assert(MAX_LEN_HASH_NAME >= nlen);

    PANIC_IF(1 != fwrite(&nlenb, sizeof(nlenb), 1, cfghdl));
    PANIC_IF(nlen != fwrite(&cfg->hash_name, 1, nlen, cfghdl));
    fclose(cfghdl);
  }

  return triefort_ok;
}

static S load_cfg(CFG * const cfg, const char * const path) {
  FILE * cfghdl = fopen(path, "r");
  if (NULL == cfghdl) {
    return triefort_err_config_could_not_be_opened;
  } else {
    PANIC_IF(1 != fread(&cfg->depth, sizeof(cfg->depth), 1, cfghdl));
    PANIC_IF(1 != fread(&cfg->hash_len, sizeof(cfg->hash_len), 1, cfghdl));
    uint8_t nlenb = 0;
    PANIC_IF(1 != fread(&nlenb, sizeof(nlenb), 1, cfghdl));
    PANIC_IF(nlenb != fread(&cfg->hash_name, 1, nlenb, cfghdl));
    fclose(cfghdl);
  }

  return triefort_ok;
}
