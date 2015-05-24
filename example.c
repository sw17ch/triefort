#include "triefort.h"

#include <gcrypt.h>
#include <getopt.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/param.h>

#define TF_PATH "__triefort_example_dir"
#define HASH_NAME "sha1"
#define HASH_LEN 20

static int hasher(void * hash, const size_t hashlen, const void * buffer, const size_t bufferlen) {
  if (hashlen != gcry_md_get_algo_dlen(GCRY_MD_SHA1)) {
    return -1;
  }

  gcry_md_hash_buffer(GCRY_MD_SHA1, hash, buffer, bufferlen);

  return 0;
}

const struct triefort_cfg cfg = {
  .depth = 2,
  .width = 1,
  .hash_len = HASH_LEN,
  .max_key_len = 128,
  .hash_name = HASH_NAME,
};

const struct triefort_hash_cfg hcfg = {
  .fn_name = HASH_NAME,
  .hasher = hasher,
};

enum mode {
  MODE_UNDEFINED,
  MODE_USAGE,
  MODE_LIST,
  MODE_GET_BY_HASH,
  MODE_GET_BY_KEY,
  MODE_PUT,
  MODE_PUT_BY_KEY,
};

static void hash_to_str(uint8_t * hash, char * str, size_t len);
static void str_to_hash(const char * const str, const size_t slen, uint8_t * const hash, const size_t hlen);

static int get_by_hash(const char * const hashstr);
static int get_by_key(const char * const keystr);
static int put(const void * const data, size_t datalen);
static int put_by_key(const char * const key, const void * const data, size_t datalen);
static int list_all(void);
static void print_usage(const char * const name);

static struct triefort * init(void);

int main(int argc, char * argv[]) {
  enum mode mode = MODE_UNDEFINED;
  char * mode_option = NULL;
  char * key = NULL;
  int c;
  opterr = 0;

  while( (c = getopt(argc, argv, "g:G:p:P:lhk:")) != -1) {
    if (c == 'k') {
      key = optarg;
    } else {
      if (MODE_UNDEFINED == mode) {
        mode_option = optarg;

        switch (c) {
        case 'g': mode = MODE_GET_BY_HASH; break;
        case 'G': mode = MODE_GET_BY_KEY;  break;
        case 'p': mode = MODE_PUT;         break;
        case 'P': mode = MODE_PUT_BY_KEY;  break;
        case 'l': mode = MODE_LIST;        break;
        case 'h': mode = MODE_USAGE;       break;

        case 'k': break;

        case '?':
        default:
          switch(optopt) {
            case 'g': case 'G': case 'p': case 'P': case 'k':
              fprintf(stderr, "Option requries an argument: -%c\n\n", optopt);
              break;
            default:
              fprintf(stderr, "Unknown option: %c\n\n", optopt);
              break;
          }
          break;
        }
      } else {
        fprintf(stderr, "Mode already defined.\n");
        mode = MODE_USAGE;
      }
    }
  }

  if (NULL != key && mode != MODE_PUT_BY_KEY) {
    fprintf(stderr, "WARNING: ignoring key value: %s\n", key);
  }

  int result = 0;

  switch(mode) {
  case MODE_UNDEFINED:
    result = 1;
  case MODE_USAGE:
    print_usage(argv[0]);
    break;
  case MODE_GET_BY_HASH:
    result = get_by_hash(mode_option);
    break;
  case MODE_GET_BY_KEY:
    result = get_by_key(mode_option);
    break;
  case MODE_PUT:
    result = put(mode_option, strlen(mode_option));
    break;
  case MODE_PUT_BY_KEY:
    result = put_by_key(key, mode_option, strlen(mode_option));
    break;
  case MODE_LIST:
    result = list_all();
    break;
  }

  return result;
}

static void hash_to_str(uint8_t * hash, char * str, size_t len) {
  snprintf(str, len,
      "%02x%02x%02x%02x"
      "%02x%02x%02x%02x"
      "%02x%02x%02x%02x"
      "%02x%02x%02x%02x"
      "%02x%02x%02x%02x",
      hash[0],  hash[1],  hash[2],  hash[3],
      hash[4],  hash[5],  hash[6],  hash[7],
      hash[8],  hash[9],  hash[10], hash[11],
      hash[12], hash[13], hash[14], hash[15],
      hash[16], hash[17], hash[18], hash[19]);
}

static void str_to_hash(const char * const str, const size_t slen, uint8_t * const hash, const size_t hlen) {
  size_t bytes = MIN(slen / 2, hlen);

  for(size_t i = 0; i < bytes; i++) {
    sscanf(&str[i * 2], "%02hhx", &hash[i]);
  }
}

static void print_usage(const char * const name) {
  fprintf(stderr, "usage %s [-h] [-g hash] [-G key] [-p data] [-k key -P data]\n"
                  "\n"
                  "    g - get by hash\n"
                  "    G - get by key\n"
                  "    p - put\n"
                  "    P - put by key\n"
                  "    l - list values in triefort\n"
                  "    h - list this usage information\n"
                  "    k - key value\n"
                  "\n"
                  "    Only 1 of [gGpPlh] may be present.\n"

      , name);
}

static int get_by_hash(const char * const hashstr) {
  uint8_t hash[20] = {0};
  struct triefort_info * info = NULL;
  struct triefort * f = init();

  if (NULL == f) { return 255; }

  str_to_hash(hashstr, strlen(hashstr), hash, sizeof(hash));

  enum triefort_status s = triefort_info(f, hash, &info);

  if (triefort_ok != s) {
    fprintf(stderr, "Error during `%s`: %d\n", __FUNCTION__, s);
  } else {
    char * data = calloc(1, info->length + 1);
    size_t readlen = 0;
    s = triefort_get(f, hash, data, info->length, &readlen);
    fputs(data, stdout);
    free(data);
  }

  return s;
}

static int get_by_key(const char * const keystr) {
  size_t keylen = strlen(keystr);
  struct triefort_info * info = NULL;
  struct triefort * f = init();

  if (NULL == f) { return 255; }

  enum triefort_status s = triefort_info_with_key(f, keystr, keylen, &info);

  if (triefort_ok != s) {
    fprintf(stderr, "Error during `%s`: %d\n", __FUNCTION__, s);
  } else {
    char * data = calloc(1, info->length + 1);
    size_t readlen = 0;
    s = triefort_get_with_key(f, keystr, keylen, data, info->length, &readlen);
    fputs(data, stdout);
    free(data);
  }

  return s;
}

static int put(const void * const data, size_t datalen) {
  struct triefort * f = init();
  if (NULL == f) { return 255; }

  uint8_t hash[20];
  enum triefort_status s = triefort_put(f, data, datalen, hash);

  if (triefort_ok != s) {
    fprintf(stderr, "Error during `%s`: %d\n", __FUNCTION__, s);
  }
  triefort_close(f);
  return 0;
}
static int put_by_key(const char * const key, const void * const data, size_t datalen) {
  struct triefort * f = init();
  if (NULL == f) { return 255; }

  uint8_t hash[20];
  enum triefort_status s = triefort_put_with_key(
      f,
      key,
      strlen(key),
      data,
      datalen, hash);

  if (triefort_ok != s) {
    fprintf(stderr, "Error during `%s`: %d\n", __FUNCTION__, s);
  }
  triefort_close(f);

  return 0;
}

static int list_all(void) {
  struct triefort * fort = init();
  if (NULL == fort) { return 255; }

  struct triefort_iter * iter = NULL;
  triefort_iter_create(fort, &iter);

  while(!triefort_iter_is_done(iter)) {
    struct triefort_info * info = NULL;
    triefort_iter_info(iter, &info);
    {
      char hashstr[(HASH_LEN * 2) + 1] = { 0 };

      hash_to_str(info->hash, hashstr, sizeof(hashstr));
      if (info->keylen > 0) {
        char * key = calloc(1, info->keylen + 1);
        memcpy(key, info->key, info->keylen);

        printf("%s -- %s\n", hashstr, key);

        free(key);
      } else {
        printf("%s\n", hashstr);
      }

      triefort_iter_next(iter);
    }
    free(info);
  }

  triefort_iter_free(iter);
  return 0;
}

static struct triefort * init(void) {
  struct triefort * f = NULL;

  if (triefort_ok != triefort_open(&f, &hcfg, TF_PATH)) {
    if (triefort_ok != triefort_init(TF_PATH, &cfg)) {
      return NULL;
    }

    if (triefort_ok != triefort_open(&f, &hcfg, TF_PATH)) {
      return NULL;
    }
  }

  return f;
}
