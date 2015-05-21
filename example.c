#include "triefort.h"

#include <gcrypt.h>
#include <stdint.h>
#include <stdio.h>

#define TF_PATH "__triefort_example_dir"
#define HASH_NAME "sha1"
#define HASH_LEN 20

static int hasher(
    void * hash,
    const size_t hashlen,
    const void * buffer,
    const size_t bufferlen);

const struct triefort_cfg cfg = {
  .depth = 4,
  .width = 4,
  .hash_len = HASH_LEN,
  .max_key_len = 128,
  .hash_name = HASH_NAME,
};

const struct triefort_hash_cfg hcfg = {
  .fn_name = HASH_NAME,
  .hasher = hasher,
};

void hash_to_str(uint8_t * hash, char * str, size_t len);

int main(int argc, char * argv[]) {
  (void)argc;
  (void)argv;

  enum triefort_status s;
  struct triefort * fort = NULL;

  s = triefort_open(&fort, &hcfg, TF_PATH);

  if (triefort_ok != s) {
    puts("Unable to open triefort at " TF_PATH ". Attempting to create it.");

    s = triefort_init(TF_PATH, &cfg);

    if (triefort_ok != s) {
      puts("Unable to create triefort. Bailing.");
    } else {
      puts("Triefort created. Rerun app to begin.");
    }

    return -1;
  }

  /* Create an iterator and print out all members of the triefort. */
  struct triefort_iter * iter = NULL;
  triefort_iter_create(fort, &iter);

  while(!triefort_iter_is_done(iter)) {
    struct triefort_info * info = NULL;
    triefort_iter_info(iter, &info);
    {
      char hashstr[(HASH_LEN * 2) + 1] = { 0 };

      hash_to_str(info->hash, hashstr, sizeof(hashstr));
      printf("%s -- \n", hashstr);

      triefort_iter_next(iter);
    }
    free(info);
  }

  triefort_iter_free(iter);

  /* Read a line from stdin and add it to the triefort. */
  char * line = NULL;
  size_t linecap = 0;
  uint8_t hash[HASH_LEN] = {0};

  ssize_t len = getline(&line, &linecap, stdin);
  if (len < 0) {
    puts("something went wrong");
  } else {
    s = triefort_put(fort, line, len, hash);
    if (triefort_ok != s) {
      puts("something went wrong putting");
    } else {
      puts("added entry");
    }
  }
  free(line);

  triefort_close(fort);

  return 0;
}

static int hasher(void * hash, const size_t hashlen, const void * buffer, const size_t bufferlen) {
  const int algo = GCRY_MD_SHA1;

  if (hashlen != gcry_md_get_algo_dlen(algo)) {
    return -1;
  } else {
    gcry_md_hash_buffer(algo, hash, buffer, bufferlen);
  }

  return 0;
}

void hash_to_str(uint8_t * hash, char * str, size_t len) {
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
