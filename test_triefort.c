#include "greatest.h"
#include "triefort.h"
#include "triefort_internal_types.h"

#include "test_utils.h"

#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <unistd.h>

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
  const struct triefort_cfg * cfg = NULL;
  struct triefort * fort = NULL;

  s = triefort_open(&fort, &hashcfg, TEST_TRIEFORT_PATH);
  ASSERT_EQ_FMT(triefort_ok, s, "%d");

  s = triefort_config_get(fort, &cfg);
  ASSERT_EQ_FMT(triefort_ok, s, "%d");

  ASSERT_EQ_FMT(TEST_TRIE_DEPTH, cfg->depth, "%d");
  ASSERT_EQ_FMT(TEST_TRIE_WIDTH, cfg->width, "%d");
  ASSERT_EQ_FMT(TEST_HASH_LEN, cfg->hash_len, "%d");
  ASSERT_STR_EQ(TEST_HASH_NAME, cfg->hash_name);

  PASS();
}

TEST triefort_put__creates_key_hash(void) {
  CHECK_CALL(create_test_triefort());

  enum triefort_status s;
  struct triefort * fort = NULL;

  s = triefort_open(&fort, &hashcfg, TEST_TRIEFORT_PATH);
  ASSERT_EQ_FMT(triefort_ok, s, "%d");

  char key[] = "test key";
  char buffer[] = "test buffer";
  uint8_t hash[20] = { 0 };

  s = triefort_put(
      fort,
      key, sizeof(key),
      buffer, sizeof(buffer),
      hash, sizeof(hash));

  ASSERT_FALSE(buffer_all_null(hash, sizeof(hash)));
  ASSERT_EQ(triefort_ok, s);

  PASS();
}

TEST triefort_put__creates_buffer_hash(void) {
  CHECK_CALL(create_test_triefort());

  enum triefort_status s;
  struct triefort * fort = NULL;

  s = triefort_open(&fort, &hashcfg, TEST_TRIEFORT_PATH);
  ASSERT_EQ_FMT(triefort_ok, s, "%d");

  char buffer[] = "test buffer";
  uint8_t hash[20] = { 0 };

  s = triefort_put(
      fort,
      NULL, 0,
      buffer, sizeof(buffer),
      hash, sizeof(hash));

  ASSERT_FALSE(buffer_all_null(hash, sizeof(hash)));
  ASSERT_EQ(triefort_ok, s);

  PASS();
}

TEST triefort_put__adds_prefix_directories(void) {
  CHECK_CALL(create_test_triefort());

  enum triefort_status s;
  struct triefort * fort = NULL;

  s = triefort_open(&fort, &hashcfg, TEST_TRIEFORT_PATH);
  ASSERT_EQ_FMT(triefort_ok, s, "%d");

  char buffer[] = "test buffer";
  uint8_t hash[20] = { 0 };

  s = triefort_put(
      fort,
      NULL, 0,
      buffer, sizeof(buffer),
      hash, sizeof(hash));

  ASSERT_FALSE(buffer_all_null(hash, sizeof(hash)));
  ASSERT_EQ(triefort_ok, s);

  char path_buf[512];

  snprintf(path_buf, sizeof(path_buf), "%s/%02x%02x/%02x%02x",
      TEST_TRIEFORT_PATH,
      hash[0], hash[1],
      hash[2], hash[3]);

  ASSERT(dir_exists(path_buf));

  PASS();
}

TEST triefort_put__writes_buffer_data(void) {
  FAIL();
}

TEST triefort_put__writes_key_data(void) {
  FAIL();
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
  RUN_TEST(triefort_put__creates_key_hash);
  RUN_TEST(triefort_put__creates_buffer_hash);
  RUN_TEST(triefort_put__adds_prefix_directories);
  RUN_TEST(triefort_put__writes_buffer_data);
  RUN_TEST(triefort_put__writes_key_data);
}

GREATEST_MAIN_DEFS();

int main(int argc, char * argv[]) {
  GREATEST_MAIN_BEGIN();
  RUN_SUITE(suite_triefort);
  GREATEST_MAIN_END();
}
