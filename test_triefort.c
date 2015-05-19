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
  struct triefort * fort = NULL;
  CHECK_CALL(open_test_triefort(&fort));

  triefort_close(fort);
  PASS();
}

TEST triefort_open__populates_internal_config(void) {
  struct triefort * fort = NULL;
  CHECK_CALL(open_test_triefort(&fort));

  ASSERT_EQ_FMT(TEST_TRIE_DEPTH, fort->cfg.depth, "%u");
  ASSERT_EQ_FMT(TEST_HASH_LEN, fort->cfg.hash_len, "%u");
  ASSERT_EQ_FMT(TEST_MAX_KEY_LEN, fort->cfg.max_key_len, "%u");
  ASSERT_STR_EQ(TEST_HASH_NAME, fort->cfg.hash_name);

  triefort_close(fort);
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

  triefort_close(fort);
  PASS();
}

TEST triefort_close__runs_without_segfaulting(void) {
  struct triefort * fort = NULL;
  CHECK_CALL(open_test_triefort(&fort));

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
  enum triefort_status s;
  const struct triefort_cfg * cfg = NULL;
  struct triefort * fort = NULL;

  CHECK_CALL(open_test_triefort(&fort));

  s = triefort_config_get(fort, &cfg);
  ASSERT_EQ_FMT(triefort_ok, s, "%d");

  ASSERT_EQ_FMT(TEST_TRIE_DEPTH, cfg->depth, "%d");
  ASSERT_EQ_FMT(TEST_TRIE_WIDTH, cfg->width, "%d");
  ASSERT_EQ_FMT(TEST_HASH_LEN, cfg->hash_len, "%d");
  ASSERT_STR_EQ(TEST_HASH_NAME, cfg->hash_name);

  triefort_close(fort);
  PASS();
}

TEST triefort_put_with_key__uses_key_for_hash(void) {
  struct triefort * fort = NULL;

  char * key = "test key!";
  char * buffer = "test buffer!";
  uint8_t hash_actual[20] = { 0 };
  uint8_t hash_expected[20] = { 0 };

  CHECK_CALL(open_test_triefort_with_data(&fort, key, buffer, hash_actual));

  ASSERT(0 == test_hasher(hash_expected, sizeof(hash_expected), key, strlen(key)));
  ASSERT(0 == memcmp(hash_expected, hash_actual, sizeof(hash_actual)));

  triefort_close(fort);
  PASS();
}

TEST triefort_put__uses_buffer_for_hash(void) {
  struct triefort * fort = NULL;

  char * buffer = "test buffer!";
  uint8_t hash_expected[20] = { 0 };
  uint8_t hash_actual[20] = { 0 };

  CHECK_CALL(open_test_triefort_with_data(&fort, NULL, buffer, hash_actual));

  ASSERT(0 == test_hasher(hash_expected, sizeof(hash_expected), buffer, strlen(buffer)));
  ASSERT(0 == memcmp(hash_expected, hash_actual, sizeof(hash_actual)));

  triefort_close(fort);
  PASS();
}

TEST triefort_put__writes_buffer_data(void) {
  struct triefort * fort = NULL;

  char * buffer = "test buffer!";
  uint8_t hash[20] = { 0 };

  CHECK_CALL(open_test_triefort_with_data(&fort, NULL, buffer, hash));

  ASSERT_FALSE(buffer_all_null(hash, sizeof(hash)));

  char hash_str[(TEST_HASH_LEN * 2) + 1] = {0};
  char path_buf[512];

  for (size_t i = 0; i < TEST_HASH_LEN; i++) {
    char * h = &hash_str[i * 2];
    snprintf(h, 3, "%02x", hash[i]);
  }

  snprintf(path_buf, sizeof(path_buf), "%s/%02x%02x/%02x%02x/%s/triefort.data",
      TEST_TRIEFORT_PATH,
      hash[0], hash[1],
      hash[2], hash[3],
      hash_str);

  ASSERT(file_exists(path_buf));

  triefort_close(fort);
  PASS();
}

TEST triefort_put_with_key__writes_key_data(void) {
  struct triefort * fort = NULL;

  char * key = "test key!";
  char * buffer = "test buffer!";
  uint8_t hash[20] = { 0 };

  CHECK_CALL(open_test_triefort_with_data(&fort, key, buffer, hash));

  ASSERT_FALSE(buffer_all_null(hash, sizeof(hash)));

  char hash_str[(TEST_HASH_LEN * 2) + 1] = {0};
  char path_buf[512];

  for (size_t i = 0; i < TEST_HASH_LEN; i++) {
    char * h = &hash_str[i * 2];
    snprintf(h, 3, "%02x", hash[i]);
  }

  snprintf(path_buf, sizeof(path_buf), "%s/%02x%02x/%02x%02x/%s/triefort.key",
      TEST_TRIEFORT_PATH,
      hash[0], hash[1],
      hash[2], hash[3],
      hash_str);

  ASSERT(file_exists(path_buf));

  triefort_close(fort);
  PASS();
}

TEST triefort_info__gets_info_about_the_hash(void) {
  struct triefort * fort = NULL;

  char * key = "test key!";
  char * buffer = "test buffer!";
  uint8_t hash[20] = { 0 };

  CHECK_CALL(open_test_triefort_with_data(&fort, key, buffer, hash));

  struct triefort_info * info = NULL;
  enum triefort_status s = triefort_info(fort, hash, &info);
  ASSERT_EQ(triefort_ok, s);
  ASSERT(info != NULL);

  ASSERT_EQ_FMT(strlen(buffer), info->length, "%lu");
  ASSERT_STR_EQ(key, info->key);
  ASSERT_EQ_FMT(strlen(key), info->keylen, "%lu");

  triefort_info_free(info);

  triefort_close(fort);
  PASS();
}

TEST triefort_info_with_key__gets_info_about_the_key(void) {
  struct triefort * fort = NULL;

  char * key = "test key!";
  char * buffer = "test buffer!";
  uint8_t hash[20] = { 0 };

  CHECK_CALL(open_test_triefort_with_data(&fort, key, buffer, hash));

  enum triefort_status s =
    triefort_put_with_key(
      fort,
      key, sizeof(key),
      buffer, sizeof(buffer),
      hash);
  ASSERT_EQ(triefort_ok, s);

  struct triefort_info * info = NULL;
  s = triefort_info_with_key(fort, key, strlen(key), &info);
  ASSERT_EQ(triefort_ok, s);
  ASSERT(info != NULL);

  ASSERT_EQ_FMT(strlen(buffer), info->length, "%lu");
  ASSERT_STR_EQ(key, info->key);
  ASSERT_EQ_FMT(strlen(key), info->keylen, "%lu");

  triefort_info_free(info);

  triefort_close(fort);
  PASS();
}

TEST triefort_get_stream__opens_a_file_handle(void) {
  enum triefort_status s;
  struct triefort * fort = NULL;

  char * key = "test key!";
  char buffer[] = "test buffer!";
  uint8_t hash[20] = { 0 };

  CHECK_CALL(open_test_triefort_with_data(&fort, key, buffer, hash));

  // make sure we get a stream
  FILE * stream = NULL;
  s = triefort_get_stream(
      fort, hash, &stream);
  ASSERT(stream != NULL);
  ASSERT_EQ(triefort_ok, s);

  // check that the stream has the right data
  char rbuffer[sizeof(buffer)] = {0};
  fread(rbuffer, strlen(buffer), 1, stream);
  ASSERT_STR_EQ(buffer, rbuffer);

  s = triefort_stream_close(fort, stream);
  ASSERT_EQ(triefort_ok, s);

  triefort_close(fort);
  PASS();
}

TEST triefort_get_stream_with_key__opens_a_file_handle(void) {
  enum triefort_status s;
  struct triefort * fort = NULL;

  char * key = "test key!";
  char buffer[] = "test buffer!";
  uint8_t hash[20] = { 0 };

  CHECK_CALL(open_test_triefort_with_data(&fort, key, buffer, hash));

  s = triefort_put_with_key(
      fort,
      key, strlen(key),
      buffer, strlen(buffer),
      hash);
  ASSERT_EQ(triefort_ok, s);

  // make sure we get a stream
  FILE * stream = NULL;
  s = triefort_get_stream_with_key(
      fort, key, strlen(key), &stream);
  ASSERT(stream != NULL);
  ASSERT_EQ(triefort_ok, s);

  // check that the stream has the right data
  char rbuffer[sizeof(buffer)];
  fread(rbuffer, strlen(rbuffer), 1, stream);
  ASSERT_STR_EQ(buffer, rbuffer);

  s = triefort_stream_close(fort, stream);
  ASSERT_EQ(triefort_ok, s);

  triefort_close(fort);
  PASS();
}

TEST triefort_get__reads_out_the_stored_data(void) {
  enum triefort_status s;
  struct triefort * fort = NULL;

  char * key = "test key!";
  char buffer[] = "test buffer!";
  uint8_t hash[20] = { 0 };

  CHECK_CALL(open_test_triefort_with_data(&fort, key, buffer, hash));

  char rbuffer[sizeof(buffer)] = {0};
  size_t readlen = 0;

  s = triefort_get(
      fort, hash,
      rbuffer, sizeof(rbuffer),
      &readlen);
  ASSERT(readlen == strlen(buffer));
  ASSERT_EQ(triefort_ok, s);
  ASSERT_STR_EQ(buffer, rbuffer);

  triefort_close(fort);
  PASS();
}

TEST triefort_get_with_key__reads_out_the_stored_data(void) {
  enum triefort_status s;
  struct triefort * fort = NULL;

  char * key = "test key!";
  char buffer[] = "test buffer!";
  uint8_t hash[20] = { 0 };

  CHECK_CALL(open_test_triefort_with_data(&fort, key, buffer, hash));

  char rbuffer[sizeof(buffer)] = {0};
  size_t readlen = 0;

  s = triefort_get_with_key(
      fort,
      key, strlen(key),
      rbuffer, sizeof(rbuffer),
      &readlen);
  ASSERT(readlen == strlen(buffer));
  ASSERT_EQ(triefort_ok, s);
  ASSERT_STR_EQ(buffer, rbuffer);

  triefort_close(fort);
  PASS();
}

TEST triefort_iter_create__makes_a_new_iterator(void) {
  char * key = "iter test!";
  char buffer[] = "some buffer for testing iterators.";
  uint8_t hash[20] = { 0 };

  struct triefort * fort = NULL;
  CHECK_CALL(open_test_triefort_with_data(&fort, key, buffer, hash));

  struct triefort_iter * iter = NULL;
  enum triefort_status s = triefort_iter_create(fort, &iter);
  ASSERT_EQ(triefort_ok, s);
  ASSERT(NULL != iter);
  ASSERT_EQ(fort, iter->fort);
  triefort_iter_free(iter);

  PASS();
}

TEST triefort_iter_create__points_to_the_first_entry(void) {
  char * key = "iter test!";
  char buffer[] = "some buffer for testing iterators.";
  uint8_t hash[20] = { 0 };
  uint8_t iter_hash[20] = { 0 };

  struct triefort * fort = NULL;
  CHECK_CALL(open_test_triefort_with_data(&fort, key, buffer, hash));

  struct triefort_iter * iter = NULL;
  enum triefort_status s;

  s = triefort_iter_create(fort, &iter);
  ASSERT_EQ(triefort_ok, s);

  s = triefort_iter_hash(iter, iter_hash);
  ASSERT_EQ(triefort_ok, s);
  ASSERT(0 == memcmp(hash, iter_hash, sizeof(hash)));

  size_t iter_buffer_len = 0;
  char iter_buffer[sizeof(buffer)] = { 0 };

  s = triefort_iter_data(iter, iter_buffer, sizeof(iter_buffer), &iter_buffer_len);
  ASSERT_EQ(triefort_ok, s);
  ASSERT_STR_EQ(buffer, iter_buffer);

  triefort_iter_free(iter);

  PASS();
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
  RUN_TEST(triefort_put_with_key__uses_key_for_hash);
  RUN_TEST(triefort_put__uses_buffer_for_hash);
  RUN_TEST(triefort_put__writes_buffer_data);
  RUN_TEST(triefort_put_with_key__writes_key_data);
  RUN_TEST(triefort_info__gets_info_about_the_hash);
  RUN_TEST(triefort_info_with_key__gets_info_about_the_key);
  RUN_TEST(triefort_get_stream__opens_a_file_handle);
  RUN_TEST(triefort_get_stream_with_key__opens_a_file_handle);
  RUN_TEST(triefort_get__reads_out_the_stored_data);
  RUN_TEST(triefort_get_with_key__reads_out_the_stored_data);
  RUN_TEST(triefort_iter_create__makes_a_new_iterator);
  RUN_TEST(triefort_iter_create__points_to_the_first_entry);
}

GREATEST_MAIN_DEFS();

int main(int argc, char * argv[]) {
  GREATEST_MAIN_BEGIN();
  RUN_SUITE(suite_triefort);
  GREATEST_MAIN_END();
}
