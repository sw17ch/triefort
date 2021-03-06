#ifndef TRIEFORT_H
#define TRIEFORT_H

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>

#define MAX_LEN_HASH_NAME 64

/**
 * enum triefort_status
 *
 * Return codes for triefort library functions.
 *
 * All status codes but `triefort_ok` indicate a failure or negative result.
 * `triefort_ok` will always have a value of 0.
 */
enum triefort_status {
  triefort_ok = 0,

  triefort_err_PANIC,
  triefort_err_NULL_PTR,

  triefort_err_config_could_not_be_created,
  triefort_err_config_could_not_be_opened,
  triefort_err_hash_already_exists,
  triefort_err_hash_does_not_exist,
  triefort_err_hash_name_mismatch,
  triefort_err_hasher_error,
  triefort_err_invalid_config,
  triefort_err_iterator_done,
  triefort_err_key_too_long,
  triefort_err_not_a_triefort,
  triefort_err_path_already_exists,
  triefort_err_path_could_not_be_created,
  triefort_err_path_could_not_be_destroyed,
  triefort_err_write_error,
};

/**
 * struct triefort
 *
 * A opaque handle to a triefort.
 */
struct triefort;

/**
 * struct triefort_cfg
 *
 * Configuration parameters for a triefort.
 */
struct triefort_cfg {
  /* The maximum directory depth a triefort can use on disk. Must be > 0. */
  uint8_t depth;

  /* The number of bytes to use per directory. Must be > 0. */
  uint8_t width;

  /* The number of bytes each hash contains. Must be >= (depth * width). */
  uint16_t hash_len;

  /* The maximum size of a key. If 0, keys are not allowed. */
  uint32_t max_key_len;

  /* The name of the hash implementation. */
  char hash_name[MAX_LEN_HASH_NAME];
};

/**
 * triefort_hasher_fn
 *
 * The type of the hashing function. Should return 0 on success.
 */
typedef int (triefort_hasher_fn)(
    void * hash,
    const size_t hashlen,
    const void * buffer,
    const size_t bufferlen);

/**
 * struct triefort_hash_cfg
 *
 * Holds a function pointer to the hashing function and the name of the hash
 * function. This name must match exactly match the name of hash name in the
 * triefort configuration.
 */
struct triefort_hash_cfg {
  const char * fn_name;
  triefort_hasher_fn * hasher;
};

/**
 * struct triefort_info
 *
 * Stores information about triefort entries.
 */
struct triefort_info {
  /* How much data is referenced by the hash. */
  size_t length;

  /* A pointer to the key data. NULL if there's no key. */
  void * key;

  /* The length of the key. 0 if there's no key. */
  size_t keylen;

  /* A pointer to the hash. */
  void * hash;

  /* The length of the hash. Always equal to length in
   * triefort config. */
  size_t hashlen;
};

/**
 * struct triefort_iter
 *
 * An opaque reference to an iterator over all hashes in the triefort.
 */
struct triefort_iter;

/**
 * triefort_init
 *
 * Create a triefort at the specified `path  using options in `cfg`. The
 * triefort can then be opened with `triefort_open`.
 *
 * Returns
 *    - triefort_ok - the triefort was created successfully.
 *    - triefort_err_path_already_exists - the specified path already exists.
 *    - triefort_err_path_could_not_be_created - the path does not exist, but
 *      also could not be created.
 */
enum triefort_status triefort_init(
    const char * const path,
    const struct triefort_cfg * const cfg);

/**
 * triefort_open
 *
 * Open an existing triefort at `path` already created by `triefort_init`.
 * `fort` will be a handle to the triefort after it is loaded.
 *
 * Returns
 *    - triefort_ok - the triefort was opened successfull
 *    - triefort_err_not_a_triefort - the path is not a triefort
 *    - triefort_err_invalid_config - the config was invalid
 *    - triefort_err_hash_name_mismatch - the hash name in the config does not
 *      match the hash name in `hashcfg`.
 */
enum triefort_status triefort_open(
    struct triefort ** const fort,
    const struct triefort_hash_cfg * const hashcfg,
    const char * const path);

/**
 * triefort_close
 *
 * Close a triefort. No more calls with `fort` can be made until it is
 * reopened.
 */
enum triefort_status triefort_close(
    struct triefort * fort);

/**
 * triefort_destroy
 *
 * Remove all traces of the triefort located at `path` from the filesystem.
 *
 * Returns
 *    - triefort_ok - the triefort at `path` was destroyed.
 *    - triefort_err_not_a_triefort - `path` does not reference a triefort.
 *    - triefort_err_path_could_not_be_destroyed - `path` exists and has a
 *    .config file, but couldn't be removed by the OS.
 */
enum triefort_status triefort_destroy(
    const char * const path);

/**
 * triefort_config_get
 *
 * Retrieve the configuration from a triefort. `cfg` will be a copy of the
 * triefort's configuration.
 *
 * Returns
 *    - triefort_ok - the configuration was copied successfully
 */
enum triefort_status triefort_config_get(
    struct triefort * const fort,
    const struct triefort_cfg ** cfg);

/**
 * triefort_put
 *
 * Write the content in `buffer` to the triefort. The hash of `buffer` will be
 * the identifier for this content in the triefort. The computed hash value for
 * `buffer` will be stored in `hash`. `hash` must be at least as long as the
 * hash length defined in the triefort config.
 *
 * Returns
 *    - triefort_ok - `buffer` has been written to the triefort and `hash`
 *      contains the hash of `buffer`.
 *    - triefort_err_duplicate_hash - the hash of the content is already
 *      present in the trie.
 */
enum triefort_status triefort_put(
    struct triefort * fort,
    const void * const buffer,
    const size_t bufferlen,
    void * const hash);

/**
 * triefort_put_with_key
 *
 * Write the content in `buffer` to the triefort. The hash of `key` will be the
 * identifier for this content in the triefort. The computed hash value for
 * `key` will be stored in `hash`.  `hash` must be at least as long as the hash
 * length defined in the triefort config.
 *
 * Returns
 *    - triefort_ok - `buffer` has been written to the triefort and `hash`
 *      contains the hash of `key`.
 *    - triefort_err_duplicate_hash - the hash of the content is already
 *      present in the trie.
 */
enum triefort_status triefort_put_with_key(
    struct triefort * fort,
    const void * const key,
    const size_t keylen,
    const void * const buffer,
    const size_t bufferlen,
    void * const hash);

/**
 * triefort_info
 *
 * Get information about the specified hash. `hash` must have enough space to
 * accomodate the hash length defined in the triefort config.
 *
 * `info` must be freed with `triefort_info_free`.
 *
 * Returns
 *    - triefort_ok - `info` has been populated
 *    - triefort_err_hash_does_not_exist - `hash` is not in the triefort
 */
enum triefort_status triefort_info(
    const struct triefort * const fort,
    const void * const hash,
    struct triefort_info ** const info);

/**
 * triefort_info_with_key
 *
 * Get information about the hash of the specified key.
 *
 * `info` must be freed with `triefort_info_free`.
 *
 * Returns
 *    - triefort_ok - `info` has been populated
 *    - triefort_err_hash_does_not_exist - the hash of `key` is not in the
 *      triefort
 */
enum triefort_status triefort_info_with_key(
    const struct triefort * const fort,
    const void * const key,
    const size_t keylen,
    struct triefort_info ** const info);

/**
 * triefort_info_free
 *
 * Free `triefort_info` structures.
 */
void triefort_info_free(
    struct triefort_info * const info);

/**
 * triefort_get_stream
 *
 * Open a read-only file stream to the specified hash in the tirefort, if it
 * exists. If the hash does not exist in the triefort, an error is returned.
 * `hash` must have enough space to accomodate the hash length defined in the
 * triefort config.
 *
 * Returns
 *    - triefort_ok - `*hdl` points to a valid file stream referenced by `hash`
 *    - triefort_err_hash_does_not_exist - `hash` does not reference a real path
 */
enum triefort_status triefort_get_stream(
    struct triefort * const fort,
    const void * const hash,
    FILE ** const hdl);

/**
 * triefort_get_stream_with_key
 *
 * Open a read-only file stream to the hash of the key in the tirefort, if it
 * exists. If the hash of the key does not exist in the triefort, an error is
 * returned.
 *
 * Returns
 *    - triefort_ok - `*hdl` points to a valid file stream referenced by `hash`
 *    - triefort_err_hash_does_not_exist - the hash of `key` does not reference
 *      a real path
 */
enum triefort_status triefort_get_stream_with_key(
    struct triefort * const fort,
    const void * const key,
    const size_t keylen,
    FILE ** const hdl);

/**
 * triefort_stream_close
 *
 * Closes a file stream opened from the triefort.
 *
 * Returns
 *    - triefort_ok - the file was successfully closed
 */
enum triefort_status triefort_stream_close(
    struct triefort * const fort,
    FILE * const hdl);

/**
 * triefort_get
 *
 * Read the content identified by `hash` into `buffer`. At most `bufferlen`
 * bytes will be copied. After copying the data into the buffer `readlen` will
 * be the number of bytes copied into buffer. `hash` must have enough space to
 * accomodate the hash length defined in the triefort config.
 *
 * Returns
 *    - triefort_ok - `buffer` contains all the data referenced by `hash`.
 *    - triefort_err_would_overflow - `buffer` contains `bufferlen` bytes of
 *      data. The hash references more data than would fit.
 *    - triefort_err_hash_does_not_exist - the hash does not exist in the
 *      triefort.
 */
enum triefort_status triefort_get(
    struct triefort * const fort,
    void * hash,
    void * buffer,
    size_t bufferlen,
    size_t * readlen);

/**
 * triefort_get_with_key
 *
 * Read the content identified by `hash` into `buffer`. At most `bufferlen`
 * bytes will be copied. After copying the data into the buffer `readlen` will
 * be the number of bytes copied into buffer.
 *
 * Returns
 *    - triefort_ok - `buffer` contains all the data referenced by `hash`.
 *    - triefort_err_would_overflow - `buffer` contains `bufferlen` bytes of
 *      data. The hash references more data than would fit.
 *    - triefort_err_hash_does_not_exist - the hash does not exist in the
 *      triefort.
 */
enum triefort_status triefort_get_with_key(
    struct triefort * const fort,
    const void * const key,
    size_t keylen,
    void * buffer,
    size_t bufferlen,
    size_t * readlen);

/**
 * triefort_drop
 *
 * Drop a hash and its data from the triefort.
 *
 * Returns
 *    - triefort_ok - `hash` was dropped from the triefort
 *    - triefort_err_hash_does_not_exist - the hash did not exist in the
 *      triefort
 */
enum triefort_status triefort_drop(
    struct triefort * const fort,
    const void * const hash);

/**
 * triefort_drop_with_key
 *
 * Drop a key and its data from the triefort.
 *
 * Returns
 *    - triefort_ok - `hash` was dropped from the triefort
 *    - triefort_err_hash_does_not_exist - the hash did not exist in the
 *      triefort
 */
enum triefort_status triefort_drop_with_key(
    struct triefort * const fort,
    const void * const key,
    const size_t keylen);

/**
 * triefort_exists
 *
 * Check if a hash is present in the triefort.
 *
 * Returns
 *    - triefort_ok - `hash` exists
 *    - triefort_err_hash_does_not_exist - `hash` does not exist
 */
enum triefort_status triefort_exists(
    struct triefort * const fort,
    const void * const hash);

/**
 * triefort_exists
 *
 * Check if a key is present in the triefort.
 *
 * Returns
 *    - triefort_ok - `key` exists
 *    - triefort_err_hash_does_not_exist - `hash` does not exist
 */
enum triefort_status triefort_exists_with_key(
    struct triefort * const fort,
    const void * const key,
    const size_t keylen);

/**
 * triefort_iter_create
 *
 * Create an iterator over all hashes in the triefort. The order in which
 * hashes are iterated is implementation dependent.
 *
 * Returns
 *    - triefort_ok - `*iter` points to a new iterator.
 */
enum triefort_status triefort_iter_create(
    struct triefort * const fort,
    struct triefort_iter ** const iter);

/**
 * triefort_iter_free
 *
 * Frees resources used by the iterator.
 */
void triefort_iter_free(
    struct triefort_iter * iter);

/**
 * triefort_iter_is_done
 *
 * Returns true when the iterator has nothing else to iterate.
 */
bool triefort_iter_is_done(
    struct triefort_iter * iter);

/**
 * triefort_iter_hash
 *
 * Copies the current hash into the provided buffer.
 *
 * `hash` must have at least as many bytes as specified by the triefort
 * configuration.
 *
 * Returns
 *    - triefort_ok - `hash` has been populated.
 *    - triefort_err_iterator_done - the iterator doesn't have any more elements.
 */
enum triefort_status triefort_iter_hash(
    struct triefort_iter * const iter,
    void * const hash);

/**
 * triefort_iter_data
 *
 * Copies the data of the node pointed to by the iterator into the provided
 * buffer.
 *
 * Returns
 *    - triefort_ok - `buffer` has been populated.
 *    - triefort_err_iterator_done - the iterator doesn't have any more elements.
 */
enum triefort_status triefort_iter_data(
    struct triefort_iter * const iter,
    void * buffer,
    size_t bufferlen,
    size_t * readlen);

/**
 * triefort_iter_key
 *
 * Copies the key of the node pointed to by the iterator into the provided
 * buffer.
 *
 * Returns
 *    - triefort_ok - `key` has been populated.
 *    - triefort_err_iterator_done - the iterator doesn't have any more elements.
 */
enum triefort_status triefort_iter_key(
    struct triefort_iter * const iter,
    void * key,
    size_t keylen,
    size_t * readlen);

/**
 * triefort_iter_next
 *
 * Advance the iterator to the next element.
 *
 * Returns
 *    - tirefort_ok - the iterator has been advanced to the next element.
 *    - triefort_err_iterator_done - there are no more elements to iterate.
 * */
enum triefort_status triefort_iter_next(
    struct triefort_iter * const iter);

/**
 * triefort_iter_reset
 *
 * Reset the iterator to the beginning.
 *
 * Returns
 *    - triefort_ok - the iterator was reset.
 */
enum triefort_status triefort_iter_reset(
    struct triefort_iter * iter);

/**
 * triefort_iter_info
 *
 * Get an info structure about the current member of the triefort.
 *
 * `info` must be freed with `triefort_info_free`.
 *
 * Returns
 *    - triefort_ok - `*info` points to a valid structure.
 */
enum triefort_status triefort_iter_info(
    struct triefort_iter * iter,
    struct triefort_info ** info);

#endif /* TRIEFORT_H */
