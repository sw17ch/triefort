#ifndef TRIEFORT_H
#define TRIEFORT_H

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>

/**
 * enum triefort_status
 *
 * Return codes for triefort library functions.
 */
enum triefort_status {
  triefort_ok,
  triefort_err_no_fort_at_path,
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
  /* The maximum directory depth a triefort can use on disk. */
  uint8_t depth;

  /* The number of bytes each hash contains. */
  uint16_t hash_len;
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
 *    - triefort_ok - the triefort was created successfully
 *    - triefort_err_already_exists - the specified path already exists
 */
enum triefort_status triefort_init(
    const char * const path,
    struct triefort_cfg * cfg);

/**
 * triefort_open
 *
 * Open the triefort at the specified `path`. `fort` will be a handle to the
 * triefort after it is loaded.
 *
 * Returns
 *    - triefort_ok - the triefort was opened successfull
 *    - triefort_err_not_a_triefort - the path is not a triefort
 */
enum triefort_status triefort_open(
    struct triefort * fort,
    struct triefort_hash_cfg * hashcfg,
    const char * const path);

/**
 * triefort_close
 *
 * Close a triefort. No more calls with `fort` can be made until it is
 * reopened.
 *
 * Returns
 *    - triefort_ok - the `fort` was closed
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
 *    - triefort_err_no_fort_at_path - `path` does not reference a triefort.
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
    struct triefort * fort,
    struct triefort_cfg * cfg);

/**
 * triefort_info
 *
 * Get information about the hash.
 *
 * Returns
 *    - triefort_ok - `info` has been populated with information about the data
 *      referenced by `hash`
 *    - triefort_err_does_not_exist - the hash does not exist in the triefort.
 */
enum triefort_status triefort_info(
    struct triefort * fort,
    void * hash,
    size_t hashlen,
    struct triefort_info * info);

/**
 * triefort_get_stream
 *
 * Open a read-only file stream to the specified hash in the tirefort, if it
 * exists. If the hash does not exist in the triefort, an error is returned.
 *
 * Returns
 *    - triefort_ok - `*hdl` points to a valid file stream referenced by `hash`
 *    - triefort_err_does_not_exist - `hash` does not reference a real path
 */
enum triefort_status triefort_get_stream(
    struct triefort * fort,
    void * hash,
    size_t hashlen,
    FILE ** hdl);

/**
 * triefort_get_stream_close
 *
 * Closes a file stream opened from the triefort.
 *
 * Returns
 *    - triefort_ok - the file was successfully closed
 */
enum triefort_status triefort_get_stream_close(
    FILE * hdl);

/**
 * triefort_get
 *
 * Read the content identified by `hash` into `buffer`. At most `bufferlen`
 * bytes will be copied. After copying the data into the buffer `readlen` will
 * be the number of bytes copied into buffer.
 *
 * Returns
 *    - triefort_ok - `buffer` contains all the data referenced by `hash`.
 *    - triefort_err_would_overflow - `buffer` contains `bufferlen` bytes of
 *      data. The hash references more data than would fit.
 *    - triefort_err_does_not_exist - the hash does not exist in the triefort.
 */
enum triefort_status triefort_get(
    struct triefort * fort,
    void * hash,
    size_t hashlen,
    void * buffer,
    size_t bufferlen,
    size_t * readlen);

/**
 * triefort_set
 *
 * Write the content in `buffer` to the triefort. The hash of the content will
 * be stored in `hash`.
 *
 * Returns
 *    - triefort_ok - `buffer` has been written to the triefor and `hash`
 *      contains the hash of the buffer.
 *    - triefort_err_duplicate_hash - the hash of the content is already
 *      present in the trie.
 */
enum triefort_status triefort_set(
    struct triefort * fort,
    void * hash,
    size_t hashlen,
    void * buffer,
    size_t bufferlen);

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
    struct triefort * fort,
    struct triefort_iter ** iter);

/**
 * triefort_iter_free
 *
 * Frees resources used by the iterator.
 */
void triefort_iter_free(
    struct triefort_iter * iter);

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
 * triefort_iter_next
 *
 * Advance the iterator to the next element.
 *
 * Returns
 *    - tirefort_ok - the iterator has been advanced to the next element.
 *    - triefort_err_iterator_done - there are no more elements to iterate.
 * */
enum triefort_status triefort_iter_next(
    struct triefort_iter * iter);

/**
 * triefort_iter_hash
 *
 * Copy the hash the iterator is currently referencing into `hash`.
 *
 * Returns
 *    - triefort_ok - the current hash has been copied to `hash`.
 *    - triefort_err_iterator_done - the iterator has reached the end.
 */
enum triefort_status triefort_iter_hash(
    struct triefort_iter * iter,
    void * hash,
    size_t hashlen);

#endif /* TRIEFORT_H */