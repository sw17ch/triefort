# triefort

A library for storing data in a file system using prefix
trees of arbitrary hashes.

## Disk Model

```
/triefort
  /config
  /ab
    /4e
      /ab4ec9a2
        /data
    /a9
      /aba9aacf
        /key
        /data
  /3c
    /d1
      /3cd1002a
        /data
  /4c
    /02
      /4c02c3c8
        /data
```

The `config` file encodes three parameters:
  * `depth` - how many nested directories to use
  * `hash_len` - the length of the hash. NOTE: this must be
    greater than or equal to depth.
  * `hash_name` - this must match the name used in the
    `triefort_hash_cfg` used with `triefort_open`. The hash name may be at most
    `MAX_LEN_HASH_NAME` bytes long.

If a key is provided when doing a `_put`, that key will be used to generate the
hash and the value of the key will be stored in the `key` file.

If no key is specified, a hash of the buffer will be used instead. No `key`
file will be created.
