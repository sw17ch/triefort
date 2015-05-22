# triefort

A library for storing data in a file system using prefix
trees of arbitrary hashes.

## Disk Model

```
/triefort
| /config
| /ab
| | /4e
| | | /ab4ec9a2
| | | | /trifort.data
| | /a9
| | | /aba9aacf
| | | | /trifort.key
| | | | /trifort.data
| /3c
| | /d1
| | | /3cd1002a
| | | | /trifort.data
| /4c
| | /02
| | | /4c02c3c8
| | | | /trifort.data
```

The `config` file encodes three parameters:
  * `depth` - how many nested directories to use
  * `hash_len` - the length of the hash in bytes. This must be greater than or
    equal to `depth`.
  * `hash_name` - this must match the name used in the
    `triefort_hash_cfg` used with `triefort_open`. The hash name may be at most
    `MAX_LEN_HASH_NAME` bytes long.

If a key is provided when doing a `triefort_put`, that key will be used to
generate the hash and the value of the key will be stored in the `key` file.

If no key is specified, a hash of the buffer will be used instead. No `key`
file will be created.

# Third Party Software

* [greatest (60e25ce7)](https://github.com/silentbicycle/greatest)
  * greatest.h
* [sds (d86a9b85)](https://github.com/antirez/sds)
  * sds.h
  * sds.c
