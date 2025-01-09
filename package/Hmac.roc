module [hmac_sha256]

import Sha

block_size = 64

outer_pad = List.repeat(0x5c, block_size)
inner_pad = List.repeat(0x36, block_size)

pad_by = \key, n -> List.concat(key, List.repeat(0x00, n))

compute_block_sized_key : List U8 -> List U8
compute_block_sized_key = \key ->
    pad_if_needed = \bytes ->
        pad_count = block_size - List.len(bytes)
        if pad_count > 0 then
            pad_by(bytes, pad_count)
        else
            bytes
    smaller_key =
        if List.len(key) > block_size then
            Sha.sha256(key)
        else
            key
    pad_if_needed(smaller_key)

## Computes the HMAC-SHA256 signature of a message using given a key.
##
##     "this is my message" |> Str.toUtf8 |> hmacSha256 myKey
hmac_sha256 : List U8, List U8 -> List U8
hmac_sha256 = \message, key ->
    block_sized_key = compute_block_sized_key(key)
    outer_key = List.map2(block_sized_key, outer_pad, Num.bitwise_xor)
    inner_key = List.map2(block_sized_key, inner_pad, Num.bitwise_xor)
    inner_hash = inner_key |> List.concat(message) |> Sha.sha256
    outer_key |> List.concat(inner_hash) |> Sha.sha256

expect
    key = Str.to_utf8("key")
    result = Str.to_utf8("The quick brown fox jumps over the lazy dog") |> hmac_sha256(key)
    result == [0xf7, 0xbc, 0x83, 0xf4, 0x30, 0x53, 0x84, 0x24, 0xb1, 0x32, 0x98, 0xe6, 0xaa, 0x6f, 0xb1, 0x43, 0xef, 0x4d, 0x59, 0xa1, 0x49, 0x46, 0x17, 0x59, 0x97, 0x47, 0x9d, 0xbc, 0x2d, 0x1a, 0x3c, 0xd8]

expect
    key = Str.to_utf8("Thomas Paine")
    result = Str.to_utf8("my country is the world, and my religion is to do good") |> hmac_sha256(key)
    result == [0xc9, 0x47, 0x5b, 0x8e, 0xe8, 0x78, 0x51, 0xc7, 0xad, 0x23, 0x91, 0x96, 0x09, 0x6c, 0x9d, 0x5a, 0x1a, 0x96, 0x75, 0x3d, 0x6d, 0xc3, 0x29, 0x95, 0xff, 0xa7, 0x79, 0x7f, 0x14, 0x04, 0xeb, 0xbd]

expect
    key = List.repeat(65, 200)
    result = Str.to_utf8("my country is the world, and my religion is to do good") |> hmac_sha256(key)
    result == [0x9e, 0xc7, 0x4a, 0x1c, 0x89, 0x71, 0x7a, 0x62, 0x28, 0xaa, 0x95, 0x74, 0xcd, 0x59, 0x58, 0x2c, 0x08, 0x3a, 0xbf, 0x41, 0x9f, 0x87, 0xc6, 0x80, 0xc3, 0xac, 0x67, 0x87, 0x61, 0x8f, 0x03, 0xca]
