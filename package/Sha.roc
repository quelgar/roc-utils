module [sha256]

# Hash values
h0 = 0x6a09e667
h1 = 0xbb67ae85
h2 = 0x3c6ef372
h3 = 0xa54ff53a
h4 = 0x510e527f
h5 = 0x9b05688c
h6 = 0x1f83d9ab
h7 = 0x5be0cd19

init_hash = {
    h0,
    h1,
    h2,
    h3,
    h4,
    h5,
    h6,
    h7,
}

# Round constants
k_constants = [
    0x428a2f98,
    0x71374491,
    0xb5c0fbcf,
    0xe9b5dba5,
    0x3956c25b,
    0x59f111f1,
    0x923f82a4,
    0xab1c5ed5,
    0xd807aa98,
    0x12835b01,
    0x243185be,
    0x550c7dc3,
    0x72be5d74,
    0x80deb1fe,
    0x9bdc06a7,
    0xc19bf174,
    0xe49b69c1,
    0xefbe4786,
    0x0fc19dc6,
    0x240ca1cc,
    0x2de92c6f,
    0x4a7484aa,
    0x5cb0a9dc,
    0x76f988da,
    0x983e5152,
    0xa831c66d,
    0xb00327c8,
    0xbf597fc7,
    0xc6e00bf3,
    0xd5a79147,
    0x06ca6351,
    0x14292967,
    0x27b70a85,
    0x2e1b2138,
    0x4d2c6dfc,
    0x53380d13,
    0x650a7354,
    0x766a0abb,
    0x81c2c92e,
    0x92722c85,
    0xa2bfe8a1,
    0xa81a664b,
    0xc24b8b70,
    0xc76c51a3,
    0xd192e819,
    0xd6990624,
    0xf40e3585,
    0x106aa070,
    0x19a4c116,
    0x1e376c08,
    0x2748774c,
    0x34b0bcb5,
    0x391c0cb3,
    0x4ed8aa4a,
    0x5b9cca4f,
    0x682e6ff3,
    0x748f82ee,
    0x78a5636f,
    0x84c87814,
    0x8cc70208,
    0x90befffa,
    0xa4506ceb,
    0xbef9a3f7,
    0xc67178f2,
]

rotate_right_by : U32, U8 -> U32
rotate_right_by = \value, bits ->
    right = Num.shift_right_zf_by(value, bits)
    left = Num.shift_left_by(value, (32 - bits))
    Num.bitwise_or(left, right)

expect
    result = rotate_right_by(0xAABB, 8)
    result == 0xBB0000AA
expect
    result = rotate_right_by(0xAABB00CC, 4)
    result == 0xCAABB00C
expect
    result = rotate_right_by(0xAABB, 0)
    result == 0xAABB

bytes_to_word = \bytes ->
    (_, word) = List.walk(
        bytes,
        (32, 0),
        \(shift_by, result), b ->
            s = shift_by - 8
            (s, b |> Num.to_u32 |> Num.shift_left_by(s) |> Num.bitwise_or(result)),
    )
    word

expect
    result = bytes_to_word([0x80, 0x00, 0x00, 0x00])
    result == 0x80000000
expect
    result = bytes_to_word([0x00, 0xFF, 0x00, 0x80])
    result == 0x00FF0080

word_to_bytes = \word -> [
    Num.shift_right_zf_by(word, 24) |> Num.to_u8,
    Num.shift_right_zf_by(word, 16) |> Num.to_u8,
    Num.shift_right_zf_by(word, 8) |> Num.to_u8,
    word |> Num.to_u8,
]

pre_process : List U8 -> List U8
pre_process = \message ->
    big_endian64 = \i -> [
        Num.shift_right_zf_by(i, 56) |> Num.to_u8,
        Num.shift_right_zf_by(i, 48) |> Num.to_u8,
        Num.shift_right_zf_by(i, 40) |> Num.to_u8,
        Num.shift_right_zf_by(i, 32) |> Num.to_u8,
        Num.shift_right_zf_by(i, 24) |> Num.to_u8,
        Num.shift_right_zf_by(i, 16) |> Num.to_u8,
        Num.shift_right_zf_by(i, 8) |> Num.to_u8,
        i |> Num.to_u8,
    ]
    length = List.len(message)
    bit_length = length * 8
    remainder = (length + 1) % 64
    used = 64 - 8
    num_pad_bytes = if remainder > used then 64 + used - remainder else used - remainder
    padding = List.repeat(0, num_pad_bytes)
    length_bytes = big_endian64(bit_length)
    message |> List.append(0x80) |> List.concat(padding) |> List.concat(length_bytes)

unsafe_get = \array, i ->
    when List.get(array, i) is
        Ok(x) -> x
        Err(_) -> crash("Bug: array length not correct")

process = \padded_message ->
    chunks = List.chunks_of(padded_message, 64)
    process_chunk = \current_hash, chunk ->
        schedule_array =
            List.chunks_of(chunk, 4)
            |> List.walk(
                List.with_capacity(64),
                \state, word_bytes ->
                    word = bytes_to_word(word_bytes)
                    List.append(state, word),
            )
        filled =
            List.range({ start: At(16), end: Before(64) })
            |> List.walk(
                schedule_array,
                \state, i ->
                    s0 =
                        n = unsafe_get(state, (i - 15))
                        (rotate_right_by(n, 7)) |> Num.bitwise_xor(rotate_right_by(n, 18)) |> Num.bitwise_xor(Num.shift_right_zf_by(n, 3))
                    s1 =
                        n = unsafe_get(state, (i - 2))
                        (rotate_right_by(n, 17)) |> Num.bitwise_xor(rotate_right_by(n, 19)) |> Num.bitwise_xor(Num.shift_right_zf_by(n, 10))
                    w = unsafe_get(state, (i - 16)) |> Num.add_wrap(s0) |> Num.add_wrap(unsafe_get(state, (i - 7))) |> Num.add_wrap(s1)
                    List.append(state, w),
            )
        with_constants = List.map2(filled, k_constants, \w, k -> (w, k))
        new_hash = List.walk(
            with_constants,
            current_hash,
            \{ h0: a, h1: b, h2: c, h3: d, h4: e, h5: f, h6: g, h7: h }, (w, k) ->
                s1 = (rotate_right_by(e, 6)) |> Num.bitwise_xor(rotate_right_by(e, 11)) |> Num.bitwise_xor(rotate_right_by(e, 25))
                ch = Num.bitwise_xor(Num.bitwise_and(e, f), Num.bitwise_and(Num.bitwise_not(e), g))
                temp1 = h |> Num.add_wrap(s1) |> Num.add_wrap(ch) |> Num.add_wrap(k) |> Num.add_wrap(w)
                s0 = (rotate_right_by(a, 2)) |> Num.bitwise_xor(rotate_right_by(a, 13)) |> Num.bitwise_xor(rotate_right_by(a, 22))
                maj = (Num.bitwise_and(a, b)) |> Num.bitwise_xor(Num.bitwise_and(a, c)) |> Num.bitwise_xor(Num.bitwise_and(b, c))
                temp2 = Num.add_wrap(s0, maj)
                {
                    h0: Num.add_wrap(temp1, temp2),
                    h1: a,
                    h2: b,
                    h3: c,
                    h4: Num.add_wrap(d, temp1),
                    h5: e,
                    h6: f,
                    h7: g,
                },
        )
        {
            h0: Num.add_wrap(current_hash.h0, new_hash.h0),
            h1: Num.add_wrap(current_hash.h1, new_hash.h1),
            h2: Num.add_wrap(current_hash.h2, new_hash.h2),
            h3: Num.add_wrap(current_hash.h3, new_hash.h3),
            h4: Num.add_wrap(current_hash.h4, new_hash.h4),
            h5: Num.add_wrap(current_hash.h5, new_hash.h5),
            h6: Num.add_wrap(current_hash.h6, new_hash.h6),
            h7: Num.add_wrap(current_hash.h7, new_hash.h7),
        }
    hw = List.walk(chunks, init_hash, process_chunk)
    [hw.h0, hw.h1, hw.h2, hw.h3, hw.h4, hw.h5, hw.h6, hw.h7] |> List.join_map(word_to_bytes)

sha256 : List U8 -> List U8
sha256 = \message -> message |> pre_process |> process

expect
    result = sha256([])
    result == [0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55]

test_message = "my country is the world, and my religion is to do good"

expect
    result = Str.to_utf8(test_message) |> sha256
    result == [0x0f, 0xaa, 0x25, 0xc4, 0x85, 0x35, 0x46, 0xdf, 0x9f, 0xb7, 0xc1, 0x89, 0x2c, 0x1e, 0xd6, 0xf8, 0x24, 0x05, 0x3f, 0x3e, 0xf9, 0x0c, 0x89, 0x3e, 0x46, 0xfd, 0xdf, 0xab, 0x3f, 0xb9, 0xa3, 0x0b]

expect
    result = List.repeat(test_message, 10) |> Str.join_with("") |> Str.to_utf8 |> sha256
    result == [0x53, 0xa7, 0x0f, 0x5b, 0x13, 0xac, 0x17, 0x01, 0x67, 0x46, 0xcb, 0x83, 0x1b, 0x9d, 0xf4, 0x33, 0x40, 0xf8, 0x14, 0xd5, 0x70, 0x5d, 0xaa, 0xa7, 0xca, 0xb2, 0xe5, 0xef, 0xd1, 0xd5, 0xa6, 0xd0]
