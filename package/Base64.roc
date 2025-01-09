module [encode, decode]

base64_index_table = [
    'A',
    'B',
    'C',
    'D',
    'E',
    'F',
    'G',
    'H',
    'I',
    'J',
    'K',
    'L',
    'M',
    'N',
    'O',
    'P',
    'Q',
    'R',
    'S',
    'T',
    'U',
    'V',
    'W',
    'X',
    'Y',
    'Z',
    'a',
    'b',
    'c',
    'd',
    'e',
    'f',
    'g',
    'h',
    'i',
    'j',
    'k',
    'l',
    'm',
    'n',
    'o',
    'p',
    'q',
    'r',
    's',
    't',
    'u',
    'v',
    'w',
    'x',
    'y',
    'z',
    '0',
    '1',
    '2',
    '3',
    '4',
    '5',
    '6',
    '7',
    '8',
    '9',
    '+',
    '/',
]

reverse_base64_index_map = base64_index_table |> List.map_with_index(\e, i -> (e, i)) |> Dict.from_list |> Dict.insert('=', 0)

## Encodes a list of bytes into a Base64 string.
encode : List U8 -> Str
encode = \bytes ->
    length = List.len(bytes)
    padding_count =
        when length % 3 is
            1 -> 2
            2 -> 1
            _ -> 0
    padded_input = List.concat(bytes, List.repeat(0, padding_count))
    encode_chunk = \state, chunk ->
        when chunk is
            [a, b, c] ->
                n =
                    Num.to_u32(a)
                    |> Num.shift_left_by(16)
                    |> Num.bitwise_or((Num.to_u32(b) |> Num.shift_left_by(8)))
                    |> Num.bitwise_or(Num.to_u32(c))
                six1 = Num.shift_right_zf_by(n, 18) |> Num.bitwise_and(0x3F)
                six2 = Num.shift_right_zf_by(n, 12) |> Num.bitwise_and(0x3F)
                six3 = Num.shift_right_zf_by(n, 6) |> Num.bitwise_and(0x3F)
                six4 = n |> Num.bitwise_and(0x3F)
                when List.map_try([six1, six2, six3, six4], \i -> List.get(base64_index_table, Num.to_u64(i))) is
                    Ok(l) -> List.concat(state, l)
                    Err(_) -> crash("bug in base64Encode")

            other -> crash("expected a list of 3 elements, but got $(List.len(other) |> Num.to_str) elements")

    out_padding = List.repeat('=', padding_count)
    out_length = (length + padding_count) // 3 * 4

    List.chunks_of(padded_input, 3)
    |> List.walk(List.with_capacity(out_length), encode_chunk)
    |> List.drop_last(padding_count)
    |> List.concat(out_padding)
    |> Str.from_utf8
    |> \r ->
        when r is
            Ok(v) -> v
            Err(_) -> crash("bug in base64Encode")

expect
    result = Str.to_utf8("Many hands make light work.") |> encode
    result == "TWFueSBoYW5kcyBtYWtlIGxpZ2h0IHdvcmsu"

expect
    result = Str.to_utf8("my country is the world, and my religion is to do good.") |> encode
    result == "bXkgY291bnRyeSBpcyB0aGUgd29ybGQsIGFuZCBteSByZWxpZ2lvbiBpcyB0byBkbyBnb29kLg=="

expect
    result = [] |> encode
    result == ""

expect
    result = [0] |> encode
    result == "AA=="

expect
    result = [0, 0, 0] |> encode
    result == "AAAA"

decode : Str -> Result (List U8) [InvalidBase64Char, InvalidBase64Length]
decode = \str ->
    chars = str |> Str.to_utf8
    length = List.len(chars)
    if length % 4 != 0 then
        Err(InvalidBase64Length)
    else
        out_length = length // 4 * 3
        chars
        |> List.chunks_of(4)
        |> List.walk_try(
            List.with_capacity(out_length),
            \state, chunk4 ->
                padding_count = List.count_if(chunk4, \c -> c == '=')
                chunk4
                |> List.map_try(\c -> Dict.get(reverse_base64_index_map, c))
                |> Result.map(
                    \l ->
                        when l is
                            [six1, six2, six3, six4] ->
                                shifted1 = Num.shift_left_by(six1, 18)
                                shifted2 = Num.shift_left_by(six2, 12)
                                shifted3 = Num.shift_left_by(six3, 6)
                                shifted4 = six4
                                combined = shifted1 |> Num.bitwise_or(shifted2) |> Num.bitwise_or(shifted3) |> Num.bitwise_or(shifted4)
                                bytes =
                                    [
                                        Num.shift_right_zf_by(combined, 16) |> Num.to_u8,
                                        Num.shift_right_zf_by(combined, 8) |> Num.to_u8,
                                        combined |> Num.to_u8,
                                    ]
                                    |> List.drop_last(padding_count)
                                state |> List.concat(bytes)

                            _ -> crash("bug in base64Decode: should have already checked the length was a multiple of 4"),
                ),
        )
        |> Result.map_err(\_ -> InvalidBase64Char)

expect
    result = decode("TWFueSBoYW5kcyBtYWtlIGxpZ2h0IHdvcmsu")
    result == Ok(Str.to_utf8("Many hands make light work."))

expect
    result = decode("bXkgY291bnRyeSBpcyB0aGUgd29ybGQsIGFuZCBteSByZWxpZ2lvbiBpcyB0byBkbyBnb29kLg==")
    result == Ok(Str.to_utf8("my country is the world, and my religion is to do good."))

expect
    result = decode("")
    result == Ok([])

expect
    result = decode("AA==")
    result == Ok([0])

expect
    result = decode("AAAA")
    result == Ok([0, 0, 0])
