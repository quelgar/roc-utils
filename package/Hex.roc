module [to_hex_string, from_hex_string]

hex_chars = ["0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "a", "b", "c", "d", "e", "f"]

byte_to_hex : U8 -> Str
byte_to_hex = \byte ->
    hi = Num.shift_right_zf_by(byte, 4)
    lo = Num.bitwise_and(byte, 0xF)
    result =
        hex_chars
        |> List.get(Num.to_u64(hi))
        |> Result.try(
            \h ->
                List.get(hex_chars, Num.to_u64(lo)) |> Result.map(\l -> Str.concat(h, l)),
        )
    when result is
        Ok(hex) -> hex
        Err(_) -> crash("Bug in byteToHex!")

expect
    result = byte_to_hex(0x00)
    result == "00"
expect
    result = byte_to_hex(0xFF)
    result == "ff"
expect
    result = byte_to_hex(0xC5)
    result == "c5"

## Converts a list of bytes to the equivalent hex string.
to_hex_string : List U8 -> Str
to_hex_string = \bytes -> bytes |> List.map(byte_to_hex) |> Str.join_with("")

expect
    result = to_hex_string([0x00, 0xFF, 0xC5])
    result == "00ffc5"

hex_to_nibble : U8 -> Result U8 [InvalidHexChar]
hex_to_nibble = \char ->
    when char is
        x if x >= '0' && x <= '9' -> x - '0' |> Ok
        x if x >= 'a' && x <= 'f' -> x - 'a' + 10 |> Ok
        x if x >= 'A' && x <= 'F' -> x - 'A' + 10 |> Ok
        _ -> Err(InvalidHexChar)

expect
    result = hex_to_nibble('0')
    result == Ok(0)

expect
    result = hex_to_nibble('9')
    result == Ok(9)

expect
    result = hex_to_nibble('d')
    result == Ok(13)

expect
    result = hex_to_nibble('D')
    result == Ok(13)

expect
    result = hex_to_nibble('x')
    result == Err(InvalidHexChar)

expect
    result = hex_to_nibble(0)
    result == Err(InvalidHexChar)

hex_to_byte : { lo : U8, hi : U8 } -> Result U8 [InvalidHexChar]
hex_to_byte = \{ lo, hi } ->
    hex_to_nibble(hi)
    |> Result.map(\v -> Num.shift_left_by(v, 4))
    |> Result.try(
        \hi2 ->
            hex_to_nibble(lo)
            |> Result.map(\lo2 -> Num.bitwise_or(hi2, lo2)),
    )

expect
    result = hex_to_byte({ lo: '0', hi: '0' })
    result == Ok(0)

expect
    result = hex_to_byte({ lo: '5', hi: 'c' })
    result == Ok(0xC5)

expect
    result = hex_to_byte({ lo: 'E', hi: 'd' })
    result == Ok(0xDE)

expect
    result = hex_to_byte({ lo: 'x', hi: '0' })
    result == Err(InvalidHexChar)

## Converts a string of hex characters to the equivalent list of bytes.
from_hex_string : Str -> Result (List U8) [InvalidHexChar, InvalidHexLength]
from_hex_string = \hex ->
    Str.to_utf8(hex)
    |> List.chunks_of(2)
    |> List.map_try(
        \chunk ->
            when chunk is
                [hi, lo] -> hex_to_byte({ lo, hi })
                _ -> Err(InvalidHexLength),
    )

expect
    result = from_hex_string("00ffc520De")
    result == Ok([0x00, 0xFF, 0xC5, 0x20, 0xDE])

expect
    result = from_hex_string("00ffc520D")
    result == Err(InvalidHexLength)

expect
    result = from_hex_string("00ffc520Dx")
    result == Err(InvalidHexChar)
