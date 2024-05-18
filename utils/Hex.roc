module [toHexString, fromHexString]

hexChars = ["0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "a", "b", "c", "d", "e", "f"]

byteToHex : U8 -> Str
byteToHex = \byte ->
    hi = Num.shiftRightZfBy byte 4
    lo = Num.bitwiseAnd byte 0xF
    result =
        hexChars
        |> List.get (Num.toU64 hi)
        |> Result.try \h ->
            List.get hexChars (Num.toU64 lo) |> Result.map \l -> Str.concat h l
    when result is
        Ok hex -> hex
        Err _ -> crash "Bug in byteToHex!"

expect
    result = byteToHex 0x00
    result == "00"
expect
    result = byteToHex 0xFF
    result == "ff"
expect
    result = byteToHex 0xC5
    result == "c5"

## Converts a list of bytes to the equivalent hex string.
toHexString : List U8 -> Str
toHexString = \bytes -> bytes |> List.map byteToHex |> Str.joinWith ""

expect
    result = toHexString [0x00, 0xFF, 0xC5]
    result == "00ffc5"

hexToNibble : U8 -> Result U8 [InvalidHexChar]
hexToNibble = \char ->
    when char is
        x if x >= '0' && x <= '9' -> x - '0' |> Ok
        x if x >= 'a' && x <= 'f' -> x - 'a' + 10 |> Ok
        x if x >= 'A' && x <= 'F' -> x - 'A' + 10 |> Ok
        _ -> Err InvalidHexChar

expect
    result = hexToNibble '0'
    result == Ok 0

expect
    result = hexToNibble '9'
    result == Ok 9

expect
    result = hexToNibble 'd'
    result == Ok 13

expect
    result = hexToNibble 'D'
    result == Ok 13

expect
    result = hexToNibble 'x'
    result == Err InvalidHexChar

expect
    result = hexToNibble 0
    result == Err InvalidHexChar

hexToByte : { lo : U8, hi : U8 } -> Result U8 [InvalidHexChar]
hexToByte = \{ lo, hi } ->
    hexToNibble hi
    |> Result.map \v -> Num.shiftLeftBy v 4
    |> Result.try \hi2 -> hexToNibble lo
        |> Result.map \lo2 -> Num.bitwiseOr hi2 lo2

expect
    result = hexToByte { lo: '0', hi: '0' }
    result == Ok 0

expect
    result = hexToByte { lo: '5', hi: 'c' }
    result == Ok 0xC5

expect
    result = hexToByte { lo: 'E', hi: 'd' }
    result == Ok 0xDE

expect
    result = hexToByte { lo: 'x', hi: '0' }
    result == Err InvalidHexChar

## Converts a string of hex characters to the equivalent list of bytes.
fromHexString : Str -> Result (List U8) [InvalidHexChar, InvalidHexLength]
fromHexString = \hex ->
    Str.toUtf8 hex
    |> List.chunksOf 2
    |> List.mapTry \chunk ->
        when chunk is
            [hi, lo] -> hexToByte { lo, hi }
            _ -> Err InvalidHexLength

expect
    result = fromHexString "00ffc520De"
    result == Ok [0x00, 0xFF, 0xC5, 0x20, 0xDE]

expect
    result = fromHexString "00ffc520D"
    result == Err InvalidHexLength

expect
    result = fromHexString "00ffc520Dx"
    result == Err InvalidHexChar
