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

initHash = {
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
kConstants = [
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

rotateRightBy : U32, U8 -> U32
rotateRightBy = \value, bits ->
    right = Num.shiftRightZfBy value bits
    left = Num.shiftLeftBy value (32 - bits)
    Num.bitwiseOr left right

expect
    result = rotateRightBy 0xAABB 8
    result == 0xBB0000AA
expect
    result = rotateRightBy 0xAABB00CC 4
    result == 0xCAABB00C
expect
    result = rotateRightBy 0xAABB 0
    result == 0xAABB

bytesToWord = \bytes ->
    (_, word) = List.walk bytes (32, 0) \(shiftBy, result), b ->
        s = shiftBy - 8
        (s, b |> Num.toU32 |> Num.shiftLeftBy s |> Num.bitwiseOr result)
    word

expect
    result = bytesToWord [0x80, 0x00, 0x00, 0x00]
    result == 0x80000000
expect
    result = bytesToWord [0x00, 0xFF, 0x00, 0x80]
    result == 0x00FF0080

wordToBytes = \word -> [
    Num.shiftRightZfBy word 24 |> Num.toU8,
    Num.shiftRightZfBy word 16 |> Num.toU8,
    Num.shiftRightZfBy word 8 |> Num.toU8,
    word |> Num.toU8,
]

preProcess : List U8 -> List U8
preProcess = \message ->
    bigEndian64 = \i -> [
        Num.shiftRightZfBy i 56 |> Num.toU8,
        Num.shiftRightZfBy i 48 |> Num.toU8,
        Num.shiftRightZfBy i 40 |> Num.toU8,
        Num.shiftRightZfBy i 32 |> Num.toU8,
        Num.shiftRightZfBy i 24 |> Num.toU8,
        Num.shiftRightZfBy i 16 |> Num.toU8,
        Num.shiftRightZfBy i 8 |> Num.toU8,
        i |> Num.toU8,
    ]
    length = List.len message
    bitLength = length * 8
    remainder = (length + 1) % 64
    used = 64 - 8
    numPadBytes = if remainder > used then 64 + used - remainder else used - remainder
    padding = List.repeat 0 numPadBytes
    lengthBytes = bigEndian64 bitLength
    message |> List.append 0x80 |> List.concat padding |> List.concat lengthBytes

unsafeGet = \array, i ->
    when List.get array i is
        Ok x -> x
        Err _ -> crash "Bug: array length not correct"

process = \paddedMessage ->
    chunks = List.chunksOf paddedMessage 64
    processChunk = \currentHash, chunk ->
        scheduleArray =
            List.chunksOf chunk 4
            |> List.walk (List.withCapacity 64) \state, wordBytes ->
                word = bytesToWord wordBytes
                List.append state word
        filled =
            List.range { start: At 16, end: Before 64 }
            |> List.walk scheduleArray \state, i ->
                s0 =
                    n = unsafeGet state (i - 15)
                    (rotateRightBy n 7) |> Num.bitwiseXor (rotateRightBy n 18) |> Num.bitwiseXor (Num.shiftRightZfBy n 3)
                s1 =
                    n = unsafeGet state (i - 2)
                    (rotateRightBy n 17) |> Num.bitwiseXor (rotateRightBy n 19) |> Num.bitwiseXor (Num.shiftRightZfBy n 10)
                w = unsafeGet state (i - 16) |> Num.addWrap s0 |> Num.addWrap (unsafeGet state (i - 7)) |> Num.addWrap s1
                List.append state w
        withConstants = List.map2 filled kConstants \w, k -> (w, k)
        newHash = List.walk withConstants currentHash \{ h0: a, h1: b, h2: c, h3: d, h4: e, h5: f, h6: g, h7: h }, (w, k) ->
            s1 = (rotateRightBy e 6) |> Num.bitwiseXor (rotateRightBy e 11) |> Num.bitwiseXor (rotateRightBy e 25)
            ch = Num.bitwiseXor (Num.bitwiseAnd e f) (Num.bitwiseAnd (Num.bitwiseNot e) g)
            temp1 = h |> Num.addWrap s1 |> Num.addWrap ch |> Num.addWrap k |> Num.addWrap w
            s0 = (rotateRightBy a 2) |> Num.bitwiseXor (rotateRightBy a 13) |> Num.bitwiseXor (rotateRightBy a 22)
            maj = (Num.bitwiseAnd a b) |> Num.bitwiseXor (Num.bitwiseAnd a c) |> Num.bitwiseXor (Num.bitwiseAnd b c)
            temp2 = Num.addWrap s0 maj
            {
                h0: Num.addWrap temp1 temp2,
                h1: a,
                h2: b,
                h3: c,
                h4: Num.addWrap d temp1,
                h5: e,
                h6: f,
                h7: g,
            }
        {
            h0: Num.addWrap currentHash.h0 newHash.h0,
            h1: Num.addWrap currentHash.h1 newHash.h1,
            h2: Num.addWrap currentHash.h2 newHash.h2,
            h3: Num.addWrap currentHash.h3 newHash.h3,
            h4: Num.addWrap currentHash.h4 newHash.h4,
            h5: Num.addWrap currentHash.h5 newHash.h5,
            h6: Num.addWrap currentHash.h6 newHash.h6,
            h7: Num.addWrap currentHash.h7 newHash.h7,
        }
    hw = List.walk chunks initHash processChunk
    [hw.h0, hw.h1, hw.h2, hw.h3, hw.h4, hw.h5, hw.h6, hw.h7] |> List.joinMap wordToBytes

sha256 : List U8 -> List U8
sha256 = \message -> message |> preProcess |> process

expect
    result = sha256 []
    result == [0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55]

testMessage = "my country is the world, and my religion is to do good"

expect
    result = Str.toUtf8 testMessage |> sha256
    result == [0x0f, 0xaa, 0x25, 0xc4, 0x85, 0x35, 0x46, 0xdf, 0x9f, 0xb7, 0xc1, 0x89, 0x2c, 0x1e, 0xd6, 0xf8, 0x24, 0x05, 0x3f, 0x3e, 0xf9, 0x0c, 0x89, 0x3e, 0x46, 0xfd, 0xdf, 0xab, 0x3f, 0xb9, 0xa3, 0x0b]

expect
    result = List.repeat testMessage 10 |> Str.joinWith "" |> Str.toUtf8 |> sha256
    result == [0x53, 0xa7, 0x0f, 0x5b, 0x13, 0xac, 0x17, 0x01, 0x67, 0x46, 0xcb, 0x83, 0x1b, 0x9d, 0xf4, 0x33, 0x40, 0xf8, 0x14, 0xd5, 0x70, 0x5d, 0xaa, 0xa7, 0xca, 0xb2, 0xe5, 0xef, 0xd1, 0xd5, 0xa6, 0xd0]
