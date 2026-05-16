# SHA-256 constants
K = [
    0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5,
    0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
    0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3,
    0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
    0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC,
    0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
    0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7,
    0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
    0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13,
    0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
    0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3,
    0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
    0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5,
    0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
    0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208,
    0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2,
]

# SHA-256 init hash vals
INITIAL_HASHES = [
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
    0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
]


def _right_rotate(value: int, shift: int) -> int:
    # 32bit int rotation by bit shift
    return ((value >> shift) | (value << (32 - shift))) & 0xFFFFFFFF


def _pad_message(message: bytes) -> bytes:
    # message padding, final length must be multiple of 512bits
    original_bit_length = len(message) * 8

    # single '1' bit append, as 0x80
    padded = message + b"\x80"

    # appending zeros until length is 448 mod 512bits
    while (len(padded) % 64) != 56:
        padded += b"\x00"

    # appending original length as 64bit big-endian int
    padded += original_bit_length.to_bytes(8, byteorder="big")

    return padded


def sha256(data: bytes) -> bytes:
    # prep padded msg
    padded_data = _pad_message(data)

    # init working hash values
    h = INITIAL_HASHES.copy()

    # msg processing in chunks
    for chunk_start in range(0, len(padded_data), 64):
        chunk = padded_data[chunk_start:chunk_start + 64]

        w = [0] * 64

        for i in range(16):
            word_start = i * 4
            w[i] = int.from_bytes(chunk[word_start:word_start + 4], byteorder="big")

        for i in range(16, 64):
            s0 = (
                _right_rotate(w[i - 15], 7) ^
                _right_rotate(w[i - 15], 18) ^
                (w[i - 15] >> 3)
            )
            s1 = (
                _right_rotate(w[i - 2], 17) ^
                _right_rotate(w[i - 2], 19) ^
                (w[i - 2] >> 10)
            )
            w[i] = (w[i - 16] + s0 + w[i - 7] + s1) & 0xFFFFFFFF

        a, b, c, d, e, f, g, hh = h

        # compression loop
        for i in range(64):
            sum1 = (
                _right_rotate(e, 6) ^
                _right_rotate(e, 11) ^
                _right_rotate(e, 25)
            )
            ch = (e & f) ^ ((~e) & g)
            temp1 = (hh + sum1 + ch + K[i] + w[i]) & 0xFFFFFFFF

            sum0 = (
                _right_rotate(a, 2) ^
                _right_rotate(a, 13) ^
                _right_rotate(a, 22)
            )
            maj = (a & b) ^ (a & c) ^ (b & c)
            temp2 = (sum0 + maj) & 0xFFFFFFFF

            hh = g
            g = f
            f = e
            e = (d + temp1) & 0xFFFFFFFF
            d = c
            c = b
            b = a
            a = (temp1 + temp2) & 0xFFFFFFFF

        # adding compressed chunk to curr hash val
        h[0] = (h[0] + a) & 0xFFFFFFFF
        h[1] = (h[1] + b) & 0xFFFFFFFF
        h[2] = (h[2] + c) & 0xFFFFFFFF
        h[3] = (h[3] + d) & 0xFFFFFFFF
        h[4] = (h[4] + e) & 0xFFFFFFFF
        h[5] = (h[5] + f) & 0xFFFFFFFF
        h[6] = (h[6] + g) & 0xFFFFFFFF
        h[7] = (h[7] + hh) & 0xFFFFFFFF

    return b"".join(value.to_bytes(4, byteorder="big") for value in h)


def sha256_hex(data: bytes) -> str:
    return sha256(data).hex()


def hash_message(message: str) -> int:
    digest = sha256(message.encode("utf-8"))
    return int.from_bytes(digest, byteorder="big")


# old hashing solution left in file to be removed later
'''
import hashlib



def hash_message(message: str) -> int:
    message_bytes = message.encode("utf-8")
    digest = hashlib.sha256(message_bytes).digest()
    return int.from_bytes(digest, byteorder="big")
'''
