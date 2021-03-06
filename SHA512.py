# IMPORTS ------------------------------------------------------------------------------------------
import numpy as np
from PIL import Image
from bitarray import bitarray
from bitarray.util import ba2int, hex2ba, ba2hex, int2ba

# CONSTANTS ---------------------------------------------------------------------------------------
K = [hex2ba("428a2f98d728ae22"), hex2ba("7137449123ef65cd"), hex2ba("b5c0fbcfec4d3b2f"), hex2ba("e9b5dba58189dbbc"),
     hex2ba("3956c25bf348b538"), hex2ba("59f111f1b605d019"), hex2ba("923f82a4af194f9b"), hex2ba("ab1c5ed5da6d8118"),
     hex2ba("d807aa98a3030242"), hex2ba("12835b0145706fbe"), hex2ba("243185be4ee4b28c"), hex2ba("550c7dc3d5ffb4e2"),
     hex2ba("72be5d74f27b896f"), hex2ba("80deb1fe3b1696b1"), hex2ba("9bdc06a725c71235"), hex2ba("c19bf174cf692694"),
     hex2ba("e49b69c19ef14ad2"), hex2ba("efbe4786384f25e3"), hex2ba("0fc19dc68b8cd5b5"), hex2ba("240ca1cc77ac9c65"),
     hex2ba("2de92c6f592b0275"), hex2ba("4a7484aa6ea6e483"), hex2ba("5cb0a9dcbd41fbd4"), hex2ba("76f988da831153b5"),
     hex2ba("983e5152ee66dfab"), hex2ba("a831c66d2db43210"), hex2ba("b00327c898fb213f"), hex2ba("bf597fc7beef0ee4"),
     hex2ba("c6e00bf33da88fc2"), hex2ba("d5a79147930aa725"), hex2ba("06ca6351e003826f"), hex2ba("142929670a0e6e70"),
     hex2ba("27b70a8546d22ffc"), hex2ba("2e1b21385c26c926"), hex2ba("4d2c6dfc5ac42aed"), hex2ba("53380d139d95b3df"),
     hex2ba("650a73548baf63de"), hex2ba("766a0abb3c77b2a8"), hex2ba("81c2c92e47edaee6"), hex2ba("92722c851482353b"),
     hex2ba("a2bfe8a14cf10364"), hex2ba("a81a664bbc423001"), hex2ba("c24b8b70d0f89791"), hex2ba("c76c51a30654be30"),
     hex2ba("d192e819d6ef5218"), hex2ba("d69906245565a910"), hex2ba("f40e35855771202a"), hex2ba("106aa07032bbd1b8"),
     hex2ba("19a4c116b8d2d0c8"), hex2ba("1e376c085141ab53"), hex2ba("2748774cdf8eeb99"), hex2ba("34b0bcb5e19b48a8"),
     hex2ba("391c0cb3c5c95a63"), hex2ba("4ed8aa4ae3418acb"), hex2ba("5b9cca4f7763e373"), hex2ba("682e6ff3d6b2b8a3"),
     hex2ba("748f82ee5defb2fc"), hex2ba("78a5636f43172f60"), hex2ba("84c87814a1f0ab72"), hex2ba("8cc702081a6439ec"),
     hex2ba("90befffa23631e28"), hex2ba("a4506cebde82bde9"), hex2ba("bef9a3f7b2c67915"), hex2ba("c67178f2e372532b"),
     hex2ba("ca273eceea26619c"), hex2ba("d186b8c721c0c207"), hex2ba("eada7dd6cde0eb1e"), hex2ba("f57d4f7fee6ed178"),
     hex2ba("06f067aa72176fba"), hex2ba("0a637dc5a2c898a6"), hex2ba("113f9804bef90dae"), hex2ba("1b710b35131c471b"),
     hex2ba("28db77f523047d84"), hex2ba("32caab7b40c72493"), hex2ba("3c9ebe0a15c9bebc"), hex2ba("431d67c49c100d4c"),
     hex2ba("4cc5d4becb3e42b6"), hex2ba("597f299cfc657e2a"), hex2ba("5fcb6fab3ad6faec"), hex2ba("6c44198c4a475817")]


# SHA-512 Hashing Function -------------------------------------------------------------------------
def sha512_hash(data, type):

    global K
    h0 = hex2ba("6a09e667f3bcc908")
    h1 = hex2ba("bb67ae8584caa73b")
    h2 = hex2ba("3c6ef372fe94f82b")
    h3 = hex2ba("a54ff53a5f1d36f1")
    h4 = hex2ba("510e527fade682d1")
    h5 = hex2ba("9b05688c2b3e6c1f")
    h6 = hex2ba("1f83d9abfb41bd6b")
    h7 = hex2ba("5be0cd19137e2179")

    # Pad message and separate into blocks
    if type == "text" or type == "textfile" or type == "image":
        msg_blocks = sha512_padding(data, type)
        len_blocks = len(msg_blocks)
    else:
        print("Error in data type.")
        return "Error"

    for i in range(len_blocks):

        # Prepare message schedule
        w_t = []
        for t in range(16):
            w_t.append(msg_blocks[i][t*64:(t+1)*64:1])

        for t in range(16, 80):
            w_t_value = (ba2int(sigma_1(w_t[t-2])) + ba2int(w_t[t-7]) + ba2int(sigma_0(w_t[t-15])) + ba2int(w_t[t-16])) % (2**64)
            w_t.append(int2ba(w_t_value, 64))

        # Initialise working variables
        a = h0
        b = h1
        c = h2
        d = h3
        e = h4
        f = h5
        g = h6
        h = h7

        # Perform calculations
        for t in range(80):
            s1 = ba2int(sum_1(e))
            ch1 = ba2int(ch(e, f, g))
            t1_int = (ba2int(h) + s1 + ch1 + ba2int(K[t]) + ba2int(w_t[t])) % (2**64)

            s0 = ba2int(sum_0(a))
            mj = ba2int(maj(a, b, c))
            t2_int = (s0 + mj) % (2**64)

            h = g
            g = f
            f = e
            e = int2ba((ba2int(d) + t1_int) % (2**64), 64)
            d = c
            c = b
            b = a
            a = int2ba((t1_int + t2_int) % (2**64), 64)

        # Compute intermediate hash value
        h0 = int2ba((ba2int(a) + ba2int(h0)) % (2 ** 64), 64)
        h1 = int2ba((ba2int(b) + ba2int(h1)) % (2 ** 64), 64)
        h2 = int2ba((ba2int(c) + ba2int(h2)) % (2 ** 64), 64)
        h3 = int2ba((ba2int(d) + ba2int(h3)) % (2 ** 64), 64)
        h4 = int2ba((ba2int(e) + ba2int(h4)) % (2 ** 64), 64)
        h5 = int2ba((ba2int(f) + ba2int(h5)) % (2 ** 64), 64)
        h6 = int2ba((ba2int(g) + ba2int(h6)) % (2 ** 64), 64)
        h7 = int2ba((ba2int(h) + ba2int(h7)) % (2 ** 64), 64)

    # Compute final digest
    digest = h0 + h1 + h2 + h3 + h4 + h5 + h6 + h7
    return ba2hex(digest)


# SHA-512 Preprocessing (Padding) -----------------------------------------------------------------
def sha512_padding(message, type):

    if type == "text" or type == "textfile":
        # Convert message to bits
        bits = bitarray()
        byte = bytes(message, 'utf-8')
        bits.frombytes(byte)
    elif type == "image":
        # Image dimensions
        imageHeight = len(message)
        imageWidth = len(message[0])
        # Convert image to bits
        bits = bitarray()
        for i in range(imageHeight):
            for j in range(imageWidth):
                for k in range(3):
                    bits += int2ba(int(message[i][j][k]))

    # Length of bits
    l = len(bits)
    # Calculate k zero bits
    k = ((896 % 1024) - l - 1) % 1024

    # Append padding bits
    bits.append(1)
    for i in range(k):
        bits.append(0)

    l_bits = int2ba(l, 128)
    bits.extend(l_bits)

    # Separate into blocks of 1024 bits
    blocks = []
    num_blocks = int(len(bits) / 1024)
    for i in range(num_blocks):
        blocks.append(bits[i*1024:(i+1)*1024:1])

    return blocks


# HELPER FUNCTIONS -------------------------------------------------------------------------------
# Perform right shift of n bits
def right_shift(word, num):

    shifted = word >> num
    return shifted


# Perform circular right shift of n bits
def circ_right_shift(word, num):

    shifted = word
    for i in range(num):
        temp = shifted[-1]
        shifted = shifted >> 1
        shifted[0] = temp

    return shifted


# Calculate value of sigma 0 function
def sigma_0(word):

    rotr_1 = circ_right_shift(word, 1)
    rotr_8 = circ_right_shift(word, 8)
    shr_7  = right_shift(word, 7)

    sig_value = rotr_1 ^ rotr_8 ^ shr_7
    return sig_value


# Calculate value of sigma 1 function
def sigma_1(word):
    rotr_19 = circ_right_shift(word, 19)
    rotr_61 = circ_right_shift(word, 61)
    shr_6   = right_shift(word, 6)

    sig_value = rotr_19 ^ rotr_61 ^ shr_6
    return sig_value


# Calculate value of sum 0 function
def sum_0(word):

    rotr_28 = circ_right_shift(word, 28)
    rotr_34 = circ_right_shift(word, 34)
    rotr_39 = circ_right_shift(word, 39)

    sig_value = rotr_28 ^ rotr_34 ^ rotr_39
    return sig_value


# Calculate value of sum 1 function
def sum_1(word):

    rotr_14 = circ_right_shift(word, 14)
    rotr_18 = circ_right_shift(word, 18)
    rotr_41 = circ_right_shift(word, 41)

    sig_value = rotr_14 ^ rotr_18 ^ rotr_41
    return sig_value


# Ch function calculation
def ch(x, y, z):
    value = (x & y) ^ (~x & z)
    return value


# Maj function calculation
def maj(x, y, z):
    value = (x & y) ^ (x & z) ^ (y & z)
    return value


