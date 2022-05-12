# ---- Imports  --------------------------------------------------------------------------------------------------------
import numpy as np
from PIL import Image
from bitarray.util import ba2hex, hex2ba, ba2int, int2ba
# ----------------------------------------------------------------------------------------------------------------------


# ---- RC4 Encryption  -------------------------------------------------------------------------------------------------
def RC4_Encrypt(plaintext, key):

    index = 0
    key_index = 0
    new_key = ""
    while index < 256:
        if key_index == len(key) - 1:
            key_index = 0
        else:
            key_index += 1
        new_key += key[key_index]
        index += 1

    plainList = []
    for i in range(0, len(plaintext), 2):
        ch = hex2ba(plaintext[i] + plaintext[i+1])
        intCh = ba2int(ch)
        plainList.append(intCh)

    S = initS(new_key)
    cipherVals = coreFunction(S, plainList)
    cipherText = ""
    for i in range(len(cipherVals)):
        cipherText += chr(cipherVals[i])

    return cipherText


# ----------------------------------------------------------------------------------------------------------------------


# ---- Helper Functions ------------------------------------------------------------------------------------------------
def coreFunction(S, byteStream):

    returnList = []

    i = 0
    j = 0

    # Stream generation
    for x in range(len(byteStream)):
        i = (i + 1) % 256
        j = (j + S[i]) % 256

        # Swap S at i and j
        temp = S[i]
        S[i] = S[j]
        S[j] = temp

        t = (S[i] + S[j]) % 256
        k = S[t]

        valByte = int2ba(byteStream[x], 8)
        valK = int2ba(k, 8)
        XOR = valByte ^ valK

        returnList.append(ba2int(XOR))

    return returnList


# Initialisation of S table
def initS(key):

    # Initialisation
    S = []
    T = []
    for i in range(256):
        S.append(i)
        T.append(ord(key[i % len(key)]))

    # Initial permutation
    j = 0
    for i in range(256):
        j = (j + S[i] + T[i]) % 256
        temp = S[i]
        S[i] = S[j]
        S[j] = temp

    return S


# ----------------------------------------------------------------------------------------------------------------------


