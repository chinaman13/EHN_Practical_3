# ---- Imports  --------------------------------------------------------------------------------------------------------
import numpy as np
from PIL import Image
from bitarray.util import ba2hex, hex2ba, ba2int, int2ba
# ----------------------------------------------------------------------------------------------------------------------


# ---- RC4 Encryption  -------------------------------------------------------------------------------------------------
def RC4_Encrypt(plaintext, key):

    plainList = []
    for i in range(0, len(plaintext), 2):
        ch = hex2ba(plaintext[i] + plaintext[i+1])
        intCh = ba2int(ch)
        plainList.append(intCh)

    S = initS(key)
    cipherVals = coreFunction(S, plainList)
    cipherText = ""
    for i in range(len(cipherVals)):
        cipherText += chr(cipherVals[i])

    return cipherText


# ----------------------------------------------------------------------------------------------------------------------


# ---- RC4 Decryption  -------------------------------------------------------------------------------------------------
def RC4_Decrypt(ciphertext, key):

    # Text decryption
    if isinstance(ciphertext, str):

        cipherList = []
        for i in range(len(ciphertext)):
            cipherList.append(ord(ciphertext[i]))

        S = initS(key)
        plainVals = coreFunction(S, cipherList)
        plainText = ""
        for i in range(len(plainVals)):
            plainText += chr(plainVals[i])

        return plainText
    # Image decryption
    else:

        S = initS(key)
        imageHeight = len(ciphertext)
        imageWidth = len(ciphertext[0])

        R = []
        G = []
        B = []

        # Separate image into Red, Green and Blue layers
        for h in range(imageHeight):
            for w in range(imageWidth):
                R.append(int(ciphertext[h][w][0]))
                G.append(int(ciphertext[h][w][1]))
                B.append(int(ciphertext[h][w][2]))

        # Encrypt each image layer separately
        RedCipher = coreFunction(S, R)
        GreCipher = coreFunction(S, G)
        BluCipher = coreFunction(S, B)

        index = 0
        plainImage = np.zeros((imageHeight, imageWidth, 3))

        # Reconstruct encrypted values back into ndarray
        for h in range(imageHeight):
            for w in range(imageWidth):
                plainImage[h][w][0] = RedCipher[index]
                plainImage[h][w][1] = GreCipher[index]
                plainImage[h][w][2] = BluCipher[index]
                index += 1

        return plainImage

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


# ---- Testing ---------------------------------------------------------------------------------------------------------

"""
# Plain text
# key = "9876543210zyxwvutsrqponmlk" # Key 1
key = "0123456789abcdefghijklmnop" # Key 2
plain = "This test shows that different keys produce different ciphertexts!"

encryption = RC4_Encrypt(plain, key)
decryption = RC4_Decrypt(encryption, key)

length = len(encryption)
sum = 0
for i in range(length):
    if encryption[i] == decryption[i]:
        sum += 1
similarity = (sum/length) * 100

print()
print("___________________________________________________ RC4 ___________________________________________________\n")
print("Key       = ", key)
print("Plaintext = ", plain)
print()
print("Encrypted Ciphertext = ", encryption)
print("Decrypted Plaintext  = ", decryption)
print("Plaintext to Ciphertext similarity = " + str(similarity) + "%")
print("____________________________________________________________________________________________________________\n")
"""



"""
# Image Encryption
# key = "9876543210zyxwvutsrqponmlk" # Key 1
# key = "0123456789abcdefghijklmnop" # Key 2
key = " " # Key 3

image = Image.open("Images/OG.png")
imageArray = np.array(image)
image.show()

encrypt = RC4_Encrypt(imageArray, key)
encryptImage = Image.fromarray(np.uint8(encrypt)).convert('RGB')
encryptImage.save("RC4ImageEncryptKey3.jpg")
encryptImage.show()

decrypt = RC4_Decrypt(encrypt, key)
decryptImage = Image.fromarray(np.uint8(decrypt)).convert('RGB')
decryptImage.save("RC4ImageDecryptKey3.jpg")
decryptImage.show()
"""

