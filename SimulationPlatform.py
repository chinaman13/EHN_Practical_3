import SHA512
import RC4
import RSA
from PIL import Image
import numpy as np
from bitarray.util import int2ba, ba2hex
import bitarray

imageHeight = 0
imageWidth = 0


class Transmitter:

    def __init__(self):
        self.encryptedKey = []
        self.hash = ""
        self.fullDigest = ""
        self.ciphertext = ""
        self.ciphertextHex = ""

    def get_RSA_pub_key(self, pubKey):
        self.encryptedKey = RSA.EncryptUsingPublicKey(pubKey)

    def generate_hash(self, message, type):
        self.hash = SHA512.sha512_hash(message, type)
        print("TRANSMITTER Plaintext Hash:")
        print(self.hash.upper())

    def concatenate_digest(self, data, type, height, width):
        digest = ""
        if type == "text" or type == "textfile":
            for i in range(len(data)):
                baVal = int2ba(ord(data[i]), 8)
                hexVal = ba2hex(baVal)
                digest += hexVal
            digest += self.hash
        else:
            for i in range(height):
                for j in range(width):
                    for k in range(3):
                        baVal = int2ba(int(data[i][j][k]), 8)
                        hexVal = ba2hex(baVal)
                        digest += hexVal
            digest += self.hash

        self.fullDigest = digest

    def encrypt_digest(self):
        print("TRANSMITTER RC4 Encrypted Ciphertext:")
        self.ciphertext = RC4.RC4_Encrypt(self.fullDigest, RSA.plaintexKey)

        for i in range(len(self.ciphertext)):
            baVal = int2ba(ord(self.ciphertext[i]), 8)
            hexVal = ba2hex(baVal)
            self.ciphertextHex += hexVal

        print(self.ciphertextHex)


    def send_digest(self):
        print("Encrypted digest sent")


class Receiver:

    def __init__(self):
        self.publicKey = []
        self.privateKey = []
        self.encryptRC4Key = []
        self.decryptRC4Key = ""
        self.cipherText = ""
        self.plainText = ""
        self.plainTextSlice = ""
        self.imageArray = np.empty((0))
        self.receivedHash = ""
        self.hashCheck = ""

    def send_RSA_pub_key(self):
        keys = RSA.ReciverAutoGeneratePrdouceKeys()
        self.publicKey = keys[0]
        self.privateKey = keys[1]

    def get_RC4_key(self, key):
        self.encryptRC4Key = key
        self.decryptRC4Key = RSA.DecryptUsingPrivateKey(key, self.privateKey)

    def get_ciphertext(self, ciphertext):
        self.cipherText = ciphertext

    def decrypt_data_stream(self, type, height, width):
        self.plainText = RC4.RC4_Encrypt(self.cipherText, self.decryptRC4Key)
        start = len(self.plainText) - 64
        end = len(self.plainText)

        if type == "text" or type == "textfile":
            for i in range(0, start):
                self.plainTextSlice += self.plainText[i]
        else:
            index = 0
            self.imageArray = np.zeros((height, width, 3))
            for i in range(height):
                for j in range(width):
                    for k in range(3):
                        self.imageArray[i][j][k] = ord(self.plainText[index])
                        index += 1

        for i in range(start, end):
            baVal = int2ba(ord(self.plainText[i]), 8)
            hexval = ba2hex(baVal)
            self.receivedHash += hexval

        print("RECEIVER Decrypted message received:")
        if type == "text" or type == "textfile":
            print(self.plainTextSlice)
        else:
            print(self.imageArray)

        print("RECEIVER Expected Hash:")
        print(self.receivedHash)

    def generate_hash(self, type):
        if type == "text" or type == "textfile":
            self.hashCheck = SHA512.sha512_hash(self.plainTextSlice, type)
        else:
            self.hashCheck = SHA512.sha512_hash(self.imageArray, type)

        print("RECEIVER Received Hash:")
        print(self.hashCheck.upper())

    def message_auth(self):
        if self.hashCheck == self.receivedHash:
            print("Message Authenticated.")
        else:
            print("Message Authentication Failed.")


def SimulationSystem():

    global imageHeight, imageWidth

    rec = Receiver()
    tra = Transmitter()

    # Phase 1 = Key distribution
    # Receiver sends RSA public key to transmitter
    rec.send_RSA_pub_key()
    tra.get_RSA_pub_key(rec.publicKey)
    rec.get_RC4_key(tra.encryptedKey)

    # Phase 2 = Data signing and encryption
    print("Phase 2")
    message = input("TRANSMITTER Please Enter a message: ")
    print()

    if message.__contains__(".txt"):
        type = "textfile"
        print("TRANSMITTER Loading message from file \'" + message + "\':")
    elif message.__contains__(".png"):
        type = "image"
        print("TRANSMITTER Loading image data from file \'" + message + "\':")
        image = Image.open(message)
        data = np.array(image)
        imageHeight = len(data)
        imageWidth = len(data[0])
    else:
        type = "text"
        data = message

    # Transmitter processes the message stream through a hash function
    tra.generate_hash(data, type)
    # Transmitter appends message and hash to form digest
    tra.concatenate_digest(data, type, imageHeight, imageWidth)
    # Transmitter encrypts the digest using RC4
    tra.encrypt_digest()

    # Phase 3 = Data decryption and authentication
    print("Phase 3")
    # Receiver gets the encrypted ciphertext from the transmitter
    rec.get_ciphertext(tra.ciphertextHex)
    # Receiver decrypts the data stream using RC4 to get the received digest
    rec.decrypt_data_stream(type, imageHeight, imageWidth)
    # Receiver computes the hash for the received message and compares to the received hash
    rec.generate_hash(type)
    # Message is authenticated if the hashes match
    rec.message_auth()


SimulationSystem()
