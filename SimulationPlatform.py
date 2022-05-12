import SHA512
import RC4
import RSA
from PIL import Image
import numpy as np
from bitarray.util import int2ba, ba2hex, ba2int
import random
import bitarray

imageHeight = 0
imageWidth = 0


# Class to simulate functionality of a transmitter
class Transmitter:

    def __init__(self):
        self.encryptedKey = []
        self.hash = ""
        self.fullDigest = ""
        self.ciphertext = ""
        self.ciphertextHex = ""
        self.imageArray = np.empty((0))

    # Get the RSA public key from the receiver
    def get_RSA_pub_key(self, pubKey):
        self.encryptedKey = RSA.EncryptUsingPublicKey(pubKey)

    # Calculate the hash value of the plaintext or image
    def generate_hash(self, message, type):
        if type == "textfile":
            textFile = open(message, "r+")
            textData = textFile.read()
            self.hash = SHA512.sha512_hash(textData, type)
        else:
            self.hash = SHA512.sha512_hash(message, type)
        print("TRANSMITTER Plaintext Hash:")
        printing_hex(self.hash.upper())

    # Create the full digest (consists of message + hash)
    def concatenate_digest(self, data, type, height, width):
        digest = ""
        # Create digest for text from terminal
        if type == "text":
            for i in range(len(data)):
                baVal = int2ba(ord(data[i]), 8)
                hexVal = ba2hex(baVal)
                digest += hexVal
            digest += self.hash
        # Create digest for text from text file
        elif type == "textfile":
            textFile = open(data, "r")
            textData = textFile.read()
            for i in range(len(textData)):
                baVal = int2ba(ord(textData[i]), 8)
                hexVal = ba2hex(baVal)
                digest += hexVal
            digest += self.hash
            textFile.close()
            textFile = open(data, "w")
            textFile.write(digest)
            textFile.close()
        # Create digest for an image
        else:
            for i in range(height):
                for j in range(width):
                    for k in range(3):
                        baVal = int2ba(int(data[i][j][k]), 8)
                        hexVal = ba2hex(baVal)
                        digest += hexVal
            digest += self.hash

        self.fullDigest = digest

    # Encrypt the full digest using the RC4 cipher
    def encrypt_digest(self, type, height, width):
        print("TRANSMITTER RC4 Encrypted Ciphertext:")
        self.ciphertext = RC4.RC4_Encrypt(self.fullDigest, RSA.plaintexKey)

        # Encrypt text from terminal or text file
        if type == "text" or type == "textfile":
            for i in range(len(self.ciphertext)):
                baVal = int2ba(ord(self.ciphertext[i]), 8)
                hexVal = ba2hex(baVal)
                self.ciphertextHex += hexVal

            printing_hex(self.ciphertextHex)
        # Encrypt an image
        else:
            for i in range(len(self.ciphertext)):
                baVal = int2ba(ord(self.ciphertext[i]), 8)
                hexVal = ba2hex(baVal)
                self.ciphertextHex += hexVal

            index = 0
            self.imageArray = np.zeros((height, width, 3))
            for i in range(height):
                for j in range(width):
                    for k in range(3):
                        self.imageArray[i][j][k] = ord(self.ciphertext[index])
                        index += 1
            print("Encrypted image displayed.")
            encryptImage = Image.fromarray(np.uint8(self.imageArray)).convert('RGB')
            encryptImage.show()


# Class to simulate functionality of a receiver
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

    # Send the RSA public key to the transmitter
    def send_RSA_pub_key(self):
        keys = RSA.ReciverAutoGeneratePrdouceKeys()
        self.publicKey = keys[0]
        self.privateKey = keys[1]

    # Obtain the encrypted RC4 key from the transmitter
    def get_RC4_key(self, key):
        self.encryptRC4Key = key
        self.decryptRC4Key = RSA.DecryptUsingPrivateKey(key, self.privateKey)

    # Obatine the ciphertext from the transmitter
    def get_ciphertext(self, ciphertext):
        self.cipherText = ciphertext

    # Decrypt the received data stream ciphertext
    def decrypt_data_stream(self, type, height, width):
        self.plainText = RC4.RC4_Encrypt(self.cipherText, self.decryptRC4Key)
        start = len(self.plainText) - 64
        end = len(self.plainText)

        # Chance of randomly flipping a bit in the first 4 bytes
        chance = random.randint(0, 9)
        if chance == 5:
            index = random.randint(0, 3)
            listString = list(self.plainText)
            intVal = ord(listString[index])
            baVal = int2ba(intVal, 8)
            index2 = random.randint(0, 8)
            if baVal[index2] == 0:
                baVal[index2] = 1
            else:
                baVal[index2] = 0
            intVal = ba2int(baVal)
            listString[index] = chr(intVal)
            self.plainText = ''.join(listString)

        # Extract received plain text
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

        # Extract received hash value
        for i in range(start, end):
            baVal = int2ba(ord(self.plainText[i]), 8)
            hexval = ba2hex(baVal)
            self.receivedHash += hexval

        print("RECEIVER Decrypted message received:")
        if type == "text" or type == "textfile":
            print(self.plainTextSlice)
        else:
            print("Image displayed.")
            encryptImage = Image.fromarray(np.uint8(self.imageArray)).convert('RGB')
            encryptImage.show()

        print("\nRECEIVER Expected Hash:")
        printing_hex(self.receivedHash)

    # Calculate the hash value of the received plaintext message
    def generate_hash(self, type):
        if type == "text" or type == "textfile":
            self.hashCheck = SHA512.sha512_hash(self.plainTextSlice, type)
        else:
            self.hashCheck = SHA512.sha512_hash(self.imageArray, type)

        print("RECEIVER Received Hash:")
        printing_hex(self.hashCheck)

    # Authenticate the received message by comparing hash values
    def message_auth(self):
        if self.hashCheck == self.receivedHash:
            print("\nMessage Authenticated.")
        else:
            print("\nMessage Authentication Failed.")


# Format output hex values
def printing_hex(data):

    length = len(data)
    line = ""
    for i in range(0, length, 2):
        if i % 40 == 0 and i != 0:
            print(line)
            line = ""
            line += data[i].upper() + data[i + 1].upper() + " "
        else:
            line += data[i].upper() + data[i+1].upper() + " "
    print(line)


def SimulationSystem():

    global imageHeight, imageWidth

    # Transmitter and Receiver class objects
    rec = Receiver()
    tra = Transmitter()

    # Phase 1 = Key distribution
    # Receiver sends RSA public key to transmitter
    rec.send_RSA_pub_key()
    tra.get_RSA_pub_key(rec.publicKey)
    rec.get_RC4_key(tra.encryptedKey)

    # Phase 2 = Data signing and encryption
    print("\n--------------- Phase 2 ---------------")
    message = input("TRANSMITTER Please Enter a message: ")
    print()

    # Message is a text file
    if message.__contains__(".txt"):
        type = "textfile"
        print("TRANSMITTER Loading message from file \'" + message + "\':")
        textFile = open(message, "r")
        data = message
        textData = textFile.read()
        textFile.close()
        print(textData + "\n")
    # Message is an image
    elif message.__contains__(".png"):
        type = "image"
        print("TRANSMITTER Loading image data from file \'" + message + "\':")
        image = Image.open(message)
        data = np.array(image)
        imageHeight = len(data)
        imageWidth = len(data[0])
        image.close()
        ogImage = Image.fromarray(np.uint8(data)).convert('RGB')
        ogImage.show()
    # Message is plain text from terminal
    else:
        type = "text"
        data = message

    # Transmitter processes the message stream through a hash function
    tra.generate_hash(data, type)
    # Transmitter appends message and hash to form digest
    tra.concatenate_digest(data, type, imageHeight, imageWidth)
    # Transmitter encrypts the digest using RC4
    tra.encrypt_digest(type, imageHeight, imageHeight)

    # Phase 3 = Data decryption and authentication
    print("\n--------------- Phase 3 ---------------")
    # Receiver gets the encrypted ciphertext from the transmitter
    rec.get_ciphertext(tra.ciphertextHex)
    # Receiver decrypts the data stream using RC4 to get the received digest
    rec.decrypt_data_stream(type, imageHeight, imageWidth)
    # Receiver computes the hash for the received message and compares to the received hash
    rec.generate_hash(type)
    # Message is authenticated if the hashes match
    rec.message_auth()


SimulationSystem()
