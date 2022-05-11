import SHA512
import RC4
from PIL import Image


class Transmitter:

    def get_RSA_pub_key(self):
        print("Received pub key from receiver")

    def encrypt_RC4_key(self):
        print("Encrypted RC4 key")

    def send_encrypted_RC4_key(self):
        print("Sent encrypted RC4 key")

    def generate_hash(self):
        print("Hash generated")

    def concatenate_digest(self):
        print("Digest created")

    def encrypt_digest(self):
        print("Digest encrypted")

    def send_digest(self):
        print("Encrypted digest sent")


class Receiver:

    def send_RSA_pub_key(self):
        print("Send pub key to transmitter")

    def get_RC4_key(self):
        print("Received encrypted RC4 key")

    def get_ciphertext(self):
        print("Ciphertext received")

    def decrypt_data_stream(self):
        print("Digest decrypted")

    def generate_hash(self):
        print("Hash generated")

    def message_auth(self):
        print("Authenticating message")


def SimulationSystem():

    rec = Receiver()
    tra = Transmitter()

    # Phase 1 = Key distribution
    # Receiver sends RSA public key to transmitter
    rec.send_RSA_pub_key()
    tra.get_RSA_pub_key()
    # Transmitter uses RSA to encrypt RC4 key
    tra.encrypt_RC4_key()
    # Transmitter send the encrypted RC4 key to the receiver
    tra.send_encrypted_RC4_key()
    rec.get_RC4_key()
    print()

    # Phase 2 = Data signing and encryption
    # Transmitter processes the message stream through a hash function
    tra.generate_hash()
    # Transmitter appends message and has to form digest
    tra.concatenate_digest()
    # Transmitter encrypts the digest using RC4
    tra.encrypt_digest()
    # Transmitter sends the encrypted data to the receiver
    tra.send_digest()
    print()

    # Phase 3 = Data decryption and authentication
    # Receiver gets the encrypted ciphertext from the transmitter
    rec.get_ciphertext()
    # Receiver decrypts the data stream using RC4 to get the received digest
    rec.decrypt_data_stream()
    # Receiver computes the hash for the received message and compares to the received hash
    rec.generate_hash()
    # Message is authenticated if the hashes match
    rec.message_auth()


SimulationSystem()
