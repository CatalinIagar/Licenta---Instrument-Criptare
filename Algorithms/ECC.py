import os

from Crypto.Cipher import AES
from Crypto.Hash import SHA256, HMAC
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from Crypto.PublicKey import ECC
from Crypto.Protocol.KDF import HKDF

class ECCAlgorithm:
    def derive_key(self, salt, shared_info):
        key = HKDF(shared_info, 32, salt, SHA256)
        return key

    def generate_key(self):
        private_key = ECC.generate(curve='secp256r1')
        public_key = private_key.public_key()

        # Save private key to a .pem file
        private_key_pem = private_key.export_key(format='PEM')
        with open("private_key.pem", 'wb') as f:
            f.write(private_key_pem.encode())

        # Save public key to a .pem file
        public_key_pem = public_key.export_key(format='PEM')
        with open("public_key.pem", 'wb') as f:
            f.write(public_key_pem.encode())

        print("Private and public keys saved successfully.")

    def load_private_key(self, private_key_file):
        with open(private_key_file, 'rb') as f:
            private_key_data = f.read()
        private_key = ECC.import_key(private_key_data)
        return private_key

    def load_public_key(self, public_key_file):
        with open(public_key_file, 'rb') as f:
            public_key_data = f.read()
        public_key = ECC.import_key(public_key_data)
        return public_key

    def encrypt(self, public_key_file, plaintext_file, shared_info):
        public_key = self.load_public_key(public_key_file)

        ephemeral_key = ECC.generate(curve='secp256r1')
        ephemeral_pubkey = ephemeral_key.public_key().export_key(format='DER')

        # Derive shared secret
        shared_secret = ephemeral_key.d * public_key.pointQ
        shared_secret_bytes = shared_secret.x.to_bytes(32, 'big') + shared_secret.y.to_bytes(32, 'big')
        salt = get_random_bytes(16)  # Salt for key derivation
        derived_key = self.derive_key(salt, shared_info + shared_secret_bytes)

        with open(plaintext_file, "rb") as f:
            plaintext = f.read()

        # Encrypt the plaintext with AES-256 in CBC mode
        iv = get_random_bytes(16)
        cipher = AES.new(derived_key, AES.MODE_CBC, iv)
        ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))

        # Compute MAC tag using HMAC-SHA256
        mac_key = derived_key[:16]
        mac_data = iv + ephemeral_pubkey + ciphertext
        mac = HMAC.new(mac_key, mac_data, SHA256).digest()

        file_to_write = plaintext_file + ".ecc"

        with open(file_to_write, "wb") as out_file:
            out_file.write(ephemeral_pubkey)
            out_file.write(salt)
            out_file.write(iv)
            out_file.write(ciphertext)
            out_file.write(mac)

        print("Encryption process finished successfully.")

    def decrypt(self, private_key_file, ciphertext_file, shared_info):
        file_to_write = ciphertext_file.replace(os.path.splitext(ciphertext_file)[1], "")
        private_key = self.load_private_key(private_key_file)

        with open(ciphertext_file, "rb") as f:
            ciphertext = f.read()

        ephemeral_pubkey = ciphertext[:91]
        salt = ciphertext[91:107]
        iv = ciphertext[107:123]
        encrypted_message = ciphertext[123:-32]
        received_mac = ciphertext[-32:]

        shared_secret = private_key.d * ECC.import_key(ephemeral_pubkey).pointQ
        shared_secret_bytes = shared_secret.x.to_bytes(32, 'big') + shared_secret.y.to_bytes(32, 'big')

        derived_key = self.derive_key(salt, shared_info + shared_secret_bytes)

        # Verify MAC tag
        mac_key = derived_key[:16]
        mac_data = iv + ephemeral_pubkey + encrypted_message
        computed_mac = HMAC.new(mac_key, mac_data, SHA256).digest()
        if computed_mac != received_mac:
            raise ValueError("MAC verification failed. The ciphertext may have been tampered with.")

        # Decrypt the ciphertext with AES-256 in CBC mode
        cipher = AES.new(derived_key, AES.MODE_CBC, iv)
        decrypted_message = unpad(cipher.decrypt(encrypted_message), AES.block_size)

        with open(file_to_write, "wb") as out:
            out.write(decrypted_message)

        print("Decryption process finished successfully.")
