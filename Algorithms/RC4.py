import os

class RC4:
    def __init__(self, file, key, chunk_size = 1024*1024):
        self.file = file
        self.key = key
        self.chunk_size = chunk_size

    def rc4_encrypt(self, chunk):
        S = list(range(256))
        j = 0
        for i in range(256):
            j = (j + S[i] + self.key[i % len(self.key)]) % 256
            S[i], S[j] = S[j], S[i]

        i = j = 0
        key_stream = []
        for byte in chunk:
            i = (i + 1) % 256
            j = (j + S[i]) % 256
            S[i], S[j] = S[j], S[i]
            k = S[(S[i] + S[j]) % 256]
            key_stream.append(k)

        encrypted_text = bytes([p ^ k for p, k in zip(chunk, key_stream)])

        return encrypted_text

    def rc4_decrypt(self, chunk):
        S = list(range(256))
        j = 0
        for i in range(256):
            j = (j + S[i] + self.key[i % len(self.key)]) % 256
            S[i], S[j] = S[j], S[i]

        i = j = 0
        key_stream = []
        for byte in chunk:
            i = (i + 1) % 256
            j = (j + S[i]) % 256
            S[i], S[j] = S[j], S[i]
            k = S[(S[i] + S[j]) % 256]
            key_stream.append(k)

        decrypted_text = bytes([p ^ k for p, k in zip(chunk, key_stream)])

        return decrypted_text

    def encrypt(self):
        output_file = self.file + ".rc4"
        with open(self.file, 'rb') as in_file, open(output_file, 'wb') as out_file:
            while True:
                chunk = in_file.read(self.chunk_size)
                if not chunk:
                    break
                encrypted_chunk = self.rc4_encrypt(chunk)
                out_file.write(encrypted_chunk)

        print("Encryption process finished successfully.")

    def decrypt(self):
        output_file = self.file.replace(os.path.splitext(self.file)[1], "")
        with open(self.file, 'rb') as in_file, open(output_file, 'wb') as out_file:
            while True:
                chunk = in_file.read(self.chunk_size)
                if not chunk:
                    break
                encrypted_chunk = self.rc4_encrypt(chunk)
                out_file.write(encrypted_chunk)

        print("Decryption process finished successfully.")