import struct
import os

class Salsa20:
    def __init__(self, file, key, nonce):
        self.file = file
        self.key = key
        self.nonce = nonce

    def rotate_left(self, value, shift):
        return ((value << shift) & 0xFFFFFFFF) | (value >> (32 - shift))

    def salsa20_word_to_bytes(self, word):
        return struct.pack("<Q", word)

    def salsa20_bytes_to_word(self, bytes):
        return struct.unpack("<I", bytes)[0]

    def salsa20_quarter_round(self, a, b, c, d):
        b ^= self.rotate_left((a + d) & 0xFFFFFFFF, 7)
        c ^= self.rotate_left((b + a) & 0xFFFFFFFF, 9)
        d ^= self.rotate_left((c + b) & 0xFFFFFFFF, 13)
        a ^= self.rotate_left((d + c) & 0xFFFFFFFF, 18)
        return a, b, c, d

    def salsa20_row_round(self, state):
        state[1], state[5], state[9], state[13] = self.salsa20_quarter_round(state[1], state[5], state[9], state[13])
        state[6], state[10], state[14], state[2] = self.salsa20_quarter_round(state[6], state[10], state[14], state[2])
        state[11], state[15], state[3], state[7] = self.salsa20_quarter_round(state[11], state[15], state[3], state[7])
        state[0], state[4], state[8], state[12] = self.salsa20_quarter_round(state[0], state[4], state[8], state[12])
        return state

    def salsa20_column_round(self, state):
        state[1], state[5], state[9], state[13] = self.salsa20_quarter_round(state[1], state[5], state[9], state[13])
        state[6], state[10], state[14], state[2] = self.salsa20_quarter_round(state[6], state[10], state[14], state[2])
        state[11], state[15], state[3], state[7] = self.salsa20_quarter_round(state[11], state[15], state[3], state[7])
        state[0], state[4], state[8], state[12] = self.salsa20_quarter_round(state[0], state[4], state[8], state[12])
        return state

    def salsa20_double_round(self, state):
        state = self.salsa20_row_round(state)
        state = self.salsa20_column_round(state)
        return state

    def salsa20_initialize(self, key, nonce, counter):
        constants = [0x61707865, 0x3320646E, 0x79622D32, 0x6B206574]
        state = [0] * 16
        state[0] = constants[0]
        state[5] = constants[1]
        state[10] = constants[2]
        state[15] = constants[3]
        state[1:5] = struct.unpack("<4I", key[:16])
        state[11:15] = struct.unpack("<4I", key[16:32])
        state[6] = struct.unpack("<I", nonce[:4])[0]
        state[7] = struct.unpack("<I", nonce[4:8])[0]
        state[8:10] = counter
        return state

    def salsa20_generate_keystream(self, state):
        keystream = [0] * 64
        temp_state = list(state)

        for i in range(6):
            temp_state = self.salsa20_double_round(temp_state)

        for i in range(16):
            temp_state[i] += state[i]

        for i in range(16):
            keystream_bytes = self.salsa20_word_to_bytes(temp_state[i])
            keystream[4 * i:4 * (i + 1)] = list(keystream_bytes)

        return keystream

    def encrypt(self):
        file_to_write = self.file + ".salsa20"

        with open(self.file, "rb") as f, open(file_to_write, "wb") as w:
            counter = [0, 0]
            while True:
                data = f.read(64)
                if not data:
                    break

                encrypted_message = bytearray()
                state = self.salsa20_initialize(self.key, self.nonce, counter)
                keystream = self.salsa20_generate_keystream(state)

                for i in range(min(len(data), 64)):
                    encrypted_message.append(data[i] ^ keystream[i])

                counter[0] += 1
                if counter[0] == 0:
                    counter[1] += 1

                w.write(encrypted_message)

    def decrypt(self):
        output_file = self.file.replace(os.path.splitext(self.file)[1], "")

        with open(self.file, "rb") as f, open(output_file, "wb") as w:
            counter = [0, 0]
            while True:
                data = f.read(64)
                if not data:
                    break

                encrypted_message = bytearray()
                state = self.salsa20_initialize(self.key, self.nonce, counter)
                keystream = self.salsa20_generate_keystream(state)

                for i in range(min(len(data), 64)):
                    encrypted_message.append(data[i] ^ keystream[i])

                counter[0] += 1
                if counter[0] == 0:
                    counter[1] += 1

                w.write(encrypted_message)