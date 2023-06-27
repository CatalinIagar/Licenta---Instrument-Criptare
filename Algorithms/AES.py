import os

class AES:
    SBOX = [
        [0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76],
        [0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0],
        [0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15],
        [0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75],
        [0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84],
        [0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf],
        [0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8],
        [0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2],
        [0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73],
        [0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb],
        [0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79],
        [0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08],
        [0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a],
        [0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e],
        [0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf],
        [0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16]
    ]

    SBOXINV = [
        [0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb],
        [0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb],
        [0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e],
        [0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25],
        [0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92],
        [0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84],
        [0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06],
        [0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b],
        [0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73],
        [0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e],
        [0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b],
        [0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4],
        [0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f],
        [0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef],
        [0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61],
        [0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d]
    ]

    MIXCOL = [
        [0x02, 0x03, 0x01, 0x01],
        [0x01, 0x02, 0x03, 0x01],
        [0x01, 0x01, 0x02, 0x03],
        [0x03, 0x01, 0x01, 0x02]
    ]

    MIXCOLINV = [
        [0x0e, 0x0b, 0x0d, 0x09],
        [0x09, 0x0e, 0x0b, 0x0d],
        [0x0d, 0x09, 0x0e, 0x0b],
        [0x0b, 0x0d, 0x09, 0x0e]
    ]

    ROUND_CONSTANTS = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36]

    def __init__(self, file, mode, key, iv=None):
        self.file = file
        self.key = key
        self.mode = mode
        self.keys = []
        self.state = []
        self.iv = iv

    def turn_to_hex(self, text):
        res = []
        for letter in text:
            res.append(hex(letter))
        return res

    def generate_words(self, key):
        temp = key
        result = []
        while temp:
            result.append(temp[:4])
            temp = temp[4:]

        return result

    def g_function(self, key, round):
        result = [key[1], key[2], key[3], key[0]]

        subResult = []
        for value in result:
            if len(value) == 3:
                row = 0
                column = int(value[2], 16)
            else:
                row = int(value[2], 16)
                column = int(value[3], 16)

            subResult.append(hex(self.SBOX[row][column]))

        temp = []
        for item in subResult:
            temp.append(item)

        subResult[0] = hex(int(subResult[0], 16) ^ self.ROUND_CONSTANTS[round])

        return subResult

    def calculate_round_words(self, key, w):
        result = []
        row = []

        for i in range(4):
            row.append(hex(int(key[0][i], 16) ^ int(w[i], 16)))
        result.append(row)

        for i in range(3):
            row = []
            for j in range(4):
                row.append(hex(int(result[i][j], 16) ^ int(key[i + 1][j], 16)))
            result.append(row)

        return result

    def generate_keys(self, key):
        hexKey = self.turn_to_hex(key)
        self.keys.append(hexKey)

        for i in range(10):
            wordKeys = self.generate_words(self.keys[i])
            w = self.g_function(wordKeys[3], i)
            roundKey = self.calculate_round_words(wordKeys, w)
            result = [item for sublist in roundKey for item in sublist]
            self.keys.append(result)

    def add_round_key(self, key):
        result = []

        for i in range(4):
            row = []
            for j in range(4):
                row.append(hex(int(self.state[i][j], 16) ^ int(key[i][j], 16)))
            result.append(row)

        self.state = result

    def sub_bytes(self):
        result = []
        for i in range(4):
            rows = []
            for j in range(4):
                if len(self.state[i][j]) == 3:
                    row = 0
                    column = int(self.state[i][j][2], 16)
                else:
                    row = int(self.state[i][j][2], 16)
                    column = int(self.state[i][j][3], 16)
                rows.append(hex(self.SBOX[row][column]))
            result.append(rows)

        self.state = result

    def inverse_sub_bytes(self):
        result = []
        for i in range(4):
            rows = []
            for j in range(4):
                if len(self.state[i][j]) == 3:
                    row = 0
                    column = int(self.state[i][j][2], 16)
                else:
                    row = int(self.state[i][j][2], 16)
                    column = int(self.state[i][j][3], 16)
                rows.append(hex(self.SBOXINV[row][column]))
            result.append(rows)

        self.state = result

    def shift_rows(self):

        self.state[1][0], self.state[1][1], self.state[1][2], self.state[1][3] = self.state[1][1], self.state[1][2], \
                                                                                 self.state[1][3], self.state[1][0]
        self.state[2][0], self.state[2][1], self.state[2][2], self.state[2][3] = self.state[2][2], self.state[2][3], \
                                                                                 self.state[2][0], self.state[2][1]
        self.state[3][0], self.state[3][1], self.state[3][2], self.state[3][3] = self.state[3][3], self.state[3][0], \
                                                                                 self.state[3][1], self.state[3][2]

    def inverse_shift_rows(self):

        self.state[1][0], self.state[1][1], self.state[1][2], self.state[1][3] = self.state[1][3], self.state[1][0], \
                                                                                 self.state[1][1], self.state[1][2]
        self.state[2][0], self.state[2][1], self.state[2][2], self.state[2][3] = self.state[2][2], self.state[2][3], \
                                                                                 self.state[2][0], self.state[2][1]
        self.state[3][0], self.state[3][1], self.state[3][2], self.state[3][3] = self.state[3][1], self.state[3][2], \
                                                                                 self.state[3][3], self.state[3][0]

    def mix_column(self):
        result = []
        res = []

        for i in range(4):
            row = []
            for j in range(4):
                row.append(self.state[j][i])
            result.append(row)

        for i in range(4):
            row = result[i]
            row_res = []
            for j in range(4):
                val = self.calc_mix_column(int(row[0], 16), self.MIXCOL[j][0]) ^ self.calc_mix_column(int(row[1], 16),
                                                                                                      self.MIXCOL[j][
                                                                                                          1]) ^ self.calc_mix_column(
                    int(row[2], 16),
                    self.MIXCOL[j][2]) ^ self.calc_mix_column(int(row[3], 16), self.MIXCOL[j][3])
                row_res.append(hex(val))
            res.append(row_res)

        final = [
            [res[0][0], res[1][0], res[2][0], res[3][0]],
            [res[0][1], res[1][1], res[2][1], res[3][1]],
            [res[0][2], res[1][2], res[2][2], res[3][2]],
            [res[0][3], res[1][3], res[2][3], res[3][3]]
        ]

        self.state = final

    def inverse_mix_column(self):
        result = []
        res = []

        for i in range(4):
            row = []
            for j in range(4):
                row.append(self.state[j][i])
            result.append(row)

        for i in range(4):
            row = result[i]
            row_res = []
            for j in range(4):
                val = self.calc_inv_mix_column(int(row[0], 16), self.MIXCOLINV[j][0]) ^ self.calc_inv_mix_column(
                    int(row[1], 16),
                    self.MIXCOLINV[j][1]) ^ self.calc_inv_mix_column(int(row[2], 16),
                                                                     self.MIXCOLINV[j][2]) ^ self.calc_inv_mix_column(
                    int(row[3], 16), self.MIXCOLINV[j][3])
                row_res.append(hex(val))
            res.append(row_res)

        final = [
            [res[0][0], res[1][0], res[2][0], res[3][0]],
            [res[0][1], res[1][1], res[2][1], res[3][1]],
            [res[0][2], res[1][2], res[2][2], res[3][2]],
            [res[0][3], res[1][3], res[2][3], res[3][3]]
        ]

        self.state = final

    def calc_mix_column(self, a, b):
        if b == 1:
            return a
        if b == 2:
            if a * 2 > 255:
                return (a * 2) ^ 0x11b
            else:
                return a * 2
        if b == 3:
            return self.calc_mix_column(a, 2) ^ a

    def calc_inv_mix_column(self, a, b):
        if b == 2:
            if a * 2 > 255:
                return (a * 2) ^ 0x11b
            else:
                return a * 2
        if b == 9:
            return self.calc_inv_mix_column(self.calc_inv_mix_column(self.calc_inv_mix_column(a, 2), 2), 2) ^ a
        if b == 11:
            return self.calc_inv_mix_column(self.calc_inv_mix_column(self.calc_inv_mix_column(a, 2), 2) ^ a, 2) ^ a
        if b == 13:
            return self.calc_inv_mix_column(self.calc_inv_mix_column(self.calc_inv_mix_column(a, 2) ^ a, 2), 2) ^ a
        if b == 14:
            return self.calc_inv_mix_column(self.calc_inv_mix_column(self.calc_inv_mix_column(a, 2) ^ a, 2) ^ a, 2)

    def encrypt_process(self, hex_data):
        self.state = []

        for i in range(4):
            self.state.append(hex_data[i::4])

        for i in range(11):
            key = []
            for j in range(4):
                key.append(self.keys[i][j::4])
            if i == 0:
                self.add_round_key(key)
            else:
                self.sub_bytes()
                self.shift_rows()
                if i != 10:
                    self.mix_column()
                self.add_round_key(key)

    def decrypt_process(self, hex_data):
        self.state = []

        for i in range(4):
            self.state.append(hex_data[i::4])

        for i in range(10, -1, -1):
            key = []
            for j in range(4):
                key.append(self.keys[i][j::4])
            if i == 10:
                self.add_round_key(key)
            else:
                self.inverse_shift_rows()
                self.inverse_sub_bytes()
                self.add_round_key(key)
                if i != 0:
                    self.inverse_mix_column()

    def encrypt(self):
        if self.mode == "ECB":
            self.encrypt_ecb()
        if self.mode == "CBC":
            self.encrypt_cbc()
        if self.mode == "CFB":
            self.encrypt_cfb()
        if self.mode == "OFB":
            self.encrypt_ofb()


    def decrypt(self):
        if self.mode == "ECB":
            self.decrypt_ecb()
        if self.mode == "CBC":
            self.decrypt_cbc()
        if self.mode == "CFB":
            self.decrypt_cfb()
        if self.mode == "OFB":
            self.decrypt_ofb()

    def encrypt_ecb(self):
        self.generate_keys(self.key)
        file_to_write = self.file + ".aes"

        with open(self.file, "rb") as f, open(file_to_write, "wb") as w:
            while True:
                data = f.read(16)
                if not data:
                    break

                if len(data) != 16:
                    padding_needed = 16 - len(data)
                    padding = bytes([padding_needed]) * padding_needed
                    data = data + padding
                hex_data = [hex(byte) for byte in data]

                self.encrypt_process(hex_data)

                hex_string = ""
                for col in range(4):
                    for row in range(4):
                        if len(self.state[row][col][2:]) == 1:
                            hex_string += "0" + self.state[row][col][2:]
                        else:
                            hex_string += self.state[row][col][2:]
                w.write(bytes.fromhex(hex_string))

    def encrypt_cbc(self):
        self.generate_keys(self.key)
        file_to_write = self.file + ".aes"
        first = True
        iv = [hex(byte) for byte in self.iv]

        with open(self.file, "rb") as f, open(file_to_write, "wb") as w:
            while True:
                data = f.read(16)
                if not data:
                    break

                if len(data) != 16:
                    padding_needed = 16 - len(data)
                    padding = bytes([padding_needed]) * padding_needed
                    data = data + padding
                hex_data = [hex(byte) for byte in data]

                if first:
                    for i in range(16):
                        hex_data[i] = hex(int(hex_data[i], 16) ^ int(iv[i], 16))
                    first = False
                else:
                    for i in range(16):
                        hex_data[i] = hex(int(hex_data[i], 16) ^ int(prev_block[i], 16))
                self.encrypt_process(hex_data)

                hex_string = ""
                for col in range(4):
                    for row in range(4):
                        if len(self.state[row][col][2:]) == 1:
                            hex_string += "0" + self.state[row][col][2:]
                        else:
                            hex_string += self.state[row][col][2:]

                prev_block = bytes.fromhex(hex_string)
                prev_block = [hex(byte) for byte in prev_block]

                w.write(bytes.fromhex(hex_string))

    def encrypt_cfb(self):
        self.generate_keys(self.key)
        file_to_write = self.file + ".aes"
        first = True
        iv = [hex(byte) for byte in self.iv]

        with open(self.file, "rb") as f, open(file_to_write, "wb") as w:
            while True:
                data = f.read(16)
                if not data:
                    break

                hex_data = [hex(byte) for byte in data]

                if first:
                    self.encrypt_process(iv)
                    first = False
                else:
                    self.encrypt_process(crypt_block)

                crypt_block = []

                for col in range(4):
                    for row in range(4):
                        crypt_block.append(self.state[row][col])

                for i in range(len(hex_data)):
                    crypt_block[i] = hex(int(crypt_block[i], 16) ^ int(hex_data[i], 16))

                hex_string = ""
                for i in range(len(hex_data)):
                    if len(crypt_block[i][2:]) == 1:
                        hex_string += "0" + crypt_block[i][2:]
                    else:
                        hex_string += crypt_block[i][2:]

                w.write(bytes.fromhex(hex_string))

    def decrypt_cfb(self):
        self.generate_keys(self.key)
        file_to_write = self.file.replace(os.path.splitext(self.file)[1], "")
        first = True
        iv = [hex(byte) for byte in self.iv]

        with open(self.file, "rb") as f, open(file_to_write, "wb") as w:
            while True:
                data = f.read(16)
                if not data:
                    break

                hex_data = [hex(byte) for byte in data]

                if first:
                    self.encrypt_process(iv)
                    first = False
                else:
                    self.encrypt_process(prev_hex_data)

                crypt_block = []

                for col in range(4):
                    for row in range(4):
                        crypt_block.append(self.state[row][col])

                for i in range(len(hex_data)):
                    crypt_block[i] = hex(int(crypt_block[i], 16) ^ int(hex_data[i], 16))

                hex_string = ""
                for i in range(len(hex_data)):
                    if len(crypt_block[i][2:]) == 1:
                        hex_string += "0" + crypt_block[i][2:]
                    else:
                        hex_string += crypt_block[i][2:]

                prev_hex_data = hex_data

                w.write(bytes.fromhex(hex_string))

    def encrypt_ofb(self):
        self.generate_keys(self.key)
        file_to_write = self.file + ".aes"
        iv = [hex(byte) for byte in self.iv]

        with open(self.file, "rb") as f, open(file_to_write, "wb") as w:
            while True:
                data = f.read(16)
                if not data:
                    break

                hex_data = [hex(byte) for byte in data]

                self.encrypt_process(iv)

                crypt_block = []

                for col in range(4):
                    for row in range(4):
                        crypt_block.append(self.state[row][col])

                iv = crypt_block

                for i in range(len(hex_data)):
                    hex_data[i] = hex(int(crypt_block[i], 16) ^ int(hex_data[i], 16))

                hex_string = ""

                for i in range(len(hex_data)):
                    if len(hex_data[i][2:]) == 1:
                        hex_string += "0" + hex_data[i][2:]
                    else:
                        hex_string += hex_data[i][2:]

                w.write(bytes.fromhex(hex_string))

    def decrypt_ecb(self):
        self.generate_keys(self.key)
        file_to_write = self.file.replace(os.path.splitext(self.file)[1], "")
        blocks = os.path.getsize(self.file) / 16

        with open(self.file, "rb") as f, open(file_to_write, "wb") as w:
            i = 0
            while True:
                i += 1
                data = f.read(16)
                if not data:
                    break

                hex_data = [hex(byte) for byte in data]

                self.decrypt_process(hex_data)

                hex_string = ""
                for col in range(4):
                    for row in range(4):
                        if len(self.state[row][col][2:]) == 1:
                            hex_string += "0" + self.state[row][col][2:]
                        else:
                            hex_string += self.state[row][col][2:]

                block = bytes.fromhex(hex_string)

                if i == blocks:
                    padding_length = block[-1]
                    padding = block[-padding_length:-1]

                    if all(byte == padding_length for byte in padding):
                        block = block[:-padding_length]

                w.write(block)



    def decrypt_cbc(self):
        self.generate_keys(self.key)
        file_to_write = self.file.replace(os.path.splitext(self.file)[1], "")
        blocks = os.path.getsize(self.file) / 16
        first = True

        with open(self.file, "rb") as f, open(file_to_write, "wb") as w:
            i = 0
            while True:
                i += 1
                data = f.read(16)
                if not data:
                    break

                hex_data = [hex(byte) for byte in data]

                self.decrypt_process(hex_data)

                if first:
                    for col in range(4):
                        for row in range(4):
                            self.state[row][col] = hex(int(self.state[row][col], 16) ^ self.iv[col * 4 + row])
                    first = False
                else:
                    for col in range(4):
                        for row in range(4):
                            self.state[row][col] = hex(int(self.state[row][col], 16) ^ int(prev_block[col * 4 + row], 16))

                hex_string = ""
                for col in range(4):
                    for row in range(4):
                        if len(self.state[row][col][2:]) == 1:
                            hex_string += "0" + self.state[row][col][2:]
                        else:
                            hex_string += self.state[row][col][2:]

                block = bytes.fromhex(hex_string)

                if i == blocks:
                    padding_length = block[-1]
                    padding = block[-padding_length:-1]

                    if all(byte == padding_length for byte in padding):
                        block = block[:-padding_length]

                prev_block = hex_data

                w.write(block)

    def decrypt_ofb(self):
        self.generate_keys(self.key)
        file_to_write = self.file.replace(os.path.splitext(self.file)[1], "")

        iv = [hex(byte) for byte in self.iv]

        with open(self.file, "rb") as f, open(file_to_write, "wb") as w:
            while True:
                data = f.read(16)
                if not data:
                    break

                hex_data = [hex(byte) for byte in data]

                self.encrypt_process(iv)

                crypt_block = []

                for col in range(4):
                    for row in range(4):
                        crypt_block.append(self.state[row][col])

                iv = crypt_block

                for i in range(len(hex_data)):
                    hex_data[i] = hex(int(crypt_block[i], 16) ^ int(hex_data[i], 16))

                hex_string = ""

                for i in range(len(hex_data)):
                    if len(hex_data[i][2:]) == 1:
                        hex_string += "0" + hex_data[i][2:]
                    else:
                        hex_string += hex_data[i][2:]

                w.write(bytes.fromhex(hex_string))