import binascii
import os
import random
import sys
import ast

from Algorithms.SHA256 import SHA256
from Algorithms.AES import AES
from Algorithms.RC4 import RC4
from Algorithms.TwoFish import TwoFish
from Algorithms.Salsa20 import Salsa20
from ErrorHelper import Errors

ALGORITHMS = ["AES", "TwoFish", "Salsa", "RC4", "RSA", "ECC"]
AES_MODES = ["ECB", "CBC", "CFB", "OFB"]

E = Errors()


class App:

    def start(self):
        if len(sys.argv) > 1:
            if sys.argv[1] == "generate_key":
                self.generate_byte_key()
            elif sys.argv[1] == "hash":
                self.hashStart()
            elif sys.argv[1] == "hash_verify":
                self.hashVerifyStart()
            elif sys.argv[1] == "encrypt":
                self.encryption_start()
            elif sys.argv[1] == "decrypt":
                self.decryption_start()
            else:
                E.error_message("NO_START_ARGUMENT_FOUND")
        else:
            E.error_message("NO_START_ARGUMENT_FOUND")

    def find_param(self, param):
        found = False
        pos = -1
        for i in range(1, len(sys.argv)):
            if param == sys.argv[i]:
                found = True
                pos = i

        if not found:
            print("Argument {} not found.".format(param))
            return False

        if (pos + 1) > len(sys.argv) - 1:
            print("Missing value for {}".format(param))
            return False

        value = sys.argv[pos + 1]

        if param == "-iv":
            return value

        if param == "-f" or param == "-f1" or param == "-f2":
            if os.path.isfile(value):
                return value
            else:
                print("File doesn't exist")
                return False

        if param == "-alg":
            if value in ALGORITHMS:
                return value
            else:
                return False

        if param == "-m":
            if value in AES_MODES:
                return value
            else:
                return False

        if param == "-k":
            return value

        if param == "-n":
            return value

        if param == "-o":
            return value

        if param == "-l":
            return value

    def encryption_start(self):
        print("Encryption process")

        filename = self.find_param("-f")
        if not filename:
            E.error_message("NO_INPUT_FILE_SPECIFIED")
            return

        algorithm = self.find_param("-alg")
        if not algorithm:
            E.error_message("NO_ALGORITHM_SPECIFIED")
            return

        if algorithm == "AES":
            self.encryptAES(filename)
        elif algorithm == "TwoFish":
            self.encrypt_TwoFish(filename)
        elif algorithm == "Salsa":
            self.encrypt_Salsa(filename)
        elif algorithm == "RC4":
            self.encrypt_RC4(filename)
        else:
            E.error_message("NO_ALGORITHM_FOUND")
            return

    def decryption_start(self):
        print("Decryption process")

        filename = self.find_param("-f")
        if not filename:
            E.error_message("NO_INPUT_FILE_SPECIFIED")
            return

        algorithm = self.find_param("-alg")
        if not algorithm:
            E.error_message("NO_ALGORITHM_SPECIFIED")
            return

        if algorithm == "AES":
            extension = os.path.splitext(filename)[1]
            if extension != ".aes":
                E.error_message("AES_DECRYPT_WRONG_EXTENSION")
            else:
                self.decryptAES(filename)
        elif algorithm == "TwoFish":
            extension = os.path.splitext(filename)[1]
            if extension != ".twofish":
                print("Wrong file extension for TwoFish decryption")
            else:
                self.decrypt_TwoFish(filename)
        elif algorithm == "Salsa":
            extension = os.path.splitext(filename)[1]
            if extension != ".salsa20":
                print("Wrong file extension for Salsa decryption")
            else:
                self.decrypt_Salsa(filename)
        elif algorithm == "RC4":
            extension = os.path.splitext(filename)[1]
            if extension != ".rc4":
                print("Wrong file extension for RC4 decryption")
            else:
                self.decrypt_RC4(filename)
        else:
            print("Invalid algorithm")
            print("Use -h -alg to see the list of available algorithms")
            return

    def encryptAES(self, file):
        mode = self.find_param("-m")
        if not mode:
            print("Use -m to specify the mode for AES")
            return

        key = self.find_param("-k")
        key = ast.literal_eval(key)

        if not key:
            E.error_message("NO_AES_KEY_FOUND")
            return

        if len(key) != 16:
            E.error_message("AES_KEY_LENGTH_ERROR")
            return

        if mode == "ECB":
            self.print_file_details(file)
            print("Algorithm: AES")
            print("Mode: EBC")
            print("Key: {}".format(key))
            res = input("Continue? (y/n): ")
            if res == "y":
                encryption = AES(file, "ECB", key)
                encryption.encrypt()
            else:
                print("Program stopped")
        elif mode == "CBC":
            iv = self.find_param("-iv")
            iv = ast.literal_eval(iv)

            if not iv:
                E.error_message("NO_IV_AES_FOUND")

            if len(iv) != 16:
                E.error_message("AES_IV_LENGTH_ERROR")
                return

            self.print_file_details(file)
            print("Algorithm: AES")
            print("Mode: CBC")
            print("Key: {}".format(key))
            print("IV: {}".format(iv))
            res = input("Continue? (y/n): ")
            if res == "y":
                encryption = AES(file, "CBC", key, iv)
                encryption.encrypt()
            else:
                print("Program stopped")
        elif mode == "CFB":
            iv = self.find_param("-iv")
            iv = ast.literal_eval(iv)

            if not iv:
                E.error_message("NO_IV_AES_FOUND")

            if len(iv) != 16:
                E.error_message("AES_IV_LENGTH_ERROR")
                return
            self.print_file_details(file)
            print("Algorithm: AES")
            print("Mode: CFB")
            print("Key: {}".format(key))
            print("IV: {}".format(iv))
            res = input("Continue? (y/n): ")
            if res == "y":
                encryption = AES(file, "CFB", key, iv)
                encryption.encrypt()
            else:
                print("Program stopped")
        elif mode == "OFB":
            iv = self.find_param("-iv")
            iv = ast.literal_eval(iv)

            if not iv:
                E.error_message("NO_IV_AES_FOUND")

            if len(iv) != 16:
                E.error_message("AES_IV_LENGTH_ERROR")
                return
            self.print_file_details(file)
            print("Algorithm: AES")
            print("Mode: OFB")
            print("Key: {}".format(key))
            print("IV: {}".format(iv))
            res = input("Continue? (y/n): ")
            if res == "y":
                encryption = AES(file, "OFB", key, iv)
                encryption.encrypt()
            else:
                E.error_message("PROGRAM_STOP")
        else:
            E.error_message("NO_AES_MODE_SPECIFIED")

    def encrypt_RC4(self, file):
        key = self.find_param("-k")
        key = ast.literal_eval(key)

        if not key:
            E.error_message("NO_RC4_KEY_FOUND")
            return

        self.print_file_details(file)
        print("Algorithm: RC4")
        print("Key: {}".format(key))
        res = input("Continue? (y/n): ")
        if res == "y":
            encryption = RC4(file, key)
            encryption.encrypt()
        else:
            print("Program stopped")

    def encrypt_TwoFish(self, file):
        key = self.find_param("-k")
        key = ast.literal_eval(key)

        if not key:
            E.error_message("NO_TWOFISH_KEY_FOUND")
            return

        if len(key) not in [16, 24, 32]:
            E.error_message("TWOFISH_KEY_LENGTH_ERROR")
            return

        self.print_file_details(file)
        print("Algorithm: TwoFish")
        print("Key: {}".format(key))
        res = input("Continue? (y/n): ")
        if res == "y":
            encryption = TwoFish(file, key)
            encryption.encrypt()
        else:
            print("Program stopped")

    def encrypt_Salsa(self, file):
        key = self.find_param("-k")
        key = ast.literal_eval(key)

        if not key:
            E.error_message("NO_SALSA_KEY_FOUND")
            return

        if len(key) != 32:
            E.error_message("SALSA_KEY_LENGTH_ERROR")
            return

        nonce = self.find_param("-n")
        nonce = ast.literal_eval(nonce)

        if not nonce:
            E.error_message("NO_SALSA_NONCE_FOUND")
            return

        if len(nonce) != 8:
            E.error_message("SALSA_NONCE_LENGTH_ERROR")
            return

        self.print_file_details(file)
        print("Algorithm: Salsa20/12")
        print("Key: {}".format(key))
        print("Nonce: {}".format(nonce))
        res = input("Continue? (y/n): ")
        if res == "y":
            encryption = Salsa20(file, key, nonce)
            encryption.encrypt()
        else:
            print("Program stopped")

    def decryptAES(self, file):
        mode = self.find_param("-m")
        if not mode:
            print("Use -m to specify the mode for AES")
            return

        key = self.find_param("-k")
        key = ast.literal_eval(key)

        if not key:
            E.error_message("NO_AES_KEY_FOUND")
            return

        if len(key) != 16:
            E.error_message("AES_KEY_LENGTH_ERROR")
            return

        if mode == "ECB":
            self.print_file_details(file)
            print("Algorithm: AES")
            print("Mode: EBC")
            print("Key: {}".format(key))
            res = input("Continue? (y/n): ")
            if res == "y":
                encryption = AES(file, "ECB", key)
                encryption.decrypt()
            else:
                print("Program stopped")
        elif mode == "CBC":
            iv = self.find_param("-iv")
            iv = ast.literal_eval(iv)

            if not iv:
                E.error_message("NO_IV_AES_FOUND")

            if len(iv) != 16:
                E.error_message("AES_IV_LENGTH_ERROR")
                return
            self.print_file_details(file)
            print("Algorithm: AES")
            print("Mode: CBC")
            print("Key: {}".format(key))
            print("IV: {}".format(iv))
            res = input("Continue? (y/n): ")
            if res == "y":
                encryption = AES(file, "CBC", key, iv)
                encryption.decrypt()
            else:
                print("Program stopped")

        elif mode == "CFB":
            iv = self.find_param("-iv")
            iv = ast.literal_eval(iv)

            if not iv:
                E.error_message("NO_IV_AES_FOUND")

            if len(iv) != 16:
                E.error_message("AES_IV_LENGTH_ERROR")
                return
            self.print_file_details(file)
            print("Algorithm: AES")
            print("Mode: CFB")
            print("Key: {}".format(key))
            print("IV: {}".format(iv))
            res = input("Continue? (y/n): ")
            if res == "y":
                encryption = AES(file, "CFB", key, iv)
                encryption.decrypt()
            else:
                print("Program stopped")
        elif mode == "OFB":
            iv = self.find_param("-iv")
            iv = ast.literal_eval(iv)

            if not iv:
                E.error_message("NO_IV_AES_FOUND")

            if len(iv) != 16:
                E.error_message("AES_IV_LENGTH_ERROR")
                return
            self.print_file_details(file)
            print("Algorithm: AES")
            print("Mode: OFB")
            print("Key: {}".format(key))
            print("IV: {}".format(iv))
            res = input("Continue? (y/n): ")
            if res == "y":
                encryption = AES(file, "OFB", key, iv)
                encryption.decrypt()
            else:
                E.error_message("PROGRAM_STOP")
        else:
            E.error_message("NO_AES_MODE_SPECIFIED")

    def decrypt_RC4(self, file):
        key = self.find_param("-k")
        key = ast.literal_eval(key)

        if not key:
            E.error_message("NO_RC4_KEY_FOUND")
            return

        self.print_file_details(file)
        print("Algorithm: RC4")
        print("Key: {}".format(key))
        res = input("Continue? (y/n): ")
        if res == "y":
            encryption = RC4(file, key)
            encryption.decrypt()
        else:
            print("Program stopped")

    def decrypt_TwoFish(self, file):
        key = self.find_param("-k")
        key = ast.literal_eval(key)

        if not key:
            E.error_message("NO_TWOFISH_KEY_FOUND")
            return

        if len(key) not in [16, 24, 32]:
            E.error_message("TWOFISH_KEY_LENGTH_ERROR")
            return

        self.print_file_details(file)
        print("Algorithm: TwoFish")
        print("Key: {}".format(key))
        res = input("Continue? (y/n): ")
        if res == "y":
            encryption = TwoFish(file, key)
            encryption.decrypt()
        else:
            print("Program stopped")

    def decrypt_Salsa(self, file):
        key = self.find_param("-k")
        key = ast.literal_eval(key)

        if not key:
            E.error_message("NO_SALSA_KEY_FOUND")
            return

        if len(key) != 32:
            E.error_message("SALSA_KEY_LENGTH_ERROR")
            return

        nonce = self.find_param("-n")
        nonce = ast.literal_eval(nonce)

        if not nonce:
            E.error_message("NO_SALSA_NONCE_FOUND")
            return

        if len(nonce) != 8:
            E.error_message("SALSA_NONCE_LENGTH_ERROR")
            return

        self.print_file_details(file)
        print("Algorithm: Salsa20/12")
        print("Key: {}".format(key))
        print("Nonce: {}".format(nonce))
        res = input("Continue? (y/n): ")
        if res == "y":
            encryption = Salsa20(file, key, nonce)
            encryption.decrypt()
        else:
            print("Program stopped")

    def print_file_details(self, file):
        filename = os.path.splitext(file)[0]
        extension = os.path.splitext(file)[1]
        size = os.path.getsize(file)
        print("File name: " + filename)
        print("File extension: " + extension)
        print("File size: " + str(size) + " bytes")

    def hashVerifyStart(self):
        file1 = self.findParam("-f1")
        if not file1:
            E.error_message("NO_INPUT_FILE_1_SPECIFIED")
            return
        file2 = self.findParam("-f2")
        if not file2:
            E.error_message("NO_INPUT_FILE_2_SPECIFIED")
            return

        with open(file1, 'rb') as f1, open(file2, 'rb') as f2:
            bytes1 = f1.read()
            bytes2 = f2.read()

            if bytes1 == bytes2:
                print("Hash values are equal")
            else:
                print("Hash values are different")

    def hashStart(self):
        print("Hashing process")

        filename = self.findParam("-f")
        if not filename:
            E.error_message("NO_INPUT_FILE_SPECIFIED")
            return

        output = self.findParam("-o")
        if not output:
            E.error_message("NO_OUTPUT_FILE_SPECIFIED")
            return

        self.print_file_details(filename)
        print("Algorithm: SHA256")
        res = input("Continue? (y/n): ")
        if res == "y":
            hash = SHA256(filename, output)
            hash.sha256_streaming()
        else:
            E.error_message("PROGRAM_STOP")

    def generate_byte_key(self):
        length = self.find_param("-l")
        length = int(length)

        if length <= 0:
            E.error_message("GENERATE_KEY_LESS_THAN_0")
            return

        key = [random.randint(0, 255) for _ in range(length)]
        key_bytes = bytes(key)

        print(key_bytes)
