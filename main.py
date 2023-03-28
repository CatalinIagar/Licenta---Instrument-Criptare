import sys
import os

import printHelper
from Algorithms import AES

ALGORITHMS = ["AES", "TwoFish", "Salsa", "RC4", "RSA", "ECC"]
AES_MODES = ["ECB", "CBC", "CFB", "OFB"]

def findParam(param):
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

    if param == "-f":
        if os.path.isfile(value):
            return value
        else:
            print("File doesn't exist")
            return False

    if param == "-alg":
        if value in ALGORITHMS:
            return value
        else:
            print("Invalid algorithm")
            print("Use -h -alg to see the list of available algorithms")
            return False

    if param == "-m":
        if value in AES_MODES:
            return value
        else:
            print("Invalid mode")
            print("Use -h -alg to see the available modes of AES")
            return False

    if param == "-k":
        return value

def printFileDetails(file):
    filename = os.path.splitext(file)[0]
    extension = os.path.splitext(file)[1]
    size = os.path.getsize(file)
    print("File name: " + filename)
    print("File extension: " + extension)
    print("File size: " + str(size) + " bytes")

def encryptAES(file):
    mode = findParam("-m")
    if not mode:
        print("Use -m to specify the mode for AES")
        return

    key = findParam("-k")

    if not key:
        print("Use -k to specify the mode for AES")
        return

    if len(key) != 16:
        print("Invalid key")
        print("Key must be 128-bit long (16 characters)")
        return

    if mode == "ECB":
        printFileDetails(file)
        print("Algorithm: AES")
        print("Mode: EBC")
        print("Key: {}".format(key))
        res = input("Continue? (y/n): ")
        if res == "y":
            encryption = AES.AES(file, "ECB", key)
            encryption.encrypt()
        else:
            print("Program stopped")
    elif mode == "CBC":
        print("CBC")
    elif mode == "CFB":
        print("CFB")
    elif mode == "OFB":
        print("OFB")
    else:
        print("Invalid mode")
        print("Use -h -alg to see the list of available AES modes")

def encryptionStart():
    print("Encryption process")

    filename = findParam("-f")
    if not filename:
        print("Use -f to specify the file for encryption")
        return

    algorithm = findParam("-alg")
    if not algorithm:
        print("Use -alg to specify the encryption algorithm")
        print("Use -h -alg to see the list of available algorithms")
        return

    if algorithm == "AES":
        encryptAES(filename)
    elif algorithm == "TwoFish":
        print("TwoFish")
    elif algorithm == "Salsa":
        print("Salsa 20/12")
    elif algorithm == "RC4":
        print("RC4")
    else:
        print("Invalid algorithm")
        print("Use -h -alg to see the list of available algorithms")
        return

def decryptionStart():
    print("Decryption process")

if __name__ == '__main__':
    if len(sys.argv) > 1:
        if sys.argv[1] == "encrypt":
            encryptionStart()
        elif sys.argv[1] == "decrypt":
            decryptionStart()
        elif sys.argv[1] == "-h":
            if len(sys.argv) == 3:
                extraArg = sys.argv[2]
                printHelper.helpExtra(extraArg)
            else:
                printHelper.help()
        else:
            printHelper.missingArgs()
    else:
        printHelper.missingArgs()
