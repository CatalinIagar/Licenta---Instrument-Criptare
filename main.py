import sys
import os

import printHelper

def printFileDetails(file):
    filename = os.path.splitext(file)[0]
    extension = os.path.splitext(file)[1]
    size = os.path.getsize(file)
    print("File name: " + filename)
    print("File extension: " + extension)
    print("File size: " + str(size) + " bytes")

def encryptAES(file):
    if len(sys.argv) < 8 or sys.argv[6] != "-m":
        print("Use -m to specify AES mode")
        return

    mode = sys.argv[7]

    if len(sys.argv) < 10 or sys.argv[8] != "-k":
        print("Use -k to specify encryption key")
        return

    key = sys.argv[9]
    if len(key) != 16:
        print("Invalid key")
        print("Key must be 128-bit long (16 characters)")
        return

    if mode == "ECB":
        print("ECB")
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

    if len(sys.argv) < 4 or sys.argv[2] != "-f":
        print("Use -f to specify the file for encryption")
        return

    if len(sys.argv) < 6 or sys.argv[4] != "-alg":
        print("Use -alg to specify the encryption algorithm")
        print("Use -h -alg to see the list of available algorithms")
        return

    filename = sys.argv[3]
    algorithm = sys.argv[5]

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
