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


def encryptionStart():
    print("Encryption process")

    if len(sys.argv) < 4:
        print("Use -f to specify the file for encryption")
        return

    if len(sys.argv) < 6:
        print("Use -alg to specify the encryption algorithm")
        print("Use -h -alg to see the list of available algorithms")
        return

    filename = sys.argv[3]
    algorithm = sys.argv[5]

    if algorithm == "AES":
        print("AES")
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
                printHelper.printHelpExtra(extraArg)
            else:
                printHelper.printHelp()
        else:
            printHelper.printHelp()
    else:
        printHelper.printHelp()
