import sys


def encryptionStart():
    print("Encryption process")

    if len(sys.argv) < 4:
        print("Missing arguments")
        printHelp()
        return
    else:
        print(sys.argv[3])

def decryptionStart():
    print("Decryption process")


def printHelp():
    print("First argument:")
    print("    encrypt - for encryption mode")
    print("    decrypt - for decryption mode")
    print("2nd argument:")
    print("    -f - specify the file you want to encrypt/decrypt")

if __name__ == '__main__':
    if len(sys.argv) > 1:
        if sys.argv[1] == "encrypt":
            encryptionStart()
        elif sys.argv[1] == "decrypt":
            decryptionStart()
        elif sys.argv[1] == "-h":
            printHelp()
        else:
            printHelp()
    else:
        printHelp()
