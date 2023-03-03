def help():
    print("First argument:")
    print("    encrypt -for encryption mode")
    print("    decrypt -for decryption mode")
    print("2nd argument:")
    print("    -f -specify the file you want to encrypt/decrypt")
    print("3rd argument:")
    print("    -alg -specify the algorithm you want to use")

def missingArgs():
    print("No arguments found.")
    print("To see the list of available arguments use -h")

def helpExtra(option):
    if option == "-alg":
        printAlg()
    else:
        print("Invalid argument")

def printAlg():
    print("\nASYMMETRIC ALGORITHMS:")
    print("    -AES-128")
    print("        -ECB Mode")
    print("        -CBC Mode")
    print("        -CFB Mode")
    print("        -OFB Mode")
    print("    -TwoFish")
    print("    -Salsa 20/12")
    print("    -RC4")

    print("\nSYMMETRIC ALGORITHMS:")
    print("    -RSA")
    print("    -ECC")