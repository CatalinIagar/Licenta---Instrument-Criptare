import math
import os
import pickle
import random

class RSA:

    def encrypt(self, file, key):
        public_key_str = key.strip()[1:-1]

        e, n = map(int, public_key_str.split(','))

        file_to_write = file + ".rsa"

        with open(file, "rb") as f, open(file_to_write, "wb") as w:
            while True:
                input_bytes = f.read()

                if not input_bytes:
                    break

                encrypted_bytes = [pow(c, e, n) for c in input_bytes]

                pickle.dump(encrypted_bytes, w)


    def decrypt(self, file, key):
        private_key_str = key.strip()[1:-1]

        d, n = map(int, private_key_str.split(','))

        file_to_write = file.replace(os.path.splitext(file)[1], "")

        with open(file, "rb") as f, open(file_to_write, "wb") as w:
            input_bytes = pickle.load(f)

            if not input_bytes:
                return

            decrypted_msg = [pow(c, d, n) for c in input_bytes]

            w.write(bytes(decrypted_msg))


    def generate_key(self):
        p = self.generate_prime_number()
        q = self.generate_prime_number()

        n = p * q

        phi_n = (p - 1) * (q - 1)

        e = self.public_exponent(phi_n)

        d = self.modular_inverse(e, phi_n)

        public_key = (e, n)
        private_key = (d, n)

        return public_key, private_key

    def generate_prime_number(self):
        while True:
            number = random.getrandbits(32)
            if self.is_prime(number):
                return number

    def is_prime(self, number):
        if number < 2:
            return False

        for i in range(2, math.isqrt(number) + 1):
            if number % i == 0:
                return False

        return True

    def public_exponent(self, phi_n):
        while True:
            e = random.randint(2, phi_n - 1)
            if math.gcd(e, phi_n) == 1:
                return e

    def modular_inverse(self, a, m):
        g, x, _ = self.extended_euclidean(a, m)
        if g == 1:
            return x % m

    def extended_euclidean(self, a, b):
        if a == 0:
            return b, 0, 1
        else:
            g, x, y = self.extended_euclidean(b % a, a)
            return g, y - (b // a) * x, x
