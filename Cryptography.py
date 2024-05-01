import streamlit as st
import pyDes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import random
import sympy
from sympy import mod_inverse

# Function for DES encryption
def des_encryption(key, plaintext):
    des = pyDes.des(key, pyDes.ECB, pad=None, padmode=pyDes.PAD_PKCS5)
    ciphertext = des.encrypt(plaintext)
    return ciphertext

# Function for DES decryption
def des_decryption(key, ciphertext):
    des = pyDes.des(key, pyDes.ECB, pad=None, padmode=pyDes.PAD_PKCS5)
    plaintext = des.decrypt(ciphertext)
    return plaintext

# Function for AES encryption
def aes_encryption(key, iv, plaintext):
    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(128).padder()
    padded_plaintext = padder.update(plaintext) + padder.finalize()
    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()
    return ciphertext

# Function for AES decryption
def aes_decryption(key, iv, ciphertext):
    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
    return plaintext

# Function for RSA key generation, encryption, and decryption
def rsa_operations(plaintext):
    def gcd(a, b):
        while b != 0:
            a, b = b, a % b
        return a

    def is_prime(num, k=10):
        return sympy.isprime(num)

    def generate_prime(bits):
        num = random.getrandbits(bits)
        while not is_prime(num):
            num = random.getrandbits(bits)
        return num

    def generate_keypair(bits):
    # Generate one distinct prime number p
        p = generate_prime(bits)

    # Find another prime number q close to p
        q = generate_prime(bits)
        while abs(p - q) < 2**((bits-1)//2):
            q = generate_prime(bits)

    # Calculate n (modulus)
        n = p * q

    # Calculate Euler's totient function (φ)
        phi = (p - 1) * (q - 1)

    # Choose an integer e such that 1 < e < φ(n) and gcd(e, φ(n)) = 1
        e = random.randrange(2**16, phi)
        while gcd(e, phi) != 1:
            e = random.randrange(2**16, phi)

    # Calculate the modular multiplicative inverse of e modulo φ(n)
        d = mod_inverse(e, phi)

    # Public key: (e, n), Private key: (d, n)
        public_key = (e, n)
        private_key = (d, n)

        return public_key, private_key

    def encrypt(message, public_key):
        e, n = public_key
        cipher = [pow(ord(char), e, n) for char in message]
        return cipher

    def decrypt(encrypted_message, private_key):
        d, n = private_key
        plain = [chr(pow(char, d, n)) for char in encrypted_message]
        return ''.join(plain)

    # Generate RSA key pair
    public_key, private_key = generate_keypair(1024)

    # Encrypt the message
    cipher = encrypt(plaintext, public_key)

    # Decrypt the message
    dplain = decrypt(cipher, private_key)

    return public_key, private_key, cipher, dplain

# Function for Diffie-Hellman key exchange
def diffie_hellman():
    def mod_exp(base, exponent, modulus):
        """Modular exponentiation: (base^exponent) mod modulus."""
        result = 1
        while exponent > 0:
            if exponent % 2 == 1:
                result = (result * base) % modulus
            exponent //= 2
            base = (base * base) % modulus
        return result

    # Common prime and base (generator) for the exchange
    prime = 23
    base = 5

    # Alice's private key
    private_key_A = 6
    # Alice's public key
    public_key_A = mod_exp(base, private_key_A, prime)

    # Bob's private key
    private_key_B = 15
    # Bob's public key
    public_key_B = mod_exp(base, private_key_B, prime)

    # Shared secret computation
    shared_secret_A = mod_exp(public_key_B, private_key_A, prime)
    shared_secret_B = mod_exp(public_key_A, private_key_B, prime)

    return shared_secret_A, shared_secret_B
# Function for hashing
def hashing(plaintext):
    return hash(plaintext)

# Main function to display the Streamlit app
def main():
    st.title("Cryptography & Hashing")

    # Selection box for choosing symmetric, asymmetric, or hashing
    cryptosystem_type = st.selectbox("Select one of the Options", ["Symmetric Cryptography", "Asymmetric Cryptography", "Hashing"])

    if cryptosystem_type == "Symmetric Cryptography":
        # Radio button for selecting DES or AES under symmetric cryptosystems
        symmetric_algorithm = st.radio("Select Symmetric Algorithm", ["DES", "AES"])

        if symmetric_algorithm == "DES":
            key = b'blahblee'
            plaintext = st.text_input("Enter the Plaintext")
            if st.button("Encrypt"):
                if key and plaintext:
                    ciphertext = des_encryption(key, plaintext.encode())
                    st.write("Ciphertext:", ciphertext.hex())
                else:
                    st.write("Please enter both key and plaintext.")

            ciphertext_input = st.text_input("Enter the Ciphertext (in hex)")
            if st.button("Decrypt"):
                if key and ciphertext_input:
                    ciphertext = bytes.fromhex(ciphertext_input)
                    plaintext = des_decryption(key, ciphertext).decode()
                    st.write("Decrypted Plaintext:", plaintext)

        elif symmetric_algorithm == "AES":
            key = b'blahbleeblehblue'
            iv = b'bippitybopityboo'
            plaintext = st.text_input("Enter the Plaintext")
            if st.button("Encrypt"):
                if key and iv and plaintext:
                    ciphertext = aes_encryption(key, iv, plaintext.encode())
                    st.write("Ciphertext:", ciphertext.hex())
                else:
                    st.write("Please enter key, IV, and plaintext.")

            ciphertext_input = st.text_input("Enter the Ciphertext (in hex)")
            if st.button("Decrypt"):
                if key and iv and ciphertext_input:
                    ciphertext = bytes.fromhex(ciphertext_input)
                    plaintext = aes_decryption(key, iv, ciphertext).decode()
                    st.write("Decrypted Plaintext:", plaintext)

    elif cryptosystem_type == "Asymmetric Cryptography":
        # Radio button for selecting RSA or Diffie-Hellman under asymmetric cryptosystems
        asymmetric_algorithm = st.radio("Select Asymmetric Algorithm", ["RSA", "Diffie-Hellman"])

        if asymmetric_algorithm == "RSA":
            plaintext = st.text_input("Enter the Plaintext")
            if st.button("Encrypt"):
                if plaintext:
                    public_key, private_key, cipher, dplain = rsa_operations(plaintext)
                    st.write("Public Key for RSA:", public_key)
                    st.write("Private Key for RSA:", private_key)
                    st.write("Ciphertext for RSA:", cipher)
                    st.write("Decrypted Plaintext for RSA:", dplain)
                
        elif asymmetric_algorithm == "Diffie-Hellman":
            if st.button("Execute"):
                shared_secret_A, shared_secret_B = diffie_hellman()
                st.write("Diffie-Hellman Algorithm executed successfully.")
                st.write("Shared Secret for Alice:", shared_secret_A)
                st.write("Shared Secret for Bob:", shared_secret_B)
    # Hashing
    elif cryptosystem_type == "Hashing":
        plaintext_hashing = st.text_input("Enter a String for Hashing")
        if st.button("Hash"):
            if plaintext_hashing:
                hashed_value = hashing(plaintext_hashing)
                st.write("Hash Value:", hashed_value)
            else:
                st.write("Please enter a string for hashing.")

if __name__ == "__main__":
    main()