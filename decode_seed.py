import sys, os, logging

import binascii
import random, getpass
from pyblake2 import blake2b
from bitstring import BitArray
from pure25519 import ed25519_oop as ed25519
from simplecrypt import encrypt, decrypt
from configparser import SafeConfigParser

def read_encrypted(password, filename, string=True):
    with open(filename, 'rb') as input:
        ciphertext = input.read()
        plaintext = decrypt(password, ciphertext)
        if string:
            return plaintext.decode('utf8')
        else:
            return plaintext

while True:
    password = getpass.getpass('Enter password: ')
    password_confirm = getpass.getpass('Confirm password: ')
    if password == password_confirm:
        break
    print("Password Mismatch!")

print('Decoding Now')
seed = read_encrypted(password, 'seed.txt', string=True)
print(seed)
