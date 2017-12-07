import sys, os, logging

import binascii
import random, getpass
from pyblake2 import blake2b
from bitstring import BitArray
from pure25519 import ed25519_oop as ed25519
from simplecrypt import encrypt, decrypt
from configparser import SafeConfigParser


default_representative = \
    'xrb_16k5pimotz9zehjk795wa4qcx54mtusk8hc5mdsjgy57gnhbj3hj6zaib4ic'

def read_encrypted(password, filename, string=True):
    with open(filename, 'rb') as input:
        ciphertext = input.read()
        plaintext = decrypt(password, ciphertext)
        if string:
            return plaintext.decode('utf8')
        else:
            return plaintext

def write_encrypted(password, filename, plaintext):
    with open(filename, 'wb') as output:
        ciphertext = encrypt(password, plaintext)
        output.write(ciphertext)

def xrb_account(address):
    # Given a string containing an XRB address, confirm validity and
    # provide resulting hex address
    if len(address) == 64 and (address[:4] == 'xrb_'):
        # each index = binary value, account_lookup[0] == '1'
        account_map = "13456789abcdefghijkmnopqrstuwxyz"
        account_lookup = {}
        # populate lookup index with prebuilt bitarrays ready to append
        for i in range(32):
            account_lookup[account_map[i]] = BitArray(uint=i,length=5)
    
        # we want everything after 'xrb_' but before the 8-char checksum
        acrop_key = address[4:-8]
        # extract checksum
        acrop_check = address[-8:]
        
        # convert base-32 (5-bit) values to byte string by appending each
        # 5-bit value to the bitstring, essentially bitshifting << 5 and
        # then adding the 5-bit value.
        number_l = BitArray()
        for x in range(0, len(acrop_key)):
            number_l.append(account_lookup[acrop_key[x]])
    # reduce from 260 to 256 bit (upper 4 bits are never used as account
    # is a uint256)
        number_l = number_l[4:]
    
        check_l = BitArray()
        for x in range(0, len(acrop_check)):
            check_l.append(account_lookup[acrop_check[x]])

    # reverse byte order to match hashing format
        check_l.byteswap()
        result = number_l.hex.upper()
        
        # verify checksum
        h = blake2b(digest_size=5)
        h.update(number_l.bytes)
        if (h.hexdigest() == check_l.hex):
            return result
        else:
            return False
    else:
        return False

def account_xrb(account):
    # Given a string containing a hex address, encode to public address
    # format with checksum
    # each index = binary value, account_lookup['00001'] == '3'
    account_map = "13456789abcdefghijkmnopqrstuwxyz"
    account_lookup = {}
    # populate lookup index for binary string to base-32 string character
    for i in range(32):
        account_lookup[BitArray(uint=i,length=5).bin] = account_map[i]
    # hex string > binary
    account = BitArray(hex=account)

# get checksum
    h = blake2b(digest_size=5)
    h.update(account.bytes)
    checksum = BitArray(hex=h.hexdigest())
    
    # encode checksum
    # swap bytes for compatibility with original implementation
    checksum.byteswap()
    encode_check = ''
    for x in range(0,int(len(checksum.bin)/5)):
        # each 5-bit sequence = a base-32 character from account_map
        encode_check += account_lookup[checksum.bin[x*5:x*5+5]]
    
    # encode account
    encode_account = ''
    while len(account.bin) < 260:
        # pad our binary value so it is 260 bits long before conversion
        # (first value can only be 00000 '1' or 00001 '3')
        account = '0b0' + account
    for x in range(0,int(len(account.bin)/5)):
        # each 5-bit sequence = a base-32 character from account_map
        encode_account += account_lookup[account.bin[x*5:x*5+5]]

    # build final address string
    return 'xrb_'+encode_account+encode_check

def private_public(private):
    return ed25519.SigningKey(private).get_verifying_key().to_bytes()

def seed_account(seed, index):
    # Given an account seed and index #, provide the account private and
    # public keys
    h = blake2b(digest_size=32)
    
    seed_data = BitArray(hex=seed)
    seed_index = BitArray(int=index,length=32)
    
    h.update(seed_data.bytes)
    h.update(seed_index.bytes)
    
    account_key = BitArray(h.digest())
    return account_key.bytes, private_public(account_key.bytes)

parser = SafeConfigParser()
config_files = parser.read('config.ini')

if len(config_files) == 0:

    wallet_seed = input('Enter your wallet seed: ')
    
    while True:
        password = getpass.getpass('Enter password: ')
        password_confirm = getpass.getpass('Confirm password: ')
        if password == password_confirm:
            break
        print("Password Mismatch!")

    print("Wallet Seed (make a copy of this in a safe place!): ", wallet_seed)
    write_encrypted(password, 'seed.txt', wallet_seed)

    cfgfile = open("config.ini",'w')
    parser.add_section('wallet')
    priv_key, pub_key = seed_account(str(wallet_seed), 0)
    public_key = str(binascii.hexlify(pub_key), 'ascii')
    print("Public Key: ", str(public_key))
    
    account = account_xrb(str(public_key))
    print("Account Address: ", account)
    
    parser.set('wallet', 'account', account)
    parser.set('wallet', 'index', '0')
    parser.set('wallet', 'representative', default_representative)
    parser.set('wallet', 'pow_source', 'internal')
    parser.set('wallet', 'server', 'wss://yapraiwallet.space')
    parser.set('wallet', 'cached_pow', '')
    parser.set('wallet', 'balance', '0')
    parser.set('wallet', 'open', '0')
    
    parser.write(cfgfile)
    cfgfile.close()
    print('Seed imported and config file written\nClosing')
else:
    print('Config file already present\nClosing')
