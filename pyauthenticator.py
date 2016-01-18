#!/usr/bin/env python3.4
import os
import sys
import getopt
import time
import math

import base64

import hashlib
import hmac

def usage():
    print("pyauthenticator.py [-s|--secret SECRET]\n")
    print("  -s, --secret\t Your base-32 encoded secret.")
    print("\t\t If not supplied, the environment variable GOOGLE_AUTH_SECRET is used")
    print("  -h, --help\t This help message\n")
    

def auth_code(secret):
    if not secret:
        usage()
        exit(1)
    key = base64.b32decode(secret)

    # The message we pass into the hmac is the current UNIX time, divided by 30
    # Converted into a 64-bit bytearray in big-endian
    message = math.floor(time.time() / 30).to_bytes(8, byteorder='big')

    # Seed a SHA-1 HMAC with the message and the secret key
    ghmac = hmac.new(key, message, hashlib.sha1)

    # Take the digest of the hmac and convert to a bytearray
    digest = bytearray(ghmac.digest())

    # The offset where we take the integer is determined from the last nibble
    # of the digest
    offset = digest[-1] & 0xF
    digest = digest[offset:]

    # Set the first bit of the digest to 0
    digest[0] &= 0x7F

    # Convert the bits of the digest, from offest to offset+4 to an integer
    authcode = int.from_bytes(digest[0:4], byteorder="big")

    # Take the integer modulo 1 million to give us a 5 or 6 digit number
    authcode %= 1000000

    # If the number is only 5 digits, a leading 0 is added to make it 6 digits
    if len(str(authcode)) != 6:
        authcode =  str(authcode).rjust(6, '0')
    return authcode

if __name__ == "__main__":
    try:
        opts, args = getopt.getopt(sys.argv[1:], "hs", ["help", "secret="])
    except getopt.GetoptError:
        usage()
        sys.exit(2)

    secret = os.getenv("GOOGLE_AUTH_SECRET")

    for opt, arg in opts:
        if opt in ["-h", "--help"]:
            usage()
            sys.exit(0)
        elif opt in ["-s", "--secret"]:
            secret = arg
        
    print(auth_code(secret))
