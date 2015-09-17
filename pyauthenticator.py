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
    print("  -s, --secret\t Your base-32 encoded secret. If not supplied, the environment variable GOOGLE_AUTH_SECRET is used")
    print("  -h, --help\t This help message\n")
    

def auth_code(secret):
    key = base64.b32decode(secret)

    message = math.floor(time.time() / 30).to_bytes(8, byteorder='big')
    ghmac = hmac.new(key, message, hashlib.sha1)
    digest = bytearray(ghmac.digest())
    offset = digest[-1] & 0xF
    digest = digest[offset:]
    digest[0] = digest[0] & 0x7F
    authcode = int.from_bytes(digest[0:4], byteorder="big")
    #authcode = digest[0] << 24 | digest[1] << 16 | digest[2] << 8 | digest[3]

    authcode = authcode % 1000000
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
