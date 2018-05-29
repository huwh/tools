#!/usr/bin/env python

import hmac, base64, struct, hashlib, time

def calGoogleCode(secretKey):
    input = int(time.time())//30
    key = base64.b32decode(secretKey.replace(' ','').upper())
    msg = struct.pack(">Q", input)
    googleCode = hmac.new(key, msg, hashlib.sha1).digest()
    o = ord(googleCode[19]) & 15
    googleCode = str((struct.unpack(">I", googleCode[o:o+4])[0] & 0x7fffffff) % 1000000)
    if len(googleCode) != 6:
        googleCode = '0'*(6-len(googleCode)) + googleCode
    return googleCode

