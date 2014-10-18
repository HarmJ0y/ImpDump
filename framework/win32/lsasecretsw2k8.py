# This file is part of creddump.
#
# creddump is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# creddump is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with creddump.  If not, see <http://www.gnu.org/licenses/>.

"""
@author:       Csaba Barta
@license:      GNU General Public License 2.0 or later
@contact:      csaba.barta@gmail.com
"""

from framework.win32.rawreg import *
from framework.addrspace import HiveFileAddressSpace
from framework.win32.hashdump import get_bootkey,str_to_key
from Crypto.Hash import SHA256
from Crypto.Cipher import AES


def get_lsa_key(secaddr, bootkey):
    root = get_root(secaddr)
    if not root:
        return None

    enc_reg_key = open_key(root, ["Policy", "PolEKList"])
    if not enc_reg_key:
        return None

    enc_reg_value = enc_reg_key.ValueList.List[0]
    if not enc_reg_value:
        return None

    obf_lsa_key = secaddr.read(enc_reg_value.Data.value,
            enc_reg_value.DataLength.value)

    lsa_key = decrypt_secret(obf_lsa_key, bootkey)

    return lsa_key[68:100]

def decrypt_secret(data, key):
    if not data:
        return None

    aeskey = ""
    sha256 = SHA256.new()
    sha256.update(key)
    for i in range(1000):
        sha256.update(data[28:60])
    aeskey = sha256.digest()

    secret = ""
    aes = AES.new(aeskey)
    for key_offset in range(0, len(data) - 60, 16):
        if (key_offset + 16) <= len(data) - 60:
            secret = secret + aes.decrypt(data[60 + key_offset:60 + key_offset + 16])

    return secret

def get_secret_by_name(secaddr, name, lsakey):
    root = get_root(secaddr)
    if not root:
        return None
    
    enc_secret_key = open_key(root, ["Policy", "Secrets", name, "CurrVal"])
    if not enc_secret_key:
        return None

    enc_secret_value = enc_secret_key.ValueList.List[0]
    if not enc_secret_value:
        return None

    enc_secret = secaddr.read(enc_secret_value.Data.value,
            enc_secret_value.DataLength.value)
    if not enc_secret:
        return None

    secret = decrypt_secret(enc_secret, lsakey)
    (secret_len,) = unpack("<L", secret[:4])

#    return secret
    return secret[16:16 + secret_len]

def get_secrets(sysaddr, secaddr):
    root = get_root(secaddr)
    if not root:
        return None

    bootkey = get_bootkey(sysaddr)
    lsakey = get_lsa_key(secaddr, bootkey)

    secrets_key = open_key(root, ["Policy", "Secrets"])
    if not secrets_key:
        return None
    
    secrets = {}
    for key in subkeys(secrets_key):
        sec_val_key = open_key(key, ["CurrVal"])
        if not sec_val_key:
            continue
        
        enc_secret_value = sec_val_key.ValueList.List[0]
        if not enc_secret_value:
            continue
        
        enc_secret = secaddr.read(enc_secret_value.Data.value,
                enc_secret_value.DataLength.value)
        if not enc_secret:
            continue

        secret = decrypt_secret(enc_secret, lsakey)
        (secret_len,) = unpack("<L", secret[:4])
#	secrets[key.Name] = secret
        secrets[key.Name] = secret[16:16+secret_len]
    return secrets

def get_file_secrets(sysfile, secfile):
    sysaddr = HiveFileAddressSpace(sysfile)
    secaddr = HiveFileAddressSpace(secfile)

    return get_secrets(sysaddr, secaddr)
