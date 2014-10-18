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
@author:       Csaba Barta and Laszlo Toth
@license:      GNU General Public License 2.0 or later
@contact:      csaba.barta@gmail.com
"""

from framework.addrspace import HiveFileAddressSpace
from framework.win32.hashdump import sid_to_key, get_bootkey
from Crypto.Hash import MD5
from Crypto.Cipher import ARC4,DES
from struct import unpack,pack
from binascii import *
import sys
import datetime

def get_syskey(syshive_fname):
    sysaddr = HiveFileAddressSpace(syshive_fname)
    bootkey = get_bootkey(sysaddr)
    return bootkey

def ds_decrypt_pek(bootkey, enc_pek):
    md5=MD5.new()
    md5.update(bootkey)
    for i in range(1000):
        md5.update(enc_pek[0:16])
    rc4_key=md5.digest();
    rc4 = ARC4.new(rc4_key)
    pek=rc4.encrypt(enc_pek[16:])
    return pek[36:]

def ds_decrypt_with_pek(pek, enc_hash):
    md5=MD5.new()
    md5.update(pek)
    md5.update(enc_hash[0:16])
    rc4_key=md5.digest();
    rc4 = ARC4.new(rc4_key)
    return rc4.encrypt(enc_hash[16:])

def ds_decrypt_single_hash(rid, enc_hash):
    (des_k1,des_k2) = sid_to_key(rid)
    d1 = DES.new(des_k1, DES.MODE_ECB)
    d2 = DES.new(des_k2, DES.MODE_ECB)
    hash = d1.decrypt(enc_hash[:8]) + d2.decrypt(enc_hash[8:])
    return hash


def decrypt_user_hash(hiveName,rawRid,rawPekKey,rawNTLMHash):
    
    #get the bootkey from the system hive
    bootkey = get_syskey(hiveName)

    if (bootkey == ""):
        sys.stdout.write("Bootkey cannot be retrieved\n")
        exit

    # print "bootkey:",bootkey

    rid = rid = int(rawRid[48:],16)
    # print "rid:",rid

    enc_pek = unhexlify(rawPekKey[16:])
    pek = ds_decrypt_pek(bootkey, enc_pek)

    pek_enc_ntlm = unhexlify(rawNTLMHash[16:])
    enc_ntlm = ds_decrypt_with_pek(pek, pek_enc_ntlm)
    ntlm = ds_decrypt_single_hash(rid, enc_ntlm)

    sys.stdout.write(ntlm.encode('hex').upper()+":::")
    print ""


def ds_dump_file_hashes(syshive_fname, datatable, include_disabled=False, include_locked=False):
    user_index    = -1
    rid_index     = -1
    user_accountcontrol_index = -1
    pek_key_index = -1
    pek_cn_index  = -1
    pek_enc_lm_index = -1
    pek_enc_nt_index = -1

    enc_pek = ""
    pek     = ""

    #open the file containing the dump
    f = open(datatable)
    lines = f.readlines()

    #get the bootkey from the system hive
    bootkey = get_syskey(syshive_fname)

    if (bootkey == ""):
        sys.stdout.write("Bootkey cannot be retrieved\n")
        exit

    #determine column indexes    
    tmp = lines[0].split("\t")
    for col in range(0, len(tmp)-1):
        if (tmp[col] == "ATTm3"):
            user_index = col
        if (tmp[col] == "ATTr589970"):
            rid_index = col
        if (tmp[col] == "ATTj589832"):
            user_accountcontrol_index = col
        if (tmp[col] == "ATTk590689"):
            pek_key_index = col
        if (tmp[col] == "ATTk589879"):
            pek_enc_lm_index = col
        if (tmp[col] == "ATTk589914"):
            pek_enc_nt_index = col
        if (tmp[col] == "ATTm590715"):
            pek_cn_index = col

    #check if every column was found
    if (user_index == -1):
        sys.stdout.write("Username column not found\n")
        exit
    if (rid_index == -1):
        sys.stdout.write("SID column not found\n")
        exit
    if (pek_enc_lm_index == -1):
        sys.stdout.write("LM hash column not found\n")
        exit
    if (pek_enc_nt_index == -1):
        sys.stdout.write("NT hash column not found\n")
        exit

    if (pek_key_index == -1):
        sys.stdout.write("Encrypted PEK key column not found\n")
        exit
    if (pek_cn_index == -1):
        sys.stdout.write("PEK CN column not found\n")
        exit

    #get the PEK key
    for line in lines[1:]:
        tmp = line.split("\t")
        if (tmp[pek_key_index] != ""):
            enc_pek = unhexlify(tmp[pek_key_index][16:])
            pek     = ds_decrypt_pek(bootkey, enc_pek)

    if (pek == ""):
        sys.stdout.write("PEK cannot be decrypted\n")
        exit

    #get user hashes
    for line in lines[1:]:
        tmp = line.split("\t")
	
        #if the line contains the PEK then it contains no user hash	
        if (tmp[pek_key_index] != ""):
            continue

        #check if the user account is disabled
        if ((int(tmp[user_accountcontrol_index]) & 2)  > 0) and (include_disabled == False):
            continue

        #check if the user account is locked
        if ((int(tmp[user_accountcontrol_index]) & 16)  > 0) and (include_locked == False):
            continue

        #get the user name
        user = tmp[user_index]
        #get the RID of the user
        rid = int(tmp[rid_index][48:],16)
        #get encrypted hashes
        pek_enc_lm   = unhexlify(tmp[pek_enc_lm_index][16:])
        pek_enc_ntlm = unhexlify(tmp[pek_enc_nt_index][16:])

        #decrypt the hashes
        enc_lm   = ds_decrypt_with_pek(pek, pek_enc_lm)
        enc_ntlm = ds_decrypt_with_pek(pek, pek_enc_ntlm)

        lm   = ds_decrypt_single_hash(rid, enc_lm)
        ntlm = ds_decrypt_single_hash(rid, enc_ntlm)


        #do the output
        sys.stdout.write(user+":")
        sys.stdout.write(str(rid))
        if (lm == ""):
            sys.stdout.write(":NO PASSWORD*********************:")
        else:
            sys.stdout.write(":"+lm.encode('hex').upper()+":")
        if (ntlm == ""):
            sys.stdout.write("NO PASSWORD*********************:::")
        else:
            sys.stdout.write(ntlm.encode('hex').upper()+":::")
        sys.stdout.write("\n")

def ds_dump_file_hash_history(syshive_fname, datatable, include_disabled=False, include_locked=False):
    user_index    = -1
    rid_index     = -1
    user_accountcontrol_index = -1
    pek_key_index = -1
    pek_cn_index  = -1
    pek_enc_lm_hist_index = -1
    pek_enc_nt_hist_index = -1

    enc_pek = ""
    pek     = ""

    #open the file containing the dump
    f = open(datatable)
    lines = f.readlines()

    #get the bootkey from the system hive
    bootkey = get_syskey(syshive_fname)

    if (bootkey == ""):
        sys.stdout.write("Bootkey cannot be retrieved\n")
        exit

    #determine column indexes    
    tmp = lines[0].split("\t")
    for col in range(0, len(tmp)-1):
        if (tmp[col] == "ATTm3"):
            user_index = col
        if (tmp[col] == "ATTr589970"):
            rid_index = col
        if (tmp[col] == "ATTj589832"):
            user_accountcontrol_index = col
        if (tmp[col] == "ATTk590689"):
            pek_key_index = col
        if (tmp[col] == "ATTk589984"):
            pek_enc_lm_hist_index = col
        if (tmp[col] == "ATTk589918"):
            pek_enc_nt_hist_index = col
        if (tmp[col] == "ATTm590715"):
            pek_cn_index = col

    #check if every column was found
    if (user_index == -1):
        sys.stdout.write("Username column not found\n")
        exit
    if (rid_index == -1):
        sys.stdout.write("SID column not found\n")
        exit
    if (pek_enc_lm_hist_index == -1):
        sys.stdout.write("LM hash column not found\n")
        exit
    if (pek_enc_nt_hist_index == -1):
        sys.stdout.write("NT hash column not found\n")
        exit

    if (pek_key_index == -1):
        sys.stdout.write("Encrypted PEK key column not found\n")
        exit
    if (pek_cn_index == -1):
        sys.stdout.write("PEK CN column not found\n")
        exit

    #get the PEK key
    for line in lines[1:]:
        tmp = line.split("\t")
        if (tmp[pek_key_index] != ""):
            enc_pek=unhexlify(tmp[pek_key_index][16:])
            pek=ds_decrypt_pek(bootkey, enc_pek)

    if (pek == ""):
        sys.stdout.write("PEK cannot be decrypted\n")
        exit

    #get user hashes
    for line in lines[1:]:
        tmp = line.split("\t")
	
        #if the line contains the PEK then it contains no user hash	
        if (tmp[pek_key_index] != ""):
            continue

        #check if the user account is disabled
        if ((int(tmp[user_accountcontrol_index]) & 2)  > 0) and (include_disabled == False):
            continue

        #check if the user account is locked
        if ((int(tmp[user_accountcontrol_index]) & 16)  > 0) and (include_locked == False):
            continue

        #get the user name
        user = tmp[user_index]
        #get the RID of the user
        rid = int(tmp[rid_index][48:],16)

        #get encrypted history
        pek_enc_lm   = unhexlify(tmp[pek_enc_lm_hist_index][16:])
        pek_enc_ntlm = unhexlify(tmp[pek_enc_nt_hist_index][16:])

        enc_lm   = ds_decrypt_with_pek(pek, pek_enc_lm)
        enc_ntlm = ds_decrypt_with_pek(pek, pek_enc_ntlm)

        #decrypt the hashes
        for hindex in range(0,len(enc_ntlm)/16):
            ntlm = ds_decrypt_single_hash(rid, enc_ntlm[hindex*16:(hindex+1)*16])
            lm   = ds_decrypt_single_hash(rid, enc_lm[hindex*16:(hindex+1)*16])

            #do the output
            if hindex == 0:
                sys.stdout.write(user+":")
            else:
                sys.stdout.write(user+"_history"+str(hindex-1)+":")

            sys.stdout.write(str(rid))

            if (lm == ""):
                sys.stdout.write(":NO PASSWORD*********************:")
            else:
                sys.stdout.write(":"+lm.encode('hex').upper()+":")
            if (ntlm == ""):
                sys.stdout.write("NO PASSWORD*********************:::")
            else:
                sys.stdout.write(ntlm.encode('hex').upper()+":::")
            sys.stdout.write("\n")

def ds_dump_file_userinfo(datatable):
    user_name_index           = -1
    user_sid_index            = -1
    user_lastpwdchange_index  = -1
    user_accountcontrol_index = -1
    user_accountexpire_index  = -1
    user_badpwdcount_index    = -1
    user_lastlogin_index      = -1

    pek_key_index             = -1

    _FILETIME_null_date = datetime.datetime(1601, 1, 1, 0, 0, 0)
    
    #open the file containing the dump
    f=open(datatable)
    lines=f.readlines()

    #determine column indexes    
    tmp=lines[0].split("\t")
    for col in range(0, len(tmp)-1):
        if (tmp[col] == "ATTm3"):
            user_name_index = col
        if (tmp[col] == "ATTr589970"):
            user_sid_index = col
        if (tmp[col] == "ATTq589920"):
            user_lastpwdchange_index = col
        if (tmp[col] == "ATTj589832"):
            user_accountcontrol_index = col
        if (tmp[col] == "ATTq589983"):
            user_accountexpire_index = col
        if (tmp[col] == "ATTj589993"):
            user_badpwdcount_index = col
        if (tmp[col] == "ATTq589876"):
            user_lastlogin_index = col
        if (tmp[col] == "ATTk590689"):
            pek_key_index = col


    #check if every column was found
    if (user_name_index == -1):
        sys.stdout.write("Username column not found\n")
        exit
    if (user_sid_index == -1):
        sys.stdout.write("SID column not found\n")
        exit
    if (user_lastpwdchange_index == -1):
        sys.stdout.write("Last password change column not found\n")
        exit
    if (user_accountcontrol_index == -1):
        sys.stdout.write("UAC column not found\n")
        exit
    if (user_accountexpire_index == -1):
        sys.stdout.write("Account expire column not found\n")
        exit

    #Iterate through lines
    for line in lines[1:]:
        tmp = line.split("\t")
	
        #if the line contains the PEK then it contains no user hash	
        if (tmp[pek_key_index] != ""):
            continue

        #get the user name
        user = tmp[user_name_index]
        #get the RID of the user
        rid = int(tmp[user_sid_index][48:],16)

        acctype = ""        
        if (int(tmp[user_accountcontrol_index]) & 512) > 0:
            acctype = "NORMAL_ACCOUNT"
        if (int(tmp[user_accountcontrol_index]) & 2048) > 0:
            acctype = "INTERDOMAIN_TRUST_ACCOUNT"
        if (int(tmp[user_accountcontrol_index]) & 4096) > 0:
            acctype = "WORKSTATION_TRUST_ACCOUNT"
        if (int(tmp[user_accountcontrol_index]) & 8192) > 0:
            acctype = "SERVER_TRUST_ACCOUNT"

        locked   = (int(tmp[user_accountcontrol_index]) & 16) > 0
        disabled = (int(tmp[user_accountcontrol_index]) & 2)  > 0

        pwdexpired      = (int(tmp[user_accountcontrol_index]) & 8388608) > 0
        pwdneverexpires = (int(tmp[user_accountcontrol_index]) & 65536) > 0
        pwdcantchange   = (int(tmp[user_accountcontrol_index]) & 64) > 0

        if tmp[user_badpwdcount_index] != "":
            badpwdcount = (int(tmp[user_badpwdcount_index]))
        else:
            badpwdcount = -1

        if tmp[user_lastpwdchange_index] == "0":
            lastpwdchange = 0
        else:
            lastpwdchange = _FILETIME_null_date + datetime.timedelta(microseconds=int(tmp[user_lastpwdchange_index]) / 10)

        if tmp[user_lastlogin_index] == "0" or tmp[user_lastlogin_index] == "":
            lastlogin     = 0
        else:
            lastlogin     = _FILETIME_null_date + datetime.timedelta(microseconds=int(tmp[user_lastlogin_index]) / 10)
        
        if (int(tmp[user_accountexpire_index]) >= int(9223372036854775807)) or (int(tmp[user_accountexpire_index]) == 0):
            accountexpire = 0
        else:
            accountexpire = _FILETIME_null_date + datetime.timedelta(microseconds=int(tmp[user_accountexpire_index]) / 10)

        #do the output
        sys.stdout.write(user + " - ")
        sys.stdout.write(str(rid))
        sys.stdout.write("\n\tAccount type      = " + acctype)

        if accountexpire == 0:
            sys.stdout.write("\n\tAccount expires   = Never")
        else:
            sys.stdout.write("\n\tAccount expires   = " + str(accountexpire) + " UTC")

        sys.stdout.write("\n\tAccount locked    = " + str(locked))
        sys.stdout.write("\n\tAccount disabled  = " + str(disabled))

        if lastlogin == 0:
            sys.stdout.write("\n\tLast login        = Never")
        else:
            sys.stdout.write("\n\tLast login        = " + str(lastlogin) + " UTC")

        sys.stdout.write("\n\tBad PWD count     = " + str(badpwdcount))

        if lastpwdchange == 0:
            sys.stdout.write("\n\tPWD last change   = Never")
        else:
            sys.stdout.write("\n\tPWD last change   = " + str(lastpwdchange) + " UTC")

        sys.stdout.write("\n\tPWD never expires = " + str(pwdneverexpires))
        sys.stdout.write("\n\tPWD expired       = " + str(pwdexpired))
        sys.stdout.write("\n\tPWD cannot change = " + str(pwdcantchange))
        sys.stdout.write("\n\n")
