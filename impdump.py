#!/usr/bin/python

#
# ImpDump uses the creddump library (included) and was heavily adapted
# from creddump's code.
#
# All credit to the original author(s): Brendan Dolan-Gavitt and others
# See the README for full credits.
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
#

import sys, unicodedata
from binascii import *
from framework.win32.dshashdump import get_syskey,ds_decrypt_pek,ds_decrypt_single_hash,ds_decrypt_with_pek


# manually decrypt a single hash
def decUserHash(bootkey,rawPekKey,user,rawRID,rawLMhash,rawNTLMhash):
    
    # "rawRID" may already be the RID, or the full SID - if latter is true, truncate
    rid = int(rawRID,16) if len(rawRID)==8 else int(rawRID[48:],16)
    
    encPEK = unhexlify(rawPekKey[16:])
    pek = ds_decrypt_pek(bootkey, encPEK)

    if (not rawLMhash):
        rawLMhash = ""

    if rawLMhash.startswith("1100000000000000"):
        rawLMhash = rawLMhash[16:]
    if rawNTLMhash.startswith("1100000000000000"):
        rawNTLMhash = rawNTLMhash[16:]

    pekENClm = unhexlify(rawLMhash)
    pekENCntlm = unhexlify(rawNTLMhash)
    
    encLM = ds_decrypt_with_pek(pek, rawLMhash)
    encNTLM = ds_decrypt_with_pek(pek, pekENCntlm)
    
    lm = ds_decrypt_single_hash(rid, encLM)
    ntlm = ds_decrypt_single_hash(rid, encNTLM)
    
    out = user+":"+str(rid)
    if ((not encLM) or (encLM == "")):
        out+= ":aad3b435b51404eeaad3b435b51404ee:"
    else:
        out += ":"+lm.encode('hex')+":"
    if (ntlm == ""):
        out += "NO PASSWORD*********************:::"
    else:
        out += ntlm.encode('hex')+":::"
    
    return out


# decrypt user hash histories
def decUserHashHistory(bootkey, rawPekKey, user, rawRID, rawLMhashHistory, rawNTLMhashHistory):

    # "rawRID" may already be the RID, or the full SID - if latter is true, truncate
    rid = int(rawRID,16) if len(rawRID)==8 else int(rawRID[48:],16)
    
    encPEK = unhexlify(rawPekKey[16:])
    pek = ds_decrypt_pek(bootkey, encPEK)

    if rawLMhashHistory.startswith("1100000000000000"):
        rawLMhashHistory = rawLMhashHistory[16:]
    if rawNTLMhashHistory.startswith("1100000000000000"):
        rawNTLMhashHistory = rawNTLMhashHistory[16:]

    pekENClmHistory = unhexlify(rawLMhashHistory)
    pekENCntlmHistory = unhexlify(rawNTLMhashHistory)
    
    encLM = ds_decrypt_with_pek(pek, pekENClmHistory)
    encNTLM = ds_decrypt_with_pek(pek, pekENCntlmHistory)

    histories = []
    
    for hindex in range(0,len(encNTLM)/16):
        ntlm = ds_decrypt_single_hash(rid, encNTLM[hindex*16:(hindex+1)*16])
        lm   = ds_decrypt_single_hash(rid, encLM[hindex*16:(hindex+1)*16])

        if hindex == 0:
            out = user+":"+str(rid)
        else:
            out = user+"_history"+str(hindex-1)+":"+str(rid)

        if (lm == ""):
            out+= ":aad3b435b51404eeaad3b435b51404ee:"
        else:
            out += ":"+lm.encode('hex')+":"
        if (ntlm == ""):
            out += "NO PASSWORD*********************:::"
        else:
            out += ntlm.encode('hex')+":::"

        histories.append(out)

    return histories


# decrypt/return just the krbtgt NTLM hash
def decKrbtgt(hiveFile,hashFile):

    #get the bootkey from the system hive
    bootkey = get_syskey(hiveFile)

    f = open(hashFile)
    raw = f.read()
    f.close()

    krbtgt_acct = None
    rawPekKey = None
    rawRID = None
    rawNTLMhash = None

    # split along account boundaries
    accts = raw.split("ATTm3")

    for acct in accts:
        if "ATTk590689" in acct:
            for part in acct.split('\n'):
                if part.startswith("ATTk590689"):
                    rawPekKey = part.split(":")[1].strip().strip('\'')

        elif "u\'krbtgt\'" in acct and "ATTk589914" in acct:

            for part in acct.split('\n'):

                if part.startswith("ATTr589970"):
                    rawRID = part.split(":")[1].strip().strip('\'')

                elif part.startswith("ATTk589914"): 
                    rawNTLMhash = part.split(":")[1].strip().strip('\'')

    print decUserHash(bootkey, rawPekKey, "krbtgt", rawRID, "", rawNTLMhash)


# decrypt/return all user hashes
def decUserHashes(hiveFile,hashFile):

    #get the bootkey from the system hive
    bootkey = get_syskey(hiveFile)

    f = open(hashFile)
    raw = f.read()
    f.close()

    krbtgt_acct = None
    rawPekKey = None
    rawRID = None
    rawNTLMhash = None
    rawLMhash = None

    # split along account boundaries
    accts = raw.split("ATTm3")

    for acct in accts:
        if "ATTk590689" in acct:
            for part in acct.split('\n'):
                if part.startswith("ATTk590689"):
                    rawPekKey = part.split(":")[1].strip().strip('\'')

        # only examine accts with a valid NTLM hash
        elif "ATTk589914" in acct:

            parts = acct.split('\n')

            for part in parts:
                if part.startswith("ATTm590045"):
                    name = part.split(":")[1].strip()[1:].strip('\'')
                elif part.startswith("ATTr589970"):
                    rawRID = part.split(":")[1].strip().strip('\'')
                elif part.startswith("ATTk589879"):
                    rawLMhash = part.split(":")[1].strip().strip('\'')
                elif part.startswith("ATTk589914"): 
                    rawNTLMhash = part.split(":")[1].strip().strip('\'')

            print decUserHash(bootkey, rawPekKey, name, rawRID, "", rawNTLMhash)


# decrypt/return all user hash histories
def decUserHashHistories(hiveFile,hashFile):

    #get the bootkey from the system hive
    bootkey = get_syskey(hiveFile)

    f = open(hashFile)
    raw = f.read()
    f.close()

    krbtgt_acct = None
    rawPekKey = None
    rawRID = None
    rawNTLMhash = None
    rawLMhash = None
    rawNTLMhashHistory = None
    rawLMhashHistory = None

    # split along account boundaries
    accts = raw.split("ATTm3")

    for acct in accts:
        if "ATTk590689" in acct:
            for part in acct.split('\n'):
                if part.startswith("ATTk590689"):
                    rawPekKey = part.split(":")[1].strip().strip('\'')

        # only examine accts with a valid NTLM hash history
        elif "ATTk589918" in acct:

            parts = acct.split('\n')

            for part in parts:
                if part.startswith("ATTm590045"):
                    name = part.split(":")[1].strip()[1:].strip('\'')
                elif part.startswith("ATTr589970"):
                    rawRID = part.split(":")[1].strip().strip('\'')
                elif part.startswith("ATTk589984"):
                    rawLMhashHistory = part.split(":")[1].strip().strip('\'')
                elif part.startswith("ATTk589918"): 
                    rawNTLMhashHistory = part.split(":")[1].strip().strip('\'')

            histories = decUserHashHistory(bootkey, rawPekKey, name, rawRID, rawLMhashHistory, rawNTLMhashHistory)
            for history in histories:
                print history


if len(sys.argv) == 3:
    decUserHashes(sys.argv[1], sys.argv[2])


elif len(sys.argv) == 4:
    if (sys.argv[3].lower() == "-history"):
        decUserHashHistories(sys.argv[1], sys.argv[2])
    else:
        decKrbtgt(sys.argv[1], sys.argv[2])


elif len(sys.argv) == 5:
    bootkey = get_syskey(sys.argv[1])
    decUserHash(bootKey, sys.argv[2], "user", sys.argv[3], sys.argv[4])

else:
    print "\nFirst dump the datatable using esentutl.py:"
    print "\tesentutl.py /path/to/ntds.dit export -table datatable | grep -E \"ATTk590689|ATTm3|ATTm590045|ATTm590045|ATTr589970|ATTk589914|ATTk589879|ATTk589984|ATTk589918\" > outfile.txt\n"
    print "Then       : %s <system hive> <hash file>" % sys.argv[0]
    print "\tor : %s <system hive> <hash file> -krbtgt" % sys.argv[0]
    print "\tor : %s <system hive> <hash file> -history" % sys.argv[0]
    print "\tor : %s <system hive> <rawPekKey> <rawRid> <rawNTLMhash>\n" % sys.argv[0]
    sys.exit(1)
