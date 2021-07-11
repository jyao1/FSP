## @ FspGenCoSwid.py
#
# This tool generates CBOR format CoMID tag.
#
# Reference:
#   CoSWID:
#   RATS: Reference Integrity Measurement Extension for Concise Hardware Identities, https://ietf-rats.github.io/draft-birkholz-rats-corim/draft-birkholz-rats-corim.html
#
#
# Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
# SPDX-License-Identifier: BSD-2-Clause-Patent
#
##

import os
import platform
import cbor
import json
import argparse
import subprocess
from ecdsa.keys import SigningKey, VerifyingKey
from pycose.cosemessage import CoseMessage
from pycose.signmessage import SignMessage

FspToolPath = os.path.join(os.path.dirname(__file__), 'FspTools.py')

osType = platform.system()

if osType == 'Windows':
    eol = '\r\n'
elif osType == 'Linux':
    eol = '\n'

SupportHashAlgMap = {'sha256': 1}

IntegerMapDict = {'comid.language': 0, 'comid.tag-identity': 1, 'comid.entity': 2, 'comid.linked-tags': 3, 'comid.triples': 4,
                  'comid.tag-id': 0, 'comid.tag-version': 1, 'comid.entity-name': 0, 'comid.reg-id': 1, 'comid.role': 2,
                  'comid.linked-tag-id': 0, 'comid.tag-rel': 1, 'comid.reference-triples': 0, 'comid.endorsed-triples': 1,
                  'comid.identity-triples': 2, 'comid.attest-key-triples': 3, 'comid.class': 0, 'comid.instance': 1,
                  'comid.group': 2, 'comid.class-id': 0, 'comid.vendor': 1, 'comid.model': 2, 'comid.layer': 3, 'comid.index': 4,
                  'comid.mkey': 0, 'comid.mval': 1, 'comid.ver': 0, 'comid.svn': 1, 'comid.digests': 2, 'comid.flags': 3,
                  'comid.raw-value': 4, 'comid.raw-value-mask': 5, 'comid.mac-addr': 6, 'comid.ip-addr': 7, 'comid.serial-number': 8,
                  'comid.ueid': 9, 'comid.uuid': 10, 'comid.key': 0, 'comid.keychain': 1, 'comid.version': 0, 'comid.version-scheme': 1,
                  'comid.supplements': 0, 'comid.replaces': 1, 'comid.tag-creator': 0, 'comid.creator': 1, 'comid.maintainer': 2,
                  'corim.id': 0, 'corim.tags': 1, 'corim.dependent-rims': 2, 'corim.href': 0, 'corim.thumbprint': 1, 'corim.alg-id': 1,
                  'corim.content-type': 3, 'corim.issuer-key-id': 4, 'corim.meta': 8, 'corim.not-before': 0, 'corim.not-after': 1,
                  'corim.signer': 0, 'corim.validity': 1, 'corim.entity-name': 0, 'corim.reg-id': 1, 'corim.role': 2,
                  'corim.manifest-creator': 1, 'corim.manifest-signer': 2
                  }

class GenCbor():
    def __init__(self, CorimData, OutputFile, HashType):
        self.CorimData = CorimData
        self.CborPath = OutputFile
        self.HashType = HashType
        self.CborData = {}

    def genCbor(self):
        UnsignedCorimDictStr = str(self.CorimData)
        for key in IntegerMapDict:
            if key == 'comid.version-scheme' or key == 'comid.class-id' or key == 'comid.entity-name':
                UnsignedCorimDictStr = UnsignedCorimDictStr.replace(key, str(IntegerMapDict[key]))

        for key in IntegerMapDict:
            if key == 'comid.version':
                UnsignedCorimDictStr = UnsignedCorimDictStr.replace(key, str(IntegerMapDict[key]))

        for key in IntegerMapDict:
            UnsignedCorimDictStr = UnsignedCorimDictStr.replace(key, str(IntegerMapDict[key]))

        for key in SupportHashAlgMap:
            UnsignedCorimDictStr = UnsignedCorimDictStr.replace(key, str(SupportHashAlgMap[key]))

        with open(self.CborPath, 'wb') as f:
            f.write(cbor.dumps(eval(UnsignedCorimDictStr)))

        print(json.dumps(eval(UnsignedCorimDictStr), indent=2))

def SearchKeyAndSetValue(data, keyName, comid_flag, value):
    if isinstance(data, dict):
        for key in data.keys():
            if key == keyName and data[key]['comid.flags'] == comid_flag:
                data[key]['comid.digests'] = value
                return
            SearchKeyAndSetValue(data[key], keyName, comid_flag, value)
    elif isinstance(data, list):
        for item in data:
            SearchKeyAndSetValue(item, keyName, comid_flag, value)

def ParseJsonCorim(JsonFilePath, PayloadFile, HashType, Mode):
    CmdList = ['python', FspToolPath, 'hash', '-f', PayloadFile, '-m', Mode]

    try:
        parseFspImage = subprocess.Popen(CmdList, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                         shell=False)
        msg = parseFspImage.communicate()
    except Exception:
        print(msg[1])
    else:
        if msg[0].decode() == '':
            print(msg[1].decode())
            os._exit(1)

    FSPComponents = msg[0].decode().split(eol)

    Jsonfp = open(JsonFilePath, 'r')
    JsonData = json.loads(Jsonfp.read())
    Jsonfp.close()

    for component in FSPComponents:
        if component != '':
            FspFlag = component.split(' ')[0]
            FapDigest = component.split(' ')[2]
            SearchKeyAndSetValue(JsonData, 'comid.mval', FspFlag, ['sha256', FapDigest])

    print(json.dumps(JsonData, indent=2))
    return JsonData

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(title='commands', dest='which')

    parser_gencomid = subparsers.add_parser('gencomid', help='Generate CoMID file in CBOR format')
    parser_gencomid.set_defaults(which='gencomid')
    parser_gencomid.add_argument('-c', '--corim', dest='CorimPath', type=str, help='Corim configuration file path', required=True)
    parser_gencomid.add_argument('-p', '--payload', dest='Payload', type=str, help='Payload File name', required=True)
    parser_gencomid.add_argument('-m', '--mode', choices=['binary', 'separation'], dest='Mode', type=str, help='Different mode to generate hash for FSP image', default='binary')
    parser_gencomid.add_argument('-t', '--hash', dest='HashType',  type=str, choices=SupportHashAlgMap.keys(), help='Hash types {}'.format(str(SupportHashAlgMap.keys())), default='sha256')
    parser_gencomid.add_argument('-o', '--outfile', dest='OutputFile', type=str, help='Output Cbor file path', default='', required=True)

    args = parser.parse_args()

    if args.which == 'gencomid':
        if not os.path.exists(args.CorimPath):
            raise Exception("ERROR: Could not locate Ini file '%s' !" % args.IniPath)
        if not os.path.exists(args.Payload):
            raise Exception("ERROR: Could not locate payload file '%s' !" % args.Payload)
        if os.path.isabs(args.OutputFile):
            if not os.path.exists(os.path.dirname(args.OutputFile)):
                os.makedirs(os.path.dirname(args.OutputFile))

    if args.which == 'gencomid':
        Data = ParseJsonCorim(args.CorimPath, args.Payload, args.HashType, args.Mode)
        Encode = GenCbor(Data, args.OutputFile, args.HashType)
        Encode.genCbor()