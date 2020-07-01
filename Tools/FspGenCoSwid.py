## @ FspGenCoSwid.py
#
# Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
# SPDX-License-Identifier: BSD-2-Clause-Patent
#
##

import os
import copy
import cbor
import json
import base64
import hashlib
import argparse
import configparser
from jose import jws
from pycose.cosemessage import CoseMessage
from pycose.signmessage import SignMessage

TagTypeList   = ['primary', 'corpus', 'patch', 'supplemental']
UseMap       = {'required': 2, 'recommended': 3, 'optional': 1}
OwnershipMap = {'abandon': 3, 'private': 2, 'shared': 1}
VersionSchemeMap = {'multipartnumeric': 1, 'multipartnumeric-suffix': 2, 'alphanumeric': 3, 'decimal': 4, 'semver': 16384}
HashAlgorithmMap = {"SHA_256": 1, "SHA_256_128": 2, "SHA_256_120": 3, "SHA_256_96": 4, "SHA_256_64": 5, "SHA_256_32": 6,
                    "SHA_384": 7, "SHA_512": 8, "SHA_3_224": 9, "SHA_3_256": 9, "SHA_3_384": 9, "SHA_3_512": 9}
RoleMap = {"tagCreator": 1, "softwareCreator": 2, "aggregator": 3, "distributor": 4, "licensor": 5}
RelMap = {'ancestor': 1, 'component': 2, 'feature': 3, 'installationmedia': 4, 'packageinstaller': 5, 'parent': 6,
          'patches': 7, 'requires': 8, 'see-also': 9, 'supersedes': 10, 'supplemental': 11}


EntityBuilder = {'name': None, 'role': [], 'regid': None, 'thumbprint': None}
LinkBuilder = {'artifact': None, 'href': None, 'media': None, 'ownership': None, 'rel': None, 'type': None, 'use': None}
MetaBuilder = {'activationStatus': None, 'channelType': None, 'colloquialVersion': None, 'description': None, 'edition': None, 'entitlementDataRequired': None,
               'entitlementKey': None, 'generator': None, 'persistentId': None, 'productBaseName': None, 'productFamily': None, 'revision': None, 'summary': None,
               'unspscCode': None, 'unspscVersion': None}
FileBuilder = {'name': '', 'size': '', 'version': '', 'hash': {}}
EvidenceBuilder = {'date': '', 'deviceId': '', }

mapDict = {"tag-id": 0, "swid-name": 1, "entity": 2, "evidence": 3, "link": 4, "software-meta": 5, "payload": 6,
           "hash": 7, "corpus": 8, "patch": 9, "media": 10, "supplemental": 11, "tag-version": 12, "software-version": 13,
            "version-scheme": 14, "lang": 15, "directory": 16, "file": 17, "process": 18, "resource": 19, "size": 20,
            "file-version": 21, "key": 22, "location": 23, "fs-name": 24, "root": 25, "path-elements": 26, "process-name": 27,
            "pid": 28, "type": 29, "entity-name": 31, "reg-id": 32, "role": 33, "thumbprint": 34, "date": 35, "device-id": 36,
            "artifact": 37, "href": 38, "ownership": 39, "rel": 40, "media-type": 41, "use": 42, "activation-status": 43,
            "channel-type": 44, "colloquial-version": 45, "description": 46, "edition": 47, "entitlement-data-required": 48,
            "entitlement-key": 49, "generator": 50, "persistent-id": 51, "product": 52, "product-family": 53, "revision": 54,
            "summary": 55, "unspsc-code": 56, "unspsc-version": 57}

SupportHashAlgorithmList = ["SHA_256", "SHA_384", "SHA_512", "SHA_3_256", "SHA_3_384", "SHA_3_512"]
# SignSupportAlgorithmList = ["ES256", "ES384", "ES512", "HS256/64", "HS256", "HS384", "HS512", "EdDSA", "AES-MAC128/64",\
#                             "AES-MAC256/64", "AES-MAC128/128", "AES-MAC256/128", "A128GCM", "A192GCM", "A256GCM"]
SignSupportAlgorithmList = ["ES256", "ES384", "ES512"]

class SWIDBuilder:
    def __init__(self):
        self.tagType = 0
        self.name = None
        self.tagId = None
        self.tagVersion = None
        self.version = None
        self.versionScheme = None
        self.entities = []
        self.evidence = []
        self.links = []
        self.metas = []
        self.payload = []

    def addEntity(self, entity):
        self.entities.append(entity)

    def addLink(self, link):
        self.links.append(link)

    def addMeta(self, meta):
        self.metas.append(meta)

    def addPayload(self, payload):
        self.payload.append(payload)

class GenCbor():
    def __init__(self, OutputFile, SWIDBuilder):
        self.CborPath = OutputFile
        self.CborData = {}
        self.SWIDBuilder = SWIDBuilder

    def buildAttribute(self, dict, tag, value):
        if value != None:
            dict[tag] = value

    def validateNonEmpty(self, tagName, value):
        if value == None or value == []:
            raise Exception("the field {} must contain a non-empty value".format(tagName))

    def validateEntity(self, entity):
        self.validateNonEmpty('name', entity['name'])
        self.validateNonEmpty('role', entity['role'])

    def validateLink(self, link):
        self.validateNonEmpty('href', link['href'])
        self.validateNonEmpty('rel', link['rel'])

    def validatePayload(self, payload):
        self.validateNonEmpty('name', payload['name'])

    def validate(self):
        self.validateNonEmpty('name', self.SWIDBuilder.name)
        self.validateNonEmpty('tagId', self.SWIDBuilder.tagId)
        self.validateNonEmpty('entity', self.SWIDBuilder.entities)

        foundTagCreator = False
        for entity in self.SWIDBuilder.entities:
            self.validateEntity(entity)
            if 'tagCreator' in entity['role']:
                foundTagCreator = True

        if not foundTagCreator:
            raise Exception('at least one entity with role, tagCreator must be provided.')

        if self.SWIDBuilder.payload != [] and self.SWIDBuilder.evidence != []:
            raise Exception('Only one of evidence or payload must be provided.')

        if self.SWIDBuilder.payload != []:
            self.validatePayload(self.SWIDBuilder.payload[0])

        for link in self.SWIDBuilder.links:
            self.validateLink(link)

    def genCobor(self):
        self.validate()
        # required attributes
        self.CborData[mapDict['tag-id']] = self.SWIDBuilder.tagId
        self.CborData[mapDict['tag-version']] = int(self.SWIDBuilder.tagVersion)
        self.CborData[mapDict['swid-name']] = self.SWIDBuilder.name

        if self.SWIDBuilder.version != None:
            self.CborData[mapDict['software-version']] = self.SWIDBuilder.version
        if self.SWIDBuilder.versionScheme != None:
            self.CborData[mapDict['version-scheme']] = VersionSchemeMap[self.SWIDBuilder.versionScheme]

        # Optional attribute
        if self.SWIDBuilder.tagType == 'primary':
            pass
        elif self.SWIDBuilder.tagType not in TagTypeList:
            print("TagType: {} is illegal".format(self.SWIDBuilder.tagType))
            os._exit()
        else:
            self.CborData[mapDict[self.SWIDBuilder.tagType]] = True

        # child elements
        # Required
        if self.SWIDBuilder.entities != []:
            self.CborData[mapDict['entity']] = []
            for entity in self.SWIDBuilder.entities:
                entity_dict = {}
                # required
                entity_dict[mapDict['entity-name']] = entity['name']
                entity_dict[mapDict['role']] = []
                for role in entity['role']:
                    entity_dict[mapDict['role']].append(RoleMap[role])
                # optional
                if entity['regid'] != None:
                    entity_dict[mapDict['reg-id']] = entity['regid']
                if entity['thumbprint'] != None:
                    entity_dict[mapDict['thumbprint']] = entity['thumbprint']
                self.CborData[mapDict['entity']].append(entity_dict)

        # optional
        if self.SWIDBuilder.links != []:
            self.CborData[mapDict['link']] = []
            for link in self.SWIDBuilder.links:
                link_dict = {}
                # required
                link_dict[mapDict['href']] = link['href']
                link_dict[mapDict['rel']]  = RelMap[link['rel']]

                # optional
                self.buildAttribute(link_dict, mapDict['artifact'], link['artifact'])
                self.buildAttribute(link_dict, mapDict['media'], link['media'])
                self.buildAttribute(link_dict, mapDict['ownership'], OwnershipMap[link['ownership']])
                self.buildAttribute(link_dict, mapDict['media-type'], link['type'])
                self.buildAttribute(link_dict, mapDict['use'], UseMap[link['use']])
                self.CborData[mapDict['link']].append(link_dict)

        if self.SWIDBuilder.metas != []:
            self.CborData[mapDict['software-meta']] = []
            for meta in self.SWIDBuilder.metas:
                meta_dict = {}
                self.buildAttribute(meta_dict, mapDict['activation-status'], meta['activationStatus'])
                self.buildAttribute(meta_dict, mapDict['channel-type'], meta['channelType'])
                self.buildAttribute(meta_dict, mapDict['colloquial-version'], meta['colloquialVersion'])
                self.buildAttribute(meta_dict, mapDict['description'], meta['description'])
                self.buildAttribute(meta_dict, mapDict['edition'], meta['edition'])
                self.buildAttribute(meta_dict, mapDict['entitlement-data-required'], meta['entitlementDataRequired'])
                self.buildAttribute(meta_dict, mapDict['entitlement-key'], meta['entitlementKey'])
                self.buildAttribute(meta_dict, mapDict['generator'], meta['generator'])
                self.buildAttribute(meta_dict, mapDict['persistent-id'], meta['persistentId'])
                self.buildAttribute(meta_dict, mapDict['product'], meta['productBaseName'])
                self.buildAttribute(meta_dict, mapDict['product-family'], meta['productFamily'])
                self.buildAttribute(meta_dict, mapDict['revision'], meta['revision'])
                self.buildAttribute(meta_dict, mapDict['summary'], meta['summary'])
                self.buildAttribute(meta_dict, mapDict['unspsc-code'], meta['unspscCode'])
                self.buildAttribute(meta_dict, mapDict['unspsc-version'], meta['unspscVersion'])
                self.CborData[mapDict['software-meta']].append(meta_dict)

        if self.SWIDBuilder.payload != []:
            self.CborData[mapDict['payload']] = {}
            self.CborData[mapDict['payload']][mapDict['file']] = {}
            self.CborData[mapDict['payload']][mapDict['file']][mapDict['fs-name']] = str(self.SWIDBuilder.payload[0]['name'])
            self.CborData[mapDict['payload']][mapDict['file']][mapDict['size']] = self.SWIDBuilder.payload[0]['size']
            self.CborData[mapDict['payload']][mapDict['file']][mapDict['hash']] = []
            for hashType in self.SWIDBuilder.payload[0]['hash'].keys():
                self.CborData[mapDict['payload']][mapDict['file']][mapDict['hash']].append([HashAlgorithmMap[hashType.replace('-', '_')], str(self.SWIDBuilder.payload[0]['hash'][hashType])])

        with open(self.CborPath, 'wb') as f:
            f.write(cbor.dumps(self.CborData))

def GetValueFromSec(ini_obj, section, option):
    if ini_obj.has_option(section, option):
        return ini_obj.get(section, option)
    else:
        return None

def ParseAndBuildSwidData(IniPath, PayloadFile, HashTypes):
    swid_builder = SWIDBuilder()

    ini = configparser.ConfigParser()
    ini.read(IniPath, encoding='utf-8')
    sections = ini.sections()

    for section in sections:
        if section == 'SoftwareIdentity':
            swid_builder.name          = GetValueFromSec(ini, section, 'name')
            swid_builder.tagId         = GetValueFromSec(ini, section, 'tagid')
            swid_builder.version       = GetValueFromSec(ini, section, 'version')
            swid_builder.tagType       = GetValueFromSec(ini, section, 'tagtype')
            swid_builder.tagVersion    = GetValueFromSec(ini, section, 'tagversion')
            swid_builder.versionScheme = GetValueFromSec(ini, section, 'versionscheme')
        elif section.startswith('Entity'):
            Entity = copy.deepcopy(EntityBuilder)
            Entity['name']       = GetValueFromSec(ini, section, 'name')
            Entity['regid']      = GetValueFromSec(ini, section, 'regid')
            Entity['role']       = GetValueFromSec(ini, section, 'role').split(' ')
            Entity['thumbprint'] = GetValueFromSec(ini, section, 'thumbprint')
            swid_builder.addEntity(Entity)
        elif section == 'Link':
            Link = copy.deepcopy(LinkBuilder)
            Link['rel']       = GetValueFromSec(ini, section, 'rel')
            Link['href']      = GetValueFromSec(ini, section, 'href')
            Link['use']       = GetValueFromSec(ini, section, 'use')
            Link['media']     = GetValueFromSec(ini, section, 'media')
            Link['type']      = GetValueFromSec(ini, section, 'type')
            Link['artifact']  = GetValueFromSec(ini, section, 'artifact')
            Link['ownership'] = GetValueFromSec(ini, section, 'ownership')
            swid_builder.addLink(Link)
        elif section == 'Meta':
            Meta = copy.deepcopy(MetaBuilder)
            Meta['activationStatus']        = GetValueFromSec(ini, section, 'activationstatus')
            Meta['channelType']             = GetValueFromSec(ini, section, 'channeltype')
            Meta['colloquialVersion']       = GetValueFromSec(ini, section, 'colloquilversion')
            Meta['description']             = GetValueFromSec(ini, section, 'description')
            Meta['edition']                 = GetValueFromSec(ini, section, 'edition')
            Meta['entitlementDataRequired'] = GetValueFromSec(ini, section, 'entitlementdatarequired')
            Meta['entitlementKey']          = GetValueFromSec(ini, section, 'entitlementkey')
            Meta['generator']               = GetValueFromSec(ini, section, 'generator')
            Meta['persistentId']            = GetValueFromSec(ini, section, 'persistentid')
            Meta['productBaseName']         = GetValueFromSec(ini, section, 'productbasename')
            Meta['productFamily']           = GetValueFromSec(ini, section, 'productfamily')
            Meta['revision']                = GetValueFromSec(ini, section, 'revision')
            Meta['summary']                 = GetValueFromSec(ini, section, 'summary')
            Meta['unspscCode']              = GetValueFromSec(ini, section, 'unspsccode')
            Meta['unspscVersion']           = GetValueFromSec(ini, section, 'unspscversion')
            swid_builder.addMeta(Meta)

    payload = genFileBuilder(PayloadFile, HashTypes)
    swid_builder.addPayload(payload)

    return swid_builder

def genFileBuilder(FileName, HashAlgorithms):
    if not os.path.exists(FileName):
        raise Exception("{} is not exists.".format(FileName))

    with open(FileName, 'rb') as f:
        content = f.read()

    fb = copy.deepcopy(FileBuilder)
    fb['name'] = FileName
    fb['size'] = os.path.getsize(FileName)
    fb['version'] = None
    for HashAlgorithm in HashAlgorithms:
        if HashAlgorithm == 'SHA_256':
            fb['hash']['SHA-256'] = hashlib.sha256(content).hexdigest()
        elif HashAlgorithm == 'SHA_384':
            fb['hash']['SHA-384'] = hashlib.sha384(content).hexdigest()
        elif HashAlgorithm == 'SHA_512':
            fb['hash']['SHA-512'] = hashlib.sha512(content).hexdigest()
        elif HashAlgorithm == 'SHA_3_256':
            fb['hash']['SHA-3-256'] = hashlib.sha3_256(content).hexdigest()
        elif HashAlgorithm == 'SHA_3_384':
            fb['hash']['SHA-3-384'] = hashlib.sha3_384(content).hexdigest()
        elif HashAlgorithm == 'SHA_3_512':
            fb['hash']['SHA-3-512'] = hashlib.sha3_512(content).hexdigest()

    return fb

def GetKeyByValue(dict, value):
    for key in dict.keys():
        if dict[key] == value:
            return key

def DecodeCbor(FilePath, Translate):
    with open(FilePath, 'rb') as f:
        content = f.read()

    cborDict = cbor.loads(content)
   
    if Translate:
        decodeCborData = {}
        for key in cborDict.keys():
            if key in [0, 1, 8, 9, 10, 11, 12, 13, 14]:
                if key == 14:
                    decodeCborData[GetKeyByValue(mapDict, key)] = GetKeyByValue(VersionSchemeMap, cborDict[key])
                else:
                    decodeCborData[GetKeyByValue(mapDict, key)] = cborDict[key]
            elif key == 2:
                decodeCborData[GetKeyByValue(mapDict, key)] = []
                for entity in cborDict[key]:
                    entityDict = {}
                    for subkey in entity:
                        if subkey == 33:
                            entityDict[GetKeyByValue(mapDict, subkey)] = []
                            for role in entity[subkey]:
                                entityDict[GetKeyByValue(mapDict, subkey)].append(GetKeyByValue(RoleMap, role))
                        else:
                            entityDict[GetKeyByValue(mapDict, subkey)] = entity[subkey]

                    decodeCborData[GetKeyByValue(mapDict, key)].append(entityDict)
            elif key == 3:
                pass
            elif key == 4:
                decodeCborData[GetKeyByValue(mapDict, key)] = []
                for link in cborDict[key]:
                    linkDict = {}
                    for subkey in link:
                        if subkey in [10, 37, 38, 41]:
                            linkDict[GetKeyByValue(mapDict, subkey)] = link[subkey]
                        elif subkey == 39:
                            linkDict[GetKeyByValue(mapDict, subkey)] = GetKeyByValue(OwnershipMap, link[subkey])
                        elif subkey == 40:
                            linkDict[GetKeyByValue(mapDict, subkey)] = GetKeyByValue(RelMap, link[subkey])
                        elif subkey == 42:
                            linkDict[GetKeyByValue(mapDict, subkey)] = GetKeyByValue(UseMap, link[subkey])

                    decodeCborData[GetKeyByValue(mapDict, key)].append(linkDict)
            elif key == 5:
                decodeCborData[GetKeyByValue(mapDict, key)] = []
                for meta in cborDict[key]:
                    metaDict = {}
                    for subkey in meta:
                        metaDict[GetKeyByValue(mapDict, subkey)] = meta[subkey]

                    decodeCborData[GetKeyByValue(mapDict, key)].append(metaDict)
            elif key == 6:
                decodeCborData[GetKeyByValue(mapDict, key)] = {}
                for subkey in cborDict[key]:
                    decodeCborData[GetKeyByValue(mapDict, key)][GetKeyByValue(mapDict, subkey)] = {}
                    for sub_subkey in cborDict[key][subkey]:
                        if sub_subkey == 7:
                            decodeCborData[GetKeyByValue(mapDict, key)][GetKeyByValue(mapDict, subkey)][GetKeyByValue(mapDict, sub_subkey)] = []
                            for item in cborDict[key][subkey][sub_subkey]:
                                decodeCborData[GetKeyByValue(mapDict, key)][GetKeyByValue(mapDict, subkey)][
                                    GetKeyByValue(mapDict, sub_subkey)].append([
                                    GetKeyByValue(HashAlgorithmMap, item[0]), item[1]])
                        else:
                            decodeCborData[GetKeyByValue(mapDict, key)][GetKeyByValue(mapDict, subkey)][
                                GetKeyByValue(mapDict, sub_subkey)] = cborDict[key][subkey][sub_subkey]

        print(json.dumps(decodeCborData, sort_keys=True, indent=2))
    else:
        if not isinstance(cborDict, dict):
            HierarchyDiplay(str(cborDict).replace(' ', ''))

        else:
            print(json.dumps(cborDict, sort_keys=True, indent=2))

def HierarchyDiplay(str):
    MinIndent = 0
    MaxIndent = -2
    for num, i in enumerate(str):
        if i in ['(', '[']:
            MaxIndent += 2

    for i in str:
        if i == ']':
            MaxIndent -= 2
            print('\n' + ' ' * MaxIndent, end='')
        if i == ')':
            MaxIndent -= 2
            print('\n' + ' ' * MaxIndent, end='')

        print(i, end='')
        
        if i == '(':
            MinIndent += 2
            print('\n' + ' ' * MinIndent, end='')
        if i == ',':
            print('\n' + ' ' * MinIndent, end='')
        if i == '[':
            MinIndent += 2
            print('\n' + ' ' * MinIndent, end='')

def SignCbor(FilePath, Key, Algorithm, SignedCborPath):
    with open(FilePath, 'rb') as f:
        cborData = f.read()

    with open(Key, 'r') as f:
        key = f.read()

    # /protected/
    # /unprotected/
    # /payload/
    # /signatures/ [
    #     /protected/
    #     /unprotected/
    #     /signature/
    #     ]

    (pHeader, unpHeader, payload, pSigner, unpSigner) = [{}, {}, cborData, {"alg": Algorithm}, {"kid": "11"}]

    sign_msg = SignMessage()

    for k1 in pHeader:
        sign_msg.add_to_headers(k1, pHeader[k1], 'PROTECTED')
    for k2 in unpHeader:
        sign_msg.add_to_headers(k2, unpHeader[k2], 'UNPROTECTED')
    sign_msg.payload = payload
    for k3 in pSigner:
        sign_msg.add_to_signers(1, k3, pSigner[k3], 'PROTECTED')
    for k4 in unpSigner:
        sign_msg.add_to_signers(1, k4, unpSigner[k4], 'UNPROTECTED')

    sign_msg.key = key

    alg = sign_msg.find_in_headers(sign_msg.protected_header, 'alg')
    if alg == None:
        alg = sign_msg.find_in_signers('alg')

    sign_msg.add_signature_to_signers(1, sign_msg.compute_signature(alg))

    with open(SignedCborPath, 'wb') as f:
        f.write(cbor.dumps(cbor.loads(sign_msg.encode())))

    # verify signature
    cose_msg = CoseMessage.decode(cbor.dumps(cbor.loads(sign_msg.encode())))

    # cose_msg.key =  key
    # alg = cose_msg.find_in_headers('alg')
    #
    # alg = cose_msg.find_in_signers('alg')
    #
    # print(cose_msg.verify_signature(alg, signer=1))

#
# Convert cbor to json and sign the data
#
def SignCborByJws(FilePath, Key, Algorithm, SignedJsonPath):
    with open(FilePath, 'rb') as f:
        cborData = f.read()

    with open(Key, 'r') as f:
        key = f.read()

    jsonData = json.dumps(cbor.loads(cborData)).encode()
    jsonSignData = jws.sign(jsonData, key, algorithm=Algorithm)
    
    with open(SignedJsonPath, 'w') as f:
        f.write(jsonSignData)

    # verify sign data
    #
    # with open('ecc-public-key.pem', 'r') as f:
    #     key = f.read()
    #
    # print(jws.verify(jsonSignData, key, Algorithm) == jsonData)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(title='commands', dest="which")

    parser_encode = subparsers.add_parser('encode', help='Encode cbor format file')
    parser_encode.set_defaults(which='encode')
    parser_encode.add_argument('-i', '--inifile', dest='IniPath', type=str, help='Ini configuration file path', required=True)
    parser_encode.add_argument('-p', '--payload', dest='Payload', type=str, help="Payload File name", required=True)
    parser_encode.add_argument('-t', '--hash', dest='HashType', action='append', type=str, choices=SupportHashAlgorithmList, help="Hash types {}".format(str(HashAlgorithmMap.keys())), required=True)
    parser_encode.add_argument('-o', '--outfile', dest='OutputFile', type=str, help='Output Cbor file path', default='', required=True)

    parser_decode = subparsers.add_parser('decode', help='Decode cbor format file')
    parser_decode.set_defaults(which='decode')
    parser_decode.add_argument('-f', '--file', dest='File', type=str, help='Cbor format file path', required=True)
    parser_decode.add_argument('-t', '--translate', dest='Translate', action='store_true', help='Flag used to enable translate func')

    parser_sign = subparsers.add_parser('sign', help='Sign cbor file')
    parser_sign.set_defaults(which='sign')
    parser_sign.add_argument('-f', '--file', dest='File', type=str, help='Cbor format file path', required=True)
    parser_sign.add_argument('--key', dest='Key', type=str, help='Key for signing', required=True)
    parser_sign.add_argument('--alg', dest='Algorithm', type=str, choices=SignSupportAlgorithmList, help='Key for signing', required=True)
    parser_sign.add_argument('--jws', dest='JWS', action='store_true', help='Flag used to enable use JWS to sign cbor')
    parser_sign.add_argument('-o', '--output', dest='SignedCborPath', type=str, help='SignedCbor file path COSE/JWS', required=True)

    args = parser.parse_args()

    if args.which == 'encode':
        if not os.path.exists(args.IniPath):
            raise Exception("ERROR: Could not locate Ini file '%s' !" % args.IniPath)
        if not os.path.exists(args.Payload):
            raise Exception("ERROR: Could not locate payload file '%s' !" % args.Payload)
        if os.path.isabs(args.OutputFile):
            if not os.path.exists(os.path.dirname(args.OutputFile)):
                os.makedirs(os.path.dirname(args.OutputFile))

    if args.which == 'decode':
        if not os.path.exists(args.File):
            raise Exception("ERROR: Could not locate Cbor file '%s' !" % args.File)

    if args.which == 'sign':
        if not os.path.exists(args.File):
            raise Exception("ERROR: Could not locate Cbor file '%s' !" % args.File)
        if os.path.isabs(args.SignedCborPath):
            if not os.path.exists(os.path.dirname(args.SignedCborPath)):
                os.makedirs(os.path.dirname(args.SignedCborPath))

    if args.which == 'encode':
        Encode = GenCbor(args.OutputFile, ParseAndBuildSwidData(args.IniPath, args.Payload, args.HashType))
        Encode.genCobor()
    elif args.which == 'decode':
        DecodeCbor(args.File, args.Translate)

    if args.which == 'sign':
        if args.JWS:
            SignCborByJws(args.File, args.Key, args.Algorithm, args.SignedCborPath)
        else:
            SignCbor(args.File, args.Key, args.Algorithm, args.SignedCborPath)
