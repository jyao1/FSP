## @ FspGenCoSwid.py
#
# This tool generates signed CBOR format CoSWID tag.
#
# Reference:
#   CoSWID:
#   SACM: Concise Software Identification Tags, https://datatracker.ietf.org/doc/draft-ietf-sacm-coswid/
#   RATS: Reference Integrity Measurement Extension for Concise Software Identities, https://datatracker.ietf.org/doc/draft-birkholz-rats-coswid-rim/
#
#   CBOR:
#   [RFC7049] Concise Binary Object Presentation (CBOR), https://tools.ietf.org/html/rfc7049
#   [RFC8152] CBOR Object Signing and Encryption (COSE), https://tools.ietf.org/html/rfc8152
#   [RFC8610] Concise Data Definition Language (CDDL), https://tools.ietf.org/html/rfc8610
#   [RFC8392] CBOR Web Token (CWT), https://tools.ietf.org/html/rfc8392
#
#   JSON:
#   [RFC7515] JSON Web Signature (JWS), https://tools.ietf.org/html/rfc7515
#   [RFC7516] JSON Web Encryption (JWE), https://tools.ietf.org/html/rfc7516
#   [RFC7517] JSON Web Key (JWK), https://tools.ietf.org/html/rfc7517
#   [RFC7518] JSON Web Algorithms (JWA), https://tools.ietf.org/html/rfc7518
#   [RFC7519] JSON Web Token (JWT), https://tools.ietf.org/html/rfc7519
#   [RFC7520] Examples of Protecting Content Using JSON Object Signing and Encryption (JOSE), https://tools.ietf.org/html/rfc7520
#
# Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
# SPDX-License-Identifier: BSD-2-Clause-Patent
#
##

import os
import copy
import cbor
import json
import operator
import argparse
import subprocess
import configparser
from jose import jws
from binascii import hexlify
from ecdsa.keys import SigningKey, VerifyingKey
from pycose.cosemessage import CoseMessage
from pycose.signmessage import SignMessage

FspToolPath = os.path.join(os.path.dirname(__file__), 'FspTools.py')

VersionSchemeMap = {'multipartnumeric': 1, 'multipartnumeric-suffix': 2, 'alphanumeric': 3, 'decimal': 4, 'semver': 16384}
HashAlgorithmMap = {"SHA_256": 1, "SHA_256_128": 2, "SHA_256_120": 3, "SHA_256_96": 4, "SHA_256_64": 5, "SHA_256_32": 6,
                    "SHA_384": 7, "SHA_512": 8, "SHA_3_224": 9, "SHA_3_256": 9, "SHA_3_384": 9, "SHA_3_512": 9}
RoleMap = {"tagCreator": 1, "softwareCreator": 2, "aggregator": 3, "distributor": 4, "licensor": 5}
RelMap = {'ancestor': 1, 'component': 2, 'feature': 3, 'installationmedia': 4, 'packageinstaller': 5, 'parent': 6,
          'patches': 7, 'requires': 8, 'see-also': 9, 'supersedes': 10, 'supplemental': 11}

PayloadTypeMap = {"direct": 0, "indirect": 1, "hybriid": 2}
SupportHashAlgorithmMap = {"SHA_256": 1, "SHA_384": 7, "SHA_512": 8, "SHA_3_256": 10, "SHA_3_384": 11, "SHA_3_512": 12}

CoseTypeMap = {"cose-sign": 98, "cose-sign1": 18, "cose-encrypt": 96, "cose-encrypt0": 16, "cose-mac": 97, "cose-mac0": 17}
CoseKeyMap = {"alg": 1, "crit": 2, "content type": 3, "kid": 4, "IV": 5, "Partial IV": 6, "counter signature": 7}
SignSupportAlgorithmMap = {"ES256": -7, "ES384": -35, "ES512": -36}


EntityBuilder = {'name': None, 'role': [], 'regid': None, 'thumbprint': None}
LinkBuilder = {'artifact': None, 'href': None, 'media': None, 'ownership': None, 'rel': None, 'type': None, 'use': None}
MetaBuilder = {'colloquialVersion': None, 'edition': None, 'product': None, 'revision': None}
DirectoryBuilder = {'name': None, 'location': None, 'file': []}
FileBuilder = {'name': None, 'size': None, 'version': None}
ReferenceMeasurementBuilder = {'PayloadType': None, 'PlatformManufacturerStr': None, 'PlatformManufacturerId': None,
                               'PlatformModel': None, 'PlatformVersion': None, 'FirmwareManufacturerStr': None,
                               'FirmwareManufacturerId': None, 'FirmwareMode': None, 'FirmwareVersion': None, 'BindingSpec': None,
                               'BindingSpecVersion': None, 'pcURIlocal': None, 'pcURIGlobal': None, 'RIMLinkHash': None}

mapDict = {"tag-id": 0, "software-name": 1, "entity": 2, "evidence": 3, "link": 4, "software-meta": 5, "payload": 6,
           "hash": 7, "corpus": 8, "patch": 9, "media": 10, "supplemental": 11, "tag-version": 12, "software-version": 13,
            "version-scheme": 14, "lang": 15, "directory": 16, "file": 17, "process": 18, "resource": 19, "size": 20,
            "file-version": 21, "key": 22, "location": 23, "fs-name": 24, "root": 25, "path-elements": 26, "process-name": 27,
            "pid": 28, "type": 29, "entity-name": 31, "reg-id": 32, "role": 33, "thumbprint": 34, "date": 35, "device-id": 36,
            "artifact": 37, "href": 38, "ownership": 39, "rel": 40, "media-type": 41, "use": 42, "activation-status": 43,
            "channel-type": 44, "colloquial-version": 45, "description": 46, "edition": 47, "entitlement-data-required": 48,
            "entitlement-key": 49, "generator": 50, "persistent-id": 51, "product": 52, "product-family": 53, "revision": 54,
            "summary": 55, "unspsc-code": 56, "unspsc-version": 57, "reference-measurement": 58, "payload-type": 59, "payload-rim":60,
            "platform-configuration-uri-global": 61, "platform-configuration-uri-local": 62, "binding-spec-name": 63,
            "binding-spec-version": 64, "platform-manufacturer-id": 65, "platform-manufacturer-name": 66, "platform-model-name": 67,
            "platform-version": 68, "firmware-manufacturer-id": 69, "firmware-manufacturer-name": 70, "firmware-model-name": 71,
            "firmware-version": 72, "rim-link-hash": 73, "support-rim-type-kramdown": 74, "support-rim-format": 75, "support-rim-uri-global": 76,
            "rim-reference": 77, "boot-events": 78, "boot-event-number": 79, "boot-event-type": 80, "boot-digest-list": 81, "boot-event-data": 82}

class SWIDBuilder:
    def __init__(self):
        self.name = None
        self.tagId = None
        self.tagVersion = None
        self.version = None
        self.corpus = None
        self.patch = None
        self.supplemental = None
        self.versionScheme = None
        self.media = None
        self.entities = []
        self.evidence = []
        self.links = []
        self.metas = []
        self.payload = []
        self.ReferenceMeasurement = []

    def addEntity(self, entity):
        self.entities.append(entity)

    def addLink(self, link):
        self.links.append(link)

    def addMeta(self, meta):
        self.metas.append(meta)

    def addPayload(self, payload):
        self.payload.append(payload)

    def addReferenceMeasurement(self, ReferenceMeasurement):
        self.ReferenceMeasurement.append(ReferenceMeasurement)

class GenCbor():
    def __init__(self, OutputFile, SWIDBuilder, HashType):
        self.CborPath = OutputFile
        self.CborData = {}
        self.SWIDBuilder = SWIDBuilder
        self.HashType = HashType
        self.MetaAttNonEmptyList = ['colloquialVersion', 'edition', 'product', 'revision']
        self.ReferenceMeasurementAttNonEmptyList = ['BindingSpec', 'BindingSpecVersion', 'PlatformManufacturerStr', 'PlatformManufacturerId',
                                                    'PlatformModel']

    def buildAttribute(self, dict, tag, value):
        if value != None:
            dict[tag] = value

    def validateNonEmpty(self, tagName, value):
        if value == None or value == [] or value == '':
            raise Exception("The field {} must contain a non-empty value".format(tagName))

    def validateEntity(self, entity):
        self.validateNonEmpty('name', entity['name'])
        self.validateNonEmpty('role', entity['role'])
        # self.validateNonEmpty('thumbprint', entity['thumbprint'])

    def validateLink(self, link):
        self.validateNonEmpty('href', link['href'])
        self.validateNonEmpty('rel', link['rel'])

    def validateMeta(self, meta):
        for AttributeName in self.MetaAttNonEmptyList:
            self.validateNonEmpty(AttributeName, meta[AttributeName])

    def validateReferenceMeasurement(self, ReferenceMeasurement):
        for AttributeName in self.ReferenceMeasurementAttNonEmptyList:
            self.validateNonEmpty(AttributeName, ReferenceMeasurement[AttributeName])

    def validate(self):
        self.validateNonEmpty('name', self.SWIDBuilder.name)
        self.validateNonEmpty('version', self.SWIDBuilder.tagId)
        self.validateNonEmpty('tagId', self.SWIDBuilder.tagId)
        self.validateNonEmpty('tagVersion', self.SWIDBuilder.tagVersion)
        self.validateNonEmpty('entity', self.SWIDBuilder.entities)
        self.validateNonEmpty('meta', self.SWIDBuilder.metas)
        self.validateNonEmpty('ReferenceMeasurement', self.SWIDBuilder.ReferenceMeasurement)

        foundTagCreator = False
        for entity in self.SWIDBuilder.entities:
            self.validateEntity(entity)
            for role in entity['role'].split(' '):
                if role not in RoleMap.keys():
                    raise Exception('Role "{}" should be one in [{}].'.format(role, ' '.join(RoleMap.keys())))
            if 'tagCreator' in entity['role']:
                foundTagCreator = True

        if not foundTagCreator:
            raise Exception('at least one entity with role, tagCreator must be provided.')

        for link in self.SWIDBuilder.links:
            self.validateLink(link)

        for meta in self.SWIDBuilder.metas:
            self.validateMeta(meta)

        for ReferenceMeasurement in self.SWIDBuilder.ReferenceMeasurement:
            self.validateReferenceMeasurement(ReferenceMeasurement)

    def genCobor(self):
        self.validate()
        # Required
        self.CborData[mapDict['tag-id']] = self.SWIDBuilder.tagId
        self.CborData[mapDict['tag-version']] = int(self.SWIDBuilder.tagVersion)
        self.CborData[mapDict['software-name']] = self.SWIDBuilder.name
        self.CborData[mapDict['software-version']] = self.SWIDBuilder.version

        # Optional
        if self.SWIDBuilder.corpus != None:
            self.CborData[mapDict['corpus']] = ConvertStrToBool(self.SWIDBuilder.corpus)
        if self.SWIDBuilder.patch != None:
            self.CborData[mapDict['patch']] = ConvertStrToBool(self.SWIDBuilder.patch)
        if self.SWIDBuilder.supplemental != None:
            self.CborData[mapDict['supplemental']] = ConvertStrToBool(self.SWIDBuilder.supplemental)
        if self.SWIDBuilder.versionScheme != None:
            self.CborData[mapDict['version-scheme']] = VersionSchemeMap[self.SWIDBuilder.versionScheme]
        if self.SWIDBuilder.media != None:
            self.CborData[mapDict['media']] = VersionSchemeMap[self.SWIDBuilder.media]

        if self.SWIDBuilder.metas != []:
            self.CborData[mapDict['software-meta']] = []
            for meta in self.SWIDBuilder.metas:
                meta_dict = {}
                meta_dict[mapDict['colloquial-version']] = meta['colloquialVersion']
                meta_dict[mapDict['edition']] = meta['edition']
                meta_dict[mapDict['product']] = meta['product']
                meta_dict[mapDict['revision']] = meta['revision']
                self.CborData[mapDict['software-meta']].append(meta_dict)

        if self.SWIDBuilder.entities != []:
            self.CborData[mapDict['entity']] = []
            for entity in self.SWIDBuilder.entities:
                entity_dict = {}
                entity_dict[mapDict['entity-name']] = entity['name']
                entity_dict[mapDict['role']] = []
                for role in entity['role'].split(' '):
                    entity_dict[mapDict['role']].append(RoleMap[role])
                entity_dict[mapDict['thumbprint']] = []
                # hash-alg-id
                entity_dict[mapDict['thumbprint']].append(HashAlgorithmMap[self.HashType])
                # hash-value
                entity_dict[mapDict['thumbprint']].append(entity['thumbprint'])
                # optional
                if entity['regid'] != None:
                    entity_dict[mapDict['reg-id']] = entity['regid']

                self.CborData[mapDict['entity']].append(entity_dict)

        if self.SWIDBuilder.links != []:
            self.CborData[mapDict['link']] = []
            for link in self.SWIDBuilder.links:
                link_dict = {}
                # required
                link_dict[mapDict['href']] = link['href']
                link_dict[mapDict['rel']]  = RelMap[link['rel']]
                self.CborData[mapDict['link']].append(link_dict)

        PayloadData = self.SWIDBuilder.payload[0]
        if self.SWIDBuilder.payload != []:
            self.CborData[mapDict['payload']] = {}
            self.CborData[mapDict['payload']][mapDict['directory']] = {}
            self.CborData[mapDict['payload']][mapDict['directory']][mapDict['fs-name']] = PayloadData['name']
            self.CborData[mapDict['payload']][mapDict['directory']][mapDict['location']] = PayloadData['location']

            self.CborData[mapDict['payload']][mapDict['directory']][mapDict['path-elements']] = {}
            self.CborData[mapDict['payload']][mapDict['directory']][mapDict['path-elements']][mapDict['file']] = []
            for file in PayloadData['file']:
                FileElement = {}
                FileElement[mapDict['fs-name']] = file['name']
                FileElement[mapDict['size']] = file['size']
                FileElement[mapDict['hash']] = []
                FileElement[mapDict['hash']].append(HashAlgorithmMap[self.HashType])
                FileElement[mapDict['hash']].append(file[self.HashType])
                self.CborData[mapDict['payload']][mapDict['directory']][mapDict['path-elements']][mapDict['file']].append(FileElement)

        ReferenceMeasurement = self.SWIDBuilder.ReferenceMeasurement[0]
        if self.SWIDBuilder.ReferenceMeasurement != []:
            self.CborData[mapDict['reference-measurement']] = {}
            self.CborData[mapDict['reference-measurement']][mapDict['payload-type']] = PayloadTypeMap[ReferenceMeasurement['PayloadType'].lower()]
            self.CborData[mapDict['reference-measurement']][mapDict['platform-configuration-uri-global']] = ReferenceMeasurement['pcURIGlobal']
            self.CborData[mapDict['reference-measurement']][mapDict['platform-configuration-uri-local']] = ReferenceMeasurement['pcURIlocal']
            self.CborData[mapDict['reference-measurement']][mapDict['binding-spec-name']] = ReferenceMeasurement['BindingSpec']
            self.CborData[mapDict['reference-measurement']][mapDict['binding-spec-version']] = ReferenceMeasurement['BindingSpecVersion']
            self.CborData[mapDict['reference-measurement']][mapDict['platform-manufacturer-id']] = ReferenceMeasurement['PlatformManufacturerId']
            self.CborData[mapDict['reference-measurement']][mapDict['platform-manufacturer-name']] = ReferenceMeasurement['PlatformManufacturerStr']
            self.CborData[mapDict['reference-measurement']][mapDict['platform-model-name']] = ReferenceMeasurement['PlatformModel']
            self.CborData[mapDict['reference-measurement']][mapDict['platform-version']] = ReferenceMeasurement['PlatformVersion']
            self.CborData[mapDict['reference-measurement']][mapDict['firmware-manufacturer-id']] = ReferenceMeasurement['FirmwareManufacturerId']
            self.CborData[mapDict['reference-measurement']][mapDict['firmware-manufacturer-name']] = ReferenceMeasurement['FirmwareManufacturerStr']
            self.CborData[mapDict['reference-measurement']][mapDict['firmware-model-name']] = ReferenceMeasurement['FirmwareMode']
            self.CborData[mapDict['reference-measurement']][mapDict['firmware-version']] = ReferenceMeasurement['FirmwareVersion']
            self.CborData[mapDict['reference-measurement']][mapDict['rim-link-hash']] = []
            self.CborData[mapDict['reference-measurement']][mapDict['rim-link-hash']].append(HashAlgorithmMap[self.HashType])
            self.CborData[mapDict['reference-measurement']][mapDict['rim-link-hash']].append(ReferenceMeasurement['RIMLinkHash'])

        # delete key which value is null in reference-measurement
        for key in list(self.CborData[mapDict['reference-measurement']].keys()):
            if self.CborData[mapDict['reference-measurement']][key] == None:
                del self.CborData[mapDict['reference-measurement']][key]

        with open(self.CborPath, 'wb') as f:
            f.write(cbor.dumps(self.CborData))

        print(json.dumps(self.CborData, indent=2))

class DecodeCbor():
    def __init__(self, FilePath):
        self.FilePath = FilePath
        f = open(self.FilePath, 'rb')
        self.CborData = cbor.load(f)
        f.close()

    def SearchKey(self, Dict, keyValue):
        for key in Dict.keys():
            if key == keyValue:
                return Dict[key]
            else:
                if isinstance(Dict[key], dict):
                    if self.SearchKey(Dict[key], keyValue) != None:
                        return self.SearchKey(Dict[key], keyValue)
                elif isinstance(Dict[key], list):
                    for item in Dict[key]:
                        if isinstance(item, dict):
                            if self.SearchKey(item, keyValue) != None:
                                return self.SearchKey(item, keyValue)
                else:
                    pass

    def Decode(self):
        if isinstance(self.CborData, dict):
            self.DecodeCbor(self.CborData)
        else:
            self.DecodeSignedCbor(self.CborData)

    def DecodeCbor(self, cborDict):
        jd = json.dumps(cborDict, indent=2)

        RoleMessage = str([GetKeyByValue(RoleMap, role) for role in self.SearchKey(cborDict, 33)])
        ThumbprintHashMessage = str(GetKeyByValue(HashAlgorithmMap, self.SearchKey(cborDict, 34)[0]))
        payloadFileHashMessage = str(GetKeyByValue(HashAlgorithmMap, self.SearchKey(cborDict, 7)[0]))
        payloadTypeMessage = str(GetKeyByValue(PayloadTypeMap, self.SearchKey(cborDict, 59)))
        rimlinkHashMessage = str(GetKeyByValue(HashAlgorithmMap, self.SearchKey(cborDict, 73)[0]))

        signatureFlag = 0
        for line in jd.split('\n'):
            if ':' in line:
                flag = 0
                for key in ["cose-sign", "protected", "unprotected", "concise-swid-tag", "signatures"]:
                    if key in line:
                        flag = 1
                if "signature" in line:
                    signatureFlag = 1

                if flag:
                    print(line)
                else:
                    KeyValue = eval(eval(line.split(':')[0]))
                    if KeyValue == 33:
                        print(line + '   // ' + GetKeyByValue(mapDict, KeyValue) + ': ' + RoleMessage)
                    elif KeyValue == 34:
                        print(line + '   // ' + GetKeyByValue(mapDict, KeyValue) + ': ' + ThumbprintHashMessage)
                    elif KeyValue == 7:
                        print(line + '   // ' + GetKeyByValue(mapDict, KeyValue) + ': ' + payloadFileHashMessage)
                    elif KeyValue == 59:
                        print(line + '   // ' + GetKeyByValue(mapDict, KeyValue) + ': ' + payloadTypeMessage)
                    elif KeyValue == 73:
                        print(line + '   // ' + GetKeyByValue(mapDict, KeyValue) + ': ' + rimlinkHashMessage)
                    else:
                        if not signatureFlag:
                            print(line + '   // ' + GetKeyByValue(mapDict, KeyValue))
                        else:
                            if KeyValue == 1:
                                print(line + '   // ' + GetKeyByValue(CoseKeyMap, KeyValue) + ': ' + GetKeyByValue(SignSupportAlgorithmMap, eval(line.split(':')[1])))
                            else:
                                print(line + '   // ' + GetKeyByValue(CoseKeyMap, KeyValue))
            else:
                print(line)

    def DecodeSignedCbor(self, cborData):
        SignedCborDict = {}
        SignedCborDict[GetKeyByValue(CoseTypeMap, cborData.tag)] = {}
        SignedCborDict[GetKeyByValue(CoseTypeMap, cborData.tag)]["protected"] = str(cborData.value[0])
        SignedCborDict[GetKeyByValue(CoseTypeMap, cborData.tag)]["unprotected"] = str(cborData.value[1])
        SignedCborDict[GetKeyByValue(CoseTypeMap, cborData.tag)]["concise-swid-tag"] = cbor.loads(cborData.value[2])
        SignedCborDict[GetKeyByValue(CoseTypeMap, cborData.tag)]["signatures"] = []
        for num, item in enumerate(cborData.value[3]):
            cborData.value[3][num][0] = cbor.loads(cborData.value[3][num][0])
            cborData.value[3][num][2] = hexlify(cborData.value[3][num][2]).decode()
            SignedCborDict[GetKeyByValue(CoseTypeMap, cborData.tag)]["signatures"].append(cborData.value[3][num])

        self.DecodeCbor(SignedCborDict)

def ConvertStrToBool(str):
    if str.lower() == 'true':
        return True
    elif str.lower() == 'false':
        return False
    else:
        raise Exception('Value should be "True" or "False".')

def GetValueFromSec(ini_obj, section, option):
    if ini_obj.has_option(section, option):
        return ini_obj.get(section, option)
    else:
        return None

def ParseAndBuildSwidData(IniPath, PayloadFile, HashTypes, Mode):
    swid_builder = SWIDBuilder()

    ini = configparser.ConfigParser()
    ini.read(IniPath, encoding='utf-8')
    sections = ini.sections()

    for section in sections:
        if section == 'SoftwareIdentity':
            swid_builder.name = GetValueFromSec(ini, section, 'name')
            swid_builder.tagId = GetValueFromSec(ini, section, 'tagid')
            swid_builder.version = GetValueFromSec(ini, section, 'version')
            swid_builder.corpus = GetValueFromSec(ini, section, 'corpus').lower()
            swid_builder.patch = GetValueFromSec(ini, section, 'patch').lower()
            swid_builder.supplemental = GetValueFromSec(ini, section, 'supplemental').lower()
            swid_builder.tagVersion = GetValueFromSec(ini, section, 'tagversion')
            swid_builder.versionScheme = GetValueFromSec(ini, section, 'versionscheme')
        elif section.startswith('Entity'):
            Entity = copy.deepcopy(EntityBuilder)
            for Attribute in EntityBuilder.keys():
                Entity[Attribute] = GetValueFromSec(ini, section, Attribute)
            swid_builder.addEntity(Entity)
        elif section.startswith('Link'):
            Link = copy.deepcopy(LinkBuilder)
            for Attribute in LinkBuilder.keys():
                Link[Attribute] = GetValueFromSec(ini, section, Attribute)
            swid_builder.addLink(Link)
        elif section.startswith('Meta'):
            Meta = copy.deepcopy(MetaBuilder)
            ReferenceMeasurement = copy.deepcopy(ReferenceMeasurementBuilder)
            for Attribute in MetaBuilder.keys():
                Meta[Attribute] = GetValueFromSec(ini, section, Attribute)
            for Attribute in ReferenceMeasurementBuilder.keys():
                ReferenceMeasurement[Attribute] = GetValueFromSec(ini, section, Attribute.lower())
            swid_builder.addMeta(Meta)
            swid_builder.addReferenceMeasurement(ReferenceMeasurement)

    payload = genPayloadBuilder(PayloadFile, HashTypes, Mode)
    swid_builder.addPayload(payload)

    return swid_builder

def genPayloadBuilder(FileName, HashAlgorithm, Mode):   
    CmdList = ['python', FspToolPath, 'hash', '-f', FileName, '-m', Mode]

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

    FSPComponents = msg[0].decode().split('\r\n')

    db = copy.deepcopy(DirectoryBuilder)
    db['name'] = 'FSP binary'
    db['location'] = os.path.relpath(FileName)

    for comp in FSPComponents:
        if comp != '':
            fb = copy.deepcopy(FileBuilder)
            fb['name'] = comp.split(' ')[0]
            fb['size'] = comp.split(' ')[1]
            fb[HashAlgorithm] = comp.split(' ')[2]
            db['file'].append(fb)

    return db

def GetKeyByValue(dict, value):
    for key in dict.keys():
        if dict[key] == value:
            return key

def DecodeJwt(FilePath):
    with open(FilePath, 'rb') as f:
        SignedData = f.read()

    header, payload, signing_input, signature = jws._load(SignedData)
    print('header: {}'.format(header))
    print('payload: {}'.format(json.dumps(json.loads(payload), indent=2)))
    print('signing key: {}'.format(signing_input))
    print('signature: {}'.format(signature))

def SignCbor(FilePath, Key, Algorithm, SignedCborPath):
    with open(FilePath, 'rb') as f:
        cborData = f.read()

    with open(Key, 'r') as f:
        key = SigningKey.from_pem(f.read())

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

def VerifySignedCbor(FilePath, Key, Algorithm):
    with open(FilePath, 'rb') as f:
        cose_msg = CoseMessage.decode(f.read())

    with open(Key, 'r') as f:
        key = VerifyingKey.from_pem(f.read())

    cose_msg.key = key
    cose_msg.verify_signature(Algorithm, signer=1)

    print("Signature verification passed")

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

def VerifySignedJwt(FilePath, Key, Algorithm):
    with open(FilePath, 'rb') as f:
        SignedData = f.read()

    with open(Key, 'r') as f:
        key = f.read()

    jws.verify(SignedData, key, Algorithm, verify=True)

    print("Signature verification passed")

def VerifyHash(CborFile, TcgEventLog, FlashBinary):
    Mode = 'binary'

    CborHashDict = {}
    TcgEventLogDict = {}
    FlashBinaryDict = {}

    Decode = DecodeCbor(CborFile)
    if isinstance(Decode.CborData, dict):
        for item in Decode.SearchKey(Decode.CborData, mapDict['file']):
            CborHashDict[item[mapDict["fs-name"]]] = item[mapDict["hash"]][1]
    else:
        for item in Decode.SearchKey(cbor.loads(Decode.CborData.value[2]), mapDict['file']):
            CborHashDict[item[mapDict["fs-name"]]] = item[mapDict["hash"]][1]

    # Check mode is binary or separation
    if len(CborHashDict) == 6:
        Mode = 'separation'

    GetHashFromTcgCmd = ['python', FspToolPath, 'hash', '-f', TcgEventLog, '--tcg', '-m', Mode]
    GetHashFromFspCmd = ['python', FspToolPath, 'hash', '-f', FlashBinary, '-m', Mode]

    if FlashBinary != '':
        GetHash = subprocess.Popen(GetHashFromFspCmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, shell=False)
        msg = GetHash.communicate()
        FSPComponents = msg[0].decode().split('\r\n')
        for item in FSPComponents:
            if item != '':
                FlashBinaryDict[item.split(' ')[0]] = item.split(' ')[2]

        if operator.eq(CborHashDict, FlashBinaryDict):
            print('Hash verify pass!')
        else:
            print('Hash verify fail!')
            print('Hash in cbor:\n{}'.format(CborHashDict))
            print('Hash in flash bianry:\n{}'.format(FlashBinaryDict))
    else:
        GetHash = subprocess.Popen(GetHashFromTcgCmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, shell=False)
        msg = GetHash.communicate()
        FSPComponents = msg[0].decode().split('\r\n')
        for item in FSPComponents:
            if item != '':
                TcgEventLogDict[item.split(' ')[0]] = item.split(' ')[1]

        if operator.eq(CborHashDict, TcgEventLogDict):
            print('Hash verify pass!')
        else:
            print('Hash verify fail!')
            print('Hash in cbor:\n{}'.format(CborHashDict))
            print('Hash in TCG event log:\n{}'.format(TcgEventLogDict))

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(title='commands', dest="which")

    parser_gencoswid = subparsers.add_parser('gencoswid', help='Generate CoSwid file in CBOR format')
    parser_gencoswid .set_defaults(which='gencoswid')
    parser_gencoswid .add_argument('-i', '--inifile', dest='IniPath', type=str, help='Ini configuration file path', required=True)
    parser_gencoswid .add_argument('-p', '--payload', dest='Payload', type=str, help="Payload File name", required=True)
    parser_gencoswid.add_argument('-m', '--mode', choices=['binary', 'separation'], dest='Mode', type=str, help='Different mode to generate hash for FSP image', default='binary')
    parser_gencoswid .add_argument('-t', '--hash', dest='HashType',  type=str, choices=SupportHashAlgorithmMap.keys(), help="Hash types {}".format(str(HashAlgorithmMap.keys())), default='SHA_256')
    parser_gencoswid .add_argument('-o', '--outfile', dest='OutputFile', type=str, help='Output Cbor file path', default='', required=True)

    parser_dump = subparsers.add_parser('dump', help='dump CoSwid CBOR file')
    parser_dump.set_defaults(which='dump')
    parser_dump.add_argument('-f', '--file', dest='File', type=str, help='Cbor format file path', required=True)
    parser_dump.add_argument('--jwt', dest='JWT', action='store_true', help='Flag used to enable decode Json Web Token')

    parser_sign = subparsers.add_parser('sign', help='Sign CoSwid CBOR file')
    parser_sign.set_defaults(which='sign')
    parser_sign.add_argument('-f', '--file', dest='File', type=str, help='Cbor format file path', required=True)
    parser_sign.add_argument('--key', dest='PrivateKey', type=str, help='Private key for signing', required=True)
    parser_sign.add_argument('--alg', dest='Algorithm', type=str, choices=SignSupportAlgorithmMap.keys(), help='Algorithm for signing', required=True)
    parser_sign.add_argument('--jws', dest='JWS', action='store_true', help='Flag used to enable use JWS to sign cbor')
    parser_sign.add_argument('-o', '--output', dest='SignedCborPath', type=str, help='SignedCbor file path COSE/JWS', required=True)

    parser_verify = subparsers.add_parser('verify', help='Verify signature of signed CoSwid CBOR file')
    parser_verify.set_defaults(which='verify')
    parser_verify.add_argument('-f', '--file', dest='File', type=str, help='Signed file path', required=True)
    parser_verify.add_argument('--key', dest='PublicKey', type=str, help='Public key for signing', required=True)
    parser_verify.add_argument('--alg', dest='Algorithm', type=str, choices=SignSupportAlgorithmMap.keys(), help='Algorithm for signing', required=True)
    parser_verify.add_argument('--jws', dest='JWS', action='store_true', help='Flag used to enable use JWS to verify JWT')

    parser_verify_hash = subparsers.add_parser('verify-hash', help='Verify hash in RIM')
    parser_verify_hash.set_defaults(which='verify-hash')
    parser_verify_hash.add_argument('-f', '--file', dest='File', type=str, help='Cbor format file path', required=True)
    parser_verify_hash.add_argument('--evt', dest='TcgEventLog', type=str, help='Tcg event log path', default='')
    parser_verify_hash.add_argument('--bin', dest='FlashBinary', type=str, help='Flash binary path', default='')

    args = parser.parse_args()

    if args.which == 'gencoswid':
        if not os.path.exists(args.IniPath):
            raise Exception("ERROR: Could not locate Ini file '%s' !" % args.IniPath)
        if not os.path.exists(args.Payload):
            raise Exception("ERROR: Could not locate payload file '%s' !" % args.Payload)
        if os.path.isabs(args.OutputFile):
            if not os.path.exists(os.path.dirname(args.OutputFile)):
                os.makedirs(os.path.dirname(args.OutputFile))

    if args.which == 'dump':
        if not os.path.exists(args.File):
            raise Exception("ERROR: Could not locate Cbor file '%s' !" % args.File)

    if args.which == 'sign':
        if not os.path.exists(args.File):
            raise Exception("ERROR: Could not locate Cbor file '%s' !" % args.File)
        if os.path.isabs(args.SignedCborPath):
            if not os.path.exists(os.path.dirname(args.SignedCborPath)):
                os.makedirs(os.path.dirname(args.SignedCborPath))

    if args.which == 'verify':
        if not os.path.exists(args.File):
            raise Exception("ERROR: Could not locate file '%s' !" % args.File)

    if args.which == 'verify-hash':
        if not os.path.exists(args.File):
            raise Exception("ERROR: Could not locate file '%s' !" % args.File)
        if args.TcgEventLog == '' and args.FlashBinary == '':
            raise Exception("ERROR: At least one of Tcg event log and flash binary be given!")
        if args.TcgEventLog != '':
            if not os.path.exists(args.TcgEventLog):
                raise Exception("ERROR: Could not locate file '%s' !" % args.TcgEventLog)
        if args.FlashBinary != '':
            if not os.path.exists(args.FlashBinary):
                raise Exception("ERROR: Could not locate file '%s' !" % args.FlashBinary)

    if args.which == 'gencoswid':
        Encode = GenCbor(args.OutputFile, ParseAndBuildSwidData(args.IniPath, args.Payload, args.HashType, args.Mode), args.HashType)
        Encode.genCobor()
    elif args.which == 'dump':
        if args.JWT:
            DecodeJwt(args.File)
        else:
            Decode = DecodeCbor(args.File)
            Decode.Decode()

    if args.which == 'sign':
        if args.JWS:
            SignCborByJws(args.File, args.PrivateKey, args.Algorithm, args.SignedCborPath)
        else:
            SignCbor(args.File, args.PrivateKey, args.Algorithm, args.SignedCborPath)

    if args.which == 'verify':
        if args.JWS:
            VerifySignedJwt(args.File, args.PublicKey, args.Algorithm)
        else:
            VerifySignedCbor(args.File, args.PublicKey, args.Algorithm)

    if args.which == 'verify-hash':
        VerifyHash(args.File, args.TcgEventLog, args.FlashBinary)
