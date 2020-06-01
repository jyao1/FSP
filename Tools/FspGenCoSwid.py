## @ FspGenCoSwid.py
#
# Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
# SPDX-License-Identifier: BSD-2-Clause-Patent
#
##

import os
import copy
import cbor
import hashlib

# TagType
# CORPUS = 1
# PATCH = 2
# SUPPLEMENTAL = 3
# PRIMARY = 0
TagTypeDict   = {0: 'primary', 1: 'corpus', 2: 'patch', '3': 'supplemental'}
RoleList      = ['aggregator', 'distributor', 'licensor', 'softwareCreator', 'tagCreator']
UseList       = ['required', 'recommended', 'optional']
OwnershipList = ['abandon', 'private', 'shared']
VersionSchemeList = ['multipartnumeric', 'multipartnumeric+suffix', 'alphanumeric', 'decimal', 'semver', 'unknown']
HashAlgorithmMap = {"SHA-256": 1, "SHA_256_128": 2, "SHA_256_120": 3, "SHA_256_96": 4, "SHA_256_64": 5, "SHA_256_32": 6, "SHA_384": 7, "SHA-512": 8, "SHA_3_224": 9, "SHA_3_256": 9, "SHA_3_384": 9, "SHA_3_512": 9}

EntityBuilder = {'name': '', 'role': [], 'regid': '', 'thumbprint': ''}
LinkBuilder = {'artifact': '', 'href': '', 'media': '', 'ownership': '', 'rel': '', 'type': '', 'use': ''}
MetaBuilder = {'activationStatus': '', 'channelType': '', 'colloquialVersion': '', 'description': '', 'edition': '', 'entitlementDataRequired': '',
               'entitlementKey': '', 'generator': '', 'persistentId': '', 'productBaseName': '', 'productFamily': '', 'revision': '', 'summary': '',
               'unspscCode': '', 'unspscVersion': ''}
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


class SWIDBuilder:
    def __init__(self):
        self.tagType = 0
        self.name = ''
        self.tagId = ''
        self.tagVersion = 0
        self.version = ''
        self.versionScheme = ''
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

class bin:
    def __init__(self, path):
        self.BinPath = path
        # Name to ID map dict
        self.mapDict = {"tag-id": 0, "swid-name": 1, "entity": 2, "evidence": 3, "link": 4, "software-meta": 5, "payload": 6,
                        "hash": 7, "corpus": 8, "patch": 9, "media": 10, "supplemental": 11, "tag-version": 12, "software-version": 13,
                        "version-scheme": 14, "lang": 15, "directory": 16, "file": 17, "process": 18, "resource": 19, "size": 20,
                        "file-version": 21, "key": 22, "location": 23, "fs-name": 24, "root": 25, "path-elements": 26, "process-name": 27,
                        "pid": 28, "type": 29, "entity-name": 31, "reg-id": 32, "role": 33, "thumbprint": 34, "date": 35, "device-id": 36,
                        "artifact": 37, "href": 38, "ownership": 39, "rel": 40, "media-type": 41, "use": 42, "activation-status": 43,
                        "channel-type": 44, "colloquial-version": 45, "description": 46, "edition": 47, "entitlement-data-required": 48,
                        "entitlement-key": 49, "generator": 50, "persistent-id": 51, "product": 52, "product-family": 53, "revision": 54,
                        "summary": 55, "unspsc-code": 56, "unspsc-version": 57}

    # Parser bin data
    def parseBin(self):
        with open(self.BinPath, 'rb') as f:
            binData = f.read()


class GenCbor():
    def __init__(self, CborPath, SWIDBuilder):
        self.CborPath = CborPath
        self.CborData = {}
        self.SWIDBuilder = SWIDBuilder

    def genCobor(self):
        # required attributes
        self.CborData[mapDict['tag-id']] = self.SWIDBuilder.tagId
        self.CborData[mapDict['tag-version']] = self.SWIDBuilder.tagVersion
        self.CborData[mapDict['swid-name']] = self.SWIDBuilder.name

        if self.SWIDBuilder.version != '':
            self.CborData[mapDict['software-version']] = self.SWIDBuilder.version
        if self.SWIDBuilder.versionScheme != '':
            self.CborData[mapDict['version-scheme']] = self.SWIDBuilder.versionScheme

        # Optional attribute
        if self.SWIDBuilder.tagType not in TagTypeDict.keys():
            print("TagType: {} is illegal".format(self.SWIDBuilder.tagType))
            os._exit()
        elif self.SWIDBuilder.tagType == 0:
            pass
        else:
            self.CborData[mapDict[TagTypeDict[self.SWIDBuilder.tagType]]] = 'true'

        if self.SWIDBuilder.payload != []:
            self.CborData[mapDict['payload']] = {}
            self.CborData[mapDict['payload']][mapDict['file']] = {}
            self.CborData[mapDict['payload']][mapDict['file']][mapDict['fs-name']] = str(self.SWIDBuilder.payload[0]['name'])
            self.CborData[mapDict['payload']][mapDict['file']][mapDict['size']]    = self.SWIDBuilder.payload[0]['size']
            self.CborData[mapDict['payload']][mapDict['file']][mapDict['hash']]    = [HashAlgorithmMap['SHA-256'], str(self.SWIDBuilder.payload[0]['hash']['SHA-256'])]

        print(self.CborData)
        with open(self.CborPath, 'wb') as f:
            f.write(cbor.dumps(self.CborData))

def genFileBuilder(FileName, HashAlgorithms):
    if not os.path.exists(FileName):
        raise Exception("{} is not exists.".format(FileName))

    with open(FileName, 'rb') as f:
        content = f.read()

    fb = copy.deepcopy(FileBuilder)
    fb['name'] = FileName
    fb['size'] = os.path.getsize(FileName)
    fb['version'] = ''
    for HashAlgorithm in HashAlgorithms:
        if HashAlgorithm.lower() == 'sha256':
            fb['hash']['SHA-256'] = hashlib.sha256(content).hexdigest()

    return fb

if __name__ == "__main__":
    ss = genFileBuilder('Fsp.fd', ['SHA256'])
    xx = SWIDBuilder()
    xx.tagId = '052'
    xx.tagVersion = 123456
    xx.name = 'hello'
    xx.addPayload(ss)

    cc = GenCbor('FspManifest.cbor', xx)
    cc.genCobor()