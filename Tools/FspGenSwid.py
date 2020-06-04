## @ FspGenSwid.py
#
# Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
# SPDX-License-Identifier: BSD-2-Clause-Patent
#
##

import os
import copy
import hashlib
import argparse
import configparser
from xml.dom.minidom import Document

TagTypeList   = ['primary', 'corpus', 'patch', 'supplemental']
RoleList      = ['aggregator', 'distributor', 'licensor', 'softwareCreator', 'tagCreator']
UseList       = ['required', 'recommended', 'optional']
OwnershipList = ['abandon', 'private', 'shared']
VersionSchemeList = ['multipartnumeric', 'multipartnumeric+suffix', 'alphanumeric', 'decimal', 'semver', 'unknown']
HashAlgorithmMap = {"SHA-256": 1, "SHA_256_128": 2, "SHA_256_120": 3, "SHA_256_96": 4, "SHA_256_64": 5, "SHA_256_32": 6,
                    "SHA_384": 7, "SHA-512": 8, "SHA_3_224": 9, "SHA_3_256": 9, "SHA_3_384": 9, "SHA_3_512": 9}

EntityBuilder = {'name': '', 'role': [], 'regid': '', 'thumbprint': ''}
LinkBuilder = {'artifact': '', 'href': '', 'media': '', 'ownership': '', 'rel': '', 'type': '', 'use': ''}
MetaBuilder = {'activationStatus': '', 'channelType': '', 'colloquialVersion': '', 'description': '', 'edition': '', 'entitlementDataRequired': '',
               'entitlementKey': '', 'generator': '', 'persistentId': '', 'productBaseName': '', 'productFamily': '', 'revision': '', 'summary': '',
               'unspscCode': '', 'unspscVersion': ''}
FileBuilder = {'name': '', 'size': '', 'version': '', 'hash': {}}
EvidenceBuilder = {'date': '', 'deviceId': '', }

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

class GenXml():
    def __init__(self, XmlPath, SWIDBuilder):
        self.XmlPath = XmlPath
        self.SWIDBuilder = SWIDBuilder

    def buildAttribute(self, attributeName, value, element):
        if (value != None):
            element.setAttribute(attributeName, value)

    def buildAbstractResourceCollectionBuilder(self, doc, element, data):
        FileElement = doc.createElement('File')
        for key in data.keys():
            if key != 'hash':
                if data[key] != None:
                    FileElement.setAttribute(key, str(data[key]))
            else:
                for hashTag in data[key].keys():
                    FileElement.setAttribute(hashTag, str(data[key][hashTag]))

        element.appendChild(FileElement)

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

    def genXml(self):
        self.validate()
        doc = Document()
        root = doc.createElement('SoftwareIdentity')
        root.setAttribute('xmlns', "http://standards.iso.org/iso/19770/-2/2015/schema.xsd")
        root.setAttribute('name', str(self.SWIDBuilder.name))
        root.setAttribute('tagId', str(self.SWIDBuilder.tagId))

        if self.SWIDBuilder.tagType not in TagTypeList:
            raise Exception("TagType: {} is illegal".format(self.SWIDBuilder.tagType ))
        elif self.SWIDBuilder.tagType == 'primary':
            pass
        else:
            root.setAttribute(self.SWIDBuilder.tagType, "true")

        root.setAttribute('tagVersion', str(self.SWIDBuilder.tagVersion))

        self.buildAttribute("version", self.SWIDBuilder.version, root);
        self.buildAttribute("versionScheme", self.SWIDBuilder.versionScheme, root);

        # child element
        # Required
        if self.SWIDBuilder.entities != []:
            for entity in self.SWIDBuilder.entities:
                EntityElement = doc.createElement('Entity')
                for att in entity.keys():
                    if entity[att] != None and entity[att] != []:
                        if att != 'roles':
                            EntityElement.setAttribute(att, str(entity[att]))
                        else:
                            EntityElement.setAttribute('role', ' '.join(entity[att]))

                root.appendChild(EntityElement)

        # Optional
        # need to fix
        if self.SWIDBuilder.evidence != []:
            EvidenceElement = doc.createElement('Evidencce')

        if self.SWIDBuilder.links != []:
            for link in self.SWIDBuilder.links:
                LinkElement = doc.createElement('Link')
                for att in link.keys():
                    if link[att] != None:
                        LinkElement.setAttribute(att, str(link[att]))

                root.appendChild(LinkElement)

        if self.SWIDBuilder.metas != []:
            for meta in self.SWIDBuilder.metas:
                MetaElement = doc.createElement('Meta')
                for att in meta.keys():
                    if meta[att] != None:
                        MetaElement.setAttribute(att, str(meta[att]))

                root.appendChild(MetaElement)

        if self.SWIDBuilder.payload != []:
            PayloadElement = doc.createElement('Payload')
            self.buildAbstractResourceCollectionBuilder(doc, PayloadElement, self.SWIDBuilder.payload[0])
            root.appendChild(PayloadElement)

        doc.appendChild(root)

        with open(self.XmlPath, 'w') as f:
            doc.writexml(f, indent='\t', addindent='\t', newl='\n', encoding="utf-8")

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
            Entity['name']  = GetValueFromSec(ini, section, 'name')
            Entity['regid'] = GetValueFromSec(ini, section, 'regid')
            Entity['role']  = GetValueFromSec(ini, section, 'role').split(' ')
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
            Meta['activationStatus'] = GetValueFromSec(ini, section, 'activationstatus')
            Meta['channelType'] = GetValueFromSec(ini, section, 'channeltype')
            Meta['colloquialVersion'] = GetValueFromSec(ini, section, 'colloquilversion')
            Meta['description'] = GetValueFromSec(ini, section, 'description')
            Meta['edition'] = GetValueFromSec(ini, section, 'edition')
            Meta['entitlementDataRequired'] = GetValueFromSec(ini, section, 'entitlementdatarequired')
            Meta['entitlementKey'] = GetValueFromSec(ini, section, 'entitlementkey')
            Meta['generator'] = GetValueFromSec(ini, section, 'generator')
            Meta['persistentId'] = GetValueFromSec(ini, section, 'persistentid')
            Meta['productBaseName'] = GetValueFromSec(ini, section, 'productbasename')
            Meta['productFamily'] = GetValueFromSec(ini, section, 'productfamily')
            Meta['revision'] = GetValueFromSec(ini, section, 'revision')
            Meta['summary'] = GetValueFromSec(ini, section, 'summary')
            Meta['unspscCode'] = GetValueFromSec(ini, section, 'unspsccode')
            Meta['unspscVersion'] = GetValueFromSec(ini, section, 'unspscversion')
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
        if HashAlgorithm == 'SHA-256':
            fb['hash']['SHA256:hash'] = hashlib.sha256(content).hexdigest()

    return fb

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('-i', '--inifile', dest='IniPath', type=str, help='Ini configuration file path', required=True)
    parser.add_argument('-p', '--payload', dest='Payload', type=str, help="Payload File name", required=True)
    parser.add_argument('-t', '--hash', dest='HashType', action='append', type=str, choices=HashAlgorithmMap.keys(), help="Hash types {}".format(str(HashAlgorithmMap.keys())), required=True)
    parser.add_argument('-o', '--outfile', dest='OutputFile', type=str, help='Cbor file path', default='', required=True)
    args = parser.parse_args()

    if not os.path.exists(args.IniPath):
        raise Exception("ERROR: Could not locate Ini file '%s' !" % args.IniPath)
    if not os.path.exists(args.Payload):
        raise Exception("ERROR: Could not locate payload file '%s' !" % args.Payload)
    if os.path.isabs(args.OutputFile):
        if not os.path.exists(os.path.dirname(args.OutputFile)):
            os.makedirs(os.path.dirname(args.OutputFile))

    xmlObj = GenXml(args.OutputFile, ParseAndBuildSwidData(args.IniPath, args.Payload, args.HashType))
    xmlObj.genXml()