## @ FspGenSwid.py
#
# Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
# SPDX-License-Identifier: BSD-2-Clause-Patent
#
##

import os
import copy
import hashlib
from xml.dom.minidom import Document

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

class GenXml():
    def __init__(self, XmlPath, SWIDBuilder):
        self.XmlPath = XmlPath
        self.SWIDBuilder = SWIDBuilder

    def buildAttribute(self, attributeName, value, element):
        if (value != ''):
            element.setAttribute(attributeName, value)

    def buildAbstractResourceCollectionBuilder(self, doc, element, data):
        FileElement = doc.createElement('File')
        for key in data.keys():
            if key != 'hash':
                if data[key] != '':
                    FileElement.setAttribute(key, str(data[key]))
            else:
                for hashTag in data[key].keys():
                    FileElement.setAttribute(hashTag, str(data[key][hashTag]))

        element.appendChild(FileElement)

    def validateNonEmpty(self, tagName, value):
        if value == '' or value == []:
            raise Exception("{} should not be empty.".format(tagName))

    def validateEntity(self, entity):
        self.validateNonEmpty('name', entity['name'])
        self.validateNonEmpty('role', entity['role'])

    def validateEvidence(self, evidence):
        self.validateNonEmpty('date', evidence['date'])
        self.validateNonEmpty('deviceId', evidence['deviceId'])

    def validateLink(self, link):
        self.validateNonEmpty('href', link['href'])
        self.validateNonEmpty('rel', link['rel'])

    # def validateMeta(self, meta):
    #     self.validateNonEmpty('href', meta['href'])
    #     self.validateNonEmpty('rel', meta['rel'])

    def validate(self):
        self.validateNonEmpty('name', self.SWIDBuilder.name)
        self.validateNonEmpty('tagId', self.SWIDBuilder.tagId)
        self.validateNonEmpty('entity', self.SWIDBuilder.entities)

        for entity in self.SWIDBuilder.entities:
            self.validateEntity(entity)
            if 'tagCreator' in entity['role']:
                foundTagCreator = True

        if not foundTagCreator:
            raise Exception('at least one entity with role, tagCreator must be provided.')

        if self.SWIDBuilder.payload != [] and self.SWIDBuilder.evidence != []:
            raise Exception('Only one of evidence or payload must be provided.')

        if self.SWIDBuilder.payload != []:
            pass
        if self.SWIDBuilder.evidence != []:
            self.validateEvidence(self.SWIDBuilder.evidence[0])

        for link in self.SWIDBuilder.links:
            self.validateLink(link)
        #
        # for meta in self.SWIDBuilder.metas:
        #     self.validateMeta(meta)



    def genXml(self):
        # self.validate()
        doc = Document()
        root = doc.createElement('SoftwareIdentity')
        root.setAttribute('xmlns', "http://standards.iso.org/iso/19770/-2/2015/schema.xsd")
        root.setAttribute('name', str(self.SWIDBuilder.name))
        root.setAttribute('tagId', str(self.SWIDBuilder.tagId))

        if self.SWIDBuilder.tagType not in TagTypeDict.keys():
            raise Exception("TagType: {} is illegal".format(self.SWIDBuilder.tagType ))
        elif self.SWIDBuilder.tagType == 0:
            pass
        else:
            root.setAttribute(TagTypeDict[self.SWIDBuilder.tagType], "true")

        root.setAttribute('tagVersion', str(self.SWIDBuilder.tagVersion))

        self.buildAttribute("version", self.SWIDBuilder.version, root);
        self.buildAttribute("versionScheme", self.SWIDBuilder.versionScheme, root);

        # child element
        # Required
        if self.SWIDBuilder.entities != []:
            for entity in self.SWIDBuilder.entities:
                EntityElement = doc.createElement('Entity')
                for att in entity.keys():
                    if entity[att] != '' and entity[att] != []:
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
                    if link[att] != '':
                        LinkElement.setAttribute(att, str(link[att]))

                root.appendChild(LinkElement)

        if self.SWIDBuilder.metas != []:
            for meta in self.SWIDBuilder.metas:
                MetaElement = doc.createElement('Meta')
                for att in meta.keys():
                    if meta[att] != '':
                        MetaElement.setAttribute(att, str(meta[att]))

                root.appendChild(MetaElement)

        if self.SWIDBuilder.payload != []:
            PayloadElement = doc.createElement('Payload')
            self.buildAbstractResourceCollectionBuilder(doc, PayloadElement, self.SWIDBuilder.payload[0])
            root.appendChild(PayloadElement)

        doc.appendChild(root)

        with open(self.XmlPath, 'w') as f:
            doc.writexml(f, indent='\t', addindent='\t', newl='\n', encoding="utf-8")


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
            fb['hash']['SHA256:hash'] = hashlib.sha256(content).hexdigest()

    return fb

if __name__ == "__main__":
    ss = genFileBuilder('Fsp.fd', ['SHA256'])
    xx = SWIDBuilder()
    xx.tagId = 1
    xx.name = 'hello'
    Entity1 = copy.deepcopy(EntityBuilder)
    Entity1['name'] = 'world'
    Entity1['regid'] = 250
    Entity1['roles'] = ['ddwfwfe', 'xxxxxx']
    Entity1['thumbprint'] = 'dddddd'

    Entity2 = copy.deepcopy(EntityBuilder)
    Entity2['name'] = 'wxxx'
    Entity2['regid'] = 250444
    Entity2['roles'] = []
    Entity2['thumbprint'] = 'dddddd'

    xx.addEntity(Entity1)
    xx.addEntity(Entity2)

    xx.addPayload(ss)


    ss = GenXml("FspManifest.xml", xx)
    ss.genXml()