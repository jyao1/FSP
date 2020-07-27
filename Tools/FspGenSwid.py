## @ FspGenSwid.py
#
# This tool generates signed XML format SWID tag.
#
# Reference:
#   SWID:
#   Software-Identification-SWID, https://csrc.nist.gov/projects/Software-Identification-SWID
#
#   XML
#   https://www.w3.org/XML/
#   http://www.w3.org/2000/09/xmldsig#enveloped-signature
#   http://www.w3.org/2001/04/xmlenc#sha256
#   https://www.w3.org/TR/xmldsig-core1/
#
# Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
# SPDX-License-Identifier: BSD-2-Clause-Patent
#
##

import os
import copy
import argparse
import subprocess
import configparser
from lxml import etree
from signxml import XMLSigner, XMLVerifier, methods
from xml.dom.minidom import Document

RoleList      = ['aggregator', 'distributor', 'licensor', 'softwareCreator', 'tagCreator']

HashAlgorithmMap = {"SHA_256": "http://www.w3.org/2001/04/xmlenc#sha256",
                    "SHA_256_128": "http://www.w3.org/2001/04/xmlenc#sha256",
                    "SHA_256_120": "http://www.w3.org/2001/04/xmlenc#sha256",
                    "SHA_256_96": "http://www.w3.org/2001/04/xmlenc#sha256",
                    "SHA_256_64": "http://www.w3.org/2001/04/xmlenc#sha256",
                    "SHA_256_32": "http://www.w3.org/2001/04/xmlenc#sha256",
                    "SHA_384": "http://www.w3.org/2001/04/xmldsig-more#sha384",
                    "SHA_512": "http://www.w3.org/2001/04/xmlenc#sha512",
                    "SHA_3_224": "http://www.w3.org/2007/05/xmldsig-more#sha3-224",
                    "SHA_3_256": "http://www.w3.org/2007/05/xmldsig-more#sha3-256",
                    "SHA_3_384": "http://www.w3.org/2007/05/xmldsig-more#sha3-384",
                    "SHA_3_512": "http://www.w3.org/2007/05/xmldsig-more#sha3-512"}

EntityBuilder = {'name': '', 'role': '', 'regid': '', 'thumbprint': ''}
LinkBuilder = {'artifact': '', 'href': '', 'media': '', 'ownership': '', 'rel': '', 'type': '', 'use': ''}

MetaBuilder = {'colloquialVersion': '', 'edition': '', 'product': '', 'revision': '', 'PayloadType': '', 'PlatformManufacturerStr': '',
               'PlatformManufacturerId': '', 'PlatformModel': '', 'PlatformVersion': '', 'FirmwareManufacturerStr': '', 'FirmwareManufacturerId': '',
               'FirmwareMode': '', 'FirmwareVersion': '', 'BindingSpec': '', 'BindingSpecVersion': '', 'pcURIlocal': '', 'pcURIGlobal': '', 'RIMLinkHash': ''}

DirectoryBuilder = {'name': '', 'location': '', 'file': []}
FileBuilder = {'name': '', 'size': '', 'version': ''}

SupportHashAlgorithmList = ["SHA_256", "SHA_384", "SHA_512", "SHA_3_256", "SHA_3_384", "SHA_3_512"]

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
        self.entities = []
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
        self.NameSpace = 'http://standards.iso.org/iso/19770/-2/2015/schema.xsd'
        self.NameSpace8060 = 'http://csrc.nist.gov/ns/swid/2015-extensions/1.0'
        self.MetaAttNonEmptyList = ['colloquialVersion', 'edition', 'product', 'revision', 'PlatformManufacturerStr',
                                    'PlatformManufacturerId', 'PlatformModel', 'BindingSpec', 'BindingSpecVersion', 'RIMLinkHash']
        self.MetaAttOfRimList = ['PayloadType', 'PlatformManufacturerStr', 'PlatformManufacturerId', 'PlatformModel',
                                 'PlatformVersion', 'FirmwareManufacturerStr', 'FirmwareManufacturerId', 'FirmwareMode',
                                 'FirmwareVersion', 'BindingSpec', 'BindingSpecVersion', 'pcURIlocal', 'pcURIGlobal', 'RIMLinkHash']

    def buildAttribute(self, attributeName, value, element):
        if (value != None):
            element.setAttribute(attributeName, value)

    def buildAbstractResourceCollectionBuilder(self, doc, element, data):
        DirectoryElement = doc.createElement('Directory')
        DirectoryElement.setAttribute('name', data['name'])
        DirectoryElement.setAttribute('location', data['location'])

        for file in data['file']:
            FileElement = doc.createElement('File')
            for key in file.keys():
                if not key.startswith('SHA'):
                    if file[key] != None and file[key] != '':
                        FileElement.setAttribute(key, str(file[key]))
                else:
                    hashQualifiedName = 'SHA' + key.split("_")[-1] + ':hash'
                    element.setAttributeNS(self.NameSpace, 'xmlns:' + 'SHA' + key.split("_")[-1], HashAlgorithmMap[key])
                    FileElement.setAttributeNS(HashAlgorithmMap[key], hashQualifiedName, str(file[key]))
            DirectoryElement.appendChild(FileElement)

        element.appendChild(DirectoryElement)

    def validateNonEmpty(self, tagName, value):
        if value == None or value == [] or value == '':
            raise Exception('The field "{}" must contain a non-empty value'.format(tagName))

    def validateEntity(self, entity):
        self.validateNonEmpty('name', entity['name'])
        self.validateNonEmpty('role', entity['role'])
        self.validateNonEmpty('thumbprint', entity['thumbprint'])

    def validateLink(self, link):
        self.validateNonEmpty('href', link['href'])
        self.validateNonEmpty('rel', link['rel'])

    def validateMeta(self, meta):
        for AttributeName in self.MetaAttNonEmptyList:
            self.validateNonEmpty(AttributeName, meta[AttributeName])

    def validate(self):
        self.validateNonEmpty('name', self.SWIDBuilder.name)
        self.validateNonEmpty('version', self.SWIDBuilder.tagId)
        self.validateNonEmpty('tagId', self.SWIDBuilder.tagId)
        self.validateNonEmpty('tagVersion', self.SWIDBuilder.tagVersion)
        self.validateNonEmpty('entity', self.SWIDBuilder.entities)
        self.validateNonEmpty('meta', self.SWIDBuilder.metas)

        foundTagCreator = False
        for entity in self.SWIDBuilder.entities:
            self.validateEntity(entity)
            for role in entity['role'].split(' '):
                if role not in RoleList:
                    raise Exception('Role "{}" should be one in [{}].'.format(role, ' '.join(RoleList)))
            if 'tagCreator' in entity['role']:
                foundTagCreator = True

        if not foundTagCreator:
            raise Exception('at least one entity with role, tagCreator must be provided.')

        for link in self.SWIDBuilder.links:
            self.validateLink(link)

        for meta in self.SWIDBuilder.metas:
            self.validateMeta(meta)

    def genXml(self):
        self.validate()
        doc = Document()
        root = doc.createElement('SoftwareIdentity')

        # Required
        root.setAttribute('xmlns', self.NameSpace)
        root.setAttributeNS(self.NameSpace, 'xmlns:n8060', self.NameSpace8060)
        root.setAttribute('name', self.SWIDBuilder.name)
        root.setAttribute('version', self.SWIDBuilder.version)
        root.setAttribute('tagId', self.SWIDBuilder.tagId)
        root.setAttribute('tagVersion', self.SWIDBuilder.tagVersion)

        # Optional
        self.buildAttribute('corpus', self.SWIDBuilder.corpus, root)
        self.buildAttribute('patch', self.SWIDBuilder.patch, root)
        self.buildAttribute('supplemental', self.SWIDBuilder.supplemental, root)
        self.buildAttribute('versionScheme', self.SWIDBuilder.versionScheme, root)

        # child element
        # Required
        if self.SWIDBuilder.entities != []:
            for entity in self.SWIDBuilder.entities:
                EntityElement = doc.createElement('Entity')
                for att in entity.keys():
                    if entity[att] != None:
                        EntityElement.setAttribute(att, entity[att])

                root.appendChild(EntityElement)

        if self.SWIDBuilder.links != []:
            for link in self.SWIDBuilder.links:
                LinkElement = doc.createElement('Link')
                for att in link.keys():
                    if link[att] != None:
                        LinkElement.setAttribute(att, link[att])

                root.appendChild(LinkElement)

        if self.SWIDBuilder.metas != []:
            for meta in self.SWIDBuilder.metas:
                MetaElement = doc.createElement('Meta')
                MetaElement.setAttributeNS(self.NameSpace, 'xmlns:rim', 'https://trustedcomputinggroup.org/wp-content/uploads/TCG_RIM_Model')
                for att in meta.keys():
                    if meta[att] != None and att not in self.MetaAttOfRimList:
                        MetaElement.setAttribute(att, meta[att])
                    elif meta[att] != None and att in self.MetaAttOfRimList:
                        MetaElement.setAttribute('rim:' + att, meta[att])

                root.appendChild(MetaElement)

        if self.SWIDBuilder.payload != []:
            PayloadElement = doc.createElement('Payload')
            PayloadElement.setAttributeNS(self.NameSpace8060, 'n8060:envVarPrefix', '$')
            PayloadElement.setAttributeNS(self.NameSpace8060, 'n8060:envVarSuffix', '')
            PayloadElement.setAttributeNS(self.NameSpace8060, 'n8060:pathSeparator', '/')
            self.buildAbstractResourceCollectionBuilder(doc, PayloadElement, self.SWIDBuilder.payload[0])
            root.appendChild(PayloadElement)

        doc.appendChild(root)

        with open(self.XmlPath, 'w') as f:
            doc.writexml(f, indent='', addindent='\t', newl='\n', encoding="utf-8")

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
            swid_builder.corpus        = GetValueFromSec(ini, section, 'corpus').lower()
            swid_builder.patch         = GetValueFromSec(ini, section, 'patch').lower()
            swid_builder.supplemental  = GetValueFromSec(ini, section, 'supplemental').lower()
            swid_builder.tagVersion    = GetValueFromSec(ini, section, 'tagversion')
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
            for Attribute in MetaBuilder.keys():
                Meta[Attribute] = GetValueFromSec(ini, section, Attribute)
            swid_builder.addMeta(Meta)

    payload = genPayloadBuilder(PayloadFile, HashTypes)
    swid_builder.addPayload(payload)

    return swid_builder

def genPayloadBuilder(FileName, HashAlgorithm):
    ToolPath = os.path.join(os.path.dirname(__file__), 'FspTools.py')
    CmdList = ['python', ToolPath, 'hash', '-f', FileName]

    try:
        parseFspImage = subprocess.Popen(CmdList, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=False)
        msg = parseFspImage.communicate()
    except Exception:
        print(msg[1])

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

def SignXmlFile(XmlPath, KeyPath, CertPath, SignedXmlPath):
    with open(XmlPath, 'rb') as f:
        data_to_sign = f.read()

    key, cert = [open(path).read() for path in [KeyPath, CertPath]]

    root = etree.fromstring(data_to_sign)
    signed_root = XMLSigner(method=methods.enveloping).sign(root, key=key, cert=cert)

    etree.ElementTree(signed_root).write(SignedXmlPath)

def VerifySignXmlFile(SignedXmlPath, CertPath):
    with open(CertPath, 'r') as f:
        cert = f.read()

    with open(SignedXmlPath, 'rb') as f:
        SignedXmlData = etree.fromstring(f.read())

    # Verify signature
    XMLVerifier().verify(SignedXmlData, x509_cert=cert).signed_xml

    print("Signature verification passed")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(title='commands', dest="which")

    parser_genswid = subparsers.add_parser('genswid', help='Generate Swid format file')
    parser_genswid.add_argument('-i', '--inifile', dest='IniPath', type=str, help='Ini configuration file path', required=True)
    parser_genswid.add_argument('-p', '--payload', dest='Payload', type=str, help="Payload File name", required=True)
    parser_genswid.add_argument('-t', '--hash', dest='HashType', type=str, choices=SupportHashAlgorithmList, help="Hash types {}".format(str(HashAlgorithmMap.keys())), default='SHA_256')
    parser_genswid.add_argument('-o', '--outfile', dest='OutputFile', type=str, help='Output Swid file path', default='', required=True)

    parser_sign = subparsers.add_parser('sign', help='Signed xml file')
    parser_sign.add_argument('-i', '--input', dest='XmlPath', type=str, help='Xml file path', required=True)
    parser_sign.add_argument('--privatekey', dest='PrivateKey', type=str, help='Private key for signing (PEM format)', required=True)
    parser_sign.add_argument('--cert', dest='Cert', type=str, help='Cert file path (PEM format)', required=True)
    parser_sign.add_argument('-o', '--output', dest='SignedXmlPath', type=str, help='SignedXml file path', required=True)

    parser_verify = subparsers.add_parser('verify', help='Signed xml file')
    parser_verify.add_argument('-i', '--input', dest='SignedXmlPath', type=str, help='Signed Xml file path', required=True)
    parser_verify.add_argument('--cert', dest='Cert', type=str, help='Cert file path (PEM format)', required=True)
    args = parser.parse_args()

    if args.which == "genswid":
        if not os.path.exists(args.IniPath):
            raise Exception("ERROR: Could not locate Ini file '%s' !" % args.IniPath)
        if not os.path.exists(args.Payload):
            raise Exception("ERROR: Could not locate payload file '%s' !" % args.Payload)
        if os.path.isabs(args.OutputFile):
            if not os.path.exists(os.path.dirname(args.OutputFile)):
                os.makedirs(os.path.dirname(args.OutputFile))

        xmlObj = GenXml(args.OutputFile, ParseAndBuildSwidData(args.IniPath, args.Payload, args.HashType))
        xmlObj.genXml()
    elif args.which == "sign":
        if not os.path.exists(args.XmlPath):
            raise Exception("ERROR: Could not locate Xml file '%s' !" % args.XmlPath)
        if not os.path.exists(args.PrivateKey):
            raise Exception("ERROR: Could not locate private key file '%s' !" % args.PrivateKey)
        if not os.path.exists(args.Cert):
            raise Exception("ERROR: Could not locate cert file '%s' !" % args.Cert)
        if os.path.isabs(args.SignedXmlPath):
            if not os.path.exists(os.path.dirname(args.SignedXmlPath)):
                os.makedirs(os.path.dirname(args.SignedXmlPath))

        SignXmlFile(args.XmlPath, args.PrivateKey, args.Cert, args.SignedXmlPath)
    elif args.which == "verify":
        if not os.path.exists(args.SignedXmlPath):
            raise Exception("ERROR: Could not locate signed Xml file '%s' !" % args.SignedXmlPath)
        if not os.path.exists(args.Cert):
            raise Exception("ERROR: Could not locate cert file '%s' !" % args.Cert)

        VerifySignXmlFile(args.SignedXmlPath, args.Cert)