# This FSP manifest tool is a sample implementation to generate SWID or CoSWID for FSP.

## Specification

   * RIM
     * NIST: SP800-155 [BIOS Integrity Measurement Guidelines](https://csrc.nist.gov/CSRC/media/Publications/sp/800-155/draft/documents/draft-SP800-155_Dec2011.pdf)
     * TCG: [TCG Reference Integrity Manifest (RIM) Information Model](https://trustedcomputinggroup.org/wp-content/uploads/TCG_RIM_Model_v1-r13_2feb20.pdf)
     * TCG: [TCG PC Client Reference Integrity Measurement](https://trustedcomputinggroup.org/wp-content/uploads/TCG_PC_Client_RIM_r0p15_15june2020.pdf)

   * SWID:
     * ISO/IEC 19770-2:2015 Part 2: Software Identification Tag
     * NIST: [Software-Identification-SWID](https://csrc.nist.gov/projects/Software-Identification-SWID)
     * NIST: NISTID.8060 [Guidelines for the Creation of Interoperable SWID Tags](https://csrc.nist.gov/publications/detail/nistir/8060/final)

   * CoSWID:
     * SACM: [Concise Software Identification Tags](https://datatracker.ietf.org/doc/draft-ietf-sacm-coswid/)
     * RATS: [Reference Integrity Measurement Extension for Concise Software Identities](https://datatracker.ietf.org/doc/draft-birkholz-rats-coswid-rim/)

   * Other related TCG specification
     * TCG: [TCG Platform Certificate Profile](https://trustedcomputinggroup.org/resource/tcg-platform-certificate-profile/)
     * TCG: [TCG PC Client Platform Firmware Integrity Measurement](https://trustedcomputinggroup.org/wp-content/uploads/TCG_PC_Client-FIM_v1r24_3feb20.pdf)
     * TCG: [TCG Platform Firmware Profile](https://trustedcomputinggroup.org/resource/pc-client-specific-platform-firmware-profile-specification/)
     * TCG: [TCG Server Management Domain Firmware Profile](https://trustedcomputinggroup.org/wp-content/uploads/TCG_ServerManagementDomainFirmwareProfile_v1p00_11aug2020.pdf)
     * TCG: [TCG EK Credential Profile](https://trustedcomputinggroup.org/resource/tcg-ek-credential-profile-for-tpm-family-2-0/)
     * TCG: [TCG PC Client Platform TPM Profile (PTP)](https://trustedcomputinggroup.org/resource/pc-client-platform-tpm-profile-ptp-specification/)
     * TCG: [TCG DICE certificate Profile](https://trustedcomputinggroup.org/wp-content/uploads/DICE-Certificate-Profiles-r01_3june2020-1.pdf)

## Feature

The FSP manifest support 2 mode.

1) binary mode - hash FSPT, FSPM, FSPS binary

2) separation mode - separation hash for FSP code and FSP UPD region for FSPT, FSPM, FSPS binary

The tools can generate SWID/CoSWID tag for FSP binary in binary mode or separation mode.

The tools can also verify the SWID/CoSWID tag based upon TCG event log or the FSP binary.

## RIM Generation

0) prerequisites

0.1) Install required python package:

   `pip install -r requirements.txt`

0.2) Prepare RIM configuration INI file.

   The sample RimConfig INI file is at [FspRimTemplate.ini](https://github.com/jyao1/FSP/blob/FspAttestation/Tools/ManifestTools/SampleConfig/FspRimTemplate.ini)

0.3) Prepare KEY files (private and public).

   The sample test KEY are at [SampleTestKey](https://github.com/jyao1/FSP/blob/FspAttestation/Tools/ManifestTools/SampleTestKey). Please do NOT use them in any production.

1) Generate RIM in binary mode

1.1) SWID tag

   To create the SWID tag:

   `FspGenSwid.py genswid -i <RimConfig INI file> -p <FSP BIN file> -t <HASH algorithm, such as SHA_256> -o <unsigned SWID XML file>`

   To sign the SWID tag:

   `FspGenSwid.py sign -i <unsigned SWID XML file> --privatekey <PEM private key file> --cert [PEM public certificate file ...] [--passwd <Password to decrypt the key>] -o <signed SWID XML file>`

   Sample signed SWID XML is at [FspSwidTemplate.xml](https://github.com/jyao1/FSP/blob/FspAttestation/Tools/ManifestTools/SampleManifests/FspSwidTemplate.xml)

1.2) CoSWID tag

   To create the CoSWID tag:

   `FspGenCoSwid.py gencoswid -i <RimConfig INI file> -p <FSP BIN file> -t <HASH algorithm, such as SHA_256> -o <unsigned CoSWID CBOR file>`

   To sign the CoSWID tag:

   `FspGenCoSwid.py sign -f <unsigned CoSWID CBOR file> --key <PEM private key file> --alg <signing algorithm, such as ES256> -o <signed CoSWID CBOR file>`

   Sample signed CoSWID CBOR is at [FspCoSwidTemplate.cbor](https://github.com/jyao1/FSP/blob/FspAttestation/Tools/ManifestTools/SampleManifests/FspCoSwidTemplate.cbor) and binary dump at [FspCoSwidTemplate.json](https://github.com/jyao1/FSP/blob/FspAttestation/Tools/ManifestTools/SampleManifests/FspCoSwidTemplate.json)

2) Generate RIM in separation mode

   Add `-m separation` when create the SWID or CoSWID tag.

2.1) SWID tag

   Sample signed SWID XML is at [FspSwidTemplate2.xml](https://github.com/jyao1/FSP/blob/FspAttestation/Tools/ManifestTools/SampleManifests/FspSwidTemplate2.xml)

2.2) CoSWID tag

   Sample signed CoSWID CBOR is at [FspCoSwidTemplate2.cbor](https://github.com/jyao1/FSP/blob/FspAttestation/Tools/ManifestTools/SampleManifests/FspCoSwidTemplate2.cbor) and binary dump at [FspCoSwidTemplate2.json](https://github.com/jyao1/FSP/blob/FspAttestation/Tools/ManifestTools/SampleManifests/FspCoSwidTemplate2.json)

3) Verification

3.1) Verify: FSP binary in flash == FSP RIM == TCG event log

3.1.1) Without TCG event log:
   Verify the FSP binary hash (verify FSP binary with hash in RIM)

   For SWID：
   
   `FspGenSwid.py verify-hash -f <SWID XML file> -t <HASH algorithm, such as SHA_256> --fd <flash image binary file>`
   
   For CoSWID:
   
   `FspGenCoSwid.py verify-hash -f <CoSWID CBOR file> --fd <flash image binary file>`

3.1.2) With TCG event log:
   Verify the TCG event log with RIM. (verify hash in TCG event log with hash in RIM)

   For SWID：
   
   `FspGenSwid.py verify-hash -f <SWID XML file> -t <HASH algorithm, such as SHA_256> --evt <EventLog binary file>`
   
   For CoSWID:
   
   `FspGenCoSwid.py verify-hash -f <CoSWID CBOR file> --evt <EventLog binary file>`

3.1.2.1) Double confirm TCG event log:
   Verify the FSP binary with TCG event log. (verify FSP binary with hash in TCG event log)

   `FspTools.py compare --evt <EventLog binary file> --fd <flash image binary file>`

   The EventLog binary can be got from [Tcg2DumpLog](https://github.com/jyao1/EdkiiShellTool/tree/master/EdkiiShellToolPkg/Tcg2DumpLog)

   `Tcg2DumpLog.efi -BIN <EventLog binary file>` in UEFI shell environment.

3.2) Verify: integrity of RIM

3.2.1) verify the certChain by using RootCert (verify RIM with RootCert)

3.2.1.1) SWID tag

   To verify the signature:
  
   `FspGenSwid.py verify -i <signed SWID XML file> --cert <Issued PEM public certificate file> --issued`

3.2.1.2) CoSWID tag:
    
   To verify the signature:
   
   TBD

3.2.2) Verify the signature of data by using LeafCert (verify RIM with RootCert)

3.2.2.1) SWID tag

   To verify the signature:

   `FspGenSwid.py verify -i <signed SWID XML file> --cert <PEM public certificate file>`

3.2.2.2) CoSWID tag

   To verify the signature:

   `FspGenCoSwid.py verify -f <signed CoSWID CBOR file> --key <PEM public key file> --alg <signing algorithm, such as ES256>`

   To dump the CBOR:

   `FspGenCoSwid.py dump -f <signed CoSWID CBOR file>`

## Feature not implemented yet

1) thumbprint

2) Support certificate chain

3) CoSWID keyid

## Known limitation
This package is only the sample code to show the concept.
It does not have a full validation such as robustness functional test. It does not meet the production quality yet.
Any codes including the API definition, the libary and the drivers are subject to change.

