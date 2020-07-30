# This FSP manifest tool is a sample implementation to generate SWID or CoSWID for FSP.

## Specification

   * RIM
     * TCG: [TCG RIM Model](https://trustedcomputinggroup.org/wp-content/uploads/TCG_RIM_Model_v1-r13_2feb20.pdf)
     * TCG: [TCG PcClient RIM](https://trustedcomputinggroup.org/wp-content/uploads/TCG_PC_Client_RIM_r0p15_15june2020.pdf)

   * SWID:
     * ISO/IEC 19770-2:2015 Part 2: Software Identification Tag
     * NIST: [Software-Identification-SWID](https://csrc.nist.gov/projects/Software-Identification-SWID)
     * NIST: NISTID.8060 [Guidelines for the Creation of Interoperable SWID Tags](https://csrc.nist.gov/publications/detail/nistir/8060/final)

   * CoSWID:
     * SACM: [Concise Software Identification Tags](https://datatracker.ietf.org/doc/draft-ietf-sacm-coswid/)
     * RATS: [Reference Integrity Measurement Extension for Concise Software Identities](https://datatracker.ietf.org/doc/draft-birkholz-rats-coswid-rim/)

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

   The template is at [FspRimTemplate.ini](https://github.com/jyao1/FSP/blob/FspAttestation/Tools/FspRimTemplate.ini)

1) Generate RIM in binary mode

1.1) SWID tag

   To create the SWID tag:

   `FspGenSwid.py genswid -i FspRimTemplate.ini -p Fsp.fd -t SHA_256 -o FspRim.xml`

   To sign the SWID tag with sample test key:

   `FspGenSwid.py sign -i FspRim.xml --privatekey TestKey\example.key.pem --cert TestKey\example.cer.pem -o FspRim.sign.xml`

   Sample output is at [FspSwidTemplate.xml](https://github.com/jyao1/FSP/blob/FspAttestation/Tools/FspSwidTemplate.xml)

1.2) CoSWID tag

   To create the CoSWID tag:

   `FspGenCoSwid.py gencoswid -i FspRimTemplate.ini -p Fsp.fd -t SHA_256 -o FspRim.cbor`

   To sign the CoSWID tag with sample test key:

   `FspGenCoSwid.py sign -f FspRim.cbor --key TestKey\ecc-private-key.pem --alg ES256 -o FspRim.sign.cbor`

   Sample output is at [FspCoSwidTemplate.json](https://github.com/jyao1/FSP/blob/FspAttestation/Tools/FspCoSwidTemplate.json)

2) Generate RIM in separation mode

   Add `-m separation` when create the SWID or CoSWID tag.

2.1) SWID tag

   Sample output is at [FspSwidTemplate2.xml](https://github.com/jyao1/FSP/blob/FspAttestation/Tools/FspSwidTemplate2.xml)

2.2) CoSWID tag

   Sample output is at [FspCoSwidTemplate2.json](https://github.com/jyao1/FSP/blob/FspAttestation/Tools/FspCoSwidTemplate2.json)

3) Verification

3.1) Verify: FSP binary in flash == FSP RIM == TCG event log

3.1.1) Without TCG event log:
     Verify the FSP binary hash (verify FSP binary with hash in RIM)

     TBD

3.1.2) With TCG event log:
     Verify the TCG event log with RIM. (verify hash in TCG event log with hash in RIM)

     TBD

3.1.2.1) Double confirm TCG event log:
   Verify the FSP binary with TCG event log. (verify FSP binary with hash in TCG event log)

   `FspTools.py compare --evt evt.bin --fd KABYLAKERVP3.fd`

   The EventLog binary can be got from [Tcg2DumpLog](https://github.com/jyao1/EdkiiShellTool/tree/master/EdkiiShellToolPkg/Tcg2DumpLog)

   `Tcg2DumpLog.efi -BIN evt.bin` in UEFI shell environment.

3.2) Verify: integrity of RIM

3.2.1) verify the certChain by using RootCert (verify RIM with RootCert)

   TBD

3.2.2) Verify the signature of data by using LeafCert (verify RIM with RootCert)

3.2.2.1) SWID tag

   To verify the signature:

   `FspGenSwid.py verify -i FspRim.sign.xml --cert TestKey\example.cer.pem`

3.2.2.2) CoSWID tag

   To verify the signature:

   `FspGenCoSwid.py verify -f FspRim.sign.cbor --key TestKey\ecc-public-key.pem --alg ES256`

   To dump the CBOR:

   `FspGenCoSwid.py dump -f FspRim.sign.cbor`

## Feature not implemented yet

1) Support certificate chain

2) CoSWID keyid

## Known limitation
This package is only the sample code to show the concept.
It does not have a full validation such as robustness functional test. It does not meet the production quality yet.
Any codes including the API definition, the libary and the drivers are subject to change.

