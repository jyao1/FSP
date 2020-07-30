# This FSP manifest tool is a sample implementation to generate SWID or CoSWID for FSP.

## Specification

   * RIM
     * TCG: [TCG RIM Model](https://trustedcomputinggroup.org/wp-content/uploads/TCG_RIM_Model_v1-r13_2feb20.pdf)
     * TCG: [TCG PcClient RIM](https://trustedcomputinggroup.org/wp-content/uploads/TCG_PC_Client_RIM_r0p15_15june2020.pdf)

   * SWID:
     * ISO/IEC 19770-2:2015 Part 2: Software Identification Tag
     * NIST: Guidelines for the Creation of Interoperable SWID Tags [NISTIR.8060](https://csrc.nist.gov/publications/detail/nistir/8060/final)

   * CoSWID:
     * SACM: [Concise Software Identification Tags](https://datatracker.ietf.org/doc/draft-ietf-sacm-coswid/)
     * RATS: [Reference Integrity Measurement Extension for Concise Software Identities](https://datatracker.ietf.org/doc/draft-birkholz-rats-coswid-rim/)

## Feature

The FSP manifest support 2 mode.

1) binary mode - hash FSPT, FSPM, FSPS binary

2) separation mode - separation hash for FSP code and FSP UPD region for FSPT, FSPM, FSPS binary

## RIM Generation

0) prerequisites

1) Generate RIM in binary mode

1.1) SWID tag

   To create the SWID tag:
   `FspGenSwid.py genswid -i FspRimTemplate.ini -p Fsp.fd -t SHA_256 -o FspRim.xml`

   To sign the SWID tag with sample test key:
   `FspGenSwid.py sign -i FspRim.xml --privatekey TestKey\example.key.pem --cert TestKey\example.cer.pem -o FspRim.sign.xml`

   To verify the signature:
   `FspGenSwid.py verify -i test.sign.xml --cert TestKey\example.cer.pem`

1.2) CoSWID tag

   To create the CoSWID tag:
   `FspGenCoSwid.py gencoswid -i FspRimTemplate.ini -p Fsp.fd -t SHA_256 -o FspRim.cbor`

   To sign the CoSWID tag with sample test key:
   `FspGenCoSwid.py sign -f FspRim.cbor --key TestKey\ecc-private-key.pem --alg ES256 -o FspRim.sign.cbor`

   To verify the signature:
   `FspGenCoSwid.py verify -f FspRim.sign.cbor --key TestKey\ecc-public-key.pem --alg ES256`

   To dump the CBOR:
   `FspGenCoSwid.py dump -f FspRim.sign.cbor`

2) Generate RIM in separation mode

   (TBD)

3) Verification

   (TBD)

3.1) Verify: FSP binary in flash == FSP RIM == TCG event log
3.1.1) Without TCG event log:
     Verify the FSP binary hash (verify FSP binary with hash in RIM) -- FspGenCoSwid/FspGenSwid
3.1.2) With TCG event log:
     Verify the TCG event log with RIM. (verify hash in TCG event log with hash in RIM) -- FspTools
     Double confirm TCG event log:
     3.1.2.1) Verify the FSP binary with TCG event log. (verify FSP binary with hash in TCG event log) -- FspTools

3.2) Verify: integrity of RIM
3.2.1) verify the certChain by using RootCert (verify RIM with RootCert) -- FspGenCoSwid/FspGenSwid
3.2.2) Verify the signature of data by using LeafCert (verify RIM with RootCert) -- FspGenCoSwid/FspGenSwid

## Feature not implemented yet

1) Support certificate chain (TBD)

## Known limitation
This package is only the sample code to show the concept.
It does not have a full validation such as robustness functional test and fuzzing test. It does not meet the production quality yet.
Any codes including the API definition, the libary and the drivers are subject to change.

