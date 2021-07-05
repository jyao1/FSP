# This SPDM tool is a sample implementation to generate and verify SPDM event log.

## Feature

parse-eventlog.sh is used to generate event log file by tpm2 tools.

fsp-attestation.sh is used to verify hash in event binary file and BIOS image file.

ShellDmpLogs.efi is used to generate SPDM event log file in UEFI shell.

Tcg2DumpLog.efi is used to generate SPDM event binary file in UEFI shell.

## Dependence

All tools were tested at Ubuntu 21.04.

0) Prerequisites

​	0.1) Follow the ../../ManifestTools/readme.md to install FSP manifest tool.

​	0.2) Install required Tpm2 tools(version 5.1.1 at least):

  	 `sudo apt-get update -y`

  	 `sudo apt-get install -y tpm2-tools`

​	0.3) Copy the BIOS measurements binary file to this location:

​	`	cp  /sys/kernel/security/tpm0/binary_bios_measurements <binary_file_name>`

​	`sudo chmod 777 <binary_file_name>`

​	0.4) If you cannot find BIOS measurements binary file in kernel, also can use Tcg2DumpLog.efi tool to generate:

​		0.4.1) Copy  `Tcg2DumpLog.efi`  to U-Disk.

​		0.4.2) Entry UEFI shell and:

​		`Tcg2Dumplog.efi -BIN <binary_file_name>`

​		0.4.3) Copy the BIOS measurements binary file to this location from U-DISK.

​	0.5) Copy the BIOS image binary file to this location:

​	`<image_file_name>`

## SPDM Log Verification

0) View event log:

`./parse-eventlog.sh <binary_file_name>`

Also can use ShellDmpLogs.efi generate event log file in UEFI shell:

Copy  `ShellDmpLogs.efi`  to U-Disk.

Entry UEFI shell and:

​	`ShellDmpLogs.efi > <log_file_name>`

​	`	edit <log_file_name>`

1)Verify event binary:

`./fsp-attestation.sh <image_file_name> <binary_file_name>`

## Known limitation
This package is only the sample code to show the concept.
It does not have a full validation such as robustness functional test. It does not meet the production quality yet.
Any codes including the API definition, the libary and the drivers are subject to change.

