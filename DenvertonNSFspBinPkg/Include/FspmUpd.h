/** @file

Copyright (c) 2018, Intel Corporation. All rights reserved.<BR>

Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met:

* Redistributions of source code must retain the above copyright notice, this
  list of conditions and the following disclaimer.
* Redistributions in binary form must reproduce the above copyright notice, this
  list of conditions and the following disclaimer in the documentation and/or
  other materials provided with the distribution.
* Neither the name of Intel Corporation nor the names of its contributors may
  be used to endorse or promote products derived from this software without
  specific prior written permission.

  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
  ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
  LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
  CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
  ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
  THE POSSIBILITY OF SUCH DAMAGE.

  This file is automatically generated. Please do NOT modify !!!

**/

#ifndef __FSPMUPD_H__
#define __FSPMUPD_H__

#include <FspUpd.h>

#pragma pack(1)

#define MAX_CH 2            /* Maximum Number of Memory Channels */
#define MAX_DIMM 2          /* Maximum Number of DIMMs PER Memory Channel */
#define MAX_SPD_BYTES 512   /* Maximum Number of SPD bytes */

/*
 * Memory Down structures.
 */
typedef enum {
  STATE_MEMORY_SLOT = 0,    /* No memory down and a physical memory slot. */
  STATE_MEMORY_DOWN = 1,    /* Memory down and not a physical memory slot. */
} MemorySlotState;

typedef struct {
  MemorySlotState  SlotState[MAX_CH][MAX_DIMM];   /* Memory Down state of each DIMM in each Channel */
  UINT16           SpdDataLen;                    /* Length in Bytes of a single DIMM's SPD Data */
  UINT8            *SpdDataPtr[MAX_CH][MAX_DIMM]; /* Pointer to SPD Data for each DIMM in each Channel */
} MEMORY_DOWN_CONFIG;

/*
* SMBIOS Memory Info structures.
*/
typedef struct {
  UINT8         DimmId;
  UINT32        SizeInMb;
  UINT16        MfgId;
  UINT8         ModulePartNum[20];/* Module part number for DDR3 is 18 bytes however for DRR4 20 bytes as per JEDEC Spec, so reserving 20 bytes */
} DIMM_INFO;

typedef struct {
  UINT8         ChannelId;
  UINT8         DimmCount;
  DIMM_INFO     DimmInfo[MAX_DIMM];
} CHANNEL_INFO;

typedef struct {
  UINT8         Revision;
  UINT16        DataWidth;
  /** As defined in SMBIOS 3.0 spec
  Section 7.18.2 and Table 75
  **/
  UINT8         MemoryType;
  UINT16        MemoryFrequencyInMHz;
  /** As defined in SMBIOS 3.0 spec
  Section 7.17.3 and Table 72
  **/
  UINT8         ErrorCorrectionType;
  UINT8         ChannelCount;
  CHANNEL_INFO  ChannelInfo[MAX_CH];
} FSP_SMBIOS_MEMORY_INFO;

/*
* GBE PCD supported states.
*/
typedef enum {
  BL_GBE0_GBE1_DISABLED,
  BL_GBE0_GBE1_ENABLED,
  BL_GBE1_DISABLED,
} BL_GBE_PCD_STATE;

/*
* FIA MUX configuration structures.
*/

#define BL_ME_FIA_MUX_LANE_NUM_MAX    20
#define BL_ME_FIA_MUX_LANE_NUM_MIN    1
#define BL_ME_FIA_MUX_LANE_MUX_SEL_WIDTH 2
#define BL_ME_FIA_MUX_LANE_MUX_SEL_MASK    0x3
#define BL_ME_FIA_MUX_LANE_XHCI_ONLY       0xFF00000000

typedef enum {
  BL_FIA_LANE00 = 0,
  BL_FIA_LANE01,
  BL_FIA_LANE02,
  BL_FIA_LANE03,
  BL_FIA_LANE04,
  BL_FIA_LANE05,
  BL_FIA_LANE06,
  BL_FIA_LANE07,
  BL_FIA_LANE08,
  BL_FIA_LANE09,
  BL_FIA_LANE10,
  BL_FIA_LANE11,
  BL_FIA_LANE12,
  BL_FIA_LANE13,
  BL_FIA_LANE14,
  BL_FIA_LANE15,
  BL_FIA_LANE16,
  BL_FIA_LANE17,
  BL_FIA_LANE18,
  BL_FIA_LANE19,
} BL_ME_FIA_MUX_LANE_ORDER;

#define BL_ME_FIA_MUX_LANE_SATA0_BEGING BL_FIA_LANE04
#define BL_ME_FIA_MUX_LANE_SATA1_BEGING BL_FIA_LANE12

#define BL_FIA_LANE_CONFIG(Config, Lane) ( (UINT64) ( (UINT64)(Config) << ( (UINT64)(Lane) * (BL_ME_FIA_MUX_LANE_MUX_SEL_WIDTH))))

typedef union _BL_ME_FIA_MUX_CONFIG {
  UINT64 MeFiaMuxLaneConfig;
  struct {
    UINT64 Lane00MuxSel : 2;  // ME_FIA_MUX_LANE_DISABLED or PCIE
    UINT64 Lane01MuxSel : 2;  // ME_FIA_MUX_LANE_DISABLED or PCIE
    UINT64 Lane02MuxSel : 2;  // ME_FIA_MUX_LANE_DISABLED or PCIE
    UINT64 Lane03MuxSel : 2;  // ME_FIA_MUX_LANE_DISABLED or PCIE
    UINT64 Lane04MuxSel : 2;  // ME_FIA_MUX_LANE_DISABLED or PCIE or SATA
    UINT64 Lane05MuxSel : 2;  // ME_FIA_MUX_LANE_DISABLED or PCIE or SATA
    UINT64 Lane06MuxSel : 2;  // ME_FIA_MUX_LANE_DISABLED or PCIE or SATA
    UINT64 Lane07MuxSel : 2;  // ME_FIA_MUX_LANE_DISABLED or PCIE or SATA
    UINT64 Lane08MuxSel : 2;  // ME_FIA_MUX_LANE_DISABLED or PCIE or SATA
    UINT64 Lane09MuxSel : 2;  // ME_FIA_MUX_LANE_DISABLED or PCIE or SATA
    UINT64 Lane10MuxSel : 2;  // ME_FIA_MUX_LANE_DISABLED or PCIE or SATA
    UINT64 Lane11MuxSel : 2;  // ME_FIA_MUX_LANE_DISABLED or PCIE or SATA
    UINT64 Lane12MuxSel : 2;  // ME_FIA_MUX_LANE_DISABLED or PCIE or SATA
    UINT64 Lane13MuxSel : 2;  // ME_FIA_MUX_LANE_DISABLED or PCIE or SATA
    UINT64 Lane14MuxSel : 2;  // ME_FIA_MUX_LANE_DISABLED or PCIE or SATA
    UINT64 Lane15MuxSel : 2;  // ME_FIA_MUX_LANE_DISABLED or PCIE or SATA
    UINT64 Lane16MuxSel : 2;  // ME_FIA_MUX_LANE_DISABLED or XHCI or SATA
    UINT64 Lane17MuxSel : 2;  // ME_FIA_MUX_LANE_DISABLED or XHCI or SATA
    UINT64 Lane18MuxSel : 2;  // ME_FIA_MUX_LANE_DISABLED or XHCI or SATA
    UINT64 Lane19MuxSel : 2;  // ME_FIA_MUX_LANE_DISABLED or XHCI or SATA
    UINT64 Reserved     : 24;
  } BL_MeFiaMuxLaneMuxSel;
} BL_ME_FIA_MUX_CONFIG;

typedef enum {
  BL_ME_FIA_MUX_LANE_DISCONNECTED,
  BL_ME_FIA_MUX_LANE_PCIE,
  BL_ME_FIA_MUX_LANE_SATA,
  BL_ME_FIA_MUX_LANE_XHCI,
} BL_ME_FIA_MUX_LANE_CONFIG;

#define BL_ME_FIA_SATA_LANE_SEL_WIDTH   2
#define BL_ME_FIA_SATA_LANE_XHCI_ONLY   0x55000000

typedef enum {
  BL_FIA_SATA_LANE04 = 0,
  BL_FIA_SATA_LANE05,
  BL_FIA_SATA_LANE06,
  BL_FIA_SATA_LANE07,
  BL_FIA_SATA_LANE08,
  BL_FIA_SATA_LANE09,
  BL_FIA_SATA_LANE10,
  BL_FIA_SATA_LANE11,
  BL_FIA_SATA_LANE12,
  BL_FIA_SATA_LANE13,
  BL_FIA_SATA_LANE14,
  BL_FIA_SATA_LANE15,
  BL_FIA_SATA_LANE16,
  BL_FIA_SATA_LANE17,
  BL_FIA_SATA_LANE18,
  BL_FIA_SATA_LANE19
} BL_ME_FIA_SATA_LANE_ORDER;

#define BL_FIA_SATA_LANE_CONFIG(Config, Lane) ( (UINT32) ( (UINT32)(Config) << ( (UINT32)(Lane) * (BL_ME_FIA_SATA_LANE_SEL_WIDTH))))

typedef union _BL_ME_FIA_SATA_CONFIG {
  UINT64 MeFiaSataLaneConfig;
  struct {
    UINT64 Lane04SataSel : 2;
    UINT64 Lane05SataSel : 2;
    UINT64 Lane06SataSel : 2;
    UINT64 Lane07SataSel : 2;
    UINT64 Lane08SataSel : 2;
    UINT64 Lane09SataSel : 2;
    UINT64 Lane10SataSel : 2;
    UINT64 Lane11SataSel : 2;
    UINT64 Lane12SataSel : 2;
    UINT64 Lane13SataSel : 2;
    UINT64 Lane14SataSel : 2;
    UINT64 Lane15SataSel : 2;
    UINT64 Lane16SataSel : 2;
    UINT64 Lane17SataSel : 2;
    UINT64 Lane18SataSel : 2;
    UINT64 Lane19SataSel : 2;
    UINT64 Reserved      : 32;
  } BL_MeFiaSataLaneSataSel;
} BL_ME_FIA_SATA_CONFIG;

typedef enum
{
  BL_ME_FIA_SATA_CONTROLLER_LANE_ASSIGNED = 0,
  BL_ME_FIA_SATA_CONTROLLER_LANE_NOT_ASSIGNED = 1,
  BL_ME_FIA_SATA_CONTROLLER_LANE_SS_AND_GPIO_ASSIGNED = 3
} BL_ME_FIA_SATA_LANE_CONFIG;

#define BL_ME_FIA_PCIE_ROOT_PORT_LINK_WIDTH_SEL_WIDTH   4
#define BL_ME_FIA_PCIE_ROOT_PORTS_STATE_WIDTH           8
#define BL_ME_FIA_PCIE_ROOT_CONFIG_XHCI_ONLY            0x0

typedef enum {
  BL_FIA_PCIE_ROOT_PORT_0 = 0,
  BL_FIA_PCIE_ROOT_PORT_1,
  BL_FIA_PCIE_ROOT_PORT_2,
  BL_FIA_PCIE_ROOT_PORT_3,
  BL_FIA_PCIE_ROOT_PORT_4,
  BL_FIA_PCIE_ROOT_PORT_5,
  BL_FIA_PCIE_ROOT_PORT_6,
  BL_FIA_PCIE_ROOT_PORT_7
} BL_ME_FIA_PCIE_ROOT_PORT_ORDER;

#define BL_FIA_PCIE_ROOT_PORT_CONFIG(Type, Config, PcieRootPort) \
  (((Type) == BL_ME_FIA_PCIE_ROOT_PORT_STATE) ? \
      ((UINT64)((UINT64)(Config) << (UINT64)(PcieRootPort))) : \
      ((UINT64)((UINT64)(Config) << (UINT64)(((UINT64)(PcieRootPort) * (BL_ME_FIA_PCIE_ROOT_PORT_LINK_WIDTH_SEL_WIDTH)) + BL_ME_FIA_PCIE_ROOT_PORTS_STATE_WIDTH))))

typedef union _BL_ME_FIA_PCIE_ROOT_PORTS_CONFIG {
  UINT64 MeFiaPcieRootPortsConfig;
  struct {
    UINT64 PcieRp0En        : 1;
    UINT64 PcieRp1En        : 1;
    UINT64 PcieRp2En        : 1;
    UINT64 PcieRp3En        : 1;
    UINT64 PcieRp4En        : 1;
    UINT64 PcieRp5En        : 1;
    UINT64 PcieRp6En        : 1;
    UINT64 PcieRp7En        : 1;
    UINT64 PcieRp0LinkWidth : 4;
    UINT64 PcieRp1LinkWidth : 4;
    UINT64 PcieRp2LinkWidth : 4;
    UINT64 PcieRp3LinkWidth : 4;
    UINT64 PcieRp4LinkWidth : 4;
    UINT64 PcieRp5LinkWidth : 4;
    UINT64 PcieRp6LinkWidth : 4;
    UINT64 PcieRp7LinkWidth : 4;
    UINT64 Reserved         : 24;
  } BL_MeFiaPcieRpConfig;
} BL_ME_FIA_PCIE_ROOT_PORTS_CONFIG;

typedef enum
{
  BL_ME_FIA_PCIE_ROOT_PORT_STATE,
  BL_ME_FIA_PCIE_ROOT_PORT_LINK_WIDTH
} BL_ME_FIA_PCIE_ROOT_PORT_CONFIG_TYPE;

typedef enum
{
  BL_ME_FIA_PCIE_ROOT_PORT_DISABLED,
  BL_ME_FIA_PCIE_ROOT_PORT_ENABLED
} BL_ME_FIA_PCIE_ROOT_PORT_STATE_CONFIG;

typedef enum
{
  BL_ME_FIA_PCIE_ROOT_PORT_LINK_WIDTH_BICTRL = 0,
  BL_ME_FIA_PCIE_ROOT_PORT_LINK_X1 = 0xF
} BL_ME_FIA_PCIE_ROOT_PORT_LINK_CONFIG;

typedef struct _BL_ME_FIA_CONFIG
{
  BL_ME_FIA_MUX_CONFIG               MuxConfiguration;
  BL_ME_FIA_SATA_CONFIG              SataLaneConfiguration;
  BL_ME_FIA_PCIE_ROOT_PORTS_CONFIG   PcieRootPortsConfiguration;
} BL_ME_FIA_CONFIG;

/*
 * The FIA_MUX_CONFIG block describes the expected configuration of
 * FIA MUX configuration.
 */
typedef struct {
  UINT32  SkuNumLanesAllowed;             // Platform view of Num Lanes allowed
  BL_ME_FIA_CONFIG  FiaMuxConfig;         // Current Platform FIA MUX Configuration
  BL_ME_FIA_CONFIG  FiaMuxConfigRequest;  // FIA MUX Configuration Requested
} BL_FIA_MUX_CONFIG;

/*
 * The FIA_MUX_CONFIG_STATUS describes the status of configuring
 * FIA MUX configuration.
*/
typedef struct {
  UINT64     FiaMuxConfigGetStatus;    // Status returned from FiaMuxConfigGet,if not EFI_SUCCESS, then error occurred and user can decide on next steps
  UINT64     FiaMuxConfigSetStatus;    // Status returned from FiaMuxConfigSet,if not EFI_SUCCESS, then error occurred and user can decide on next steps
  BOOLEAN    FiaMuxConfigSetRequired;  // Boolean: True - A FiaMuxConfigSet was required, False - Otherwise
} BL_FIA_MUX_CONFIG_STATUS;

/*
* FIA MUX Config HOB structure
*/
typedef struct {
  BL_FIA_MUX_CONFIG              FiaMuxConfig;
  BL_FIA_MUX_CONFIG_STATUS       FiaMuxConfigStatus;
} BL_FIA_MUX_CONFIG_HOB;

/* PCIe port bifurcation codes - matches setup option values */
#define PCIE_BIF_CTRL_x2x2x2x2             0
#define PCIE_BIF_CTRL_x2x2x4               1
#define PCIE_BIF_CTRL_x4x2x2               2
#define PCIE_BIF_CTRL_x4x4                 3
#define PCIE_BIF_CTRL_x8                   4

#define BL_MAX_PCIE_CTRL     2

/*
 * HSIO INFORMATION structure
 */
typedef enum {
  BL_SKU_HSIO_06 = 6,
  BL_SKU_HSIO_08 = 8,
  BL_SKU_HSIO_10 = 10,
  BL_SKU_HSIO_12 = 12,
  BL_SKU_HSIO_20 = 20,
} BL_SKU_HSIO_LANE_NUMBER;

typedef struct {
  UINT16          NumLanesSupported;
  UINT8           PcieBifCtr[BL_MAX_PCIE_CTRL];
  BL_ME_FIA_CONFIG           FiaConfig;
} BL_HSIO_INFORMATION;

/*
 * eMMC DLL structure for EMMC DLL registers settings
 */
typedef struct {
  UINT32 TxCmdCntl;
  UINT32 TxDataCntl1;
  UINT32 TxDataCntl2;
  UINT32 RxCmdDataCntl1;
  UINT32 RxStrobeCntl;
  UINT32 RxCmdDataCntl2;
  UINT32 MasterSwCntl;
} BL_EMMC_DLL_CONFIG;

typedef struct {
  UINT16          Signature;
  BL_EMMC_DLL_CONFIG           eMMCDLLConfig;
} BL_EMMC_INFORMATION;

typedef enum {
  BL_FAST_BOOT_CHECKER_NORMAL = 0,
  BL_FAST_BOOT_CHECKER_WARNING,
  BL_FAST_BOOT_CHECKER_CRITICAL
} BL_FAST_BOOT_CHECKER;

#define  BL_MAX_SCRUB_SEGMENTS  5

typedef struct {
  UINT16    Start;    // Determines the low range for a memory segment (in MB)
  UINT16    End;      // Determines the high range for a memory segment (in MB)
} BL_SCRUB_SEGMENT;

typedef struct {
  UINT8              NumberOfSegments;
  UINT8              Reserved;
  BL_SCRUB_SEGMENT   ScrubSegment[BL_MAX_SCRUB_SEGMENTS];
} BL_MEMORY_SCRUB_SEGMENTS;


/** Fsp M Configuration
**/
typedef struct {

/** Offset 0x0040 - Tseg Size
  Size of SMRAM memory reserved.
  2:2 MB, 4:4 MB, 8:8 MB, 16:16 MB
**/
  UINT8                       PcdSmmTsegSize;

/** Offset 0x0041 - FSP Debug Print Level
  Select the FSP debug message print level.
  0:NO DEBUG, 1:MIN DEBUG, 2:MED DEBUG, 3:VERBOSE DEBUG
**/
  UINT8                       PcdFspDebugPrintErrorLevel;

/** Offset 0x0042 - Channel 0 DIMM 0 SPD SMBus Address
  SPD SMBus Address of each DIMM slot.
**/
  UINT8                       PcdSpdSmbusAddress_0_0;

/** Offset 0x0043 - Channel 0 DIMM 1 SPD SMBus Address
  SPD SMBus Address of each DIMM slot.
**/
  UINT8                       PcdSpdSmbusAddress_0_1;

/** Offset 0x0044 - Channel 1 DIMM 0 SPD SMBus Address
  SPD SMBus Address of each DIMM slot.
**/
  UINT8                       PcdSpdSmbusAddress_1_0;

/** Offset 0x0045 - Channel 1 DIMM 1 SPD SMBus Address
  SPD SMBus Address of each DIMM slot.
**/
  UINT8                       PcdSpdSmbusAddress_1_1;

/** Offset 0x0046 - Enable Rank Margin Tool
  Enable/disable Rank Margin Tool.
  $EN_DIS
**/
  UINT8                       PcdMrcRmtSupport;

/** Offset 0x0047 - RMT CPGC exp_loop_cnt
  Set the CPGC exp_loop_cnt field for RMT execution 2^(exp_loop_cnt -1).
  1:1, 2:2, 3:3, 4:4, 5:5, 6:6, 7:7, 8:8, 9:9, 10:10, 11:11, 12:12, 13:13, 14:14, 15:15
**/
  UINT8                       PcdMrcRmtCpgcExpLoopCntValue;

/** Offset 0x0048 - RMT CPGC num_bursts
  Set the CPGC num_bursts field for RMT execution 2^(num_bursts -1).
  1:1, 2:2, 3:3, 4:4, 5:5, 6:6, 7:7, 8:8, 9:9, 10:10, 11:11, 12:12, 13:13, 14:14, 15:15
**/
  UINT8                       PcdMrcRmtCpgcNumBursts;

/** Offset 0x0049 - Preserve Memory Across Reset
  Enable/disable memory preservation across reset.
  $EN_DIS
**/
  UINT8                       PcdMemoryPreservation;

/** Offset 0x004A - Fast Boot
  Enable/disable Fast Boot function. Once enabled, all following boots will use the
  presaved MRC data to improve the boot performance.
  $EN_DIS
**/
  UINT8                       PcdFastBoot;

/** Offset 0x004B - ECC Support
  Enable/disable ECC Support.
  $EN_DIS
**/
  UINT8                       PcdEccSupport;

/** Offset 0x004C - HSUART Device
  Select the PCI High Speed UART Device for Serial Port.
  0:HSUART0, 1:HSUART1, 2:HSUART2
**/
  UINT8                       PcdHsuartDevice;

/** Offset 0x004D - Memory Down
  Enable/disable Memory Down function.
  $EN_DIS
**/
  UINT8                       PcdMemoryDown;

/** Offset 0x004E
**/
  UINT32                      PcdMemoryDownConfigPtr;

/** Offset 0x0052 - SATA Controller 0
  Enable/disable SATA Controller 0.
  $EN_DIS
**/
  UINT8                       PcdEnableSATA0;

/** Offset 0x0053 - SATA Controller 1
  Enable/disable SATA Controller 1.
  $EN_DIS
**/
  UINT8                       PcdEnableSATA1;

/** Offset 0x0054 - Intel Quick Assist Technology
  Enable/disable Intel Quick Assist Technology.
  $EN_DIS
**/
  UINT8                       PcdEnableIQAT;

/** Offset 0x0055 - SPD Write Disable
  Select SMBus SPD Write Enable State (Default: 0 = [FORCE_ENABLE], 1 = [FORCE_DISABLE])
  0:Force Enable, 1:Force Disable
**/
  UINT8                       PcdSmbusSpdWriteDisable;

/** Offset 0x0056 - ME_SHUTDOWN Message
  Enable/Disable sending ME_SHUTDOWN message to ME, refer to FSP Integration Guide
  for details.
  $EN_DIS
**/
  UINT8                       PcdEnableMeShutdown;

/** Offset 0x0057 - XHCI Controller
  Enable / Disable XHCI controller
  $EN_DIS
**/
  UINT8                       PcdEnableXhci;

/** Offset 0x0058 - Memory Frequency
  Set DDR Memory Frequency, refer to FSP Integration Guide for details.
  15:Auto, 3:1600, 4:1866, 5:2133, 6:2400
**/
  UINT8                       PcdDdrFreq;

/** Offset 0x0059 - MMIO Size
  Set memory mapped IO space size
  0:2048M, 1:1024M, 2:3072M
**/
  UINT8                       PcdMmioSize;

/** Offset 0x005A - ME HECI Communication
  Enable/Disable ME HECI communication
  $EN_DIS
**/
  UINT8                       PcdMeHeciCommunication;

/** Offset 0x005B - HSIO Lanes Number
  HSIO lanes number of SKU
  6:6, 8:8, 10:10, 12:12, 20:20
**/
  UINT8                       PcdHsioLanesNumber;

/** Offset 0x005C
**/
  UINT32                      PcdFiaMuxConfigPtr;

/** Offset 0x0060 - Customer Revision
  The Customer can set this revision string for their own purpose.
**/
  UINT8                       PcdCustomerRevision[32];

/** Offset 0x0080 - 32-Bit bus mode
  Enable/Disable 32-Bit bus memory mode.
  $EN_DIS
**/
  UINT8                       PcdHalfWidthEnable;

/** Offset 0x0081 - TCL Performance
  Enable/Disable Tcl timing for performance.
  $EN_DIS
**/
  UINT8                       PcdTclIdle;

/** Offset 0x0082 - Interleave Mode
  Select Interleave Mode
  0:DISABLED, 1:MODE0, 2:MODE1, 3:MODE2
**/
  UINT8                       PcdInterleaveMode;

/** Offset 0x0083 - Memory Thermal Throttling
  Enable/disable Memory Thermal Throttling management mode
  $EN_DIS
**/
  UINT8                       PcdMemoryThermalThrottling;

/** Offset 0x0084 - Memory Test
  Enable / Disable Memory Test, refer to FSP Integration Guide for details.
  $EN_DIS
**/
  UINT8                       PcdSkipMemoryTest;

/** Offset 0x0085
**/
  BL_MEMORY_SCRUB_SEGMENTS*   PcdScrubSegmentPtr;

/** Offset 0x0089 - USB2 Port 1 OC Pin
  Map selected OC pin to the port
  0:OC Pin 0, 8:No pin mapped
**/
  UINT8                       PcdUsb2Port1Pin;

/** Offset 0x008A - USB2 Port 2 OC Pin
  Map selected OC pin to the port
  0:OC Pin 0, 8:No pin mapped
**/
  UINT8                       PcdUsb2Port2Pin;

/** Offset 0x008B - USB2 Port 3 OC Pin
  Map selected OC pin to the port
  0:OC Pin 0, 8:No pin mapped
**/
  UINT8                       PcdUsb2Port3Pin;

/** Offset 0x008C - USB2 Port 4 OC Pin
  Map selected OC pin to the port
  0:OC Pin 0, 8:No pin mapped
**/
  UINT8                       PcdUsb2Port4Pin;

/** Offset 0x008D - USB3 Port 1 OC Pin
  Map selected OC pin to the port
  0:OC Pin 0, 8:No pin mapped
**/
  UINT8                       PcdUsb3Port1Pin;

/** Offset 0x008E - USB3 Port 2 OC Pin
  Map selected OC pin to the port
  0:OC Pin 0, 8:No pin mapped
**/
  UINT8                       PcdUsb3Port2Pin;

/** Offset 0x008F - USB3 Port 3 OC Pin
  Map selected OC pin to the port
  0:OC Pin 0, 8:No pin mapped
**/
  UINT8                       PcdUsb3Port3Pin;

/** Offset 0x0090 - USB3 Port 4 OC Pin
  Map selected OC pin to the port
  0:OC Pin 0, 8:No pin mapped
**/
  UINT8                       PcdUsb3Port4Pin;

/** Offset 0x0091 - IOxAPIC 0-199
  Enable/disable IOxAPIC 24-119 entries
  $EN_DIS
**/
  UINT8                       PcdIOxAPIC0_199;

/** Offset 0x0092 - DMAP_X16
  Enable/Disable DMAP_X16 dynamic MRC field indicating memory device width is x16 or not
  $EN_DIS
**/
  UINT8                       PcdDmapX16;

/** Offset 0x0093
**/
  UINT8                       UnusedUpdSpace0[333];

/** Offset 0x01E0
**/
  UINT8                       ReservedMemoryInitUpd[16];
} FSPM_CONFIG;

/** Fsp M UPD Configuration
**/
typedef struct {

/** Offset 0x0000
**/
  FSP_UPD_HEADER              FspUpdHeader;

/** Offset 0x0020
**/
  FSPM_ARCH_UPD               FspmArchUpd;

/** Offset 0x0040
**/
  FSPM_CONFIG                 FspmConfig;

/** Offset 0x01F0
**/
  UINT8                       UnusedUpdSpace1[14];

/** Offset 0x01FE
**/
  UINT16                      UpdTerminator;
} FSPM_UPD;

#pragma pack()

#endif