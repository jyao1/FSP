#!/bin/bash
# fsp attestation
#

FSPtools_path="../"
Image_bin="$1"
Eventlog_bin="$2"
Out_xml="spdm_swid_temp.xml"
#echo color:
GREEN='\E[1;32m'
YELOW='\E[1;33m'
BLUE='\E[1;34m'
PINK='\E[1;35m'
RES='\E[0m' 

echo  -e "${BLUE} -------------------------------------- ${RES}"
echo  -e "${BLUE} |FSP TOOLS start ...                 | ${RES}"
echo  -e "${BLUE} |genswid start ...                   | ${RES}"
echo  -e "${BLUE} -------------------------------------- ${RES}"
python $FSPtools_path/FspGenSwid.py genswid -i $FSPtools_path/SampleConfig/FspRimTemplate.ini -p $Image_bin -t SHA_256 -o $FSPtools_path/$Out_xml
sleep 1
echo  "$FSPtools_path/$Out_xml"
echo  -e "${BLUE} -------------------------------------- ${RES}"
echo  -e "${BLUE} |genswid end   ...                   | ${RES}"
echo  -e "${BLUE} -------------------------------------- ${RES}"

echo  -e "${BLUE} -------------------------------------- ${RES}"
echo  -e "${BLUE} |verify-hash start  ...              | ${RES}"
echo  -e "${BLUE} -------------------------------------- ${RES}"
python  $FSPtools_path/FspGenSwid.py verify-hash -f  $FSPtools_path/$Out_xml -t SHA_256  --evt $Eventlog_bin
sleep 1
echo  -e "${BLUE} -------------------------------------- ${RES}"
echo  -e "${BLUE} |verify-hash end    ...              | ${RES}"
echo  -e "${BLUE} -------------------------------------- ${RES}"
echo  -e "${BLUE} -------------------------------------- ${RES}"
echo  -e "${BLUE} |compare start ...                   | ${RES}"
echo  -e "${BLUE} -------------------------------------- ${RES}"

python  $FSPtools_path/FspTools.py compare --evt $Eventlog_bin --fd $Image_bin


echo  -e "${BLUE} -------------------------------------- ${RES}"
echo  -e "${BLUE} |compare end   ...                   | ${RES}"
echo  -e "${BLUE} -------------------------------------- ${RES}"
