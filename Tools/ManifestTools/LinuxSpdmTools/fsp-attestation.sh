#!/bin/bash
# fsp attestation
FSPtools_path="../"
Image_bin="$1"
Eventlog_bin="$2"
Out_xml="spdm_swid_temp.xml"

echo  -e "\033[34m -------------------------------------- \033[0m"
echo  -e "\033[34m |FSP TOOLS start ...                 | \033[0m"
echo  -e "\033[34m |genswid start ...                   | \033[0m"
echo  -e "\033[34m -------------------------------------- \033[0m"
python $FSPtools_path/FspGenSwid.py genswid -i $FSPtools_path/SampleConfig/FspRimTemplate.ini -p $Image_bin -t SHA_256 -o $FSPtools_path/$Out_xml
sleep 1
echo  "$FSPtools_path/$Out_xml"
echo  -e "\033[34m -------------------------------------- \033[0m"
echo  -e "\033[34m |genswid end   ...                   | \033[0m"
echo  -e "\033[34m -------------------------------------- \033[0m"

echo  -e "\033[34m -------------------------------------- \033[0m"
echo  -e "\033[34m |verify-hash start  ...              | \033[0m"
echo  -e "\033[34m -------------------------------------- \033[0m"
python  $FSPtools_path/FspGenSwid.py verify-hash -f  $FSPtools_path/$Out_xml -t SHA_256  --evt $Eventlog_bin
sleep 1
echo  -e "\033[34m -------------------------------------- \033[0m"
echo  -e "\033[34m |verify-hash end    ...              | \033[0m"
echo  -e "\033[34m -------------------------------------- \033[0m"
echo  -e "\033[34m -------------------------------------- \033[0m"
echo  -e "\033[34m |compare start ...                   | \033[0m"
echo  -e "\033[34m -------------------------------------- \033[0m"

python  $FSPtools_path/FspTools.py compare --evt $Eventlog_bin --fd $Image_bin


echo  -e "\033[34m -------------------------------------- \033[0m"
echo  -e "\033[34m |compare end   ...                   | \033[0m"
echo  -e "\033[34m -------------------------------------- \033[0m"
