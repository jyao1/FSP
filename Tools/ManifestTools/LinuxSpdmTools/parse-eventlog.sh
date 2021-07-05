#!/bin/bash
# parse event log
#
echo  -e "\033[34m -------------------------------------- \033[0m"
echo  -e "\033[34m |parse the event log ...             | \033[0m"
echo  -e "\033[34m -------------------------------------- \033[0m"
tpm2_eventlog $1 > temp.log

sleep 1
echo  -e "\033[34m -------------------------------------- \033[0m"
echo  -e "\033[34m |View the event log  ...             | \033[0m"
echo  -e "\033[34m -------------------------------------- \033[0m"
sleep 1

vim  temp.log
