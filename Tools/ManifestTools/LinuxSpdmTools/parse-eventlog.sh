#!/bin/bash
# parse event log
#

#echo color:
GREEN='\E[1;32m'
YELOW='\E[1;33m'
BLUE='\E[1;34m'
PINK='\E[1;35m'
RES='\E[0m' 
echo  -e "${BLUE} -------------------------------------- ${RES}"
echo  -e "${BLUE} |parse the event log ...             | ${RES}"
echo  -e "${BLUE} -------------------------------------- ${RES}"
tpm2_eventlog $1 > temp.log

sleep 1
echo  -e "${BLUE} -------------------------------------- ${RES}"
echo  -e "${BLUE} |View the event log  ...             | ${RES}"
echo  -e "${BLUE} -------------------------------------- ${RES}"
sleep 1

vim  temp.log
