#!/bin/bash

if [ "$#" -ne 1 ]; then
    echo "Please pass the path to a ntds.dit database"
    exit
fi

esentutl.py $1 export -table datatable | grep -E "ATTk590689|ATTm3|ATTm590045|ATTm590045|ATTr589970|ATTk589914|ATTk589879|ATTk589984|ATTk589918"
