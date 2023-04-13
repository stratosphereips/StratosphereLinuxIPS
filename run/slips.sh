#!/bin/bash
# this script runs slips in docker using the argument given whether it's an interface or a file
# the output of slips will be stored in the local output/ dir


if [ -z "$*" ]; then
  echo "Usage: <script> <interface/file>";
  exit 1;
fi

# Declare an empty array to store interface names
interface_list=()

# get all intefaces
for interface in $(ip link show | awk -F': ' '{print $2}' | sed '/lo/d'); do
  interface_list+=("$interface")
done


# Check if first argument is in the list
if [[ " ${interface_list[*]} " == *" ${1} "* ]]; then
  # first arg is an interface
  docker run -it -d --rm --name slips --net=host -p 55000:55000 -v $(pwd)/dataset:/StratosphereLinuxIPS/dataset -v $(pwd)/output:/StratosphereLinuxIPS/output -v $(pwd)/config:/StratosphereLinuxIPS/config stratosphereips/slips ./slips.py -e 1 -i ${1}
else
  docker run -it -d --rm --name slips --net=host -p 55000:55000 -v $(pwd)/dataset:/StratosphereLinuxIPS/dataset -v $(pwd)/output:/StratosphereLinuxIPS/output -v $(pwd)/config:/StratosphereLinuxIPS/config stratosphereips/slips ./slips.py -e 1 -f ${1}
fi

