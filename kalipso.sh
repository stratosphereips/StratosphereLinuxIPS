#!/bin/bash
cd modules/kalipso
echo "To close all unused redis servers, run slips with --killall"
file="../../running_slips_info.txt"
# Declare a string array
declare -a open_redis_servers=()
declare -a ports=()

while IFS= read -r line # read file line by line
do
    # ignore line if it starts with # or has Date in it
    if [[ ${line} =~ "Date" ]] || [[ ${line} =~ "#" ]]; then
     continue
    fi

    # set , as delimiter
    IFS=','
    read -ra splitted_line <<< "$line"   # line is read into an array as tokens separated by ,

    # add the used file to open_redis_servers array
    open_redis_servers[${#open_redis_servers[@]}]=${splitted_line[1]}
    # append the used port to  ports arr
    ports[${#ports[@]}]=${splitted_line[2]}
done < "$file"



if [[ ${#open_redis_servers[@]} -eq 0 ]]; then
  echo "You have 0 open redis-servers to use. Make sure you run slips first"
  exit 1
# if we have only 1 server open, use it
elif [[ ${#open_redis_servers[@]} -eq 1 ]]; then
  port_to_use=${ports[0]}
# if we have more than 1 open redis server in the arr, prompt which one to use
elif [[ ${#open_redis_servers[@]} -gt 0 ]]; then
    echo "You have ${#open_redis_servers[@]} open redis servers, Choose which one to use [1,2,3 etc..] "
    # ctr to print next to each server
    ctr=1
    for value in "${open_redis_servers[@]}"
        do
             echo "[$ctr] $value - port ${ports[ctr-1]}"
             let ctr=ctr+1
        done
    # the user will choose 1,2,3 etc
    read index
    let index=index-1
    # get the pid in this index
    port_to_use=${ports[index]}
fi
# run kalipso
node kalipso -l 2000 -p ${port_to_use}
