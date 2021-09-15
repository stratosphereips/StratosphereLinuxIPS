#!/bin/bash
cd modules/kalipso

file="../../used_redis_servers.txt"
# Declare a string array
declare -a unused_redis_servers=()

while IFS= read -r line # read file line by line
do
    # ignore line if it starts with # or had Date in it
    if [[ ${line} =~ "Date" ]] || [[ ${line} =~ "#" ]]; then
     continue
    fi

    # set space as delimiter
    IFS=' '
    read -ra splitted_line <<< "$line"   # line is read into an array as tokens separated by space

    # add the pid to unused_redis_servers array
#    unused_redis_servers+=${splitted_line[-1]}
    unused_redis_servers[${#unused_redis_servers[@]}]=${splitted_line[-1]}
done < "$file"


# if we have only 1 server open, use it
if [[ ${#unused_redis_servers[@]} -eq 1 ]]; then
  pid_to_use=${unused_redis_servers[0]}
# if we have more than 1 PIDs in the arr, prompt which pid to use
elif [[ ${#unused_redis_servers[@]} -gt 0 ]]; then
    echo "You have ${#unused_redis_servers[@]} open redis servers, Choose the PID to use? [1,2,3 etc..] "
    # ctr to print next to each pid
    ctr=1
    for value in "${unused_redis_servers[@]}"
        do
             echo "[$ctr] $value"
             let ctr=ctr+1
        done
    # the user will choose 1,2,3 etc
    read pid_idx
    let pid_idx=pid_idx-1
    # get the pid in this index
    pid_to_use=${unused_redis_servers[pid_idx]}
fi
echo "To close all unused redis servers, run slips with --killall"
# run kalipso
node kalipso -l 2000 -p pid_to_use
