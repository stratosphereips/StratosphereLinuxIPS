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
    unused_redis_servers+=${splitted_line[-1]}
    
done < "$file"


for value in "${unused_redis_servers[@]}"
do
     echo $value
done

#node kalipso -l 2000
