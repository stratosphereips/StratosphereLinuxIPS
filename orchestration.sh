#!/bin/bash

numbers=( 0 .. 7) # Add more numbers as needed 0..7?
for num in "${numbers[@]}"; do
    ./training_script.sh "$num"
    if [ $? -ne 0 ]; then
        exit 1
    fi
done
