#!/bin/bash

for num in 0 1 2 3 4 5 6 7 ; do
    ./training_script.sh "$num"
    if [ $? -ne 0 ]; then
        exit 1
    fi
done
