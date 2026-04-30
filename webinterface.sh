#!/bin/bash

set -e

if [ -x ".venv/bin/python3" ]; then
    .venv/bin/python3 -m webinterface.app
else
    python3 -m webinterface.app
fi
