# This is the configuration file to create a docker for running slips.

# Build instructions

- Then build: docker build -t slips -f Dockerfile .
- Run container: docker run -it --rm --net=host slips
- Run Slips in container: ./slips.py -c slips.conf -i wlan0
