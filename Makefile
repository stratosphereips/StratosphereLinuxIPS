bash:
	docker run --rm -it slips /bin/bash

image:
	docker build -t slips -f docker/ubuntu-image/Dockerfile .
