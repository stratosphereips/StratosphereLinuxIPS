# FAQ

## Slips starting too slow in docker

Make sure you're not running many containers at the same time because they share kernel resources 
even though they're isolated.


## Docker time is not in syncs with that of the host

You can add your local /etc/localtime as volume in Slips Docker container by using:

```
docker run -it --rm --net=host --cap-add=NET_ADMIN -v /etc/localtime:/etc/localtime:ro --name slips stratosphereips/slips:latest 
```

