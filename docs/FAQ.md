# FAQ

## Slips starting too slow in docker

Make sure you're not running many containers at the same time because they share kernel resources
even though they're isolated.


## Getting "Illegal instruction" error when running slips

If the tensorflow version you're using isn't compatible with your architecture,
you will get the "Illegal instruction" error and slips will terminate.

To fix this you can disable the modules that use tensorflow by adding
```rnn-cc-detection, flowmldetection``` to the ```disable``` key in ```config/slips.yaml```


## Docker time is not in sync with that of the host

You can add your local /etc/localtime as volume in Slips Docker container by using:

```
docker run -it --rm --net=host --cap-add=NET_ADMIN -v /etc/localtime:/etc/localtime:ro --name slips stratosphereips/slips:latest
```

## Redis WARNING Memory overcommit must be enabled! in docker

This is a redis known issue, you can find the fix here
https://redis.io/docs/latest/operate/oss_and_stack/management/admin/#:~:text=Redis%20setup%20tips-,Linux,-Deploy%20Redis%20using
