# Verify a Raspberry Pi Slips release

A Pi can run a Docker image built from a different revision than a local checkout. Check the running container after an update, rather than relying on its image tag alone.

Run these commands on the Pi. Set `slips_container` to the name shown by `docker ps`:

```sh
slips_container=slips_rpi2
docker ps --filter "name=$slips_container" --format '{{.Names}} {{.Status}} {{.Image}}'
docker exec "$slips_container" git rev-parse HEAD
docker image inspect "$(docker inspect "$slips_container" --format '{{.Image}}')" \
  --format '{{index .Config.Labels "org.opencontainers.image.revision"}}'
```

The Git revision and image revision label must match the intended release commit. Check the running process and recent errors:

```sh
docker top "$slips_container"
docker logs --tail 50 "$slips_container"
```

Before replacing a container, record the existing command and bind mounts with `docker inspect`. Keep the `config`, `output`, and `permanent` mounts when creating the replacement. After it starts, verify those mounts again and confirm that the existing detection database and peer identity are still present. Keep the old stopped container until the new one is capturing and the web interface responds.
