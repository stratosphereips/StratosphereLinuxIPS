# Table Of Contents
- [Installing Slips On The Raspberry PI](#installing-slips-on-the-raspberry-pi)
- [Protect your local network with Slips on the RPI](#protect-your-local-network-with-slips-on-the-rpi)
- [Debugging common AP errors](#debugging-common-ap-errors)
  - [ERROR: Your adapter can not be a station (i.e. be connected) and an AP at the same time](#error--your-adapter-can-not-be-a-station--ie-be-connected--and-an-ap-at-the-same-time)
  - [dnsmasq: failed to bind DHCP server socket: Address already in use](#dnsmasq--failed-to-bind-dhcp-server-socket--address-already-in-use)
  - [RTNETLINK answers: Operation not possible due to RF-kill](#rtnetlink-answers--operation-not-possible-due-to-rf-kill)

# Installing Slips On The Raspberry PI

The recommended way to install Slips on the RPI is using docker.

If you're using the 64-bit (arm64) version of the RPI,
follow the official docker [installation instructions for Debian](https://docs.docker.com/engine/install/debian/).

Slips now supports a native linux/arm64 docker image, you can pull it using

    docker pull stratosphereips/slips:latest

To enable P2P, make sure of the following:
* You run Slips docker with --net=host
* You don't have redis running on the host and occupying Redis' default IP/Port 127.0.0.1:6379.

### Protect your local network with Slips on the RPI

By installing Slips on your RPI and using it as an access point,
you can extend its protection to your other connected devices.

Once Slips detects a malicious device, it will block all traffic to and from it using iptables.
Meaning it wil kick out the malicious device from the AP.

![](../images/immune/rpi_as_an_acces_point.jpeg)


1. Connect your RPI to your router using an ethernet cable
2. Run your RPI as an access point using [create_ap](https://github.com/oblique/create_ap)

`sudo create_ap wlan0 eth0 rpi_wifi mysecurepassword -c 40`

where `wlan0` is the wifi interface of your RPI, `eth0` is the ethernet interface and `-c 40` is the channel of the access point.

We chose channel 40 because it is a 5GHz channel, which is faster and less crowded than the 2.4GHz channels.

Note: Please make sure your RPI model supports 5GHz channels. If not, you can use `-c 1` for 2.4GHz.


If all goes well you should see `wlan0: AP-ENABLED` in the output of the command.


Check the [Debugging common AP errors](#debugging-common-ap-errors) section if you have any issues.

3. Run Slips in the RPI using the command below to listen to the traffic from the access point.

```bash
./slips.py -i wlan0
```

4. (Optional) If you want to block malicious devices, run Slips with the `-p` parameter. Using this parameter will
block all traffic to and from the malicious device when slips sets an alert.

```bash
./slips.py -i wlan0 -p
```

Now connect your devices to the rpi_wifi with "mysecurepassword" as the password, and enjoy the protection of Slips.


## Debugging common AP errors


#### ERROR: Your adapter can not be a station (i.e. be connected) and an AP at the same time

If you get this error while connected to the router with an ethernet, This means that your rpi is still using wifi
for internet and not you ethernet

---


#### dnsmasq: failed to bind DHCP server socket: Address already in use

Ensure no other DHCP server is running: Check for other services that may be using DHCP (like dnsmasq) and stop them:
`sudo systemctl stop dnsmasq`

---

#### RTNETLINK answers: Operation not possible due to RF-kill

This error indicates that the wireless interface is blocked by a hardware or software kill switch.
Check the blocked interface using `sudo rfkill list` then unblock it using `sudo rfkill unblock <number>`
