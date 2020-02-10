#!/bin/sh
ifconfig wlan0 down
ip link set name mon0 wlan0
iwconfig mon0 mode moniter
ifconfig mon0 up
airmon-ng check kill
echo done
