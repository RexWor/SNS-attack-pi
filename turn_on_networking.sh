#!/bin/bash

WLAN=$1

sudo systemctl restart networking
sudo ip link set $WLAN down
sudo iw $WLAN set type managed
sudo ip link set $WLAN up
sudo rfkill unblock wifi
sudo rfkill unblock all
sudo systemctl restart wpa_supplicant
sudo systemctl restart NetworkManager
