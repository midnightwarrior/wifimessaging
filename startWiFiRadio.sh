#!/bin/bash

interface=$1
channel=$2

sudo ifconfig $1 down
sudo iw dev $1 set monitor otherbss fcsfail
sudo ifconfig $1 up
sudo iwconfig $1 channel $2

