#!/bin/sh

device=$(df -hl --output=source . | sed 1d | sed 's/[0-9]//g')
device=${device##*/}

rotational=$(cat /sys/block/$device/queue/rotational)

if [ $rotational = "1" ] ; then
	printf "HDD"
else
	printf "SSD"
fi
