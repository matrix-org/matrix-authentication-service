#!/bin/sh

if [ "$#" -ne 1 ]; then
  echo "usage: $0 [platform]" >&2
  exit 1
fi

if [ "$1" = "linux/arm64" -o "$1" = "linux/arm64/v8" ]; then
  echo "aarch64-unknown-linux-gnu"
elif [ "$1" = "linux/arm" -o "$1" = "linux/arm/v7" ]; then
  echo "armv7-unknown-linux-gnueabihf"
elif [ "$1" = "linux/arm/v6" ]; then
  echo "arm-unknown-linux-gnueabihf"
elif [ "$1" = "linux/amd64" ]; then
  echo "x86_64-unknown-linux-gnu"
elif [ "$1" = "linux/i386" ]; then
  echo "i686-unknown-linux-gnu"
else
  echo "unsupported platform $1" >&2
  exit 2
fi
