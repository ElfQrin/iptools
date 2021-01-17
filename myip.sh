#!/bin/bash

# MyIP
# r2020-12-30 fr2017-04-18
# by Valerio Capello - http://labs.geody.com/ - License: GPL v3.0

# Config

tshilon="\e[0;33m"; tshilof="\e[0m"; # Hilight Text On / Off
tsalerton="\e[0;31m"; tsalertof="\e[0m"; # Alert Text On / Off
showdate=true; # Show Date


# Main

# Show info

if ( $showdate ); then date "+%a %d %b %Y %H:%M:%S %Z (UTC%:z)"; fi

echo -n "Hello "; echo -ne "$tshilon"; echo -n "$(whoami)"; echo -ne "$tshilof";
if [ "$SSH_CONNECTION" ]; then
echo -n " ("; echo -ne "$tshilon"; echo -n "$( echo $SSH_CLIENT | awk '{print $1}' )"; echo -ne "$tshilof)";
fi
echo -n ", ";

echo -n "this is "; echo -ne "$tshilon"; echo -n "$( hostname )"; echo -ne "$tshilof";
echo -n " ("; echo -ne "$tshilon";
# echo -n "$( hostname -i )";
echo -n "$( ifconfig | sed -En 's/127.0.0.1//;s/.*inet (addr:)?(([0-9]*\.){3}[0-9]*).*/\2/p' )";
echo -ne "$tshilof";
echo -n "; Gateway: ";
echo -ne "$tshilon";
echo -n "$( route -n | grep 'UG[ \t]' | awk '{print $2}' )";
echo -ne "$tshilof";
echo -n ")";
echo ".";

echo -n "You are ";
if [ -n "$SSH_CONNECTION" ]; then
echo -n "connected remotely via SSH";
elif [[ "${DISPLAY%%:0*}" != "" ]]; then
echo -n "connected remotely "; echo -ne "$tsalerton"; echo -n "NOT"; echo -ne "$tsalertof"; echo " via SSH (which is Bad)";
else
echo -n "connected locally";
fi

echo
