#!/bin/bash

# IPv4 Converter (ipv4conv)
# r2020-12-06 fr2020-12-06


# Config

prinp=true; # Print input (given IP)


# Functions

function apphelp() {
echo "IPv4 Converter (ipv4conv)";
echo "by Valerio Capello - labs.geody.com - License: GPL v3.0";
echo;
echo "Converts dotted (short) IP to undotted (long) IP and viceversa.";
echo;
echo "Usage:";
echo "ipv4conv [action] IP";
echo;
echo "Actions:"
echo "--d2u  : Dotted (Short) IP to Undotted (Long) IP";
echo "--u2d  : Undotted (Long) IP to Dotted (Short) IP";
echo "--auto : Auto sense";
echo "If action is omitted, auto sensing is applied by default.";
echo;
echo "Examples:";
echo "ipv4conv --d2u 192.0.2.100";
echo "ipv4conv --u2d 3221226084";
echo "ipv4conv --auto 192.0.2.100";
echo "ipv4conv --auto 3221226084";
echo "ipv4conv 192.0.2.100";
echo "ipv4conv 3221226084";
}

isipv4dot() {
if [ "$#" -le 0 ]; then return 1; fi
local ip=${1:-1.2.3.4}
if expr "$ip" : '[0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*$' >/dev/null; then
IFS=.
set $ip
for quad in 1 2 3 4; do
if eval [ \$$quad -gt 255 ]; then
# echo "fail ($ip)"
return 1
fi
done
# echo "success ($ip)"
return 0
else
# echo "fail ($ip)"
return 1
fi
}

isipv4und() {
if [ "$#" -le 0 ]; then return 1; fi
local ip="$1";
if [[ $ip =~ ^[0-9]+$ ]] && [ $ip -ge 0 ] && [ $ip -le 4294967295 ]; then
# echo "success ($ip)"
return 0
else
# echo "fail ($ip)"
return 1
fi
}

isipv6() {
if [ "$#" -le 0 ]; then return 1; fi
local ip="$1";
local pattipv6='^([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}$';
if [[ "$ip" =~ $pattipv6 ]]; then
# if (echo "$ip" | grep -Eq $regex); then # POSIX
# echo "success ($ip)"
return 0
else
# echo "fail ($ip)"
return 1
fi
}

# Requires isipv4dot, isipv4und, isipv6
isip() {
if [ "$#" -le 0 ]; then return 1; fi
if isipv4dot "$1"; then
echo -n '4';
return 0
elif isipv4und "$1"; then
echo -n '5';
return 0
elif isipv6 "$1"; then
echo -n '6';
return 0
else
echo -n '0';
return 1
fi
}

ipdot2undot() {
if [ "$#" -le 0 ]; then return 1; fi
local a b c d ip=$@
IFS=. read -r a b c d <<< "$ip"
printf '%d' "$((a * 256 ** 3 + b * 256 ** 2 + c * 256 + d))"
}

ipundot2dot() {
if [ "$#" -le 0 ]; then return 1; fi
local ip dec=$@
for e in {3..0}
do
((octet = dec / (256 ** e) ))
((dec -= octet * 256 ** e))
ip+=$delim$octet
delim=.
done
printf '%s' "$ip"
}

# Requires isip (isipv4dot, isipv4und, isipv6), ipdot2undot, ipundot2dot
ipdotautoconv() {
if [ "$#" -le 0 ]; then return 1; fi
local ipv=$(isip "$1")
case $ipv in
4)
echo -n $(ipdot2undot "$1");
return 0
;;
5)
echo -n $(ipundot2dot "$1");
return 0
;;
6)
# echo -n 'IPv6';
return 1
;;
*)
# echo -n 'Invalid IP';
return 1
;;
esac
}


# Main

if [ "$#" -eq 0 ]; then
echo "Missing parameters."; echo; apphelp;
exit 1;
elif [ "$#" -gt 2 ]; then
echo "Too many parameters."; echo; apphelp;
exit 1;
fi

if [ "$#" -eq 1 ]; then
act='--auto'; ip="$1";
else
act="$1"; ip="$2";
fi

if [[ "$act" != '--auto' ]] && [[ "$act" != '--d2u' ]] && [[ "$act" != '--u2d' ]]; then
echo "$act: invalid action";
exit 1;
fi

ipv=$(isip "$ip")

if ( $prinp ); then
echo -n "$ip : ";
fi

if [ $ipv -eq 4 ] || [ $ipv -eq 5 ]; then
case "$act" in
'--auto')
echo "$(ipdotautoconv $ip)";
;;
'--d2u')
if [ $ipv -eq 4 ]; then
echo "$(ipdot2undot $ip)";
else
echo 'Already Undotted';
fi
;;
'--u2d')
if [ $ipv -eq 5 ]; then
echo "$(ipundot2dot $ip)";
else
echo 'Already Dotted';
fi
;;
*)
echo "$act: invalid action"; # Can't happen: it's detected before
;;
esac
elif [ $ipv -eq 6 ]; then
echo 'IPv6';
else
echo 'Invalid IP';
fi
