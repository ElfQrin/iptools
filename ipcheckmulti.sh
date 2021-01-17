#!/bin/bash

# IPcheckmulti - Minimal IPcheck to check multiple IPs from a file or an Apache Log
xver='r2021-01-16 fr2020-08-20';
# by Valerio Capello - http://labs.geody.com/ - License: GPL v3.0


# Config

ipfetch=10; # How many most active IPs will be fetched from the Apache Log File if the IP File is not provided
nreshd=10; # Limit Results for Log Head
nrestl=$nreshd; # Limit Results for Log Tail
elsep='----------'; # Separator between each IP's report
rmtmpfile=true; # Remove tmp file, if one has been created (that is, if the IP File is not provided and it's generated fetching IPs from the Apache Log)


# Functions

apphdr() {
echo "IPcheckmulti - Minimal IPcheck to check multiple IPs from a file or an Apache Log";
echo "by Valerio Capello - labs.geody.com - License: GPL v3.0";
}

# Requires apphdr
apphelp() {
apphdr; echo;
echo "Usage:";
echo "ipcheckmulti LOG         # Check IP activity for the $ipfetch most active IPs in Apache LOG";
echo "ipcheckmulti LOG IPFILE  # Check IP activity for the IPs from IPFILE (one per line) in Apache LOG";
echo "ipcheckmulti --help      # Display this help";
echo "ipcheckmulti --version   # Display version information";
echo;
echo "Example:";
echo "ipcheckmulti /var/log/apache2/access.log";
}

isfile() {
if [[ -d $1 ]]; then
echo -n '2';
return 0
elif [[ -f $1 ]]; then
echo -n '1';
return 0
else
echo -n '0';
return 1
fi
}

function hrtime {
local T=$1
local D=$((T/60/60/24))
local H=$((T/60/60%24))
local M=$((T/60%60))
local S=$((T%60))
(( $D > 0 )) && printf '%d days ' $D
(( $H > 0 )) && printf '%d hours ' $H
(( $M > 0 )) && printf '%d minutes ' $M
(( $D > 0 || $H > 0 || $M > 0 )) && printf ''
printf '%d seconds' $S
}


# Get Parameters

if [ $# -eq 1 ]; then
case $1 in
'--help')
apphelp
exit 0;
;;
'--ver'|'--version')
apphdr; echo
echo "Version: $xver";
exit 0;
;;
esac
logf=$1; # Apache Log File
ipsf=''; # File with the IPs is missing, top IPs from the Apache Log File will be fetched instead
elif [ $# -eq 2 ]; then
logf=$1; # Apache Log File
ipsf=$2; # File with the IPs
else
apphelp
exit 1;
fi


# Log Presets

if [ -n "$logf" ]; then
case $logf in
apache | apache2 | "apache 2" | standard)
logfx="/var/log/apache2/access.log";
;;
*)
logfx=$logf;
;;
esac
fi


# Main

apphdr; echo;

echo "Processing Apache Log: $logfx";

filex=$(isfile "$logfx")
if [ $filex -eq 2 ]; then
echo "The provided Apache Log File is actually a directory.";
exit 1;
elif [ $filex -ne 1 ]; then
echo "Apache Log File not found.";
exit 1;
fi

if [ -z "$ipsf" ]; then
tmpfile=true;
ipsf="/tmp/tcheckips.txt"
cat "$logfx" | awk '{print $1}' | sort -n | uniq -c | sort -rn | head --lines=$ipfetch | awk '{print $2}' > $ipsf
else
echo "Processing IP File: $ipsf"; echo
fi

filex=$(isfile "$ipsf")
if [ $filex -eq 2 ]; then
echo "The provided IP File is actually a directory.";
exit 1;
elif [ $filex -ne 1 ]; then
echo "IP File not found.";
exit 1;
fi

timepnow=$( date +"%s" )
echo; echo -n "Current Time: "; date "+%a %d %b %Y %H:%M:%S %Z (UTC%:z)"
echo;

aclogtt=$(wc -l $logfx | awk '{print $1}');

if [ $aclogtt -gt 0 ]; then

cnti=0;
while read ipx; do
if [ -n "$ipx" ] && [ "$(echo -n $ipx | cut -c1-1)" != "#" ]; then
(( ++cnti ))
echo "# $cnti : $ipx"; echo;

aclogip=$(grep -i $ipx $logfx | wc -l);

if [ $aclogip -gt 0 ]; then

timelog1=$( grep -i $ipx $logfx | head --lines=1 | sed 's#[^[]*[[]\([^]][^]]*\).*#\1#' | awk '{print $1}' )
timeplog1=$( date -d "$( echo $timelog1 | sed -e 's,/,-,g' -e 's,:, ,')" +"%s" )
echo -n "First seen  : "; date -d "$(echo $timelog1 | sed -e 's,/,-,g' -e 's,:, ,')" "+%a %d %b %Y %H:%M:%S" | tr -d '\n'
echo -n ' ('; hrtime $(( $timepnow-$timeplog1 )); echo ' ago)';

timelog2=$( grep -i $ipx $logfx | tail --lines=1 | sed 's#[^[]*[[]\([^]][^]]*\).*#\1#' | awk '{print $1}' )
timeplog2=$( date -d "$( echo $timelog2 | sed -e 's,/,-,g' -e 's,:, ,')" +"%s" )
echo -n "Last seen   : "; date -d "$(echo $timelog2 | sed -e 's,/,-,g' -e 's,:, ,')" "+%a %d %b %Y %H:%M:%S" | tr -d '\n'
echo -n ' ('; hrtime $(( $timepnow-$timeplog2 )); echo ' ago)';

timepspanlog=$(( $timeplog2-$timeplog1 ));
echo -n "Time span: "; hrtime $(( $timepspanlog )); echo

echo "Access count: $aclogip of $aclogtt ($(( $aclogip * 100 / $aclogtt ))%)"

if [ $timepspanlog -lt 60 ]; then
timepspanlog=60
fi

echo "Average accesses per minute: $(( $aclogip/(($timepspanlog)/60) ))";

echo; echo "Log Head for the IP:";
grep -i $ipx $logfx | head --lines=$nreshd

echo; echo "Log Tail for the IP:";
grep -i $ipx $logfx | tail --lines=$nrestl

else
echo; echo "No matches found in Apache Log File.";
fi

echo $elsep; echo;
fi
done < $ipsf

else
echo; echo "Apache Log File is empty.";
fi

if ( $tmpfile ) && ( $rmtmpfile ); then
rm $ipsf
fi
