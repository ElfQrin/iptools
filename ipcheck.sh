#!/bin/bash

# IPcheck
xver='r2021-07-19 fr2020-09-12';
# by Valerio Capello - http://labs.geody.com/ - License: GPL v3.0


# Config

iptfw=1; # IP Tables framework: 0: Standard, 1: nft (nftables, default and recommended since Debian Buster)
shwuserip=true; # Show User's IP
shwmachip=true; # Show Machine's IP and Default Gateway
nreshd=10; # Limit Results for Log Head
nrestl=$nreshd; # Limit Results for Log Tail
nrestop=20; # Limit Results for top results
sortfileswoquery=true; # Sort top accessed files excluding query strings in the URL
showerrreq=true; # Show top IPs and Files causing HTTP errors (for example: 404 Not Found)
shwlogstats=false; # Show Log Stats anyway, whether an IP is given or not
ipundott2dott=true; # If an undotted IP is passed, convert it to a dotted IP before to look for it into logs
whoisip=1; # Whois: 0: Disabled, 1: Selected Keywords, 2: Verbose (if enabled, it will connect to a whois service)
ipping=false; # Ping IP (setting it to true would expose your machine's IP and slow down the output)
iptrroute=false; # Trace Route to IP (setting it to true would expose your machine's IP and slow down the output)
rephstmn=400; # Min HTTP Status to report in detail (recommended: 400 )
rephstmx=599; # Max HTTP Status to report in detail (recommended: 599 )
enfileprintlist=false; # Show the content of the files in printlist
fileprintlist=('/etc/hosts' '/etc/hosts.allow' '/etc/hosts.deny'); # File Printlist. Example: fileprintlist=('/etc/hosts' '/etc/hosts.allow' '/etc/hosts.deny');
enfilewatchlist=true; # Show occurrences of the IP within the files in watchlist
filewatchlist=('/etc/hosts' '/etc/hosts.allow' '/etc/hosts.deny'); # File Watchlist. Example: filewatchlist=('/etc/hosts' '/etc/hosts.allow' '/etc/hosts.deny');
ipinloggedusersnow=true; # Show occurrences of the IP in currently logged users
ipinloggeduserslast=true; # Show occurrences of the IP in last logged users
shwloggedusersnow=false; # Show currently logged users
shwloggeduserslast=false; # Show last logged users
lastuserssince='yesterday'; # Consider last logged users since the specified time
ipinlogscurrent=true; # Show occurrences of the IP in all current logs
ipinlogsold=true; # Show occurrences of the IP in all old logs
logdir='/var/log/apache2/'; # Apache Logs Directory (only required to search the IP into all current and old logs)
logscurrentext='.log'; # Extension for current logs
logsoldext='.log.1'; # Extension for old logs
enipwatchlist=true; # Show occurrences of the IP in the watchlist
minoccenipwatchlist=1; # Minimum occurrences for an IP in the watchlist to report
ipwatchlist=(); # IP watchlist. Example: ipwatchlist=('192.0.2.1' '192.0.2.100' '192.0.2.101');
subnetcheck=true; # Count and List occurrences of IPs in the subnets of the IP into the given log (if this is set to False, no subnets will be checked even if enabled)
subnetchecken=(); subnetchecken[8]=false; subnetchecken[16]=true; subnetchecken[24]=true; # Count and List occurrences of IPs in the /8 /16 /24 subnets of the IP into the given log
subnetchecklist=(); subnetchecklist[8]=true; subnetchecklist[16]=true; subnetchecklist[24]=true; # Count and List occurrences of IPs in the /8 /16 /24 subnets of the IP into the given log
subnetchecklistlim=(); subnetchecklistlim[8]=256; subnetchecklistlim[16]=256; subnetchecklistlim[24]=256; # Set output limit for the list of IPs in the /8 /16 /24 subnets of the IP into the given log

f2benable=true; # Enable Fail2Ban checks (Seek IP in Fail2Ban banned IP lists)
f2bjaillist=true; # If Fail2Ban is enabled, list Fail2Ban Jails when checking webserver logs

ufwenable=true; # Enable UFW (Uncomplicated Firewall) checks (Seek IP in UFW status)
ufwlist=true; # If UFW is enabled, list ufw status (verbose)


# Functions

apphdr() {
echo "IPcheck";
echo "by Valerio Capello - labs.geody.com - License: GPL v3.0";
}

# Requires apphdr
apphelp() {
apphdr; echo;
echo -n 'IPTables Framework: ';
if [ $iptfw -eq 1 ]; then
echo 'nftables';
else
echo 'standard';
fi
echo;
echo "Usage:";
echo "ipcheck LOG IP              # Check IP activity within Apache LOG";
echo "ipcheck LOG                 # Check Apache LOG";
echo "ipcheck IP                  # Check IP";
echo "ipcheck --help              # Display this help";
echo "ipcheck --version           # Display version information";
echo "ipcheck --httpstatus CODE   # Return HTTP Status for given CODE";
echo "ipcheck --salute            # Display the IPs of the user and the machine";
echo "ipcheck --myip              # Display the IP of the user";
echo "ipcheck --yourip            # Display the IPs of the machine";
echo "ipcheck --listallapachelogs # List all Apache Logs";
if ( $f2benable ); then
echo "ipcheck --f2blist           # List all Fail2Ban Jails";
echo "ipcheck --f2bstatus         # Display status for all Fail2Ban Jails";
fi
if ( $ufwenable ); then
echo "ipcheck --ufwstatus         # Display UFW status";
fi
echo;
echo "Examples:";
echo "ipcheck /var/log/apache2/access.log 192.0.2.100";
echo "ipcheck /var/log/apache2/access.log";
echo "ipcheck 192.0.2.100";
echo "ipcheck --httpstatus 404";
}

userip() {
local tshilon=''; local tshilof='';
echo -n "Hello "; echo -ne "$tshilon"; echo -n "$(whoami)"; echo -ne "$tshilof";
if [ "$SSH_CONNECTION" ]; then
echo -n " ("; echo -ne "$tshilon"; echo -n "$( echo $SSH_CLIENT | awk '{print $1}' )"; echo -ne "$tshilof)";
fi
echo "."
}

machip() {
local tshilon=''; local tshilof='';
echo -n "This is "; echo -ne "$tshilon"; echo -n "$( hostname )"; echo -ne "$tshilof";
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
}

# Requires userip, machip
salute() {
userip;
machip;
}

printhttplogip() {
local ipx="$1";
local logfx="$2";
local httpstcod="$3";
local nrestop="$4";
local stverb="";

if [ -n "$httpstcod" ]; then local stverb="($(httpstatcod2msg $httpstcod)) "; fi
echo; echo "Top requests by the IP causing a $httpstcod ${stverb}error:";
grep -i $ipx $logfx | grep " $httpstcod " | awk -F\" '$9=$httpstcod{print $2}' | sort | uniq -c | sort -rg | head --lines=$nrestop # | nl -n rn -s '. ' # Requests
# grep -i $ipx $logfx | grep " $httpstcod " | awk -F\" '$9=$httpstcod{print $9" "$2}' | awk {'print $7'} | sort | uniq -c | sort -rg | head --lines=$nrestop # | nl -n rn -s '. ' # Files
}

printhttplog() {
local logfx="$1";
local httpstcod="$2";
local nrestop="$3";
local stverb="";

if [ -n "$httpstcod" ]; then local stverb="($(httpstatcod2msg $httpstcod)) "; fi
echo; echo "Top requests causing a $httpstcod ${stverb}error:";
grep " $httpstcod " $logfx | awk -F\" '$9=$httpstcod{print $2}' | sort | uniq -c | sort -rg | head --lines=$nrestop # | nl -n rn -s '. ' # Requests
# grep " $httpstcod " $logfx | awk -F\" '$9=$httpstcod{print $9" "$2}' | awk {'print $7'} | sort | uniq -c | sort -rg | head --lines=$nrestop # | nl -n rn -s '. ' # Files
echo; echo "Top IPs causing a $httpstcod ${stverb}error:";
grep " $httpstcod " $logfx | awk '$9=$httpstcod{print $1}' | sort | uniq -c | sort -rg | head --lines=$nrestop # | nl -n rn -s '. '
}


isipv4dot() {
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

dec2bin() {
local n="$1"
local zf="$2"
if [ -z "$zf" ] || [ $zf -le 0 ]; then
local zf=0
fi
local bit=""
while [ "$n" -gt 0 ]; do
local bit="$(( n&1 ))$bit";
: $(( n >>= 1 ))
done
if [ $zf -le 0 ]; then
printf "%s" "$bit"
else
printf "%0${zf}d" "$bit"
fi
}

# Requires dec2bin
ipdot2bin() {
local zf=8;
if [ "$#" -le 0 ]; then return 1; fi
local a b c d ip=$@
IFS=. read -r a b c d <<< "$ip"
echo -n "$(dec2bin $a $zf).$(dec2bin $b $zf).$(dec2bin $c $zf).$(dec2bin $d $zf)";
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

# Requires isip (isipv4dot, isipv4und, isipv6), isipknown
ipinfo() {
local ipx="$1";

echo "Checking IP: $ipx";
# echo

local ipv=$(isip "$ipx")

echo -n "Format: ";
case $ipv in
4)
echo 'Valid IPv4 dotted';
;;
5)
echo 'Valid IPv4 undotted';
;;
6)
echo 'Valid IPv6';
;;
*)
echo 'NOT a valid IP';
;;
esac

if [ $ipv -eq 4 ] || [ $ipv -eq 5 ]; then
if [ $ipv -eq 4 ]; then
ipdott="$ipx";
ipundott="$(ipdot2undot $ipx)";
echo "Undotted IP: $ipundott";
fi
if [ $ipv -eq 5 ]; then
ipundott="$ipx";
ipdott="$(ipundot2dot $ipx)";
echo "Dotted IP: $ipdott";
fi
echo -n "Hex: "; printf '%02X' ${ipdott//./ } | sed 's/.\{2\}/&\./g' | awk '{sub(/\.$/, "")};1'
echo -n "Bin: "; ipdot2bin $ipdott ; echo

if [ $ipundott -eq 0 ]; then
echo 'Scope: Local (Private Network)'; echo 'Class: A'; echo 'Function: Routing ("All Other Network Addresses" in routing tables)';
elif [ $ipundott -eq 2130706433 ]; then
echo 'Scope: Local (Private Network)'; echo 'Class: A'; echo 'Function: Localhost';
elif [ $ipundott -ge 2130706432 ] && [ $ipundott -le 2147483647 ]; then
echo 'Scope: Local (Private Network)'; echo 'Class: A'; echo 'Function: Loopback';
elif [ $ipundott -ge 2851995648 ] && [ $ipundott -le 2852061183 ]; then
echo 'Scope: Local (Private Network)'; echo 'Class: B'; echo 'Function: Autoconfiguration (APIPA, typically because of DHCP failure)';
elif [ $ipundott -ge 3221225984 ] && [ $ipundott -le 3221226239 ]; then
echo 'Class: C'; echo 'Function: Example';
elif [ $ipundott -ge 3758096384 ] && [ $ipundott -le 4026531839 ]; then
echo 'Class: D'; echo -n 'Function: Multicast';
if [ $ipundott -ge 3758096384 ] && [ $ipundott -le 3758096639 ]; then
echo ' / Local subnetwork / Not Routable';
elif [ $ipundott -ge 3758096640 ] && [ $ipundott -le 3758096895 ]; then
echo ' / Internetwork control / Routable';
elif [ $ipundott -ge 3758096896 ] && [ $ipundott -le 3758161919 ]; then
echo ' / AD-HOC block 1 / Routable';
elif [ $ipundott -ge 3758161920 ] && [ $ipundott -le 3758424063 ]; then
echo ' / AD-HOC block 2 / Routable';
elif [ $ipundott -ge 3758424064 ] && [ $ipundott -le 3909091327 ]; then
echo ' / Source-specific multicast / Routable';
elif [ $ipundott -ge 3909091328 ] && [ $ipundott -le 3925606399 ]; then
echo ' / GLOP addressing / Routable';
elif [ $ipundott -ge 3925606400 ] && [ $ipundott -le 3925868543 ]; then
echo ' / AD-HOC block 3 / Routable';
elif [ $ipundott -ge 3925868544 ] && [ $ipundott -le 3942645759 ]; then
echo ' / Unicast-prefix-based / Routable';
elif [ $ipundott -ge 3942645760 ] && [ $ipundott -le 4026531839 ]; then
echo ' / Administratively scoped / Routable';
else
echo; # Can't happen
fi
elif [ $ipundott -eq 4294967295 ]; then
echo 'Class: E'; echo 'Function: Broadcast';
elif [ $ipundott -ge 167772160 ] && [ $ipundott -le 184549375 ]; then
echo 'Scope: Local (Private Network)'; echo 'Class: A';
elif [ $ipundott -ge 2886729728 ] && [ $ipundott -le 2887778303 ]; then
echo 'Scope: Local (Private Network)'; echo 'Class: B';
elif [ $ipundott -ge 3232235520 ] && [ $ipundott -le 3232301055 ]; then
echo 'Scope: Local (Private Network)'; echo 'Class: C';
elif [ $ipundott -ge 0 ] && [ $ipundott -le 2130706431 ]; then
echo 'Scope: Global (Public Network)'; echo 'Class: A';
elif [ $ipundott -ge 2147483648 ] && [ $ipundott -le 3221225471 ]; then
echo 'Scope: Global (Public Network)'; echo 'Class: B';
elif [ $ipundott -ge 3221225472 ] && [ $ipundott -le 3758096383 ]; then
echo 'Scope: Global (Public Network)'; echo 'Class: C';
elif [ $ipundott -ge 3758096384 ] && [ $ipundott -le 4026531839 ]; then
echo 'Scope: Global (Public Network)'; echo 'Class: D';
elif [ $ipundott -ge 4026531840 ] && [ $ipundott -le 4294967295 ]; then
echo 'Scope: Global (Public Network)'; echo 'Class: E';
fi

if [ $ipv -eq 5 ] && ( $ipundott2dott ); then
ipx="$(ipundot2dot $ipx)"; ipv=4;
fi

fi

echo;

isipknown $ipx
}

isipknown() {
local ipx="$1";
if [[ "$ipx" == "$( echo -n $SSH_CLIENT | awk '{print $1}' | tr -d '\n' )" ]]; then
echo 'This IP is YOUR IP.'; echo;
elif [[ "$ipx" == "$( hostname -i | tr -d '\n' )" ]]; then
echo "This IP is this machine's local IP."; echo;
elif [[ "$ipx" == "$( ifconfig | sed -En 's/127.0.0.1//;s/.*inet (addr:)?(([0-9]*\.){3}[0-9]*).*/\2/p' | tr -d '\n' )" ]]; then
echo "This IP is this machine's global IP."; echo;
elif [[ "$ipx" == "$( route -n | grep 'UG[ \t]' | awk '{print $2}' | tr -d '\n' )" ]]; then
echo "This IP is this machine's default gateway."; echo;
fi
}

f2blist() {
echo "Fail2Ban:"

local iptcmd="iptables${iptfwx}"; local ipttxt='IPTables';
ipttotrulf2b=$( $iptcmd -S | grep "\-A f2b\-" | wc -l ); # ipttotrulf2b=$((ipttotrulf2b-2));
if [ $ipttotrulf2b -gt 0 ]; then
echo "$ipttotrulf2b Fail2Ban rules found in $ipttxt.";
else
echo "No Fail2Ban rules found in $ipttxt.";
fi

local iptcmd="ip6tables${iptfwx}"; local ipttxt='IP6Tables';
ipttotrulf2b=$( $iptcmd -S | grep "\-A f2b\-" | wc -l ); # ipttotrulf2b=$((ipttotrulf2b-2));
if [ $ipttotrulf2b -gt 0 ]; then
echo "$ipttotrulf2b Fail2Ban rules found in $ipttxt.";
else
echo "No Fail2Ban rules found in $ipttxt.";
fi

if [ -n "$istheref2b" ]; then
if ( $f2bjaillist ); then
echo; echo "Fail2Ban Jails:"
jails=$(fail2ban-client status | grep -m 1 'Jail list' | sed -E 's/^[^:]+:[ \t]+//' | sed 's/,//g')
jailsnum=0; jailsthislognum=0;
for jail in $jails
do
jailsnum=$((jailsnum+1));
echo -n $jail
jailstatus=$(fail2ban-client status $jail)
filelist=$( echo -n "$jailstatus" | grep -m 1 'File list:' | awk {'print $5'} );
if [[ "$filelist" == "$logfx" ]]; then
jailsthislognum=$((jailsthislognum+1));
echo " for this Log";
else
echo " for $filelist";
fi
done
else
jailsnum=$( fail2ban-client status | grep -m 1 'Number of jail:' | awk {'print $5'} );
fi
if [ $jailsnum -eq 1 ]; then
echo "$jailsnum Fail2Ban Jail found.";
elif [ $jailsnum -gt 1 ]; then
echo "$jailsnum Fail2Ban Jails found.";
else
echo "No Fail2Ban Jails found.";
fi
if [ -n "$logfx" ]; then
if [ $jailsthislognum -eq 1 ]; then
echo "$jailsthislognum Fail2Ban Jail for this Log found.";
elif [ $jailsthislognum -gt 1 ]; then
echo "$jailsthislognum Fail2Ban Jails for this Log found.";
else
echo "No Fail2Ban Jails for this Log found.";
fi
fi
else
echo "Fail2Ban is not present.";
fi
}

ufwstatus() {
echo "UFW (Uncomplicated Firewall):"

ipttotrulufwusrinp=$( iptables -L ufw-user-input -n | wc -l ); ipttotrulufwusrinp=$((ipttotrulufwusrinp-2));
if [ $ipttotrulufwusrinp -gt 0 ]; then
if [ $ipttotrulufwusrinp -eq 1 ]; then
echo "$ipttotrulufwusrinp UFW user input rule found in IPTables.";
else
echo "$ipttotrulufwusrinp UFW user input rules found in IPTables.";
fi
else
echo "No UFW user input rules in IPTables.";
fi

if [ -n "$isthereufw" ]; then
if ( $isufwon ); then
if ( $ufwlist ); then
ufw version ; ufw status verbose | head --lines=4 ; ufw status numbered | grep -v -m 1 'Status' ;
else
echo "UFW is present and enabled.";
ufw version ;
fi
else
echo "UFW is present but disabled.";
ufw version ; ufw status ;
fi
else
echo "UFW is not present.";
fi
}

httpstatcod2msg() {
# local statuscod="$1"
local statuscat=""
local statusmsg=""
case ${1:0:1} in
1) local statuscat="Informational"
case $1 in
100) local statusmsg="Continue" ;;
101) local statusmsg="Switching Protocols" ;;
102) local statusmsg="Processing" ;;
103) local statusmsg="Early Hints" ;;
*)   local statusmsg="Unknown" ;;
esac
;;
2) local statuscat="Success"
case $1 in
200) local statusmsg="OK" ;;
201) local statusmsg="Created" ;;
202) local statusmsg="Accepted" ;;
203) local statusmsg="Non-Authoritative Information" ;;
204) local statusmsg="No Content" ;;
205) local statusmsg="Reset Content" ;;
206) local statusmsg="Partial Content" ;;
207) local statusmsg="Multi-Status" ;;
208) local statusmsg="Already Reported" ;;
226) local statusmsg="IM Used" ;;
*)   local statusmsg="Unknown" ;;
esac
;;
3) local statuscat="Redirection"
case $1 in
300) local statusmsg="Multiple Choices" ;;
301) local statusmsg="Moved Permanently" ;;
302) local statusmsg="Found" ;;
303) local statusmsg="See Other" ;;
304) local statusmsg="Not Modified" ;;
305) local statusmsg="Use Proxy" ;;
306) local statusmsg="Switch Proxy" ;;
307) local statusmsg="Temporary Redirect" ;;
308) local statusmsg="Permanent Redirect" ;;
*)   local statusmsg="Unknown" ;;
esac
;;
4) local statuscat="Client Error"
case $1 in
400) local statusmsg="Bad Request" ;;
401) local statusmsg="Unauthorized" ;;
402) local statusmsg="Payment Required" ;;
403) local statusmsg="Forbidden" ;;
404) local statusmsg="Not Found" ;;
405) local statusmsg="Method Not Allowed" ;;
406) local statusmsg="Not Acceptable" ;;
407) local statusmsg="Proxy Authentication Required" ;;
408) local statusmsg="Request Timeout" ;;
409) local statusmsg="Conflict" ;;
410) local statusmsg="Gone" ;;
411) local statusmsg="Length Required" ;;
412) local statusmsg="Precondition Failed" ;;
413) local statusmsg="Request Entity Too Large" ;;
414) local statusmsg="Request-URI Too Long" ;;
415) local statusmsg="Unsupported Media Type" ;;
416) local statusmsg="Requested Range Not Satisfiable" ;;
417) local statusmsg="Expectation Failed" ;;
418) local statusmsg="I'm a teapot" ;;
421) local statusmsg="Misdirected Request" ;;
422) local statusmsg="Unprocessable Entity" ;;
423) local statusmsg="Locked" ;;
424) local statusmsg="Failed Dependency" ;;
425) local statusmsg="Too Early" ;;
426) local statusmsg="Upgrade Required" ;;
428) local statusmsg="Precondition Required" ;;
429) local statusmsg="Too Many Requests" ;;
431) local statusmsg="Request Header Fields Too Large" ;;
451) local statusmsg="Unavailable For Legal Reasons" ;;
*)   local statusmsg="Unknown" ;;
esac
;;
5) local statuscat="Server Error"
case $1 in
500) local statusmsg="Internal Server Error" ;;
501) local statusmsg="Not Implemented" ;;
502) local statusmsg="Bad Gateway" ;;
503) local statusmsg="Service Unavailable" ;;
504) local statusmsg="Gateway Timeout" ;;
505) local statusmsg="HTTP Version Not Supported" ;;
506) local statusmsg="Variant Also Negotiates" ;;
507) local statusmsg="Insufficient Storage" ;;
508) local statusmsg="Loop Detected" ;;
510) local statusmsg="Not Extended" ;;
511) local statusmsg="Network Authentication Required" ;;
*)   local statusmsg="Unknown" ;;
esac
;;
*) local statuscat="Other"
local statusmsg="Unknown"
;;
esac
echo -n "$statuscat: $statusmsg"
}


# Get Parameters

# Add a trailing slash to log's path if missing
if [ ${#logdir} -gt 0 ]; then
if [[ "${logdir: -1}" != '/' ]]; then logdir="${logdir}/"; fi
fi

istheref2b=$( type -t fail2ban-client );

isthereufw=$( type -t ufw );
if [ -n "$isthereufw" ]; then
ufwstatus=$( ufw status | head --lines=1 | tr -d '\n' );
if [[ "$ufwstatus" == 'Status: active' ]]; then isufwon=true; else isufwon=false; fi
else
isufwon=false;
fi

istherenetstat=$( type -t netstat );

action=$( echo "$1" | tr '[:upper:]' '[:lower:]' );

case $action in
'--help')
apphelp
exit 0;
;;
'--ver'|'--version')
apphdr; echo
echo "Version: $xver";
exit 0;
;;
'--httpstatus')
apphdr; echo
httpstcod=$2;
if [ $# -ge 2 ]; then
if [[ $httpstcod =~ ^[0-9]+$ ]] && [ $httpstcod -ge 100 ] && [ $httpstcod -lt 600 ]; then
stverb="($(httpstatcod2msg $httpstcod))";
if [ -n "$stverb" ]; then
echo "HTTP Status: $httpstcod $stverb"
else
echo "$httpstcod is not a valid HTTP status code";
fi
else
echo "$httpstcod is not a valid HTTP status code";
fi
else
echo 'Missing HTTP status code';
exit 1;
fi
exit 0;
;;
'--salute'|'--ourip')
apphdr; echo
salute;
exit 0;
;;
'--myip'|'--userip')
apphdr; echo
userip;
exit 0;
;;
'--yourip'|'--machip'|'--machineip')
apphdr; echo
machip;
exit 0;
;;
'--listallapachelogs'|'--listalllogs')
if [ -n "$logdir" ]; then
apphdr; echo
echo "All Apache Logs:"
filex=$(isfile "$logdir")
case $filex in
1)
echo "$logdir is a file, not a directory." ;;
2)
echo "Current Apache Logs:"
ls -aF $logdir*$logscurrentext
totlogapacur=$( ls -aF $logdir*$logscurrentext | wc -l );
echo "Total Current Apache Logs: $totlogapacur";
echo "Old Apache Logs:"
ls -aF $logdir*$logsoldext
totlogapaold=$( ls -aF $logdir*$logscurrentext | wc -l );
echo "Total Old Apache Logs: $totlogapaold";
echo "Total Apache Logs: $((totlogapacur+totlogapaold))";
;;
*) echo "$logdir not found." ;;
esac
else
echo "Log Path not provided (empty).";
fi
exit 0;
;;
'--f2blist')
apphdr; echo
if ( ! $f2benable ); then echo "Fail2Ban is disabled in IPcheck configuration."; exit 1; fi
f2blist;
exit 0;
;;
'--f2bstatus'|'--f2bstatusall')
apphdr; echo
if ( ! $f2benable ); then echo "Fail2Ban is disabled in IPcheck configuration."; exit 1; fi
if [ -n "$istheref2b" ]; then
echo "fail2ban-client status --all"; echo;
fail2ban-client --version
echo
jails=$(fail2ban-client status | grep "Jail list" | sed -E 's/^[^:]+:[ \t]+//' | sed 's/,//g')
jailsnum=0;
for jail in $jails
do
jailsnum=$((jailsnum+1));
fail2ban-client status $jail
echo
done
if [ $jailsnum -eq 1 ]; then
echo "$jailsnum Fail2Ban Jail found.";
elif [ $jailsnum -gt 1 ]; then
echo "$jailsnum Fail2Ban Jails found.";
else
echo "No Fail2Ban Jails found.";
fi
echo
# f2bdbsize=$( du -bs '/var/lib/fail2ban/' | awk '{print $1}' | tr -d '\n' );
f2bdbsize=$( du -bsc /var/lib/fail2ban/* | tail --lines=1 | awk '{print $1}' | tr -d '\n' );
f2blgsize=$( du -bsc /var/log/fail2ban.* | tail --lines=1 | awk '{print $1}' | tr -d '\n' );
f2btotsize=( $f2bdbsize + $f2blgsize );
echo "Fail2Ban Database size is $f2bdbsize bytes.";
echo "Fail2Ban Logs size is $f2blgsize bytes.";
echo "Fail2Ban total data size is $f2btotsize bytes.";
exit 1;
else
echo "Fail2Ban is not present.";
exit 1;
fi
;;
'--ufwstatus'|'--ufwlist')
apphdr; echo
if ( ! $ufwenable ); then echo "UFW is disabled in IPcheck configuration."; exit 1; fi
ufw version ; ufw status verbose | head --lines=4 ; ufw status numbered | grep -v 'Status' ;
exit 0;
;;
esac

if [ $# -eq 1 ]; then
ipv=$(isip "$1")
if [ $ipv -eq 4 ] || [ $ipv -eq 5 ] || [ $ipv -eq 6 ]; then
logf=""; # Apache Log File
ipx=$1; # Target IP
else
logf=$1; # Apache Log File
ipx=""; # Target IP
fi
elif [ $# -eq 2 ]; then
logf=$1; # Apache Log File
ipx=$2; # Target IP
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

if [ $iptfw -eq 1 ]; then
iptfwx='-nft';
else
iptfwx='';
fi

if ( $shwuserip ) || ( $shwmachip ); then
if ( $shwuserip ); then
userip;
fi
if ( $shwmachip ); then
machip;
fi
echo;
fi

if [ $( fail2ban-client status | wc -l ) -ge 3 ]; then
isf2bon=true;
else
isf2bon=false;
fi

if [ -n "$ipx" ]; then

ipv=$(isip "$ipx")

ipinfo $ipx

if [ $ipv -eq 6 ]; then
iptcmd="ip6tables${iptfwx}"; ipttxt='IP6Tables';
else
iptcmd="iptables${iptfwx}"; ipttxt='IPTables';
fi

if [ $ipv -eq 5 ]; then
ipx="$(ipundot2dot $ipx)"; ipv=4;
fi

echo "Host: "
host $ipx 

if [ $whoisip -ge 1 ]; then
echo; echo "Who is:"
case $whoisip in
1) whois $ipx | grep -iE "^\s*netrange:|^\s*netblock:|^\s*cidr:|^\s*inetnum:|^\s*route:|^\s*\s*netname:|^\s*orgname:|^\s*organisation:|^\s*organization:|^\s*org-name:|^\s*custname:|^\s*owner:|^\s*country:|^\s*orgabuseemail:|^\s*e-mail:|^\s*descr:|^\s*remarks:" ;;
2) whois $ipx ;;
esac
fi

if ( $ipping ); then
echo; ping -c 3 $ipx
fi

if ( $iptrroute ); then
if ( ! $ipping ); then echo; fi
traceroute $ipx
fi

echo; echo "IP in $ipttxt:"
ipxintablesn=$($iptcmd -L INPUT -n --line-numbers | grep $ipx | wc -l );
if [ $ipxintablesn -eq 0 ]; then
echo "No matches found for the IP in $ipttxt INPUT rules.";
else
$iptcmd -L INPUT -n --line-numbers | grep $ipx
fi

if ( $f2benable ); then
echo; echo "IP in Fail2Ban:"
if ( $isf2bon ); then
ctipj=0;
jails=$(fail2ban-client status | grep -m 1 'Jail list' | sed -E 's/^[^:]+:[ \t]+//' | sed 's/,//g')
for jail in $jails
do
jailstatus=$(fail2ban-client status $jail)
isipin=$(echo -n "$jailstatus" | grep $ipx)
if [ -n "$isipin" ]; then
echo -n "IP found in Jail $jail";
filelist=$( echo -n "$jailstatus" | grep -m 1 'File list:' | awk {'print $5'} );
echo " for $filelist";
ctipj=$((ctipj+1));
fi
done
if [ $ctipj -eq 0 ]; then
echo "No matches found for the IP in Fail2Ban Jails ban lists.";
elif [ $ctipj -eq 1 ]; then
echo "IP found in $ctipj Fail2Ban Jails ban list.";
else
echo "IP found in $ctipj Fail2Ban Jails ban lists.";
fi
else
echo 'No Fail2Ban entries found in IPTables.';
fi
fi

if ( $ufwenable ); then
echo; echo "IP in UFW (Uncomplicated Firewall):"
if [ -n "$isthereufw" ]; then
if ( $isufwon ); then
ufw version ; ufw status verbose | head --lines=4 ; ufw status | grep $ipx ;
ctipufw=$( ufw status | grep $ipx | wc -l )
if [ $ctipufw -eq 0 ]; then
echo "No matches found for the IP in UFW rules.";
elif [ $ctipufw -eq 1 ]; then
echo "IP found in $ctipufw UFW rule.";
else
echo "IP found in $ctipufw UFW rules.";
fi
else
echo "UFW is present but disabled.";
ufw version ; ufw status ;
fi
else
echo "UFW is not present.";
fi
fi

if ( $ipinloggedusersnow ) || ( $ipinloggeduserslast ); then
echo; echo "IP in Logged Users:"

if ( $ipinloggedusersnow ); then
echo "IP in currently logged users:"
ipocc=$( who -s --ips | grep $ipx | awk '!array[$5]++' | wc -l );
ipocctot=$( who -s --ips | grep $ipx | wc -l );
if [ $ipocc -gt 0 ]; then
echo "$( who -s --ips | grep $ipx)";
if [ $ipocc -eq 1 ]; then
echo "$ipocc occurrence ($ipocctot total) of the IP found in currently logged users.";
else
echo "$ipocc occurrences ($ipocctot total) of the IP found in currently logged users.";
fi
else
echo "No matches found for the IP in currently logged users.";
fi
fi

if ( $ipinloggeduserslast ) && [ -n "$lastuserssince" ]; then
echo "IP in last logged users (since $lastuserssince):"
ipocc=$( last -i --since $lastuserssince | grep $ipx | awk '!array[$3]++' | wc -l );
ipocctot=$( last -i --since $lastuserssince | grep $ipx | wc -l );
if [ $ipocc -gt 0 ]; then
echo "$( last -i --since $lastuserssince | grep $ipx )";
if [ $ipocc -eq 1 ]; then
echo "$ipocc occurrence ($ipocctot total) of the IP found in last logged users.";
else
echo "$ipocc occurrences ($ipocctot total) of the IP found in last logged users.";
fi
else
echo "No matches found for the IP in last logged users.";
fi
fi

fi

if ( $ipinlogscurrent ) || ( $ipinlogsold ); then

if [ -n "$logdir" ]; then
echo; echo "IP in all Apache Logs:"
filex=$(isfile "$logdir")
case $filex in
1)
echo "$logdir is a file, not a directory." ;;
2)
if ( $ipinlogscurrent ); then
echo "IP in current Apache Logs:"
ipinallogs="$( grep -r -l $ipx $logdir*$logscurrentext )";
if [ ${#ipinallogs} -gt 0 ]; then
# echo $ipinallogs # File names in a single line
echo "$ipinallogs" # File names in multiple lines
else
echo 'Not Found.';
fi
fi
if ( $ipinlogsold ); then
echo "IP in old Apache Logs:"
ipinallogs="$( grep -r -l $ipx $logdir*$logsoldext )";
if [ ${#ipinallogs} -gt 0 ]; then
# echo $ipinallogs # File names in a single line
echo "$ipinallogs" # File names in multiple lines
else
echo 'Not Found.';
fi
fi
;;
*) echo "$logdir not found." ;;
esac
else
echo "Log Path not provided (empty).";
fi

fi

if ( $enfilewatchlist ); then

echo; echo "IP within files in Watchlist:"

if [ ${#filewatchlist[@]} -gt 0 ]; then

for filei in "${filewatchlist[@]}"
do
if [ -n "$filei" ]; then
fileish="$( basename $filei )";
echo "IP in $filei:"
filex=$(isfile "$filei")
case $filex in
1)
ipocc=$( grep $ipx $filei | grep -v '^#' | wc -l );
if [ $ipocc -gt 0 ]; then
echo $( grep $ipx $filei | grep -v '^#' );
if [ $ipocc -eq 1 ]; then
echo "$ipocc occurrence of the IP found in ${fileish}";
else
echo "$ipocc occurrences of the IP found in ${fileish}";
fi
else
echo "No matches found for the IP in ${fileish}";
fi
;;
2) echo "$filei is a directory, not a file." ;;
*) echo "$filei not found." ;;
esac
fi
done
else
echo "The File Watchlist is empty."
fi

fi

if ( $enipwatchlist ); then
echo; echo "IP in Watchlist:"
if [ ${#ipwatchlist[@]} -gt 0 ]; then
if [[ " ${ipwatchlist[*]} " == *" ${ipx} "* ]]; then echo "The IP was FOUND in the Watchlist."; else echo "No matches found for the IP in the Watchlist."; fi
else
echo "The IP Watchlist is empty."
fi
fi

if [ -n "$istherenetstat" ]; then
echo; echo "Current IP activity:"
ipconnct=$( netstat -anp | grep $ipx | wc -l )
if [ $ipconnct -gt 0 ]; then
netstat -anp | grep $ipx | head --lines=$nrestop # | nl -n rn -s '. '
if [ $ipconnct -eq 1 ]; then
echo "$ipconnct established connection.";
else
echo -n "$ipconnct established connections.";
if [ $ipconnct -gt $nrestop ]; then echo " (only $nrestop topmost established connections are listed)."; else echo; fi
fi
else
echo 'No current activity for this IP.'
fi
fi


if [ -n "$logfx" ]; then

echo; echo "IP in Apache Log File: $logfx";

timepnow=$( date +"%s" )
echo; echo -n "Current Time: "; date "+%a %d %b %Y %H:%M:%S %Z (UTC%:z)"

filex=$(isfile "$logfx")

if [ $filex -eq 1 ]; then

aclogtt=$(wc -l $logfx | awk '{print $1}');

if [ $aclogtt -gt 0 ]; then

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


if ( $subnetcheck ) && [ $ipv -eq 4 ]; then
echo; echo 'Subnets for the IP in Log:';
ipp=();
IFS=. ; read ipp[1] ipp[2] ipp[3] ipp[4] <<< "$ipx"; IFS=$' \t\n';
snma=('24' '16' '8');

for snm in "${snma[@]}"
do
if ( ${subnetchecken[$snm]} ); then
echo -n "Subnet /${snm}";
case $snm in
24)
snpp="${ipp[1]}\.${ipp[2]}\.${ipp[3]}\.";
echo " (${ipp[1]}.${ipp[2]}.${ipp[3]}.x):";
;;
16)
snpp="${ipp[1]}\.${ipp[2]}\.";
echo " (${ipp[1]}.${ipp[2]}.x.x):";
;;
8)
snpp="${ipp[1]}\.";
echo " (${ipp[1]}.x.x.x):";
;;
*) echo ':'; echo "Subnet /$snm not supported." ;;
esac

snpct=$( grep ^${snpp} $logfx | awk '{print $1}' | sort -n | uniq -c | wc -l );

if [ $snpct -eq 1 ]; then
echo -n "$snpct occurrence found (only the given IP: $ipx )";
else
echo -n "$snpct occurrences found";
fi

if [ $snpct -gt 1 ]; then
echo ':';
else
echo '.';
fi

if  ( $subnetchecklist ) && [ $snpct -gt 1 ]; then
if [ ${subnetchecklistlim[$snm]} -gt 0 ] && [ $snpct -gt ${subnetchecklistlim[$snm]} ]; then
grep ^$snpp $logfx | awk '{print $1}' | sort -n | uniq -c | sort -rn | head --lines=$subnetchecklistlim[$snm] ;
echo " [ and $(( $snpct - $subnetchecklistlim[$snm] )) more ]";
else
grep ^$snpp $logfx | awk '{print $1}' | sort -n | uniq -c | sort -rn ;
fi
fi

fi
done
fi

echo; echo "Log Head for the IP:";
grep -i $ipx $logfx | head --lines=$nreshd

echo; echo "Log Tail for the IP:";
grep -i $ipx $logfx | tail --lines=$nrestl

if ( $sortfileswoquery ); then
echo; echo "Top accessed files by the IP:"
grep -i $ipx $logfx | awk -F\" '{print $2}' | awk '{print $2}' | sed '/^$/d' | sed 's/\?.*//g' | sort | uniq -c | sort -rn | head --lines=$nrestop # | nl -n rn -s '. '
else
echo; echo "Top accessed files by the IP (including query strings):"
grep -i $ipx $logfx | awk -F\" '{print $2}' | awk '{print $2}' | sort | uniq -c | sort -g | tail --lines=$nrestop | tac # | nl -n rn -s '. '
fi

echo; echo "Top HTTP response status code for the IP:"
IFS=$'\n' read -r -d '' -a httpst < <( ( grep -i $ipx $logfx | sed 's/\\"//g' | sed 's/ - ".*" \[/ - - \[/g' | cut -d'"' -f3 | cut -d' ' -f2 | sort | uniq -c | sort -rg ) && printf '\0' )

if [ $# -ge 1 ]; then
ct=0; cterr=0;
for httpstel in "${httpst[@]}"; do
httpstcod="$( echo -n $httpstel | awk {'print $2'} )";
if [[ $httpstcod =~ ^[0-9]+$ ]]; then
ct=$((ct+1));
if [ $ct -eq 1 ]; then el1=$( echo -n "$httpstel" | awk {'print $1'} | tr -d '\n' ); lel1=${#el1}; fi
printf "%03s" "${ct}"; echo -n '. ';
printf "%0${lel1}s" "$( echo -n $httpstel | awk {'print $1'} | tr -d '\n' )"
httpstocc="$( echo -n $httpstel | awk {'print $1'} )"
echo -n ' ('
printf "%03s" "$(( $httpstocc * 100 / $aclogip ))"
echo -n '%) '
echo -n "$httpstel" | awk {'print $2'} | tr -d '\n'
echo " ($(httpstatcod2msg $( echo -n $httpstel | awk {'print $2'} )))"
else
# echo "ERROR: $httpstel"
cterr=$((cterr+1)); # Shouldn't happen
fi
done
if ( $showerrreq ); then
for httpstel in "${httpst[@]}"; do
httpstcod="$( echo -n $httpstel | awk {'print $2'} )";
if [[ $httpstcod =~ ^[0-9]+$ ]] && [ $httpstcod -ge $rephstmn ] && [ $httpstcod -le $rephstmx ]; then
echo "$( printhttplogip $ipx $logfx $httpstcod $nrestop )";
fi
done
fi
else
echo 'No requests found by the IP';
fi

# Shouldn't happen
if [ $cterr -gt 0 ]; then
echo
if [ $cterr -eq 1 ]; then
echo "The IP caused $cterr malformed field in the Apache Log File.";
else
echo "The IP caused $cterr malformed fields in the Apache Log File.";
fi
fi

else

echo; echo "No matches found in Apache Log File.";

fi

else

echo; echo "Apache Log File is empty.";

fi

elif [ $filex -eq 2 ]; then
echo; echo "The provided Apache Log File is actually a directory."
else
echo; echo "Apache Log File not found."
fi

fi

fi

if [ -n "$logfx" ] && ( [ -z "$ipx" ] || $shwlogstats ); then

iptcmd="iptables${iptfwx}"; ipttxt='IPTables';
echo "$ipttxt:"
ipttotrulinp=$( $iptcmd -L INPUT -n | wc -l ); ipttotrulinp=$((ipttotrulinp-2));
if [ $ipttotrulinp -gt 0 ]; then
if [ $ipttotrulinp -eq 1 ]; then
echo "$ipttotrulinp INPUT rule found in $ipttxt.";
else
echo "$ipttotrulinp INPUT rules found in $ipttxt.";
fi
else
echo "No INPUT rules found in $ipttxt.";
fi

iptcmd="ip6tables${iptfwx}"; ipttxt='IP6Tables';
echo "$ipttxt:"
ipttotrulinp=$( $iptcmd -L INPUT -n | wc -l ); ipttotrulinp=$((ipttotrulinp-2));
if [ $ipttotrulinp -gt 0 ]; then
if [ $ipttotrulinp -eq 1 ]; then
echo "$ipttotrulinp INPUT rule found in $ipttxt.";
else
echo "$ipttotrulinp INPUT rules found in $ipttxt.";
fi
else
echo "No INPUT rules found in $ipttxt.";
fi

if ( $f2benable ); then
echo; f2blist;
fi

if ( $ufwenable ); then
echo; ufwstatus;
fi

if ( $shwloggedusersnow ) || ( $shwloggeduserslast ); then

echo; echo "Logged Users:"

if ( $shwloggedusersnow ); then
echo "Currently logged users:"
who -s --ips
fi

if ( $shwloggeduserslast ) && [ -n "$lastuserssince" ]; then
echo "Last logged users (since $lastuserssince):"
last -i --since yesterday | head --lines=-2
fi

fi

if ( $enfileprintlist ); then

echo; echo "Showing content of Files in Printlist:"

if [ ${#fileprintlist[@]} -gt 0 ]; then

for filei in "${fileprintlist[@]}"
do
if [ -n "$filei" ]; then
# fileish="$( basename $filei )";
echo "Showing $filei:"
filex=$(isfile "$filei")
case $filex in
1)
cat "$filei"; # | more ;
echo;
;;
2) echo "$filei is a directory, not a file." ;;
*) echo "$filei not found." ;;
esac
fi
done
else
echo "The File Printlist is empty."
fi

fi

if ( $enipwatchlist ); then
echo; echo "IPs in Watchlist:"
if [ ${#ipwatchlist[@]} -gt 0 ]; then
for ipel in "${ipwatchlist[@]}"; do
ipocc=$( grep $ipel $logfx | wc -l );
if [ $ipocc -ge $minoccenipwatchlist ]; then
if [ $ipocc -eq 1 ]; then
echo "IP $ipel : $ipocc occurrence found in the Apache Log File.";
else
echo "IP $ipel : $ipocc occurrences found in the Apache Log File.";
fi
fi
done
else
echo "The Watchlist is empty."
fi
fi

if [ -n "$istherenetstat" ]; then
echo; echo "Top IPs accessing the system now:"
conntot=$( netstat -an | wc -l )
if [ $conntot -gt 0 ]; then
connest=$( netstat -an | grep 'ESTABLISHED' | wc -l )
netstat -an | grep 'ESTABLISHED' | awk '{print $5}' | grep -o "[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}" | egrep -v "(`for i in \`ip addr | grep inet | grep eth0 | cut -d/ -f1 | awk '{print $2}'\`;do echo -n "$i|"| sed 's/\./\\\./g;';done`127\.|0\.0\.0)" | sort -n | uniq -c | sort -rn | head --lines=$nrestop # | nl -n rn -s '. '
if [ $connest -gt 1 ]; then echo "$connest established connections."; else echo "$connest established connection."; fi
if [ $conntot -gt 1 ]; then echo "$conntot total connections."; else echo "$conntot total connection."; fi
else
echo "No active connections.";
fi
fi

echo

if [[ -d $logfx ]]; then
echo "Apache Log File not found (specified file name is a directory)"
exit 1
elif [[ ! -f $logfx ]]; then
echo "Apache Log File not found"
exit 1
fi

if [ -n "$ipx" ]; then echo; fi

echo "Apache Log File: $logfx";

timepnow=$( date +"%s" )
echo; echo -n "Current Time: "; date "+%a %d %b %Y %H:%M:%S %Z (UTC%:z)"

aclogtt=$(wc -l $logfx | awk '{print $1}');

if [ $aclogtt -gt 0 ]; then

timelog1=$( cat $logfx | head --lines=1 | sed 's#[^[]*[[]\([^]][^]]*\).*#\1#' | awk '{print $1}' )
timeplog1=$( date -d "$( echo $timelog1 | sed -e 's,/,-,g' -e 's,:, ,')" +"%s" )
echo -n "First access: "; date -d "$(echo $timelog1 | sed -e 's,/,-,g' -e 's,:, ,')" "+%a %d %b %Y %H:%M:%S" | tr -d '\n'
echo -n ' ('; hrtime $(( $timepnow-$timeplog1 )); echo ' ago)';

timelog2=$( cat $logfx | tail --lines=1 | sed 's#[^[]*[[]\([^]][^]]*\).*#\1#' | awk '{print $1}' )
timeplog2=$( date -d "$( echo $timelog2 | sed -e 's,/,-,g' -e 's,:, ,')" +"%s" )
echo -n "Last access : "; date -d "$(echo $timelog2 | sed -e 's,/,-,g' -e 's,:, ,')" "+%a %d %b %Y %H:%M:%S" | tr -d '\n'
echo -n ' ('; hrtime $(( $timepnow-$timeplog2 )); echo ' ago)';

timepspanlog=$(( $timeplog2-$timeplog1 ));
echo -n "Time span: "; hrtime $(( $timepspanlog )); echo

echo "Total access count: $aclogtt"

if [ $timepspanlog -lt 60 ]; then
timepspanlog=60
fi

echo "Average accesses per minute: $(( $aclogtt/(($timepspanlog)/60) ))";

echo; echo "Log Head:";
head --lines=$nreshd $logfx

echo; echo "Log Tail:";
tail --lines=$nrestl $logfx

if ( $sortfileswoquery ); then
echo; echo "Top accessed files:";
grep '/' $logfx | awk -F\" '{print $2}' | awk '{print $2}' | sed '/^$/d' | sed 's/\?.*//g' | sort | uniq -c | sort -rn | head --lines=$nrestop # | nl -n rn -s '. '
else
echo; echo "Top accessed files (including query strings):";
grep '/' $logfx | awk -F\" '{print $2}' | awk '{print $2}' | sort | uniq -c | sort -g | tail --lines=$nrestop | tac # | nl -n rn -s '. '
fi

echo; echo "Top requests by returned HTTP response status code:"
IFS=$'\n' read -r -d '' -a httpst < <( ( cat $logfx | sed 's/\\"//g' | sed 's/ - ".*" \[/ - - \[/g' | cut -d'"' -f3 | cut -d' ' -f2 | sort | uniq -c | sort -rg ) && printf '\0' )

if [ $# -ge 1 ]; then
ct=0; cterr=0;
for httpstel in "${httpst[@]}"; do
httpstcod="$( echo -n $httpstel | awk {'print $2'} )";
if [[ $httpstcod =~ ^[0-9]+$ ]]; then
ct=$((ct+1));
if [ $ct -eq 1 ]; then el1=$( echo -n "$httpstel" | awk {'print $1'} | tr -d '\n' ); lel1=${#el1}; fi
printf "%03s" "${ct}"; echo -n '. ';
printf "%0${lel1}s" "$( echo -n $httpstel | awk {'print $1'} | tr -d '\n' )"
httpstocc="$( echo -n $httpstel | awk {'print $1'} )"
echo -n ' ('
printf "%03s" "$(( $httpstocc * 100 / $aclogtt ))"
echo -n '%) '
echo -n "$httpstel" | awk {'print $2'} | tr -d '\n'
echo " ($(httpstatcod2msg $( echo -n $httpstel | awk {'print $2'} )))"
else
# echo "ERROR: $httpstel"
cterr=$((cterr+1)); # Shouldn't happen
fi
done
if ( $showerrreq ); then
for httpstel in "${httpst[@]}"; do
httpstcod="$( echo -n $httpstel | awk {'print $2'} )";
if [[ $httpstcod =~ ^[0-9]+$ ]] && [ $httpstcod -ge $rephstmn ] && [ $httpstcod -le $rephstmx ]; then
echo "$( printhttplog $logfx $httpstcod $nrestop )";
fi
done
fi
else
echo 'No requests found';
fi

# Shouldn't happen
if [ $cterr -gt 0 ]; then
echo
if [ $cterr -eq 1 ]; then
echo "There are $cterr malformed field in the Apache Log File.";
else
echo "There are $cterr malformed fields in the Apache Log File.";
fi
fi

echo; echo "Top IPs access count:"
cat $logfx | awk '{print $1}' | sort -n | uniq -c | sort -rn | head --lines=$nrestop # | nl -n rn -s '. '

fi

fi
