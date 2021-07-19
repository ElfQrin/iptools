#!/bin/bash

# IPban
xver='r2021-07-19 fr2020-09-12';
# by Valerio Capello - http://labs.geody.com/ - License: GPL v3.0


# Config

iptfw=1; # IP Tables framework: 0: Standard, 1: nft (nftables, default and recommended since Debian Buster)
ipundott2dott=true; # If an undotted IP is passed, convert it to a dotted IP before to process it
allwarns=false; # Issue all warnings and messages, regardless of the requested ban/unban action
watchmachine=2; # Watch the IPs of the machine and its gateway: 0: No, 1: Warn, 2: Protect (recommended: 2)
watchcurrentuser=2; # Watch the IP of the current user: 0: No, 1: Warn, 2: Protect (recommended: 2)
watchloggedusersnow=1; # Watch IPs of currently logged users: 0: No, 1: Warn, 2: Protect
watchloggeduserslast=1; # Watch IPs of last logged users: 0: No, 1: Warn, 2: Protect
lastuserssince='yesterday'; # Consider last logged users since the specified time
enfileprintlist=false; # Show the content of the files in printlist
fileprintlist=('/etc/hosts' '/etc/hosts.allow' '/etc/hosts.deny'); # File Printlist. Example: fileprintlist=('/etc/hosts' '/etc/hosts.allow' '/etc/hosts.deny');
enfilewarnlist=true; # Warn about IPs within the files in Warnlist
filewarnlist=(); # File Warnlist.
enfileprotectlist=true; # Protect IPs within the files in Protectlist
fileprotectlist=('/etc/hosts' '/etc/hosts.allow'); # File Protectlist. Example: fileprotectlist=('/etc/hosts' '/etc/hosts.allow');
enfileblocklist=false; # Keep blocked IPs within the files in Blocklist (blacklist).
fileblocklist=('/etc/hosts.deny'); # File Blocklist (blacklist). Example: fileblocklist=('/etc/hosts.deny');
enipwarnlist=true; # Warn about IPs in the Warnlist
ipwarnlist=(); # IP Warnlist. Example: ipwarnlist=('192.0.2.1' '192.0.2.254');
enipallowlist=true; # Protect IPs in the Allowlist (whitelist)
ipallowlist=(); # IP Allowlist (whitelist). Example: ipallowlist=('192.0.2.100' '192.0.2.101');
enipblocklist=false; # Keep blocked IPs in the Blocklist (blacklist)
ipblocklist=(); # IP Blocklist (blacklist). Example: ipblocklist=('192.0.2.200' '192.0.2.201');

f2benable=true; # Enable all Fail2Ban actions and commands (requires Fail2Ban to be present)
f2bcheck=1; # Seek IP in Fail2ban banned IP lists: 0: Never, 1: Only if the action requires Fail2Ban, 2: Always (if Fail2Ban is present and active)
f2biptflushstop=1; # Stop Fail2Ban before to flush IPTables (requires Fail2Ban to be present): 0: No, 1: Yes
f2biptflushstart=1; # Start Fail2Ban after flushing IPTables (requires Fail2Ban to be present): 0: No, 1: Yes

ufwenable=true; # Enable all UFW actions and commands (requires UFW to be present)
ufwcheck=1; # Seek IP in UFW (Uncomplicated Firewall) status: 0: Never, 1: Only if the action requires UFW, 2: Always (if UFW is present and enabled)
ufwallowforcestart=true; # Allow force start (for UFW)
ufwiptflushstop=1; # Stop UFW before to flush IPTables (requires UFW to be present): 0: No, 1: Yes
ufwiptflushstart=1; # Start UFW after flushing IPTables (requires UFW to be present): 0: No, 1: Yes, 2: Yes and Force


# Functions

apphdr() {
echo "IPban";
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
echo "ipban ACTION IP # Perform the requested ACTION on the IP";
echo "ipban COMMAND   # Perform the requested COMMAND";
echo;
echo "Actions on IPs:"
echo "--drop       # Drop IP in IPTables";
echo "--reject     # Reject IP (return icmp-port-unreachable) in IPTables";
echo "--undrop     # Undrop IP in IPTables";
echo "--unreject   # Unreject IP in IPTables";
echo "--unblock    # Undrop and Unreject IP in IPTables";
echo "--unban      # Unban (Undrop, Unreject) IP in IPTables";
if ( $f2benable ); then
echo "--f2bunban   # Unban IP in all Fail2Ban Jails, if enabled";
fi
if ( $ufwenable ); then
echo "--ufwdeny    # Deny IP in UFW, if enabled";
echo "--ufwban     # Ban (Delete Allow, Deny) IP in UFW, if enabled";
echo "--ufwallow   # Allow IP in UFW, if enabled";
echo "--ufwunban   # Unban (Delete Deny, Allow) IP in UFW, if enabled";
echo "--ufwclear   # Clear (Delete Allow, Delete Deny) IP in UFW, if enabled";
fi
echo -n "--check      # Check IP matches in IPTables";
if ( $f2benable ) || ( $ufwenable ); then
echo -n ", and if present and enabled,";
if ( $f2benable ); then
echo -n " Fail2Ban";
fi
if ( $ufwenable ); then
if ( $f2benable ); then echo -n " and"; fi
echo " UFW";
else
echo;
fi
fi
echo;
echo "Commands:"
echo "--help          # Display this help";
echo "--version       # Display version information";
echo;
# echo "--ip4tflush     # Flush IP4Tables";
# echo "--ip4tstatus    # List all INPUT rules in IP4Tables";
# echo "--ip4tstatusall # List all rules in IP4Tables";
# echo "--ip6tflush     # Flush IP6Tables";
# echo "--ip6tstatus    # List all INPUT rules in IP6Tables";
# echo "--ip6tstatusall # List all rules in IP6Tables";
# echo "--ipxtflush     # Flush IP4Tables and IP6Tables";
# echo "--ipxtstatus    # List all INPUT rules in IP4Tables and IP6Tables";
# echo "--ipxtstatusall # List all rules in IP4Tables and IP6Tables";
echo "--ip4tflush     # Flush IP4Tables";
echo "--ip6tflush     # Flush IP6Tables";
echo "--ipxtflush     # Flush IP4Tables and IP6Tables";
echo "--ip4tstatus    # List all INPUT rules in IP4Tables";
echo "--ip6tstatus    # List all INPUT rules in IP6Tables";
echo "--ipxtstatus    # List all INPUT rules in IP4Tables and IP6Tables";
echo "--ip4tstatusall # List all rules in IP4Tables";
echo "--ip6tstatusall # List all rules in IP6Tables";
echo "--ipxtstatusall # List all rules in IP4Tables and IP6Tables";
echo;
if ( $f2benable ); then
echo "--f2bstop       # Stop Fail2Ban";
echo "--f2bstart      # Start Fail2Ban";
echo "--f2brestart    # Restart Fail2Ban";
echo "--f2bflush      # Stop, Flush Fail2Ban";
echo "--f2bflushnrestart # Stop, Flush, Start Fail2Ban";
echo "--f2blist       # List all Fail2Ban Jails";
echo "--f2bstatus     # Display status for all Fail2Ban Jails";
echo;
fi
if ( $ufwenable ); then
echo "--ufwstop       # Stop UFW";
echo "--ufwstart      # Start UFW";
if ( $ufwallowforcestart ); then
echo "--ufwstartforce # Start UFW without confirmation";
fi
echo "--ufwrestart    # Restart UFW";
if ( $ufwallowforcestart ); then
echo "--ufwrestartforce # Restart UFW without confirmation on start";
fi
echo "--ufwflush      # Stop, Flush (reset all rules) UFW";
echo "--ufwflushnrestart # Stop, Flush (reset all rules), Start UFW";
if ( $ufwallowforcestart ); then
echo "--ufwflushnrestartforce # Stop, Flush (reset all rules), Start UFW without confirmation";
fi
echo "--ufwflushsafe  # Stop, Flush (reset then set safe rules) UFW";
echo "--ufwflushsafenrestart # Stop, Flush (reset then set safe rules), Start UFW";
if ( $ufwallowforcestart ); then
echo "--ufwflushsafenrestartforce # Stop, Flush (reset then set safe rules), Start UFW without confirmation";
fi
echo "--ufwstatus     # Display UFW status";
echo;
fi
echo "Example: ipban --check 192.0.2.100";
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

iptstatus() {
local ipv="$1";
if [ -z "$ipv" ] || [[ "$ipv" == "" ]] || [ $ipv -eq 0 ]; then local ipv="4"; fi
if [ $ipv -eq 4 ] || [ $ipv -eq 6 ]; then
if [ $ipv -eq 6 ]; then
local iptcmd="ip6tables${iptfwx}"; local ipttxt='IP6Tables';
else
local iptcmd="iptables${iptfwx}"; local ipttxt='IPTables';
fi
local cmd=$( echo "$2" | tr '[:upper:]' '[:lower:]' );
if [ -n "$cmd" ] && [[ "$cmd" == "all" ]]; then
echo "All rules in $ipttxt";
$iptcmd -L -n --line-numbers
else
echo "All INPUT rules in $ipttxt";
$iptcmd -L INPUT -n --line-numbers
fi
fi

echo; echo 'INPUT Rules:';
echo -n 'Total: '; iptables -S|grep "\-A INPUT "|wc -l
echo -n 'Drop: '; iptables -S|grep "\-A INPUT "|grep " DROP"|wc -l
echo -n 'Reject: '; iptables -S|grep "\-A INPUT "|grep " REJECT"|wc -l
if ( $f2benable ) && [ -n "$istheref2b" ]; then
echo; echo -n 'F2B Rules ';
if ($isf2bon); then
echo -n '(F2B is present and enabled)';
else
echo -n '(F2B is present but disabled)';
fi
echo ':';
echo -n 'Total: '; iptables -S|grep "\-A f2b\-"|wc -l
echo -n 'Drop: '; iptables -S|grep "\-A f2b\-"|grep " DROP"|wc -l
echo -n 'Reject: '; iptables -S|grep "\-A f2b\-"|grep " REJECT"|wc -l
fi
if ( $ufwenable ) && [ -n "$isthereufw" ]; then
echo; echo -n 'UFW Rules ';
if ($isufwenabled); then
echo -n '(UFW is present and enabled)';
else
echo -n '(UFW is present but disabled)';
fi
echo ':';
echo -n 'Total: '; iptables -S|grep "\-A ufw\-"|wc -l
echo -n 'Drop: '; iptables -S|grep "\-A ufw\-"|grep " DROP"|wc -l
echo -n 'Reject: '; iptables -S|grep "\-A ufw\-"|grep " REJECT"|wc -l
fi
}

iptflush() {
local ipv="$1";
if [ -z "$ipv" ] || [[ "$ipv" == "" ]] || [ $ipv -eq 0 ]; then local ipv="4"; fi
if [ $ipv -eq 4 ] || [ $ipv -eq 6 ]; then
if [ $ipv -eq 6 ]; then
local iptcmd="ip6tables${iptfwx}"; local ipttxt='IP6Tables';
else
local iptcmd="iptables${iptfwx}"; local ipttxt='IPTables';
fi
if ( $f2benable ) && [ -n "$istheref2b" ] && ($isf2bon) && [ $f2biptflushstop -gt 0 ]; then
f2bstop;
fi
if ( $ufwenable ) && [ -n "$isthereufw" ] && ($isufwenabled) && [ $ufwiptflushstop -gt 0 ]; then
ufwstop;
fi
# local iptcmd="echo # iptest ";
echo "Flushing $ipttxt";
$iptcmd -F
$iptcmd -X
$iptcmd -t nat -F
$iptcmd -t nat -X
$iptcmd -t mangle -F
$iptcmd -t mangle -X
$iptcmd -t raw -F
$iptcmd -t raw -X
$iptcmd -P INPUT ACCEPT
$iptcmd -P FORWARD ACCEPT
$iptcmd -P OUTPUT ACCEPT
if ( $f2benable ) && [ -n "$istheref2b" ] && ($isf2bon) && [ $f2biptflushstart -gt 0 ]; then
f2bstart;
fi
if ( $ufwenable ) && [ -n "$isthereufw" ] && ($isufwenabled) && [ $ufwiptflushstart -gt 0 ]; then
if [ $ufwiptflushstart -eq 1 ]; then
ufwstart "safe";
else
ufwstart "force";
fi
fi
fi
}

if ( $f2benable ); then

f2blist() {
echo "fail2ban list jails"; echo;
# fail2ban-client --version ; echo;
jails=$(fail2ban-client status | grep "Jail list" | sed -E 's/^[^:]+:[ \t]+//' | sed 's/,//g')
jailsnum=0;
for jail in $jails
do
jailsnum=$((jailsnum+1));
jailstatus=$(fail2ban-client status $jail)
filelist=$( echo -n "$jailstatus" | grep -m 1 'File list:' | awk {'print $5'} );
echo "$jail for $filelist";
done
if [ $jailsnum -eq 1 ]; then
echo "$jailsnum Fail2Ban Jail found.";
elif [ $jailsnum -gt 1 ]; then
echo "$jailsnum Fail2Ban Jails found.";
else
echo "No Fail2Ban Jails found.";
fi
}

f2bstatus() {
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
}

f2bdatasize() {
# f2bdbsize=$( du -bs '/var/lib/fail2ban/' | awk '{print $1}' | tr -d '\n' );
f2bdbsize=$( du -bsc /var/lib/fail2ban/* | head --lines=1 | awk '{print $1}' | tr -d '\n' );
f2blgsize=$( du -bsc /var/log/fail2ban.* | head --lines=1 | awk '{print $1}' | tr -d '\n' );
f2btotsize=( $f2bdbsize + $f2blgsize );
echo "Fail2Ban Database size is $f2bdbsize bytes.";
echo "Fail2Ban Logs size is $f2blgsize bytes.";
echo "Fail2Ban total data size is $f2btotsize bytes.";
}

f2bstop() {
echo "Stopping Fail2Ban";
/usr/bin/fail2ban-client -x stop
systemctl stop fail2ban
}

f2bstart() {
echo "Starting Fail2Ban";
/usr/bin/fail2ban-client -x start
systemctl start fail2ban
systemctl enable fail2ban
fail2ban-client --version
}

# Requires f2bstart, f2bstop
f2brestart() {
f2bstop; f2bstart;
}

f2bflush() {
echo "Fail2Ban Flush:";
echo "Purging Fail2Ban Logs";
rm /var/log/fail2ban.*
echo "Purging Fail2Ban DataBase";
rm /var/lib/fail2ban/fail2ban.sqlite*
}

fi

if ( $ufwenable ); then

ufwstatus() {
ufw version ; ufw status verbose | head --lines=4 ; ufw status numbered | grep -v 'Status' ;
}

ufwstop() {
echo "Stopping UFW";
ufw disable
}

# Requires ufwstatus
ufwstart() {
local cmd=$( echo "$1" | tr '[:upper:]' '[:lower:]' );
if [ -n "$cmd" ] && [[ "$cmd" == "force" ]]; then
if ( $ufwallowforcestart ); then
echo "Starting UFW (force start: without confirmation)";
ufw --force enable
else
echo "Starting UFW (UFW force start is disabled in IPban configuration)";
ufw enable
fi
ufwstatus;
else
echo "Starting UFW";
ufw enable
ufwstatus;
fi
}

# Requires ufwstart (ufwstatus), ufwstop
ufwrestart() {
ufwstop; ufwstart "$1";
}

ufwflush() {
local cmd=$( echo "$1" | tr '[:upper:]' '[:lower:]' );
if [ -n "$cmd" ] && [[ "$cmd" == "reset" ]]; then
echo "Flushing UFW (reset all rules)";
ufw reset
else
echo "Flushing UFW (safe mode: allow incoming, outgoing, ssh, http, https)";
ufw reset
ufw default allow incoming
ufw default allow outgoing
ufw allow ssh
ufw allow http
ufw allow https
fi
}

fi


# Get Parameters

if [ $# -lt 1 ] || [ $# -gt 2 ]; then
apphelp
exit 1;
fi

action=$1; # Action
action=$( echo "$action" | tr '[:upper:]' '[:lower:]' );
ipx=$2; # Target IP


# Quick Commands

if [ $# -eq 1 ]; then
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
esac
fi


# Define Aliases and Set Flags

if [ $# -eq 2 ]; then
case $action in
"--ban" | "--drop")
action='drop';
acheckban=true; acheckunban=false; acheckf2b=false; acheckufw=false;
;;
"--reject")
action='reject';
acheckban=true; acheckunban=false; acheckf2b=false; acheckufw=false;
;;
"--undrop")
action='undrop';
acheckban=false; acheckunban=true; acheckf2b=false; acheckufw=false;
;;
"--unreject")
action='unreject';
acheckban=false; acheckunban=true; acheckf2b=false; acheckufw=false;
;;
"--unban")
action='unban';
acheckban=false; acheckunban=true; acheckf2b=false; acheckufw=false;
;;
"--f2bunban")
action='f2bunban';
acheckban=false; acheckunban=true; acheckf2b=true; acheckufw=false;
;;
"--ufwdeny")
action='ufwdeny';
acheckban=true; acheckunban=false; acheckf2b=false; acheckufw=true;
;;
"--ufwban")
action='ufwban';
acheckban=true; acheckunban=false; acheckf2b=false; acheckufw=true;
;;
"--ufwallow")
action='ufwallow';
acheckban=false; acheckunban=true; acheckf2b=false; acheckufw=true;
;;
"--ufwunban")
action='ufwunban';
acheckban=false; acheckunban=true; acheckf2b=false; acheckufw=true;
;;
"--ufwclear")
action='ufwclear';
acheckban=true; acheckunban=true; acheckf2b=false; acheckufw=true;
;;
"--check")
action='check';
acheckban=true; acheckunban=true; acheckf2b=true; acheckufw=true;
;;
*)
echo "No action specified.";
exit 1;
;;
esac

if [[ "${action:0:3}" == "f2b" ]]; then
if ( ! $f2benable ); then echo "Fail2Ban is disabled in IPban configuration."; exit 1; fi
elif [[ "${action:0:3}" == "ufw" ]]; then
if ( ! $ufwenable ); then echo "UFW is disabled in IPban configuration."; exit 1; fi
fi

fi

if [ $f2bcheck -eq 0 ]; then
acheckf2b=false;
elif [ $f2bcheck -eq 2 ]; then
acheckf2b=true;
fi

if [ $ufwcheck -eq 0 ]; then
acheckufw=false;
elif [ $ufwcheck -eq 2 ]; then
acheckufw=true;
fi

if ( $allwarns ); then
acheckban=true; acheckunban=true;
fi

if ( ! $f2benable ); then acheckf2b=false; fi
if ( ! $ufwenable ); then acheckufw=false; fi

# Main

if [ $iptfw -eq 1 ]; then
iptfwx='-nft';
else
iptfwx='';
fi

istheref2b=$( type -t fail2ban-client );
if [ $( fail2ban-client status | wc -l ) -ge 3 ]; then
isf2bon=true;
else
isf2bon=false;
fi

isthereufw=$( type -t ufw );
if [ -n "$isthereufw" ]; then
ufwstatus=$( ufw status | head --lines=1 | tr -d '\n' );
if [[ "$ufwstatus" == 'Status: active' ]]; then isufwenabled=true; else isufwenabled=false; fi
else
isufwenabled=false;
fi

msgtrigipbpr="TRIGGERING IP BAN PROTECTION.";
msgtrigipblk="TRIGGERING IP BLOCK.";

apphdr; echo;

if [ $# -eq 1 ]; then
if [[ "${action:0:4}" == "--ip" ]]; then
case $action in
"--ip4tstatus")
iptstatus "4" "input";
exit 0;
;;
"--ip4tstatusall")
iptstatus "4" "all";
exit 0;
;;
"--ip6tstatus")
iptstatus "6" "input";
exit 0;
;;
"--ip6tstatusall")
iptstatus "6" "all";
exit 0;
;;
"--ipxtstatus")
iptstatus "4" "input";
echo;
iptstatus "6" "input";
exit 0;
;;
"--ipxtstatusall")
iptstatus "4" "all";
echo;
iptstatus "6" "all";
exit 0;
;;
"--ip4tflush")
iptflush "4";
exit 0;
;;
"--ip6tflush")
iptflush "6";
exit 0;
;;
"--ipxtflush")
iptflush "4";
iptflush "6";
exit 0;
;;
*)
echo 'Invalid command.';
exit 1;
;;
esac
elif [[ "${action:0:5}" == "--f2b" ]]; then
if ( ! $f2benable ); then echo "Fail2Ban is disabled in IPban configuration."; exit 1; fi
if [ -z "$istheref2b" ]; then echo "Fail2Ban is not present."; exit 1; fi
case $action in
"--f2blist")
f2blist;
exit 0;
;;
"--f2bstatus")
f2bstatus;
echo;
f2bdatasize;
exit 0;
;;
"--f2bstop")
f2bstop;
exit 0;
;;
"--f2bstart")
f2bstart;
exit 0;
;;
"--f2brestart")
f2brestart;
exit 0;
;;
"--f2bflush")
f2bstop;
f2bflush;
echo "Fail2Ban is now disabled. Use 'ipban --f2bstart' to start it.";
exit 0;
;;
"--f2bflushnrestart")
f2bstop;
f2bflush;
f2bstart;
exit 0;
;;
*)
echo 'Invalid command.';
exit 1;
;;
esac
elif [[ "${action:0:5}" == "--ufw" ]]; then
if ( ! $ufwenable ); then echo "UFW is disabled in IPban configuration."; exit 1; fi
if [ -z "$isthereufw" ]; then echo "UFW is not present."; exit 1; fi
case $action in
"--ufwstatus")
ufwstatus;
exit 0;
;;
"--ufwstop")
ufwstop;
exit 0;
;;
"--ufwstart")
ufwstart "safe";
exit 0;
;;
"--ufwstartforce")
ufwstart "force";
exit 0;
;;
"--ufwrestart")
ufwrestart "safe";
exit 0;
;;
"--ufwrestartforce")
ufwrestart "force";
exit 0;
;;
"--ufwflush")
ufwstop;
ufwflush "safe";
echo "UFW is now disabled. Use 'ipban --ufwstart' to start it.";
exit 0;
;;
"--ufwflushnrestart")
ufwstop;
ufwflush "safe";
ufwstart "safe";
exit 0;
;;
"--ufwflushnrestartforce")
ufwstop;
ufwflush "safe";
ufwstart "force";
exit 0;
;;
"--ufwflushreset")
ufwstop;
ufwflush "reset";
echo "UFW is now disabled. Use 'ipban --ufwstart' to start it.";
exit 0;
;;
"--ufwflushresetnrestart")
ufwstop;
ufwflush "reset";
ufwstart "safe";
exit 0;
;;
"--ufwflushresetnrestartforce")
ufwstop;
ufwflush "reset";
ufwstart "force";
exit 0;
;;
*)
echo 'Invalid command.';
exit 1;
;;
esac
fi
exit 1; # Can't happen
fi


echo "IP: $ipx";

ipv=$(isip "$ipx")

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
exit 1;
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

if [ $ipv -eq 5 ] && ( $ipundott2dott ); then
ipx="$(ipundot2dot $ipx)"; ipv=4;
fi
fi

echo;

isipprot=0;
isipblock=0;

# IPTables
if [ $ipv -eq 6 ]; then
iptcmd="ip6tables${iptfwx}"; ipttxt='IP6Tables';
else
iptcmd="iptables${iptfwx}"; ipttxt='IPTables';
fi

echo "IP in $ipttxt:"

ipxintablesn=$($iptcmd -L INPUT -n --line-numbers | grep $ipx | wc -l );
ipxintablesdropn=$($iptcmd -L INPUT -n --line-numbers | grep $ipx | grep "DROP" | wc -l );
ipxintablesrejn=$($iptcmd -L INPUT -n --line-numbers | grep $ipx | grep "REJECT" | wc -l );

if [ $ipxintablesn -eq 0 ]; then
echo "No matches found in ${ipttxt}.";
else
$iptcmd -L INPUT -n --line-numbers | grep $ipx
if [ $ipxintablesdropn -gt 0 ]; then
echo "The IP was found in the $ipttxt Drop list";
fi
if [ $ipxintablesrejn -gt 0 ]; then
echo "The IP was found in the $ipttxt Reject list";
fi
fi

# Fail2Ban
if ( $f2benable ) && ( $acheckf2b ) && [[ "$action" != "f2bunban" ]]; then
echo "IP in Fail2Ban:"
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

# UFW
if ( $ufwenable ) && ( $acheckufw ); then
echo "IP in UFW (Uncomplicated Firewall):"
if [ -n "$isthereufw" ]; then
if ( $isufwenabled ); then
# ufw version ; ufw status verbose | head --lines=4 ;
ufw status | grep $ipx ;
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
# ufw version ; ufw status ;
fi
else
echo "UFW is not present.";
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

if ( $enfilewarnlist ); then

echo "IP within files in Warnlist:"

if [ ${#filewarnlist[@]} -gt 0 ]; then

for filei in "${filewarnlist[@]}"
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
echo "Warning: $ipocc occurrence of the IP found in ${fileish}";
else
echo "Warning: $ipocc occurrences of the IP found in ${fileish}";
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
echo "The File Warnlist is empty."
fi

fi

if ( $enfileprotectlist ) && ( $acheckban ); then

echo "IP within files in Protectlist:"

if [ ${#fileprotectlist[@]} -gt 0 ]; then

for filei in "${fileprotectlist[@]}"
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
# if ( $enfileprotectlist ) && ( $acheckban ); then
echo "$msgtrigipbpr";
isipprot=$((isipprot+1));
# fi
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
echo "The File Protectlist is empty."
fi

fi

if ( $enfileblocklist ) && ( $acheckunban ); then

echo "IP within files in Blocklist:"

if [ ${#fileblocklist[@]} -gt 0 ]; then

for filei in "${fileblocklist[@]}"
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
# if ( $enfileblocklist ) && ( $acheckban ); then
echo "$msgtrigipblk";
isipblock=$((isipblock+1));
# fi
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
echo "The File Blocklist is empty."
fi

fi

if [ $watchloggedusersnow -gt 0 ] || [ $watchloggeduserslast -gt 0 ]; then

# echo; echo "IP in Logged Users:"

if [ $watchloggedusersnow -gt 0 ]; then
# echo "IP in currently logged users:"
ipocc=$( who -s --ips | grep $ipx | awk '!array[$5]++' | wc -l );
ipocctot=$( who -s --ips | grep $ipx | wc -l );
if [ $ipocc -gt 0 ]; then
echo "$( who -s --ips | grep $ipx)";
if [ $watchloggedusersnow -eq 1 ]; then echo -n 'Warning: '; fi
if [ $ipocc -eq 1 ]; then
echo "$ipocc occurrence ($ipocctot total) of the IP found in currently logged users.";
else
echo "$ipocc occurrences ($ipocctot total) of the IP found in currently logged users.";
fi
if [ $watchloggedusersnow -eq 2 ] && ( $acheckban ); then
echo "$msgtrigipbpr";
isipprot=$((isipprot+1));
fi
else
echo "No matches found for the IP in currently logged users.";
fi
fi

if [ $watchloggeduserslast -gt 0 ] && [ -n "$lastuserssince" ]; then
# echo "IP in last logged users (since $lastuserssince):"
ipocc=$( last -i --since $lastuserssince | grep $ipx | awk '!array[$3]++' | wc -l );
ipocctot=$( last -i --since $lastuserssince | grep $ipx | wc -l );
if [ $ipocc -gt 0 ]; then
echo "$( last -i --since $lastuserssince | grep $ipx )";
if [ $watchloggeduserslast -eq 1 ]; then echo -n 'Warning: '; fi
if [ $ipocc -eq 1 ]; then
echo "$ipocc occurrence ($ipocctot total) of the IP found in last logged users (since $lastuserssince).";
else
echo "$ipocc occurrences ($ipocctot total) of the IP found in last logged users (since $lastuserssince).";
fi
if [ $watchloggeduserslast -eq 2 ] && ( $acheckban ); then
echo "$msgtrigipbpr";
isipprot=$((isipprot+1));
fi
else
echo "No matches found for the IP in last logged users (since $lastuserssince).";
fi
fi

fi

if ( $enipwarnlist ); then
# echo; echo "IP in Warnlist:"
if [ ${#ipwarnlist[@]} -gt 0 ]; then
if [[ " ${ipwarnlist[*]} " == *" ${ipx} "* ]]; then
echo "Warning: The IP was FOUND in the IP Warnlist.";
else
echo "No matches found for the IP in the IP Warnlist.";
fi
else
echo "The IP Warnlist is empty."
fi
fi

if ( $enipallowlist ) && ( $acheckban ); then
# echo; echo "IP in Allowlist:"
if [ ${#ipallowlist[@]} -gt 0 ]; then
if [[ " ${ipallowlist[*]} " == *" ${ipx} "* ]]; then
echo "The IP was FOUND in the IP Allowlist.";
# if ( $enipallowlist ); then
echo "$msgtrigipbpr";
isipprot=$((isipprot+1));
# fi
else
echo "No matches found for the IP in the IP Allowlist.";
fi
else
echo "The IP Allowlist is empty."
fi
fi

if ( $enipblocklist ) && ( $acheckunban ); then
# echo; echo "IP in Blocklist:"
if [ ${#ipblocklist[@]} -gt 0 ]; then
if [[ " ${ipblocklist[*]} " == *" ${ipx} "* ]]; then
echo "The IP was FOUND in the IP Blocklist.";
# if ( $enipblocklist ) && ( $acheckunban ); then
echo "$msgtrigipblk";
isipblock=$((isipblock+1));
# fi
else
echo "No matches found for the IP in the IP Blocklist.";
fi
else
echo "The IP Blocklist is empty."
fi
fi

if [[ "$ipx" == "$( echo -n $SSH_CLIENT | awk '{print $1}' | tr -d '\n' )" ]]; then
if [ $watchcurrentuser -eq 1 ]; then echo -n 'Warning: '; fi
if [ $watchcurrentuser -ge 1 ]; then echo 'This IP is YOUR IP.'; fi
if [ $watchcurrentuser -eq 2 ] && ( $acheckban ); then
echo "$msgtrigipbpr";
isipprot=$((isipprot+1));
fi
elif [[ "$ipx" == "$( hostname -i | tr -d '\n' )" ]]; then
if [ $watchmachine -eq 1 ]; then echo -n 'Warning: '; fi
if [ $watchmachine -ge 1 ]; then echo "This IP is this machine's local IP."; fi
if [ $watchmachine -eq 2 ] && ( $acheckban ); then
echo "$msgtrigipbpr";
isipprot=$((isipprot+1));
fi
elif [[ "$ipx" == "$( ifconfig | sed -En 's/127.0.0.1//;s/.*inet (addr:)?(([0-9]*\.){3}[0-9]*).*/\2/p' | tr -d '\n' )" ]]; then
if [ $watchmachine -eq 1 ]; then echo -n 'Warning: '; fi
if [ $watchmachine -ge 1 ]; then echo "This IP is this machine's global IP."; fi
if [ $watchmachine -eq 2 ] && ( $acheckban ); then
echo "$msgtrigipbpr";
isipprot=$((isipprot+1));
fi
elif [[ "$ipx" == "$( route -n | grep 'UG[ \t]' | awk '{print $2}' | tr -d '\n' )" ]]; then
if [ $watchmachine -eq 1 ]; then echo -n 'Warning: '; fi
if [ $watchmachine -ge 1 ]; then echo "This IP is this machine's default gateway."; fi
if [ $watchmachine -eq 2 ] && ( $acheckban ); then
echo "$msgtrigipbpr";
isipprot=$((isipprot+1));
fi
fi

echo
if  ( $acheckban ); then
if [ $isipprot -gt 0 ]; then
if [ $isipprot -eq 1 ]; then
echo "This is IP is PROTECTED because it matches $isipprot criterion for protection."; echo;
else
echo "This is IP is PROTECTED because it matches $isipprot criteria for protection."; echo;
fi
else
echo "This is IP is not protected because it matches no criteria for protection."; echo;
fi
fi

if  ( $acheckunban ); then
if ( $enfileblocklist ) || ( $enipblocklist ); then
if [ $isipblock -gt 0 ]; then
if [ $isipblock -eq 1 ]; then
echo "This is IP is BLOCKED if already banned because it matches $isipblock criterion to remain blocked."; echo;
else
echo "This is IP is BLOCKED if already banned because it matches $isipblock criteria to remain blocked."; echo;
fi
else
echo "This is IP is not blocked because it matches no criteria to remain blocked."; echo;
fi
fi
fi


# Act

# iptcmd='echo TEST ; # TEST ';

case $action in
"drop")
echo "Dropping IP in $ipttxt";
if [ $ipxintablesdropn -eq 0 ]; then
if [ $isipprot -le 0 ]; then
$iptcmd -I INPUT -s $ipx -j DROP;
else
echo "This IP is protected. SKIPPING action.";
fi
else
echo "Already dropped. Nothing to do.";
fi
if [ $ipxintablesrejn -gt 0 ]; then echo 'IP is also already in the Reject list.'; fi
$iptcmd -L INPUT -n --line-numbers | grep $ipx
;;
"reject")
echo "Rejecting IP in $ipttxt";
if [ $ipxintablesrejn -eq 0 ]; then
if [ $isipprot -le 0 ]; then
$iptcmd -I INPUT -s $ipx -j REJECT --reject-with icmp-port-unreachable ;
else
echo "This IP is protected. SKIPPING action.";
fi
else
echo "Already rejected. Nothing to do.";
fi
if [ $ipxintablesdropn -gt 0 ]; then echo 'IP is also already in the Drop list.'; fi
$iptcmd -L INPUT -n --line-numbers | grep $ipx
;;
"undrop")
echo "Undropping IP in $ipttxt";
if [ $isipblock -le 0 ]; then
$iptcmd -D INPUT -s $ipx -j DROP;
$iptcmd -L INPUT -n --line-numbers | grep $ipx
else
echo "This IP is blocked. SKIPPING action.";
fi
;;
"unreject")
echo "Unrejecting IP in $ipttxt";
if [ $isipblock -le 0 ]; then
$iptcmd -D INPUT -s $ipx -j REJECT;
$iptcmd -L INPUT -n --line-numbers | grep $ipx
else
echo "This IP is blocked. SKIPPING action.";
fi
;;
"unban")
echo "Unbanning (Undropping and Unrejecting) IP in $ipttxt";
if [ $isipblock -le 0 ]; then
$iptcmd -D INPUT -s $ipx -j DROP;
$iptcmd -D INPUT -s $ipx -j REJECT;
$iptcmd -L INPUT -n --line-numbers | grep $ipx
else
echo "This IP is blocked. SKIPPING action.";
fi
;;
"f2bunban")
echo "Unbanning IP in all Fail2Ban Jails";
if [ $isipblock -le 0 ]; then
if [ -n "istheref2b" ]; then
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
fail2ban-client set $jail unbanip $ipx
ctipj=$((ctipj+1));
fi
done
if [ $ctipj -eq 0 ]; then
echo "No matches found for the IP in Fail2Ban Jails ban lists. Nothing done.";
elif [ $ctipj -eq 1 ]; then
echo "IP unbanned from $ctipj Fail2Ban Jails ban list.";
else
echo "IP unbanned from $ctipj Fail2Ban Jails ban lists.";
fi
else
echo 'No Fail2Ban entries found in IPTables.';
fi
else
echo "Fail2Ban is not present.";
fi
else
echo "This IP is blocked. SKIPPING action.";
fi
;;
"ufwdeny"|"ufwban")
if [ $isipprot -le 0 ]; then
if [ -n "$isthereufw" ]; then
if [[ "$action" == "ufwdeny" ]]; then
echo "Denying IP in UFW";
ufw deny from $ipx ;
elif [[ "$action" == "ufwban" ]]; then
echo "Banning IP from UFW";
ufw delete allow from $ipx ;
ufw deny from $ipx ;
fi
if ( ! $isufwenabled ); then
echo 'Warning: UFW is present but disabled.';
fi
else
echo "UFW is not present.";
fi
else
echo "This IP is protected. SKIPPING action.";
fi
;;
"ufwallow"|"ufwunban")
if [ $isipblock -le 0 ]; then
if [ -n "$isthereufw" ]; then
if [[ "$action" == "ufwallow" ]]; then
echo "Allowing IP in UFW";
ufw allow from $ipx ;
elif [[ "$action" == "ufwunban" ]]; then
echo "Unbanning IP in UFW";
ufw delete deny from $ipx ;
ufw allow from $ipx ;
fi
if ( ! $isufwenabled ); then
echo 'Warning: UFW is present but disabled.';
fi
else
echo "UFW is not present.";
fi
else
echo "This IP is blocked. SKIPPING action.";
fi
;;
"ufwclear")
if [ $isipprot -le 0 ]; then
if [ $isipblock -le 0 ]; then
if [ -n "$isthereufw" ]; then
echo "Clearing IP in UFW:";
echo "Deleting deny";
ufw delete deny from $ipx ;
echo "Deleting allow";
ufw delete allow from $ipx ;
if ( ! $isufwenabled ); then
echo 'Warning: UFW is present but disabled.';
fi
else
echo "UFW is not present.";
fi
else
if [ $isipblock -gt 0 ]; then echo "This IP is protected. SKIPPING action."; fi
echo "This IP is blocked. SKIPPING action.";
fi
else
echo "This IP is protected. SKIPPING action.";
if [ $isipblock -gt 0 ]; then echo "This IP is blocked. SKIPPING action."; fi
fi
;;
"check")
$iptcmd -L INPUT -n --line-numbers | grep $ipx
;;
*)
echo "No action specified.";
;;
esac

# echo
# echo "IP Tables";
# $iptcmd -L INPUT -n --line-numbers | grep $ipx
