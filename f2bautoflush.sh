#!/bin/bash

# Fail2Ban Auto Flush
# xver='r2021-01-16 fr2021-01-16';
# by Valerio Capello - http://labs.geody.com/ - License: GPL v3.0
# Flush automatically Fail2Ban when its database exceeds given size
# Crontab entry (example): 30 0 * * * f2bautoflush >/dev/null # Check F2B DB size every day at 00:30


# Config

f2bdbsizemax=100000000; # Fail2Ban Database max allowed size in bytes
act=1; # Action to take if Fail2Ban DB is too large: 0: Warn, 1: Flush


# Functions

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

f2bflush() {
echo "Fail2Ban Flush:";
echo "Purging Fail2Ban Logs";
rm /var/log/fail2ban.*
echo "Purging Fail2Ban DataBase";
# rm /var/lib/fail2ban/fail2ban.sqlite3
rm /var/lib/fail2ban/*
}


# Main

f2bdbsize=$( du -bs '/var/lib/fail2ban/' | awk '{print $1}' | tr -d '\n' );

echo "Fail2Ban Database size is $f2bdbsize bytes.";
if [ $f2bdbsize -gt $f2bdbsizemax ]; then
echo "This is more than the max allowed size of $f2bdbsizemax bytes.";
if [ $act -eq 1 ]; then
echo "Fail2Ban Database and Logs will be purged."
f2bstop;
f2bflush;
f2bstart;
else
echo "You should stop Fail2Ban, delete its Database and Logs, and start it again.";
fi
else
if [ $f2bdbsize -lt $f2bdbsizemax ]; then
echo "This is less than the max allowed size of $f2bdbsizemax bytes.";
else
echo "This is its max allowed size.";
fi
echo "Nothing to do.";
fi
