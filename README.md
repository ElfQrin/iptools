# Geody Labs IPtools

Geody Labs IPtools are a bunch of shell scripts to monitor and handle IP traffic on your webserver.

They all can be fully customized and fine tuned in a very granular way editing the files and setting the variables in the Config section.

The set of tools includes:

IPcheck
IPcheck takes as arguments an IP, an Apache Log, or both.
If you pass an IP it gives you some basic information about it and it reports about the activity of the IP in your system.
If you pass an Apache log it will tell you what are the most visited pages, which are the IPs with most accesses, which pages and IPs are causing most errors, and so on.
If you pass both arguments, an Apache Log and an IP, it will report you about the activity of the IP on that log, when it was first and last seen, its time span, what pages it's accessing, what errors is causing, and so on.
It also supports Fail2Ban and UFW, if present in your system.

IPcheckmulti
IPcheckmulti gives you less information about IPs than IPcheck but it's meant to give you a quick glance of the activity of a set of IPs on a given Apache Log. You can pass as an arguments, besides of the Apache Log, a text file containing the IPs you'd like to check (one per line) or fetch the IPs with most accesses on the given Apache Log.

IPban
IPban lets you ban and unban IPs on IPTables, all Fail2Ban jails, UFW. It can make sure you are not banning yourself or other vital IPs (like your own machine or its gateway) and you can set your personal whitelist. Also, it makes sure you are not entering the same rule twice before to add it. It also lets you safely flush all IPTables, Fail2Ban, UFW rules.

F2Bautoflush
F2Bautoflush flushes Fail2Ban Database and Logs if the Database exceeds a given size as set in its configuration. It's mostly meant to be used in Crontab.

ipv4conv
ipv4conv converts long (undotted) IPs to short (dotted) IPs and viceversa.

MyIP
MyIP returns your IP, your system's IP, and the IP of its gateway.

http://labs.geody.com/iptools/

<img src="https://raw.githubusercontent.com/ElfQrin/iptools/main/ipcheck_screenshot.png" alt="GeodyLabs IPTools IPcheck tool bash shell script Linux screenshot" />
