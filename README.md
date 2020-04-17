# nmaparse
Revised shell script for parsing .gnmap, .xml, or .nmap port scan results files to a CSV list, lists of IPs per port, web urls, and a summary table.

# Usage
```
./nmaparse.sh [source file] [--out-dir [path]]
```
- **[source file]** specifies the input file. The script will detect the format based on finding `/open/` , `port protocol=`, or `Nmap scan report for`.
- **[--out-dir [path]]** optionally specifies an output directory other than the default nmaparse-YYYY-MM-DD-HH-MM.

# Example
Script execution:
```
# nmap -iL targets.txt -sSV -Pn -n --open -oA results1 > /dev/null
# ./nmaparse.sh results1.gnmap --out-dir test

=======================[ nmaparse.sh by Ted R (github: actuated) ]=======================

Parsing source file... Done.
nmaparse-2020-04-16-21-49.csv created with parsed results.

Parsing to [tcp/udp]-[port]-hosts.txt... Done:

  1 test/tcp-1025-hosts.txt
  1 test/tcp-1027-hosts.txt
  1 test/tcp-1034-hosts.txt
  1 test/tcp-1043-hosts.txt
  1 test/tcp-135-hosts.txt
  2 test/tcp-139-hosts.txt
  1 test/tcp-3268-hosts.txt
  1 test/tcp-389-hosts.txt
  2 test/tcp-445-hosts.txt
  1 test/tcp-464-hosts.txt
  1 test/tcp-53-hosts.txt
  1 test/tcp-5432-hosts.txt
  1 test/tcp-593-hosts.txt
  1 test/tcp-80-hosts.txt
  1 test/tcp-88-hosts.txt
 17 total

nmaparse-weburls-2020-04-16-21-49.txt created.

Creating summary report... nmaparse-summary-2020-04-16-21-49.txt created.

=========================================[ fin ]=========================================
```
CSV output file:
```
127.0.0.1,tcp,5432,postgresql,PostgreSQL DB 9.6.0 or later
192.168.0.18,tcp,53,domain?
192.168.0.18,tcp,88,kerberos-sec,Microsoft Windows Kerberos 
192.168.0.18,tcp,135,msrpc,Microsoft Windows RPC
192.168.0.18,tcp,139,netbios-ssn,Microsoft Windows netbios-ssn
192.168.0.18,tcp,389,ldap,Microsoft Windows Active Directory LDAP 
192.168.0.18,tcp,445,microsoft-ds,Microsoft Windows 2003 or 2008 microsoft-ds
192.168.0.18,tcp,464,kpasswd5?
192.168.0.18,tcp,593,ncacn_http,Microsoft Windows RPC over HTTP 1.0
192.168.0.18,tcp,1025,msrpc,Microsoft Windows RPC
192.168.0.18,tcp,1027,ncacn_http,Microsoft Windows RPC over HTTP 1.0
192.168.0.18,tcp,1034,msrpc,Microsoft Windows RPC
192.168.0.18,tcp,1043,msrpc,Microsoft Windows RPC
192.168.0.18,tcp,3268,ldap,Microsoft Windows Active Directory LDAP 
192.168.0.19,tcp,80,http,Apache httpd 2.4.29 
192.168.0.19,tcp,139,netbios-ssn,Samba smbd 3.X - 4.X 
192.168.0.19,tcp,445,netbios-ssn,Samba smbd 3.X - 4.X 
```
Created files:
```
nmaparse-2020-04-16-21-49.csv
nmaparse-summary-2020-04-16-21-49.txt
nmaparse-weburls-2020-04-16-21-49.txt
tcp-1025-hosts.txt
tcp-1027-hosts.txt
tcp-1034-hosts.txt
tcp-1043-hosts.txt
tcp-135-hosts.txt
tcp-139-hosts.txt
tcp-3268-hosts.txt
tcp-389-hosts.txt
tcp-445-hosts.txt
tcp-464-hosts.txt
tcp-53-hosts.txt
tcp-5432-hosts.txt
tcp-593-hosts.txt
tcp-80-hosts.txt
tcp-88-hosts.txt
```
