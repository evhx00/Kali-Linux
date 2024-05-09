#!/bin/bash

## *-----------------* CIS Compliant Firewall Registry CentOS 7 *-----------------* 

## Check if its Linux

if [[ "$OSTYPE" == "linux-gnu"* ]]; 
then

# look into this
check_root() {
if [ $EUID -ne 0 ]; then
      echo "Permission Denied"
      echo "Can only be run by root"
      exit
      else
      clear
      f_banner
      cat templates/texts/welcome-CIS
fi
}
## Timestamp
echo "Today is: $(date +%d-%b-%Y' '%T) "

## Check if updated and firewall is running well.
echo "Make sure the firewall is updated"
yum update -y

echo "Make sure the firewall is running"
sudo systemctl enable firewalld
sudo systemctl status firewalld

echo "List the default firewall zone"
firewall-cmd --get-default-zone

echo "List all the firewall zones"
firewall-cmd --list-all-zones



 # 1.1 Filesystem Configuration

 
 # 1.1.1.1 (L1) Ensure mounting of cramfs filesystems is disabled (Automated)


 # 1.1.1.2 (L2) Ensure mounting of squashfs filesystems is disabled (Automated)


 # 1.1.1.3  (L1) Ensure mounting of udf filesystems is disabled (Automated)


 # 1.1.2 (L1) Ensure /tmp is configured (Automated)


 # 1.1.3 (L1) Ensure noexec option set on /tmp partition (Automated)


 # 1.1.4 (L1) Ensure nodev option set on /tmp partition (Automated)


 # 1.1.5 (L1) Ensure nosuid option set on /tmp partition (Automated)


 # 1.1.6 (L1) Ensure /dev/shm is configured (Automated) 


 # 1.1.7 (L1) Ensure noexec option set on /dev/shm partition (Automated)


 # 1.1.8 (L1) Ensure nodev option set on /dev/shm partition (Automated) 


 # 1.1.9 (L1) Ensure nosuid option set on /dev/shm partition (Automated)


 # 1.1.10 (L2) Ensure separate partition exists for /var (Automated)


 # 1.1.11 (L2) Ensure separate partition exists for /var/tmp (Automated)


 # 1.1.12 (L1) Ensure /var/tmp partition includes the noexec option (Automated) 


 # 1.1.13 (L1) Ensure /var/tmp partition includes the nodev option(Automated)


 # 1.1.14 (L1) Ensure /var/tmp partition includes the nosuid option(Automated)


 # 1.1.15 (L2) Ensure separate partition exists for /var/log (Automated)


 # 1.1.16 (L2) Ensure separate partition exists for /var/log/audit(Automated) 


 # 1.1.17 (L2) Ensure separate partition exists for /home (Automated)


 # 1.1.18 (L1) Ensure /home partition includes the nodev option(Automated)


 # 1.1.19 (L1) Ensure removable media partitions include noexec option(Automated)


 # 1.1.20 (L1) Ensure nodev option set on removable media partitions(Automated)


 # 1.1.21 (L1) Ensure nosuid option set on removable media partitions(Automated) 


 # 1.1.22 (L1) Ensure sticky bit is set on all world-writable directories(Automated)


 # 1.1.23 (L2) Disable Automounting (Automated)


 # 1.1.24 (L2) Disable USB Storage (Automated)


 # 1.2 Configure Software Updates


 # 1.2.1 (L1) Ensure GPG keys are configured (Manual)


 # 1.2.2 (L1) Ensure package manager repositories are configured(Manual)


 # 1.2.3 (L1) Ensure gpgcheck is globally activated (Automated)


 # 1.3 Filesystem Integrity Checking


 # 1.3.1 (L1) Ensure AIDE is installed (Automated)


 # 1.3 Filesystem Integrity Checking


 # 1.3.2 (L1) Ensure filesystem integrity is regularly checked(Automated) 


 # 1.4.1 (L1) Ensure bootloader password is set (Automated)


 # 1.4.2 (L1) Ensure permissions on bootloader config are configured(Automated)


 # 1.4.3 (L1) Ensure authentication required for single user mode(Automated)


 # 1.5 Additional Process Hardening


 # 1.5.1 (L1) Ensure core dumps are restricted (Automated)


 # 1.5.2 (L1) Ensure XD/NX support is enabled (Automated)


 # 1.5.3 (L1) Ensure address space layout randomization (ASLR) isenabled (Automated)


 # 1.5.4 (L1) Ensure prelink is not installed (Automated)


 # 1.6 Mandatory Access Control


 # 1.6.1 Configure SELinux


 # 1.6 Mandatory Access Control 


 # 1.6.1.1 (L1) Ensure SELinux is installed (Automated)


 # 1.6.1.2 (L1) Ensure SELinux is not disabled in bootloader configuratio(Automated) 


 # 1.6.1.3 (L1) Ensure SELinux policy is configured (Automated)


 # 1.6.1.4 (L1) Ensure the SELinux mode is enforcing or permissive(Automated)


 # 1.6.1.5 (L2) Ensure the SELinux mode is enforcing (Automated)


 # 1.6.1.6 (L1) Ensure no unconfined services exist (Automated)


 # 1.6.1.7 (L1) Ensure SETroubleshoot is not installed (Automated)


 # 1.6.1.8 (L1) Ensure the MCS Translation Service (mcstrans) is notinstalled (Automated)


 # 1.7 Command Line Warning Banners


 # 1.7.1 (L1) Ensure message of the day is configured properly(Automated) 


 # 1.7.2 (L1) Ensure local login warning banner is configured properly(Automated)


 # 1.7.3 (L1) Ensure remote login warning banner is configured properly(Automated)


 # 1.7.4 (L1) Ensure permissions on /etc/motd are configured(Automated) 


 # 1.7.5 (L1) Ensure permissions on /etc/issue are configured(Automated)


 # 1.7.6 (L1) Ensure permissions on /etc/issue.net are configured(Automated)


 # 1.8 GNOME Display Manager


 # 1.8.1 (L2) Ensure GNOME Display Manager is removed (Manual)


 # 1.8.2 (L1) Ensure GDM login banner is configured (Automated)


 # 1.8.3 (L1) Ensure last logged in user display is disabled (Automated)


 # 1.8.4 (L1) Ensure XDCMP is not enabled (Automated) 


 # 1.9 (L1) Ensure updates, patches, and additional security software are installed (Manual)


 # 2 Services


 # 2.1 inetd Services


 # 2.1.1 (L1) Ensure xinetd is not installed (Automated)


 # 2.2 Special Purpose Services

 # 2.2.1 Time Synchronization


 # 2.2.1.1 Ensure time synchronization is in use (Not Scored)


 # 2.2.1.2 Ensure ntp is configured (Scored)


 # 2.2.1.3 Ensure chrony is configured (Scored) 


 # 2.2.2 Ensure X Window System is not installed (Scored)


 # 2.2.3 Ensure Avahi Server is not enabled (Scored)


 # 2.2.4 Ensure CUPS is not enabled (Scored) 


 # 2.2.5 Ensure DHCP Server is not enabled (Scored)


 # 2.2.6 Ensure LDAP server is not enabled (Scored)


 # 2.2.7 Ensure NFS and RPC are not enabled (Scored)


 # 2.2.8 Ensure DNS Server is not enabled (Scored)


 # 2.2.9 Ensure FTP Server is not enabled (Scored)


 # 2.2.10 Ensure HTTP server is not enabled (Scored)


 # 2.2.11 Ensure IMAP and POP3 server is not enabled (Scored)


 # 2.2.12 Ensure Samba is not enabled (Scored)


 # 2.2.13 Ensure HTTP Proxy Server is not enabled (Scored)


 # 2.2.14 Ensure SNMP Server is not enabled (Scored)


 # 2.2.15 Ensure mail transfer agent is configured for local-only mode (Scored)


 # 2.2.16 Ensure NIS Server is not enabled (Scored)


 # 2.2.17 Ensure rsh server is not enabled (Scored)


 # 2.2.18 Ensure telnet server is not enabled (Scored)


 # 2.2.19 Ensure tftp server is not enabled (Scored)


 # 2.2.20 Ensure rsync service is not enabled (Scored)


 # 2.2.21 Ensure talk server is not enabled (Scored)


 # 2.3 Service Clients


 # 2.3.1 Ensure NIS Client is not installed (Scored)


 # 2.3.2 Ensure rsh client is not installed (Scored)


 # 2.3.3 Ensure talk client is not installed (Scored)


 # 2.3.4 Ensure telnet client is not installed (Scored)


 # 2.3.5 Ensure LDAP client is not installed (Scored)


 # 3 Network Configuration 


 # 3.1 Network Parameters (Host Only)


 # 3.1.1 Ensure IP forwarding is disabled (Scored)


 # 3.1.2 Ensure packet redirect sending is disabled (Scored)


 # 3.2 Network Parameters (Host and Router)


 # 3.2.1 Ensure source routed packets are not accepted (Scored)


 # 3.2.2 Ensure ICMP redirects are not accepted (Scored)


 # 3.2.3 Ensure secure ICMP redirects are not accepted (Scored) 


 # 3.2.4 Ensure suspicious packets are logged (Scored)


 # 3.2.5 Ensure broadcast ICMP requests are ignored (Scored)


 # 3.2.6 Ensure bogus ICMP responses are ignored (Scored)


 # 3.2.7 Ensure Reverse Path Filtering is enabled (Scored)


 # 3.2.8 Ensure TCP SYN Cookies is enabled (Scored)


 # 3.3 IPv6


 # 3.3.1 Ensure IPv6 router advertisements are not accepted (Not Scored)


 # 3.3.2 Ensure IPv6 redirects are not accepted (Not Scored)


 # 3.3.3 Ensure IPv6 is disabled (Not Scored)


 # 3.4 TCP Wrappers


 # 3.4.1 Ensure TCP Wrappers is installed (Scored)


 # 3.4.2 Ensure /etc/hosts.allow is configured (Scored) 


 # 3.4.3 Ensure /etc/hosts.deny is configured (Scored) 


 # 3.4.4 Ensure permissions on /etc/hosts.allow are configured (Scored)


 # 3.4.5 Ensure permissions on /etc/hosts.deny are configured (Scored) 


 # 3.5 Uncommon Network Protocols


 # 3.5.1 Ensure DCCP is disabled (Not Scored)


 # 3.5.2 Ensure SCTP is disabled (Not Scored)


 # 3.5.3 Ensure RDS is disabled (Not Scored)


 # 3.5.4 Ensure TIPC is disabled (Not Scored)


## ------------------------------------------------ 3.5 Firewall Configuration ------------------------------------------------
echo "3.5 Firewall Configuration"

## ----------------------------- 3.5.1 Configure firewalld -----------------------------

echo "3.5.1.1 Ensure firewalld is installed (Automated)"
## Run the following command to verify that FirewallID and iptables are installed

if rpm -q firewalld iptables &> /dev/null; 
then
    echo "FirewallD and iptables are installed."
    echo "No changes were made."
else   
    echo "Installing iptables..."
    dnf -y install firewalld iptables &> /dev/null
fi


echo "3.5.1.2 Ensure iptables-services not installed with firewalld (Automated)"
## Verify that the iptables-services package is not installed
## If it is, then remove them
## Running both firewalld and iptables/ip6tables service may lead to conflict

if rpm -q iptables-services &> /dev/null; 
then
    echo "Removing iptables-services."
    sudo yum -y install iptables-services
    systemctl stop iptables
    dnf -y remove iptables-services

else   
    echo "Not installed."
    echo "No changes were made."
fi


echo "3.5.1.3 Ensure nftables either not installed or masked with firewalld(Automated)"
## Verify that nftables are not installed
## Remove if installed/active
## Running both firewalld and nftables may lead to conflict.

if  rpm -q nftables &> /dev/null; 
then
    echo "Removing nftables"
    dnf -y remove nftables &> /dev/null
else
    echo "Not installed."
    echo "No changes were made."
fi


echo "3.5.1.4 Ensure firewalld service enabled and running (Automated)"
## Ensure that the firewalld.service is enabled and running to enforce firewall rules configured through firewalld


if   systemctl is-enabled firewalld &> /dev/null; 
then
    echo "firewalld service is enabled."
    echo "No changes were made."
   
else
    echo "enabling firewalld."
	sudo yum -y install firewalld
	systemctl unmask firewalld
fi

if    firewall-cmd --state &> /dev/null; 
then
    echo "firewalld is running."
   
else
    echo "Enabling firewalld."
	systemctl --now enable firewalld
fi


echo "3.5.1.5 Ensure firewalld default zone is set (Automated)"
## The default zone is the zone that is used for everything that is not explicitly bound/assigned to another zone, it is important for the default zone to set

firewall-cmd --set-default-zone=public


echo "3.5.1.6 Ensure network interfaces are assigned to appropriate zone "
## A network interface not assigned to the appropriate zone can allow unexpected or undesired network traffic to be accepted on the interface.

firewall-cmd --zone=customezone --change-interface=eth0


echo "3.5.1.7 Ensure firewalld drops unnecessary services and ports (Manual)"


## ----------------------------- 3.4.2 Configure nftables -----------------------------

echo "3.5.2.1 Ensure nftables is installed (Automated)"
##nftables is a subsystem of the Linux kernel that can protect against threats originating from within a corporate network to include malicious mobile code and poorly configured software on a host.

if  rpm -q nftables &> /dev/null; 
then
    echo "nftables are installed."
    echo "No changes were made."
else   
    echo "Installing nftables."
     dnf -y install nftables &> /dev/null
fi


echo "3.5.2.2 Ensure firewalld is either not installed or masked with nftables(Automated)"
## Running both nftables.service and firewalld.service may lead to conflict and unexpected results.

if rpm -q iptables-services &> /dev/null; 
then
   echo "Masking firwalld."
   systemctl --now mask firewalld

else   
    echo "Firewalld is masked."
    echo "No changes were made."
	systemctl --now mask firewalld
fi


echo "3.5.2.3 Ensure iptables-services not installed with nftables (Automated)"
## Running both nftables and the services included in the iptables-services package may lead to conflict.

if  rpm -q iptables-services &> /dev/null; 
then
    echo "Removing iptables-services."
    dnf -y remove iptables-services &> /dev/null
else
    echo "iptables-services are not installed."
    echo "No changes were made."
    dnf -y remove iptables-services
fi

echo "3.5.2.4 Ensure iptables are flushed with nftables (Manual)"
## nftables is a replacement for iptables, ip6tables, ebtables and arptables
## -F = flush them

iptables -F
ip6tables -F
echo "iptables were flushed."


echo "3.5.2.5 Ensure an nftables table exists (Automated)"
## nftables doesn't have any default tables. Without a table being build, nftables will not filter network traffic.



nft create table inet filter
echo "Table created."


echo "3.5.2.6 Ensure nftables base chains exist (Automated)"
## Chains are containers for rules.
## If a base chain doesn't exist with a hook for input, forward, and delete, packets that would flow through those chains will not be touched by nftables.
## Run the following commands and verify that base chains exist for INPUT, FORWARD, and OUTPUT.

nft create chain inet filter input { type filter hook input priority 0 \; }
nft create chain inet filter forward { type filter hook forward priority 0 \; }
nft create chain inet filter output { type filter hook output priority 0 \; }


echo "3.5.2.7 Ensure nftables loopback traffic is configured (Automated)"
## Configure the loopback interface to accept traffic. Configure all other interfaces to deny traffic to the loopback network

if  nft list ruleset | awk '/hook input/,/}/' | grep 'iif "lo" accept' &> /dev/null; 
then
   nft add rule inet filter input iif lo accept
   echo "Loopback traffic is configured."
   echo "No changes were made."

    
else
    echo "Configuring loopback traffic."
    nft add rule inet filter input iif lo accept
fi

echo "3.5.2.8 Ensure nftables outbound and established connections are configured (Manual)"
## If rules are not in place for new outbound and established connections, all packets will be dropped by the default policy preventing network usage.
## Run the following commands and verify all rules for established incoming connections match site policy: site policy:
    
nft list ruleset | awk '/hook input/,/}/' | grep -E 'ip protocol (tcp|udp|icmp) ct state'


nft list ruleset | awk '/hook output/,/}/' | grep -E 'ip protocol (tcp|udp|icmp) ct state'

nft add rule inet filter input ip protocol tcp ct state established accept
nft add rule inet filter input ip protocol udp ct state established accept
nft add rule inet filter input ip protocol icmp ct state established accept
nft add rule inet filter output ip protocol tcp ct state new,related,established accept
nft add rule inet filter output ip protocol udp ct state new,related,established accept
nft add rule inet filter output ip protocol icmp ct state new,related,established accept

echo "3.5.2.9 Ensure nftables default deny firewall policy (Automated)"
## Base chain policy is the default verdict that will be applied to packets reaching the end of the chain.
## Run the following commands and verify that base chains contain a policy of DROP.

nft chain inet filter input { policy drop \; }
nft chain inet filter forward { policy drop \; }
nft chain inet filter output { policy drop \; }


echo "3.5.2.10 Ensure nftables service is enabled (Automated)"
## The nftables service allows for the loading of nftables rulesets during boot, or starting on the nftables service
## Run the following command and verify that the nftables service is enabled, if not enable them

if  systemctl is-enabled nftables &> /dev/null; 
then
    systemctl enable nftables
    echo "nftables services are enabled."
    echo "No changes were made."

else   
     echo "Enabling nftables services."
     sudo yum -y install nftables
     systemctl enable nftables
fi


echo "3.5.2.11 Ensure nftables rules are permanent (Automated)"
echo "SKIP: Has to be done manually."
## A nftables ruleset containing the input, forward, and output base chains allow network traffic to be filtered.
## Run the following commands to verify that input, forward, and output base chains are configured to be applied to a nftables ruleset on boot:


## 3.4.3 Configure iptables 
## ----------------------------- 3.4.3.1 Configure iptables software ----------------------------- 


echo "3.5.3.1.1 Ensure iptables packages are installed (Automated)"
## iptables is a utility program that allows a system administrator to configure the tables 
## Run the following command to verify that iptables and iptables-services are installed


if rpm -q iptables ip tables-services &> /dev/null; 
then
    echo "iptables packages are installed."
    echo "No changes were made."

else   
    echo "Installing iptables packages."
    dnf -y install iptables iptables-services &> /dev/null
fi


echo "3.5.3.1.2 Ensure nftables is not installed with iptables (Automated)"
## Running both iptables and nftables may lead to conflict.

if rpm -q nftables &> /dev/null; 
then
    echo "Removing nftables."
    dnf remove nftables &> /dev/null
else
    echo "nftables are not installed."
    echo "No changes were made."
    
fi


echo "3.5.3.1.3 Ensure firewalld is either not installed or masked with iptables(Automated)"
## Running iptables.service and\or ip6tables.service with firewalld.service may lead to conflict and unexpected results.

if rpm -q firewalld &> /dev/null; 
then
    echo "firewalld is installed."
    dnf remove firewalld &> /dev/null
else
    echo "firewalld is not installed."
    echo "No changes were made."
    
fi

## ----------------------------- 3.4.3.2 Configure IPv4 iptables ----------------------------- 

echo "3.5.3.2.1 Ensure iptables loopback traffic is configured (Automated)"
## Run the following commands and verify output includes the listed rules in order (packet and byte counts may differ):

iptables -L INPUT -v -n

iptables -L OUTPUT -v -n

## Run the following commands to implement the loopback rules:

iptables -A INPUT -i lo -j ACCEPT

iptables -A OUTPUT -o lo -j ACCEPT

iptables -A INPUT -s 127.0.0.0/8 -j DROP

echo "3.5.3.2.2 Ensure iptables outbound and established connections are configured (Manual)"
## Run the following command and verify all rules for new outbound, and established connections match site policy:
iptables -L -v -n

## The following commands will implement a policy to allow all outbound connections and all established connections:
iptables -A OUTPUT -p tcp -m state --state NEW,ESTABLISHED -j ACCEPT

iptables -A OUTPUT -p udp -m state --state NEW,ESTABLISHED -j ACCEPT

iptables -A OUTPUT -p icmp -m state --state NEW,ESTABLISHED -j ACCEPT

iptables -A INPUT -p tcp -m state --state ESTABLISHED -j ACCEPT

iptables -A INPUT -p udp -m state --state ESTABLISHED -j ACCEPT

iptables -A INPUT -p icmp -m state --state ESTABLISHED -j ACCEPT

echo "3.5.3.2.3 Ensure iptables rules exist for all open ports (Automated)"
## Run the following command to determine open ports:

ss -4tuln

## Run the following command to determine firewall rules:

iptables -L INPUT -v -n


echo "3.5.3.2.4 Ensure iptables default deny firewall policy (Automated)"
## Run the following command and verify that the policy for the INPUT , OUTPUT , and FORWARD chains is DROP or REJECT :
iptables -L

## Run the following commands to implement a default DROP policy:
iptables -p INPUT DROP
iptables -p OUTPUT DROP
iptables -P FORWARD DROP


echo "3.5.3.2.5 Ensure iptables rules are saved (Automated)"
## If the iptables rules are not saved and a system re-boot occurs, the iptables rules will be lost.
## Run the following command to save the verified running configuration to the file /etc/sysconfig/iptables:

service iptables save


echo "3.5.3.2.6 Ensure iptables is enabled and active (Automated)"
## iptables.service is a utility for configuring and maintaining iptables.

if systemctl is-active iptables | grep "active" &> /dev/null; 
then
    echo "iptables is activated."
    echo "No changes were made."

else
    echo "Activating iptables."
    systemctl --now enable iptables
fi

## -----------------------------  3.4.3.3 Configure IPv6 ip6tables  ----------------------------- 


echo "3.5.3.3.1 Ensure ip6tables loopback traffic is configured (Automated)"
## Configure the loopback interface to accept traffic. Configure all other interfaces to deny traffic to the loopback network (::1).

ip6tables -A INPUT -i lo -j ACCEPT ip6tables -A OUTPUT -o lo -j ACCEPT ip6tables -A INPUT -s ::1 -j DROP 


echo "3.5.3.3.2 Ensure ip6tables outbound and established connections areconfigured (Manual)"
## The following commands will implement a policy to allow all outbound connections and all established connections:
ip6tables -A OUTPUT -p tcp -m state --state NEW,ESTABLISHED -j ACCEPT 

ip6tables -A OUTPUT -p udp -m state --state NEW,ESTABLISHED -j ACCEPT 

ip6tables -A OUTPUT -p icmp -m state --state NEW,ESTABLISHED -j ACCEPT 

ip6tables -A INPUT -p tcp -m state --state ESTABLISHED -j ACCEPT 

ip6tables -A INPUT -p udp -m state --state ESTABLISHED -j ACCEPT 

ip6tables -A INPUT -p icmp -m state --state ESTABLISHED -j ACCEPT 

echo "3.5.3.3.3 Ensure ip6tables firewall rules exist for all open ports(Automated)"
## Run the following command to determine open ports:
echo "Open Ports: "
ss -4tuln

## Run the following command to determine firewall rules:

echo "Firewall rules: "
iptables -L INPUT -v -n


echo "3.5.3.3.4 Ensure ip6tables default deny firewall policy (Automated)"
## Run the following command and verify that the policy for the INPUT, OUTPUT, and FORWARD chains is DROP or REJECT:
ip6tables -P INPUT DROP

ip6tables -P OUTPUT DROP

ip6tables -P FORWARD DROP


echo "3.5.3.3.5 Ensure ip6tables rules are saved (Automated)"
## Run the following command to save the verified running configuration to the file /etc/sysconfig/ip6tables:
service ip6tables save


echo "3.5.3.3.6 Ensure ip6tables is enabled and active (Automated)"
## Run the following commands to verify ip6tables is enabled, and start if not enabled.

if systemctl is-active ip6tables | grep "active" &> /dev/null; 
then
    echo "ip6tables is activated."
    echo "No changes were made."
else
    echo "Activating ip6tables."
    systemctl --now start ip6tables
fi


echo "Firewall hardening is finished."


 # 4 Logging and Auditing 


 # 4.1 Configure System Accounting (auditd)


 # 4.1.1.1 Ensure audit log storage size is configured (Not Scored) 


 # 4.1.1.2 Ensure system is disabled when audit logs are full (Scored) 


 # 4.1.1.3 Ensure audit logs are not automatically deleted (Scored)


 # 4.1.2 Ensure auditd service is enabled (Scored) 


 # 4.1.3 Ensure auditing for processes that start prior to auditd is enabled (Scored) 205 4.1.4 Ensure events that modify date and time information are collected (Scored) 


 #4.1.5 Ensure events that modify user/group information are collected (Scored)


 # 4.1.6 Ensure events that modify the system's network environment are collected (Scored)


 # 4.1.7 Ensure events that modify the system's Mandatory Access Controls are collected (Scored)


 # 4.1.8 Ensure login and logout events are collected (Scored)


 # 4.1.9 Ensure session initiation information is collected (Scored)


 # 4.1.10 Ensure discretionary access control permission modification events are collected (Scored)


 # 4.1.11 Ensure unsuccessful unauthorized file access attempts are collected (Scored)


 # 4.1.12 Ensure use of privileged commands is collected (Scored)


 # 4.1.13 Ensure successful file system mounts are collected (Scored)


 # 4.1.14 Ensure file deletion events by users are collected (Scored)


 # 4.1.15 Ensure changes to system administration scope (sudoers) is collected (Scored)


 # 4.1.16 Ensure system administrator actions (sudolog) are collected (Scored)


 # 4.1.17 Ensure kernel module loading and unloading is collected (Scored)


 # 4.1.18 Ensure the audit configuration is immutable (Scored).


 # 4.2 Configure Logging


 # 4.2.1.1 Ensure rsyslog Service is enabled (Scored)


 # 4.2.1.2 Ensure logging is configured (Not Scored) 


 # 4.2.1.3 Ensure rsyslog default file permissions configured (Scored)


 # 4.2.1.4 Ensure rsyslog is configured to send logs to a remote log host (Scored)


 # 4.2.1.5 Ensure remote rsyslog messages are only accepted on designated log hosts. (Not Scored).


 # 4.2.2.1 Ensure syslog-ng service is enabled (Scored)


 # 4.2.2.2 Ensure logging is configured (Not Scored) 


 # 4.2.2.3 Ensure syslog-ng default file permissions configured (Scored)


 # 4.2.2.4 Ensure syslog-ng is configured to send logs to a remote log host (Not Scored) 


 # 4.2.2.5 Ensure remote syslog-ng messages are only accepted on designated log hosts (Not Scored)


 # 4.2.3 Ensure rsyslog or syslog-ng is installed (Scored)


 # 4.2.4 Ensure permissions on all logfiles are configured (Scored)


 # 4.3 Ensure logrotate is configured (Not Scored)


 # 5 Access, Authentication and Authorization


 # 5.1 Configure cron


 # 5.1.1 Ensure cron daemon is enabled (Scored)


 # 5.1.2 Ensure permissions on /etc/crontab are configured (Scored) 


 # 5.1.3 Ensure permissions on /etc/cron.hourly are configured (Scored)


 # 5.1.4 Ensure permissions on /etc/cron.daily are configured (Scored)


 # 5.1.5 Ensure permissions on /etc/cron.weekly are configured (Scored)


 # 5.1.6 Ensure permissions on /etc/cron.monthly are configured (Scored)


 # 5.1.7 Ensure permissions on /etc/cron.d are configured (Scored)


 # 5.1.8 Ensure at/cron is restricted to authorized users (Scored)


 # 5.2 SSH Server Configuration


 # 5.2.1 Ensure permissions on /etc/ssh/sshd_config are configured (Scored)


 # 5.2.2 Ensure SSH Protocol is set to 2 (Scored)


 # 5.2.3 Ensure SSH LogLevel is set to INFO (Scored)


 # 5.2.4 Ensure SSH X11 forwarding is disabled (Scored)


 # 5.2.5 Ensure SSH MaxAuthTries is set to 4 or less (Scored)


 # 5.2.6 Ensure SSH IgnoreRhosts is enabled (Scored)


 # 5.2.7 Ensure SSH HostbasedAuthentication is disabled (Scored)


 # 5.2.8 Ensure SSH root login is disabled (Scored)


 # 5.2.9 Ensure SSH PermitEmptyPasswords is disabled (Scored)


 # 5.2.10 Ensure SSH PermitUserEnvironment is disabled (Scored)


 # 5.2.11 Ensure only approved MAC algorithms are used (Scored)


 # 5.2.12 Ensure SSH Idle Timeout Interval is configured (Scored) 


 # 5.2.13 Ensure SSH LoginGraceTime is set to one minute or less (Scored)


 # 5.2.14 Ensure SSH access is limited (Scored)


 # 5.2.15 Ensure SSH warning banner is configured (Scored)


 # 5.3 Configure PAM


 # 5.3.1 Ensure password creation requirements are configured (Scored) 


 # 5.3.2 Ensure lockout for failed password attempts is configured (Scored)


 # 5.3.3 Ensure password reuse is limited (Scored)


 # 5.3.4 Ensure password hashing algorithm is SHA-512 (Scored)


 # 5.4 User Accounts and Environment 


 # 5.4.1.1 Ensure password expiration is 365 days or less (Scored)


 # 5.4.1.2 Ensure minimum days between password changes is 7 or more (Scored) 


 # 5.4.1.3 Ensure password expiration warning days is 7 or more (Scored)


 # 5.4.1.4 Ensure inactive password lock is 30 days or less (Scored)


 # 5.4.1.5 Ensure all users last password change date is in the past (Scored)


 # 5.4.2 Ensure system accounts are non-login (Scored)


 # 5.4.3 Ensure default group for the root account is GID 0 (Scored)


 # 5.4.4 Ensure default user umask is 027 or more restrictive (Scored)


 # 5.4.5 Ensure default user shell timeout is 900 seconds or less (Scored)


 # 5.5 Ensure root login is restricted to system console (Not Scored)


 # 5.6 Ensure access to the su command is restricted (Scored)


 # 6 System Maintenance


 # 6.1 System File Permissions


 # 6.1.1 Audit system file permissions (Not Scored)


 # 6.1.2 Ensure permissions on /etc/passwd are configured (Scored) 


 # 6.1.3 Ensure permissions on /etc/shadow are configured (Scored)


 # 6.1.4 Ensure permissions on /etc/group are configured (Scored)


 # 6.1.5 Ensure permissions on /etc/gshadow are configured (Scored)


 # 6.1.6 Ensure permissions on /etc/passwd- are configured (Scored)


 # 6.1.7 Ensure permissions on /etc/shadow- are configured (Scored)


 # 6.1.8 Ensure permissions on /etc/group- are configured (Scored) 


 # 6.1.9 Ensure permissions on /etc/gshadow- are configured (Scored) 


 # 6.1.10 Ensure no world writable files exist (Scored)


 # 6.1.11 Ensure no unowned files or directories exist (Scored)


 # 6.1.12 Ensure no ungrouped files or directories exist (Scored)


 # 6.1.13 Audit SUID executables (Not Scored)


 # 6.1.14 Audit SGID executables (Not Scored)


 # 6.2 User and Group Settings


 # 6.2.1 Ensure password fields are not empty (Scored)


 # 6.2.2 Ensure no legacy "+" entries exist in /etc/passwd (Scored)


 # 6.2.3 Ensure no legacy "+" entries exist in /etc/shadow (Scored)


 # 6.2.4 Ensure no legacy "+" entries exist in /etc/group (Scored) 


 # 6.2.5 Ensure root is the only UID 0 account (Scored)


 # 6.2.6 Ensure root PATH Integrity (Scored) 


 # 6.2.7 Ensure all users' home directories exist (Scored)


 # 6.2.8 Ensure users' home directories permissions are 750 or more restrictive (Scored)


 # 6.2.9 Ensure users own their home directories (Scored)


 # 6.2.10 Ensure users' dot files are not group or world writable (Scored)


 # 6.2.11 Ensure no users have .forward files (Scored)


 # 6.2.12 Ensure no users have .netrc files (Scored)


 # 6.2.13 Ensure users' .netrc Files are not group or world accessible (Scored)


 # 6.2.14 Ensure no users have .rhosts files (Scored)


 # 6.2.15 Ensure all groups in /etc/passwd exist in /etc/group (Scored)


 # 6.2.16 Ensure no duplicate UIDs exist (Scored)


 # 6.2.17 Ensure no duplicate GIDs exist (Scored)


 # 6.2.18 Ensure no duplicate user names exist (Scored)


 # 6.2.19 Ensure no duplicate group names exist (Scored)



else
    echo "Incompatable Operating System"
fi

