#!/bin/bash

## *-----------------* CIS Compliant Firewall Registry CentOS 7 *-----------------* 

## Check if its Linux
if [[ "$OSTYPE" == "linux-gnu"* ]]; 
then

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

## 3.4 Firewall Configuration

## ----------------------------- 3.4.1 Configure firewalld -----------------------------

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


else
    echo "Incompatable Operating System"
fi

