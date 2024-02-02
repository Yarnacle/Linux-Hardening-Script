#!/bin/bash

if [[ $EUID -ne 0 ]]; then
   echo "Script must be run with sudo"
   exit 1
fi

YELLOW='\e[33m'
PURPLE='\e[35m'
GREEN='\e[32m'
RED='\e[31m'
CLEAR='\e[0m'

function get_index() {
	local -n my_array=$1 # use -n for a reference to the array
	for i in "${!my_array[@]}"; do
		if [[ ${my_array[i]} = $2 ]]; then
			printf '%s\n' "$i"
			return
		fi
	done
	echo -1
	return 1
}

# Update package index
echo -ne "${PURPLE}Do you want to update the package index? (y/n) ${CLEAR}"
read yn
if [ "$yn" == 'y' ]; then
	echo "Updating package index..."
	apt update
	echo "Done updating package index"
fi

# Upgrade packages
echo -ne "${PURPLE}Do you want to upgrade packages? (y/n) ${CLEAR}"
read yn
if [ "$yn" == 'y' ]; then
	echo "Upgrading packages..."
	apt upgrade -y
	echo "Done upgrading packages"
fi

# Daily updating
echo -ne "${PURPLE}Do you want to enable daily updating? (y/n) ${CLEAR}"
read yn
if [ "$yn" == 'y' ]; then
	echo "Enabling daily updating..."
	echo 'APT::Periodic::Update-Package-Lists "1";' | sudo tee /etc/apt/apt.conf.d/20auto-upgrades
	echo 'APT::Periodic::Unattended-Upgrade "1";' | sudo tee -a /etc/apt/apt.conf.d/20auto-upgrades
	echo "Done enabling daily updating"
fi

# User priveleges
echo -ne "${PURPLE}Do you want to check user priveleges? (y/n) ${CLEAR}"
read yn

if [ "$yn" == 'y' ]; then
	echo -ne "Expected sudo users separated by spaces: "
	read -a expected_sudo_users
	echo -ne "Expected regular users separated by spaces: "
	read -a expected_regular_users

	echo "Checking sudo users..."
	sudo_users=()
	while IFS= read -r user; do
		sudo_users+=("$user")
		i=$(get_index expected_sudo_users "$user")

  		if [ $i != -1 ]; then
			echo -e "${GREEN}${user} is an expected sudo user${CLEAR}"
			unset expected_sudo_users[$i]
		else
			echo -e "${RED}${user} is not an expected sudo user${CLEAR}"
		fi
	done < <(grep -Po '^sudo.+:\K.*$' /etc/group | tr ',' '\n')

	for file in /etc/sudoers.d/*; do
  		while IFS= read -r user; do
			sudo_users+=("$user")
			i=$(get_index expected_sudo_users "$user")

    		if [ $i != -1 ]; then
			echo -e "${GREEN}${user} is an expected sudo user${CLEAR}"
			unset expected_sudo_users[$i]
		else
			echo -e "${RED}${user} is not an expected sudo user${CLEAR}"
		fi
  		done < <(grep -Po '^sudo.+:\K.*$' "$file" | tr ',' '\n')
	done

	for user in "${expected_sudo_users[@]}"; do
		echo -e "${YELLOW}Expected sudo user ${user} was not found${CLEAR}"
	done
	echo "Done checking sudo users"

	echo "Checking regular users..."
	all_users=$(getent passwd | cut -d: -f1)

	for user in $all_users; do
		uid=$(id -u $user)
		if [[ $uid -ge 1000 && $uid -le 60000 && $user != "root" && $user != "nobody" && $(get_index sudo_users "$user") == -1 ]]; then
			i=$(get_index expected_regular_users "$user")

			if [ $i != -1 ]; then
				echo -e "${GREEN}${user} is an expected regular user${CLEAR}"
				unset expected_regular_users[$i]
			else
				echo -e "${RED}${user} is not an expected regular user${CLEAR}"
			fi
		fi
	done

	for user in "${expected_regular_users[@]}"; do
		echo -e "${YELLOW}Expected regular user ${user} was not found${CLEAR}"
	done
	echo "Done checking regular users"
fi

# Passwords
echo -ne "${PURPLE}Do you want to set passwords? (y/n) ${CLEAR}"
read yn
if [ "$yn" == 'y' ]; then
	if ! dpkg -s openssl &> /dev/null; then
		echo -e "${RED}OpenSSL is not installed on this system."
		echo -ne "Would you like to install OpenSSL? (y/n) ${CLEAR}"
		read yn
		if [ "$yn" == 'y' ]; then
			echo "Installing OpenSSL..."
			apt install openssl -y
			echo "Done installing OpenSSL"
		fi
	fi
	if [ "$yn" == 'y' ]; then # if they don't want to install OpenSSL, then exit OpenSSL section
		echo "Setting passwords..."
		password="Cyb3rPatr!0t$"
		for user in $(getent passwd | cut -d: -f1); do
			uid=$(id -u $user)
			if [[ $uid -ge 1000 && $uid -le 60000 && $user != "root" && $user != "nobody" ]]; then
				usermod --password "$(echo $password | openssl passwd -1 -stdin)" $user
				echo "Set password for user $user"
			fi
		done
		echo "Done setting passwords"
	fi
fi

# Network
echo -ne "${PURPLE}Do you want to configure networking? (y/n) ${CLEAR}"
read yn
if [ "$yn" == 'y' ]; then
	if ! command -v ufw &> /dev/null; then
    		echo -e "${RED}UFW is not installed on this system."
		echo -ne "Would you like to install UFW? (y/n) ${CLEAR}"
		read yn
		if [ "$yn" == 'y' ]; then
			echo "Installing UFW..."
			apt-get install ufw -y
			echo "Done installing UFW"
		fi
	fi
	if [ "$yn" == 'y' ]; then # if they don't want to install UFW, then exit UFW section
		echo "Enabling UFW..."
		ufw enable
		echo "Done enabling UFW"
		
		echo "Configuring UFW..."
		ufw default deny incoming
		ufw default allow outgoing
		echo "Done configuring UFW"

		echo "Enabling syn cookie protection..."
		sysctl -n net.ipv4.tcp_syncookies
		echo "Done enabling syn cookie protection"

		echo "Disabling IPv6..."
		echo "net.ipv6.conf.all.disable_ipv6 = 1" | sudo tee -a /etc/sysctl.conf
		echo "Done disabling IPv6"

		echo "Disabling IP forwarding..."
		echo 0 | sudo tee /proc/sys/net/ipv4/ip_forward
		echo "Done disabling IP forwarding"

		echo "Preventing IP spoofing..."
		echo "nospoof on" | sudo tee -a /etc/host.conf
		echo "Done preventing IP spoofing"
		echo "Done securing network"

		echo -e "${YELLOW}UFW rules:${CLEAR}"
		if [[ -n $(sudo ufw status | grep "Status: active") ]]; then
    			echo "none"
		else
			ufw status numbered
		fi
		
		echo -e "${YELLOW}Open ports:${CLEAR}"
		sudo ss -ln
	fi
fi

# Auth config
echo -ne "${PURPLE}Do you want to configure authentication security? (y/n) ${CLEAR}"
read yn
if [ "$yn" == 'y' ]; then
	if ! dpkg -s lightdm &> /dev/null; then
    		echo -e "${RED}LightDM is not installed on this system."
		echo -ne "Would you like to install LightDM? (y/n) ${CLEAR}"
		read yn
		if [ "$yn" == 'y' ]; then
			echo "Installing LightDM..."
			apt install lightdm -y
			echo "Done installing LightDM"
		fi
	fi
	if [ "$yn" == 'y' ]; then # if they don't want to install LightDM, then exit LightDM section
		echo "Turning off guest account..."
		echo "allow-guest=false" >> /etc/lightdm/lightdm.conf
		echo "Done turning off guest account"

		echo "Securing root..."
		passwd -l root
		if grep -qF 'PermitRootLogin' /etc/ssh/sshd_config; then
			sed -i 's/^.*PermitRootLogin.*$/PermitRootLogin no/' /etc/ssh/sshd_config; else echo 'PermitRootLogin no' >> /etc/ssh/sshd_config;
		fi
		echo "Done securing root"
		
		echo "Configuring PAM and password history..."
		sudo sed -i '1 s/^/auth optional pam_tally.so deny=5 unlock_time=1800 onerr=fail audit even_deny_root_account silent\n/' /etc/pam.d/common-auth
		sed -i 's/\(pam_unix\.so.*\)$/\1 remember=5 minlen=8/' /etc/pam.d/common-password
		sed -i 's/\(pam_cracklib\.so.*\)$/\1 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1/' /etc/pam.d/common-password
		sed -i 's/PASS_MAX_DAYS.*$/PASS_MAX_DAYS 90/;s/PASS_MIN_DAYS.*$/PASS_MIN_DAYS 10/;s/PASS_WARN_AGE.*$/PASS_WARN_AGE 7/' /etc/login.defs
		echo "Done configuring PAM and password history"
	fi
fi

# Bad packages
echo -ne "${PURPLE}Do you want to check for bad packages? (y/n) ${CLEAR}"
read yn
if [ "$yn" == 'y' ]; then
	bad=("john" "nmap" "vuze" "frostwire" "kismet" "freeciv" "minetest" "minetest-server" "medusa" "hydra" "truecrack" "ophcrack" "nikto" "cryptcat" "nc" "netcat" "tightvncserver" "x11vnc" "nfs" "xinetd" "rlogind" "rshd" "rcmd" "rexecd" "rbootd" "rquotad" "rstatd" "rusersd" "rwalld" "rexd" "fingerd" "tftpd" "telnet" "snmp" "minetest-data" "libwireshark-data" "libwireshark15":"amd64" "wireshark" "wireshark-common" "wireshark-qt" "netcat-openbsd" "freeciv-client-gtk3" "freeciv-data" "freeciv-server" "hunt" "dsniff" "endless-sky" "endless-sky-data" "ettercap-common" "ettercap-graphical" "nmap-common" "p0f" "nbtscan" "john-data" "hydra-gtk" "libpcap" "zenmap" "nitko")
	echo "Checking for bad packages..."
	for package in "${bad[@]}"; do
		if dpkg -s "$package" > /dev/null 2>&1; then
			echo -e "${RED} $package is a bad package${CLEAR}"
		fi
	done
	echo "Done checking for bad packages"

	echo "Checking for potential risk packages..." 
	risk=("samba" "postgresql" "sftpd" "vsftpd" "apache" "apache2" "ftp" "mysql" "php" "snmp" "pop3" "icmp" "sendmail" "dovecot" "bind9" "nginx")
	for package in "${risk[@]}"; do
		if dpkg -s "$package" > /dev/null 2>&1; then
			echo -e "${YELLOW} $package is a potential risk package${CLEAR}"
		fi
	done
	echo "Done checking for potential risk packages"
fi

# Crontab
echo -ne "${PURPLE}Do you want to check for cron jobs? (y/n) ${CLEAR}"
read yn
if [ "$yn" == 'y' ]; then
	echo "Checking cron jobs..."
	for user in $(cut -f1 -d: /etc/passwd); do
		crontab_exists=$(sudo -u $user crontab -l 2>/dev/null)
		if [ -n "$crontab_exists" ]; then
			echo "${YELLOW}Crontab found for user $user${CLEAR}:"
			echo "$crontab_exists"
		fi
	done
	echo "Done checking cron jobs"
fi

# Prohibited files
echo -ne "${PURPLE}Do you want to search for prohibited files? ${YELLOW}WARNING: This may take a long time ${PURPLE}(y/n) ${CLEAR}"
read yn
if [ "$yn" == 'y' ]; then
	rm possible_prohibited_files.txt -f
	echo "Searching for prohibited files..."

	printf "\nImages:\n\n" >> possible_prohibited_files.txt
	find / -type f -name "*.jpg" -o -name "*.jpeg" -o -name "*.gif" -o -name "*.png" -o -name "*.bmp" >> possible_prohibited_files.txt

	printf "\nVideos:\n\n" >> possible_prohibited_files.txt
	find / -type f -name "*.mp4" -o -name "*.mov" -o -name "*.wmv" -o -name "*.avi" -o -name "*.mkv" >> possible_prohibited_files.txt

	printf "\nMusic:\n\n" >> possible_prohibited_files.txt
	find / -type f -name "*.mp3" -o -name "*.aac" -o  -name "*.flac" -o -name "*.alac" -o -name "*.wav">> possible_prohibited_files.txt

	echo "Done searching for prohibited files"
fi

# Reinstall
echo -ne "${PURPLE}Do you want to reinstall everything? ${YELLOW}WARNING: This may take a long time ${PURPLE}(y/n) ${CLEAR}"
read yn
if [ "$yn" == 'y' ]; then
	apt-get -V -y install --reinstall coreutils
fi
