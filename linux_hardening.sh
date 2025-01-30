#!/bin/bash

# Universal Linux Hardening Script
# Supports Ubuntu, Debian, CentOS, Fedora, Arch Linux

LOGFILE="/var/log/linux_hardening.log"
NC="\e[0m" 
BOLD="\e[1m" 
R="\e[1;31m" 
G="\e[1;32m" 
Y="\e[1;33m" 
C="\e[1;36m" 
W="\e[1;37m" 

# Ensure script is run as root
if [ $UID -ne 0 ]; then
    echo -e "${R}[!] Run the script as root${NC}"
    exit 1
fi

# Detect Linux Distribution and Package Manager
if command -v apt &>/dev/null; then
    PM="apt"
elif command -v dnf &>/dev/null; then
    PM="dnf"
elif command -v yum &>/dev/null; then
    PM="yum"
elif command -v pacman &>/dev/null; then
    PM="pacman"
else
    echo -e "${R}[!] Unsupported Linux Distribution${NC}"
    exit 1
fi

echo "$(date) - Script started on $(uname -a)" >> $LOGFILE

# System Update
update_system() {
    echo -e "${C}[+] Updating System Packages...${NC}"
    if [ "$PM" == "apt" ]; then
        apt update -y && apt upgrade -y
    elif [ "$PM" == "dnf" ] || [ "$PM" == "yum" ]; then
        $PM update -y && $PM upgrade -y
    elif [ "$PM" == "pacman" ]; then
        pacman -Syu --noconfirm
    fi
    echo -e "${G}[✔] System Updated!${NC}"
}

# Firewall Setup
setup_firewall() {
    echo -e "${C}[+] Configuring Firewall...${NC}"
    if command -v ufw &>/dev/null; then
        ufw enable && ufw default deny incoming && ufw default allow outgoing
        echo -e "${G}[✔] UFW Configured${NC}"
    elif command -v firewalld &>/dev/null; then
        systemctl enable firewalld && systemctl start firewalld
        echo -e "${G}[✔] Firewalld Configured${NC}"
    elif command -v iptables &>/dev/null; then
        iptables -P INPUT DROP
        iptables -P FORWARD DROP
        iptables -P OUTPUT ACCEPT
        echo -e "${G}[✔] Iptables Configured${NC}"
    else
        echo -e "${R}[!] No Firewall Found${NC}"
    fi
}

# SSH Hardening
harden_ssh() {
    echo -e "${C}[+] Hardening SSH...${NC}"
    sed -i 's/#PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config
    sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
    systemctl restart sshd
    echo -e "${G}[✔] SSH Hardened${NC}"
}

# Kernel Hardening
harden_kernel() {
    echo -e "${C}[+] Applying Kernel Hardening...${NC}"
    echo 'net.ipv4.tcp_syncookies=1' >> /etc/sysctl.conf
    echo 'net.ipv4.conf.all.rp_filter=1' >> /etc/sysctl.conf
    echo 'kernel.dmesg_restrict=1' >> /etc/sysctl.conf
    echo 'net.ipv6.conf.all.disable_ipv6=1' >> /etc/sysctl.conf
    echo 'net.ipv6.conf.default.disable_ipv6=1' >> /etc/sysctl.conf
    sysctl -p
    echo -e "${G}[✔] Kernel Security Applied${NC}"
}

# Install Fail2Ban
install_fail2ban() {
    echo -e "${C}[+] Installing Fail2Ban...${NC}"
    if [ "$PM" == "apt" ]; then
        apt install fail2ban -y
    elif [ "$PM" == "dnf" ] || [ "$PM" == "yum" ]; then
        $PM install fail2ban -y
    elif [ "$PM" == "pacman" ]; then
        pacman -S fail2ban --noconfirm
    fi
    systemctl enable --now fail2ban
    echo -e "${G}[✔] Fail2Ban Installed & Configured${NC}"
}

# Disable USB Storage
disable_usb() {
    echo -e "${C}[+] Disabling USB Storage...${NC}"
    echo "blacklist usb_storage" >> /etc/modprobe.d/blacklist.conf
    echo -e "${G}[✔] USB Storage Disabled${NC}"
}

# Secure GRUB
secure_grub() {
    echo -e "${C}[+] Securing GRUB...${NC}"
    grub-mkpasswd-pbkdf2 | tee /etc/grub.d/40_custom
    update-grub
    echo -e "${G}[✔] GRUB Secured${NC}"
}

# Enforce Strong Password Policies
enforce_password_policy() {
    echo -e "${C}[+] Enforcing Strong Password Policies...${NC}"
    if [ "$PM" == "apt" ]; then
        apt install libpam-pwquality -y
    elif [ "$PM" == "dnf" ] || [ "$PM" == "yum" ]; then
        $PM install pam_pwquality -y
    elif [ "$PM" == "pacman" ]; then
        pacman -S pam --noconfirm
    fi
    echo "password requisite pam_pwquality.so retry=3 minlen=12 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1" >> /etc/security/pwquality.conf
    echo -e "${G}[✔] Password Policies Enforced${NC}"
}

# Main Menu
while true; do
    clear
    echo -e "${BOLD}Linux Hardening Script - Menu${NC}"
    echo -e "1) Update System"
    echo -e "2) Setup Firewall"
    echo -e "3) Harden SSH"
    echo -e "4) Kernel Hardening"
    echo -e "5) Install Fail2Ban"
    echo -e "6) Disable USB Storage"
    echo -e "7) Secure GRUB"
    echo -e "8) Enforce Strong Password Policies"
    echo -e "0) Exit"
    echo -n "Select an option: "
    read option

    case $option in
        1) update_system ;;
        2) setup_firewall ;;
        3) harden_ssh ;;
        4) harden_kernel ;;
        5) install_fail2ban ;;
        6) disable_usb ;;
        7) secure_grub ;;
        8) enforce_password_policy ;;
        0) echo -e "${G}[✔] Exiting...${NC}"; exit 0 ;;
        *) echo -e "${R}[!] Invalid Option!${NC}" ;;
    esac
    echo -e "${C}Press Enter to Continue...${NC}"
    read
done
