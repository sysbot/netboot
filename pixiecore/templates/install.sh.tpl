#!/bin/bash -x
# Bastion IP: {{ ServerIP }}
# For use on USB, copy this file as /<usb>/cumulus-ztp

# ============================== Error handling ==============================
# Log all output from this script
exec >/var/log/autoprovision 2>&1
date "+%FT%T ztp starting script $0"
set -e
function error() {
  echo -e "\e[0;33mERROR: The install script failed while running the command $BASH_COMMAND at line $BASH_LINENO.\e[0m" >&2
  exit 1
}
trap error ERR

exec 2>&1

# ============================== OOB access ==============================
mkdir -pm 700 /root/.ssh
cat > /root/.ssh/authorized_keys <<EOF
# bao
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQDQkNuY7Ci1Nv4qG2haApZpGN/3uC4moeiQH3/GoN+6++RIHME28Y+LoufDLp6kkE8ZHJWt1ZbKo1e5KMjcDqiGU9BIopC3IYjgQUBxy+YYd//59lCd2xly3vmxs0d6TvV/6Agp/9ZO8cg6vEfrCOUclmM9eMPIvZ6aL7M6JRkC8A5cWOiWOvyOJ/O5N3wPhuOoITZ3pbOI6Ao6GlYosO7EwGl1KG5C8XhZos4aVvrF9XSpPmXj3SH1pi5JM4/AbqGBrrFLXw9LLEGwlrZHwFd9e456LuHVFQ0fjapqxudLLtEiZ8QZgjkolTV3ZMiVXsHd+lY9Me5aTm9VM//XV4YGf1chFYBRDn4D/kZnEhwLhiChGWkUUR0rEwQ3O5MgXR3FL2MgL49EV/2v621c3m6uQciQYu81e5MDl671OAQIMUTzB4in1Oh9quwcXCmp3A5HXwS4m0Iu/OKLvOhIJJUSZExPrq8yfZglQVIRsofqzt2QB33u8Poq/MEjZSc5KApdU4mEdQGWoZEspsqnHB7MMYrp+Jy02J9CRHGmBHXRNOhf+UUJyY906Khc4xBdlnp7vVZj18kNf9evenGMREx0Jxu/982Iwpc5KDye+hR0yeefcao+1mC3hP2A/Qs1Fb0E0PKbRG4nXOpSK
# disposable
ecdsa-sha2-nistp521 AAAAE2VjZHNhLXNoYTItbmlzdHA1MjEAAAAIbmlzdHA1MjEAAACFBAB7adhtxfKa/u1cj6lTWedJE5Q2jj8/l44r/AR8G9JMSsMSg1twrX0U6CiffNUUnuss4MgQkBJBrQQ920PJo6qR9QEtTffvpQQG1Ra75wicY4KIw9vecCseRf4qvUMD/u53yRFXLEhKN9e6fSJvrThKZELy/HNZDF4HKJogG++0kN87lA==
EOF
chmod 0600 /root/.ssh/authorized_keys && chown -R root:root /root/.ssh


# =================================== Clock ==================================
# we'll need the correct time in order to validate certs below
# temporary stop ntp.service, this will restart on reboot
apt-get update
apt-get install ntpdate
systemctl stop ntp.service || true  # Ignore error if any.
ntpdate -u {{ MyNTPServer }}
systemctl start ntp.service || true

# ensure this set to hwclock as well
hwclock --systohc --localtime

# ================================== Debian ==================================
# Add Debian Repositories
cat > /etc/apt/sources.list.d/debian.list <<EOF
deb http://http.us.debian.org/debian jessie main
deb http://security.debian.org/ jessie/updates main
EOF
# Update Packages
apt-get update
apt-get upgrade -y
apt-get install -y python3 python3-dev build-essential software-properties-common python3-apt

# configs the interfaces
rm -rf /etc/network/interfaces
cat > /etc/network/interfaces <<EOF
#-------------------------------- Management ---------------------------------
# The loopback network interface
auto lo
iface lo inet loopback

# The primary network interface
auto eth0
iface eth0 inet manual
    # address 10.3.0.252
    # netmask 255.255.255.0
    # gateway 10.3.0.251/24

#--------------------------------- Outbound ----------------------------------
{{ range $k, $v := MyInterfaces -}}
auto {{ $k }}
iface {{ $k }}
      # {{ $v }}

{{ end }}

# And the bridge for them.
auto bridge
iface bridge
    bridge-vids 1
    bridge-ports glob swp1-52
    # bridge-ageing 150
    # bridge-stp on
    bridge-vlan-aware yes

#------------------------------- VLAN configs --------------------------------
auto vlan_main
iface vlan_main
    vlan-id 1
    vlan-raw-device bridge
    address 10.3.0.252
    netmask 255.255.255.0
    # Bastion NATs for us.
    gateway 10.3.0.251
EOF

# #--------------------------------- Outbound ----------------------------------
# # Despite no connection between this and the other switches, I keep it on vlan
# # just in case.

# # Server 1
# auto swp1
# iface swp1
#     bridge-access 1

# # Server 2
# auto swp2
# iface swp2
#     bridge-access 1

# # Server 3
# auto swp3
# iface swp3
#     bridge-access 1

# # Server 4
# auto swp4
# iface swp4
#     bridge-access 1

# # Server 5
# auto swp5
# iface swp5
#     bridge-access 1

# # Server 6
# auto swp6
# iface swp6
#     bridge-access 1

# # Server 7
# auto swp7
# iface swp7
#     bridge-access 1

# # Server 8
# auto swp8
# iface swp8
#     bridge-access 1

# # Server 9
# auto swp9
# iface swp9
#     bridge-access 1

# # Server 10
# auto swp10
# iface swp10
#     bridge-access 1

# # Server 11
# auto swp11
# iface swp11
#     bridge-access 1

# # Server 12
# auto swp12
# iface swp12
#     bridge-access 1

# # Server 13
# auto swp13
# iface swp13
#     bridge-access 1

# # Server 14
# auto swp14
# iface swp14
#     bridge-access 1

# # Server 15
# auto swp15
# iface swp15
#     bridge-access 1

# # Server 16
# auto swp16
# iface swp16
#     bridge-access 1

# # Server 17
# auto swp17
# iface swp17
#     bridge-access 1

# # Server 18
# auto swp18
# iface swp18
#     bridge-access 1

# # Server 19
# auto swp19
# iface swp19
#     bridge-access 1

# # Server 20
# auto swp20
# iface swp20
#     bridge-access 1

# # Server 21
# auto swp21
# iface swp21
#     bridge-access 1

# # Server 22
# auto swp22
# iface swp22
#     bridge-access 1

# # Server 23
# auto swp23
# iface swp23
#     bridge-access 1

# # Server 24
# auto swp24
# iface swp24
#     bridge-access 1

# # Server 25
# auto swp25
# iface swp25
#     bridge-access 1

# # Server 26
# auto swp26
# iface swp26
#     bridge-access 1

# # Server 27
# auto swp27
# iface swp27
#     bridge-access 1

# # Server 28
# auto swp28
# iface swp28
#     bridge-access 1

# # Server 29
# auto swp29
# iface swp29
#     bridge-access 1

# # Server 30
# auto swp30
# iface swp30
#     bridge-access 1

# # Server 31
# auto swp31
# iface swp31
#     bridge-access 1

# # Server 32
# auto swp32
# iface swp32
#     bridge-access 1

# # Server 33
# auto swp33
# iface swp33
#     bridge-access 1

# # Server 34
# auto swp34
# iface swp34
#     bridge-access 1

# # Server 35
# auto swp35
# iface swp35
#     bridge-access 1

# # Server 36
# auto swp36
# iface swp36
#     bridge-access 1

# # Server 37
# auto swp37
# iface swp37
#     bridge-access 1

# # Server 38
# auto swp38
# iface swp38
#     bridge-access 1

# # Server 39
# auto swp39
# iface swp39
#     bridge-access 1

# # Server 40
# auto swp40
# iface swp40
#     bridge-access 1

# # Server 41
# auto swp41
# iface swp41
#     bridge-access 1

# # Server 42
# auto swp42
# iface swp42
#     bridge-access 1

# # Server 43
# auto swp43
# iface swp43
#     bridge-access 1

# # Server 44
# auto swp44
# iface swp44
#     bridge-access 1

# # Server 45
# auto swp45
# iface swp45
#     bridge-access 1

# # Server 46
# auto swp46
# iface swp46
#     bridge-access 1

# # Server 47
# auto swp47
# iface swp47
#     bridge-access 1

# # Server 48
# auto swp48
# iface swp48
#     bridge-access 1


# # And the bridge for them.
# auto bridge
# iface bridge
#     bridge-vids 1
#     bridge-ports glob swp1-52
#     # bridge-ageing 150
#     # bridge-stp on
#     bridge-vlan-aware yes

# #------------------------------- VLAN configs --------------------------------
# auto vlan_main
# iface vlan_main
#     vlan-id 1
#     vlan-raw-device bridge
#     address 10.3.0.252
#     netmask 255.255.255.0
#     # Bastion NATs for us.
#     gateway 10.3.0.251
# EOF
#cp ${ZTP_USB_MOUNTPOINT}/interfaces /etc/network/interfaces

#Load port config from usb
#   (if breakout cables are used for certain interfaces)
#cp ${ZTP_USB_MOUNTPOINT}/ports.conf /etc/cumulus/ports.conf

# get the license
# /usr/cumulus/bin/cl-license -i http://192.168.0.254/license.txt

#Install a License from usb and restart switchd
# /usr/cumulus/bin/cl-license -i /tmp/license.txt && systemctl restart switchd.service

# adding vrf
add_vrf

cat > /tmp/license.txt <<EOF
example license
EOF
install_license /tmp/license.txt && systemctl restart switchd.service

# reload interfaces to apply loaded config
ifreload -a

# output state of interfaces
netshow interface

# required for autoprovisioning
# CUMULUS-AUTOPROVISIONING
exit 0

# =================================== ANSIBLE ===================================

# perform some callback
# /usr/bin/curl -H "Content-Type:application/json" -k -X POST --data '{"host_config_key":"'somekey'"}' -u username:password http://ansible.example.com/api/v2/job_templates/1111/callback/

# =================================== FUNCTIONS ===================================

function add_vrf(){
    # Waiting for NCLU to finish starting up
    last_code=1
    while [ "1" == "$last_code" ]; do
        net show interface &> /dev/null
        last_code=$?
    done

    net add vrf mgmt
    # TODO: correct time zone?
    net add time zone Etc/UTC
    net add time ntp server {{ MyNTPServer }} iburst
    net commit
}

function install_license(){
    # Install license
    echo "$(date) INFO: Installing License..."
    echo $1 | /usr/cumulus/bin/cl-license -i
    return_code=$?
    if [ "$return_code" == "0" ]; then
        echo "$(date) INFO: License Installed."
    else
        echo "$(date) ERROR: License not installed. Return code was: $return_code"
        /usr/cumulus/bin/cl-license
        exit 1
    fi
}

function ping_until_reachable(){
    last_code=1
    max_tries=30
    tries=0
    while [ "0" != "$last_code" ] && [ "$tries" -lt "$max_tries" ]; do
        tries=$((tries+1))
        echo "$(date) INFO: ( Attempt $tries of $max_tries ) Pinging $1 Target Until Reachable."
        ping $1 -c2 &> /dev/null
        last_code=$?
        sleep 1
    done
    if [ "$tries" -eq "$max_tries" ] && [ "$last_code" -ne "0" ]; then
        echo "$(date) ERROR: Reached maximum number of attempts to ping the target $1 ."
        exit 1
    fi
}
