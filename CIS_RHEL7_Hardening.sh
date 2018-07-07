#!/bin/bash
if [ "$EUID" -ne 0 ]
  then echo "Please run as root"
  exit
fi
df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev-type d -perm -0002 2>/dev/null | xargs chmod a+t
touch /etc/modprobe.d/CIS.conf
/bin/cat << EOM > /etc/modprobe.d/CIS.conf
install cramfs /bin/true
install freevxfs /bin/true
install jffs2 /bin/true
install hfs /bin/true
install hfsplus /bin/true
install squashfs /bin/true
install udf /bin/true
install vfat /bin/true
EOM

chkconfig rhnsd off
aide --init
mv /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz
crontab -u root -e
crontab -l > /tmp/crontmp
echo "0 5 * * * /usr/sbin/aide --check" >> /tmp/crontmp
crontab /tmp/crontmp
rm /tmp/crontmp

chown root:root /boot/grub2/grub.cfg
chmod og-rwx /boot/grub2/grub.cfg
chown root:root /boot/grub2/user.cfg
chmod og-rwx /boot/grub2/user.cfg

grub2-setpassword

echo "* hard core 0" >> /etc/security/limits.conf

echo "fs.suid_dumpable = 0" >> /etc/sysctl.conf
sysctl -w fs.suid_dumpable=0
echo "kernel.randomize_va_space = 2" >> /etc/sysctl.conf
echo "This is an official computer system and is the property of Vodafone Essar Ltd. and / or its affiliates. It is for authorized users only. Unauthorized users are prohibited. Users (authorized or unauthorized) have no explicit or implicit expectation of privacy. Any or all uses of this system may be subject to one or more of the following actions: interception, monitoring, recording, auditing, inspection and disclosing to security personnel and law enforcement personnel, as well as authorized officials of other agencies, both domestic and foreign. By using this system, the user consents to these actions. Unauthorized or improper use of this system may result in administrative disciplinary action and civil and criminal penalties. By accessing this system you indicate your awareness of and consent to these terms and conditions of use. Discontinue access immediately if you do not agree to the conditions stated in this notice." > /etc/motd
echo "This is an official computer system and is the property of Vodafone Essar Ltd. and / or its affiliates. It is for authorized users only. Unauthorized users are prohibited. Users (authorized or unauthorized) have no explicit or implicit expectation of privacy. Any or all uses of this system may be subject to one or more of the following actions: interception, monitoring, recording, auditing, inspection and disclosing to security personnel and law enforcement personnel, as well as authorized officials of other agencies, both domestic and foreign. By using this system, the user consents to these actions. Unauthorized or improper use of this system may result in administrative disciplinary action and civil and criminal penalties. By accessing this system you indicate your awareness of and consent to these terms and conditions of use. Discontinue access immediately if you do not agree to the conditions stated in this notice." > /etc/issue
echo "This is an official computer system and is the property of Vodafone Essar Ltd. and / or its affiliates. It is for authorized users only. Unauthorized users are prohibited. Users (authorized or unauthorized) have no explicit or implicit expectation of privacy. Any or all uses of this system may be subject to one or more of the following actions: interception, monitoring, recording, auditing, inspection and disclosing to security personnel and law enforcement personnel, as well as authorized officials of other agencies, both domestic and foreign. By using this system, the user consents to these actions. Unauthorized or improper use of this system may result in administrative disciplinary action and civil and criminal penalties. By accessing this system you indicate your awareness of and consent to these terms and conditions of use. Discontinue access immediately if you do not agree to the conditions stated in this notice." > /etc/issue.net
chown root:root /etc/motd
chmod 644 /etc/motd
chown root:root /etc/issue
chmod 644 /etc/issue
chown root:root /etc/issue.net
chmod 644 /etc/issue.net

Configure Mail Transfer Agent for Local-Only Mode 	
#Edit /etc/postfix/main.cf and add the following line to the RECEIVING MAIL section. 
#If the line already exists, change it to look like the line below. inet_interfaces = localhost 
# Execute the following command to restart postfix # service postfix restart
sed -i 's/inet_interfaces = all/inet_interfaces = localhost/' /etc/postfix/main.cf
sed -i 's/inet_interfaces = $myhostname/inet_interfaces = localhost/' /etc/postfix/main.cf
sed -i 's/inet_interfaces = $myhostname, localhost/inet_interfaces = localhost/' /etc/postfix/main.cf
#restart postfix service
service postfix restart
systemctl disable nfs
systemctl disable nfs-server
systemctl disable rpcbind
# yum remove telnet
sysctl -w net.ipv4.ip_forward=0
sysctl -w net.ipv4.route.flush=1
sysctl -w net.ipv4.conf.all.send_redirects=0
sysctl -w net.ipv4.conf.default.send_redirects=0
sysctl -w net.ipv4.route.flush=1
sysctl -w net.ipv4.conf.all.accept_source_route=0
sysctl -w net.ipv4.conf.default.accept_source_route=0
sysctl -w net.ipv4.route.flush=1
sysctl -w net.ipv4.conf.all.accept_redirects=0
sysctl -w net.ipv4.conf.default.accept_redirects=0
sysctl -w net.ipv4.route.flush=1
sysctl -w net.ipv4.conf.all.secure_redirects=0
sysctl -w net.ipv4.conf.default.secure_redirects=0
sysctl -w net.ipv4.route.flush=1
sysctl -w net.ipv4.conf.all.log_martians=1
sysctl -w net.ipv4.conf.default.log_martians=1
sysctl -w net.ipv4.route.flush=1
sysctl -w net.ipv4.icmp_echo_ignore_broadcasts=1
sysctl -w net.ipv4.route.flush=1
sysctl -w net.ipv4.icmp_ignore_bogus_error_responses=1
sysctl -w net.ipv4.route.flush=1
sysctl -w net.ipv4.conf.all.rp_filter=1
sysctl -w net.ipv4.conf.default.rp_filter=1
sysctl -w net.ipv4.route.flush=1
sysctl -w net.ipv4.tcp_syncookies=1
sysctl -w net.ipv4.route.flush=1
sysctl -w net.ipv6.conf.all.accept_ra=0
sysctl -w net.ipv6.conf.default.accept_ra=0
sysctl -w net.ipv6.route.flush=1
sysctl -w net.ipv6.conf.all.accept_redirects=0
sysctl -w net.ipv6.conf.default.accept_redirects=0
sysctl -w net.ipv6.route.flush=1

cat << 'EOM' >> /etc/sysctl.conf
# Benchmark Adjustments
kernel.exec-shield=1                                  # 1.6.2
kernel.randomize_va_space=2                           # 1.6.3
net.ipv4.ip_forward=0                                 # 4.1.1
net.ipv4.conf.all.send_redirects=0                    # 4.1.2
net.ipv4.conf.default.send_redirects=0                # 4.1.2
net.ipv4.conf.all.accept_source_route=0               # 4.2.1
net.ipv4.conf.default.accept_source_route=0           # 4.2.1
net.ipv4.conf.all.accept_redirects=0                  # 4.2.2
net.ipv4.conf.default.accept_redirects=0              # 4.2.2
net.ipv4.conf.all.secure_redirects=0                  # 4.2.3
net.ipv4.conf.default.secure_redirects=0              # 4.2.3
net.ipv4.conf.all.log_martians=1                      # 4.2.4
net.ipv4.conf.default.log_martians=1                  # 4.2.4
net.ipv4.icmp_echo_ignore_broadcasts=1                # 4.2.5
net.ipv4.icmp_ignore_bogus_error_responses=1          # 4.2.6
net.ipv4.conf.all.rp_filter=1                         # 4.2.7
net.ipv4.conf.default.rp_filter=1                     # 4.2.7
net.ipv4.tcp_syncookies=1                             # 4.2.8
net.ipv6.conf.default.disable_ipv6=0				  # 4.4.1
net.ipv6.conf.all.disable_ipv6=0					  # 4.4.1
net.ipv6.conf.all.accept_ra=0 						  # 4.4.1.1
net.ipv6.conf.default.accept_ra=0					  # 4.4.1.1
net.ipv6.conf.all.accept_redirects=0				  # 4.4.1.2
net.ipv6.conf.default.accept_redirect=0				  # 4.4.1.2
net.ipv6.route.flush=1								  # 4.4.1.1
EOM
############################

# only allow internally routeable addresses
touch /etc/hosts.allow
echo "ALL: 10.0.0.0/255.0.0.0" >/etc/hosts.allow
echo "ALL: 172.16.0.0/255.240.0.0" >>/etc/hosts.allow
echo "ALL: 192.168.0.0/255.255.0.0" >>/etc/hosts.allow
/bin/chmod 644 /etc/hosts.allow

touch /etc/hosts.deny
echo "ALL: ALL" >> /etc/hosts.deny
/bin/chmod 644 /etc/hosts.deny

echo "install dccp /bin/true" >> /etc/modprobe.d/CIS.conf
echo "install sctp /bin/true" >> /etc/modprobe.d/CIS.conf
echo "install rds /bin/true" >> /etc/modprobe.d/CIS.conf
echo "install tipc /bin/true" >> /etc/modprobe.d/CIS.conf

iptables -P INPUT DROP
iptables -P OUTPUT DROP
iptables -P FORWARD DROP

sed -i 's/max_log_file = 6/max_log_file = 100/' /etc/audit/auditd.conf
echo "space_left_action = email action_mail_acct = root admin_space_left_action = halt" >> /etc/audit/auditd.conf 
echo "max_log_file_action = keep_logs" >> /etc/audit/auditd.conf

cat << 'EOM' >> /etc/audit/rules.d/audit.rules
## First rule - delete all
-D

## Increase the buffers to survive stress events.
## Make this bigger for busy systems
-b 8192

## Set failure mode to syslog
-f 1
-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts
-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts
-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete
-a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete
-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts
-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts
-w /etc/sudoers -p wa -k scope
-w /etc/sudoers.d/ -p wa -k scope
-w /var/log/sudo.log -p wa -k actions
-w /sbin/insmod -p x -k modules
-w /sbin/rmmod -p x -k modules
-w /sbin/modprobe -p x -k modules
-a always,exit -F arch=b64 -S init_module -S delete_module -k modules
-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change
-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change
-a always,exit -F arch=b64 -S clock_settime -k time-change
-a always,exit -F arch=b32 -S clock_settime -k time-change
-w /etc/localtime -p wa -k time-change
-w /etc/group -p wa -k identity
-w /etc/passwd -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/security/opasswd -p wa -k identity
-a always,exit -F arch=b64 -S sethostname -S setdomainname -k system-locale
-a always,exit -F arch=b32 -S sethostname -S setdomainname -k system-locale
-w /etc/issue -p wa -k system-locale
-w /etc/issue.net -p wa -k system-locale
-w /etc/hosts -p wa -k system-locale
-w /etc/sysconfig/network -p wa -k system-locale
-w /etc/sysconfig/network-scripts/ -p wa -k system-locale
-w /etc/selinux/ -p wa -k MAC-policy
-w /usr/share/selinux/ -p wa -k MAC-policy
-w /var/log/lastlog -p wa -k logins
-w /var/run/faillock/ -p wa -k logins
-w /var/run/utmp -p wa -k session
-w /var/log/wtmp -p wa -k logins
-w /var/log/btmp -p wa -k logins
-e 2
EOM

service auditd restart

find /var/log -type f -exec chmod g-wx,o-rwx {} +
chown root:root /etc/crontab
chmod og-rwx /etc/crontab
chown root:root /etc/cron.hourly
chmod og-rwx /etc/cron.hourly
chown root:root /etc/cron.daily
chmod og-rwx /etc/cron.daily
chown root:root /etc/cron.weekly
chmod og-rwx /etc/cron.weekly
chown root:root /etc/cron.monthly
chmod og-rwx /etc/cron.monthly
chown root:root /etc/cron.d
chmod og-rwx /etc/cron.d

echo "--- Securing the SSH Daemon ---"
mv /etc/ssh/sshd_config /etc/ssh/sshd_config.bak
/bin/cat << EOM > /etc/ssh/sshd_config
HostKey /etc/ssh/ssh_host_rsa_key
HostKey /etc/ssh/ssh_host_ecdsa_key
HostKey /etc/ssh/ssh_host_ed25519_key
SyslogFacility AUTHPRIV
AuthorizedKeysFile      .ssh/authorized_keys
PasswordAuthentication yes
ChallengeResponseAuthentication no
GSSAPIAuthentication yes
GSSAPICleanupCredentials no
UsePAM yes
AcceptEnv LANG LC_CTYPE LC_NUMERIC LC_TIME LC_COLLATE LC_MONETARY LC_MESSAGES
AcceptEnv LC_PAPER LC_NAME LC_ADDRESS LC_TELEPHONE LC_MEASUREMENT
AcceptEnv LC_IDENTIFICATION LC_ALL LANGUAGE
AcceptEnv XMODIFIERS
Subsystem       sftp    /usr/libexec/openssh/sftp-server

PermitUserEnvironment no
ClientAliveInterval 300
ClientAliveCountMax 0
LoginGraceTime 60
AllowUsers root nessus
Banner /etc/issue.net
LogLevel INFO
X11Forwarding no
MaxAuthTries 4
#PermitRootLogin no
PermitEmptyPasswords no
Protocol 2
IgnoreRhosts yes
HostbasedAuthentication no
Ciphers aes128-ctr,aes192-ctr,aes256-ctr
EOM
#cat << 'EOM' > /etc/pam.d/system-auth
##%PAM-1.0
## This file is auto-generated.
## User changes will be destroyed the next time authconfig is run.
#auth        required      pam_env.so
#auth        sufficient    pam_unix.so nullok try_first_pass
#auth        requisite     pam_succeed_if.so uid >= 500 quiet
#auth        required      pam_deny.so
#account     required      pam_unix.so
#account     sufficient    pam_localuser.so
#account     sufficient    pam_succeed_if.so uid < 500 quiet
#account     required      pam_permit.so
#password    required     pam_cracklib.so password required pam_cracklib.so try_first_pass retry=3 minlen=14 dcredit=-1 ucredit=-1 ocredit=-1 lcredit=-1
#password    sufficient    pam_unix.so sha512 shadow nullok try_first_pass use_authtok remember=5
#password    required      pam_deny.so
#password    requisite     pam_passwdqc.so min=disabled,disabled,16,12,8
#session     optional      pam_keyinit.so revoke
#session     required      pam_limits.so
#session     [success=1 default=ignore] pam_succeed_if.so service in crond quiet use_uid
#session     required      pam_unix.so
#EOM
chown root:root /etc/group- 
chmod u-x,go-wx /etc/group-

