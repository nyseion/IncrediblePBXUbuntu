#!/bin/bash
#    This program installs Asterisk and Incredible PBX on Ubuntu 14.04 
#    All programs copyrighted and licensed by their respective companies.
#
#    Portions Copyright (C) 2014  Eric Teeter teetere@charter.net
#    Portions Copyright (C) 2014-2016  Ward Mundy & Associates LLC
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 2 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.
#

clear

version="13-12.2"


if [ -e "/etc/pbx/.incredible" ]; then
 echo "Incredible PBX is already installed."
 exit 1
fi

uversion=`grep "Ubuntu 14.04" /etc/lsb-release`
if [[ -z $uversion ]]; then
 echo "This version of Incredible PBX requires Ubuntu 14.04."
 exit 2
fi

if [ ! -f /root/COPYING ]; then
 echo "Before we begin, your server needs to be updated."
 echo "Once this has been accomplished, the server will reboot."
 echo "Then you'll need to rerun the Incredible PBX installer."
 echo "Press Ctrl-C now if you do not wish to proceed. Otherwise..."
 echo " "
 read -p "Press Enter to proceed at your own risk..."
 apt-get update
 touch /root/COPYING
 reboot
 exit
fi

COLUMNS=`echo -e "cols"|tput -S`
LINES=`echo -e "lines"|tput -S`

if [[ $COLUMNS -lt 80  ]] || [[ $LINES -lt 24  ]]; then
 echo Window size is too small: $COLUMNS x $LINES
 echo Please resize console window to at least 80 x 24.
 echo Then rerun the Incredible PBX installer.
 exit 1
fi

echo "SUCCESS: Incredible PBX 13 installer detected Ubuntu 14.04 OS!"
echo "UPDATED: Your Ubuntu 14.04 server has been updated successfully."
echo "We now are ready to begin the Incredible PBX 13 installation."
echo " "
read -p "Press Enter to proceed at your own risk..."

exec > >(tee -i /root/IncrediblePBX-install-log.txt)
exec 2>&1

clear
echo ".-.                          .-. _ .-.   .-.            .---. .---. .-..-."
echo ": :                          : ::_;: :   : :  v$version  : .; :: .; :: \`' :"
echo ": :,-.,-. .--. .--.  .--.  .-' :.-.: \`-. : :   .--.     :  _.':   .' \`  ' "
echo ": :: ,. :'  ..': ..'' '_.'' .; :: :' .; :: :_ ' '_.'    : :   : .; :.'  \`."
echo ":_;:_;:_;\`.__.':_;  \`.__.'\`.__.':_;\`.__.'\`.__;\`.__.'    :_;   :___.':_;:_;"
echo "Copyright (c) 2005-2016, Ward Mundy & Associates LLC. All rights reserved."
echo " "
echo "WARNING: This install will erase ALL existing FreePBX configurations!"
echo " "
echo "BY USING THE INCREDIBLE PBX, YOU AGREE TO ASSUME ALL RESPONSIBILITY"
echo "FOR USE OF THE PROGRAMS INCLUDED IN THIS INSTALLATION. NO WARRANTIES"
echo "EXPRESS OR IMPLIED INCLUDING MERCHANTABILITY AND FITNESS FOR PARTICULAR"
echo "USE ARE PROVIDED. YOU ASSUME ALL RISKS KNOWN AND UNKNOWN AND AGREE TO"
echo "HOLD WARD MUNDY, WARD MUNDY & ASSOCIATES LLC, NERD VITTLES, AND THE PBX"
echo "IN A FLASH DEVELOPMENT TEAM HARMLESS FROM ANY AND ALL LOSS OR DAMAGE"
echo "WHICH RESULTS FROM YOUR USE OF THIS SOFTWARE. AS CONFIGURED, THIS"
echo "SOFTWARE CANNOT BE USED TO MAKE 911 CALLS, AND YOU AGREE TO PROVIDE"
echo "AN ALTERNATE PHONE CAPABLE OF MAKING EMERGENCY CALLS. IF ANY OF THESE TERMS"
echo "AND CONDITIONS ARE RULED TO BE UNENFORCEABLE, YOU AGREE TO ACCEPT ONE"
echo "DOLLAR IN U.S. CURRENCY AS COMPENSATORY AND PUNITIVE LIQUIDATED DAMAGES"
echo "FOR ANY AND ALL CLAIMS YOU AND ANY USERS OF THIS SOFTWARE MIGHT HAVE."
echo " "

echo "If you do not agree with these terms and conditions of use, press Ctrl-C now."
read -p "Otherwise, press Enter to proceed at your own risk..."

echo " "
gvpick=(invalid PlainText OAuth2)
gvsetup=0
while [ $gvsetup -eq 0 -o $gvsetup -gt 2 ]
do
echo -n "Configure Google Voice for (1) Plaintext or (2) OAuth2 authentication? "
read gvsetup
if [[ -z $gvsetup  ]]; then
 gvsetup=0
fi
if [ "$gvsetup" -eq "$gvsetup" ] 2>/dev/null
then
 if [ $gvsetup -gt 2 ]; then
  gvsetup=0
 fi
 echo "GV Password Setup: ${gvpick[$gvsetup]}"
else
 gvsetup=0
 echo "GV Password Setup: ${gvpick[$gvsetup]}"
fi
done
read -p "If this is correct, press any key to continue or ctrl-C to exit"

if [ $gvsetup -eq 2 ]; then
 version="13-12.3"
fi

clear
echo ".-.                          .-. _ .-.   .-.            .---. .---. .-..-."
echo ": :                          : ::_;: :   : :  v$version  : .; :: .; :: \`' :"
echo ": :,-.,-. .--. .--.  .--.  .-' :.-.: \`-. : :   .--.     :  _.':   .' \`  ' "
echo ": :: ,. :'  ..': ..'' '_.'' .; :: :' .; :: :_ ' '_.'    : :   : .; :.'  \`."
echo ":_;:_;:_;\`.__.':_;  \`.__.'\`.__.':_;\`.__.'\`.__;\`.__.'    :_;   :___.':_;:_;"
echo "Copyright (c) 2005-2016, Ward Mundy & Associates LLC. All rights reserved."
echo " "
echo "Installing The Incredible PBX 13. Go have a cup of coffee..."
echo " "

#These are the varables required to make the install script work
#Do NOT change them

# First is the FreePBX version
export VER_FREEPBX=12.0

# Second is the Asterisk Database Password
export ASTERISK_DB_PW=amp109

# Third is the MySQL Admin password. Must be the same as when you install MySQL!!
export ADMIN_PASS=passw0rd

processor=`uname -i`
ubuntu=${processor:1:3}
# NOTE: $ubuntu will be 686 for 32-bit

update_repo() {
    sudo apt-get update -o Dir::Etc::sourcelist="sources.list.d/$1.list" \
        -o Dir::Etc::sourceparts="-" -o APT::Get::List-Cleanup="0"
}

# Installing packages needed to work with Asterisk
echo "---> Install packages needed to work with Asterisk"
apt-get install -y build-essential libssl-dev libcurl3-gnutls libcurl4-gnutls-dev libexpat1-dev gettext unzip
apt-get install -y expect debconf-utils apache2 make gawk git gcc
echo "mysql-server-5.5 mysql-server/root_password password passw0rd" | debconf-set-selections
echo "mysql-server-5.5 mysql-server/root_password_again password passw0rd" | debconf-set-selections
apt-get install -y mysql-server
apt-get install -y linux-headers-`uname -r`
apt-get install -y build-essential wget libspeex-dev libspeexdsp-dev dialog unixODBC unixODBC-dev libmyodbc libcurl4-openssl-dev libical-dev libneon27-dev
apt-get install -y libsrtp0-dev libiksemel-dev uuid uuid-dev libasound2-dev libogg-dev libvorbis-dev openssh-server apache2 mysql-client libgnutls28-dev libgnutls28 bison flex php5 php5-curl
apt-get install -y php5-cli php5-mysql php-pear php-db php5-gd curl sox libncurses5-dev libssl-dev libmysqlclient15-dev mpg123 libmpg123-0 libxml2-dev libnewt-dev 
apt-get install -y sqlite3 libsqlite3-dev pkg-config automake libtool autoconf git subversion liblua5.1 liblua5.1-0-dev libwww-perl libsox-fmt-all alsa-base apmd alsa-oss 
apt-get install -y linux-sound-base oss-compat xapm portaudio19-dev python-setuptools pptpd libspandsp-dev libossp-uuid16
apt-get install -y libiksemel-utils sox libjson-perl flac lame e2fsprogs
wait

apt-get -y autoremove
wait

# protect the Incredible Fax installer from the older one
chattr +i /root/incrediblefax11_ubuntu14.sh


#setup database
echo "----> Setup database"
pear uninstall db
pear install -Z db-1.7.14
mysql_install_db
wait

echo "Time to build Asterisk 13..."

#from source by Billy Chia
cd /usr/src
#wget http://downloads.asterisk.org/pub/telephony/dahdi-linux-complete/dahdi-linux-complete-current.tar.gz
wget http://downloads.asterisk.org/pub/telephony/dahdi-linux-complete/dahdi-linux-complete-2.10.2+2.10.2.tar.gz
wget http://downloads.asterisk.org/pub/telephony/libpri/libpri-current.tar.gz
wget http://downloads.asterisk.org/pub/telephony/asterisk/asterisk-13-current.tar.gz
#wget http://downloads.asterisk.org/pub/telephony/asterisk/asterisk-13.7.2.tar.gz

git clone https://github.com/asterisk/pjproject.git
# CentOS platform
# wget http://www.pjsip.org/release/2.2.1/pjproject-2.2.1.tar.bz2

tar zxvf dahdi-linux-complete*
tar zxvf libpri*
tar zxvf asterisk*
mv *.tar.gz /tmp

cd /usr/src/dahdi-linux-complete*
make && make install && make config

cd /usr/src/libpri*
make && make install

# centos only
#cd /usr/src
#tar -xjvf pjproject-2.2.1.tar.bz2

cd /usr/src/pjprojec*
# don't use libdir switch on Ubuntu
#CFLAGS='-DPJ_HAS_IPV6=1' ./configure --prefix=/usr --enable-shared --disable-sound --disable-resample --disable-video --disable-opencore-amr --libdir=/usr/lib64
CFLAGS='-DPJ_HAS_IPV6=1' ./configure --prefix=/usr --enable-shared --disable-sound --disable-resample --disable-video --disable-opencore-amr
make dep && make && make install

#cd /usr/src
#git clone https://github.com/akheron/jansson.git
#cd /usr/src/jansson
#autoreconf -i
#./configure
#make && make install

apt-get -y install curl libcurl3-gnutls libcurl4-gnutls-dev libjansson4 libjansson-dev ca-certificates unzip

cd /usr/src/asterisk*
# centos only
# contrib/scripts/install_prereq install
#./configure --libdir=/usr/lib64
contrib/scripts/get_mp3_source.sh 
if [ $gvsetup -eq 2 ]; then
 wget http://incrediblepbx.com/res_xmpp-13.tar.gz
 tar zxvf res_xmpp-13.tar.gz
else
 sed -i 's/SSLv3_method()/SSLv23_method()/g' res/res_xmpp.c
fi

make distclean
autoconf
./bootstrap.sh

./configure

make menuselect.makeopts
menuselect/menuselect --enable-category  MENUSELECT_ADDONS menuselect.makeopts
menuselect/menuselect --enable CORE-SOUNDS-EN-GSM --enable MOH-OPSOUND-WAV --enable EXTRA-SOUNDS-EN-GSM --enable cdr_mysql menuselect.makeopts
menuselect/menuselect --disable app_mysql --disable app_setcallerid --disable func_audiohookinherit --disable res_fax_spandsp menuselect.makeopts

#make menuselect

#expect -c 'set timeout 60;spawn make menuselect;expect "Save";send "\t\t\r";interact'

sed -i 's|march=native|mtune=native|' Makefile.rules

make && make install && make config && make samples
ldconfig

#Add Flite support
apt-get install libsdl1.2-dev libflite1 flite1-dev flite -y
cd /usr/src
# git clone https://github.com/zaf/Asterisk-Flite.git
wget http://pbxinaflash.com/flite-ubuntu14.tar.gz
tar zxvf flite-ubuntu14.tar.gz
cd Asterisk-Flite*
make clean
make
make install

# on Ubunntu platform only!!!
#ln -s /usr/lib64/libasteriskssl.so.1 /usr/lib/libasteriskssl.so.1
#ln -s /usr/lib64/libasteriskssl.so /usr/lib/libasteriskssl.so
#ldconfig
#

/etc/init.d/dahdi start
/etc/init.d/asterisk start


#Download and extract FreePBX 
echo "----> Download and extract FreePBX 12"
cd /usr/src
#git clone http://git.freepbx.org/scm/freepbx/framework.git freepbx
#git clone https://github.com/FreePBX/framework.git freepbx
git clone https://github.com/wardmundy/framework.git freepbx
wait
cd freepbx
git checkout release/${VER_FREEPBX}
wait

#Now create the Asterisk user and set ownership permissions.
echo "----> Create the Asterisk user and set ownership permissions and modify Apache"
#adduser asterisk --disabled-password --no-create-home --gecos "Asterisk User"
adduser asterisk --disabled-password --gecos "Asterisk User"
chown asterisk. /var/run/asterisk
chown -R asterisk. /etc/asterisk
chown -R asterisk. /var/{lib,log,spool}/asterisk
chown -R asterisk. /usr/lib/asterisk
mkdir /var/www/html
chown -R asterisk. /var/www/

# Set MyISAM as default MySQL storage so we can make quick backups
#/etc/init.d/mysql stop
#sed -i '/\[mysqld\]/a default-storage-engine=MyISAM' /etc/mysql/my.cnf
#sed -i '/\[mysqld\]/a skip-innodb' /etc/mysql/my.cnf
#/etc/init.d/mysql start

#Configure Asterisk database in MYSQL.
echo "----> Configure Asterisk database in MYSQL and set permissions"

mysqladmin -u root -p${ADMIN_PASS} create asterisk
mysqladmin -u root -p${ADMIN_PASS} create asteriskcdrdb
mysql -u root -p${ADMIN_PASS} asterisk < SQL/newinstall.sql
wait
mysql -u root -p${ADMIN_PASS} asteriskcdrdb < SQL/cdr_mysql_table.sql
wait

#Set permissions on MYSQL database.

mysql -u root -p${ADMIN_PASS} -e "GRANT ALL PRIVILEGES ON asterisk.* TO asteriskuser@localhost IDENTIFIED BY '${ASTERISK_DB_PW}';"
mysql -u root -p${ADMIN_PASS} -e "GRANT ALL PRIVILEGES ON asteriskcdrdb.* TO asteriskuser@localhost IDENTIFIED BY '${ASTERISK_DB_PW}';"
mysql -u root -p${ADMIN_PASS} -e "flush privileges;"


#Restart Asterisk and install FreePBX.

echo "----> Restart Asterisk and install FreePBX."
./start_asterisk start

rm -f /etc/asterisk/enum.conf
rm -f /etc/asterisk/cdr_mysql.conf
rm -f /etc/asterisk/phone.conf
rm -f /etc/asterisk/manager.conf
rm -f /etc/asterisk/meetme.conf
rm -f /etc/asterisk/indications.conf
rm -f /etc/asterisk/queues.conf
rm -f /etc/asterisk/musiconhold.conf
rm -f /etc/asterisk/modules.conf


#./install_amp --webroot /var/www/html
#./install_amp --installdb --username=asteriskuser --password=${ASTERISK_DB_PW} --freepbxip=`ifconfig | awk -F "[: ]+" '/inet addr:/ { if ($4 != "127.0.0.1") print $4 }'` --dbhost=localhost --webroot=/var/www/html --force-overwrite --scripted
./install_amp --username=asteriskuser --password=${ASTERISK_DB_PW} --freepbxip=`ifconfig | awk -F "[: ]+" '/inet addr:/ { if ($4 != "127.0.0.1") print $4 }'` --dbhost=localhost --webroot=/var/www/html --force-overwrite --scripted
wait
#amportal a ma installall
#wait
amportal a s
amportal a reload

#Finally, a few last mods and start FreePBX."

ln -s /var/lib/asterisk/moh /var/lib/asterisk/mohmp3
mkdir /var/lib/asterisk/sounds/custom
mkdir /var/lib/asterisk/sounds/tts
chown asterisk:asterisk /var/lib/asterisk/sounds/custom
chown asterisk:asterisk /var/lib/asterisk/sounds/tts
rm -rf /var/lib/asterisk/moh/moh
amportal kill
amportal start

sed -i 's/\(^upload_max_filesize = \).*/\120M/' /etc/php5/apache2/php.ini
cp /etc/apache2/apache2.conf /etc/apache2/apache2.conf_orig
sed -i 's/^\(User\|Group\).*/\1 asterisk/' /etc/apache2/apache2.conf
sed -i 's|AllowOverride None|AllowOverride All|g' /etc/apache2/apache2.conf
echo "Include /etc/pbx/httpdconf/*" >> /etc/apache2/apache2.conf
mkdir /etc/pbx
mkdir /etc/pbx/httpdconf
touch /etc/pbx/httpdconf/test
rm -f /var/www/html/index.html
service apache2 restart

mv /sbin/status /sbin/statusU

# Configuring IPtables
# Rules are saved in /etc/iptables
# /etc/init.d/iptables-persistent restart 
echo iptables-persistent iptables-persistent/autosave_v4 boolean true | debconf-set-selections
echo iptables-persistent iptables-persistent/autosave_v6 boolean true | debconf-set-selections
apt-get install -y iptables-persistent
cd /etc/init.d
wget http://incrediblepbx.com/iptables-persistent-U.tar.gz
tar zxvf iptables-persistent-U.tar.gz
rm iptables-persistent-U.tar.gz
# add TM3 rules for IPv6 here someday. In the meantime...
sed -i 's|INPUT ACCEPT|INPUT DROP|' /etc/iptables/rules.v6
sed -i '/OUTPUT ACCEPT/a # -A INPUT -s 2001:xxxx:yyyy::/48 -j ACCEPT' /etc/iptables/rules.v6
sed -i '/OUTPUT ACCEPT/a # Enable rules below to support your own internal address space' /etc/iptables/rules.v6
sed -i '/OUTPUT ACCEPT/a # -A INPUT -s 64:ff9b::/96 -p udp -m multiport --dports 5060,5061,5062,5063,5064,5065,5066,5067,5068,5069,4569 -j ACCEPT' /etc/iptables/rules.v6
sed -i '/OUTPUT ACCEPT/a # Enable rules below to support your own SIP providers' /etc/iptables/rules.v6
sed -i '/OUTPUT ACCEPT/a -A INPUT -p udp -m udp --dport 10000:20000 -j ACCEPT' /etc/iptables/rules.v6
sed -i '/OUTPUT ACCEPT/a -A INPUT -p udp -m udp --sport 53 --dport 1024:65535 -j ACCEPT' /etc/iptables/rules.v6
sed -i '/OUTPUT ACCEPT/a -A INPUT -m state --state RELATED -j ACCEPT' /etc/iptables/rules.v6
sed -i '/OUTPUT ACCEPT/a -A INPUT -m state --state ESTABLISHED -j ACCEPT' /etc/iptables/rules.v6
sed -i '/OUTPUT ACCEPT/a -A INPUT -p tcp -m tcp --tcp-flags ACK ACK -j ACCEPT' /etc/iptables/rules.v6
sed -i '/OUTPUT ACCEPT/a -A INPUT -s ::1 -j ACCEPT' /etc/iptables/rules.v6
# server IP address is?
serverip=`ifconfig | grep "inet addr" | head -1 | cut -f 2 -d ":" | cut -f 1 -d " "`
# user IP address while logged into SSH is?
userip=`echo $SSH_CONNECTION | cut -f 1 -d " "`
# public IP address in case we're on private LAN
publicip=`curl -s -S --user-agent "Mozilla/4.0" http://myip.incrediblepbx.com | awk 'NR==2'`
# WhiteList all of them by replacing 8.8.4.4 and 8.8.8.8 and 74.86.213.25 entries
cp /etc/iptables/rules.v4 /etc/iptables/rules.v4.orig
cd /etc/iptables
wget http://pbxinaflash.com/iptables4-ubuntu14.tar.gz
tar zxvf iptables4-ubuntu14.tar.gz
rm iptables4-ubuntu14.tar.gz
cp rules.v4.ubuntu14 rules.v4
sed -i 's|8.8.4.4|'$serverip'|' /etc/iptables/rules.v4
sed -i 's|8.8.8.8|'$userip'|' /etc/iptables/rules.v4
sed -i 's|74.86.213.25|'$publicip'|' /etc/iptables/rules.v4
badline=`grep -n "\-s  \-p" /etc/iptables/rules.v4 | cut -f1 -d: | tail -1`
while [[ "$badline" != "" ]]; do
sed -i "${badline}d" /etc/iptables/rules.v4
badline=`grep -n "\-s  \-p" /etc/iptables/rules.v4 | cut -f1 -d: | tail -1`
done
sed -i 's|-A INPUT -s  -j|#-A INPUT -s  -j|g' /etc/iptables/rules.v4
# we don't activate these new rules during the install
# this gives you time to adjust your setup
# rules will be activated on reboot or issuance of iptables-restart
# /etc/init.d/iptables-persistent restart
ln -s /etc/init.d/iptables-persistent /etc/init.d/iptables

chown asterisk:asterisk /etc/modprobe.d/dahdi.conf

amportal a ma update framework
amportal a ma refreshsignatures
amportal a s
amportal a r

#Installing Fail2Ban
apt-get install fail2ban -y
wait

# Installing SendMail
echo "Installing SendMail..."
apt-get -y install sendmail
apt-get -y remove postfix
apt-get -y install mailutils
wait

# Installing WebMin
echo "Installing WebMin..."
echo "deb http://download.webmin.com/download/repository sarge contrib" > /etc/apt/sources.list.d/sarge.list
cd /root
wget http://www.webmin.com/jcameron-key.asc
apt-key add jcameron-key.asc
update_repo sarge
apt-get install webmin -y
sed -i 's|10000|9001|g' /etc/webmin/miniserv.conf
service webmin restart


echo "Installing Incredible PBX apps..."

# Installing Incredible PBX stuff
amportal kill
service apache2 stop
/etc/init.d/mysql stop &
cd /

echo "Ready for Incredible Image now..."

wget http://incrediblepbx.com/incredible13-12-image.tar.gz
tar --ignore-failed-read -zxvf incredible13-12-image.tar.gz
rm incredible13-12-image.tar.gz
#wget http://incrediblepbx.com/fix-manager-permissions.tar.gz
#tar zxvf fix-manager-permissions.tar.gz
#rm fix-manager-permissions.tar.gz
#/etc/init.d/mysql start
#cd /root
#wget http://incrediblepbx.com/update-debian-pw
#chmod +x update-debian-pw
#./update-debian-pw
/etc/init.d/mysql start &
service apache2 start
rm -rf /var/lib/asterisk/moh/moh
amportal start
amportal a s
amportal a r
mkdir /etc/pbx
touch /etc/pbx/.incredible

rm -rf /var/www/html/admin/modules/sipstation
rm -rf /var/www/html/admin/modules/sms
rm -rf /var/www/html/admin/modules/isymphony
rm -rf /var/www/html/admin/modules/cxpanel

# bug fixes for Incredible apps
sed -i 's|ttspick = 1|ttspick = 0|' /var/lib/asterisk/agi-bin/nv-today.php

# reset FreePBX passwords
echo " "
echo "Randomizing all of your FreePBX extension 701 and DISA passwords..."
lowest=111337
highest=982766
ext701=$[ ( $RANDOM % ( $[ $highest - $lowest ] + 1 ) ) + $lowest ]NV
disapw=$[ ( $RANDOM % ( $[ $highest - $lowest ] + 1 ) ) + $lowest ]
vm701=$[ ( $RANDOM % ( $[ $highest - $lowest ] + 1 ) ) + $lowest ]
adminpw=$[ ( $RANDOM % ( $[ $highest - $lowest ] + 1 ) ) + $lowest ]
mysql -uroot -ppassw0rd asterisk <<EOF
use asterisk;
update sip set data="$ext701" where id="701" and keyword="secret";
update disa set pin="$disapw" where disa_id=1;
update admin set value='true' where variable="need_reload";
EOF
sed -i 's|987234871238888|'$vm701'|' /etc/asterisk/voicemail.conf
/var/lib/asterisk/bin/module_admin reload
# randomizing your admin password
#mysql -u root -ppassw0rd -e "update asterisk.ampusers set password_sha1 = '`echo -n $adminpw | sha1sum`' where username = 'admin' limit 1;"
# upgrading FreePBX as needed
#/var/lib/asterisk/bin/module_admin upgrade framework
#/var/lib/asterisk/bin/module_admin upgrade core
#/var/lib/asterisk/bin/module_admin upgradeall
#/var/lib/asterisk/bin/retrieve_conf
/var/lib/asterisk/bin/module_admin reload

echo " "

echo "Installing command line gvoice for SMS messaging..."
cd /root
#mkdir pygooglevoice
easy_install -U setuptools
easy_install simplejson
apt-get install -y mercurial
#cd kkleidal-pygooglevoiceupdate
#git clone https://github.com/wardmundy/pygooglevoice
rm -rf kk*
wget http://incrediblepbx.com/kkleidal-pygooglevoiceupdate-450e372008a2.tar.gz
tar zxvf kkleidal-pygooglevoiceupdate-450e372008a2.tar.gz
rm -f kkleidal-pygooglevoiceupdate-450e372008a2.tar.gz
cd kk*
python setup.py install
cp -p bin/gvoice /usr/bin/.
echo "asterisk ALL = NOPASSWD: /sbin/shutdown" >> /etc/sudoers
echo "asterisk ALL = NOPASSWD: /sbin/reboot" >> /etc/sudoers
echo "asterisk ALL = NOPASSWD: /usr/bin/gvoice" >> /etc/sudoers
#cd /root
#wget http://incrediblepbx.com/morestuff.tar.gz
#tar zxvf morestuff.tar.gz
#rm morestuff.tar.gz
#rm -r neorouter
echo " "

echo "Installing NeoRouter client..."
cd /root
if [ $ubuntu != 686 ] ; then
# 64-bit stuff goes here
 wget http://download.neorouter.com/Downloads/NRFree/Update_2.1.2.4326/Linux/Ubuntu/nrclient-2.1.2.4326-free-ubuntu-amd64.deb
 dpkg -i nrclient-2.1.2.4326-free-ubuntu-amd64.deb
else
# 32-bit stuff goes here
 wget http://download.neorouter.com/Downloads/NRFree/Update_2.1.2.4326/Linux/Ubuntu/nrclient-2.1.2.4326-free-ubuntu-i386.deb
 dpkg -i nrclient-2.1.2.4326-free-ubuntu-i386.deb
fi
rm *.deb

# adjusting DNS entries for PPTP access to Google DNS servers
sed -i 's|#ms-dns 10.0.0.1|ms-dns 8.8.8.8|' /etc/ppp/pptpd-options
sed -i 's|#ms-dns 10.0.0.2|ms-dns 8.8.4.4|' /etc/ppp/pptpd-options
# Administrator still must do the following to bring PPTP on line
# 1. edit /etc/pptpd.conf and add localip and remoteip address ranges
# 2. edit /etc/ppp/chap-secrets and add credentials for PPTP access:
#  mybox pptpd 1234 * (would give everyone access to mybox using 1234 pw)
# 3. restart PPTPD: service pptpd restart

# Installing status and mime-construct apps as well as automatic updater
#rm /sbin/status
cd /usr/local/sbin
wget http://incrediblepbx.com/status-ubuntu14.tar.gz
chattr -i status
tar zxvf status-ubuntu14.tar.gz
rm -f status-ubuntu14.tar.gz
#sed -i 's|mesg n|/root/update-IncrediblePBX \&\& /usr/local/sbin/status \&\& echo "Always run Incredible PBX behind a hardware-based firewall." \&\& mesg n|' /root/.profile
chattr +i update-IncrediblePBX
echo "$version" > /etc/pbx/.version

# Installing local mail
apt-get install mailutils -y

# Patching Wolfram Alpha installer for Ubuntu
# sed -i '/wget http:\/\/nerd.bz\/A7umMK/a mv A7umMK 4747.tgz' /root/wolfram/wolframalpha-oneclick.sh

# Patching grub so Ubuntu will shutdown and reboot by issuing command twice
# which sure beats NEVER which was the previous situation. Thanks, @jeff.h
sed -i 's|GRUB_CMDLINE_LINUX_DEFAULT=""|GRUB_CMDLINE_LINUX_DEFAULT="quiet splash acpi=force"|' /etc/default/grub
update-grub

# updating TM3 pieces for Ubuntu and IPtables
#cd /root
#wget http://incrediblepbx.com/iptables-ubuntu.tar.gz
#tar zxvf iptables-ubuntu.tar.gz
#rm -f iptables-ubuntu.tar.gz
#mv iptables-restart /usr/local/sbin
#sed -i 's|exit 0|/usr/local/sbin/iptables-restart\nexit 0|' /etc/rc.local
#sed -i 's|exit 0"|#exit 0"|' /etc/rc.local
#echo "*/10 5-22 * * * root /root/ipchecker > /dev/null 2>&1" >> /etc/crontab

# add timezone-setup to /root
#cd /root
#wget http://pbxinaflash.com/timezone-setup-ubuntu.tar.gz
#tar zxvf timezone-setup-ubuntu.tar.gz
#rm -f timezone-setup-ubuntu.tar.gz

# cleanup /etc/hosts to support SendMail from command line
fqdn1=`grep 127.0.1.1 /etc/hosts | cut -f 2 -d " "`
fqdn="noreply.incrediblepbx.com $fqdn1"
sed -i "s|$fqdn1|$fqdn|" /etc/hosts

# adding ODBC functionality
cd /root
wget http://incrediblepbx.com/odbc-ubuntu14.tar.gz
tar zxvf odbc-ubuntu14.tar.gz
rm odbc-ubuntu14.tar.gz
#./mysql-odbc
#./mysql-sample
./odbc-gen.sh

# Adding TM4 WhiteListing by Phone for extension 864
#cd /root
#mkdir tm4
#cd tm4
#wget http://incrediblepbx.com/tm4.tgz
#tar zxvf tm4.tgz
#mysql -uroot -ppassw0rd < tm4-accounts.sql
#sed -i '/\[from-internal-custom\]/r 'tm4-864'' /etc/asterisk/extensions_custom.conf
#cat tm4-func >> /etc/asterisk/func_odbc.conf
#mkdir /etc/asterisk/tm4
#chown asterisk:asterisk /etc/asterisk/tm4
#cp tm4-update /root/.
#cd /root
/root/odbc-gen.sh

#mv /var/www/html/index.html /var/www/html/index2.html
#echo "<?php" >  /var/www/html/index_custom.php
#echo "header('location: /admin');" >> /var/www/html/index_custom.php
#echo "?>" >>  /var/www/html/index_custom.php
#chown asterisk:asterisk /var/www/html/index_custom.php

# refreshing signatures of FreePBX modules
#amportal a ma refreshsignatures
#amportal a r

# patching Incredible Fax for pear quirk
#cd /root
#rm -f incrediblefax11_ubuntu14.sh
#wget http://incrediblepbx.com/incrediblefax11_ubuntu14.tar.gz
#tar zxvf incrediblefax11_ubuntu14.tar.gz
#rm -f incrediblefax11_ubuntu14.tar.gz

# patching Incredible Fax for location issue with faxgetty
sed -i 's|pear install -Z db-1.7.14|pear install -Z db-1.7.14\n\nln -s /usr/sbin/faxgetty /usr/local/sbin/faxgetty\n|' /root/incrediblefax11_ubuntu14.sh

# adding Port Knock daemon: knockd
apt-get install libpcap* -y
apt-get install anacron logrotate knockd -y
#if [ $ubuntu != 686 ] ; then
# 64-bit stuff goes here
# wget http://ftp.us.debian.org/debian/pool/main/k/knockd/knockd_0.5-3_amd64.deb
#else
# 32-bit stuff goes here
# wget http://ftp.us.debian.org/debian/pool/main/k/knockd/knockd_0.5-3_i386.deb
#fi
#dpkg -i knockd*
#rm knockd*.deb
echo "[options]" > /etc/knockd.conf
echo "       logfile = /var/log/knockd.log" >> /etc/knockd.conf
echo "" >> /etc/knockd.conf
echo "[opencloseALL]" >> /etc/knockd.conf
echo "        sequence      = 7:udp,8:udp,9:udp" >> /etc/knockd.conf
echo "        seq_timeout   = 15" >> /etc/knockd.conf
echo "        tcpflags      = syn" >> /etc/knockd.conf
echo "        start_command = /sbin/iptables -A INPUT -s %IP% -j ACCEPT" >> /etc/knockd.conf
echo "        cmd_timeout   = 3600" >> /etc/knockd.conf
echo "        stop_command  = /sbin/iptables -D INPUT -s %IP% -j ACCEPT" >> /etc/knockd.conf
chmod 640 /etc/knockd.conf
sed -i 's|START_KNOCKD=0|START_KNOCKD=1|' /etc/default/knockd
# randomize ports here
lowest=6001
highest=9950
knock1=$[ ( $RANDOM % ( $[ $highest - $lowest ] + 1 ) ) + $lowest ]
knock2=$[ ( $RANDOM % ( $[ $highest - $lowest ] + 1 ) ) + $lowest ]
knock3=$[ ( $RANDOM % ( $[ $highest - $lowest ] + 1 ) ) + $lowest ]
sed -i 's|7:udp|'$knock1':tcp|' /etc/knockd.conf
sed -i 's|8:udp|'$knock2':tcp|' /etc/knockd.conf
sed -i 's|9:udp|'$knock3':tcp|' /etc/knockd.conf
/etc/init.d/knockd start
apt-get install miniupnpc -y
upnpc -r 5060 udp $knock1 tcp $knock2 tcp $knock3 tcp

echo "Knock ports for access to $publicip set to TCP: $knock1 $knock2 $knock3" > /root/knock.FAQ
echo "UPnP activation attempted for UDP 5060 and your knock ports above." >> /root/knock.FAQ
echo "To enable remote access, issue these commands from any remote server:" >> /root/knock.FAQ
echo "nmap -p $knock1 $publicip && nmap -p $knock2 $publicip && nmap -p $knock3 $publicip" >> /root/knock.FAQ
echo "Or install iOS PortKnock or Android DroidKnocker on remote device." >> /root/knock.FAQ

# fix Asterisk to run as asterisk user
chown -R asterisk:asterisk /var/run/asterisk
sed -i '/END INIT INFO/a AST_USER="asterisk"\nAST_GROUP="asterisk"' /etc/init.d/asterisk
amportal kill
amportal start

# patch GoogleTTS
cd /tmp
git clone https://github.com/zaf/asterisk-googletts.git
cd asterisk-googletts
chown asterisk:asterisk goo*
sed -i 's|speed = 1|speed = 1.3|' googletts.agi
cp -p goo* /var/lib/asterisk/agi-bin/.
cd cli
chown asterisk:asterisk goo*
cp -p goo* /var/lib/asterisk/agi-bin/.

/usr/local/sbin/gui-fix

# old sendmail host patch
#sed -i 's|incrediblepbx|incrediblepbx noreply.incrediblepbx.com|' /etc/hosts
# sendmail fix
sed -i 's|noreply.incrediblepbx.com 127.0.1.1\tincrediblepbx|127.0.1.1  incrediblepbx noreply.incrediblepbx.com|' /etc/hosts



# htpasswd patch
apt-get install -y apache2-utils

# fax patch for iax registrations
echo "minregexpire=60" > /etc/asterisk/iax_registrations_custom.conf
echo "maxregexpire=600" >> /etc/asterisk/iax_registrations_custom.conf
echo "defaultexpire=300" >> /etc/asterisk/iax_registrations_custom.conf
chown asterisk:asterisk /etc/asterisk/iax_registrations_custom.conf

# SSH root login patch
sed -i 's|#PermitRootLogin|PermitRootLogin|' /etc/ssh/sshd_config

# Pico TTS replacement for GoogleTTS
cd /
wget http://incrediblepbx.com/picotts.tar.gz
tar zxvf picotts.tar.gz
cd /root
rm -f picotts-install.sh
apt-get install -y libttspico-utils
sed -i 's|en)|en-US)|' /etc/asterisk/extensions_custom.conf
sed -i 's|googletts|picotts|' /etc/asterisk/extensions_custom.conf

# gvoice and Google SMS patch
cd /
wget http://incrediblepbx.com/gvoice-patch.tar.gz
tar zxvf gvoice-patch.tar.gz

# remove module signature checking
cd /root
wget http://incrediblepbx.com/GPG-patch.tar.gz
tar zxvf GPG-patch.tar.gz
rm -f GPG-patch.tar.gz
./GPG-patch
touch /etc/pbx/.update718

# fix status quirk with Ubuntu
mv /usr/local/sbin/status /usr/local/sbin/pbxstatus
apt-get --reinstall install upstart
sed -i 's|sbin/status|sbin/pbxstatus|' /root/.profile

# patch to remove option for incoming callers to place outbound calls
mysql -uroot -ppassw0rd asterisk -e "update freepbx_settings set value = 'tr' where keyword = 'DIAL_OPTIONS' limit 1"
mysql -uroot -ppassw0rd asterisk -e "update freepbx_settings set value = '' where keyword = 'TRUNK_OPTIONS' limit 1"
amportal a r

if [ $gvsetup -eq 2 ]; then
# updates to support Google Voice OAUTH
cd /var/www/html/admin
sed -i 's|Google Voice Password|Google Voice Refresh Token|' modules/motif/views/edit.php
sed -i 's|This is your Google Voice Password|This is your Google Voice refresh token|' modules/motif/views/edit.php
echo 13-12.3 > /etc/pbx/.version
fi

# address Ubuntu upgrade bug now
apt-get upgrade -y

clear
echo "*** IMPORTANT  *** READ THIS CAREFULLY BEFORE DEPARTING!  *** IMPORTANT ***"
echo "*** Install Complete. Set the FreePBX admin password: ./admin-pw-change ***"
echo "*** Set admin password for web apps:  htpasswd /etc/pbx/wwwpasswd admin ***"
echo "*** Configure the correct time zone with this command: ./timezone-setup ***"
echo " "
echo "WARNING: Server access with firewall is NOT locked down until you reboot!"
echo "Then server will be locked down to server IP address and your PC's IP address."
echo "Modify /etc/iptables/rules.v4 and rules.v6. Restart IPtables to secure server!"
echo "You can WhiteList additional IP addresses with this command: ./add-ip"
echo "To restart or activate IPtables with new rules, issue command: iptables-restart"
echo " "
echo "Knock ports for access to $publicip set to TCP: $knock1 $knock2 $knock3"
echo "UPnP router activation attempted for UDP 5060 and your knock ports above."
echo "To enable remote access, issue these commands from any remote server:"
echo "nmap -p $knock1 $publicip && nmap -p $knock2 $publicip && nmap -p $knock3 $publicip"
echo "Or install iOS PortKnock or Android DroidKnocker on remote device. Read knock.FAQ." 
echo " "
echo "You may access webmin at https://`ifconfig | awk -F "[: ]+" '/inet addr:/ { if ($4 != "127.0.0.1") print $4 }'`:9001"
echo " "
echo "If you need to modify IPtables before locking it down, press CTRL-C now."
read -p "To REBOOT your server and lock down IPtables Firewall, press ENTER."
reboot
