#!/bin/sh

# $Id: create_slackware_docker_image.sh,v 1.7 2022/02/20 20:35:15 eha Exp eha $
# Copyright 2021  Eric Hameleers, Eindhoven, NL 
# All rights reserved.
#
#   Permission to use, copy, modify, and distribute this software for
#   any purpose with or without fee is hereby granted, provided that
#   the above copyright notice and this permission notice appear in all
#   copies.
#
#   THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESSED OR IMPLIED
#   WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
#   MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
#   IN NO EVENT SHALL THE AUTHORS AND COPYRIGHT HOLDERS AND THEIR
#   CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
#   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
#   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
#   USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
#   ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
#   OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
#   OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
#   SUCH DAMAGE.
# -----------------------------------------------------------------------------
#

# This script creates a base image for Slackware OS, to be deployed with docker.

# Make sure we are root, have wget and md5sum
if [ $(id -u) -ne 0 ]; then
  echo "$(basename $0): You need to be root, aborting."
  exit 1
fi

# Stamp today in the filename:
THEDATE=$(date +%Y%m%d)

# Slackware version to install:
SL_VERSION=${SL_VERSION:-"15.0"}

# Slackware architecture to install:
SL_PKGARCH=${SL_PKGARCH:-"x86_64"}

# Directory suffix and architecture:
if [ "$SL_PKGARCH" = "x86_64" ]; then
  DIRSUFFIX="64"
  SL_ARCH="x64"
else
  DIRSUFFIX=""
  SL_ARCH="ia32"
fi

# Root directory of a Slackware local mirror tree:
SL_REPO=${SL_REPO:-"/home/ftp/pub/Linux/Slackware"}

# Package root directory:
SL_PKGROOT=${SL_REPO}/slackware${DIRSUFFIX}-${SL_VERSION}/slackware${DIRSUFFIX}

# Patches root directory:
SL_PATCHROOT=${SL_REPO}/slackware${DIRSUFFIX}-${SL_VERSION}/patches/packages

# Directory where we will install the root filesystem:
DOCK_ROOTDIR=${DOCK_ROOTDIR:-"${HOME}/aliendock_temp"}

# Directory where the image archive will be written:
OUTPUT=${OUTPUT:-"/tmp"}

# Slackware minimal package list:
SL_PKGLIST="
aaa_base
aaa_elflibs
coreutils
aaa_glibc-solibs
aaa_libraries
aaa_terminfo
pam
cracklib
libpwquality
e2fsprogs
acl
attr
bash
bin
binutils
bison
brotli
bzip2
c-ares
ca-certificates
cpio
curl
cxxlibs
cyrus-sasl
dcron
dev86
devs
dhcpcd
dialog
diffutils
dmidecode
elvis
etc
file
findutils
flex
floppy
gawk
glibc-solibs
gnupg
gnutls
gptfdisk
grep
groff
gzip
iproute2
iptables
iputils
jansson
less
libcgroup
libpsl
librsvg
libtermcap
libunistring
mpfr
mtr
ncurses
net-tools
network-scripts
nghttp2
nghttp3
nvi
openssh
openssl
patch
pcre2
pinentry
pkgtools
polkit
procps
quota
rsync
screen
sed
shadow
sharutils
slackpkg
slocate
sqlite
strace
sudo
sysfsutils
sysklogd
sysvinit
sysvinit-scripts
tar
time
tree
udev
usbutils
utempter
util-linux
wget
which
whois
xz
zlib
"
# Action!

# Some sanity checks first.
if [ ! -d ${SL_REPO} ]; then
  echo "-- Slackware repository root '${SL_REPO}' does not exist! Exiting."
  exit 1
fi

# Create output directory for image file:
mkdir -p ${OUTPUT}
if [ $? -ne 0 ]; then
  echo "-- Creation of output directory '${OUTPUT}' failed! Exiting."
  exit 1
fi

# Create working directory:
if [ ! -d ${DOCK_ROOTDIR} ]; then
  mkdir -p ${DOCK_ROOTDIR}
  if [ $? -ne 0 ]; then
    echo "-- Creation of working directory '${DOCK_ROOTDIR}' failed! Exiting."
    exit 1
  fi
else
  echo "-- Found an existing docker root filesystem at '${DOCK_ROOTDIR}'".
  echo "-- After 10 seconds we will proceed and wipe it."
  echo "-- If you do *not* want to delete this, please press Ctrl-C now!"
  read -t 10 -p "-- Continue [Y/n] ?"
  if [ "x$REPLY" = "xn" -o "x$REPLY" = "xN" ]; then
    echo "-- OK: exiting now."
  fi
fi
echo
rm -rf --one-file-system ${DOCK_ROOTDIR}/*
chmod 775 ${DOCK_ROOTDIR}

# Find packages and install them into the temporary root:
for PKG in $(echo $SL_PKGLIST); do
  FULLPKG="$(find ${SL_PATCHROOT} -name "${PKG}-*.t?z" 2>/dev/null | grep -E "\<${PKG//+/\\+}-[^-]+-[^-]+-[^-]+.t?z" | head -1)"
  if [ "x${FULLPKG}" = "x" ]; then
    FULLPKG="$(find ${SL_PKGROOT} -name "${PKG}-*.t?z" 2>/dev/null | grep -E "\<${PKG//+/\\+}-[^-]+-[^-]+-[^-]+.t?z" | head -1)"
  else
    echo "-- $PKG found in patches"
  fi
  if [ "x${FULLPKG}" = "x" ]; then
    echo "-- Package $PKG was not found in Slackware ${SL_VERSION} !"
  else
    installpkg --terse --root ${DOCK_ROOTDIR} ${FULLPKG}
  fi
done

# Run ldconfig:
ldconfig -r ${DOCK_ROOTDIR}

# Update CA certificates, followed by some bash since we do not have perl:
chroot ${DOCK_ROOTDIR} /usr/sbin/update-ca-certificates -f
cd ${DOCK_ROOTDIR}/etc/ssl/certs
  for file in *.pem; do
    ln -sf "$file" "$(openssl x509 -hash -noout -in "$file")".0
  done
cd - 1>/dev/null

# Next step, prepare the root filesystem for use as an docker container.

# Disable unneeded services:
[ -f ${DOCK_ROOTDIR}/etc/rc.d/rc.acpid ] && chmod -x ${DOCK_ROOTDIR}/etc/rc.d/rc.acpid
[ -f ${DOCK_ROOTDIR}/etc/rc.d/rc.pcmcia ] && chmod -x ${DOCK_ROOTDIR}/etc/rc.d/rc.pcmcia
[ -f ${DOCK_ROOTDIR}/etc/rc.d/rc.setterm ] && chmod -x ${DOCK_ROOTDIR}/etc/rc.d/rc.setterm
[ -f ${DOCK_ROOTDIR}/etc/rc.d/rc.udev ] && chmod -x ${DOCK_ROOTDIR}/etc/rc.d/rc.udev

# Remove ssh server keys - new unique keys will be generated
# at first boot of a container: 
rm -f ${DOCK_ROOTDIR}/etc/ssh/*key*

# Delete /etc/mtab and make it a symlink to /proc/mounts:
rm -f ${DOCK_ROOTDIR}/etc/mtab
ln -s /proc/mounts ${DOCK_ROOTDIR}/etc/mtab

# No hardware clock present:
sed -i -e '/^if \[ -x \/sbin\/hwclock/,/^fi$/s/^/#/' ${DOCK_ROOTDIR}/etc/rc.d/rc.S

# We need this to skip the WRITE check at next boot, which would drop us in a
# recovery shell and halt the boot process:
sed -i -e '/^if touch \/fsrwtestfile/,/^fi$/s/^/#/' ${DOCK_ROOTDIR}/etc/rc.d/rc.S

# Skip all filesystem checks at boot:
touch ${DOCK_ROOTDIR}/etc/fastboot

# Setterm is not useful here:
sed -i -e '/\/bin\/setterm/s/^/# /' ${DOCK_ROOTDIR}/etc/rc.d/rc.M

# We can not write to the hardware clock:
sed -i -e '/systohc/s/^/# /' ${DOCK_ROOTDIR}/etc/rc.d/rc.6

# Sanitize /etc/fstab :
cat <<EOT > ${DOCK_ROOTDIR}/etc/fstab
devtmpfs         /dev             none
devpts           /dev/pts         devpts      gid=5,mode=620   0   0
tmpfs            /dev/shm         tmpfs   defaults,nodev,nosuid,mode=1777  0   0
EOT

# Edit /etc/inittab so that console login processes are not spawned:
sed -i -e "/agetty/s/^c/#c/" ${DOCK_ROOTDIR}/etc/inittab

# Reduce the number of local consoles, two should be enough:
sed -i -e '/^c3\|^c4\|^c5\|^c6/s/^/# /' ${DOCK_ROOTDIR}/etc/inittab

# Edit /etc/shadow and invalidate the root password.
# The docker container will not use it:
sed -i -e '/^root/s/^root::/root:!:/' ${DOCK_ROOTDIR}/etc/shadow

# Configure a usable terminal emulation:
echo "export TERM=linux" >> ${DOCK_ROOTDIR}/etc/profile.d/term.sh
chmod +x ${DOCK_ROOTDIR}/etc/profile.d/term.sh

# Docker shell uses the filesystem root as the homedirectory,
# so let's give us a proper login shell:
echo ". /etc/profile" > ${DOCK_ROOTDIR}/.bashrc

# Make sure we can access DNS:
cat <<EOT >> ${DOCK_ROOTDIR}/etc/resolv.conf
nameserver 8.8.4.4
nameserver 8.8.8.8

EOT

# Set sane defaults for running slackpkg in a Docker container:
sed -i 's/DIALOG=on/DIALOG=off/' ${DOCK_ROOTDIR}/etc/slackpkg/slackpkg.conf
sed -i 's/POSTINST=on/POSTINST=off/' ${DOCK_ROOTDIR}/etc/slackpkg/slackpkg.conf
sed -i 's/SPINNING=on/SPINNING=off/' ${DOCK_ROOTDIR}/etc/slackpkg/slackpkg.conf
if grep -q "^ *WGETFLAGS" /etc/slackpkg/slackpkg.conf ; then
  sed -e 's/^ *WGETFLAGS="/&--no-verbose /' -i ${DOCK_ROOTDIR}/etc/slackpkg/slackpkg.conf
else
  echo 'WGETFLAGS="--passive-ftp --no-verbose"' >> ${DOCK_ROOTDIR}/etc/slackpkg/slackpkg. conf
fi

# Enable a Slackware mirror for slackpkg:
cat <<EOT >> ${DOCK_ROOTDIR}/etc/slackpkg/mirrors
http://slackware.osuosl.org/slackware${DIRSUFFIX}-${SL_VERSION}/
EOT

# Blacklist the l10n packages;
cat << EOT >> ${DOCK_ROOTDIR}/etc/slackpkg/blacklist

# Blacklist the l10n packages;
calligra-l10n-
kde-l10n-

EOT

# Update the cache for slackpkg:
echo "-- Creating slackpkg cache, takes a few seconds..."
if [ "${SL_VERSION}" = "current" ]; then
  # Slackpkg wants you to opt-in on slackware-current:
  mkdir -p ${DOCK_ROOTDIR}/var/lib/slackpkg
  touch ${DOCK_ROOTDIR}/var/lib/slackpkg/current
fi
chroot ${DOCK_ROOTDIR} /usr/sbin/slackpkg -batch=on -default_answer=y update gpg
chroot ${DOCK_ROOTDIR} /usr/sbin/slackpkg -batch=on -default_answer=y update

# Clean out the unneeded stuff:
echo "-- Running clean-up routine."
rm -f ${DOCK_ROOTDIR}/boot/*
rm -f ${DOCK_ROOTDIR}/tmp/[A-Za-z]*
rm -f ${DOCK_ROOTDIR}/var/mail/*
rm -rf ${DOCK_ROOTDIR}/dev/*
rm -rf ${DOCK_ROOTDIR}/usr/share/locale/*
rm -rf ${DOCK_ROOTDIR}/usr/info/*
rm -rf ${DOCK_ROOTDIR}/usr/man/*
(cd ${DOCK_ROOTDIR}/usr/doc && find . -type d -mindepth 2 -maxdepth 2 |grep -v /cups- |xargs rm -rf)
rm -rf ${DOCK_ROOTDIR}/usr/doc/*/html
rm -f ${DOCK_ROOTDIR}/usr/doc/*/*.{pdf,db,gz,bz2,xz,txt,TXT}
rm -rf ${DOCK_ROOTDIR}/usr/share/gtk-doc
rm -rf ${DOCK_ROOTDIR}/usr/share/help
find ${DOCK_ROOTDIR}/usr/share/ -type d -name doc |xargs rm -rf

# The docker image only needs a few terminal capabilities so remove the rest:
find ${DOCK_ROOTDIR}/usr/share/terminfo/ -type f ! -name 'linux' -a ! -name 'xterm' -a ! -name 'screen.linux' | xargs rm -f 
# Remove the dangling symlinks as well:
find ${DOCK_ROOTDIR}/usr/share/terminfo/ -xtype l -delete

# Compress the tree into an docker image:
echo "-- Creating the docker image..."
cd ${DOCK_ROOTDIR}
  tar --numeric-owner -cvf ${OUTPUT}/slackware-${SL_VERSION}-${SL_PKGARCH}-minimal-${THEDATE}.tar .
  if [ $? -eq 0 ]; then
    echo "-- Created ${OUTPUT}/slackware-${SL_VERSION}-${SL_PKGARCH}-minimal-${THEDATE}.tar"
    if which docker 1>/dev/null 2>/dev/null ; then
      echo "-- Importing it into docker..."
      DOCK_ID=$(docker import ${OUTPUT}/slackware-${SL_VERSION}-${SL_PKGARCH}-minimal-${THEDATE}.tar slackware:base_${SL_ARCH}_${SL_VERSION})
      docker run --rm slackware:base_${SL_ARCH}_${SL_VERSION} printf 'slackware:base_%s_%s with id=%s created!\n' ${SL_ARCH} ${SL_VERSION} ${DOCK_ID}
    fi
  else
    echo "-- Non-zero exitcode, something went wrong."
  fi
cd -

