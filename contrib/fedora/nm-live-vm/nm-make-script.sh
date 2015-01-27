#!/bin/bash
# vim: ft=sh ts=4 sts=4 sw=4 et ai
# -*- Mode: bash; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*-

set -vx

die() {
    echo "$@" >&2
    exit 1
}

help() {
    echo "Usage: nm-make-script.sh [--mode test|normal] [--branch BRANCH] [--url URL]"
    echo "          --mode normal: (default) simple NM-enabled VM for general use"
    echo "          --mode test: enable unit-testing (do not enable NM service, run test-vm-agent.py at startup)"
    echo "          --branch: NM git branch or commit SHA to build"
    echo "          --url: NM git repository URL"
    exit 0
}

MODE=normal
COMMIT="origin/master"
URL="git://anongit.freedesktop.org/NetworkManager/NetworkManager"
while [[ $# > 0 ]]; do
    key="$1"
    case $key in
        -m|--mode)
        MODE="$2"
        if [ "$MODE" != "test" -a "$MODE" != "normal" ]; then
            exit 1
        fi
        shift
        ;;
        -b|--branch)
        COMMIT="$2"
        shift
        ;;
        -u|--url)
        URL="$2"
        shift
        ;;
        -h|--help)
        help
        ;;
        *)
        die "Unrecognized option '$key'"
        ;;
    esac
    shift
done

PPP_VERSION=`rpm -q ppp-devel >/dev/null && rpm -q --qf '%{version}' ppp-devel || echo -n bad`

passwd -d root
test -d /NetworkManager || (
    git init /NetworkManager
    cd /NetworkManager

    # check if there is a local git repository and fetch from it first (should be faster)
    test -d "/NetworkManager-local.git" && (
        git remote add local "/NetworkManager-local.git"
        git fetch local
        git remote remove local
        rm -rf "/NetworkManager-local.git"
    )
    git remote add origin "$URL"
)
cd /NetworkManager/ || exit 1
git fetch origin || die "Could not fetch $URL"
git checkout -f "$COMMIT" || exit 1
git clean -fdx
export CFLAGS='-g -Og'
export CXXFLAGS='-g -Og'
./autogen.sh --prefix=/usr \
             --exec-prefix=/usr \
             --libdir=/usr/lib64 \
             --sysconfdir=/etc \
             --localstatedir=/var \
             --with-nmtui=yes \
             --with-dhclient=yes \
             --enable-ppp=yes \
             --with-modem-manager-1=no \
             --with-wext=no \
             --enable-teamdctl=yes \
             --with-selinux=yes \
             --enable-polkit=yes \
             --enable-polkit-agent \
             --enable-modify-system=yes \
             --enable-concheck \
             --with-session-tracking=systemd \
             --with-suspend-resume=systemd \
             --enable-ifcfg-rh=yes \
             --with-system-libndp=yes \
             --with-pppd-plugin-dir="/usr/lib64/pppd/$PPP_VERSION" \
             --with-setting-plugins-default='ifcfg-rh,ibft' \
             --enable-gtk-doc || exit 1
make || exit 1
#make check || exit 1
make install || exit 1
cat <<EOF > /etc/NetworkManager/NetworkManager.conf
[main]
plugins=ifcfg-rh
debug=RLIMIT_CORE
[logging]
level=DEBUG
domains=ALL
EOF
if [ "$MODE" != "test" ]; then
    /bin/systemctl enable NetworkManager.service || exit 1
fi
/bin/systemctl enable sshd.service || exit 1

git config --global user.name "NetworkManager Test VM"
git config --global user.email "networkmanager-maint@gnome.bugs"

cat <<EOF > /root/.vimrc
EOF

cat <<EOF > /root/.bashrc
LS_OPTIONS='--color=auto -Q'
alias l='ls \$LS_OPTIONS -la'
alias ll='ls \$LS_OPTIONS -l'
EOF

# allow login for root via SSH, without password!!
sed -e 's/^#\?\(PermitRootLogin *\).*/\1yes/' \
    -e 's/^#\?\(PermitEmptyPasswords *\).*/\1yes/' \
    -i /etc/ssh/sshd_config

# disable rate limiting of the journal
sed -e 's/^#\?\(RateLimitInterval *= *\).*/\10/' \
    -e 's/^#\?\(RateLimitBurst *= *\).*/\10/' \
    -i /etc/systemd/journald.conf

mkdir /mnt/sda1

git gc
