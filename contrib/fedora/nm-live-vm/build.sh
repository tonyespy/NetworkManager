#!/bin/bash
# vim: ft=sh ts=4 sts=4 sw=4 et ai
# -*- Mode: bash; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*-


set -vx

die() {
    echo "$@" >&2
    exit 1
}

help() {
    echo "Usage: build.sh [--mode test|normal] [--branch BRANCH] [--name NAME]"
    echo "          --mode normal: (default) simple NM-enabled VM for general use"
    echo "          --mode test: enable unit-testing (do not enable NM service, run test-vm-agent.py at startup)"
    echo "          --branch: NM git branch or commit SHA to build"
    echo "          --name: initramfs name"
    exit 0
}

BASEDIR="$(readlink -f "$(dirname "$0")")"
cd "$BASEDIR" || die "Could not switch directory."

# copy output also to logfile
exec > >(tee ./.build.log)
exec 2>&1

if git rev-parse --git-dir 2> /dev/null; then
    INSIDE_GIT=1
else
    INSIDE_GIT=
fi

NAME="nm-live-vm"
if [[ $INSIDE_GIT ]]; then
    NM_BRANCH="HEAD"
else
    NM_BRANCH=master
fi

BUILD_PACKAGES="qemu febootstrap mock rpmdevtools"
ARCH=x86_64
ROOT="${ROOT:-"fedora-21-$ARCH"}"
TREE="/var/lib/mock/$ROOT/root"
PACKAGES="kernel passwd git autoconf automake libtool intltool gtk-doc libnl3-devel
    dbus-glib-devel libgudev1-devel libuuid-devel nss-devel ppp-devel newt-devel libndp-devel
    readline-devel gettext-devel pkgconfig
    gobject-introspection-devel
    pygobject3-base
    systemd-devel
    dhclient dnsmasq
    bash-completion man-db man-pages vim-minimal
    firewalld
    vim
    perl-YAML perl-XML-Parser
    wget
    gdb valgrind lsof strace nmap-ncat tcpdump
    net-tools bridge-utils vconfig
    openssh-server
    teamd teamd-devel libteam
    libsoup-devel newt-devel polkit-devel libselinux-devel
    coreutils"
#RELEASE="http://kojipkgs.fedoraproject.org/packages/fedora-release/20/1/noarch/fedora-release-20-1.noarch.rpm"
#PACKAGES="systemd bash"

check_root() {
    test "$EUID" -eq 0
}

do_prepare() {
    echo "Installing build packages..."
    check_root || die "$0 must be run as root"
    rpm -q $BUILD_PACKAGES || yum install $BUILD_PACKAGES || exit 1
    echo
}

do_chroot() {
    echo "Building the chroot..."
    mock -r "$ROOT" --init || exit 1
    mock -r "$ROOT" --install $PACKAGES || exit 1
    #mock -r "$ROOT" --installdeps NetworkManager || exit 1
    mock -r "$ROOT" --chroot cp /sbin/init /init || exit 1
    echo
}

do_build() {
    echo "Building NetworkManager..."

    if [[ $INSIDE_GIT ]]; then
        # make first a local, bare clone of our git repository and copy it into the chroot.
        # nm-make-script.sh will try to fetch from it first, to save bandwidth
        GIT1="`git rev-parse --show-toplevel`"
        GIT2="`mktemp --tmpdir -d nm.git-XXXXXXXXX`"
        git clone --bare "$GIT1" "$GIT2" || die "Could not make local clone of git dir"
        mock -r "$ROOT" --chroot 'rm -rf /NetworkManager-local.git'
        mock -r "$ROOT" --copyin "$GIT2" "/NetworkManager-local.git" || die "Could not copy local repositoy"
        rm -rf "$GIT2"
    fi

    # run the make script in chroot.
    mock -r "$ROOT" --copyin nm-make-script.sh "/usr/local/sbin/" || exit 1
    mock -r "$ROOT" --chroot "/usr/local/sbin/nm-make-script.sh -b \"$NM_BRANCH\" -m $MODE" || exit 1
    test -f "$TREE/usr/sbin/NetworkManager" || die "NetworkManager binary not found"
    echo
}

do_live_vm() {
    echo "Preparing kernel and initrd..." || exit 1
    mkdir -p $NAME || exit 1

    if [ "$MODE" = "test" ]; then
        mock -r "$ROOT" --copyin vm-agent.py "/usr/sbin" || exit 1
        mock -r "$ROOT" --copyin vm-agent.service "/usr/lib/systemd/system/" || exit 1
        mock -r "$ROOT" --chroot "/bin/systemctl enable vm-agent.service" || exit 1
    fi

    cp $TREE/boot/vmlinuz* $NAME/vmlinuz || exit 1
    mock -r "$ROOT" --chroot "{ (   cd / ; \
                                    echo 'host0 /mnt/shared 9p x-systemd.automount,x-systemd.device-timeout=10,trans=virtio,version=9p2000.L,rw 0 0' >> /etc/fstab ; \
                                    find -not \( \
                                        -path ./tmp/initramfs.img -o \
                                        -path './var/cache/yum/*' -o \
                                        -path './boot' \
                                    \) -xdev -print0 | \
                                    cpio -o0c ) || exit 1; } | gzip > /tmp/initramfs.img || exit 1" || die "error creating initramfs"
    cp "$TREE/tmp/initramfs.img" "$NAME/" || exit 1
    cp run.sh $NAME/run.sh
}

do_archive() {
    echo "Creating the archive..."
    tar -czvf $NAME.tar.gz $NAME || exit 1
    EXTRACT_SCRIPT=$(sed -e "s/__NAME_PLACEHOLDER__/$NAME/g" < self-extract.sh)
    echo "$EXTRACT_SCRIPT" | cat - ${NAME}.tar.gz > ${NAME}-bundle.sh || exit 1
    chmod +x ${NAME}-bundle.sh || exit 1
    echo "Successfully completed"
    echo
    echo "Now you can run and/or distribute: ${NAME}-bundle.sh"
}

MODE=normal
OPERATIONS=
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
        NM_BRANCH="$2"
        shift
        ;;
        -n|--name)
        NAME="$2"
        shift
        ;;
        -h|--help)
        help
        ;;
        *)
        OPERATIONS="$OPERATIONS $key"
        ;;
    esac
    shift
done

if [[ $INSIDE_GIT ]]; then
    NM_BRANCH="$(git rev-parse -q --verify "$NM_BRANCH")" || die "Could not resolve branch $NM_BRANCH"
fi

if [ -z "$OPERATIONS" ]; then
    check_root && do_prepare
    do_chroot
    do_build
    do_live_vm
    do_archive
    exit 0
fi

for i in $OPERATIONS; do
    do_$i; shift
    exit 0
done

echo "Wrong number of arguments."
exit 1
