#!/bin/sh
# vim: ft=sh ts=4 sts=4 sw=4 et ai
# -*- Mode: bash; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*-

help() {
    echo "Usage: self-extract.sh [--suffix SUFFIX] [--delete]"
    echo "          --suffix: use the given suffix when extracting the live VM directory"
    echo "          --delete: delete the live VM directory when the VM exits"
    exit 0
}

SUFFIX=
DELETE=
while [[ $# > 0 ]]; do
    key="$1"
    case $key in
        -s|--suffix)
        SUFFIX="$2"
        shift
        ;;
        -d|--delete)
        DELETE=yes
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

NAME=__NAME_PLACEHOLDER__
BUNDLE=`readlink -f "$0"` || exit 1
if [ -n "$SUFFIX" ]; then
    TEMP="$PWD/$NAME.$SUFFIX"
    mkdir -p "$TEMP"
else
    TEMP=`mktemp -d "$PWD/$NAME.XXXXXXXXXX"` || exit 1
fi

echo "Extracting to: $TEMP"
cd "$TEMP" || exit 1
sed '1,/^__MARK__$/d' "$BUNDLE" > $NAME.tar.gz || exit 1
tar -xvf $NAME.tar.gz || exit 1
cd $NAME || exit 1

./run.sh || exit 1

if [ "$DELETE" = "yes" ]; then
    rm -rf "$TEMP"
fi
exit 0
__MARK__
