#!/bin/sh

set -ev

sources=~/rpmbuild/SOURCES
version="1.0.1"

mkdir -p "$sources"
#git archive --prefix=lldpad-"$version"/ --format=tar.gz --output="$sources"/lldpad-"$version".tar.gz HEAD
tar --transform='s:^\.:lldpad-'"$version"':' --exclude='.git*' --exclude='.travis.yml' -cvzf "$sources"/lldpad-"$version".tar.gz .
#rpmbuild -ba lldpad.spec
