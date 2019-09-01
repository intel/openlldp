#!/bin/sh

set -ev

sources=~/rpmbuild/SOURCES
version="1.0.1"

mkdir -p "$sources"
git archive --prefix=lldpad-"$version"/ --format=tar.gz --output="$sources"/lldpad-"$version".tar.gz HEAD
rpmbuild -ba lldpad.spec
