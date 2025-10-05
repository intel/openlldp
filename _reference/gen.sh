#!/bin/sh

set -eux

rm -fr out
mkdir out
find . -maxdepth 1 -type f ! -name '*.*' -exec cp {} out/ \;
for i in out/*; do
	mv "$i" "$i".html
	vim '+1/<head' '+normal 0f<v' '+/End Wayback' '+normal $x' '+%s/\(['"'"'"]\)\/web\/[a-z0-9_]*\/\(https\?:\/\/\)/\1\2/g' '+%s/\(['"'"'"]\)https:\/\/web\.archive\.org\/web\/[a-z0-9_]*\/\(https\?:\/\/\)/\1\2/g' '+%s/http:\/\/\(www\.\)\?open-lldp\.org\/\([a-z_]\)/\2/g' +wq "$i".html
	vim '+1/^<\/html>/+1' '+normal dG' '+%s/css\.php[^"]*"/css.css"/g' '+%s/js\.php[^"]*"/js.js"/g' +wq "$i".html
done
