#!/bin/sh

curl -O 'https://easylist-downloads.adblockplus.org/easylist.txt'
curl -O 'https://easylist-downloads.adblockplus.org/easyprivacy.txt'
curl -O 'https://secure.fanboy.co.nz/malwaredomains_full.txt'
curl 'https://easylist-downloads.adblockplus.org/fanboy-annoyance.txt' -o fanboy_annoyance.txt
curl 'https://easylist-downloads.adblockplus.org/easylistgermany.txt' -o easylist_germany.txt
curl 'https://easylist-downloads.adblockplus.org/easylistitaly.txt' -o easylist_italy.txt
curl 'https://easylist-downloads.adblockplus.org/liste_fr.txt' -o easylist_france.txt
curl 'https://raw.githubusercontent.com/k2jp/abp-japanese-filters/master/abpjf.txt' -o japanese.txt
curl 'http://tofukko.r.ribbon.to/Adblock_Plus_list.txt' -o japanese_tofu.txt
