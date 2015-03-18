#!/usr/bin/env python

import sys

for arg in sys.argv[1:]:
    comment      = 0
    element_hide = 0
    url_filter   = 0

    print arg

    f = open(arg)
    lines = f.readlines()
    f.close()

    for line in lines[1:]:
        if line == '':
            continue
        elif line[0] == '!':
            comment += 1
        elif line.find('##') != -1:
            element_hide += 1
        else:
            url_filter += 1

    print 'filter: ', url_filter
    print 'element hide: ', element_hide
    print 'comment: ', comment
    print
