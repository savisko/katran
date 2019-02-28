#!/bin/bash

KATRAN_IF=`cat conf/katran-if.txt`
ip r | grep $KATRAN_IF | perl -pe '$_ = / src (\S+)/ ? "$1\n" : ""' | sort -u;
