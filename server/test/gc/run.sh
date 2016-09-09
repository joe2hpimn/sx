#!/bin/sh
cd $(dirname "$0")
rm -f test.log
prove -f  "$@" 2>test.log
