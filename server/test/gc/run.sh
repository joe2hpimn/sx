#!/bin/sh
cd $(dirname "$0")
prove -f -a test_out.tgz
