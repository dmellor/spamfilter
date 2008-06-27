#!/bin/sh

directory=${0%/*}
cd $directory
. bin/activate
exec python -c '
import sys
from spamfilter.greylist import GreylistPolicy
GreylistPolicy(sys.argv[1]).process()' config.ini
