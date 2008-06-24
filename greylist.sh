#!/bin/sh

directory=${0%/*}
cd $directory
. bin/activate
export PYTHONPATH=${directory}/spamfilter
exec python -c '
import sys
from greylist import GreylistPolicy
GreylistPolicy(sys.argv[1]).process()' config.ini
