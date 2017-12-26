#!/bin/sh
logLevel=8;
if [ ! -n "$1" ] ;then
    echo "The default logLvel is 8(DEBUG)."
else
    echo "The logLevel is $1 now."
    logLevel=$1
fi
sleep 1s

echo "" > dpdk.log

./build/l3fwd -c 0xC07 --log-level $logLevel  -w 0000:04:00.0 -w 0000:04:00.1 -w 0000:82:00.0 -w 0000:82:00.1  -n 4 -- -P -E -p 0xF --config="(0,0,1),(1,0,2),(2,0,10),(3,0,11)"


#./build/l3fwd -c 0xF3E0 -n 3  --proc-type auto \
#--socket-mem 2048,2048 --file-prefix pg23 \
# -w 03:00.0 -w 03:00.1 -w 03:00.2 -w 03:00.3\
# -w 82:00.0 -w 82:00.1 -w 82:00.2 -w 82:00.3\
# -- -P -E -p 0xFF --config="(0,0,6),(1,0,7),(2,0,8),(3,0,9), \
# (4,0,12),(5,0,13),(6,0,14),(7,0,15)" \
# --parse-ptype
