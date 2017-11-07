 ./build/l3fwd -c 0x7 -n 2 -- -P -E -p 0x3 --config="(0,0,1),(1,0,2)"



#./build/l3fwd -c 0xF3E0 -n 3  --proc-type auto \
#--socket-mem 2048,2048 --file-prefix pg23 \
# -w 03:00.0 -w 03:00.1 -w 03:00.2 -w 03:00.3\
# -w 82:00.0 -w 82:00.1 -w 82:00.2 -w 82:00.3\
# -- -P -E -p 0xFF --config="(0,0,6),(1,0,7),(2,0,8),(3,0,9), \
# (4,0,12),(5,0,13),(6,0,14),(7,0,15)" \
# --parse-ptype
