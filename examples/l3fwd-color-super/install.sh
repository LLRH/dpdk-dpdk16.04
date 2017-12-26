echo "Please [source install.sh]"
export RTE_SDK=$PWD
export RTE_TARGET=x86_64-native-linuxapp-gcc
echo RTE_SDK=$RTE_SDK
echo RTE_TARGET=$RTE_TARGET

sdk=$RTE_SDK
target=$RTE_TARGET
lscpu
cd $sdk
make config T=$target && make
make install T=$target
modprobe uio
insmod build/kmod/igb_uio.ko
grep -i numa /var/log/dmesg

#SMP架构
echo 4096 > /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages

#NUMA架构
echo 4096 > /sys/devices/system/node/node0/hugepages/hugepages-2048kB/nr_hugepages
echo 4096 > /sys/devices/system/node/node1/hugepages/hugepages-2048kB/nr_hugepages

mkdir -p /mnt/huge
mount -t hugetlbfs nodev /mnt/huge

free
cd tools

#根据打印的日志来绑定网卡
#0000:01:00.0 '82599ES 10-Gigabit SFI/SFP+ Network Connection' if=enp1s0f0 drv=ixgbe unused=igb_uio 
#0000:01:00.1 '82599ES 10-Gigabit SFI/SFP+ Network Connection' if=enp1s0f1 drv=ixgbe unused=igb_uio 
#0000:04:00.0 '82599ES 10-Gigabit SFI/SFP+ Network Connection' if=enp4s0f0 drv=ixgbe unused=igb_uio 
#0000:04:00.1 '82599ES 10-Gigabit SFI/SFP+ Network Connection' if=enp4s0f1 drv=ixgbe unused=igb_uio 

#关闭网卡 -> 需要你的修改
ifconfig enp1s0f0 down
ifconfig enp1s0f1 down
ifconfig enp4s0f0 down
ifconfig enp4s0f1 down
ifconfig enp130s0f0 down
ifconfig enp130s0f1 down


#绑定网卡 -> 需要你的修改
python dpdk_nic_bind.py --bind=igb_uio 0000:01:00.0
python dpdk_nic_bind.py --bind=igb_uio 0000:01:00.1
python dpdk_nic_bind.py --bind=igb_uio 0000:04:00.0
python dpdk_nic_bind.py --bind=igb_uio 0000:04:00.1
python dpdk_nic_bind.py --bind=igb_uio 0000:82:00.0
python dpdk_nic_bind.py --bind=igb_uio 0000:82:00.1

 
sudo cat /proc/meminfo | grep Huge
umount /mnt/huge
rm -rf /mnt/huge
mkdir -p /mnt/huge
mount -t hugetlbfs nodev /mnt/huge
sudo cat /proc/meminfo | grep Huge

python dpdk_nic_bind.py --status

cd ..
cd examples
echo "[l3fwd] ./build/l3fwd -c 0x6 -n 2 -- -p 0x3 --config=\"(0,0,1),(1,0,2)\""
echo [helloworld] ./build/helloworld -c 0x3 -n 2
echo [----------------------------------------------------]
echo [-------DPDK has been installed for you!-------------]
echo [-------------------------------by WenXingBeng-------]
echo [----------------------------------------------------]
