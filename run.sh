#!/bin/sh
#

#mkdir /sys/fs/cgroup/system.slice/processmaster.service/processmaster

#sleep 1000000&

#mkdir /sys/fs/cgroup/xyz.slice/test1
#echo controllers
#cat /sys/fs/cgroup/xyz.slice/test1/cgroup.controllers
#echo subtree_control
#cat /sys/fs/cgroup/xyz.slice/test1/cgroup.subtree_control
/home/code/workspace/processmaster/target/x86_64-unknown-linux-musl/release/processmaster >> test.log 2>&1 &
