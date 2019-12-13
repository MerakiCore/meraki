#!/bin/bash
# use testnet settings,  if you need mainnet,  use ~/.dashcore/merakid.pid file instead
dash_pid=$(<~/.dashcore/testnet3/merakid.pid)
sudo gdb -batch -ex "source debug.gdb" merakid ${dash_pid}
