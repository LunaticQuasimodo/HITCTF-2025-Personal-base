#!/bin/sh

chmod 600 /home/ctf/flag
chmod +s /home/ctf/readflag

chmod +x /home/ctf/run.sh

exec /bin/bash -c "/etc/init.d/xinetd start; trap : TERM INT; sleep infinity & wait"
