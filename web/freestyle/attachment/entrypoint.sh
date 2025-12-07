#!/bin/sh
# Start Next.js server in the background
# The standalone build puts server.js in the root of the working directory
HOSTNAME="0.0.0.0" PORT=3000 node server.js &

# Start Nginx in the foreground
nginx -g 'daemon off;'
