#!/bin/bash

# Number of total requests
total_requests=100

# Number of concurrent requests
concurrent_requests=5

# Delay between each execution of ab command (in seconds)
delay=3

# Server IP and port
server_ip="10.0.0.10"


# Loop through and execute ab command with a delay
for ((i = 0; i < total_requests; i += concurrent_requests)); do
    ab -n $concurrent_requests -c $concurrent_requests "http://$server_ip"
    sleep $delay
done
