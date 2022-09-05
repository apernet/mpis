#!/bin/bash

set -me

send="send"
recv="recv"

node1="node1"
node2="node2"

cleanup() {
    ip netns del "$send"
    ip netns del "$recv"
    ip netns del "$node1"
    ip netns del "$node2"
}

ip netns add "${send}"
ip netns add "${recv}"
ip netns add "${node1}"
ip netns add "${node2}"

trap cleanup EXIT

# node1 -- send -- recv -- node2
ip link add dev link-sr mtu 1500 netns "${send}" type veth peer name link-rs mtu 1500 netns "${recv}"
ip link add dev link-1s mtu 1500 netns "${send}" type veth peer name link-s1 mtu 1500 netns "${node1}"
ip link add dev link-r2 mtu 1500 netns "${recv}" type veth peer name link-2r mtu 1500 netns "${node2}"

ip -netns "${send}" link set link-sr up
ip -netns "${recv}" link set link-rs up
ip -netns "${send}" link set link-1s up
ip -netns "${node1}" link set link-s1 up
ip -netns "${recv}" link set link-r2 up
ip -netns "${node2}" link set link-2r up

# send (10.0.0.1) ---- recv (10.0.0.254)
ip -netns "${send}" -4 addr add "10.0.0.1/24" dev link-sr
ip -netns "${recv}" -4 addr add "10.0.0.254/24" dev link-rs

# node1 (10.1.0.1) -- send (10.1.0.254)
ip -netns "${node1}" -4 addr add "10.1.0.1/24" dev link-s1
ip -netns "${send}" -4 addr add "10.1.0.254/24" dev link-1s

# recv (10.2.0.254) -- node2 (10.2.0.1)
ip -netns "${recv}" -4 addr add "10.2.0.254/24" dev link-r2
ip -netns "${node2}" -4 addr add "10.2.0.1/24" dev link-2r

# node1 default via send
ip -netns "${node1}" -4 route add default via 10.1.0.254

# node2 default via recv
ip -netns "${node2}" -4 route add default via 10.2.0.254

# send default via recv
ip -netns "${send}" -4 route add default via 10.0.0.254

# recv default via node2
ip -netns "${recv}" -4 route add default via 10.2.0.1

# node1 tunnel ip on loopback 
ip -netns "${node1}" -4 addr add 1.2.3.4/32 dev lo
ip -netns "${node1}" -4 addr add 11.22.33.44/32 dev lo
ip -netns "${node1}" link set lo up

# route lo traffic to node1
ip -netns "${send}" -4 route add 1.2.3.4/32 via 10.1.0.1
ip -netns "${send}" -4 route add 11.22.33.44/32 via 10.1.0.1

# node2 tunnel ip on loopback
ip -netns "${node2}" -4 addr add 5.6.7.8/32 dev lo
ip -netns "${node2}" -4 addr add 55.66.77.88/32 dev lo
ip -netns "${node2}" link set lo up

cat > test-send.cfg << EOF
iif link-1s src 1.2.3.0/24 encap 10.0.0.254 cutoff-ttl 10
iif link-sr dst 10.0.0.1 decap 5.6.7.0/24
EOF

cat > test-recv.cfg << EOF
iif link-rs dst 10.0.0.254 decap 1.2.3.0/24
iif link-r2 src 5.6.7.0/24 encap 10.0.0.1 cutoff-ttl 10
EOF

# mpis on sender
ip netns exec "${send}" ./mpis-routectl -t test-send.cfg -e mpis-ebpf.o link-1s link-sr

# mpis on receiver
ip netns exec "${recv}" ./mpis-routectl -t test-recv.cfg -e mpis-ebpf.o link-rs link-r2

read -p 'env ready, press enter to proceed with test.'

echo '==== tests started ===='

ip netns exec "${node1}" ping -I 1.2.3.4 5.6.7.8 -c20 > /dev/null 2>&1 &
ping_pid_1=$!

echo -n 'testing encap... '
timeout 5s ip netns exec "${send}" tcpdump -i link-sr -n 'icmp and src 5.6.7.8 and dst 10.0.0.254' -c1 > /dev/null 2>&1 && echo 'ok' || echo 'failed'

echo -n 'testing decap... '
timeout 5s ip netns exec "${recv}" tcpdump -i link-rs -n 'icmp and src 1.2.3.4 and dst 5.6.7.8' -c1  > /dev/null 2>&1 && echo 'ok' || echo 'failed'

echo -n 'testing encap (inverse)... '
timeout 5s ip netns exec "${recv}" tcpdump -i link-rs -n 'icmp and src 1.2.3.4 and dst 10.0.0.1' -c1 > /dev/null 2>&1 && echo 'ok' || echo 'failed'

echo -n 'testing decap (inverse)... '
timeout 5s ip netns exec "${send}" tcpdump -i link-sr -n 'icmp and dst 1.2.3.4 and src 5.6.7.8' -c1  > /dev/null 2>&1 && echo 'ok' || echo 'failed'

ip netns exec "${node1}" ping -I 11.22.33.44 55.66.77.88 -c10 > /dev/null 2>&1 &
ping_pid_2=$!

echo -n 'testing sender-passthrough... '
timeout 5s ip netns exec "${send}" tcpdump -i link-sr -n 'icmp and src 11.22.33.44 and dst 55.66.77.88' -c1 > /dev/null 2>&1 && echo 'ok' || echo 'failed'

echo -n 'testing receiver-passthrough... '
timeout 5s ip netns exec "${recv}" tcpdump -i link-rs -n 'icmp and src 11.22.33.44 and dst 55.66.77.88' -c1  > /dev/null 2>&1 && echo 'ok' || echo 'failed'

ip netns exec "${node1}" ping -t5 -I 1.2.3.4 55.66.77.88 -c10 > /dev/null 2>&1 &
ping_pid_3=$!

echo -n 'testing ttl-cutoff... '
timeout 5s ip netns exec "${send}" tcpdump -i link-sr -n 'icmp and src 1.2.3.4 and dst 10.0.0.254' -c1 > /dev/null 2>&1 && echo 'ok' || echo 'failed'

echo -n 'testing fragmentation... '
timeout 5s ip netns exec "${node1}" ping -I 1.2.3.4 5.6.7.8 -c1 -s2000 > /dev/null 2>&1 && echo 'ok' || echo 'failed'

echo -n 'testing ip options... '
timeout 5s ip netns exec "${node1}" ping -R -I 1.2.3.4 5.6.7.8 -c1 > /dev/null 2>&1 && echo 'ok' || echo 'failed'

kill $ping_pid_1 || true
kill $ping_pid_2 || true
kill $ping_pid_3 || true

echo 'running speedtest (node1 <- node2)... '
ip netns exec "${node2}" iperf3 -s -1 > /dev/null 2>&1 &
iperf_pid_1=$!

sleep 1

ip netns exec "${node1}" iperf3  -B 1.2.3.4 -Rc 5.6.7.8 || echo 'iperf failed'

echo 'running speedtest (node2 <- node1)... '
ip netns exec "${node2}" iperf3 -s -1 > /dev/null 2>&1 &
iperf_pid_2=$!

sleep 1

ip netns exec "${node1}" iperf3 -B 1.2.3.4 -c 5.6.7.8 || echo 'iperf failed'

kill $iperf_pid_1 || true
kill $iperf_pid_2 || true

cat > test-send.cfg << EOF
iif link-1s src 1.2.3.0/24 encap 10.0.0.254 cutoff-ttl 10 override-frag
iif link-sr dst 10.0.0.1 decap 5.6.7.0/24 override-frag
EOF

cat > test-recv.cfg << EOF
iif link-rs dst 10.0.0.254 decap 1.2.3.0/24 override-frag
iif link-r2 src 5.6.7.0/24 encap 10.0.0.1 cutoff-ttl 10 override-frag
EOF

ip netns exec "${send}" ./mpis-routectl -t test-send.cfg -e mpis-ebpf.o link-1s link-sr
ip netns exec "${recv}" ./mpis-routectl -t test-recv.cfg -e mpis-ebpf.o link-rs link-r2

ip netns exec "${node1}" ping -I 1.2.3.4 5.6.7.8 -c20 > /dev/null 2>&1 &
ping_pid_1=$!

echo -n 'testing encap (override-frag)... '
timeout 5s ip netns exec "${send}" tcpdump -i link-sr -n 'icmp and src 1.2.3.4 and dst 10.0.0.254' -c1 > /dev/null 2>&1 && echo 'ok' || echo 'failed'

echo -n 'testing decap (override-frag)... '
timeout 5s ip netns exec "${recv}" tcpdump -i link-rs -n 'icmp and src 1.2.3.4 and dst 5.6.7.8' -c1  > /dev/null 2>&1 && echo 'ok' || echo 'failed'

echo -n 'testing encap (inverse, override-frag)... '
timeout 5s ip netns exec "${recv}" tcpdump -i link-rs -n 'icmp and src 5.6.7.8 and dst 10.0.0.1' -c1 > /dev/null 2>&1 && echo 'ok' || echo 'failed'

echo -n 'testing decap (inverse, override-frag)... '
timeout 5s ip netns exec "${send}" tcpdump -i link-sr -n 'icmp and dst 1.2.3.4 and src 5.6.7.8' -c1  > /dev/null 2>&1 && echo 'ok' || echo 'failed'

ip netns exec "${node1}" ping -I 11.22.33.44 55.66.77.88 -c10 > /dev/null 2>&1 &
ping_pid_2=$!

echo -n 'testing sender-passthrough (override-frag)... '
timeout 5s ip netns exec "${send}" tcpdump -i link-sr -n 'icmp and src 11.22.33.44 and dst 55.66.77.88' -c1 > /dev/null 2>&1 && echo 'ok' || echo 'failed'

echo -n 'testing receiver-passthrough (override-frag)... '
timeout 5s ip netns exec "${recv}" tcpdump -i link-rs -n 'icmp and src 11.22.33.44 and dst 55.66.77.88' -c1  > /dev/null 2>&1 && echo 'ok' || echo 'failed'

ip netns exec "${node1}" ping -t5 -I 1.2.3.4 55.66.77.88 -c10 > /dev/null 2>&1 &
ping_pid_3=$!

echo -n 'testing ttl-cutoff (override-frag)... '
timeout 5s ip netns exec "${send}" tcpdump -i link-sr -n 'icmp and src 1.2.3.4 and dst 10.0.0.254' -c1 > /dev/null 2>&1 && echo 'ok' || echo 'failed'

echo -n 'testing fragmentation (override-frag - should fail)... '
timeout 5s ip netns exec "${node1}" ping -I 1.2.3.4 5.6.7.8 -c1 -s2000 > /dev/null 2>&1 && echo 'ok' || echo 'failed'

echo -n 'testing ip options (override-frag)... '
timeout 5s ip netns exec "${node1}" ping -R -I 1.2.3.4 5.6.7.8 -c1 > /dev/null 2>&1 && echo 'ok' || echo 'failed'

kill $ping_pid_1 || true
kill $ping_pid_2 || true
kill $ping_pid_3 || true

echo 'running speedtest (override-frag, node1 <- node2)... '
ip netns exec "${node2}" iperf3 -s -1 > /dev/null 2>&1 &
iperf_pid_1=$!

sleep 1

ip netns exec "${node1}" iperf3  -B 1.2.3.4 -Rc 5.6.7.8 || echo 'iperf failed'

echo 'running speedtest (override-frag, node2 <- node1)... '
ip netns exec "${node2}" iperf3 -s -1 > /dev/null 2>&1 &
iperf_pid_2=$!

sleep 1

ip netns exec "${node1}" iperf3 -B 1.2.3.4 -c 5.6.7.8 || echo 'iperf failed'

kill $iperf_pid_1 || true
kill $iperf_pid_2 || true

read -p 'all tests completed; you may continue to play with the netns, or press enter to cleanup and exit. '

wait

