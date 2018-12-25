ip link del dev s1-h1
ip link del dev s1-h2
ovs-vsctl del-br s1
ip netns del h1
ip netns del h2

ip netns add h1
ip netns add h2
ovs-vsctl add-br s1

ip link add name s1-h1 type veth peer name h1-eth0
ip link set h1-eth0 netns h1
ovs-vsctl add-port s1 s1-h1
ip link set dev s1-h1 up

ip netns exec h1 ip addr add 10.0.0.1/24 dev h1-eth0
ip netns exec h1 ip link set dev h1-eth0 up

ip link add name s1-h2 type veth peer name h2-eth0
ip link set h2-eth0 netns h2
ovs-vsctl add-port s1 s1-h2
ip link set dev s1-h2 up

ip netns exec h2 ip addr add 10.0.0.2/24 dev h2-eth0
ip netns exec h2 ip link set dev h2-eth0 up

ovs-vsctl set-controller s1 tcp:127.0.0.1:6633
