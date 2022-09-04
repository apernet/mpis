MPIS (Multiprotocol IP Switching)
---

MPIS is an eBPF-based "tunneling" technique. The word "tunnel" is stated in quotes since this is not actually a tunnel. It also has the benefit of not losing any MTU during "tunneling."

It does come some costs. Namely: 

- To use this tunnel, you must have a connection that does not enforce source address filtering (a.k.a. reverse path filtering);
- For each tunnel endpoint, it is only possible to pass traffic for hosts within the same subnet. The size of the source subnet can be up to /16;
- The ability of IP-layer fragmentation may be affected, depending on the size of the subnet you decided to tunnel. 

### How it works

Reading the drawbacks above, you might have guessed how it works. MPIS uses the IP identification field to save the sender information. The receiver then restores the info from the ID field upon reception. The sender is doing the followings:

```c
ip->id = (((__u16 *) (&ip->saddr))[1] & ~tunneled_subnet_mask_last_16bit) | (ip->id & tunneled_subnet_mask_last_16bit);
ip->saddr = ip->daddr;
ip->daddr = target;
```

...basically, if you are trying to tunnel a /24 subnet, the least significant 8 bits of the IP ID field will be overridden with the least significant 8 bits of the source IP address. It then swaps the source and destination address and sets the new destination address to `target` - this `target` is the IP address of the tunnel receiver.

And on the receiver side:

```c
ip->daddr = ip->saddr;
ip->saddr = entry->tunneled_subnet | ((ip->id & ~tunneled_subnet_mask_last_16bit) << 16);
```

...it swaps the source and destination address back, then does a bitwise-or with the IP ID field to recover the real sender IP. At this point, we have recovered the original IP datagram (8-bits in the ID field are lost, but that should not have too big of an impact). 

Let's consider this more realistic example: say, you have two sites - one at SJC and the other one at LAX. You want a tunnel between the sites. You don't want to get the expensive L2 transit; you also don't have access to ISP's jumbo-frame-enabled IP transit. You don't want to GRE or IPIP - they drop your MTU. What's the fun in that? Let's assume that: 

- You want to tunnel traffic from SJC subnet `192.0.2.0/24` to your premium China transit you purchased at LAX.
- You have a Linux router at `203.0.113.1` at LAX as tunnel receiver.
- A host, `192.0.2.123`, is trying to reach `120.232.0.1` over the "tunnel."

This is what will happen on the tunnel sender: 

1. The tunnel sender receives a packet from `192.0.2.123`:
    ````
    192.0.2.123 -> 120.232.0.1 [IP_ID = 0x1145]
    ````
2. Tunnel sender rewrites the `IP_ID` field with last 8 bit of the source IP address:
    ```
    192.0.2.123 -> 120.232.0.1 [IP_ID = 0x117b]
    ```
3. Tunnel sedner swaps the src/dst address:
    ```
    120.232.0.1 -> 192.0.2.123 [IP_ID = 0x117b]
    ```
4. Tunnel sender rewrites the dst address as tunnel receiver:
    ```
    120.232.0.1 -> 203.0.113.1 [IP_ID = 0x117b]
    ```

Now, this packet will be delivered to `203.0.113.1`. This is your tunnel receiver. Upon packet reception, the tunnel receiver does the followings:  

1. The tunnel receiver extracts the last 8 bit of IP ID field: 
    ```
    120.232.0.1 -> 203.0.113.1 [IP_ID = 0x117b, IP_ID_LAST8 = 0x7b]
    ```
2. Tunnel receiver swaps the src/dst address:
    ```
    203.0.113.1 -> 120.232.0.1 [IP_ID_LAST8 = 0x7b]
    ```
3. Tunnel receiver set the source address as the network address of the tunneled prefix:
    ```
    192.0.2.0 -> 120.232.0.1 [IP_ID_LAST8 = 0x7b]
    ```
4. Tunnel receiver does a bitwise or between `IP_ID_LAST8` and source address:
    ```
    (192.0.2.0 | 0x7b) = 192.0.2.123 -> 120.232.0.1
    ```

At this point, we can forward this packet as we normally would. 

### Usage

To build MPIS:

```
$ sudo apt install build-essential clang llvm libelf-dev gcc-multilib linux-headers-`dpkg --print-architecture`
$ git clone https://github.com/apernet/mpis
$ cd mpis
$ git submodule update --init
$ make
```

To configure MIPS, you will need to define a MIPS route table. Syntax:

```
iif <in-interface-name> src <network>/<length> encap <receiver> cutoff-ttl <ttl>
iif <in-interface-name> dst <local-ip> swap <next-receiver> cutoff-ttl <ttl>
iif <in-interface-name> dst <local-ip> decap <network>/<length>
```

There are three types of actions: `encap`, `swap`, and `decap`.

#### encap

`encap` action "encapsulates" the traffic by overriding the ID field, swapping src/dst, and changing dst to the given `receiver`. `cutoff-ttl` allows you to define a TTL value, where if the TTL of the packet is lower than the given value, MPIS will not change the ID field and source IP. 

This means that if users were to do a traceroute, until the given TTL, users were actually tracing to the tunnel receiver. Hops on the path to the tunnel receiver will reply with the TTL expired message. Since that is the same path tunneled packet will actually travel, it can be useful for troubleshooting. 

#### swap

`swap` action changes the destination address again, potentially relaying the tunneled traffic to another receiver. `cutoff-ttl` is not working correctly for `swap` yet.

#### decap

`decap` action "decapsulates" the traffic that was previously `encap`-ed by the sender.

### Configuration example

Putting the example in "how it works" as configuration files will look something like this: 

SJC site:

```
iif eth1 src 192.0.2.0/24 encap 203.0.113.1
```

LAX site:

```
iif eth0 dst 203.0.113.1 decap 192.0.2.0/24
```

Note that this only creates a one-side path (SJC -> LAX).  

### Running

To run `mpis`, use `mpis-routectl`:

```
usage: ./mpis-routectl [-adhrs] -t mpis-table-file -e epbf-object [interfaces ...]
    -a: attach (default)
    -d: detach
    -r: re-attach
    -s: xdp skb mode
    -h: help
```

For example, to run on `eth0` and `eth1`, using `routes.conf` as route configuration:

```
$ sudo ./mpis-routectl -t routes.conf -e mpis-ebpf.o eth0 eth1
```

If it fails, try running in SKB mode (`-s`). Note that the error `libbpf: Error in bpf_create_map_xattr(encap_map):Invalid argument(-22). Retrying without BTF.` can be safely ignored.

### Misc

#### Why "MPIS"?

Well, that just sounded right to me. MPLS swaps labels, and MPIS swaps IP addresses. MPLS operates at layer 2, so it can carry "MP" layer 2 traffics. IP operates at layer 3, so MPIS carries layer 3 "MP" traffic (i.e., UDP, TCP, ICMP, GRE, etc.)

#### About IP fragmentation

When tunneling a `/24`, we are talking 8 bits away from the ID field. This means there can only be 256 unique IDs for actual fragmentation. In most workloads, this really shouldn't matter. IP-layer fragmentation is quite rare; at least, you won't see any impact on your normal TCP connections. 

If fragmentation is really that important - we can always reduce the subnet size. Tunneling `/28` each receiver IP will give 12 bits for ID (4,096 unique IDs). I can't really think of any normal workflow that would cause this many unique fragmented flows.

#### Security consideration 

Potentially, this will allows others to have your network send spoof packets against their source IP address. Not sure how useful that will be. 