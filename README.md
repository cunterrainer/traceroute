
# Traceroute

It's a simple traceroute command line application, that enables you to see the route packages - send by you - "travel" on the way to their destination.

# Example

```
traceroute to 'myexampleaddr.com' (128.203.255.124) reverse DNS 'my-reverse-dns.net', 32 hops max, 64 byte packets
1. 16.46.10.225    ttl=1 rtt=2.15313 ms
2. 229.154.175.62  ttl=2 rtt=9.02325 ms
3. 26.64.71.223    ttl=3 rtt=11.8219 ms
4. 159.187.76.192  ttl=4 rtt=11.1212 ms
5. 147.245.82.44   ttl=5 rtt=14.1749 ms
6. 173.127.137.66  ttl=6 rtt=11.4544 ms
7. 128.203.255.124 ttl=7 rtt=10.6382 ms

Traceing time:   7075.42 ms | 7.07541 sec
Traceroute time: 7103.23 ms | 7.10323 sec
```
This are randomly generated sample addresses

# Status

- [x] Linux
    - [x] IPv4
    - [ ] IPv6
- [ ] Windows
    - [ ] IPv4
    - [ ] IPv6

Windows `IPv4` is almost done.  
Current implementation status: It's a ping just without the ability to trace the package.  
`IPv6` for windows and linux will be implemented in the near future.

# Build

This project uses premake as it's build system. The premake5 binaries for windows and linux are already provided.  
For additional information use:
```
./vendor/premake5 --help
```

## Clone

```
git clone https://github.com/pyvyx/traceroute.git
```
```
cd traceroute
```

## Visual Studio

```
vendor\premake5.exe vs2022
```
This should have generated a .sln file

## Make

### Linux

```
./vendor/premake5 gmake [cc]
```

### Windows

```
vendor\premake5.exe gmake [cc]
```

GCC should already be the default compiler, however you can explicitly specify it if you'd like.  
GCC:   --cc=gcc  
Clang: --cc=clang

### Build

```
make config=<configuration>
```
Configurations:
 - debug_x86
 - debug_x64 (default, the same as just using `make`)
 - release_x86
 - release_x64

```
make help
```
for additional information
