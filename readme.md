
# Traceroute

It's a simple traceroute command line application, that enables you to see the route packages - send by you - "travel" on the way to their destination.

# Example

```
traceroute to 'myexampleaddr.com' (128.203.255.124) reverse DNS 'my-reverse-dns.net', 32 hops max, 64 bytes packets
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
This are just some random example addresses

# Build

## Linux

```
make [conf=]
```
conf is a parameter used to control optimization.  
conf=d: Debugging build, with [-g && -ggdb] flags  
conf=of: -Ofast  
conf= or just use without conf for [-O2]

## Windows  

Simply use the provided .sln for visual studio.

## Other  

If you want to use something else it's pritty trivial since the project consists only of a single .cpp file, the rest is defined in header files. Simply compile the .cpp file and be good to go.  

## Errors  

If you get errors regarding platform dependend includes etc. make sure to
```
#define __linux__
#undef  _WIN32
```
when compiling for linux or
```
#define _WIN32
#undef  __linux__
```
when compiling for windows.

Even better than defining this in each header seperately, is to use your compiler specific define flag.  
GCC & Clang:
```
-D __linux__ | -D _WIN32
```