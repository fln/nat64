Linux kernel NAT64 module
=========================

This is a NAT64 implementation for linux as a kernel module.

To use this module you must have IPv4 and IPv6 prefixes dedicated for the NAT64 
service. It can not be used with the same IP addresses that is already used on 
other network interfaces (like convential linux NAT44 can be used). This 
limitation can be avoided by additional layer of conventional linux NAT44. This 
additional layer of NAT44 is only needed if server does not have dedicated IPv4 
prefix for NAT64 service.

Module usage
------------

To compile this module simply use make. Compiled module will be named 
*nat64.ko*.

To insert module you must specify IPv4 prefix that will be used for translation.
IPv6 prefix is optional (if unspecified, a well-known prefix 64:ff9b::/96 will 
be used).

