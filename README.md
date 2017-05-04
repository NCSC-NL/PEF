# Privacy Enhanced Filtering

A research prototype application demonstrating network traffic pseudonymization
using a model-driven engineering approach.

It uses declarative definitions to parse the following data structures:

- Link Layer:        Ethernet 2 Frame
- Internet Layer:    IPv4, ICMPv4, _IPv6 partially_
- Transport Layer:   UDP, TCP
- Application Layer: DNS formatted application data (DNS, MDNS, LLMNR, NBNS)

These are used to find network packets containing valid DNS requests and responses.

Supplied is a Java implementation of a format preserving encryption algorithm
that is used to pseudonymize IP addresses of internet packets containing DNS data.

## Limitations

Here is a list of known limitations of this PEF implementation:

- IPv6 parsing is not fully supported.
  (extension headers are not fully supported and only UDP/TCP/IPv4(IP in IP) are parsed further)
- TCP reassembly in order to recognize DNS payload over TCP is not supported yet. for example,
  large DNS transfers can be segmented over multiple packets)
- Only the protocols stated at the top are supported
- If for some reason packet data is not fully parsed, the packet is left untouched
- At least 8 bits have to be pseudonymized, or none
  
Limitations of the command line tool:
- Works only on PCAP and PCAPNG files

## Requirements:

- Java Runtime Environment 7
- Maven
- The test suite uses [jNetPcap](http://jnetpcap.com/), which requires a native PCAP library, such 
  as `libpcap-dev` on Ubuntu or `WinPcap` on Windows.

## Usage

A command line tool is built around this implementation. This tool can can be used to pseudonymize 
DNS packets in PCAP/PCAPNG files.

Build the application:

```
$ mvn clean package
```

Show the command line tool usage:

```
$ java -jar target/pef-0.9.0-jar-with-dependencies.jar -h

```

An example run could be:

```
$ java -jar target/pef-0.9.0-jar-with-dependencies.jar -i inputfile.pcap -o anonymized.pcap -4 0123456789ABCDEF0123456789ABCDEF /10 -6 0123456789ABCDEF0123456789ABCDEF /55 -c ipv4,icmp,udp -m 4

```

Explanation:

- `java -jar target/pef-0.9.0-jar-with-dependencies.jar` - execute the command line tool, pseudonymizes IP addresses of packets with DNS formatted application data
- `inputfile.pcap` - the input file to process (PCAP or PCAPNG)
- `anonymized.pcap` - the output file to write the results to
- `-4 0123456789ABCDEF0123456789ABCDEF /10` - pseudonymize IPv4 source and destination addresses, using format preserving encryption with the given key, but leave first ten bits untouched
- `-6 0123456789ABCDEF0123456789ABCDEF /55` - same as above, but for IPv6
- `-c ipv4,icmp,udp` - recalculate the IPv4 header, ICMP and UDP checksum (another possibility is `-c all`)
- `-m 4` - run across four threads

The pseudonymization parameter specifies the key to use and how much of the original message to transform. The key should be a 32 character hexadecimal string, 
representing 16 bytes, i.e. a 128-bit key. The part of the message to transform is determined by the mask. This value determines how many of the most significant
bits to keep. For example: IP address 255.255.255.255 with /8 mask will pseudonymize to 255.x.x.x, where x are the encrypted values.

## License

Copyright 2015, 2016, 2017 National Cyber Security Centre and Netherlands Forensic Institute

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

