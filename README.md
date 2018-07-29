# SNMP
Discovers interfaces and monitors traffic in a device

SNMP ROGRAMMING PROJECT
FUNCTIONAL SPECIFICATION

This program is intended to discover device interfaces, discover what devices those interfaces are connected to at an IP level (neighboring devices), and monitor the traffic on the device’s interfaces. The user needs to supply the time intervals between samples, number of samples to take, IP address of the agent, and the community. It is easier to read than the default output one would get using the terminal.

It prints a message “printing neighboring IP addresses of device” and proceeds to return the IP addresses of neighboring devices. It also discovers the total number of interfaces on the device specified by the user. This number is later used in the main portion of the code to loop through all interfaces while monitoring the traffic on the device interfaces.

The output states the sample number currently being returned to the user. Each interface has IP information, the total number of octets received on the interface, and the total number of octets transmitted out of the interface. Each time, these numbers change. Originally, “ifSpeed” was being used to retrieve objects, but this was only for the bandwidth, so it was changed to “ifInOctets” and “ifOutOctets”.


DESIGN SPECIFICATION
 
The simple application example on the Net-SNMP website was very helpful in learning how to use the library and write a program. There’s a main method that takes in the required input from the user and stores them in global variables. Then, it calls a begin() function that initializes a session, defining which system the program will be communicating with. The version of SNMP being used is SNMPv2 (for the GetBulk operation used to retrieve neighboring devices). In the begin() function, it first finds all neighboring devices and prints their IPs, then goes into a nested for loop (until the number of specified samples, and the number of interfaces retrieved earlier). In the second for loop for the number of interfaces, it retrieves each interface on the device one by one and prints its IP, incoming traffic, and outgoing traffic. After retrieving an interface, the response is freed, and the session is closed so it can be reopened again.
