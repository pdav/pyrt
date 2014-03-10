
# Changes in isis.py from version 2.9 by Richard Mortier

 * Point-to-point adjacencies
 	- Generate point-to-point IS to IS Hello PDUs
 	- Support for three-way handshake (RFC 5303)

 * LS and CSN PDUs acknowledgement
 	- Generate Partial Sequence Numbers (PSN) PDUs to acknowledge incoming LSPs
 	- Generate PSNPs to request information for outdated LSP upon receiving a CSNP

 * Security
 	- Support for plain text authentication

 * Decode extra TLV fields including:
 	- Extended IS and IP reachability (RFC 5305)
 	- Restart signaling (RFC 5306)
 	- IPv6 related fields (RFC 5308)
 	- Multi-topology related fields (RFC 5120)

