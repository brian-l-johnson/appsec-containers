#!/usr/bin/python

import sys
import nmap
#enum_ssl_results = '\n  TLSv1.0: \n    ciphers: \n      TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA (rsa 2048) - A\n      TLS_RSA_WITH_AES_128_CBC_SHA (rsa 2048) - A\n      TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA (rsa 2048) - A\n      TLS_RSA_WITH_AES_256_CBC_SHA (rsa 2048) - A\n      TLS_RSA_WITH_3DES_EDE_CBC_SHA (rsa 2048) - C\n    compressors: \n      NULL\n    cipher preference: server\n    warnings: \n      64-bit block cipher 3DES vulnerable to SWEET32 attack\n  TLSv1.1: \n    ciphers: \n      TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA (rsa 2048) - A\n      TLS_RSA_WITH_AES_128_CBC_SHA (rsa 2048) - A\n      TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA (rsa 2048) - A\n      TLS_RSA_WITH_AES_256_CBC_SHA (rsa 2048) - A\n      TLS_RSA_WITH_3DES_EDE_CBC_SHA (rsa 2048) - C\n    compressors: \n      NULL\n    cipher preference: server\n    warnings: \n      64-bit block cipher 3DES vulnerable to SWEET32 attack\n  TLSv1.2: \n    ciphers: \n      TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 (rsa 2048) - A\n      TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 (rsa 2048) - A\n      TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA (rsa 2048) - A\n      TLS_RSA_WITH_AES_128_GCM_SHA256 (rsa 2048) - A\n      TLS_RSA_WITH_AES_128_CBC_SHA (rsa 2048) - A\n      TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 (rsa 2048) - A\n      TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA (rsa 2048) - A\n      TLS_RSA_WITH_AES_256_GCM_SHA384 (rsa 2048) - A\n      TLS_RSA_WITH_AES_256_CBC_SHA (rsa 2048) - A\n      TLS_RSA_WITH_3DES_EDE_CBC_SHA (rsa 2048) - C\n    compressors: \n      NULL\n    cipher preference: server\n    warnings: \n      64-bit block cipher 3DES vulnerable to SWEET32 attack\n  least strength: C'


def parseSSLEnumCiphers(script_str):
	results = {}
	protocol = ""
	section = ""
	for line in script_str.splitlines():
		if(countLeadingSpaces(line) == 2):
			if(line.startswith("  least strength")):
				results["least strength"] = line[-1]
			else:
				protocol = line.strip(' :')
				results[protocol] = {}
		if(countLeadingSpaces(line) == 4):
			section = line.lstrip()
			if(not section.endswith(": ")):
				res = section.split(": ")
				results[protocol][res[0]] = res[1]
			else:
				section =section.strip(": ")
				results[protocol][section] = [];
		if(countLeadingSpaces(line)== 6):
			results[protocol][section].append(line.lstrip())
	return results



def countLeadingSpaces(str):
	for i in range(0, len(str)):
		if(str[i] != " "):
			return i
	return len(str)


if(len(sys.argv) >1):
	nm = nmap.PortScanner()
	port = 443
	host = ""
	if(":" in sys.argv[1]):
		res = sys.argv[1].split(":")
		host = res[0]
		port = res[1]
	else:
		host = argv[1]
	print("scanning "+host+" on port "+port)
	nm.scan(hosts=host, arguments="-p "+port+" --script +ssl-enum-ciphers")
	print(parseSSLEnumCiphers(nm[nm.all_hosts()[0]].tcp(int(port))['script']['ssl-enum-ciphers']))

#print(parseSSLEnumCiphers(enum_ssl_results))
