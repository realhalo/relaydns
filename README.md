What is RelayDNS?

RelayDNS is a special-purpose authoritative DNS server which is intended to serve as a temporary key-value store to channel arbitrary data over the internet.


How does RelayDNS work?

In simple terms, by resolving value.key.domain.tld (assuming domain.tld's nameservers use RelayDNS) sets the specified "key" to the "value" for a specified period of time before it's released.
If the key sets successfully 0.0.0.0 (or :: for AAAA) is returned, if the key is already taken 255.255.255.255 (or ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff for AAAA) is returned.
This key's value can be found by requesting either a CNAME or TXT record of key.domain.tld.  The amount of time the key exists is determined by the configuration, but generally is no more than 10 minutes.


What is the purpose of RelayDNS?

RelayDNS is intended to be used for arbitrary tunneling and network bypassing purposes.
Since RelayDNS was designed to have no control over the data it receives or sends out it falls upon clients to implement security and purpose.
An basic functional chat client named "Narrowcast" (for .NET) has been created to demonstrate encrypted chat that is completely controlled by like-minded Narrowcast clients using RelayDNS, removing concern of potentially compromised servers.


How do I use RelayDNS?

Download and compile this source to one or more machines with a public static IPs.
Then, install Redis to one machine and configure(mentioned below).
Finally point your domain's nameservers to these static ips, RelayDNS will automatically work for any domain pointed at it.
You will likely want to throw RelayDNS and specified arguments into a cronjob that runs every ~5 minutes as root (for port 53, privileges are dropped), only one instance will run at a time.


How do I configure RelayDNS's distributed configuration (for multiple DNS servers)?

	Connect to your Redis server and run the following applicable commands.

	Select configuration DB (same integer as you use for ./relaydns -X 1):
		> SELECT 1

	Set/Change your nameserver IPs (required):
		> DEL conf:ns
		> LPUSH conf:ns "3.1.3.37" "3.1.3.38"
		> DEL conf:ns6
		> LPUSH conf:ns "313::37" "313::38"

	Set/Change key TTL(the higher this is the more memory your redis instance needs, required):
		> set conf:key_exp 895

	Set/Change your root ip(ie. domain.tld A/AAAA records to go to a static site/elsewhere, optional):
		> SET conf:root_ip 3.1.3.37
		> SET conf:root_ip6 313::37

	Set/Change root TXT record(optional):
		> set conf:root_txt "TXT RECORD HERE"

