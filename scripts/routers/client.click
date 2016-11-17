// Output configuration: 
//
// Packets for the network are put on output 0
// Packets for the host are put on output 1

AddressInfo(sourceAddr 192.168.2.1/24 00:50:BA:85:84:B2)

AddressInfo(router_client_network1_address 192.168.2.254/24 00:50:BA:85:84:B1)




elementclass Client {
	$address, $gateway |

	ip :: Strip(14)
		-> CheckIPHeader()
		//-> checker::IGMPTypeCheck

	//checker[0]
		-> rt :: StaticIPLookup(
					$address:ip/32 0,
					$address:ipnet 0,
					0.0.0.0/0.0.0.0 $gateway 1)
		-> [1]output;
	
	/*checker[1]
		->Discard*/

	rt[1]
		-> DropBroadcasts
		-> ipgw :: IPGWOptions($address)
		-> FixIPSrc($address)
		-> ttl :: DecIPTTL
		-> frag :: IPFragmenter(1500)
		-> arpq :: ARPQuerier($address)
		-> output;

	ipgw[1]
		-> ICMPError($address, parameterproblem)
		-> output;
	
	ttl[1]
		-> ICMPError($address, timeexceeded)
		-> output; 

	frag[1]
		-> ICMPError($address, unreachable, needfrag)
		-> output;

	// Incoming Packets
	input
		-> HostEtherFilter($address)
		-> in_cl :: Classifier(12/0806 20/0001, 12/0806 20/0002, 12/0800)
		-> arp_res :: ARPResponder($address)
		-> output;

	in_cl[1]
		-> [1]arpq;
	
	in_cl[2]
		-> ip;
}

source::MembershipQuerySource(SRC sourceAddr)
	->Unqueue
	->client::Client(sourceAddr,router_client_network1_address)

client[0]
	-> ToDump(switch.dump)
	-> Discard

client[1]
	-> ToDump(switch2.dump)
	-> Discard