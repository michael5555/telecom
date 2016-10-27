#ifndef CLICK_MEMBERSHIPQUERYSOURCE_HH
#define CLICK_MEMBERSHIPQUERYSOURCE_HH
#include <click/element.hh>
CLICK_DECLS


struct igmpquerypacket {
    
    uint8_t querytype = 0x11;
    uint8_t maxrespcode;
    uint16_t checksum;
    IPAddress groupaddress;
    uint4_t resv
    uint1_t s;
    uint3_t qrv;
    uint8_t qqic;
    uint16_t numsources;
    Vector<IPAddress> source_addresses;
};

class MembershipQuerySource : public Element { 
	public:
		MembershipQuerySource();
		~MembershipQuerySource();
		
		const char *class_name() const	{ return "MembershipQuerySource"; }
		const char *port_count() const	{ return "0/1"; }
		const char *processing() const	{ return PULL; }
		int configure(Vector<String>&, ErrorHandler*);
		
		Packet* pull(int);

	private:
		Packet* make_packet();
};

CLICK_ENDDECLS
#endif

