#ifndef CLICK_MEMBERSHIPQUERYSOURCE_HH
#define CLICK_MEMBERSHIPQUERYSOURCE_HH
#include <click/element.hh>
CLICK_DECLS

typedef struct { unsigned value : 4; } uint4_t;
typedef struct { unsigned value : 3; } uint3_t;
typedef struct { unsigned value : 1; } uint1_t;

struct resv_s_qrv {
	uint4_t resv;//=0
	uint1_t s;//=0, change using handler
	uint3_t qrv;//=2, change using handler
};


struct igmp_query_packet {
    
    uint8_t querytype;//=0x11
    uint8_t maxrespcode;//100, change using handler
    uint16_t checksum;
    IPAddress groupaddress;//HANDLER!!!
	resv_s_qrv fields;
    uint8_t qqic;//125, change using handler
    uint16_t numsources;//=0
    Vector<IPAddress> source_addresses;//empty
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

		IPAddress _srcIP;
		uint32_t _sequence;
};

CLICK_ENDDECLS
#endif

