#ifndef CLICK_MEMBERSHIPQUERYSOURCE_HH
#define CLICK_MEMBERSHIPQUERYSOURCE_HH
#include <click/element.hh>
#include <click/ipaddress.hh>

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
	resv_s_qrv* fields;
    uint8_t qqic;//125, change using handler
    uint16_t numsources;//=0
    Vector<IPAddress> source_addresses;//empty
};

class MembershipQuerySource : public Element { 
	public:
		MembershipQuerySource();
		~MembershipQuerySource();
		
		const char *class_name() const	{ return "MembershipQuerySource"; }
		const char *port_count() const	{ return "0-1/1"; }
		const char *processing() const	{ return PULL; }
		int configure(Vector<String>&, ErrorHandler*);
		
		Packet* pull(int);

		static int writer(const String &conf, Element *e, void *thunk, ErrorHandler* errh);
		static int ipwriter(const String &conf, Element *e, void *thunk, ErrorHandler* errh);
		void add_handlers();

	private:
		Packet* make_packet();
		uint1_t s;
		uint3_t qrv;
		uint8_t maxrespcode;
		uint8_t qqic;
		IPAddress group;

		IPAddress _srcIP;
		IPAddress _dstIP;
		uint32_t _sequence;
};

CLICK_ENDDECLS
#endif

