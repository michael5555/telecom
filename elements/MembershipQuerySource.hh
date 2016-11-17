#ifndef CLICK_MEMBERSHIPQUERYSOURCE_HH
#define CLICK_MEMBERSHIPQUERYSOURCE_HH
#include <click/element.hh>
#include <click/ipaddress.hh>

CLICK_DECLS

struct resv_s_qrv {
	uint8_t qrv : 3;
	uint8_t s : 1;
	uint8_t resv : 4;
    
    resv_s_qrv(uint8_t r, uint8_t ss , uint8_t q){
        
        resv = r;
        s = ss;
        qrv = q;
    }
};


struct igmp_query_packet {
    
    uint8_t querytype;//=0x11
    uint8_t maxrespcode;//100, change using handler
    uint16_t checksum;
    IPAddress groupaddress;//HANDLER!!!
	resv_s_qrv  fields;
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
		const char *processing() const	{ return AGNOSTIC; }
		int configure(Vector<String>&, ErrorHandler*);
		
		Packet* pull(int);

		void run_timer(Timer*);

		static int writer(const String &conf, Element *e, void *thunk, ErrorHandler* errh);
		static int ipwriter(const String &conf, Element *e, void *thunk, ErrorHandler* errh);
		void add_handlers();

	private:
		Packet* make_packet();
		int s;
		int qrv;
		uint8_t maxrespcode;
		uint8_t qqic;
		IPAddress group;

		IPAddress _srcIP;
		IPAddress _dstIP;
		uint32_t _sequence;
};

CLICK_ENDDECLS
#endif

