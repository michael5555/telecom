#ifndef CLICK_MEMBERSHIPREPORTSOURCE_HH
#define CLICK_MEMBERSHIPREPORTSOURCE_HH
#include <click/element.hh>
#include <click/ipaddress.hh>

CLICK_DECLS



struct group_record {
	uint8_t type;
	uint8_t aux_len;//=0
	uint16_t numsources;
	IPAddress multicast;
	Vector<IPAddress> addresses;
};

struct interface_record {
	IPAddress multicast;
	Vector<IPAddress> addresses;//=always empty in our case
	int mode;//2 = exclude , 1 = include
};

struct igmp_report_packet {
	uint8_t querytype;//=0x22
	uint8_t reserved;//=0
	uint16_t checksum;
	uint16_t reserved2;//=0
	uint16_t numgroups;//??
	Vector<group_record> groups;//??
};

class MembershipReportSource : public Element {
public:
	MembershipReportSource();
	~MembershipReportSource();

	const char *class_name() const { return "MembershipReportSource"; }
	const char *port_count() const { return "0-1/1"; }
	const char *processing() const { return PUSH; }
	int configure(Vector<String>&, ErrorHandler*);

	//Packet* pull(int);

	static int writer(const String &conf, Element *e, void *thunk, ErrorHandler* errh);
	void add_handlers();

private:
	Packet* make_packet(int);

	IPAddress _srcIP;
	IPAddress _dstIP;
	uint32_t _sequence;

	Vector<struct interface_record> interface_state;
};

CLICK_ENDDECLS
#endif

