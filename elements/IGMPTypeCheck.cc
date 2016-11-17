#include <click/config.h>
#include <click/confparse.hh>
#include <click/error.hh>
#include "IGMPTypeCheck.hh"

CLICK_DECLS
IGMPTypeCheck::IGMPTypeCheck()
{}

IGMPTypeCheck::~IGMPTypeCheck()
{}

int IGMPTypeCheck::configure(Vector<String> &conf, ErrorHandler *errh) {
	if (cp_va_kparse(conf, this, errh, cpEnd) < 0) return -1;

	return 0;
}

void IGMPTypeCheck::push(int , Packet* p) {
	WritablePacket *q = p->uniqueify();

	if (p == 0) {
		return;
	}

	click_ip *iph = (click_ip *)q->data();
	igmp_query_packet *igmph = (igmp_query_packet *)(iph + 1);


	if (igmph->querytype == 0x11) {
		output(0).push(q);
	}
	else if (igmph->querytype == 0x22) {
		output(0).push(q);
	}
	else {
		output(1).push(q);
	}
	click_chatter("Got a packet of size %d", p->length());
}



CLICK_ENDDECLS
EXPORT_ELEMENT(IGMPTypeCheck)

