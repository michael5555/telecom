#include <click/config.h>
#include <click/confparse.hh>
#include <click/error.hh>
#include "IGMPTypeCheck.hh"
#include <clicknet/ip.h>
#include <clicknet/ether.h>

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
	if (p == 0) {
		return 0;
	}

	WritablePacket* q = (WritablePacket*) p;

	if (q->querytype == 0x11) {
		output(0).push(q);
	}
	else if (q->querytype == 0x22) {
		output(0).push(q);
	}
	else {
		output(1).push(q);
	}
	click_chatter("Got a packet of size %d", p->length());
}



CLICK_ENDDECLS
EXPORT_ELEMENT(IGMPTypeCheck)

