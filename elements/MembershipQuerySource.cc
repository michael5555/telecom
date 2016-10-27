#include <click/config.h>
#include <click/confparse.hh>
#include <click/error.hh>
#include "MembershipQuerySource.hh"

CLICK_DECLS
MembershipQuerySource::MembershipQuerySource()
{}

MembershipQuerySource::~ MembershipQuerySource()
{}

int MembershipQuerySource::configure(Vector<String> &conf, ErrorHandler *errh) {
	if (conf.size() <= 0) {
		errh->error("Conf should be empty");
		return -1;
	}
	if (cp_va_kparse(conf, this, errh, cpEnd) < 0) return -1;
	
	return 0;
}

Packet* MembershipQuerySource::pull(int){
	Packet* p = input(0).pull();
	if(p == 0){
		return 0;
	}
	click_chatter("Got a packet of size %d",p->length());
	return p;
}

CLICK_ENDDECLS
EXPORT_ELEMENT(MembershipQuerySource)

