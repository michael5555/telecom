#include <click/config.h>
#include <click/confparse.hh>
#include <click/error.hh>
#include "MembershipQuerySource.hh"
#include <clicknet/ip.h>
#include <clicknet/ether.h>

CLICK_DECLS
MembershipQuerySource::MembershipQuerySource()
{}

MembershipQuerySource::~ MembershipQuerySource()
{}

int MembershipQuerySource::configure(Vector<String> &conf, ErrorHandler *errh) {
	if (cp_va_kparse(conf, this, errh, "SRC", cpkM, cpIPAddress, &_srcIP, cpEnd) < 0) return -1;
	this->s.value = 0;
	this->qrv.value = 2;
	this->maxrespcode = 100;
	this->qqic = 125;
	this->group = IPAddress(String("0.0.0.0"));
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

Packet* MembershipQuerySource::make_packet() {
	int headroom = sizeof(click_ether);
	WritablePacket *q = Packet::make(headroom, 0, sizeof(click_ip) + sizeof(struct igmp_query_packet), 0);
	if (!q)
		return 0;
	memset(q->data(), '\0', sizeof(click_ip) + sizeof(struct igmp_query_packet));

	click_ip *iph = (click_ip *)q->data();

	iph->ip_v = 4;
	iph->ip_hl = sizeof(click_ip) >> 2;
	iph->ip_len = htons(q->length());
	uint16_t ip_id = ((_sequence) % 0xFFFF) + 1; // ensure ip_id != 0
	iph->ip_id = htons(ip_id);
	iph->ip_p = 2;
	iph->ip_ttl = 1;
	iph->ip_src = _srcIP;
	if (group == IPAddress(String("0.0.0.0")) {
		_dstIP = IPAddress(String("224.0.0.1"));
	}
	else {
		_dstIP = group;
	}
	iph->ip_dst = _dstIP;//depends on grp
	iph->ip_sum = click_in_cksum((unsigned char *)iph, sizeof(click_ip));

	igmp_query_packet *igmph = (igmp_query_packet *)(iph + 1);

	igmph->querytype = 0x11;
	igmph->fields->s = this->s;
	igmph->maxrespcode = this->maxrespcode;
	igmph->fields->qrv = this->qrv;
	igmph->qqic = this->qqic;
	igmph->groupaddress = this->group;

	_sequence++;

	igmph->checksum = click_in_cksum((const unsigned char *)igmph, sizeof(igmp_query_packet));

	q->set_dst_ip_anno(_dstIP);

	return q;
}

int MembershipQuerySource::writer(const String &conf, Element *e, void *thunk, ErrorHandler* errh) {
	MembershipQuerySource* me = (MembershipQuerySource *)e;
	int input;
	if (cp_va_kparse(conf, me, errh, "INPUT", cpkM, cpInteger, &input, cpEnd) < 0) return -1;
	switch ((intptr_t)thunk) {
	case 0:
		uint1_t correct1;
		correct1.value = input;
		me->s = correct1;
		return 0;
	case 1:
		uint3_t correct3;
		correct3.value = input;
		me->qrv = correct3;
		return 0;
	case 2:
		me->maxrespcode = input;
		return 0;
	case 3:
		me->qqic = input;
		return 0;
	}
	return 0;
}

int MembershipQuerySource::writer(const String &conf, Element *e, void *thunk, ErrorHandler* errh) {
	MembershipQuerySource* me = (MembershipQuerySource *)e;
	IPAddress input;
	if (cp_va_kparse(conf, me, errh, "INPUT", cpkM, cpIPAddress, &input, cpEnd) < 0) return -1;
	me->group = input;
}

void MembershipQuerySource::add_handlers() {
	add_write_handler("s", writer, 0);
	add_write_handler("qrv", writer, 1);
	add_write_handler("maxrespcode", writer, 2);
	add_write_handler("qqic", writer, 3);
	add_write_handler("ip", ipwriter, 0);
}

CLICK_ENDDECLS
EXPORT_ELEMENT(MembershipQuerySource)

