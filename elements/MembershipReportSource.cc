#include <click/config.h>
#include <click/confparse.hh>
#include <click/error.hh>
#include "MembershipReportSource.hh"
#include <clicknet/ip.h>
#include <clicknet/ether.h>


CLICK_DECLS
MembershipReportSource::MembershipReportSource()
{}

MembershipReportSource::~MembershipReportSource()
{}

int MembershipReportSource::configure(Vector<String> &conf, ErrorHandler *errh) {
	if (cp_va_kparse(conf, this, errh, "SRC", cpkM, cpIPAddress, &_srcIP, cpEnd) < 0) return -1;
	_dstIP = IPAddress(String("224.0.0.22"));


	return 0;
}

int MembershipReportSource::writer(const String &conf, Element *e, void *thunk, ErrorHandler* errh) {
	MembershipReportSource* me = (MembershipReportSource *)e;
	IPAddress address;
	if (cp_va_kparse(conf, me, errh, "ADDR", cpkM, cpIPAddress, &address, cpEnd) < 0) return -1;
	int send;
	bool done;
	switch ((intptr_t)thunk) {
	case 0:
		send = -1;
		done = false;
		for (int i = 0; i < me->groups.size(); i++) {
			send = i;
			if (address == me->groups[i].multicast) {
				if (me->groups[i].mode == 2) {
					done = true;
					send = -1;
					break;
				}
				me->groups[i].mode = 2;
				done = true;
				break;
			}
		}
		if (!done) {
			groups.push_back(group_record(2, address));
		}
		if (send != -1) {
			Packet* p = me->make_packet(send);
			me->output(0).push(p);
			click_chatter("I left FeelsBadMan"); //add address to this!
		}
		break;
	case 1:
		send = -1;
		done = false;
		for (int i = 0; i < me->groups.size(); i++) {
			send = i;
			if (address == me->groups[i].multicast) {
				if (me->groups[i].mode == 1) {
					done = true;
					send = -1;
					break;
				}
				me->interface_state[i].mode = 1;
				done = true;
				break;
			}
		}
		if (!done) {
			groups.push_back(group_record(1, address));
			send = groups.size()-1;
		}
		if (send != -1) {
			Packet* p = me->make_packet(send);
			me->output(0).push(p);
			click_chatter("I joined FeelsGoodMan"); //add address to this!
		}
		break;
	}
	return 0;
}

void MembershipReportSource::add_handlers() {
	add_write_handler("leave", writer, 0);
	add_write_handler("join", writer, 1);
}

Packet* MembershipReportSource::make_packet(int mode) {
	int headroom = sizeof(click_ether);
	WritablePacket *q = Packet::make(headroom, 0, sizeof(click_ip) + sizeof(struct igmp_report_packet), 0);
	if (!q)
		return 0;
	memset(q->data(), '\0', sizeof(click_ip) + sizeof(struct igmp_report_packet));

	click_ip *iph = (click_ip *)q->data();

	iph->ip_v = 4;
	iph->ip_hl = sizeof(click_ip) >> 2;
	iph->ip_len = htons(q->length());
	uint16_t ip_id = ((_sequence) % 0xFFFF) + 1;
	iph->ip_id = htons(ip_id);
	iph->ip_p = 2;
	iph->ip_ttl = 1;
	iph->ip_src = _srcIP;
	iph->ip_dst = _dstIP;
	iph->ip_sum = click_in_cksum((unsigned char *)iph, sizeof(click_ip));

	igmp_report_packet *igmph = (igmp_report_packet *)(iph + 1);

	igmph->querytype = 0x22;
	igmph->numgroups = htons(interface_state.size());
	igmph->groups = this->groups;


	_sequence++;

	igmph->checksum = click_in_cksum((const unsigned char *)igmph, sizeof(igmp_report_packet));

	q->set_dst_ip_anno(_dstIP);

	return q;
}






CLICK_ENDDECLS
EXPORT_ELEMENT(MembershipReportSource)

