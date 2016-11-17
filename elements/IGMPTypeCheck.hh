#ifndef CLICK_IGMPTYPECHECK_HH
#define CLICK_IGMPTYPECHECK_HH
#include <click/element.hh>
#include <click/ipaddress.hh>

CLICK_DECLS


class IGMPTypeCheck : public Element {
public:
	IGMPTypeCheck();
	~IGMPTypeCheck();

	const char *class_name() const { return "IGMPTypeCheck"; }
	const char *port_count() const { return "1/2"; }
	const char *processing() const { return PUSH; }
	int configure(Vector<String>&, ErrorHandler*);

	void push(int,Packet*);

private:

};

CLICK_ENDDECLS
#endif

