AddressInfo(sourceAddr 10.0.0.1 1A:7C:3E:90:78:41)
AddressInfo(responderAddr 10.0.0.2 1A:7C:3E:90:78:42)

source::MembershipQuerySource( SRC sourceAddr);


source
    -> EtherEncap(0x0800, sourceAddr,responderAddr)
    -> ToDump(switch.dump)
    -> Discard
