#ifndef GADGET_DNS_COMMON_H
#define GADGET_DNS_COMMON_H

// Max DNS name length: 255
// https://datatracker.ietf.org/doc/html/rfc1034#section-3.1
#define MAX_DNS_NAME 255

struct event_t {
	union {
		__u8 saddr_v6[16];
		__u32 saddr_v4;
	};
	union {
		__u8 daddr_v6[16];
		__u32 daddr_v4;
	};
	__u32 af; // AF_INET or AF_INET6

	__u16 id;
	unsigned short qtype;

	// qr says if the dns message is a query (0), or a response (1)
	unsigned char qr;
	unsigned char pkt_type;

  __u16 answer_count;
  __u16 authority_count;

	__u8 name[MAX_DNS_NAME];

  // IF answer_count > 0 the following should be valid.
  __u32 ans_ttl;
	union {
		__u8 ans_addr_v6[16];
		__u32 ans_addr_v4;
	};
};

#endif
