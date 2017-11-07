#include "send_packet.h"

//在mian.c里面把这个结构体改成全局的变量 把static去掉
extern struct rte_mempool * pktmbuf_pool[NB_SOCKETS];

#include "CoLoR.h"


static int
pktgen_ctor_ether_header(struct ether_hdr * eth,struct rte_mbuf * m)
{
	struct ether_hdr * ether_header = eth;
	int i;
	uint8_t addr1[6]={00,0x16,0x31,0xfe,0xe6,0x90};
	uint8_t addr2[6]={00,0x16,0x31,0xfe,0xe6,0x91};
	for(i=0;i<6;i++)
	{
		ether_header->d_addr.addr_bytes[i] = addr2[i];
	}
	for(i=0;i<6;i++)
	{
		ether_header->s_addr.addr_bytes[i] = addr1[i];
	}
	ether_header->ether_type=0x0008;
	memcpy(rte_pktmbuf_mtod_offset(m,struct ether_hdr*,0),ether_header,sizeof(struct ether_hdr));
	return sizeof(struct ether_hdr);
}

static int
pktgen_ctor_ip_header(struct ipv4_hdr * ip,struct rte_mbuf *m)
{
	struct ipv4_hdr * ip_header=ip;
	ip_header->version_ihl=0x45;
	ip_header->type_of_service=0;
	ip_header->total_length=0;
	ip_header->packet_id=0;
	ip_header->fragment_offset=0;
	ip_header->time_to_live=4;
	ip_header->next_proto_id=10;
	ip_header->hdr_checksum=0;
	ip_header->src_addr=htonl(IPv4(192,168,1,2));
	ip_header->dst_addr=htonl(IPv4(192,168,18,24));
	memcpy(rte_pktmbuf_mtod_offset(m,struct ipv4_hdr*,sizeof(struct ether_hdr)),ip_header,sizeof(struct ipv4_hdr));
	return sizeof(struct ipv4_hdr);
}

static int 
pktgen_ctor_control_public_header(struct rte_mbuf *m)
{
	control_public_header_t * control_public_hdr=rte_pktmbuf_mtod_offset(m,control_public_header_t*,sizeof(struct ether_hdr)+sizeof(struct ipv4_hdr));
	
	control_public_hdr->version_type=TYPE_CONTROL;
	control_public_hdr->control_type=control_type_register;
	
	return sizeof(control_public_header_t);
}

static int
pktgen_ctor_register(struct rte_mbuf *m)
{
	
	control_register_t * control_register_hdr= \
		rte_pktmbuf_mtod_offset(m,control_register_t*,sizeof(struct ether_hdr)+sizeof(struct ipv4_hdr)+sizeof(control_public_header_t) );
	
	uint8_t n_sid[NID_LENGTH]={0x0,0x0,0x0,0x0,0x1,0x01,0x1,0x1,0x2,0x2,0x2,0x2,0x3,0x3,0x3,0x3};
	uint8_t l_sid[L_SID_LENGTH]={0x0,0x0,0x0,0x0,0x1,0x01,0x1,0x1,0x2,0x2,0x2,0x2,0x3,0x3,0x3,0x3,0x0,0x0,0x0,0x1};
	memcpy(control_register_hdr->n_sid,n_sid,NID_LENGTH);
	memcpy(control_register_hdr->l_sid,l_sid,L_SID_LENGTH);
	
	control_register_hdr->type=1;
	uint8_t nid_s[NID_LENGTH]={0x0,0x0,0x0,0x0,0x1,0x01,0x1,0x1,0x2,0x2,0x2,0x2,0x3,0x3,0x3,0x3};
	memcpy(control_register_hdr->nid_s,nid_s,NID_LENGTH);
	
	control_register_hdr->scope=4;
	
	control_register_hdr->time_of_validity=100;
	
	control_register_hdr->time_unit=1;
	
	control_register_hdr->content_size=1024;
	
	return sizeof(control_register_t);		
}

static void 
pkt_setup(struct rte_mbuf *m)
{
	int ret=0;

	struct ether_hdr eth_hdr;
	ret=pktgen_ctor_ether_header(&eth_hdr,m);

	struct ipv4_hdr ipv4_hdr;
	ret+=pktgen_ctor_ip_header(&ipv4_hdr,m);
	
	ret+=pktgen_ctor_control_public_header(m);
	ret+=pktgen_ctor_register(m);
	
	m->nb_segs=1;
	m->next=NULL;
	m->pkt_len=ret;
	m->data_len=ret;
}

void inline send_mbuf(uint8_t portid,struct rte_mbuf *mbuf, unsigned lcore_id)
{
	if(lcore_id<0){
		lcore_id=rte_lcore_id();
	}	
	
	uint8_t socketid=rte_lcore_to_socket_id(lcore_id);
	struct lcore_conf *qconf=&lcore_conf[lcore_id];	
	
	if(pktmbuf_pool[socketid]==NULL)
	{
		rte_exit(EXIT_FAILURE,"pktmbuf_pool[socketid]==NULL\n");		
	}
	else
	{
		struct rte_mbuf *m=rte_pktmbuf_alloc(pktmbuf_pool[socketid]);
		
		if(m==NULL)
		{
			rte_exit(EXIT_FAILURE,"Allocate Failure\n");		
		}	
		
		pkt_setup(m);

		send_single_packet(qconf, m, portid);
		rte_pktmbuf_free(m);
	}	
}
