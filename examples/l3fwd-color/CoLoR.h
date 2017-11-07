#ifndef _CoLoR_H_
#define _CoLoR_H_ 

#define CONTENTLEN 4 
#define PUBKEYLEN 4


typedef struct CoLoR_get
{
	uint8_t version_type;	//版本4位，类型4位
	uint8_t ttl;		//生存时间
	uint16_t total_len;	//总长度
	uint16_t port_src;	//源端口号
	uint16_t port_dst;	//目的端口号
	uint16_t minmal_PID_CP; //pid改变的周期
	uint8_t PIDs;		//PID的数目
	uint8_t Offest_RES;     //位运算取Offset
	uint32_t offset;	//偏移量
	uint32_t length;	//偏移长度
	uint16_t content_len;	//公钥长度
	uint16_t mtu;		//最大传输单元
	uint16_t publickey_len;	//公钥长度
	uint16_t checksum;	//检验和
	uint8_t nid_sid[16];	//NID part of an SID，长度为16字节
	uint8_t l_sid[20]; 	//SID的长度为20字节
	uint8_t nid[16];	//NID的长度为16字节
	uint8_t content[CONTENTLEN];	// Content characteristics
	uint8_t publickey[PUBKEYLEN];	//公钥
} CoLoR_get_t;

#endif


