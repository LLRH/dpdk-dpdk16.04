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

/*version_type字段*/
#define TYPE_GET 0xA0
#define TYPE_DTAT 0xA1
//#define TYPE_REGISTER 0xA2
#define TYPE_CONTROL 0xA3

/*control_type字段*/
#define control_type_register 0
#define control_tppe_announce 1

#define NID_LENGTH 16
struct control_public_header {
	uint8_t version_type;
	uint8_t control_type;
	uint8_t total_length;
	uint16_t port_number_1;
	uint16_t port_number_2;
	uint16_t min_pid_change_period;
	uint8_t ack_flag_res;
	uint8_t pid_index;
	uint8_t item_number;
	uint16_t checksum;
	uint8_t nids_s[NID_LENGTH];
	uint8_t nid_r[NID_LENGTH];
	uint32_t mac;
	uint32_t offset;
	uint32_t length;
	//CONTENT OF ITEM;
}__attribute__((__packed__));
typedef struct control_public_header control_public_header_t;

#define L_SID_LENGTH 20
struct control_register{
	//SID
	uint8_t n_sid[NID_LENGTH];
	uint8_t l_sid[L_SID_LENGTH];
	//类型:注册(1)，更新(2)，删除(3)
	uint8_t type;
	//提供者的NID
	uint8_t nid_s[NID_LENGTH];
	//注册的范围:默认上级(1),上级和对等体(2)，本域和邻域(3)，仅本域(4)
	uint8_t scope;
	//注册的有效期
	uint8_t time_of_validity;
	//注册的单位时间:秒(1)，分钟(2)，小时(3)，天(4)，星期(5)，月(6)，年(7)
	uint8_t time_unit;
	//注册内容的字节数
	uint32_t content_size;
	
	uint32_t content_classification;
};
typedef struct control_register control_register_t;

struct control_announce{
	//通告包
};

#endif


