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
	//SID内容
	uint8_t n_sid[NID_LENGTH];
	uint8_t l_sid[L_SID_LENGTH];
	//包类型:注册(0x01)，更新(0x02)，删除(0x03) 
	//回送ACK:SUCCESS(0x10), DUPLICATE(0x20), INVALIDE(0x30)
	uint8_t type;
	//提供者的NID
	uint8_t nid_s[NID_LENGTH];
	//注册的范围:默认上级(0x01),上级和对等体(0x02)，本域和邻域(0x03)，仅本域(0x04)
	uint8_t scope;
	//注册的有效期
	uint8_t time_of_validity;
	//注册的单位时间:秒(0x01)，分钟(0x02)，小时(0x03)，天(0x04)，星期(0x05)，月(0x06)，年(0x07)
	uint8_t time_unit;
	//注册内容的字节数
	uint32_t content_size;
	//Classification of content: txt(0x1),image(0x2),video(0x3)
	uint32_t content_classification;
};
typedef struct control_register control_register_t;

//两个自治域链路的最大个数
#define MAX_NUM_PID 8
//内容通告的所经过的自治域的路径的最大个数
#define MAX_NUM_AS_PATH  16
struct control_announce{
	//pid通告协议: 强制遵守(0x1)，利益最大化(0x2), 供参考(0x3)
	uint8_t pid_agreement;
	//通告方的PID喜好度列表
	uint8_t pid_number;
	uint32_t pid[MAX_NUM_PID];
	uint8_t pid_preference[MAX_NUM_PID];
	//通告的路径属性
	uint8_t as_number;
	uint16_t as[MAX_NUM_AS_PATH];
	//通告包的最大眺数
	uint8_t announce_ttl;
	//注册内容的个数,可以通告一系列的内容。。
	uint16_t register_number;
	//默认定义一个注册内容，后面可变长。。
	struct control_register register_first;
	//变长部分。。可以附带更多的注册条目
};

#endif


