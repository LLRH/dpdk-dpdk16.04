#ifndef _CoLoR_H_
#define _CoLoR_H_ 

#define CONTENTLEN 4 
#define PUBKEYLEN 4

typedef struct CoLoR_get
{
	uint8_t version_type;	//�汾4λ������4λ
	uint8_t ttl;		//����ʱ��
	uint16_t total_len;	//�ܳ���
	uint16_t port_src;	//Դ�˿ں�
	uint16_t port_dst;	//Ŀ�Ķ˿ں�
	uint16_t minmal_PID_CP; //pid�ı������
	uint8_t PIDs;		//PID����Ŀ
	uint8_t Offest_RES;     //λ����ȡOffset
	uint32_t offset;	//ƫ����
	uint32_t length;	//ƫ�Ƴ���
	uint16_t content_len;	//��Կ����
	uint16_t mtu;		//����䵥Ԫ
	uint16_t publickey_len;	//��Կ����
	uint16_t checksum;	//�����
	uint8_t nid_sid[16];	//NID part of an SID������Ϊ16�ֽ�
	uint8_t l_sid[20]; 	//SID�ĳ���Ϊ20�ֽ�
	uint8_t nid[16];	//NID�ĳ���Ϊ16�ֽ�
	uint8_t content[CONTENTLEN];	// Content characteristics
	uint8_t publickey[PUBKEYLEN];	//��Կ
} CoLoR_get_t;

/*version_type�ֶ�*/
#define TYPE_GET 0xA0
#define TYPE_DTAT 0xA1
//#define TYPE_REGISTER 0xA2
#define TYPE_CONTROL 0xA3

/*control_type�ֶ�*/
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
	//����:ע��(1)������(2)��ɾ��(3)
	uint8_t type;
	//�ṩ�ߵ�NID
	uint8_t nid_s[NID_LENGTH];
	//ע��ķ�Χ:Ĭ���ϼ�(1),�ϼ��ͶԵ���(2)�����������(3)��������(4)
	uint8_t scope;
	//ע�����Ч��
	uint8_t time_of_validity;
	//ע��ĵ�λʱ��:��(1)������(2)��Сʱ(3)����(4)������(5)����(6)����(7)
	uint8_t time_unit;
	//ע�����ݵ��ֽ���
	uint32_t content_size;
	
	uint32_t content_classification;
};
typedef struct control_register control_register_t;

struct control_announce{
	//ͨ���
};

#endif


