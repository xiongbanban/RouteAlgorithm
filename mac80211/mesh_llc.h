#include <linux/spinlock.h>
#include <linux/list.h>
#include <linux/time.h>



#ifndef MESH_LLC_ENABLE
#define MESH_LLC_ENABLE 
#endif

#define  MAP_MAX_COUNT  251 //���MAP����
#define  PATH_MAX_COUNT  8  //���·����


#define LLC_HDR_LEN 2
#define LLC_TYPE  0X0000


#define MAX_ORDER_NUM 1024  //һ��������������
#define WINDOW_LEN 512 //  ��3ڳ��?
 //���մ��ڵȴ����ݰ������ʱ�䣬��λms
#define DATA_INTERVAL_SEND_MAX_TIME   10 //���Ͷ��������η������ݵ�����          //��ʱ�䵥λms
#define  CONGINFO_EFFECTIVE_MAX_TIME  3 //ӵ����Ϣ��Ч�����ʱ�� ��λms


#ifndef  ETH_HDR_LEN 
 	#define  ETH_HDR_LEN 14 
#endif
#ifndef ETH_ADDR_LEN
	#define ETH_ADDR_LEN 6
#endif


#ifndef u8
	#define u8  unsigned char
#endif
#ifndef u16 
	#define u16 unsigned short
#endif	
//#ifndef u32
//	#define u32 unsigned long
//#endif

struct config_para {
	bool order_enable;
 //  int map_max_cnt;
	int wait_max_time;
	int scan_interval; 
 //  int win_len;
 };



 struct LlcHdr 
{
	u16 frame_type;
//	u8 drop_pkt_rate;
//	u8 delay;
//	u16 path_id;
	u16 seq;
//	u32 send_time_stamp;
};


struct SEND_LLC_ENTITY 
{
	spinlock_t llc_entity_lock;  //lock LLC_ENTITY 
	u16  seq;    //��Ӧ���к�
//	struct CongInfo ci[PATH_MAX_COUNT]; //ÿ��·����Ӧһ��ӵ����Ϣ�ṹ��
	u16 drop_pkt_rate;    //��Ӧ�˵��˵Ķ�����
//	unsigned long  last_send_time;    //�ö��ϴη������ݸ��Զ˵�ʱ��
//	unsigned int recv_no_data_count;
//	unsigned long cong_info_last_upda_time; 
 };

struct HashDup {
	
	struct list_head dup_list;
	unsigned short down_sign_nb;
	char addr_6[ETH_ADDR_LEN];
};



struct HashDupHead {
//	struct HashDup bucket;
	spinlock_t hash_dup_lock;
	bool bucket_status;
	struct list_head bucket_list;
	//struct list_head bucket_head_list;
};


typedef enum
{
		SUCCESS,
		FAILURE
}STATUS;

typedef enum
{
	WIN_IN,
	WIN_OUT,
	NONE
}WIN_POSITION;



struct RECEIVE_WINDOW_ELEMENT 
{
	//	spin_lock_t win_elem_lock; //lock which window elem
	struct sk_buff  *skb; //ָ����Ӧ���ݰ�������
	unsigned long pkt_arri_time;
//	spinlock_t win_elem_lock;
	//bool win_elem_status;
 };


struct RECEIVE_WINDOW 
{

	spinlock_t win_lock;  //lock the whole struct 
	bool win_status;   //�����ô������Ƿ������ݰ�����
	u16 wv_l;   //���մ����ϱ������
	unsigned long  win_first_arri_time;    //�ô��������絽������ݰ��ĵ���ʱ��
	u16  win_stop_pkt_out_count;
};


void config_para_init(void);

void Init_Llc_Entity(void);



u16 LlcValue_To_Seq_Type(u16 llc_value, u16 *pext_llc_type );

 void Init_Bucket(void);
 struct HashDup *Inode_Find_Addr_6(u8 *, u16 , u16 );
 int Mac_To_DownSign(u8 *, u16 , u16) ;

 int Fill_Llc_Header(struct sk_buff *skb, u8 *mesh_da, u16 ext_llc_type);

void Init_Win(void);
//void reentry(struct sk_buff *);
STATUS Insert_Win_Process(struct sk_buff *skb, u8 *mesh_sa,  u16  *pdown_sign);


void test_reentry(struct sk_buff * );
void deli_update_window(struct RECEIVE_WINDOW  *, struct RECEIVE_WINDOW_ELEMENT *);
void win_timeout_process(struct RECEIVE_WINDOW  *, struct RECEIVE_WINDOW_ELEMENT *, u16 );
void update_first_arri_time(struct RECEIVE_WINDOW  *pwindow, struct RECEIVE_WINDOW_ELEMENT *pwindow_elem);
void Deli_Win_Work_Func(void);
void del_hash_dup(void);

