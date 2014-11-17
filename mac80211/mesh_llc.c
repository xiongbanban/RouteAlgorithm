#include <linux/slab.h>
#include <linux/list.h>

#include <linux/etherdevice.h> //compare_ethe_addr define

#include <linux/kernel.h>
//#include <net/ip.h>
//#include <net/dsfield.h>
#include  <linux/jiffies.h> 


#include <linux/netdevice.h>
#include <linux/delay.h>
#include <linux/skbuff.h>

#include "mesh_llc.h"
//#include "debugfs_mesh_llc.h"

//#include "Cfg80211.h"
//#include "ieee80211.h"


#define LLC_HDR_LEN 2

struct SEND_LLC_ENTITY   Send_Llc_Entity[MAP_MAX_COUNT];

extern spinlock_t hash_glob_lock;
struct HashDup bucket[MAP_MAX_COUNT];
struct HashDupHead bucket_head[MAP_MAX_COUNT];

extern struct timer_list mytimer;

unsigned long last_sche_time = 0;
struct RECEIVE_WINDOW_ELEMENT  Recv_Win_Elem[MAP_MAX_COUNT][MAX_ORDER_NUM];
struct RECEIVE_WINDOW Recv_Win[MAP_MAX_COUNT];
struct config_para my_data;


void config_para_init()	{
//	my_data.map_max_cnt = 256;
	my_data.wait_max_time = 50;
//	my_data.win_len = 512;
	my_data.scan_interval = 1;
	my_data.order_enable = false;
}


void Init_Llc_Entity()                                   //MODULE INIT CALL
{
	u16 i ;
	for(i =0;i < MAP_MAX_COUNT;i++)
	{
		spin_lock_init(&Send_Llc_Entity[i].llc_entity_lock);
		Send_Llc_Entity[i].seq = 0;
		Send_Llc_Entity[i].drop_pkt_rate = 0;
	}
}


void Init_Bucket()                     //MODULE INIT CALL
{
	int i;
	for(i=0;i<MAP_MAX_COUNT;i++)
	{
/*
		bucket[i].down_sign_nb = 0;
		bucket[i].dup_list.prev = NULL;
		bucket[i].dup_list.next =NULL;
		memset(bucket[i].addr_6,0,ETH_ADDR_LEN);
*/
		
		spin_lock_init(&bucket_head[i].hash_dup_lock);
		INIT_LIST_HEAD(&bucket_head[i].bucket_list);
//		bucket_head[i].bucket.down_sign_nb = MAP_MAX_COUNT;
		bucket_head[i].bucket_status = false;
//		bucket_head[i].pbucket_list = NULL;
//		memset(bucket_head[i].bucket.addr_6,255,ETH_ADDR_LEN);
		
	}
//	struct HashDup {
//		.down_sign_nb = 0,
}




struct HashDup *Inode_Find_Addr_6( u8 *addr, u16 bucket_id, u16 size) 
{

	struct HashDup *ptarg_node;
	spin_lock(&bucket_head[bucket_id].hash_dup_lock);
	list_for_each_entry(ptarg_node,(&bucket_head[bucket_id].bucket_list),dup_list) 
	{
		if(compare_ether_addr(ptarg_node->addr_6, addr) == 0) {
			spin_unlock(&bucket_head[bucket_id].hash_dup_lock);
			return ptarg_node;
		}
	}
	spin_unlock(&bucket_head[bucket_id].hash_dup_lock);
	return NULL;
}


int Mac_To_DownSign(u8 *addr_6, u16 threshold, u16 size) {
	static u16 down_sign_count =0;
	u16  sum = 0, n, i;
	char bc_addr[ETH_ADDR_LEN] = {0xff,0xff,0xff,0xff,0xff,0xff};
	struct HashDup  *new_hash_dup,*find_result;
	if(compare_ether_addr(addr_6, bc_addr) == 0)
	{
		printk("this addr is broadcast addr,not map to down_sign\n");
		return -1;
	}
	for(i = 0;i < size; i++) {
		sum += addr_6[i];
	}
	n = sum % threshold;
	//INIT_LIST_HEAD(&bucket[n].dup_list);
	//temp = &bucket[n];
	//if(bucket_head[n].bucket.dup_list.next==&(bucket_head[n].bucket.dup_list))
	//mend:Liu
	if(bucket_head[n].bucket_status == false)	{
		bucket_head[n].bucket_status = true;
		new_hash_dup = kmalloc(sizeof(struct HashDup ), GFP_KERNEL);
			if(!new_hash_dup)
			{
				printk("find_result is NULL, kmalloc fail\n");
				return -1 ;			
			}
			spin_lock(&hash_glob_lock);
			new_hash_dup->down_sign_nb = down_sign_count;
			down_sign_count++;
		//	down_sign_count = down_sign_count % MAP_MAX_COUNT;
			spin_unlock(&hash_glob_lock);
			
			memcpy(new_hash_dup->addr_6 , addr_6,size);
		//	INIT_LIST_HEAD(&new_hash_dup->dup_list);
			spin_lock(&bucket_head[n].hash_dup_lock);
			list_add_tail(&new_hash_dup->dup_list,&bucket_head[n].bucket_list);
			
			spin_unlock(&bucket_head[n].hash_dup_lock);
			printk("list to bucket_head complete\n" );
	//		bucket_head[n].pbucket_list = &new_hash_dup->dup_list;
			printk("new first head node,down_sign is %d\n",new_hash_dup->down_sign_nb );
			return  new_hash_dup->down_sign_nb;
	}
	else	{
		find_result = Inode_Find_Addr_6( addr_6, n, size);
		if(find_result == NULL) {
			new_hash_dup = kmalloc(sizeof(struct HashDup ), GFP_KERNEL);
			if(!new_hash_dup)
			{
				printk("find_result is NULL, kmalloc fail\n");
				return -1 ;			
			}
			spin_lock(&hash_glob_lock);
			new_hash_dup->down_sign_nb = down_sign_count;
			down_sign_count++;
		//	down_sign_count = down_sign_count % MAP_MAX_COUNT;
			spin_unlock(&hash_glob_lock);
			printk("find_result is NULL,new hash node,down_sign is %d\n",new_hash_dup->down_sign_nb );

			memcpy(new_hash_dup->addr_6 , addr_6,size);

			spin_lock(&bucket_head[n].hash_dup_lock);
			list_add_tail(&new_hash_dup->dup_list,&bucket_head[n].bucket_list);
			
			spin_unlock(&bucket_head[n].hash_dup_lock);
			printk("list to bucket_head complete\n" );
			if (down_sign_count > threshold) {
				printk( KERN_INFO "over setted threshold :%d",threshold);
				return -1;
			}
			return new_hash_dup->down_sign_nb;
		}
		else	{
			return find_result->down_sign_nb;
		}
	//printk("down_sign:%d\n",find_result->down_sign_nb);
	}
}



int Fill_Llc_Header(struct sk_buff *skb, u8 *mesh_da, u16 ext_llc_type)
{
	u16 seq, llc_value;
	u16 down_sign = Mac_To_DownSign(mesh_da, MAP_MAX_COUNT, ETH_ADDR_LEN);

	if (down_sign<0)
	{
		return -1;
	}

	ext_llc_type &= 0X0003;	
	seq = Send_Llc_Entity[down_sign].seq;
    printk("send seq =:%d\n",seq);
	
	seq = (seq << 2) & 0x0ffc;	
	llc_value = ext_llc_type | seq;
	Send_Llc_Entity[down_sign].seq++;
	Send_Llc_Entity[down_sign].seq  %= MAX_ORDER_NUM;
	memcpy(skb_put(skb, LLC_HDR_LEN), &llc_value, LLC_HDR_LEN);
    printk("send llc_value =:%x\n",llc_value);
	return 0;
}


u16 LlcValue_To_Seq_Type(u16 llc_value, u16 *pext_llc_type )
{
	u16 seq;
	*pext_llc_type = llc_value & 0x0003;
	seq = (llc_value >> 2) & (0x03ff);
	return seq;
}


void Init_Win()            //MODULE INIT CALL
{
	u16 i, j;
	for(i =0;i < MAP_MAX_COUNT;i++)
	{
		spin_lock_init(&(Recv_Win[i].win_lock));
		Recv_Win[i].win_status = false;
		Recv_Win[i].wv_l = 0;
		Recv_Win[i].win_first_arri_time = 0;
		Recv_Win[i].win_stop_pkt_out_count = 0;
		for(j =0;j < MAX_ORDER_NUM;j++)
		{
			Recv_Win_Elem[i][j].skb = NULL;
			Recv_Win_Elem[i][j].pkt_arri_time = 0;
		//	spin_lock_init(&(Recv_Win_Elem[i][j].win_elem_lock));
		}
	}
}


WIN_POSITION Win_Pos_Get(u16 seq,u16 wv_l)
{
	if (wv_l < WINDOW_LEN)
	{
		return ((seq < (wv_l + WINDOW_LEN)) && (seq >= wv_l)) ? WIN_IN : WIN_OUT; 
	}
	else if (wv_l >= WINDOW_LEN)
	{
		if ((seq >=wv_l) && (seq < MAX_ORDER_NUM))
		{
			return WIN_IN;
		}
		else if (seq < (wv_l + WINDOW_LEN) % MAX_ORDER_NUM)
		{
			return WIN_IN;
		}
		else
			return WIN_OUT;
	}
	return WIN_OUT;
}


STATUS Insert_Win_Process(struct sk_buff *skb, u8 *mesh_sa,  u16  *pdown_sign) 
{
//u8 *src_mac;
//   struct ethhdr  *peth_hdr;
    u16 down_sign, seq, wv_l, llc_value;
	u16 ext_llc_type;
	u8 *pllc_value;
	WIN_POSITION pkt_pos;
//	struct LlcHdr *pllc_hdr;
	struct	RECEIVE_WINDOW_ELEMENT	*pwindow_elem;
	struct RECEIVE_WINDOW  *pwindow;
//	pinfo_carry = (struct Info_Carry *)(skb->cb + sizeof(struct ieee80211_rx_status));
//	u16 down_sign = pinfo_carry->down_sign;
//	peth_hdr = eth_hdr(skb);
//	src_mac = peth_hdr->h_source;
	down_sign = Mac_To_DownSign(mesh_sa, MAP_MAX_COUNT, ETH_ADDR_LEN);
	if(down_sign<0)
		{
		printk("down_sign false\t");
		return FAILURE;
	}
	*pdown_sign = down_sign;
//	pllc_hdr = (struct LlcHdr *)((char *)peth_hdr + 14);
	pllc_value =  (u8 *)(skb->tail - 2);
	llc_value = ((*pllc_value)<<8)|(*(pllc_value+1));
//	printk("insert pkt llc_value is :%x\t",llc_value);
	seq = LlcValue_To_Seq_Type(llc_value, &ext_llc_type );
//	printk(" seq is :%d\n",seq);
//	memset(skb->cb, 0, sizeof(skb->cb));
	pwindow_elem = Recv_Win_Elem[down_sign];
	pwindow = &Recv_Win[down_sign];
	spin_lock(&pwindow->win_lock);
	wv_l = pwindow->wv_l;
	pkt_pos = Win_Pos_Get(seq,wv_l);
	
	if(pkt_pos == WIN_IN)
	{
		if(pwindow->win_status == false)
		{
			pwindow->win_status = true;
		}
		pwindow->win_stop_pkt_out_count = 0;
	
		if(pwindow_elem[seq].skb!=NULL)
		{
			printk("window:%d  pos:%d pkt exist,ready free\n ",down_sign,seq);
			kfree_skb(pwindow_elem[seq].skb);
			
		}
		
		pwindow_elem[seq].skb = skb;
		pwindow_elem[seq].pkt_arri_time = jiffies;
	//	printk("pos :%d pkt_arri_time:%d\n",seq,pwindow_elem[seq].pkt_arri_time);
	    printk( "pkt in_window[%d]  seq:%d\n", down_sign,seq);
		spin_unlock(&pwindow->win_lock);
//		queue_work(pdeli_win_pack_work->pwq,work);
		return SUCCESS;
	}
	else if(pkt_pos == WIN_OUT)
	{
		printk( "pkt out_window[%d]  seq:%d\n", down_sign,seq);
		pwindow->win_stop_pkt_out_count++;
		if(pwindow->win_stop_pkt_out_count >= MAX_ORDER_NUM / 16)
		{
			printk( "win_stop_pkt_out_count over MAX_ORDER_NUM / 16,wv_l forced to syn\t");
			pwindow->win_stop_pkt_out_count = 0;
			pwindow->wv_l = (seq + 1) % MAX_ORDER_NUM;
			update_first_arri_time(pwindow, pwindow_elem);
		}
	spin_unlock(&pwindow->win_lock);
		return FAILURE;
	}
	else
	{
		spin_unlock(&pwindow->win_lock);
		return FAILURE; 
	}
}


void test_reentry(struct sk_buff *skb)
{
//	u16  llc_value, ext_llc_type, seq;
//	u16 *pllc_value;
/*	pllc_value = (u16 *)(skb->tail - LLC_HDR_LEN);
	llc_value = *pllc_value;
	seq = LlcValue_To_Seq_Type(llc_value, &ext_llc_type);
*/

int i;
u8 hdr1,hdr2;
u16 llc_value,seq;
i=skb->len-2;
hdr1=skb->data[i];
hdr2=skb->data[i+1];
llc_value=((hdr1<<8)|hdr2);
seq = (llc_value >> 2) & (0x03ff);
printk("reentry llc_value=%0x	seq= %d\n",llc_value,seq);


/*	skb_trim(skb, LLC_HDR_LEN);
	*pllc_value = 0;
	skb->len -= LLC_HDR_LEN;
*/
	skb->tail -=LLC_HDR_LEN;				
	skb->len -= LLC_HDR_LEN;
//	printk("reentry pkt llc_value=%0x	seq=%d\n",llc_value,seq);
	netif_receive_skb(skb);
}


void update_first_arri_time(struct RECEIVE_WINDOW  *pwindow, struct RECEIVE_WINDOW_ELEMENT *pwindow_elem)
{
	unsigned long first_arri_time = 0xffffffff;
	u16 i, j = 0;
	if (pwindow->wv_l <= WINDOW_LEN)
		{
			for (i = pwindow->wv_l; i < pwindow->wv_l + WINDOW_LEN; i++)
			{
				if (pwindow_elem[i].skb != NULL)
					{
						if (pwindow_elem[i].pkt_arri_time < first_arri_time)
						{
							first_arri_time = pwindow_elem[i].pkt_arri_time;
							j = i;
						}
					}
			}			
//		printk("pwindow_elem[i].pkt_arri_time:%d\n",first_arri_time);
		}
	
		else if ((pwindow->wv_l > WINDOW_LEN) && (pwindow->wv_l < MAX_ORDER_NUM))
		{
			for (i = pwindow->wv_l; i < MAX_ORDER_NUM; i++)	
			{
				if (pwindow_elem[i].skb != NULL)
				{
					if (pwindow_elem[i].pkt_arri_time < first_arri_time)						
					{
							first_arri_time = pwindow_elem[i].pkt_arri_time;
							j = i;
						}
				}
			}
			for (i = 0; i < (pwindow->wv_l + WINDOW_LEN) % MAX_ORDER_NUM; i++)
			{
				if (pwindow_elem[i].skb != NULL)
					{
						if (pwindow_elem[i].pkt_arri_time < first_arri_time)
						{
							first_arri_time = pwindow_elem[i].pkt_arri_time;
							j = i;
						}
					}
			}
		}
		
		if (first_arri_time == 0xffffffff)
			{
				
				pwindow->win_status = false;
				printk("by win_first_arri_time win status ready chang to false \n");
		
			}
			else  
			{
				pwindow->win_first_arri_time = first_arri_time;
//				printk("now in win pkt of seq :%d arrive first\n",j);
			}
}


void deli_update_window(struct RECEIVE_WINDOW  *pwindow, struct RECEIVE_WINDOW_ELEMENT *pwindow_elem)
{
	//unsigned long first_arri_time = 0xffffffff;
//	u16 i;
	pwindow->wv_l++;
	pwindow->wv_l %= MAX_ORDER_NUM;
//	printk("now wv_l is %d \n",pwindow->wv_l);
	update_first_arri_time(pwindow,pwindow_elem);

//	printk("now window first_arri_time update complete \n");// JIA SHANNG

}


void win_timeout_process(struct RECEIVE_WINDOW  *pwindow, struct RECEIVE_WINDOW_ELEMENT *pwindow_elem,	 u16 llc_entity_down_sign)
{
	u16 i , drop_pkt_count = 0 ;
	u16 drop_pkt_rate = 0;
	u16 wv_l = pwindow->wv_l;
//	wv_l++;
	i = wv_l;
/*	largest count of urge-deliver elements is WINDOW_LEN .
	in window once urge-delive to elem which  of pkt pointer is not NULL ,window stops here ,and caculate drop_pkt_rate 
*/
	if (wv_l <= WINDOW_LEN)
	{
		for (i = wv_l; i < wv_l + WINDOW_LEN ; i++)
		{
			if(pwindow_elem[i].skb == NULL)
				drop_pkt_count++;
			else
				break;
			}
		if (i >= wv_l + WINDOW_LEN)
		{
				printk(KERN_INFO "pkt in  window %d  all dropped", llc_entity_down_sign);
		}
	}
	else if ((wv_l > WINDOW_LEN) && (wv_l < MAX_ORDER_NUM))
	{
		for (i = wv_l; i < MAX_ORDER_NUM; i++)	
		{
			if(pwindow_elem[i].skb == NULL)
				drop_pkt_count++;
			else
				break;
		}
		if (i >= MAX_ORDER_NUM)
		{
			for (i = 0; i < (wv_l + WINDOW_LEN) % MAX_ORDER_NUM;i++)
			{
				if(pwindow_elem[i].skb == NULL)
					drop_pkt_count++;
				else
					break;
			}
			if (i >=  (wv_l + WINDOW_LEN) % MAX_ORDER_NUM)
			{
				printk(KERN_INFO "pkt in  window %d  all dropped\n", llc_entity_down_sign);
			}
		}
	}
//	printk(" drop_pkt_count record complete,drop_pkt_count = %d\n",drop_pkt_count);

	drop_pkt_rate = drop_pkt_count * 255 / ((1 << 16) - 1);
//	printk(" drop_pkt_rate calculate complete,drop_pkt_rate:%d\n",drop_pkt_rate);

	spin_lock(&Send_Llc_Entity[llc_entity_down_sign].llc_entity_lock);
	Send_Llc_Entity[llc_entity_down_sign].drop_pkt_rate = drop_pkt_rate ;
	spin_unlock(&Send_Llc_Entity[llc_entity_down_sign].llc_entity_lock);

	pwindow->wv_l = i;                                // jiashang
	printk("after timeout wv_l update to %d\n",i);       // jiashang
	update_first_arri_time(pwindow,pwindow_elem);     // jiashang
//	printk("after timeout update window complete\n ");
}


void Deli_Win_Work_Func(void) {
	struct	RECEIVE_WINDOW_ELEMENT	*pwindow_elem;
	struct RECEIVE_WINDOW  *pwindow;
	u16 wv_l;
	u16 i = 0;
//    u32 last_sche_time = jiffies;
	while (i<MAP_MAX_COUNT)	{
		pwindow_elem = Recv_Win_Elem[i];
		pwindow = &Recv_Win[i];
		
		spin_lock(&pwindow->win_lock);
		if(pwindow->win_status == true) {			
//			printk("window[%d] status true\n",i);// JIA SHANG
			update_first_arri_time(pwindow,pwindow_elem);
			while (1)	{
				wv_l = pwindow->wv_l;
				while (pwindow_elem[wv_l].skb!=NULL) {	
						printk("order to reentry pkt in win[%d]:\t",i);
						test_reentry(pwindow_elem[wv_l].skb);
						pwindow_elem[wv_l].skb = NULL;	
						deli_update_window(pwindow , pwindow_elem);
						wv_l = pwindow->wv_l;
				}
				if(pwindow->win_status == true){
					if(time_after(jiffies,pwindow->win_first_arri_time + my_data.wait_max_time * HZ / 1000)) {
					printk("pkt pos %d in window %d  wait timeout \t",pwindow->wv_l, i);
					win_timeout_process(pwindow, pwindow_elem, i);
					i++;
					break;
					}
					else{
						i++;
						break;
					}	
				}
				else{
					i++;
					break;
				}	
			}		
		}
		else	{
//			printk("window[%d] status false\t",i);
			i++;
//			printk("ready entry next win:%d\n",i);//jia		
		}
		spin_unlock(&pwindow->win_lock);
	}
	mod_timer(&mytimer,jiffies + HZ * my_data.scan_interval / 1000);		
}


void del_hash_dup(void)	{
	int i;
	for(i = 0; i<MAP_MAX_COUNT; i++ )	{
		struct HashDup *tmp_node, *sli_node;
		list_for_each_entry_safe(sli_node, tmp_node, &bucket_head[i].bucket_list, dup_list)	{
			list_del(&sli_node->dup_list);
			kfree(sli_node);
		}
	}
}

	
