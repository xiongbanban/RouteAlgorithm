/*
 * Copyright (c) 2008, 2009 open80211s Ltd.
 * Author:     Luis Carlos Cobo <luisca@cozybit.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */



#include <linux/slab.h>
#include <linux/etherdevice.h>
#include <asm/unaligned.h>
#include "wme.h"
#include "mesh.h"

#define TEST_FRAME_LEN	8192
#define MAX_METRIC	0xffffffff
#define ARITH_SHIFT	8

#define MAX_PREQ_QUEUE_LEN	64

/* Destination only */
#define MP_F_DO	0x1
/* Reply and forward */
#define MP_F_RF	0x2
/* Unknown Sequence Number */
#define MP_F_USN    0x01
/* Reason code Present */
#define MP_F_RCODE  0x02

#define IEEE80211_PREP_MAJORPATH 1
#define IEEE80211_PREP_MINORPATH 2




static void mesh_queue_preq(struct mesh_path *, u8);

static inline u32 u32_field_get(const u8 *preq_elem, int offset, bool ae)
{
	if (ae)
		offset += 6;
	return get_unaligned_le32(preq_elem + offset);
}

static inline u32 u16_field_get(const u8 *preq_elem, int offset, bool ae)
{
	if (ae)
		offset += 6;
	return get_unaligned_le16(preq_elem + offset);
}

/* HWMP IE processing macros */
#define AE_F			(1<<6)
#define AE_F_SET(x)		(*x & AE_F)
#define PREQ_IE_FLAGS(x)	(*(x))
#define PREQ_IE_HOPCOUNT(x)	(*(x + 1))
#define PREQ_IE_TTL(x)		(*(x + 2))
#define PREQ_IE_PREQ_ID(x)	u32_field_get(x, 3, 0)
#define PREQ_IE_ORIG_ADDR(x)	(x + 7)
#define PREQ_IE_ORIG_SN(x)	u32_field_get(x, 13, 0)
#define PREQ_IE_LIFETIME(x)	u32_field_get(x, 17, AE_F_SET(x))
#define PREQ_IE_METRIC(x) 	u32_field_get(x, 21, AE_F_SET(x))
#define PREQ_IE_TARGET_F(x)	(*(AE_F_SET(x) ? x + 32 : x + 26))
#define PREQ_IE_TARGET_ADDR(x) 	(AE_F_SET(x) ? x + 33 : x + 27)
#define PREQ_IE_TARGET_SN(x) 	u32_field_get(x, 33, AE_F_SET(x))


#define PREQ_IE_MID_ADDRESS(x)  (AE_F_SET(x) ? x + 43 : x + 37)
#define PREQ_IE_LENGTH(x)   (*(x-1))



#define PREP_IE_FLAGS(x)	PREQ_IE_FLAGS(x)
#define PREP_IE_HOPCOUNT(x)	PREQ_IE_HOPCOUNT(x)
#define PREP_IE_TTL(x)		PREQ_IE_TTL(x)
#define PREP_IE_ORIG_ADDR(x)	(AE_F_SET(x) ? x + 27 : x + 21)
#define PREP_IE_ORIG_SN(x)	u32_field_get(x, 27, AE_F_SET(x))
#define PREP_IE_LIFETIME(x)	u32_field_get(x, 13, AE_F_SET(x))
#define PREP_IE_METRIC(x)	u32_field_get(x, 17, AE_F_SET(x))
#define PREP_IE_TARGET_ADDR(x)	(x + 3)
#define PREP_IE_TARGET_SN(x)	u32_field_get(x, 9, 0)

#define PREP_IE_MID_ADDRESS(x)  (AE_F_SET(x) ? x + 37 : x + 31)
#define PREP_IE_LENGTH(x)  PREQ_IE_LENGTH(x) 


#define PERR_IE_TTL(x)		(*(x))
#define PERR_IE_TARGET_FLAGS(x)	(*(x + 2))
#define PERR_IE_TARGET_ADDR(x)	(x + 3)
#define PERR_IE_TARGET_SN(x)	u32_field_get(x, 9, 0)
#define PERR_IE_TARGET_RCODE(x)	u16_field_get(x, 13, 0)



#define PERR_IE_ORIG_ADDR(x)	 (x + 15)
#define PERR_IE_INVALID_ADDR(x)	 (x + 21)


#define MSEC_TO_TU(x) (x*1000/1024)
#define SN_GT(x, y) ((s32)(y - x) < 0)
#define SN_LT(x, y) ((s32)(x - y) < 0)

#define net_traversal_jiffies(s) \
	msecs_to_jiffies(s->u.mesh.mshcfg.dot11MeshHWMPnetDiameterTraversalTime)
#define default_lifetime(s) \
	MSEC_TO_TU(s->u.mesh.mshcfg.dot11MeshHWMPactivePathTimeout)
#define min_preq_int_jiff(s) \
	(msecs_to_jiffies(s->u.mesh.mshcfg.dot11MeshHWMPpreqMinInterval))
#define max_preq_retries(s) (s->u.mesh.mshcfg.dot11MeshHWMPmaxPREQretries)
#define disc_timeout_jiff(s) \
	msecs_to_jiffies(sdata->u.mesh.mshcfg.min_discovery_timeout)
#define root_path_confirmation_jiffies(s) \
	msecs_to_jiffies(sdata->u.mesh.mshcfg.dot11MeshHWMPconfirmationInterval)

enum mpath_frame_type {
	MPATH_PREQ = 0,
	MPATH_PREP,
	MPATH_PERR,
	MPATH_RANN
};

static const u8 broadcast_addr[ETH_ALEN] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};


static int mesh_path_sel_frame_tx(enum mpath_frame_type action, u8 flags,
				  const u8 *orig_addr, u32 orig_sn,
				  u8 target_flags, const u8 *target,
				  u32 target_sn, const u8 *da,
				  u8 hop_count, u8 ttl,
				  u32 lifetime, u32 metric, u32 preq_id,
		   		  const u8 *path_address_list,  u8 ie_len,                 
				  struct ieee80211_sub_if_data *sdata) 
 
{
	struct ieee80211_local *local = sdata->local;
	struct sk_buff *skb;
	struct ieee80211_mgmt *mgmt;
	u8 *pos; 
	int hdr_len = offsetof(struct ieee80211_mgmt, u.action.u.mesh_action) +
		      sizeof(mgmt->u.action.u.mesh_action);

	skb = dev_alloc_skb(local->tx_headroom +
			    hdr_len +
			    2 + ie_len); /* max HWMP IE #ifdef mesh_route  */
	if (!skb)
		return -1;
	skb_reserve(skb, local->tx_headroom);//作用：在缓冲区的头部空出指定大小的空间
	mgmt = (struct ieee80211_mgmt *) skb_put(skb, hdr_len);
	memset(mgmt, 0, hdr_len);
	mgmt->frame_control = cpu_to_le16(IEEE80211_FTYPE_MGMT |
					  IEEE80211_STYPE_ACTION);

	memcpy(mgmt->da, da, ETH_ALEN);
	memcpy(mgmt->sa, sdata->vif.addr, ETH_ALEN); //vif.addr
	/* BSSID == SA */
	memcpy(mgmt->bssid, sdata->vif.addr, ETH_ALEN);
	mgmt->u.action.category = WLAN_CATEGORY_MESH_ACTION;
	mgmt->u.action.u.mesh_action.action_code =
					WLAN_MESH_ACTION_HWMP_PATH_SELECTION;

	switch (action) {
	case MPATH_PREQ:
		mhwmp_dbg(sdata, "sending PREQ to %pM\n", target);
		//ie_len = 37;
	
        pos = skb_put(skb, 2 + ie_len);//skb_put() Ôö³¤Êý¾ÝÇøµÄ³¤¶ÈÀ´Îªmemcpy×¼±¸¿Õ¼ä
		*pos++ = WLAN_EID_PREQ;
		break;
	case MPATH_PREP:
		mhwmp_dbg(sdata, "sending PREP to %pM\n", orig_addr);
		//ie_len = 31;

		pos = skb_put(skb, 2 + ie_len);
		*pos++ = WLAN_EID_PREP;
		break;
	case MPATH_RANN:
		mhwmp_dbg(sdata, "sending RANN from %pM\n", orig_addr);
		ie_len = sizeof(struct ieee80211_rann_ie);
		pos = skb_put(skb, 2 + ie_len);
		*pos++ = WLAN_EID_RANN;
		break;
	default:
		kfree_skb(skb);
		return -ENOTSUPP;
		break;
	}
	*pos++ = ie_len;
	*pos++ = flags;
	*pos++ = hop_count;
	*pos++ = ttl;
	if (action == MPATH_PREP) {
		memcpy(pos, target, ETH_ALEN);
		pos += ETH_ALEN;
		put_unaligned_le32(target_sn, pos);//非四字节地址倍数的四字节值
		pos += 4;
	} else {
		if (action == MPATH_PREQ) {
			put_unaligned_le32(preq_id, pos);
			pos += 4;
		}
		memcpy(pos, orig_addr, ETH_ALEN);
		pos += ETH_ALEN;
		put_unaligned_le32(orig_sn, pos);
		pos += 4;
	}
	put_unaligned_le32(lifetime, pos); /* interval for RANN */
	pos += 4;
	put_unaligned_le32(metric, pos);
	pos += 4;
	if (action == MPATH_PREQ) {
		*pos++ = 1; /* destination count */
		*pos++ = target_flags;
		memcpy(pos, target, ETH_ALEN);
		pos += ETH_ALEN;
		put_unaligned_le32(target_sn, pos);
		pos += 4;
	} else if (action == MPATH_PREP) {
		memcpy(pos, orig_addr, ETH_ALEN);
		pos += ETH_ALEN;
		put_unaligned_le32(orig_sn, pos);
		pos += 4;
	}


	if(action==MPATH_PREQ && path_address_list)
	{
    	memcpy(pos,path_address_list, ie_len-37);
    }
    else if(action==MPATH_PREP && path_address_list)
    {
    	memcpy(pos,path_address_list, ie_len-31);
    }

	ieee80211_tx_skb(sdata, skb);
	return 0;
}


/*  Headroom is not adjusted.  Caller should ensure that skb has sufficient
 *  headroom in case the frame is encrypted. */
static void prepare_frame_for_deferred_tx(struct ieee80211_sub_if_data *sdata,
		struct sk_buff *skb)
{
	struct ieee80211_tx_info *info = IEEE80211_SKB_CB(skb);
	struct ieee80211_hdr *hdr = (struct ieee80211_hdr *) skb->data;

	skb_set_mac_header(skb, 0);
	skb_set_network_header(skb, 0);
	skb_set_transport_header(skb, 0);

	/* Send all internal mgmt frames on VO. Accordingly set TID to 7. */
	skb_set_queue_mapping(skb, IEEE80211_AC_VO);
	skb->priority = 7;

	info->control.vif = &sdata->vif;
	info->flags |= IEEE80211_TX_INTFL_NEED_TXPROCESSING;
	ieee80211_set_qos_hdr(sdata, skb);
	ieee80211_mps_set_frame_flags(sdata, NULL, hdr);
}

/**
 * mesh_path_error_tx - Sends a PERR mesh management frame
 *
 * @ttl: allowed remaining hops
 * @target: broken destination
 * @target_sn: SN of the broken destination
 * @target_rcode: reason code for this PERR
 * @ra: node this frame is addressed to
 * @sdata: local mesh subif
 *
 * Note: This function may be called with driver locks taken that the driver
 * also acquires in the TX path.  To avoid a deadlock we don't transmit the
 * frame directly but add it to the pending queue instead.å?å?å?å?
 */
int mesh_path_error_tx(struct ieee80211_sub_if_data *sdata,
		       u8 ttl, const u8 *target, u32 target_sn,
		       u16 target_rcode, const u8 *ra
		       ,const u8 *orig_addr,const u8 * invalid_addr,enum mesh_perr_flgas flag)
{
	struct ieee80211_local *local = sdata->local;
	struct sk_buff *skb;
	struct ieee80211_if_mesh *ifmsh = &sdata->u.mesh;
	struct ieee80211_mgmt *mgmt;
	u8 *pos, ie_len;
	u8 invalid_null[ETH_ALEN]={0,0,0,0,0,0};
	int hdr_len = offsetof(struct ieee80211_mgmt, u.action.u.mesh_action) +
		      sizeof(mgmt->u.action.u.mesh_action);

	if (time_before(jiffies, ifmsh->next_perr))
		return -EAGAIN;

	skb = dev_alloc_skb(local->tx_headroom +
			    IEEE80211_ENCRYPT_HEADROOM+//sdata->encrypt_headroom +  openwrt	
			    IEEE80211_ENCRYPT_TAILROOM +
			    hdr_len +
			    2 + 15+(2*ETH_ALEN) /* PERR IE */);
	if (!skb)
		return -1;
	skb_reserve(skb, local->tx_headroom + IEEE80211_ENCRYPT_HEADROOM);
	mgmt = (struct ieee80211_mgmt *) skb_put(skb, hdr_len);
	memset(mgmt, 0, hdr_len);
	mgmt->frame_control = cpu_to_le16(IEEE80211_FTYPE_MGMT |
					  IEEE80211_STYPE_ACTION);

	memcpy(mgmt->da, ra, ETH_ALEN);
	memcpy(mgmt->sa, sdata->vif.addr, ETH_ALEN);
	/* BSSID == SA */
	memcpy(mgmt->bssid, sdata->vif.addr, ETH_ALEN);
	mgmt->u.action.category = WLAN_CATEGORY_MESH_ACTION;
	mgmt->u.action.u.mesh_action.action_code =
					WLAN_MESH_ACTION_HWMP_PATH_SELECTION;
	ie_len = 15+(2*ETH_ALEN);
	pos = skb_put(skb, 2 + ie_len);
	*pos++ = WLAN_EID_PERR;
	*pos++ = ie_len;
	/* ttl */
	*pos++ = ttl;
	/* number of destinations */
	*pos++ = 1;
	/*
	 * flags bit, bit 1 is unset if we know the sequence number and
	 * bit 2 is set if we have a reason code
	 * bit 3 for major path
	 * bit 4 for minor path
	 */
	*pos = 0;
	if (!target_sn)
		*pos |= MP_F_USN;
	if (target_rcode)
		*pos |= MP_F_RCODE;
	if(flag==MP_F_MAJOR)
        *pos |= MP_F_MAJOR;
	if(flag==MP_F_MINOR)
		*pos |= MP_F_MINOR;
		
	pos++;
	memcpy(pos, target, ETH_ALEN);
	pos += ETH_ALEN;
	put_unaligned_le32(target_sn, pos);
	pos += 4;
	put_unaligned_le16(target_rcode, pos);
    pos += 2;

	memcpy(pos, orig_addr, ETH_ALEN);
	pos+=ETH_ALEN;
    if(invalid_addr==NULL){
        memcpy(pos, invalid_null, ETH_ALEN);
    }
	else {
		memcpy(pos, invalid_addr, ETH_ALEN);
	}
	pos+=ETH_ALEN;//

	/* see note in function header */
	prepare_frame_for_deferred_tx(sdata, skb);
	ifmsh->next_perr = TU_TO_EXP_TIME(
				   ifmsh->mshcfg.dot11MeshHWMPperrMinInterval);
	ieee80211_add_pending_skb(local, skb);
	return 0;
}

void ieee80211s_update_metric(struct ieee80211_local *local,
		struct sta_info *sta, struct sk_buff *skb)
{
	struct ieee80211_tx_info *txinfo = IEEE80211_SKB_CB(skb);
	struct ieee80211_hdr *hdr = (struct ieee80211_hdr *) skb->data;
	int failed;

	if (!ieee80211_is_data(hdr->frame_control))
		return;

	failed = !(txinfo->flags & IEEE80211_TX_STAT_ACK);

	/* moving average, scaled to 100 */
	sta->fail_avg = ((80 * sta->fail_avg + 5) / 100 + 20 * failed);
	if (sta->fail_avg > 95)
		mesh_plink_broken(sta);
}

static u32 airtime_link_metric_get(struct ieee80211_local *local,
				   struct sta_info *sta)
{
	struct rate_info rinfo;
	/* This should be adjusted for each device */
	int device_constant = 1 << ARITH_SHIFT;
	int test_frame_len = TEST_FRAME_LEN << ARITH_SHIFT;
	int s_unit = 1 << ARITH_SHIFT;
	int rate, err;
	u32 tx_time, estimated_retx;
	u64 result;

	if (sta->fail_avg >= 100)
		return MAX_METRIC;

	sta_set_rate_info_tx(sta, &sta->last_tx_rate, &rinfo);
	rate = cfg80211_calculate_bitrate(&rinfo);
	if (WARN_ON(!rate))
		return MAX_METRIC;

	err = (sta->fail_avg << ARITH_SHIFT) / 100;

	/* bitrate is in units of 100 Kbps, while we need rate in units of
	 * 1Mbps. This will be corrected on tx_time computation.
	 */
	tx_time = (device_constant + 10 * test_frame_len / rate);
	estimated_retx = ((1 << (2 * ARITH_SHIFT)) / (s_unit - err));
	result = (tx_time * estimated_retx) >> (2 * ARITH_SHIFT) ;
	return (u32)result;
}

/**
 * hwmp_route_info_get - Update routing info to originator and transmitter
 *
 * @sdata: local mesh subif
 * @mgmt: mesh management frame
 * @hwmp_ie: hwmp information element (PREP or PREQ)
 * @action: type of hwmp ie
 *
 * This function updates the path routing information to the originator and the
 * transmitter of a HWMP PREQ or PREP frame.
 *
 * Returns: metric to frame originator or 0 if the frame should not be further
 * processed
 *
 * Notes: this function is the only place (besides user-provided info) where
 * path routing information is updated.
 */
static u32 hwmp_route_info_get(struct ieee80211_sub_if_data *sdata,
			       struct ieee80211_mgmt *mgmt,
			       const u8 *hwmp_ie, enum mpath_frame_type action)  //只为prep调用
{
	struct ieee80211_local *local = sdata->local;
	struct mesh_path *mpath;
	struct sta_info *sta;
	bool fresh_info;
	const u8 *orig_addr;
	const u8 *target_addr;
	u32 orig_sn, orig_metric,target_sn;
	unsigned long orig_lifetime, exp_time;
	u32 last_hop_metric, new_metric;
	bool process = true;


	const u8 *mid_address_list;
	u8 ie_len;
	u8 flags;

	//xf
	//printk("route info get\n");

	rcu_read_lock();
	sta = sta_info_get(sdata, mgmt->sa);
	if (!sta) {
		rcu_read_unlock();
		return 0;
	}

	last_hop_metric = airtime_link_metric_get(local, sta);
	/* Update and check originator routing info */
	fresh_info = true;

	switch (action) {	
	case MPATH_PREQ:
		orig_addr = PREQ_IE_ORIG_ADDR(hwmp_ie);
		orig_sn = PREQ_IE_ORIG_SN(hwmp_ie);
		orig_lifetime = PREQ_IE_LIFETIME(hwmp_ie);
		orig_metric = PREQ_IE_METRIC(hwmp_ie);
		break;
	case MPATH_PREP:
		/* Originator here refers to the MP that was the target in the
		 * Path Request. We divert from the nomenclature in the draft
		 * so that we can easily use a single function to gather path
		 * information from both PREQ and PREP frames.
		 */
		orig_addr = PREP_IE_TARGET_ADDR(hwmp_ie);
		orig_sn = PREP_IE_TARGET_SN(hwmp_ie);
		orig_lifetime = PREP_IE_LIFETIME(hwmp_ie);
		orig_metric = PREP_IE_METRIC(hwmp_ie);
		ie_len=PREP_IE_LENGTH(hwmp_ie);
		mid_address_list=PREP_IE_MID_ADDRESS(hwmp_ie);//
		target_addr=PREP_IE_ORIG_ADDR(hwmp_ie);
	    flags=PREP_IE_FLAGS(hwmp_ie);
	    target_sn=PREP_IE_ORIG_SN(hwmp_ie);
		break;
	default:
		rcu_read_unlock();
		return 0;
	}
	new_metric = orig_metric + last_hop_metric;
	if (new_metric < orig_metric)  //·ÀÖ¹Òç³ö
		new_metric = MAX_METRIC;
	exp_time = TU_TO_EXP_TIME(orig_lifetime);
	

	if (ether_addr_equal(orig_addr, sdata->vif.addr)) {
		/* This MP is the originator, we are not interested in this
		 * frame, except for updating transmitter's path info.
		 */
		process = false;
		fresh_info = false;
	}else if(MPATH_PREQ==action){



	} else if(MPATH_PREP==action) {

	    
	   //xf
	   //printk(" PREP from %pM\n",orig_addr);
	

		if(flags & IEEE80211_PREP_MAJORPATH) //主路径
		{        
		  mpath = mesh_major_path_lookup(sdata, orig_addr,target_addr);//建立到目的节点的路径
		  if (mpath) {
			spin_lock_bh(&mpath->state_lock);
			if (mpath->flags & MESH_PATH_FIXED)
				//固定路径 不更新
				fresh_info = false;
			else if ((mpath->flags & MESH_PATH_ACTIVE) &&
			    (mpath->flags & MESH_PATH_SN_VALID)) {
				if (SN_GT(mpath->sn, orig_sn) ||
					((!SN_GT(mpath->sn, orig_sn) && new_metric> mpath->metric))) {
					process = false;
					fresh_info = false;
				}
			}
		  } else {
			mpath = mesh_path_add(sdata, MESH_PATHS,orig_addr,target_addr);
			if (IS_ERR(mpath)) {
				rcu_read_unlock();
				return 0;
			}
			spin_lock_bh(&mpath->state_lock);
		  }

		  if (fresh_info) {
			mesh_path_assign_nexthop(mpath, sta);
			//xf
			printk("prep mpath_orig=%pM,dst=%pM,prep_major_path_next_hop=%pM\n",mpath->orig,mpath->dst,(mpath->next_hop->sta).addr);
			
			mpath->flags |= MESH_PATH_SN_VALID;
			mpath->metric = new_metric;
			mpath->sn = orig_sn;
			mpath->exp_time = time_after(mpath->exp_time, exp_time)
					  ?  mpath->exp_time : exp_time;
			mesh_path_activate(mpath);
			spin_unlock_bh(&mpath->state_lock);
			mesh_path_tx_pending(mpath);
		
			
		   } else
			   spin_unlock_bh(&mpath->state_lock);

          // 换一个sta 列表最后的一个
          //xf
          if(ie_len>31)
          {
             //printk("prep_mid_list_count=%u\n",(ie_len-31)/ETH_ALEN);
			 u8 i;
			 for(i=0;i<(ie_len-31)/ETH_ALEN;i++)
			 {
			    //printk("prep_mid_list_addr=%pM\n",mid_address_list+i*ETH_ALEN);
			 }
          }
          if(ie_len>31+ETH_ALEN){
             sta=sta_info_get(sdata,mid_address_list+ie_len-31-(2*ETH_ALEN)); //?????
             if (!sta) {
		        rcu_read_unlock();
		       return 0;
	         }
           }else if(ie_len>31){
             sta=sta_info_get(sdata,target_addr);
             if (!sta) {
		        rcu_read_unlock();
		       return 0;
	         }
		   }else{
	       	   rcu_read_unlock();
		       return 0;
	       }
		 


		  mpath = mesh_major_path_lookup(sdata,target_addr,orig_addr);//建立到源节点的路径
		  if (mpath) {
			spin_lock_bh(&mpath->state_lock);
			if (mpath->flags & MESH_PATH_FIXED)
				//固定路径 不更新
				fresh_info = false;
			else if ((mpath->flags & MESH_PATH_ACTIVE) &&
			    (mpath->flags & MESH_PATH_SN_VALID)) {
				if (SN_GT(mpath->sn, target_sn) ||
					((!SN_GT(mpath->sn, orig_sn) && new_metric> mpath->metric))) {
					process = false;
					fresh_info = false;
				}
			}
		  } else {
			mpath = mesh_path_add(sdata, MESH_PATHS,target_addr,orig_addr);
			if (IS_ERR(mpath)) {
				rcu_read_unlock();
				return 0;
			}
			spin_lock_bh(&mpath->state_lock);
		  }

		  if (fresh_info) {
			mesh_path_assign_nexthop(mpath, sta);
			//xf
			printk("prep mpath_orig=%pM,dst=%pM,prep_major_path_next_hop=%pM\n",mpath->orig,mpath->dst,(mpath->next_hop->sta).addr);
			mpath->flags |= MESH_PATH_SN_VALID;
			//mpath->metric = new_metric;
			mpath->sn = target_sn;
			mpath->exp_time = time_after(mpath->exp_time, exp_time)
					  ?  mpath->exp_time : exp_time;
			mesh_path_activate(mpath);
			spin_unlock_bh(&mpath->state_lock);
			//mesh_path_tx_pending(mpath);
		
			/* draft says preq_id should be saved to, but there does
			 * not seem to be any use for it, skipping by now
			 */
		   } else
			   spin_unlock_bh(&mpath->state_lock);
		  }

	
		else if(flags & IEEE80211_PREP_MINORPATH)//备份路径
		 {
            mpath = mesh_minor_path_lookup(sdata, orig_addr,target_addr);//建立到目的节点的路径
		    if (mpath) {
			 spin_lock_bh(&mpath->state_lock);
			  if (mpath->flags & MESH_PATH_FIXED)
				//固定路径 不更新
				fresh_info = false;
			else if ((mpath->flags & MESH_PATH_ACTIVE) &&
			    (mpath->flags & MESH_PATH_SN_VALID)) {
				if (SN_GT(mpath->sn, orig_sn) ||
					((!SN_GT(mpath->sn, orig_sn) && new_metric> mpath->metric))) {
					process = false;
					fresh_info = false;
				}
			}
		    
		    } else {
			mpath = mesh_path_add(sdata, MESH_PATHS_BACKUP,orig_addr,target_addr);
			if (IS_ERR(mpath)) {
				rcu_read_unlock();
				return 0;
			}
			spin_lock_bh(&mpath->state_lock);
		  }

		  if (fresh_info) {
			mesh_path_assign_nexthop(mpath, sta);
			//xf
			printk("prep mpath_orig=%pM,dst=%pM,prep_minor_path_next_hop=%pM\n",mpath->orig,mpath->dst,(mpath->next_hop->sta).addr);
			mpath->flags |= MESH_PATH_SN_VALID;
			mpath->metric = new_metric;
			mpath->sn = orig_sn;
			mpath->exp_time = time_after(mpath->exp_time, exp_time)
					  ?  mpath->exp_time : exp_time;
			mesh_path_activate(mpath);
			spin_unlock_bh(&mpath->state_lock);
			mesh_path_tx_pending(mpath);
		
			
		   } else
			   spin_unlock_bh(&mpath->state_lock);

          // 换一个sta 列表最后的一个
          if(ie_len>31+ETH_ALEN){
             sta=sta_info_get(sdata,mid_address_list+ie_len-31-(2*ETH_ALEN)); //?????
             if (!sta) {
		        rcu_read_unlock();
		       return 0;
	         }
           }else if(ie_len>31){
             sta=sta_info_get(sdata,target_addr);
             if (!sta) {
		        rcu_read_unlock();
		       return 0;
	         }
		   }else{
	       	   rcu_read_unlock();
		       return 0;
	       }
		 


		  mpath = mesh_minor_path_lookup(sdata,target_addr,orig_addr);//建立到源节点的路径
		  if (mpath) {
			spin_lock_bh(&mpath->state_lock);
			if (mpath->flags & MESH_PATH_FIXED)
				//固定路径 不更新
				fresh_info = false;
			else if ((mpath->flags & MESH_PATH_ACTIVE) &&
			    (mpath->flags & MESH_PATH_SN_VALID)) {
				if (SN_GT(mpath->sn, target_sn) ||
					((!SN_GT(mpath->sn, orig_sn) && new_metric> mpath->metric))) {
					process = false;
					fresh_info = false;
				}
			}
		  } else {
			mpath = mesh_path_add(sdata, MESH_PATHS_BACKUP,target_addr,orig_addr);
			if (IS_ERR(mpath)) {
				rcu_read_unlock();
				return 0;
			}
			spin_lock_bh(&mpath->state_lock);
		  }

		  if (fresh_info) {
			mesh_path_assign_nexthop(mpath, sta);
			//xf
			printk("prep mpath_orig=%pM,dst=%pM,prep_minor_path_next_hop=%pM\n",mpath->orig,mpath->dst,(mpath->next_hop->sta).addr);
			mpath->flags |= MESH_PATH_SN_VALID;
			//mpath->metric = new_metric;
			mpath->sn = target_sn;
			mpath->exp_time = time_after(mpath->exp_time, exp_time)
					  ?  mpath->exp_time : exp_time;
			mesh_path_activate(mpath);
			spin_unlock_bh(&mpath->state_lock);
			//mesh_path_tx_pending(mpath);
		
			/* draft says preq_id should be saved to, but there does
			 * not seem to be any use for it, skipping by now
			 */
		   } else
			   spin_unlock_bh(&mpath->state_lock);
		 }
	
       	}

	/* Update and check transmitter routing info */
	
	rcu_read_unlock();

	return process ? new_metric : 0;
}

static void hwmp_preq_frame_process(struct ieee80211_sub_if_data *sdata,
				    struct ieee80211_mgmt *mgmt,
				    const u8 *preq_elem, u32 metric)

{
	struct ieee80211_if_mesh *ifmsh = &sdata->u.mesh;
	struct mesh_path *mpath = NULL;
	const u8 *target_addr, *orig_addr;
	const u8 *da;
	u8 target_flags, ttl, flag;
	u32 orig_sn, target_sn, lifetime, orig_metric;
	bool reply = false;
	bool forward = true;
	bool root_is_gate;
	u8 *  mid_address_list;


	struct sta_info *sta;
	rcu_read_lock();
	sta = sta_info_get(sdata, mgmt->sa);
	if (!sta) {
		rcu_read_unlock();
		return ;
	}
	rcu_read_unlock();


	const u8 * mid_address; 
	u8 hopcount;
	u8 ie_len;
	ie_len=PREQ_IE_LENGTH(preq_elem);
	hopcount = PREQ_IE_HOPCOUNT(preq_elem) + 1;
    mid_address=PREQ_IE_MID_ADDRESS(preq_elem);


	/* Update target SN, if present */
	target_addr = PREQ_IE_TARGET_ADDR(preq_elem);
	orig_addr = PREQ_IE_ORIG_ADDR(preq_elem);
	target_sn = PREQ_IE_TARGET_SN(preq_elem);
	orig_sn = PREQ_IE_ORIG_SN(preq_elem);
	target_flags = PREQ_IE_TARGET_F(preq_elem);
	orig_metric = metric;

	
	/* Proactive PREQ gate announcements */
	flag = PREQ_IE_FLAGS(preq_elem);
	root_is_gate = !!(flag & RANN_FLAG_IS_GATE);//??

	mhwmp_dbg(sdata, "received PREQ from %pM\n", orig_addr);
	
	//xf
	//printk("received PREQ from %pM\n", orig_addr);



	if (ether_addr_equal(orig_addr, sdata->vif.addr)) {//源地址和自己一样 不要
		
		return;
	} /*else {
		mpath = mesh_path_lookup(sdata, orig_addr);
		if (mpath) {
			spin_lock_bh(&mpath->state_lock);
			if (mpath->flags & MESH_PATH_FIXED)
				//固定路径 不更新
				return;
			else if ((mpath->flags & MESH_PATH_ACTIVE) &&
			    (mpath->flags & MESH_PATH_SN_VALID)) {
				if (SN_GT(mpath->sn, orig_sn) ) {
					return;
				}
			}
		} else {
			mpath = mesh_path_add(sdata, orig_addr);//添加路径
			if (IS_ERR(mpath)) {
				rcu_read_unlock();
				return ;
			}
			spin_lock_bh(&mpath->state_lock);
		  } 
		}*/
    u8 i=0;
	while(hopcount>1&& i<((ie_len-37)/ETH_ALEN) )  //不在地址列表中
	{
        if (ether_addr_equal(mid_address+((i)*ETH_ALEN), sdata->vif.addr))
        {
           
           return;
        }
        i++;        
    }

    if(hopcount>19)  //太多 其实这个也可以在发送preq的ttl中
    	return;

	if (ether_addr_equal(target_addr, sdata->vif.addr)) {  // 目的节点 
		forward = false;
		reply = true;
		//metric = 0;
	
		if (time_after(jiffies, ifmsh->last_sn_update +
					net_traversal_jiffies(sdata)) ||
		    time_before(jiffies, ifmsh->last_sn_update)) {
			target_sn = ++ifmsh->sn;//ÐÞ¸Äsn
			ifmsh->last_sn_update = jiffies;
		}
	}/* else if (is_broadcast_ether_addr(target_addr) &&//这一段不会执行
	//ÊÇ¹ã²¥°ü¿ÉÒÔreply
		   (target_flags & IEEE80211_PREQ_TO_FLAG)) {
		rcu_read_lock();
		mpath = mesh_path_lookup(sdata, orig_addr);
		if (mpath) {
			if (flags & IEEE80211_PREQ_PROACTIVE_PREP_FLAG) {
				reply = true;
				target_addr = sdata->vif.addr;
				target_sn = ++ifmsh->sn;
				metric = 0;
				ifmsh->last_sn_update = jiffies;
			}
			if (root_is_gate)
				mesh_path_add_gate(mpath);
		}
		rcu_read_unlock();
	} else {                                  //到这里 不是目的节点 根据协议实现 不更新 故注释掉 
	//ÊÇµ¥²¥°ü
		rcu_read_lock();
		mpath = mesh_path_lookup(sdata, target_addr);
		if (mpath) {
			;if ((!(mpath->flags & MESH_PATH_SN_VALID)) ||
					SN_LT(mpath->sn, target_sn)) {
				mpath->sn = target_sn;
				mpath->flags |= MESH_PATH_SN_VALID;
			} else if ((!(target_flags & MP_F_DO)) &&    //目前只允许目的节点reply 也注释掉
					(mpath->flags & MESH_PATH_ACTIVE)) {
				reply = true;
				metric = mpath->metric;//metric 
				target_sn = mpath->sn;
				if (target_flags & MP_F_RF)//// 
					target_flags |= MP_F_DO;
				else
					forward = false;
			}
		}
		rcu_read_unlock();*/
	//}


	    ie_len +=ETH_ALEN; // mid_node_count就是 hopcount 这里会算上目的节点 
	                                      // 必须要带上目的节点 用来判断链路不想交

		mid_address_list=kmalloc(hopcount*ETH_ALEN,GFP_ATOMIC);
		if(mid_address&&hopcount >1){

			memcpy(mid_address_list,mid_address,(hopcount-1)*ETH_ALEN);	
			
		}
		
			
	    memcpy(mid_address_list+(hopcount-1)*ETH_ALEN,sdata->vif.addr,ETH_ALEN);		
        //xf
        
		//for (i=0;i<(hopcount);i++)
		//{
        //printk("mid_address_list=%pM\n",mid_address_list+i*ETH_ALEN);
		//}
		//printk("mid_address_list=%pM\n",mid_address_list);

	if (reply) {

		lifetime = PREQ_IE_LIFETIME(preq_elem);	
        //xf
        //printk("reply\n");
		 		
        destination_node_preq_process(orig_addr, ie_len,mid_address_list, metric,
								orig_sn,lifetime, sdata);
		

	}


	if (forward && ifmsh->mshcfg.dot11MeshForwarding) {
		u32 preq_id;
		//u8 hopcount;

		ttl = PREQ_IE_TTL(preq_elem);
		lifetime = PREQ_IE_LIFETIME(preq_elem);
		if (ttl <= 1) {
			ifmsh->mshstats.dropped_frames_ttl++;
			return;
		}
		mhwmp_dbg(sdata, "forwarding the PREQ from %pM\n", orig_addr);
		--ttl;
		preq_id = PREQ_IE_PREQ_ID(preq_elem);
		//hopcount = PREQ_IE_HOPCOUNT(preq_elem) + 1;


		da = (mpath && mpath->is_root) ?
			mpath->rann_snd_addr : broadcast_addr;

		if (flag & IEEE80211_PREQ_PROACTIVE_PREP_FLAG) {   //这里也不会执行
			target_addr = PREQ_IE_TARGET_ADDR(preq_elem);
			target_sn = PREQ_IE_TARGET_SN(preq_elem);
			metric = orig_metric;
		}


		mesh_path_sel_frame_tx(MPATH_PREQ, flag, orig_addr,
				       orig_sn, target_flags, target_addr,
				       target_sn, da, hopcount, ttl, lifetime,
				       metric, preq_id, mid_address_list,ie_len,sdata);
		if (!is_multicast_ether_addr(da))
			ifmsh->mshstats.fwded_unicast++;
		else
			ifmsh->mshstats.fwded_mcast++;
		ifmsh->mshstats.fwded_frames++;
	}





	kfree(mid_address_list);


}


 void  destination_node_preq_process(const u8 * orig_addr, 
								u8 ie_len, u8 *mid_address_list,u32 metric,
								u32 orig_sn,u32 lifetime, struct ieee80211_sub_if_data *sdata)
{
    
    //xf
	//printk("destination_node_preq_process1\n");

	struct mesh_preq_state_machine * node=mesh_get_preq_from_list(orig_addr);

    //xf
	//printk("destination_node_preq_process2\n");

	if(node==NULL){
		//xf
	    //printk("preq_state_machine_add\n");

		preq_state_machine_add(orig_addr);
	}
    if (node){
		//xf
	    //printk("node switch %pM\n",node->originater_address);
		spin_lock_bh(&node->lock);
	    if(node->flags & MESH_RECEIVE_PREQ_TIMEOUT)// timeout if no time_after discard
	    {
	    	
	    	//if(time_after(jiffies,node->des_req_timer_timeout_time+des_req_resetFlags_timeout) 
	    	//	|| time_before(jiffies,node->des_req_timer_timeout_time)){
	    	    //xf
	    	    //printk("preq timeout,return\n");
	    		spin_unlock_bh(&node->lock);
	    		return;
	    }
  
       if(!(node->flags & MESH_NOT_FIRST_RECEIVE_PREQ) ) //first preq
	  //&&(!(mpath->flags & MESH_PATH_RECEIVE_PREQ_TIMEOUT)))
	   {  
           node->flags |=MESH_NOT_FIRST_RECEIVE_PREQ; 
		    //xf
	      // printk("first preq,mod timer\n");
           mod_timer(&node->des_req_timer,jiffies+30);
           mod_timer(&node->des_req_clear_timer,jiffies+30+20);

	    }
	   if(!(node->flags & MESH_RECEIVE_PREQ_TIMEOUT) ) //no timeout
	   	//metric比主路径好 就一定更新 再判断原来的主路径是否和这条路径链路相交 不是 原来的主换成备份 
	   	//metric只比备份好 就还要判断是否和主路径相交 如果是的 就不更新
	   	//更新有两种 1 更新主 判断 再决定主换备 2 只更新备份 
		{

			 path_info_add (node,ie_len, mid_address_list,metric,lifetime,orig_sn,sdata);
	       /*if(metric < node->metric_minor)
	       {													
	       	  if(metric < node->metric_major) 
	       	  {
	       	  	   
                  change_node_major_info(ie_len,mid_address_list,metric,lifetime,orig_sn,sdata); //1 这个函数内部调用了link_disconnet
                  
	       	  }
	       	  else if(link_disconnect(orig_addr,ie_len,mid_address_list,1))
	       	  {
	       	  	 
                  change_node_minor_info(ie_len,mid_address_list,metric,lifetime,orig_sn,sdata); //2
                  
	       	  }
	       }*/

           
	        
		}
	spin_unlock_bh(&node->lock);
   }
}

u8 mesh_preq_state_machine_hash(const u8 * orig_addr)
{
   return (orig_addr[4])%10;
}

u8 mesh_preq_mid_list_hash(u8 *node1_addr, u8 *node2_addr)// 各取最后一个字节 加起来 做hash
{
   return (node1_addr[4] + node2_addr[4])%10;  
}

void mesh_preq_mid_list_hash_tabel_add(u8 *node1_addr, u8 *node2_addr,
	                                  struct mesh_preq_state_machine * node)
{
	u8 hash_num=mesh_preq_mid_list_hash(node1_addr, node2_addr);
	struct mesh_preq_mid_list_hash_node *hash_node, *new_node;

	//xf
	//printk("hash_node_add\n");

	hash_node=&((node->mesh_preq_mid_list_hash_tabel_major)[hash_num]);
	if(hash_node->flags==0){
		    //xf
		    //printk("hash_node_add_no_dup\n");
		    hash_node->node1_addr=node1_addr;
		    hash_node->node2_addr=node2_addr;
		    hash_node->flags=1;
	}else{
	    new_node=kzalloc(sizeof(struct mesh_preq_mid_list_hash_node),GFP_ATOMIC);
	    //spin_lock_init(&new_node->lock);
	    //xf
		//printk("hash_node_add_dup\n");
	    new_node->node1_addr=node1_addr;
		new_node->node2_addr=node2_addr;
		new_node->flags=1;
	    list_add_tail(&new_node->list,&hash_node->list);//??????
	}
	//xf
	  /*u8 i;
	  struct mesh_preq_mid_list_hash_node *print_node,*list_node;
      for (i=0;i<(NODE_NUM);i++)
	  {
	     print_node=&((node->mesh_preq_mid_list_hash_tabel_major)[i]);
		 printk("hash_node1=%pM,hash_node2=%pM,flag=%u\n",print_node->node1_addr,print_node->node2_addr,print_node->flags);

         list_for_each_entry(list_node,&(print_node->list),list)
         {
             
       	  printk("hash_node1=%pM,hash_node2=%pM,flag=%u\n",list_node->node1_addr,list_node->node2_addr,list_node->flags);
		  
        }
	  }*/

}


bool mesh_preq_mid_list_hash_tabel_has(struct mesh_preq_state_machine * node,u8 *node1_addr, u8 *node2_addr)//通过地址列表中的两个地址判
{
	struct mesh_preq_mid_list_hash_node *hash_node,*each_node;

	u8 hash_num=mesh_preq_mid_list_hash(node1_addr, node2_addr);
	//xf
	//printk("hash_node_hash_num=%u\n",hash_num);

	hash_node=&((node->mesh_preq_mid_list_hash_tabel_major)[hash_num]); //
		

    if(hash_node->flags==0){
       return false;
    }
    else{

		if((ether_addr_equal(hash_node->node1_addr,node1_addr) && ether_addr_equal(hash_node->node2_addr,node2_addr))
            	||(ether_addr_equal(hash_node->node1_addr,node2_addr) && ether_addr_equal(hash_node->node1_addr,node2_addr)))
        {
                  return true;
        }
    	list_for_each_entry(each_node,&(hash_node->list),list)
    	{ 
            if((ether_addr_equal(each_node->node1_addr,node1_addr) && ether_addr_equal(each_node->node2_addr,node2_addr))
            	||(ether_addr_equal(each_node->node1_addr,node2_addr) && ether_addr_equal(each_node->node1_addr,node2_addr)))
            	{
                  return true;
                }
    	}
    }
    
    return false;
}

void major_path_hash_table_free(struct mesh_preq_state_machine * node)
{
   u8 i;
   struct mesh_preq_mid_list_hash_node *hash_node,*each_node,*next_node;
   
   if(node->mesh_preq_mid_list_hash_tabel_major){
   	for(i=0;i<NODE_NUM;i++){
   		hash_node=&((node->mesh_preq_mid_list_hash_tabel_major)[i]); 
	   	if(hash_node->flags==0)	       
	       continue;

	    list_for_each_entry_safe(each_node,next_node,&hash_node->list,list)
	    { 
	            list_del(&each_node->list);
	            kfree(each_node);
	    }
     }

     kfree(node->mesh_preq_mid_list_hash_tabel_major);
   }


}

void generate_major_path_hash_table(struct mesh_preq_state_machine * node,u8 * mid_address_list_new, u8 count)
// generate_major_path_hash_table 
//对于第二个preq 用这个函数直接添加进去  应该可以？
{
   u8 i;
   //u8 hash_num;
   //struct mesh_preq_mid_list_hash_node *hash_node;
   //struct mesh_preq_mid_list_hash_node *each_node, *next_node;
   //struct mesh_preq_state_machine * node=mesh_get_preq_from_list(orig_addr);
   //spin_lock_bh(&(node->lock));

   node->mesh_preq_mid_list_hash_tabel_major=kzalloc(sizeof(struct mesh_preq_mid_list_hash_node)*NODE_NUM,GFP_ATOMIC);

   for(i=0;i<NODE_NUM;i++){

    ((node->mesh_preq_mid_list_hash_tabel_major)[i]).flags=0;
	INIT_LIST_HEAD(&(((node->mesh_preq_mid_list_hash_tabel_major)[i]).list));
   }
   
   if(count>0){
   	  //xf
      //printk("hash_table_node_cnt=%u\n",count);
	   for(i=0;i<(count-1);i++){
		      //hash_num=mesh_preq_mid_list_hash(mid_address_list_new+(i*ETH_ALEN),mid_address_list_new+((i+1)*ETH_ALEN));
		     // hash_node=&((node->mesh_preq_mid_list_hash_tabel_major)[hash_num]);
		  mesh_preq_mid_list_hash_tabel_add(mid_address_list_new+(i*ETH_ALEN),
             mid_address_list_new+((i+1)*ETH_ALEN), node);
		}

	   mesh_preq_mid_list_hash_tabel_add(mid_address_list_new,
             node->originater_address, node);
    }
   

     
   
    //spin_unlock_bh(&(node->lock));

   //首先要清0  这里就把flags 改为0  还要释放连接上去的节点 ???
   /*if(kind==1){
	   for(i=0;i<NODE_NUM;i++){
	      hash_node=&((node->mesh_preq_mid_list_hash_tabel_major)[i]);
	      spin_lock_bh(&(hash_node->lock));
	      hash_node->flags=0;
	      list_for_each_entry_safe(each_node,next_node,&hash_node->list,list)// free node 好虚啊
	      {
              if(each_node->flags==1){
              	list_del(&each_node->list);
              	kfree(each_node);//或者使用rcu延迟释放？？
              }
	      }
	      spin_unlock_bh(&(hash_node->lock));
	   }
   }else if(kind==2){
       for(i=0;i<NODE_NUM;i++){
	      hash_node=&((node->mesh_preq_mid_list_hash_tabel_minor)[i]);
	      spin_lock_bh(&(hash_node->lock));
	      hash_node->flags=0;
	      list_for_each_entry_safe(each_node,next_node,&hash_node->list,list)// free node
	      {
              if(each_node->flags==1){
              	list_del(&each_node->list);
              	kfree(each_node);//或者使用rcu延迟释放？？
              }
	      }
	      spin_unlock_bh(&(hash_node->lock));
	   }

   }*/
   
   //然后再替换
  /* for(i=0;i<count-1;i++){
      hash_num=mesh_preq_mid_list_hash(mid_address_list_new+(i*ETH_ALEN),mid_address_list_new+((i+1)*ETH_ALEN));
      hash_node=&((node->mesh_preq_mid_list_hash_tabel)[hash_num]);
      spin_lock(&(hash_node->lock));
      if(hash_node->flags==1){// 添加到链表上
      	  struct mesh_preq_mid_list_hash_node *new_node=kzalloc(sizeof(mesh_preq_mid_list_hash_node),GFP_ATOMIC);
	      new_node->node1_addr=mid_address_list_new+(i*ETH_ALEN);
		  new_node->node2_addr=mid_address_list_new+((i+1)*ETH_ALEN);
		  new_node->flags=1;
		  spin_lock_init(&new_node->lock);
		  list_add_tail(&new_node->list,&hash_node->list);//??????
		  spin_unlock(&(hash_node->lock));
	  }else{
          hash_node->node1_addr=mid_address_list_new+(i*ETH_ALEN);
		  hash_node->node2_addr=mid_address_list_new+((i+1)*ETH_ALEN);
		  hash_node->flags=1;
		  spin_unlock(&(hash_node->lock));	  	   
	  }
   }*/
       	
} 
 



bool link_disconnect(struct mesh_preq_state_machine * state_machine,struct path_info * path_minor)//hash
//kind 1 指主路径 2 指 备份路径
{
     //如果由orig_addr找到的node的minor_node_count是0 那么就是不相交的
	//struct mesh_preq_mid_list_hash_node *hash_node;
	//u8 hash_num;
    u8 i;
	//struct mesh_preq_mid_list_hash_node *each_node;
	if(! state_machine){
		return false;
	}
	//xf
	//printk("path_minor_node_cnt=%u,metirc=%u\n",path_minor->node_cnt,path_minor->metric);

    if( path_minor->node_cnt>1 )
	{
		for(i =0; i<(path_minor->node_cnt-1) ; i++)
		{		
			 // hash_num=mesh_preq_mid_list_hash(mid_address_list_new+(i*ETH_ALEN),mid_address_list_new+((i+1)*ETH_ALEN));
             //hash_node=&((node->mesh_preq_mid_list_hash_tabel)[hash_num]);
            if(mesh_preq_mid_list_hash_tabel_has(state_machine,path_minor->path_list+(i*ETH_ALEN),path_minor->path_list+((i+1)*ETH_ALEN)))
            {
               
               return false;
            }
		}		
	}
	if (path_minor->node_cnt >0){
        if(mesh_preq_mid_list_hash_tabel_has(state_machine,path_minor->path_list,state_machine->originater_address))
        {
           return false;
        }

	}

	return true;
  
}


/*bool link_disconnect(u8 * orig_addr,u8 ie_len,char *mid_address_list,u8 kind)//真的要一个个比较？
//kind 1 指主路径 2 指 备份路径
{
     //如果由orig_addr找到的node的minor_node_count是0 那么就是不相交的
	struct mesh_preq_state_machine * node=mesh_get_preq_from_list(orig_addr);
	if(node->minor_node_cnt==0)
		return true;
    if(node && ie_len>37 )
	{
		for(i =0; i<((ie_len-37)/ETH_ALEN-1) ; i++)
		{
			if(kind==1 && node->major_node_cnt>0){
				for(j= 0;j<(node->major_node_cnt-1);j++)
				{
                   if(ether_addr_equal(mid_address_list+(i*ETH_ALEN),node->path_list_major+(j*ETH_ALEN))&&
                   	ether_addr_equal(mid_address_list+((i+1)*ETH_ALEN),node->path_list_major+((j+1)*ETH_ALEN)))
                   	  return false;
				}
			}
			else if(kind==2 && node->minor_node_cnt>0){
				for(j= 0;j<(node->minor_node_cnt-1);j++)
				{
                  if(ether_addr_equal(mid_address_list+(i*ETH_ALEN),node->path_list_minor+(j*ETH_ALEN))&&
                   	ether_addr_equal(mid_address_list+((i+1)*ETH_ALEN),node->path_list_minor+((j+1)*ETH_ALEN)))
                   	  return false;
				}
			}
		}
	}
}*/


bool node_disconnect(u8 * orig_addr,u8 ie_len,char *mid_address_list,u8 kind){}
//kind 1 指主路径 2 指 备份路径
/* { */
/*     struct mesh_preq_state_machine * node=mesh_get_preq_from_list(orig_addr); */
/*     u8 i ,j; */
/* 	if(node) */
/* 	{ */
/* 		for(i =0; i<(ie_len-37)/ETH_ALEN ; i++) */
/* 		{ */
/* 			if(kind==1){ */
/* 				for(j= 0;j<node->major_node_cnt;j++) */
/* 				{ */
/*                    if(ether_addr_equal(mid_address_list+(i*ETH_ALEN),node->path_list_major+(j*ETH_ALEN)) */
/*                    	  return false; */
/* 				} */
/* 			} */
/* 			else if(kind==2){ */
/* 				for(j= 0;j<node->minor_node_cnt;j++) */
/* 				{ */
/*                   if(ether_addr_equal(mid_address_list+(i*ETH_ALEN),node->path_list_minor+(j*ETH_ALEN)) */
/*                    	  return false; */
/* 				} */
/* 			} */
/* 		} */
/* 	} */
/* 	return ture; */
/* } */




void change_node_major_info(u8 * orig_addr,u8 ie_len,char *mid_address_list,u32 metric,u32 lifetime,
	                       u32 orig_sn, struct ieee80211_sub_if_data *sdata)
{

  /*struct mesh_preq_state_machine * node=mesh_get_preq_from_list(orig_addr);
  spin_lock_bh(&(node->lock));

  if(link_disconnect(orig_addr,ie_len,mid_address_list,1)){
	   struct mesh_preq_mid_list_hash_node* mesh_preq_mid_list_hash_tabel_temp;

	   
       mesh_preq_mid_list_hash_tabel_temp=node->mesh_preq_mid_list_hash_tabel_major;
   	   node->mesh_preq_mid_list_hash_tabel_major=node->mesh_preq_mid_list_hash_tabel_minor;
   	   node->mesh_preq_mid_list_hash_tabel_minor=mesh_preq_mid_list_hash_tabel_temp;

  }

   node->metric_major=metric;
   node->major_node_cnt=(ie_len-37)/ETH_ALEN;
   kfree(node->path_list_major);
   node->path_list_major=kmalloc((ie_len-37),GFP_ATOMIC);
   memcpy(node->path_list_major,mid_address_list,(ie_len-37));

   node->lifetime_major=lifetime;
   node->orig_sn_major=orig_sn;
   node->sdata_minor=sdata;
   mesh_preq_mid_list_hash_tabel_replace(mid_address_list, node->major_node_cnt,1 );


   spin_unlock_bh(&(node->lock));*/
   return;
}


void change_node_minor_info(u8 * orig_addr,u8 ie_len,char *mid_address_list,u32 metric,
                          struct ieee80211_sub_if_data *sdata)
{
   
   /*struct mesh_preq_state_machine * node=mesh_get_preq_from_list(orig_addr);
   spin_lock_bh(&(node->lock));
   node->metric_minor=metric;
   node->minor_node_cnt=(ie_len-37)/ETH_ALEN;
   kfree(node->path_list_minor);
   node->path_list_minor=kmalloc((ie_len-37),GFP_ATOMIC);
   node->sdata_minor=sdata;
   memcpy(node->path_list_minor,mid_address_list,(ie_len-37));

   node->lifetime_minor=lifetime;
   node->orig_sn_minor=orig_sn;
   mesh_preq_mid_list_hash_tabel_replace(mid_address_list, node->minor_node_cnt,2 );

   spin_unlock_bh(&(node->lock));*/
   return;

}


struct mesh_preq_state_machine * mesh_get_preq_from_list(const u8 *orig_addr)
{

	struct mesh_preq_state_machine * node=NULL;
	struct mesh_preq_state_macchine_table *preq_table_bucket;

	u8 hash_num=mesh_preq_state_machine_hash(orig_addr);
	//xf
	//printk("state_machine_hash_num=%u\n",hash_num);
	
	
    preq_table_bucket=&(preq_table[hash_num]);
	spin_lock_bh(&(preq_table_bucket->state_lock));

	//xf
	//printk("list_for_each_entry\n");
	
      list_for_each_entry(node,&(preq_table_bucket->list),list)
      {
       if(node && ether_addr_equal(node->originater_address,orig_addr)){
	   	  spin_unlock_bh(&(preq_table_bucket->state_lock));
		  //printk("ok\n");
       	  return node;
       	}
      }
	
	spin_unlock_bh(&(preq_table_bucket->state_lock));

	//printk("ok\n");
	return NULL;
}

          


/*struct mesh_preq_state_machine * mesh_add_preq_to_list(u8 * orig_addr)//这个没有用 被下面的函数取代了
{
	struct mesh_preq_state_machine * node=kzalloc(sizeof(mesh_preq_state_machine),GFP_ATOMIC);
	
	spin_lock(&preq_table->state_lock);
    
    list_add_tail(&node->list,&mesh_preq_state_macchine_table->list);

	spin_unlock(&preq_table->state_lock);

    return node;
}*/


struct path_info * choose_minor_path(struct mesh_preq_state_machine * state_machine)//major path就是list_preq后面的第一个 得到后删除
{
	struct path_info * node, *first_node;


	//first_node=list_first_entry (&state_machine->list_preq,struct path_info,list_preq);//????
	//xf
	//printk("first_node_sn=%u\n",first_node->orig_sn);
	list_for_each_entry(node,&state_machine->list_preq,list_preq){
       //printk("node_sn=%u\n",node->orig_sn);
	}
	list_for_each_entry(node,&state_machine->list_preq,list_preq){
       if(link_disconnect(state_machine,node)){
       	
       	  return node;
       }
	}
   
    return NULL;

}

struct path_info * choose_major_path(struct mesh_preq_state_machine * state_machine)//major path就是list_preq后面的第一个 得到后删除
{
	 struct path_info * node;
	
     if(!(list_empty(&state_machine->list_preq))){
	  
      node=list_first_entry (&state_machine->list_preq,struct path_info,list_preq);//????
      //xf
      //printk("major_path_node_sn=%u\n",node->orig_sn);
      generate_major_path_hash_table(state_machine,node->path_list, (node->node_cnt));

     
    
	  list_del(&node->list_preq);
      //kfree(node);
     
      return node;
	}
 
    return NULL;
}



void path_info_list_free(struct mesh_preq_state_machine * state_machine)
{
	struct path_info * each_node, * next_node;
	
    list_for_each_entry_safe(each_node,next_node,&state_machine->list_preq,list_preq)// free node
     {
              	list_del(&each_node->list_preq);
              	kfree(each_node->path_list);//或者使用rcu延迟释放？？
              	kfree(each_node);
     }

	 INIT_LIST_HEAD(&state_machine->list_preq);
 

}

void  path_info_add (struct mesh_preq_state_machine * node,u8 ie_len, const u8 *mid_address_list,u32 metric,u32 lifetime,
                                  u32 orig_sn, struct ieee80211_sub_if_data *sdata)//添加节点到preq state machine 上
{
	

	struct path_info *path_info_node, *path_info_for_list;

	path_info_node=kzalloc(sizeof(struct path_info ),GFP_ATOMIC);

    path_info_node->metric=metric;
    path_info_node->node_cnt=(ie_len-37)/ETH_ALEN;
	 //xf
    // printk("path info add\n");
	
    path_info_node->path_list=kmalloc((path_info_node->node_cnt)*ETH_ALEN,GFP_ATOMIC);
	if(path_info_node->path_list && mid_address_list){
       memcpy(path_info_node->path_list,mid_address_list,(path_info_node->node_cnt)*ETH_ALEN);
 
	}
	path_info_node->orig_sn=orig_sn;
    path_info_node->lifetime=lifetime;             
    path_info_node->sdata=sdata;

	INIT_LIST_HEAD(&(path_info_node->list_preq));

    if(node){
	   
	   if(list_empty(&node->list_preq)){
	         list_add(&path_info_node->list_preq,&node->list_preq);//节点后插入
             //xf
            // printk("first path info add\n");
	   }else {
	        //xf
          // printk("not first path info add\n");
	   	   list_for_each_entry(path_info_for_list,&node->list_preq,list_preq)
           {

             if(SN_GT(path_info_node->orig_sn,path_info_for_list->orig_sn) ||
             	   (!(SN_GT(path_info_for_list->orig_sn,path_info_node->orig_sn)) 
                       &&SN_GT(path_info_for_list->metric,path_info_node->metric))){
             	list_add_tail(&path_info_node->list_preq,&path_info_for_list->list_preq);// 节点前插入
       	        goto end;
       	     }
           }
	       list_add_tail(&path_info_node->list_preq,&node->list_preq);
	   }
       	 //xf
       /*printk("start list preq\n");
       list_for_each_entry(path_info_for_list,&node->list_preq,list_preq)
       {
             
       	   printk("mesh_preq_state_machine_orig_addr=%pM,path info,orig_sn=%u,metric=%u\n",
				    node->originater_address,path_info_for_list->orig_sn,path_info_for_list->metric);
		   u8 i;
		   for (i=0;i<(path_info_for_list->node_cnt);i++)
		   {
		     printk("path_list=%pM\n",path_info_for_list->path_list+i*ETH_ALEN);
		   }
       }*/
   
	   
	  
	   return;
    }
  end:
  	   //xf
  	   /*printk("start list preq\n");
       list_for_each_entry(path_info_for_list,&node->list_preq,list_preq)
       {
             
       	   printk("mesh_preq_state_machine_orig_addr=%pM,path info,orig_sn=%u,metric=%u\n",
				    node->originater_address,path_info_for_list->orig_sn,path_info_for_list->metric);
		   u8 i;
		   for (i=0;i<(path_info_for_list->node_cnt);i++)
		   {
		     printk("path_list=%pM\n",path_info_for_list->path_list+i*ETH_ALEN);
		   }
       }*/
   
	return;

}


void preq_state_machine_add(const u8 *orig_addr) //这里就在链表上添加一个节点 
										
{
    struct  mesh_preq_state_macchine_table *preq_table_bucket;
    //	u8  i=0;
	u8 hash_num;
    
    struct  mesh_preq_state_machine *new_node=kzalloc(sizeof(struct mesh_preq_state_machine),GFP_ATOMIC);
    if (!new_node)
		goto err_node_alloc;
	if(orig_addr){
	   memcpy(new_node->originater_address,orig_addr,ETH_ALEN);
	}
	new_node->des_req_timer.data=(unsigned long)new_node;
	new_node->des_req_timer.function=preq_state_machine_timer;
	new_node->des_req_timer.expires=jiffies;//define
    init_timer(&new_node->des_req_timer);
    new_node->des_req_timer_timeout_time=jiffies;

    new_node->des_req_clear_timer.data=(unsigned long)new_node;
	new_node->des_req_clear_timer.function=preq_state_machine_clean_timer;
	new_node->des_req_clear_timer.expires=jiffies;//define
    init_timer(&new_node->des_req_clear_timer);

    /*new_node->major_node_cnt=0;//(ie_len-37)/ETH_ALEN;
    new_node->metric_major=0xffffffff;
    // 下面几个kmalloc需要加上判断不成功的状态 这里仅仅为了方便省略是不好的
    new_node->path_list_major=kmalloc(ETH_ALEN,GFP_ATOMIC);//kmalloc((new_node->major_node_cnt)*ETH_ALEN,GFP_ATOMIC);

    new_node->path_list_minor=kmalloc(ETH_ALEN,GFP_ATOMIC);//先分配一段地址？
    new_node->minor_node_cnt=0;
    new_node->metric_minor=0xffffffff;*/

    INIT_LIST_HEAD(&new_node->list_preq);

    /*new_node->mesh_preq_mid_list_hash_tabel_major=kzalloc(sizeof(mesh_preq_mid_list_hash_node)*NODE_NUM,GFP_ATOMIC);//NODE_NUM 10
    //全0  这里的hash_table要不要给每一个node加一个锁 因为有链表？
    for(i=0;i<NODE_NUM;i++){
    	spin_lock_init(&((new_node->mesh_preq_mid_list_hash_tabel_major)[i]).lock); 
    	INIT_LIST_HEAD(&((new_node->mesh_preq_mid_list_hash_tabel_major)[i]).list);//???
    }

    new_node->mesh_preq_mid_list_hash_tabel_minor=kzalloc(sizeof(mesh_preq_mid_list_hash_node)*NODE_NUM,GFP_ATOMIC);//NODE_NUM 10
    //全0  这里的hash_table要不要给每一个node加一个锁 因为有链表？
    for(i=0;i<NODE_NUM;i++){
    	spin_lock_init(&((new_node->mesh_preq_mid_list_hash_tabel_minor)[i]).lock); 
    	INIT_LIST_HEAD(&((new_node->mesh_preq_mid_list_hash_tabel_minor)[i]).list);//???

    }

    new_node->orig_sn_major=orig_sn;
    new_node->lifetime_major=lifetime;

    new_node->sdata_major=sdata;*/

    new_node->flags=0;
    spin_lock_init(&new_node->lock);

    new_node->mesh_preq_mid_list_hash_tabel_major=NULL;

    hash_num=mesh_preq_state_machine_hash(orig_addr);
    
    preq_table_bucket=&(preq_table[hash_num]);

    spin_lock_bh(&preq_table_bucket->state_lock);

    list_add_tail(&new_node->list,&preq_table_bucket->list);//对于node list 还需不需要初始化？？？
    
    spin_unlock_bh(&preq_table_bucket->state_lock);
    return;

   err_node_alloc:
	  kfree(new_node);
}


void 
preq_state_machine_timer(unsigned long data)   //timer  锁 
{
    struct mesh_preq_state_machine * node=(void *)data;
	struct ieee80211_if_mesh *ifmsh ;
	struct mesh_path *mpath;
	struct sta_info *sta;
    struct path_info * major_path,*minor_path;
	u8 * next_hop,ttl;
	unsigned long exp_time;
	
    spin_lock_bh(&node->lock);
    node->des_req_timer_timeout_time=jiffies;
    node->flags |= MESH_RECEIVE_PREQ_TIMEOUT;

	//xf
	//printk("preq_state_machine_timer=%pM\n",node->originater_address);

	major_path=choose_major_path(node);
	
	minor_path=choose_minor_path(node);

    if(major_path){
		
		mpath = mesh_major_path_lookup(major_path->sdata, node->originater_address,major_path->sdata->vif.addr);
        if(!mpath){
          mpath = mesh_path_add(major_path->sdata, MESH_PATHS,node->originater_address,major_path->sdata->vif.addr);
          if (IS_ERR(mpath)) {
				return ;
		   }
		}
        
		if(mpath){
			
			if(mpath->flags & MESH_PATH_FIXED){
                return ;
			}

			spin_lock_bh(&mpath->state_lock);

			if(major_path->node_cnt>1){
				 next_hop=major_path->path_list+((major_path->node_cnt-2)*ETH_ALEN);
                
			}else{
                 next_hop=node->originater_address;
			}

			

            exp_time = TU_TO_EXP_TIME(major_path->lifetime);
			
			mpath->flags |= MESH_PATH_SN_VALID;
			mpath->metric = major_path->metric;
			mpath->sn = major_path->orig_sn;
			mpath->exp_time = time_after(mpath->exp_time, exp_time)
					  ?  mpath->exp_time : exp_time;
			
			sta=sta_info_get(major_path->sdata,next_hop);				
			mesh_path_assign_nexthop(mpath, sta);

			//xf
            printk("preq major_path_orig=%pM,dst=%pM,assign_next_hop=%pM\n",mpath->orig,mpath->dst,next_hop);
			mesh_path_activate(mpath);
			spin_unlock_bh(&mpath->state_lock);
			//mesh_path_tx_pending(mpath);

		
        ifmsh= &(major_path->sdata)->u.mesh;
		ttl = ifmsh->mshcfg.element_ttl;    //这里只回了一个 如果没有问题 再写第二个
		if (ttl != 0) {
				   mhwmp_dbg(major_path->sdata, "replying to the PREQ\n");

				   mesh_path_sel_frame_tx(MPATH_PREP,IEEE80211_PREP_MAJORPATH, node->originater_address,
						       major_path->orig_sn, 0, major_path->sdata->vif.addr,
						       ifmsh->sn,next_hop, 0, ttl,
						       major_path->lifetime, major_path->metric, 0, major_path->path_list
						       ,(major_path->node_cnt-1)*ETH_ALEN +31, major_path->sdata);

		} else {
				ifmsh->mshstats.dropped_frames_ttl++;
		}
       }
		//kfree(major_path);
	}


    if(minor_path){
		//xf
		//printk("minor_path_has\n");

        mpath = mesh_minor_path_lookup(minor_path->sdata, node->originater_address,minor_path->sdata->vif.addr);
        if(!mpath){
          mpath = mesh_path_add(minor_path->sdata, MESH_PATHS_BACKUP,node->originater_address,minor_path->sdata->vif.addr);
          if (IS_ERR(mpath)) {
				return ;
		   }
		}
        
		if(mpath){
			
			if(mpath->flags & MESH_PATH_FIXED){
                return ;
			}

			spin_lock_bh(&mpath->state_lock);

			if(minor_path->node_cnt>1){
				 next_hop=minor_path->path_list+((minor_path->node_cnt-2)*ETH_ALEN);
			}else{
                 next_hop=node->originater_address;
			}

			//xf
            printk("preq minor_path_orig=%pM,dst=%pM,assign_next_hop=%pM\n",mpath->orig,mpath->dst,next_hop);
            exp_time = TU_TO_EXP_TIME(minor_path->lifetime);
			
			mpath->flags |= MESH_PATH_SN_VALID;
			mpath->metric = minor_path->metric;
			mpath->sn = minor_path->orig_sn;
			mpath->exp_time = time_after(mpath->exp_time, exp_time)
					  ?  mpath->exp_time : exp_time;
			
			sta=sta_info_get(minor_path->sdata,next_hop);				
			mesh_path_assign_nexthop(mpath, sta);
			mesh_path_activate(mpath);
			spin_unlock_bh(&mpath->state_lock);
			//mesh_path_tx_pending(mpath);
				   

		
        ifmsh= &(minor_path->sdata)->u.mesh;
		ttl = ifmsh->mshcfg.element_ttl;    //这里只回了一个 如果没有问题 再写第二个
		
		if (ttl != 0) {
				   mhwmp_dbg(minor_path->sdata, "replying to the PREQ\n");

				   
				   mesh_path_sel_frame_tx(MPATH_PREP,IEEE80211_PREP_MINORPATH, node->originater_address,
						       minor_path->orig_sn, 0, minor_path->sdata->vif.addr,
						       ifmsh->sn,next_hop, 0, ttl,
						       minor_path->lifetime, minor_path->metric, 0, minor_path->path_list
						       ,(minor_path->node_cnt-1)*ETH_ALEN +31, minor_path->sdata);
			

		} else {
				ifmsh->mshstats.dropped_frames_ttl++;
		 }
		}
     }
    spin_unlock_bh(&node->lock);
}

void preq_state_machine_clean_timer(unsigned long data)   //timer  锁 并发 很重要 
{
	//u8 i;
    //u8 hash_num;
    //struct mesh_preq_mid_list_hash_node *hash_node;
    //struct mesh_preq_mid_list_hash_node *each_node, *next_node;
    struct mesh_preq_state_machine * node=(void *)data;
    spin_lock_bh(&node->lock);

    node->flags &= ~MESH_RECEIVE_PREQ_TIMEOUT;
    node->flags &= ~MESH_NOT_FIRST_RECEIVE_PREQ;
    /*node->metric_minor=0xffffffff;
    node->metric_major=0xffffffff;
    new_node->minor_node_cnt=0;
    new_node->major_node_cnt=0;*/
  
   //首先要清0  这里就把flags 改为0  还要释放连接上去的节点 ???
    major_path_hash_table_free(node);
    path_info_list_free(node);

    spin_unlock_bh(&node->lock);
}



inline struct sta_info *
next_hop_deref_protected(struct mesh_path *mpath)
{
	return rcu_dereference_protected(mpath->next_hop,
					 lockdep_is_held(&mpath->state_lock));
}


static void hwmp_prep_frame_process(struct ieee80211_sub_if_data *sdata,
				    struct ieee80211_mgmt *mgmt,
				    const u8 *prep_elem, u32 metric) // 发送之前要删除地址列表中的最后一个地址 lengh变
{
	struct ieee80211_if_mesh *ifmsh = &sdata->u.mesh;
	struct mesh_path *mpath;
	const u8 *target_addr, *orig_addr;
	u8 ttl, hopcount, flags;
	u8 next_hop[ETH_ALEN];
	u32 target_sn, orig_sn, lifetime;
	u8 ie_len;


	const u8 * mid_address_list;

	mhwmp_dbg(sdata, "received PREP from %pM\n",
		  PREP_IE_TARGET_ADDR(prep_elem));

	

	orig_addr = PREP_IE_ORIG_ADDR(prep_elem);
	target_addr = PREP_IE_TARGET_ADDR(prep_elem);
	if (ether_addr_equal(orig_addr, sdata->vif.addr))
		/* destination, no forwarding required */
		return;

	if (!ifmsh->mshcfg.dot11MeshForwarding)////
		return;

	ttl = PREP_IE_TTL(prep_elem);
	if (ttl <= 1) {
		sdata->u.mesh.mshstats.dropped_frames_ttl++;
		return;
	}

	rcu_read_lock();
	mpath = mesh_path_lookup(sdata, orig_addr,target_addr);
	if (mpath)
		spin_lock_bh(&mpath->state_lock);
	else
		goto fail;
	if (!(mpath->flags & MESH_PATH_ACTIVE)) {
		spin_unlock_bh(&mpath->state_lock);
		goto fail;
	}
	memcpy(next_hop, next_hop_deref_protected(mpath)->sta.addr, ETH_ALEN);//
	spin_unlock_bh(&mpath->state_lock);
	--ttl;
	flags = PREP_IE_FLAGS(prep_elem);
	lifetime = PREP_IE_LIFETIME(prep_elem);
	hopcount = PREP_IE_HOPCOUNT(prep_elem) + 1;
	target_sn = PREP_IE_TARGET_SN(prep_elem);
	orig_sn = PREP_IE_ORIG_SN(prep_elem);

    if(PREP_IE_LENGTH(prep_elem)>ETH_ALEN){
	    ie_len=PREP_IE_LENGTH(prep_elem)-ETH_ALEN; //这里只能改变length
    }else{
        ie_len=31;
	}
	//xf
	//printk("prep_ie_len=%u\n",ie_len);
	mid_address_list=PREP_IE_MID_ADDRESS(prep_elem);//
		
    printk("send prep to %pM\n",orig_addr);	
	mesh_path_sel_frame_tx(MPATH_PREP, flags, orig_addr, orig_sn, 0,
			       target_addr, target_sn, next_hop, hopcount,
			       ttl, lifetime, metric, 0, mid_address_list,ie_len,sdata);
	rcu_read_unlock();

	sdata->u.mesh.mshstats.fwded_unicast++;
	sdata->u.mesh.mshstats.fwded_frames++;
	return;

fail:
	rcu_read_unlock();
	sdata->u.mesh.mshstats.dropped_frames_no_route++;
}

static void hwmp_perr_frame_process(struct ieee80211_sub_if_data *sdata,
				    struct ieee80211_mgmt *mgmt,
				    const u8 *perr_elem)
{
	struct ieee80211_if_mesh *ifmsh = &sdata->u.mesh;
	struct mesh_path *mpath, *orig_path;
	u8 ttl, flag;
	const u8 *ta, *target_addr, *orig_addr,* invalid_addr;
	u32 target_sn;
	u16 target_rcode;
	u8 next_hop[ETH_ALEN];

	ta = mgmt->sa;
	ttl = PERR_IE_TTL(perr_elem);
	if (ttl <= 1) {
		ifmsh->mshstats.dropped_frames_ttl++;
		return;
	}
	ttl--;
	target_addr = PERR_IE_TARGET_ADDR(perr_elem);
	target_sn = PERR_IE_TARGET_SN(perr_elem);
	target_rcode = PERR_IE_TARGET_RCODE(perr_elem);
	orig_addr=PERR_IE_ORIG_ADDR(perr_elem);//这里的源地址就是路径的源地址
	invalid_addr=PERR_IE_INVALID_ADDR(perr_elem);
	flag=PERR_IE_TARGET_FLAGS(perr_elem);

    //xf
    printk("invalid_addr=%pM\n",invalid_addr);
	printk("perror target sn=%u\n",target_sn);

	rcu_read_lock();//±ê×¼ÅäÖÃ

	if(target_sn ==0 && ether_addr_equal(orig_addr,sdata->vif.addr)){
	  printk("destination receive perr sn=0 from %pM to %pM\n",orig_addr,target_addr);

	       mpath = mesh_path_lookup(sdata,target_addr,orig_addr);
           if(mpath && !(mpath->flags & MESH_PATH_RESOLVING)){
		   	//xf
		   	printk("receive perr sn=0 start queue preq\n");
             mesh_queue_preq(mpath,PREQ_Q_F_START);
	       }
		
	}else{
	 if(flag & MP_F_MAJOR){//这里同样只处理了主路劲
		printk("receive perr major path from %pM to %pM\n", orig_addr,target_addr);
		
	    mpath = mesh_major_path_lookup(sdata,target_addr,orig_addr);
		
	    if (mpath ) {
		struct sta_info *sta;
		spin_lock_bh(&mpath->state_lock);
		sta = next_hop_deref_protected(mpath);//
		//xf
		printk("mpath_major_sn=%u\n",mpath->sn);
		if (sta && mpath->flags & MESH_PATH_ACTIVE &&
		    ether_addr_equal(ta, sta->sta.addr) &&//
		    (!(mpath->flags & MESH_PATH_SN_VALID) ||
		    SN_GT(target_sn, mpath->sn))) {

			if(target_sn >0){
			    mpath->flags &= ~MESH_PATH_ACTIVE;//²»É¾³ý Ö»ÊÇÉèÖÃÎª·Çactive Ö»ÊÇÔÚexpireÖÐÉ¾³ýÃ»ÓÐÊ¹ÓÃµÄÂ·¾¶
		    }
			
			mpath->sn = target_sn;
			spin_unlock_bh(&mpath->state_lock);

			
			if (!ifmsh->mshcfg.dot11MeshForwarding)
				goto endperr;
			  if (!ether_addr_equal(orig_addr,sdata->vif.addr)){
				
			    orig_path=mesh_major_path_lookup(sdata,orig_addr ,target_addr);
				if(orig_path)
				{
				   spin_lock_bh(&orig_path->state_lock);
				}
                if(orig_path && (orig_path->flags & MESH_PATH_ACTIVE) &&
				    next_hop_deref_protected(orig_path)){
				
			        memcpy(next_hop,next_hop_deref_protected(orig_path)->sta.addr,ETH_ALEN);
			    
                    //xf
                    printk("send major path error from %pM to %pM \n",orig_addr,target_addr);
     			    mesh_path_error_tx(sdata, ttl, target_addr,
					   target_sn, target_rcode, next_hop ,
					  orig_addr,invalid_addr,MP_F_MAJOR);
                }
				if(orig_path)
				{
				   spin_unlock_bh(&orig_path->state_lock);
				}
			}else{//对于源节点
               mpath=mesh_minor_path_lookup(sdata,target_addr,orig_addr);
			   if(mpath)
			   {
			      spin_lock_bh(&mpath->state_lock);
			   }
			   if(mpath && mpath->flags & MESH_PATH_ACTIVE)
				   goto endperr;
			   else if(!(mpath->flags & MESH_PATH_RESOLVING)){
				   mesh_queue_preq(mpath,PREQ_Q_F_START);
			   }
			   if(mpath)
			   {
			      spin_unlock_bh(&mpath->state_lock);
			   }
			}
		}
		else
			spin_unlock_bh(&mpath->state_lock);
	   }
	 }

	   else if(flag & MP_F_MINOR){
        printk("receive perr minor path from %pM to %pM",orig_addr,target_addr);
		
	    mpath = mesh_minor_path_lookup(sdata,target_addr,orig_addr);
		
	    if (mpath ) {
		struct sta_info *sta;
		spin_lock_bh(&mpath->state_lock);
		//xf
		printk("mpath_minor_sn=%u\n",mpath->sn);
		sta = next_hop_deref_protected(mpath);
		if (sta && mpath->flags & MESH_PATH_ACTIVE &&
		    ether_addr_equal(ta, sta->sta.addr) &&//
		    (!(mpath->flags & MESH_PATH_SN_VALID) ||
		    SN_GT(target_sn, mpath->sn))) {

			if(target_sn >0){
			    mpath->flags &= ~MESH_PATH_ACTIVE;//²»É¾³ý Ö»ÊÇÉèÖÃÎª·Çactive Ö»ÊÇÔÚexpireÖÐÉ¾³ýÃ»ÓÐÊ¹ÓÃµÄÂ·¾¶
		    }
			
			mpath->sn = target_sn;
			spin_unlock_bh(&mpath->state_lock);

			
			if (!ifmsh->mshcfg.dot11MeshForwarding)
				goto endperr;
			  if (!ether_addr_equal(orig_addr,sdata->vif.addr)){
				
			    orig_path=mesh_minor_path_lookup(sdata,orig_addr ,target_addr);
				if(orig_path)
				{
				   spin_lock_bh(&orig_path->state_lock);
				}
                if(orig_path && (orig_path->flags & MESH_PATH_ACTIVE) &&
				    next_hop_deref_protected(orig_path)){
				
			        memcpy(next_hop,next_hop_deref_protected(orig_path)->sta.addr,ETH_ALEN);
			    
                    //xf
                    printk("send minor path error from %pM to %pM \n",orig_addr,target_addr);
     			    mesh_path_error_tx(sdata, ttl, target_addr,
					   target_sn, target_rcode, next_hop ,
					  orig_addr,invalid_addr,MP_F_MINOR);
                }  
				if(orig_path)
				{
				   spin_unlock_bh(&orig_path->state_lock);
				}
			}else{//对于源节点
               mpath=mesh_major_path_lookup(sdata,target_addr,orig_addr);
			   if(mpath)
			   {
			      spin_lock_bh(&mpath->state_lock);
			   }
			   if(mpath && mpath->flags & MESH_PATH_ACTIVE)
				   goto endperr;
			   else if(!(mpath->flags & MESH_PATH_RESOLVING)){
				   mesh_queue_preq(mpath,PREQ_Q_F_START);
			   }
			   if(mpath)
			   {
			      spin_unlock_bh(&mpath->state_lock);
			   }
			}
		}
		else
			spin_unlock_bh(&mpath->state_lock);
	   }
         

	  }
	}
endperr:
	rcu_read_unlock();
}

static void hwmp_rann_frame_process(struct ieee80211_sub_if_data *sdata,
				    struct ieee80211_mgmt *mgmt,
				    const struct ieee80211_rann_ie *rann)
{
	/*struct ieee80211_if_mesh *ifmsh = &sdata->u.mesh;
	struct ieee80211_local *local = sdata->local;
	struct sta_info *sta;
	struct mesh_path *mpath;
	u8 ttl, flags, hopcount;
	const u8 *orig_addr;
	u32 orig_sn, metric, metric_txsta, interval;
	bool root_is_gate;

	ttl = rann->rann_ttl;
	flags = rann->rann_flags;
	root_is_gate = !!(flags & RANN_FLAG_IS_GATE);
	orig_addr = rann->rann_addr;
	orig_sn = le32_to_cpu(rann->rann_seq);
	interval = le32_to_cpu(rann->rann_interval);
	hopcount = rann->rann_hopcount;
	hopcount++;
	metric = le32_to_cpu(rann->rann_metric);

	
	if (ether_addr_equal(orig_addr, sdata->vif.addr))
		return;

	mhwmp_dbg(sdata,
		  "received RANN from %pM via neighbour %pM (is_gate=%d)\n",
		  orig_addr, mgmt->sa, root_is_gate);

	rcu_read_lock();
	sta = sta_info_get(sdata, mgmt->sa);
	if (!sta) {
		rcu_read_unlock();
		return;
	}

	metric_txsta = airtime_link_metric_get(local, sta);

	mpath = mesh_path_lookup(sdata, orig_addr);
	if (!mpath) {
		mpath = mesh_path_add(sdata, orig_addr);
		if (IS_ERR(mpath)) {
			rcu_read_unlock();
			sdata->u.mesh.mshstats.dropped_frames_no_route++;
			return;
		}
	}

	if (!(SN_LT(mpath->sn, orig_sn)) &&
	    !(mpath->sn == orig_sn && metric < mpath->rann_metric)) {
		rcu_read_unlock();
		return;
	}

	if ((!(mpath->flags & (MESH_PATH_ACTIVE | MESH_PATH_RESOLVING)) ||
	     (time_after(jiffies, mpath->last_preq_to_root +
				  root_path_confirmation_jiffies(sdata)) ||
	     time_before(jiffies, mpath->last_preq_to_root))) &&
	     !(mpath->flags & MESH_PATH_FIXED) && (ttl != 0)) {
		mhwmp_dbg(sdata,
			  "time to refresh root mpath %pM\n",
			  orig_addr);
		mesh_queue_preq(mpath, PREQ_Q_F_START | PREQ_Q_F_REFRESH);
		mpath->last_preq_to_root = jiffies;
	}

	mpath->sn = orig_sn;
	mpath->rann_metric = metric + metric_txsta;
	mpath->is_root = true;

	memcpy(mpath->rann_snd_addr, mgmt->sa, ETH_ALEN);

	if (root_is_gate)
		mesh_path_add_gate(mpath);

	if (ttl <= 1) {
		ifmsh->mshstats.dropped_frames_ttl++;
		rcu_read_unlock();
		return;
	}
	ttl--;

	if (ifmsh->mshcfg.dot11MeshForwarding) {//å?å?å?å?
		mesh_path_sel_frame_tx(MPATH_RANN, flags, orig_addr,
				       orig_sn, 0, NULL, 0, broadcast_addr,
				       hopcount, ttl, interval,
				       metric + metric_txsta, 0, sdata);
	}

	rcu_read_unlock();*/
}


void mesh_rx_path_sel_frame(struct ieee80211_sub_if_data *sdata,
			    struct ieee80211_mgmt *mgmt, size_t len)
{
	struct ieee802_11_elems elems;
	size_t baselen;
	u32 last_hop_metric;
	struct sta_info *sta;

	/* need action_code */
	if (len < IEEE80211_MIN_ACTION_SIZE + 1)
		return;

	rcu_read_lock();
	sta = sta_info_get(sdata, mgmt->sa);
	if (!sta || sta->plink_state != NL80211_PLINK_ESTAB) {
		rcu_read_unlock();
		return;
	}
	rcu_read_unlock();

	baselen = (u8 *) mgmt->u.action.u.mesh_action.variable - (u8 *) mgmt;
	ieee802_11_parse_elems(mgmt->u.action.u.mesh_action.variable,
			       len - baselen, false, &elems);

	if (elems.preq) {
		//if (elems.preq_len != 37)
			/* Right now we support just 1 destination and no AE */
			//return;


		last_hop_metric = hwmp_route_info_get(sdata, mgmt, elems.preq,
						      MPATH_PREQ);
		if (last_hop_metric){
			//xf
			//printk("last_hop_metric_preq=%u\n",last_hop_metric);
			hwmp_preq_frame_process(sdata, mgmt, elems.preq, //
						last_hop_metric);
		   }

	}
	if (elems.prep) {
		//if (elems.prep_len != 31)
			/* Right now we support no AE */
			//return;
		last_hop_metric = hwmp_route_info_get(sdata, mgmt, elems.prep,
						      MPATH_PREP);
		if (last_hop_metric){
			//xf
			//printk("last_hop_metric_prep=%u\n",last_hop_metric);
			hwmp_prep_frame_process(sdata, mgmt, elems.prep,
						last_hop_metric);
			}
	}
	if (elems.perr) {
		//if (elems.perr_len != 15)
			/* Right now we support only one destination per PERR */
			//return;
		 hwmp_perr_frame_process(sdata, mgmt, elems.perr);
	}
//	if (elems.rann)
		
		//hwmp_rann_frame_process(sdata, mgmt, elems.rann);
}

/**
 * mesh_queue_preq - queue a PREQ to a given destination
 *
 * @mpath: mesh path to discover
 * @flags: special attributes of the PREQ to be sent
 *
 * Locking: the function must be called from within a rcu read lock block.
 *
 */
static void mesh_queue_preq(struct mesh_path *mpath, u8 flags)
{
	struct ieee80211_sub_if_data *sdata = mpath->sdata;
	struct ieee80211_if_mesh *ifmsh = &sdata->u.mesh;
	struct mesh_preq_queue *preq_node;

	preq_node = kmalloc(sizeof(struct mesh_preq_queue), GFP_ATOMIC);
	if (!preq_node) {
		mhwmp_dbg(sdata, "could not allocate PREQ node\n");
		return;
	}

	spin_lock_bh(&ifmsh->mesh_preq_queue_lock);
	if (ifmsh->preq_queue_len == MAX_PREQ_QUEUE_LEN) {//Â·¾¶ÉÏ³¤¶È×î´óºóÊÍ·Å
		spin_unlock_bh(&ifmsh->mesh_preq_queue_lock);
		kfree(preq_node);
		if (printk_ratelimit())
			mhwmp_dbg(sdata, "PREQ node queue full\n");
		return;
	}

	spin_lock(&mpath->state_lock);
	if (mpath->flags & MESH_PATH_REQ_QUEUED) {//Â·¾¶ÉÏÒÑ¾­ÓÐÁËreq ·µ»Ø
		spin_unlock(&mpath->state_lock);
		spin_unlock_bh(&ifmsh->mesh_preq_queue_lock);
		kfree(preq_node);
		return;
	}

	memcpy(preq_node->dst, mpath->dst, ETH_ALEN);
	preq_node->flags = flags;

	mpath->flags |= MESH_PATH_REQ_QUEUED;
	spin_unlock(&mpath->state_lock);

	list_add_tail(&preq_node->list, &ifmsh->preq_queue.list);
	//Ìí¼Óµ½Á´±í
	++ifmsh->preq_queue_len;
	spin_unlock_bh(&ifmsh->mesh_preq_queue_lock);

	if (time_after(jiffies, ifmsh->last_preq + min_preq_int_jiff(sdata)))
		ieee80211_queue_work(&sdata->local->hw, &sdata->work);
	//ÕæÕý¿ªÊ¼¹¤×÷ 

	else if (time_before(jiffies, ifmsh->last_preq)) {
		/* avoid long wait if did not send pr]eqs for a long time
		 * and jiffies wrapped around
		 */
		ifmsh->last_preq = jiffies - min_preq_int_jiff(sdata) - 1;
		ieee80211_queue_work(&sdata->local->hw, &sdata->work);
	} else
		mod_timer(&ifmsh->mesh_path_timer, ifmsh->last_preq +
						min_preq_int_jiff(sdata)); 
	//µÈÒ»¶ÎÊ±¼äºóµ÷ÓÃieee80211_queue_work Ìí¼Ó½ø¹¤×÷
}

/**
 * mesh_path_start_discovery - launch a path discovery from the PREQ queue
 *
 * @sdata: local mesh subif
 */
void mesh_path_start_discovery(struct ieee80211_sub_if_data *sdata)
{
	struct ieee80211_if_mesh *ifmsh = &sdata->u.mesh;
	struct mesh_preq_queue *preq_node;
	struct mesh_path *mpath;
	u8 ttl, target_flags;
	const u8 *da;
	u32 lifetime;

	spin_lock_bh(&ifmsh->mesh_preq_queue_lock);
	if (!ifmsh->preq_queue_len ||
		time_before(jiffies, ifmsh->last_preq +
				min_preq_int_jiff(sdata))) {  // ·¢ËÍprepµÄ×îÐ¡¼ä¸ôÊ±¼ä
		spin_unlock_bh(&ifmsh->mesh_preq_queue_lock);
		return;
	}

	preq_node = list_first_entry(&ifmsh->preq_queue.list,
			struct mesh_preq_queue, list);
	list_del(&preq_node->list);
	--ifmsh->preq_queue_len;
	spin_unlock_bh(&ifmsh->mesh_preq_queue_lock);

	rcu_read_lock();
	mpath = mesh_path_lookup(sdata, preq_node->dst,sdata->vif.addr);
	if (!mpath)
		goto enddiscovery;

	spin_lock_bh(&mpath->state_lock);
	mpath->flags &= ~MESH_PATH_REQ_QUEUED;
	if (preq_node->flags & PREQ_Q_F_START) {
		if (mpath->flags & MESH_PATH_RESOLVING) {
	//Òì³£Çé¿ö
			spin_unlock_bh(&mpath->state_lock);
			goto enddiscovery;
		} else {//Õý³£µÄ
			mpath->flags &= ~MESH_PATH_RESOLVED;
			mpath->flags |= MESH_PATH_RESOLVING;
			mpath->discovery_retries = 0;
			mpath->discovery_timeout = disc_timeout_jiff(sdata);
		}
	} else if (!(mpath->flags & MESH_PATH_RESOLVING) ||  
	//Õë¶ÔÖØ·¢µÄpreqÖ¡Ê±µÄÒì³£Çé¿ö
		mpath->flags & MESH_PATH_RESOLVED) {
		mpath->flags &= ~MESH_PATH_RESOLVING;
		spin_unlock_bh(&mpath->state_lock);
		goto enddiscovery;
	}

	ifmsh->last_preq = jiffies;

	if (time_after(jiffies, ifmsh->last_sn_update +
				net_traversal_jiffies(sdata)) ||
	    time_before(jiffies, ifmsh->last_sn_update)) { //Õë¶ÔµÄsnµÄ¸üÐÂ Èç¹ûÃ»ÓÐµ½ ¾Í²»¸üÐÂ
		++ifmsh->sn;
		sdata->u.mesh.last_sn_update = jiffies;
	}
	lifetime = default_lifetime(sdata);
	ttl = sdata->u.mesh.mshcfg.element_ttl;
	if (ttl == 0) {
		sdata->u.mesh.mshstats.dropped_frames_ttl++;
		spin_unlock_bh(&mpath->state_lock);
		goto enddiscovery;
	}

	if (preq_node->flags & PREQ_Q_F_REFRESH)//¿ØÖÆdo»¹ÊÇrf
		target_flags = MP_F_DO;
	else
		target_flags = MP_F_RF;

	spin_unlock_bh(&mpath->state_lock);
	da = (mpath->is_root) ? mpath->rann_snd_addr : broadcast_addr;//¹ã²¥
	mesh_path_sel_frame_tx(MPATH_PREQ, 0, sdata->vif.addr, ifmsh->sn,
			       target_flags, mpath->dst, mpath->sn, da, 0,
			       ttl, lifetime, 0, ifmsh->preq_id++,NULL,37,sdata);
	mod_timer(&mpath->timer, jiffies + mpath->discovery_timeout);
    //ÐÞ¸ÄÂ·¾¶·¢ÏÖ³¬Ê±µÄÖµ 
enddiscovery:
	rcu_read_unlock();
	kfree(preq_node);
}

/**
 * mesh_nexthop_resolve - lookup next hop; conditionally start path discovery
 *
 * @skb: 802.11 frame to be sent
 * @sdata: network subif the frame will be sent through
 *
 * Lookup next hop for given skb and start path discovery if no
 * forwarding information is found.
 *
 * Returns: 0 if the next hop was found and -ENOENT if the frame was queued.
 * skb is freeed here if no mpath could be allocated.
 */
int mesh_nexthop_resolve(struct ieee80211_sub_if_data *sdata,
			 struct sk_buff *skb)
{
	struct ieee80211_hdr *hdr = (struct ieee80211_hdr *) skb->data;
	struct ieee80211_tx_info *info = IEEE80211_SKB_CB(skb);
	struct mesh_path *mpath, *mpath_backup;
	struct sk_buff *skb_to_free = NULL;
	u8 *target_addr = hdr->addr3;
	int err = 0;

	/* Nulls are only sent to peers for PS and should be pre-addressed */
	if (ieee80211_is_qos_nullfunc(hdr->frame_control))
		return 0;

	rcu_read_lock();
	err = mesh_nexthop_lookup(sdata, skb);
	if (!err)
		goto endlookup;


    /*err=mesh_root_lookup(sdata,skb);
    if (!err)//找到root的路径后 nexthop的信息已经添加到数据中 退出查找
		goto endlookup;*/


	/* no nexthop found, start resolving */
	mpath = mesh_path_lookup(sdata, target_addr,sdata->vif.addr);
	if (!mpath) {

     //ÔÚÕâÀïÌí¼ÓÈç¹ûÓÐroot °ÑÊý¾ÝÏòroot		
		mpath = mesh_path_add(sdata, MESH_PATHS,target_addr,sdata->vif.addr);
		if (IS_ERR(mpath)) {
			mesh_path_discard_frame(sdata, skb);
			err = PTR_ERR(mpath);
			goto endlookup;
		}
		mpath_backup= mesh_path_add(sdata, MESH_PATHS_BACKUP,target_addr,sdata->vif.addr);
		if (IS_ERR(mpath)) {
			err = PTR_ERR(mpath);
			goto endlookup;
		}

	}


	if (!(mpath->flags & MESH_PATH_RESOLVING)){
		//Ã»ÓÐÕÒµ½ Ìí¼Ópreqµ½Â·¾¶µÄ¶ÓÁÐÉÏ
		mesh_queue_preq(mpath, PREQ_Q_F_START);
		//printk("start discovery queue preq\n");
	}
	if (skb_queue_len(&mpath->frame_queue) >= MESH_FRAME_QUEUE_LEN)
		skb_to_free = skb_dequeue(&mpath->frame_queue);

	info->flags |= IEEE80211_TX_INTFL_NEED_TXPROCESSING;
	ieee80211_set_qos_hdr(sdata, skb);
	skb_queue_tail(&mpath->frame_queue, skb);
	err = -ENOENT;
	if (skb_to_free)		
		mesh_path_discard_frame(sdata, skb_to_free);

endlookup:
	rcu_read_unlock();
	return err;
}

/**
 * mesh_nexthop_lookup - put the appropriate next hop on a mesh frame. Calling
 * this function is considered "using" the associated mpath, so preempt a path
 * refresh if this mpath expires soon.
 *
 * @skb: 802.11 frame to be sent
 * @sdata: network subif the frame will be sent through
 *
 * Returns: 0 if the next hop was found. Nonzero otherwise.
 */
int mesh_nexthop_lookup(struct ieee80211_sub_if_data *sdata,
			struct sk_buff *skb)
{
	struct mesh_path *mpath;
	struct sta_info *next_hop;
	struct ieee80211_hdr *hdr = (struct ieee80211_hdr *) skb->data;
	u8 *target_addr = hdr->addr3;
	u8 *orig_addr=hdr->addr4;
	int err = -ENOENT;

	rcu_read_lock();
	mpath = mesh_major_path_lookup(sdata, target_addr,orig_addr);

	if (!mpath || !(mpath->flags & MESH_PATH_ACTIVE))
	{
	   mpath=mesh_minor_path_lookup(sdata, target_addr,orig_addr);
	}

	if (!mpath || !(mpath->flags & MESH_PATH_ACTIVE))
	{
	    goto endlookup;
	}

	if (time_after(jiffies,
		       mpath->exp_time -
		       msecs_to_jiffies(sdata->u.mesh.mshcfg.path_refresh_time//1000ms
		       )) &&
	    ether_addr_equal(sdata->vif.addr, hdr->addr4) &&
	    !(mpath->flags & MESH_PATH_RESOLVING) &&
	    !(mpath->flags & MESH_PATH_FIXED))
	    ///¼´Ê¹ÕÒµ½Â·¾¶ Ò²»á°Ñpreq·ÅÈë¶ÓÁÐ
		mesh_queue_preq(mpath, PREQ_Q_F_START | PREQ_Q_F_REFRESH);

	next_hop = rcu_dereference(mpath->next_hop);
	if (next_hop) {
		memcpy(hdr->addr1, next_hop->sta.addr, ETH_ALEN);
		memcpy(hdr->addr2, sdata->vif.addr, ETH_ALEN);
		ieee80211_mps_set_frame_flags(sdata, next_hop, hdr);
		err = 0;
	}

endlookup:
	rcu_read_unlock();
	return err;
}

void mesh_path_timer(unsigned long data)
{
	struct mesh_path *mpath = (void *) data;
	struct ieee80211_sub_if_data *sdata = mpath->sdata;
	int ret;

	if (sdata->local->quiescing) // Í£¶Ù
		return;

	spin_lock_bh(&mpath->state_lock);
	if (mpath->flags & MESH_PATH_RESOLVED || 
		//ÕâÊÇÕÒµ½Â·¾¶ºó¸Ä±êÖ¾Î»
			(!(mpath->flags & MESH_PATH_RESOLVING))) {
		mpath->flags &= ~(MESH_PATH_RESOLVING | MESH_PATH_RESOLVED);
		spin_unlock_bh(&mpath->state_lock);
	} else if (mpath->discovery_retries < max_preq_retries(sdata)) {
        //Ã»ÕÒµ½ ÖØÊÔ     
		++mpath->discovery_retries;
		mpath->discovery_timeout *= 2;
		mpath->flags &= ~MESH_PATH_REQ_QUEUED;
		spin_unlock_bh(&mpath->state_lock);
		mesh_queue_preq(mpath, 0);
	} else {
	   // ³¬¹ý×î´ó´ÎÊý
		mpath->flags = 0;
		mpath-> exp_time = jiffies;
		spin_unlock_bh(&mpath->state_lock);
		if (!mpath->is_gate && mesh_gate_num(sdata) > 0) {
			ret = mesh_path_send_to_gates(mpath);
			if (ret)
				mhwmp_dbg(sdata, "no gate was reachable\n");
		} else
			mesh_path_flush_pending(mpath);
	}
}

void mesh_path_tx_root_frame(struct ieee80211_sub_if_data *sdata)
{
	/*struct ieee80211_if_mesh *ifmsh = &sdata->u.mesh;
	u32 interval = ifmsh->mshcfg.dot11MeshHWMPRannInterval;
	u8 flags, target_flags = 0;

	flags = (ifmsh->mshcfg.dot11MeshGateAnnouncementProtocol)
			? RANN_FLAG_IS_GATE : 0; // flags ÔÚÕâÀïÓÃÉÏÁË

	switch (ifmsh->mshcfg.dot11MeshHWMPRootMode) {
		//ÕâÀïÓÐÈýÖÖ
	case IEEE80211_PROACTIVE_RANN:
		mesh_path_sel_frame_tx(MPATH_RANN, flags, sdata->vif.addr,
				       ++ifmsh->sn, 0, NULL, 0, broadcast_addr,
				       0, ifmsh->mshcfg.element_ttl,
				       interval, 0, 0, sdata);
		break;
	case IEEE80211_PROACTIVE_PREQ_WITH_PREP:
		flags |= IEEE80211_PREQ_PROACTIVE_PREP_FLAG;
		//Òª×¢ÒâÕâÀïÃ»ÓÐbreak
	case IEEE80211_PROACTIVE_PREQ_NO_PREP:
		interval = ifmsh->mshcfg.dot11MeshHWMPactivePathToRootTimeout;
		target_flags |= IEEE80211_PREQ_TO_FLAG |
				IEEE80211_PREQ_USN_FLAG;
		mesh_path_sel_frame_tx(MPATH_PREQ, flags, sdata->vif.addr,
				       ++ifmsh->sn, target_flags,
				       (u8 *) broadcast_addr, 0, broadcast_addr,
				       0, ifmsh->mshcfg.element_ttl, interval,
				       0, ifmsh->preq_id++, sdata);
		break;
	default:
		mhwmp_dbg(sdata, "Proactive mechanism not supported\n");
		return;
	}*/
}
