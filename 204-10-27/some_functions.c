
static struct mesh_table __rcu *mesh_paths;//主路由表
static struct mesh_table __rcu *mesh_paths_backup;//备份路由表
static struct mesh_preq_state_macchine_table  *preq_table[NODE_NUM];//目的节点接受preq的头结点

 #define des_req_clear_timeout 50 HZ
 #define des_req_wait_timeout  100 HZ
 #define  NODE_NUM  10


//static DEFINE_RWLOCK(preq_state_machine_list_lock);  //读写锁 用来锁住



struct  mesh_preq_state_macchine_table
{
  struct list_head list;
  spinlock_t  state_lock;		/* One per bucket, for add/del */
  
};

//struct  mesh_preq_mid_list_hash_node mesh_preq_mid_list_hash_tabel[NODE_NUM]; // 全局变量 用来hash preq
//动态分布

struct mesh_preq_mid_list_hash_node // 每个state_machine里面个指针指向一个hash  table
{
	u8 *node1_addr;
	u8 *node2_addr;
	struct list_head list;  //初始化
	int flag; // 判断是否存在  就算存在 也要循环链表 防止hash冲突
	//spinlock_t  lock;     //初始化
};


enum mesh_preq_state_machine_flags
{
	MESH_RECEIVE_PREQ_TIMEOUT=BIT(1),
	MESH_NOT_FIRST_RECEIVE_PREQ=BIT(2),
	IEEE80211_PREQ_MAJORPATH,
	IEEE80211_PREQ_MINORPATH,
};

struct path_info 
{
	struct list_head list_preq;
	u32 metric;
 	u8 * path_list;
	u8 node_cnt;

    u32 lifetime;//  
    u32 orig_sn;
    struct ieee80211_sub_if_data *sdata;
};


struct mesh_preq_state_machine
{
	u8 originater_address[ETH_LEN];
    
	struct  list_head list;
	struct list_head list_preq;
	struct timer_list des_req_timer;
	struct timer_list des_req_clear_timer;
	unsigned long des_req_timer_timeout_time;
    spinlock_t  lock;
    enum mesh_preq_state_machine_flags flags;
    struct mesh_preq_mid_list_hash_node* mesh_preq_mid_list_hash_tabel_major;
    //指向动态分配的用来判断链路不想交的hash表
    //这个在choose_major_path里面分配内存初始化 

    //struct mesh_preq_mid_list_hash_node* mesh_preq_mid_list_hash_tabel_minor;//在kmalloc的时候固定大小了
    
};  



static int mesh_path_sel_frame_tx(enum mpath_frame_type action, u8 flags,
				  const u8 *orig_addr, u32 orig_sn,
				  u8 target_flags, const u8 *target,
				  u32 target_sn, const u8 *da,
				  u8 hop_count, u8 ttl,
				  u32 lifetime, u32 metric, u32 preq_id,
		#ifdef mesh_route    u8 *path_address_list,  u8 ie_len,                   
				  struct ieee80211_sub_if_data *sdata) ;



enum mesh_table_choose {
	MESH_PATHS,
	MESH_PATHS_BACKUP,
	MPP_PATHS,
};


struct mesh_path *
mesh_path_lookup(struct ieee80211_sub_if_data *sdata, const u8 *dst, const u8* orig)
{
	struct mesh_path* temp=mpath_lookup(rcu_dereference(mesh_paths), dst, sdata,orig);
	if(temp)
		return temp
    else
    	return mpath_lookup(rcu_dereference(mesh_paths_backup), dst, sdata,orig); 
 
}

struct mesh_path *
mesh_major_path_lookup(struct ieee80211_sub_if_data *sdata, const u8 *dst, const u8* orig)
{
	return mpath_lookup(rcu_dereference(mesh_paths), dst, sdata,orig);
 
}

struct mesh_path *
mesh_minor_path_lookup(struct ieee80211_sub_if_data *sdata, const u8 *dst, const u8* orig)
{
   return mpath_lookup(rcu_dereference(mesh_paths_backup), dst, sdata,orig); 
}

static struct mesh_path *mpath_lookup(struct mesh_table *tbl, const u8 *dst,
				      struct ieee80211_sub_if_data *sdata,const u8* orig)
{
	struct mesh_path *mpath;
	struct hlist_head *bucket;
	struct mpath_node *node;

	bucket = &tbl->hash_buckets[mesh_table_hash(dst,orig, sdata, tbl)];
	hlist_for_each_entry_rcu(node, bucket, list) {
		mpath = node->mpath;
		if (mpath->sdata == sdata &&
		    ether_addr_equal(dst, mpath->dst)) {
			if (mpath_expired(mpath)) {
				spin_lock_bh(&mpath->state_lock);//获取锁之前禁止软中断  中断嵌套
				mpath->flags &= ~MESH_PATH_ACTIVE;
				spin_unlock_bh(&mpath->state_lock);
			}
			return mpath;
		}
	}
	return NULL;
}


static u32 mesh_table_hash(const u8 *addr, const u8 *orig,struct ieee80211_sub_if_data *sdata,
			   struct mesh_table *tbl)
{
	/* Use last four bytes of hw addr and interface index as hash index */
	return jhash_3words(*(u32 *)(addr+2), *(u32 *)(orig+2),sdata->dev->ifindex,
			    tbl->hash_rnd) & tbl->hash_mask;
}

static inline struct mesh_table *resize_dereference_mesh_paths_backup(void)
{
	return rcu_dereference_protected(mesh_paths_backup,
		lockdep_is_held(&pathtbl_resize_lock));
}



struct mesh_path *mesh_path_add(struct ieee80211_sub_if_data *sdata, enum mesh_table_choose flags,  //增加了选table 和源地址
				const u8 *dst,const u8 *orig)
{
	struct ieee80211_if_mesh *ifmsh = &sdata->u.mesh;
	struct ieee80211_local *local = sdata->local;
	struct mesh_table *tbl;
	struct mesh_path *mpath, *new_mpath;
	struct mpath_node *node, *new_node;
	struct hlist_head *bucket;
	int grow = 0;
	int err;
	u32 hash_idx;

	if (ether_addr_equal(dst, sdata->vif.addr))
		/* never add ourselves as neighbours */
		return ERR_PTR(-ENOTSUPP);

	if (is_multicast_ether_addr(dst))
		return ERR_PTR(-ENOTSUPP);

	if (atomic_add_unless(&sdata->u.mesh.mpaths, 1, MESH_MAX_MPATHS) == 0)
		return ERR_PTR(-ENOSPC);

	read_lock_bh(&pathtbl_resize_lock);

	switch (flags){
        case MESH_PATHS:
             tbl = resize_dereference_mesh_paths();
             break;
        case MESH_PATHS_BACKUP:
             tbl = resize_dereference_mesh_paths_backup();
             break;

		default:
		return ERR_PTR(-ENOSPC);
		break;
	}
	

	hash_idx = mesh_table_hash(dst,orig, sdata, tbl);
	bucket = &tbl->hash_buckets[hash_idx];

	spin_lock(&tbl->hashwlock[hash_idx]);

	hlist_for_each_entry(node, bucket, list) {
		mpath = node->mpath;
		if (mpath->sdata == sdata &&
		    ether_addr_equal(dst, mpath->dst))
			goto found;
	}

	err = -ENOMEM;
	new_mpath = kzalloc(sizeof(struct mesh_path), GFP_ATOMIC);
	if (!new_mpath)
		goto err_path_alloc;

	new_node = kmalloc(sizeof(struct mpath_node), GFP_ATOMIC);
	if (!new_node)
		goto err_node_alloc;

	memcpy(new_mpath->dst, dst, ETH_ALEN);
	memcpy(new_mpath->orig, orig, ETH_ALEN);//添加了源地址
	eth_broadcast_addr(new_mpath->rann_snd_addr);
	new_mpath->is_root = false;
	new_mpath->sdata = sdata;
	new_mpath->flags = 0;
	skb_queue_head_init(&new_mpath->frame_queue);
	new_node->mpath = new_mpath;
	new_mpath->timer.data = (unsigned long) new_mpath;
	new_mpath->timer.function = mesh_path_timer;
	new_mpath->exp_time = jiffies;
	spin_lock_init(&new_mpath->state_lock);
	init_timer(&new_mpath->timer);

	hlist_add_head_rcu(&new_node->list, bucket);
	if (atomic_inc_return(&tbl->entries) >=
	    tbl->mean_chain_len * (tbl->hash_mask + 1))
		grow = 1;

	mesh_paths_generation++;

	if (grow) {
		set_bit(MESH_WORK_GROW_MPATH_TABLE,  &ifmsh->wrkq_flags);
		ieee80211_queue_work(&local->hw, &sdata->work);
	}
	mpath = new_mpath;
found:
	spin_unlock(&tbl->hashwlock[hash_idx]);
	read_unlock_bh(&pathtbl_resize_lock);
	return mpath;

err_node_alloc:
	kfree(new_mpath);
err_path_alloc:
	atomic_dec(&sdata->u.mesh.mpaths);
	spin_unlock(&tbl->hashwlock[hash_idx]);
	read_unlock_bh(&pathtbl_resize_lock);
	return ERR_PTR(err);
}




int mesh_pathtbl_init(void)//新建了一个备份路由表 同时新建了目的节点处理preq时的list
{
	struct mesh_table *tbl_path, *tbl_mpp, *tb1_path_backup;
	struct mesh_preq_state_macchine_table *ls1;
	int ret,i;


    ls1=kzalloc(sizeof(struct mesh_preq_state_macchine_table)*NODE_NUM,GFP_ATOMIC);
    if (!ls1)
		return -ENOMEM;
	for(i=0;i<NODE_NUM;i++){
	spin_lock_init(&(ls1[i])->state_lock);
    LIST_HEAD(&(ls1[i])->list);//
    }




	tbl_path = mesh_table_alloc(INIT_PATHS_SIZE_ORDER);
	if (!tbl_path)
		return -ENOMEM;
	tbl_path->free_node = &mesh_path_node_free;
	tbl_path->copy_node = &mesh_path_node_copy;
	tbl_path->mean_chain_len = MEAN_CHAIN_LEN;
	tbl_path->known_gates = kzalloc(sizeof(struct hlist_head), GFP_ATOMIC);// memset 0
	if (!tbl_path->known_gates) {
		ret = -ENOMEM;
		goto free_path;
	}
	INIT_HLIST_HEAD(tbl_path->known_gates);

	tbl_path_backup= mesh_table_alloc(INIT_PATHS_SIZE_ORDER);
	if (!tbl_path_backup)
		return -ENOMEM;
	tbl_path_backup->free_node = &mesh_path_node_free;
	tbl_path_backup->copy_node = &mesh_path_node_copy;
	tbl_path_backup->mean_chain_len = MEAN_CHAIN_LEN;
	tbl_path_backup->known_gates = kzalloc(sizeof(struct hlist_head), GFP_ATOMIC);// memset 0
	if (!tbl_path_backup)->known_gates) {
		ret = -ENOMEM;
		goto free_path_backup;
	}
	INIT_HLIST_HEAD(tbl_path_backup->known_gates);


	tbl_mpp = mesh_table_alloc(INIT_PATHS_SIZE_ORDER);
	if (!tbl_mpp) {
		ret = -ENOMEM;
		goto free_path;
	}
	tbl_mpp->free_node = &mesh_path_node_free;
	tbl_mpp->copy_node = &mesh_path_node_copy;
	tbl_mpp->mean_chain_len = MEAN_CHAIN_LEN;
	tbl_mpp->known_gates = kzalloc(sizeof(struct hlist_head), GFP_ATOMIC);
	if (!tbl_mpp->known_gates) {
		ret = -ENOMEM;
		goto free_mpp;
	}
	INIT_HLIST_HEAD(tbl_mpp->known_gates);

	/* Need no locking since this is during init */
	RCU_INIT_POINTER(mesh_paths, tbl_path);
	RCU_INIT_POINTER(mpp_paths, tbl_mpp);
	RCU_INIT_POINTER(mesh_paths_backup, tbl_path_backup);
    RCU_INIT_POINTER(preq_table,ls1);


	return 0;

free_mpp:
	mesh_table_free(tbl_mpp, true);
free_path:
	mesh_table_free(tbl_path, true);
free_path:
    mesh_table_free(tb1_path_backup,true);
	return ret;

}
