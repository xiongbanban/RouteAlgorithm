
void  path_info_add (u8 * orig_addr,u8 ie_len,char * mid_address_list,u32 metric,u32 lifetime,
                                  u32 orig_sn, struct ieee80211_sub_if_data *sdata);


void path_info_list_free(u8 * orig_addr);

struct path_info * choose_major_path(orig_addr);

struct path_info * choose_minor_path(orig_addr);

bool link_disconnect(u8 * orig_addr, path_info * path_major,path_info * path_minor);
bool mesh_preq_mid_list_hash_tabel_has(u8 *orig_addr,u8 *node1_addr, u8 *node2_addr);
void mesh_preq_mid_list_hash_tabel_add(u8 *node1_addr, u8 *node2_addr
	                                  struct mesh_preq_state_machine * node);

void major_path_hash_table_free(u8 * orig_addr);

void generate_major_path_hash_table(u8 * orig_addr,char * mid_address_list_new, u8 count)



****************************************************************************************

static void  destination_node_preq_process(mesh_path *mpath, u8 * orig_addr, 
								u8 ie_len,char *mid_address_list,u32 metric,
								u32 orig_sn, struct ieee80211_sub_if_data *sdata);

u8 mesh_preq_state_machine_hash(const u8 * orig_addr);

u8 mesh_preq_mid_list_hash(u8 *node1_addr, u8 *node2_addr);// 各取最后一个字节 加起来 做hash

void mesh_preq_mid_list_hash_tabel_add(u8 *node1_addr, u8 *node2_addr
	                                  struct mesh_preq_state_machine * node,u8 kind);

bool mesh_preq_mid_list_hash_tabel_has(u8 *node1_addr, u8 *node2_addr,u8 kind);//通过地址列表中的两个地址判断

void mesh_preq_mid_list_hash_tabel_replace(char * mid_address_list_new, u8 count,u8 kind);

bool link_disconnect(u8 * orig_addr,u8 count,char *mid_address_list,u8 kind);//hash

bool link_disconnect(u8 * orig_addr,u8 ie_len,char *mid_address_list,u8 kind);//真的要一个个比较？

bool node_disconnect(u8 * orig_addr,u8 ie_len,char *mid_address_list,u8 kind);

void change_preq_state_machine_major_info(u8 * orig_addr,u8 ie_len,char *mid_address_list,u32 metric,u32 lifetime,
	                       u32 orig_sn, struct ieee80211_sub_if_data *sdata);

void change_preq_state_machine_minor_info(u8 * orig_addr,u8 ie_len,char *mid_address_list,u32 metric,
                          struct ieee80211_sub_if_data *sdata);


struct mesh_preq_state_machine * mesh_get_preq_state_machine_from_hashtable(u8 * orig_addr);

void preq_state_machine_add(u8 * orig_addr,u8 ie_len,char * mid_address_list,u32 metric,u32 lifetime,
                                  u32 orig_sn, struct ieee80211_sub_if_data *sdata); // 在init table中建立一个全局的指针 指向链表的头结点 
										//这里就在链表上添加一个节点  这里还没办法知道路径列表的大小？？ 加锁？

void preq_state_machine_timer(unsigned long data);   //timer  锁 并发 很重要 

void preq_state_machine_clean_timer(unsigned long data);   