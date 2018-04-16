#define cortexa8_L1_numOfWay			4
#define cortexa8_L1_waySize 			0x2000
#define cortexa8_L1_setnumber 			128
#define cortexa8_cache_line_size 		64
#define cortexa8_L2_setnumber 			512
#define cortexa8_L2_waySize 			0x8000
#define cortexa8_L2_numOfWay			8
#define aes_buffer_len					16
#define aes_iv_length					16
#define aes_table_memory_address 		0xcfe13780
#define aes_table_memory_set_offset 	(aes_table_memory_address - aes_table_memory_address%0x40)%0x8000
#define aes_table_len 					0x1000
#define aes_table_set_size 				aes_table_len / 0x40
#define l2_way_len 						0x8000
#define aes_t_table_entry_in_cacheset 	cortexa8_cache_line_size / 4
#define cortexA8_load_from_memory_time  180
#define cortexA8_load_from_l2_time  	90
#define v2_attack_vp_offset 			(aes_table_memory_address+0x1000) % 0x2000 + 0x100
#define channel_measure_space_len  		256*16*4 // 256 possibility for each of 16 key bytes with 4 bytes for each counter