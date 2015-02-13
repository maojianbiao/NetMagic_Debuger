/*
 ============================================================================
 Name        : xiong_debuger.c
 Author      : Frank
 Version     :
 Copyright   : Fucking bug
 Description : Hello World in C, Ansi-style
 ============================================================================
 */

#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <libnet.h>
#include <pthread.h>
#include <sys/types.h>
#pragma pack(push)
#pragma pack(1)
struct Nmac_Header{
	u_int8_t count;
	u_int8_t reserve8_A;
	u_int16_t seq;
	u_int16_t reserve16_B;
 	u_int8_t nmac_type;
	u_int16_t parameter;
	u_int8_t reserve8_C;
};
#pragma pack(pop)
void Parsing_Callback(u_char *useless, const struct pcap_pkthdr* pkthdr,const u_char* packet);
void Send_Write_Data();
void Send_Read_Data();
int hextodec(char x);
void shell();
void nmac_connect();


pcap_t *pcap_handle;
int nmac_connected_flag=0;
int read_success_flag=0;
int write_success_flag=0;
struct libnet_ether_addr *my_mac_addr;
u_int32_t my_ip_addr, des_ip_addr;
libnet_t *libnet_handle;
u_int8_t netmagic_mac[6] = { 0x88, 0x88, 0x88, 0x88, 0x88, 0x88 };
u_char *payload;
int write_seq = 0;
int read_seq = 0;


void Parsing_Callback(u_char *useless, const struct pcap_pkthdr* pkthdr,
		const u_char* packet) {
	struct Nmac_Header *Nmac_hdr = (struct Nmac_Header*) (packet + 34);
	switch (Nmac_hdr->nmac_type) {
		//连接响应
		case 0x01:
		{
			nmac_connected_flag = 1;
			break;
		}
		//写响应
		case 0x06:
		{
			if(write_seq ==ntohs(Nmac_hdr->seq)){
				write_success_flag = 1;
				printf("写成功\n");
			}
			break;
		}
		//读响应
		case 0x05:
		{
			if (read_seq == ntohs(Nmac_hdr->seq)) {
				read_success_flag = 1;
				struct libnet_ipv4_hdr *ip_headr = (struct libnet_ipv4_hdr*)(packet + 14);
				int read_data_len = ntohs(ip_headr->ip_len) - 20 -10;
				u_int32_t *read_data = (u_int32_t*)malloc(read_data_len/4 * sizeof(u_int32_t));
				u_int32_t *read_data_tmp = (u_int32_t*)malloc(read_data_len/4 * sizeof(u_int32_t));
				memcpy(read_data_tmp,packet+44,read_data_len);
				int i;
				printf("读成功,内容为:\n");
				for(i=0;i<read_data_len/4;i++){
					read_data[i] = ntohl(read_data_tmp[i]);
					printf("%08x\n",read_data[i]);
				}
			}
			break;
		}
	}
}

void shell(){
	char cmd[4];
	while(1){
		printf("=======================\n");
		printf("1.写数据\n");
		printf("2.读数据\n");
		printf("3.退出\n");
		printf("=======================\n");
		scanf("%s",cmd);
		switch(atoi(cmd)){
		case 1:
			Send_Write_Data();
			break;
		case 2:
			Send_Read_Data();
			break;
		case 3:
			exit(0);
			break;
		}
	}
}
void Send_Read_Data() {
	u_int32_t addr = 0x00000000;
	int num;
	char content[8];
	int n;
	int k = 28;
	printf("硬件表项地址:\n");
	scanf("%s", content);
	for (n = 0; n < 8; n++) {
		addr = (addr) | (unsigned char) hextodec(content[n]) << k;
		k = k - 4;
	}
	printf("条数:\n");
	scanf("%d", &num);
	printf("发送.....\n");
	read_seq++;
	struct timeval start, end;
	libnet_ptag_t ip_protocol_tag = 0;
	libnet_ptag_t ether_protocol_tag = 0;
	u_int16_t payload_size;
	u_int32_t w_addr;
	w_addr = htonl(addr);
	struct Nmac_Header read_request = { 1, 0, htons(read_seq), 0,
			0x03, htons(num), 0 };
	memcpy(payload, &read_request, sizeof(struct Nmac_Header));
	memcpy(payload + sizeof(struct Nmac_Header), &w_addr,sizeof(u_int32_t));
	payload_size = sizeof(struct Nmac_Header) + sizeof(u_int32_t);
	ip_protocol_tag = libnet_build_ipv4(
			LIBNET_IPV4_H + payload_size,
			0,
			read_seq,
			0,
			64,
			253,
			0,
			my_ip_addr,
			des_ip_addr,
			payload,
			payload_size,
			libnet_handle,
			ip_protocol_tag
			);
	ether_protocol_tag = libnet_build_ethernet(
			netmagic_mac,
			my_mac_addr->ether_addr_octet,
			ETHERTYPE_IP,
			NULL,
			0,
			libnet_handle,
			ether_protocol_tag
			);
	payload_size = libnet_write(libnet_handle);
	gettimeofday(&start, NULL);
	libnet_clear_packet(libnet_handle);
	while (1) {
		gettimeofday(&end, NULL);
		pcap_dispatch(pcap_handle,1,Parsing_Callback,NULL);
		if ((float) ((1000000 * (end.tv_sec - start.tv_sec)  +  (end.tv_usec - start.tv_usec)) / 1000000) > 2.5) {
			printf("[警告]地址：%02x 读失败! \n", addr);
			break;
		}
		if(read_success_flag == 1){
			read_success_flag = 0;
			break;
		}
	}
}
void Send_Write_Data() {
	char content[8];
	u_int32_t *data;
	u_int32_t addr = 0x00000000;
	int n, m;
	int k = 28;
	int num;
	//获取写信息
	printf("硬件表项地址:\n");
	scanf("%s", content);
	for (n = 0; n < 8; n++) {
		addr = (addr) | (unsigned char) hextodec(content[n]) << k;
		k = k - 4;
	}
	printf("条数:\n");
	scanf("%d", &num);
	data = (u_int32_t*) malloc(num * sizeof(u_int32_t));
	printf("输入内容,8位为一条后回车:\n");
	memset(data, 0, num * sizeof(u_int32_t));
	for (n = 0; n < num; n++) {
		scanf("%s", content);
		for (m = 0; m < 8; m++) {
			data[n] = (data[n]) | (unsigned char) hextodec(content[m]) << k;
			k = k - 4;
		}
	}
	printf("发送.....\n");
	write_seq++;
	//发送
	struct timeval start, end;
	libnet_ptag_t ip_protocol_tag = 0;
	libnet_ptag_t ether_protocol_tag = 0;
	u_int32_t w_addr;
	w_addr = htonl(addr);
	int i;
	u_int32_t * data_net;
	data_net = (u_int32_t*) malloc(num * sizeof(u_int32_t));
	for (i = 0; i < num; i++){
		data_net[i] = htonl(data[i]);
	}
	u_int16_t payload_size;
	struct Nmac_Header write_request = { 1, 0, htons(write_seq), 0,
			0x04, htons(num), 0 };
	memcpy(payload, &write_request, sizeof(struct Nmac_Header));
	memcpy(payload + sizeof(struct Nmac_Header), &w_addr,
			sizeof(u_int32_t));
	memcpy(payload + sizeof(struct Nmac_Header) + sizeof(u_int32_t), data_net,
			num * sizeof(u_int32_t));
	payload_size = sizeof(struct Nmac_Header) + sizeof(u_int32_t)
			+ num * sizeof(u_int32_t);

	ip_protocol_tag = libnet_build_ipv4(
	LIBNET_IPV4_H + payload_size, 0, write_seq, 0, 64,
	253, 0, my_ip_addr, des_ip_addr, payload, payload_size,
			libnet_handle, ip_protocol_tag);
	ether_protocol_tag = libnet_build_ethernet(netmagic_mac,
			my_mac_addr->ether_addr_octet,
			ETHERTYPE_IP,
			NULL, 0, libnet_handle, ether_protocol_tag);
	libnet_write(libnet_handle);
	libnet_clear_packet(libnet_handle);
	free(data);
	gettimeofday(&start, NULL);
	//超时响应
	while (1) {
		gettimeofday(&end, NULL);
		pcap_dispatch(pcap_handle, 1, Parsing_Callback, NULL);
		if ((float) ((1000000 * (end.tv_sec - start.tv_sec)
				+ (end.tv_usec - start.tv_usec)) / 1000000) > 2.5) {
			printf("[警告]地址：%02x 写失败!\n", addr);
			break;
		}
		if (write_success_flag == 1) {
			printf("地址%02x\n 写成功!\n", addr);
			break;
		}
	}
}
void nmac_connect(){
	payload = (u_char*) malloc(1480 * sizeof(u_char));
	struct timeval start, end;
	libnet_ptag_t ip_protocol_tag = 0;
	libnet_ptag_t ether_protocol_tag = 0;
	u_int16_t payload_size;
	//连接NetMagic
	u_int16_t nmac_seq = 0;
	struct Nmac_Header nmac_head = { 1, 0, htons(0), 0, 0x01,
			htons(0x0001), 0 };
	memcpy(payload, &nmac_head, sizeof(struct Nmac_Header));
	payload_size = sizeof(struct Nmac_Header);
	ip_protocol_tag = libnet_build_ipv4(
			LIBNET_IPV4_H + payload_size,
			0,
			nmac_seq,
			0,
			64,
			253,
			0,
			my_ip_addr,
			des_ip_addr,
			payload,
			payload_size,
			libnet_handle,
			ip_protocol_tag
			);
	ether_protocol_tag = libnet_build_ethernet(
			netmagic_mac,
			my_mac_addr->ether_addr_octet,
			ETHERTYPE_IP,
			NULL,
			0,
			libnet_handle,
			ether_protocol_tag
			);
	payload_size = libnet_write(libnet_handle);
	libnet_clear_packet(libnet_handle);
	gettimeofday(&start, NULL);
	while (1) {
		gettimeofday(&end, NULL);
		pcap_dispatch(pcap_handle,1,Parsing_Callback,NULL);
		if ((float) ((1000000 * (end.tv_sec - start.tv_sec)	+ (end.tv_usec - start.tv_usec)) / 1000000) > 2.5) {
			printf("连接超时!\n");
			break;
		}
		if (nmac_connected_flag == 1) {
			printf("连接成功!\n");
			break;
		}
	}
}
int main(void) {
	pcap_if_t *alldevs;
	pcap_if_t *device;
	pcap_if_t *tmp_device;
	bpf_u_int32 net_ip;
	bpf_u_int32 net_mask;
	struct bpf_program bpf_filter;
	char bpf_filter_string[] = "ip proto 253 and ip dst 192.168.8.2";
	char errbuf[255];
	if (pcap_findalldevs(&alldevs, errbuf) == -1) {
		printf("pcap_findalldevs() :%s", errbuf);
		exit(0);
	}
	device = alldevs;
	tmp_device = alldevs;
	int device_num = 0;
	printf("设备列表\n");
	for (; device != NULL; device = device->next) {
		printf("%d:%s\n",device_num,device->name);
		device_num++;
	}
	char DeviceName[20];
	printf("选择抓包设备:");
	int temp_device_num;
	scanf("%d",&temp_device_num);
	int find_dev_num;
	for(find_dev_num=0 ; find_dev_num<temp_device_num ; find_dev_num++){
		tmp_device = tmp_device->next;
	}
	printf("%s\n",tmp_device->name);
	memcpy(DeviceName,tmp_device->name,sizeof(tmp_device->name));
//	for (; device != NULL; device = device->next) {
//		if (strncmp(device->name, DeviceName, 4) == 0) {
//			break;
//		}
//	}
	pcap_lookupnet(DeviceName, &net_ip, &net_mask, errbuf);
	pcap_handle = pcap_open_live(DeviceName, BUFSIZ, 0, -1, errbuf);
	if (pcap_handle == NULL) {
		printf("pcap_open_live(): %s\n", errbuf);
		exit(0);
	}
	pcap_compile(pcap_handle, &bpf_filter, bpf_filter_string, 0, net_ip);
	pcap_setfilter(pcap_handle, &bpf_filter);
	libnet_handle = libnet_init(LIBNET_LINK, DeviceName, errbuf);
	if (libnet_handle == NULL) {
		printf("libnet_init(): %s\n", errbuf);
		exit(0);
	}
	my_mac_addr = libnet_get_hwaddr(libnet_handle);
	my_ip_addr = libnet_get_ipaddr4(libnet_handle);
	des_ip_addr = libnet_name2addr4(libnet_handle, "136.136.136.136",
	LIBNET_DONT_RESOLVE);
	nmac_connect();
	shell();
	return 0;
}
int hextodec(char x) {
	int n;
	switch (x) {
	case '0':
		n = 0;
		break;
	case '1':
		n = 1;
		break;
	case '2':
		n = 2;
		break;
	case '3':
		n = 3;
		break;
	case '4':
		n = 4;
		break;
	case '5':
		n = 5;
		break;
	case '6':
		n = 6;
		break;
	case '7':
		n = 7;
		break;
	case '8':
		n = 8;
		break;
	case '9':
		n = 9;
		break;
	case 'a':
		n = 10;
		break;
	case 'b':
		n = 11;
		break;
	case 'c':
		n = 12;
		break;
	case 'd':
		n = 13;
		break;
	case 'e':
		n = 14;
		break;
	case 'f':
		n = 15;
		break;
	}
	return n;
}
