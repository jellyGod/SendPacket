#include<stdio.h>
#include<string.h>
#include<stdlib.h>
#include<netinet/in.h>
#include<sys/types.h>
#include<sys/socket.h>
#include<arpa/inet.h>
#include <linux/if_ether.h>
#include<linux/if_packet.h>
#include<time.h>
#include <sys/ioctl.h>
#include <net/if.h>
#define BUFSIZE 10240
#define STRSIZE 1024
typedef int bpf_int32;
typedef unsigned int bpf_u_int32;
typedef unsigned short u_short;
typedef unsigned int u_int32;
typedef unsigned short u_int16;
typedef unsigned char u_int8;
//pacp文件头结构体
struct pcap_file_header {
	bpf_u_int32 magic; /* 0xa1b2c3d4 */
	u_short version_major; /* magjor Version 2 */
	u_short version_minor; /* magjor Version 4 */
	bpf_int32 thiszone; /* gmt to local correction */
	bpf_u_int32 sigfigs; /* accuracy of timestamps */
	bpf_u_int32 snaplen; /* max length saved portion of each pkt */
	bpf_u_int32 linktype; /* data link type (LINKTYPE_*) */
};
//时间戳
struct time_val {
	int tv_sec; /* seconds 含义同 time_t 对象的值 */
	int tv_usec; /* and microseconds */
};
//pcap数据包头结构体
struct pcap_pkthdr {
	struct time_val ts; /* time stamp */
	bpf_u_int32 caplen; /* length of portion present */
	bpf_u_int32 len; /* length this packet (off wire) */
};

//数据帧头
typedef struct FramHeader_t {	//Pcap捕获的数据帧头
	u_int8 DstMAC[6];	//目的MAC地址
	u_int8 SrcMAC[6];	//源MAC地址
	u_short FrameType;    //帧类型
} FramHeader_t;
//IP数据报头
typedef struct IPHeader_t {	//IP数据报头
	u_int8 Ver_HLen;       //版本+报头长度
	u_int8 TOS;            //服务类型
	u_int16 TotalLen;       //总长度
	u_int16 ID;	//标识
	u_int16 Flag_Segment;   //标志+片偏移
	u_int8 TTL;            //生存周期
	u_int8 Protocol;       //协议类型
	u_int16 Checksum;       //头部校验和
	u_int32 SrcIP;	//源IP地址
	u_int32 DstIP;	//目的IP地址
} IPHeader_t;
//TCP数据报头
typedef struct TCPHeader_t {	//TCP数据报头
	u_int16 SrcPort;	//源端口
	u_int16 DstPort;	//目的端口
	u_int32 SeqNO;	//序号
	u_int32 AckNO;	//确认号
	u_int8 HeaderLen;	//数据报头的长度(4 bit) + 保留(4 bit)
	u_int8 Flags;	//标识TCP不同的控制消息
	u_int16 Window;	//窗口大小
	u_int16 Checksum;	//校验和
	u_int16 UrgentPointer;  //紧急指针
} TCPHeader_t;

//just create the send socket
int initSocket() {
	int sockfd_MAC = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	return sockfd_MAC;
}

//just use the socket to send the data
void SendPacket(int sockfd, void* msg, size_t len) {
	struct sockaddr_ll addr = {0};
	memset(&addr, 0, sizeof(addr));
	addr.sll_family = AF_PACKET;
	struct ifreq ifstruct;
	strcpy(ifstruct.ifr_name, "eth0");
	ioctl(sockfd, SIOCGIFINDEX, &ifstruct);
	addr.sll_ifindex = ifstruct.ifr_ifindex;
	addr.sll_protocol = htons(ETH_P_ALL);
	sendto(sockfd, msg, len, 0, &addr, sizeof(struct sockaddr_ll));
}

int main() {
	struct pcap_pkthdr *ptk_header;
	struct FramHeader_t *frame_header;
	IPHeader_t *ip_header;
	TCPHeader_t *tcp_header;
	FILE *fp;
	int pkt_offset, i = 0, j = 0;
	char buf[BUFSIZE];
	//初始化
	ptk_header = (struct pcap_pkthdr *) malloc(sizeof(struct pcap_pkthdr));
	frame_header = (FramHeader_t *) malloc(sizeof(FramHeader_t));
	ip_header = (IPHeader_t *) malloc(sizeof(IPHeader_t));
	tcp_header = (TCPHeader_t *) malloc(sizeof(TCPHeader_t));
	memset(buf, 0, sizeof(buf));
	if ((fp = fopen("task.pcap", "r")) == NULL) {
		printf("error: can not open pcap file\n");
		exit(0);
	}
	//init the socket
	int sockfd = initSocket();
	//开始读数据包
	pkt_offset = 24;	//pcap文件头结构 24个字节
	while (fseek(fp, pkt_offset, SEEK_SET) == 0)	//遍历数据包
	{
		i++;
		if (fread(ptk_header, 16, 1, fp) != 1)	//读pcap数据包头结构
				{
			printf("can't read any more!\n");
			break;
		}
		pkt_offset += 16 + ptk_header->caplen;   //下一个数据包的偏移值
		//analyze more data
		if (fread(frame_header, sizeof(FramHeader_t), 1, fp) == 1) {
			//the next layer is ip
			if (htons(frame_header->FrameType) == 0x0800) {
				//read the ip layer and judge the next
				if (fread(ip_header, sizeof(IPHeader_t), 1, fp) == 1) {
					int ipHeaderLen = (ip_header->Ver_HLen & 0x0f) * 4;
					//just read the option
					char* ipOption = (char*)malloc(sizeof(char)*(ipHeaderLen-20));
					fread(ipOption, ipHeaderLen-20, 1 ,fp);
					if (ip_header->Protocol == 0x06) {
						j++;
						if (fread(tcp_header, sizeof(TCPHeader_t), 1, fp)== 1) {
							int tcpHeaderLen = ((tcp_header->HeaderLen & 0xf0)>> 4) * 4;
						    char* tcpOption = (char*)malloc(sizeof(char)*(tcpHeaderLen-20));
						    fread(tcpOption, tcpHeaderLen-20, 1, fp);
                            //use memcpy to build a msg and then send it out
							int cLen = 0;
							int ipLen = 0;
							//just copy the frame_header
                            memcpy(buf,frame_header,14);
                            cLen += 14;
                            ipLen +=ipHeaderLen;
                            ipLen +=tcpHeaderLen;
                            ip_header->TotalLen = ipLen+10;
                            //then copy the ip_header and options
                            memcpy(buf+cLen,ip_header,20);
                            cLen +=20;
                            memcpy(buf+cLen,ipOption,ipHeaderLen-20);
                            cLen +=ipHeaderLen-20;
                            //then copy the tcp_header and options
                            memcpy(buf+cLen,tcp_header,20);
                            cLen +=20;
                            memcpy(buf+cLen,tcpOption,tcpHeaderLen-20);
                            cLen +=tcpHeaderLen - 20;
                            //add yourself payload
                            int c = 0;
                            for(c=cLen;c<cLen+10;c++){
                            	buf[c] = 98;
                            }
                            cLen +=10;
                            SendPacket(sockfd, buf, cLen);
                            printf("yes i send out!\n");
						}
					}
				}
			}
		} else {
			printf("can't read mac layer!\n");
		}
	}
	printf("there are %d packets!\n", i - 1);
	printf("there are %d tcp\n", j);
	fclose(fp);
	return 0;
}

