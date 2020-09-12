#pragma comment(lib, "ws2_32.lib")
#pragma warning(disable:4996)
#define DEFAULT_PORT 53
#include<winsock2.h>
#include<Windows.h>
#include<stdlib.h>
#include<stdio.h>
#include<string>
#include<iostream>
#include<functional>	
#define SIO_UDP_CONNRESET _WSAIOW(IOC_VENDOR, 12)



//DNS报文Head字段
typedef struct
{
	unsigned short ID;
	unsigned short sumRCODE;
	unsigned short QDCOUNT;
	unsigned short ANCOUNT;
	unsigned short NSCOUNT;
	unsigned short ARCOUNT;
}Head;



//DNS报文Question字段
typedef struct
{
	unsigned short QType;
	unsigned short QClass;
}Question;


//客户端缓存信息
//is_done表示该存储空间是否无用，即是否给该客户端发送响应包，0为未发送，1为发送，为1时可以覆盖
typedef struct
{
	struct sockaddr_in temp;
	unsigned short Id;
	int is_done=1;
}ClientBuf;

//DNS报文Answer字段
#pragma pack(1)
typedef struct
{
	unsigned short type;
	unsigned short Class;
	unsigned int TTL;
	unsigned short RDlength;
	unsigned long  Rdata;
}Answer;
#pragma pack()


typedef struct
{
	char local_ID[100];
	char local_domain[100];
}file_in;

char recvbuf[512];//接收缓冲区
char sendbuf[512];//发送缓冲区
char Ip[100];//ip地址
char Qname[100];//question字段Qname部分
char Aname[100];//answer字段Aname部分
char domain[100];//解析后的域名
Head DNS_head;//DNS报文头部分
Question DNS_question;//DNS报文question部分
Answer DNS_answer;//DNS_报文answer部分
ClientBuf client[1000];//客户端缓存
char respond[512];//回应报文
file_in txt[207];//文件存储缓冲区




void Input()
{
	FILE *fp;
	errno_t err = fopen_s(&fp, "dnsrelay.txt", "r");
	int i;
	for (i = 0; i < 207; i++)
	fscanf(fp, "%s %s\n", &txt[i].local_ID, &txt[i].local_domain);
	fclose(fp);
}
//解析域名
void translete()
{
	int i = 0, k = 0;
	while (i < strlen(Qname))
	{
		int size = Qname[i];
		for (int j = i + 1; j <= (i + size); )
		{
			domain[k] = Qname[j];
			k++;
			j++;
		}
		i = i + size + 1;
		if (i < strlen(Qname))
		{
			domain[k] = '.';
			k++;
		}
	}
	domain[k] = '\0';

	//puts(domain);
}



void Make_respond()//创建回应包
{
	unsigned short flag = DNS_head.sumRCODE;
	unsigned short ch1;
	const  char* wrongIp = "0.0.0.0";
	/*int lock = 0;
	for (int i = 0; i < strlen(Ip); i++)
	{
		if (Ip[i] != wrongIp[i])
		{
			lock = 1;
			break;
		}
	}*/
	
	if (strcmp(Ip, wrongIp) == 0)
	{
		ch1 = 0x8183;
		DNS_head.sumRCODE = htons(ch1);
		//memset(respond, 0, 512);
		memcpy(respond, &DNS_head, 12);
		strcpy(respond + 12, Qname);
		memcpy(respond + 12 + strlen(Qname) + 1, &DNS_question, 4);
	}
	else
	{
		strcpy(Aname, Ip);
		ch1 = 0x8180;
		DNS_head.sumRCODE = htons(ch1);
		DNS_answer.Class = DNS_question.QClass;
		DNS_answer.type = DNS_question.QType;
		DNS_answer.TTL = htonl(86400);
		DNS_answer.RDlength = htons(4);
		DNS_answer.Rdata = inet_addr(Ip);
		DNS_head.ANCOUNT = htons(1);
		memcpy(respond, &DNS_head, 12);
		strcpy(respond + 12, Qname);
		memcpy(respond + 12 + strlen(Qname) + 1, &DNS_question, 4);
		unsigned short pointer = 0x0cc0;
		memcpy(respond + sizeof(Head) + strlen(Qname) + 1 + sizeof(Question), &pointer, sizeof(unsigned short));
		memcpy(respond + 12 + strlen(Qname) + 1 + 4 + 2, &DNS_answer, 14);
	}
}


//返回值0代表本地查询成功，输出ip地址；返回值1代表本地查询成功，但域名被拦截
//返回值2代表本地查询失败，发送至因特网查询
int local_search()
{
	char wrongIp[] = "0.0.0.0";//0.0.0.0代表被拦截的ip地址
	wrongIp[7] = '\0';
	boolean is_domain;//代表域名在本地中是否存在，存在为true，不存在为false
	boolean is_ip;//代表ip地址是否合法，合法为true，不合法为false
	for (int i = 0; i <207; i++)//判断域名是否存在
	{
		is_domain =false;
		is_ip = false;
		for (int j = 0; j < strlen(txt[i].local_domain); j++)
		{
			if (domain[j] == txt[i].local_domain[j])
			{

				is_domain = true;
			}
			else
			{
				is_domain = false;
				break;
			}
		}
		if (is_domain == true)//域名存在，开始判断IP地址是否被拦截
		{
			for (int j = 0; j < strlen(txt[i].local_ID) && is_ip == false; j++)
			{
				if (txt[i].local_ID[j] != wrongIp[j])
				{
					is_ip = true;
					break;
				}
				else
				{
					is_ip = false;
				}
			}
		}
		if ((is_domain == true && is_ip == true)||(is_domain==true && is_ip==false))
		{
			for (int j = 0; j < strlen(txt[i].local_ID); j++)
			{
				Ip[j] = txt[i].local_ID[j];
			}
			break;
		}
	}
	if (is_domain == true && is_ip == true)//域名存在且IP地址符合规定，输出IP地址
	{
		Make_respond();
		return 0;
	}
	else if (is_domain == true && is_ip == false)//域名存在但是IP地址不符合规定，输出域名不存在
	{
		memset(Ip, 0, sizeof(Ip));
		memcpy(Ip, wrongIp, 8);
		Make_respond();
		return 1;
	}
	else
		return 2;	
}




int main(void)
{
	Input();//将文件数据存储到内存中

	//初始化套接字
	WSADATA wsaData;
	int ret = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if (ret != 0)
	{
		fputs("WSAStartup error\n", stderr);
		return 0;
	}


	//创建套接字,fd为客户端与本机DNS套接字，fp为本机DNS与上层DNS套接字
	SOCKET fp = INVALID_SOCKET;
	fp = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	SOCKET fd = INVALID_SOCKET;
	fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (INVALID_SOCKET == fd)
	{
		fputs("socket() error\n", stderr);
		WSACleanup();
		return 0;
	}
	if (INVALID_SOCKET == fp)
	{
		fputs("socket() error\n", stderr);
		WSACleanup();
		return 0;
	}


	BOOL bNewBehavior = FALSE;
	DWORD dwBytesReturned = 0;
	WSAIoctl(fd, SIO_UDP_CONNRESET, &bNewBehavior, sizeof bNewBehavior, NULL, 0, &dwBytesReturned, NULL, NULL);


	//绑定套接字
	struct sockaddr_in local = {};//本机DNS
	local.sin_family = AF_INET;
	local.sin_addr.S_un.S_addr = INADDR_ANY;
	local.sin_port = htons(DEFAULT_PORT);
	bind(fd, (const SOCKADDR *)&local, sizeof(sockaddr_in));
	
	struct sockaddr_in sockAddr = {};//向上发送的dns中继器
	sockAddr.sin_family = AF_INET;
	sockAddr.sin_addr.S_un.S_addr = inet_addr("10.3.9.5");
	sockAddr.sin_port = htons(DEFAULT_PORT);



	struct sockaddr_in ClientAddr = {};//客户端
	int datalength = sizeof(sockaddr_in);//数据报大小
	int search_result;
	int i=0;

	while (1)
	{
		//printf("sockAddr = %s\n", inet_ntoa(sockAddr.sin_addr));
		int recv_from_client_Length = recvfrom(fd, recvbuf, 512, 0,(sockaddr *)&ClientAddr,&datalength);//从客户端接收查询包，返回值为包的长度
		if (recv_from_client_Length < 0)
		{
			printf("%d\n", WSAGetLastError());
			fputs("datalength error\n", stderr);
		}
		else
		{
			printf("From %s -- ", inet_ntoa(ClientAddr.sin_addr));
			printf("接收到%d\n", recv_from_client_Length);
			for (; client[i].is_done == 0; i++)
			{
				if (i == 999)
					i = 0;
			}

			//存储客户端信息
			client[i].Id = *(unsigned short*)recvbuf;//存储查询包ID
			client[i].temp = ClientAddr;//存储客户端地址
			client[i].is_done = 0;

			//存储DNS报文Head字段
			memcpy(&DNS_head, recvbuf, 12);


			if (ntohs(DNS_head.QDCOUNT) != 1)
			{
				sendto(fp, recvbuf, recv_from_client_Length, 0,( sockaddr *)&sockAddr , sizeof(struct sockaddr_in));//将查询包发送给上层DNS
				printf("发送至 %s\n", inet_ntoa(sockAddr.sin_addr));
				sockaddr_in temp = {};//上层DNS地址(自动分配)
				int recv_from_DNS_Length=recvfrom(fp, recvbuf, 512, 0, (sockaddr *)&temp, &datalength);
				unsigned short id = *((unsigned short*)recvbuf);//响应包的ID
				for (int j = 0; j < 1000; j++)//判断响应包ID和查询包ID
				{
					if (id == client[j].Id)
					{
						sendto(fd, recvbuf, recv_from_DNS_Length, 0, (sockaddr *)&client[j].temp, sizeof(struct sockaddr_in));
						printf("成功发送至客户端 长度为%d\n", recv_from_DNS_Length);
						client[j].is_done = 1;
						break;
					}
				}
			}
			else
			{
				strcpy(Qname, recvbuf + 12);
				memcpy(&DNS_question, recvbuf + 12 + strlen(Qname) + 1, 4);
				translete();
				search_result = local_search();
				std::cout << search_result << std::endl;
				if (search_result == 0)
				{
					for (int j = 0; j < 1000; j++)
					{
						if (client[j].Id == DNS_head.ID)
						{
							int send_length=sendto(fd, respond, 12 + strlen(Qname) + 1 + 4 + 2 + 14, 0, (sockaddr *)&client[j].temp, sizeof(struct sockaddr));
							printf("域名查找成功，发送至客户端，长度为%d\n",send_length);
							client[j].is_done = 1;
						}
					}
				}
				else if (search_result == 1)
				{
					for (int j = 0; j < 1000; j++)
					{
						if (client[j].Id == DNS_head.ID)
						{
							int send_length=sendto(fd, respond, recv_from_client_Length, 0, (sockaddr*)&client[j].temp, sizeof(struct sockaddr));
							printf("域名被拦截，发送至客户端，长度为%d\n",send_length);
							client[j].is_done = 1;
						}
					}
				}
				else if (search_result == 2)
				{
					sockaddr temp{};
					sendto(fp, recvbuf, recv_from_client_Length, 0,( sockaddr *)&sockAddr, sizeof(struct sockaddr));
					int recv_from_DNS_length=recvfrom(fp, recvbuf, sizeof(recvbuf), 0, (sockaddr *)&temp, &datalength);
					unsigned short id = *(unsigned short*)recvbuf;
					for (int j = 0; j < 1000; j++)
					{
						if (id == client[j].Id)
						{
							printf("本地未查找到域名，接收到上层服务器响应包，发送至客户端，长度为%d\n",recv_from_DNS_length );
							sendto(fd, recvbuf, recv_from_DNS_length, 0, (sockaddr *)&client[i].temp, sizeof(struct sockaddr_in));
							client[j].is_done = 1;
						}
					}
				}
			}
		}
	}
}