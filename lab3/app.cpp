#define  _CRT_SECURE_NO_WARNINGS 1
#include<pcap.h>
#include<Winsock2.h>
#include<iostream>
#include<stdio.h>
#include<stdlib.h>
#include<iphlpapi.h>
#include<string>
#pragma comment(lib,"Packet.lib")
#pragma comment(lib,"wpcap.lib")
#pragma comment(lib,"ws2_32.lib")
#pragma comment(lib,"iphlpapi.lib")//表示链接的时侯找ws2_32.lib
//#pragma warning( disable : 4996 )//要使用旧函数
using namespace std;

/* 4 bytes IP address */

typedef struct ip_address {
    u_char byte1;
    u_char byte2;
    u_char byte3;
    u_char byte4;
}ip_address;
#pragma pack(1)
typedef struct ehter_header {
    u_char    ether_dhost[6];   //目的MAC地址
    u_char    ether_shost[6];   //源MAC地址
    u_short   ether_type;       //帧类型
}ether_header;

/* ARP header */
typedef struct ARP_frame {
    ether_header header;
    u_short hardware;
    u_short protocol;
    u_char hardware_size;
    u_char protocol_size;
    u_short opcode;
    u_char sender_mac[6];
    ip_address sender_ip;
    u_char target_mac[6];
    ip_address target_ip;
}ARP_frame;
#pragma pack(0)

int main()
{
    pcap_if_t* alldevs;
    pcap_if_t* d;
    int inum;
    int i = 0;
    pcap_t* adhandle;
    char errbuf[PCAP_ERRBUF_SIZE];
    ARP_frame ARPframe;
    ARP_frame* RecFrame;
    struct pcap_pkthdr* pkt_header;
	const u_char* pkt_data;
    //获取设备列表
    if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING,
        NULL, &alldevs, errbuf) == -1)
    {
        fprintf(stderr, "在检测设备时出现错误: %s\n", errbuf);
        exit(1);
    }
    //打印列表
    for (d = alldevs; d; d = d->next)
    {
        printf("%d. %s", ++i, d->name);
        if (d->description)
            printf(" (%s)\n", d->description);
        else
            printf(" 无可用设备！\n");
    }
    if (i == 0)  return -1;
    printf("请输入设备编号 (1-%d):", i);
    scanf("%d", &inum);
    if (inum < 1 || inum > i)
    {
        printf("\n超出可用范围\n");
        pcap_freealldevs(alldevs);
        return -1;
    }

    //跳转至想要监听的设备
    for (d = alldevs, i = 0; i < inum - 1; d = d->next, i++);
    //打开设备
    if ((adhandle = pcap_open(d->name, // name of the device
        65536, // portion of the packet to capture
               // 65536 guarantees that the whole packet will
               // be captured on all the link layers
        PCAP_OPENFLAG_PROMISCUOUS, // promiscuous mode
        1000, // read timeout
        NULL, // authentication on the remote machine
        errbuf // error buffer
    )) == NULL)
    {
        fprintf(stderr,
            "\n%s设备不支持！%\n",
            d->name);
        pcap_freealldevs(alldevs);
        return -1;
    }
    printf("\n正在 %s 上监听...\n", d->description);
    cout << "正在设置过滤条件...限定为ARP......"<<endl;
    char filter[40] = "ether proto \\arp";
    u_int netmask;
    struct bpf_program fcode;
    if (d->addresses != NULL)
        //获取掩码
        netmask = ((struct sockaddr_in*)(d->addresses->netmask))->sin_addr.S_un.S_addr;
    else
        //C类设备
        netmask = 0xffffff;
    if (pcap_compile(adhandle, &fcode, filter, 1, netmask) < 0)
    {
        fprintf(stderr,"\n无法解析过滤器\n");
        pcap_freealldevs(alldevs);
        return -1;
    }
    else
    {
        if (pcap_setfilter(adhandle, &fcode) < 0)
        {
            cout << "过滤器发生错误！\n" << endl;
            return -1;
        }
        cout << "正在监听" << d->description << endl;
    }
    //获取网卡设备MAC地址
    PIP_ADAPTER_ADDRESSES pAddresses=nullptr;   
    IP_ADAPTER_DNS_SERVER_ADDRESS *pDnsServer=nullptr;
    ULONG outbuflen=0;
    GetAdaptersAddresses(AF_UNSPEC,0,NULL,pAddresses,&outbuflen);
    pAddresses=(IP_ADAPTER_ADDRESSES*)malloc(outbuflen);
    GetAdaptersAddresses(AF_INET,NULL,NULL,pAddresses,&outbuflen);
    while(1)
    {
        bool find = 1;
        //简化成使用IP地址而不是设备GUID标识找到该设备
        for(int i=2;i<6;i++)
        {
            if(pAddresses->FirstUnicastAddress->Address.lpSockaddr->sa_data[i]!=d->addresses->addr->sa_data[i])
            {
                find = 0;
                break;
            }
        }
        if(find)break;
        pAddresses = pAddresses->Next;
    }
    //封装ARP包
    for(int i=0;i<6;i++)
    {
        ARPframe.header.ether_shost[i]=pAddresses->PhysicalAddress[i];
        ARPframe.header.ether_dhost[i]=0xff;
        ARPframe.sender_mac[i]=pAddresses->PhysicalAddress[i];
        ARPframe.target_mac[i]=0x00;
    }
    ARPframe.sender_ip.byte1=d->addresses->addr->sa_data[2];
    ARPframe.sender_ip.byte2=d->addresses->addr->sa_data[3];
    ARPframe.sender_ip.byte3=d->addresses->addr->sa_data[4];
    ARPframe.sender_ip.byte4=d->addresses->addr->sa_data[5];
    string ipInput;
    cout<<"输入IP地址；";
    cin>>ipInput;
    u_char addr=0;
    for(int i=0,j=0;i<ipInput.length();i++)
    {
        if(ipInput[i]!='.')
            addr=addr*10+ipInput[i]-'0';
        else
        {
            switch(j)
            {
                case 0:ARPframe.target_ip.byte1=addr;break;
                case 1:ARPframe.target_ip.byte2=addr;break;
                case 2:ARPframe.target_ip.byte3=addr;break;
            }
            addr=0;
            j++;
        }
    }
    ARPframe.target_ip.byte4=addr;
    ARPframe.header.ether_type=htons(0x0806);
    ARPframe.hardware=htons(0x0001);
    ARPframe.protocol=htons(0x0800);
    ARPframe.hardware_size=6;
    ARPframe.protocol_size=4;
    ARPframe.opcode=htons(0x0001);
    //发送ARP请求
    pcap_sendpacket(adhandle,(u_char*)&ARPframe,sizeof(ARPframe));
    //循环捕获ARP应答
    while(1)
    {
        switch(pcap_next_ex(adhandle,&pkt_header,&pkt_data))
        {
        case -1:
            cout<<"捕获错误"<<endl;
            return 0;
        case 0:
            cout<<"未捕获到数据报"<<endl;
            break;
        default:
            RecFrame=(ARP_frame*)pkt_data;
            if(RecFrame->target_ip.byte1==ARPframe.sender_ip.byte1
            &&RecFrame->target_ip.byte2==ARPframe.sender_ip.byte2
            &&RecFrame->target_ip.byte3==ARPframe.sender_ip.byte3
            &&RecFrame->target_ip.byte4==ARPframe.sender_ip.byte4
            &&RecFrame->sender_ip.byte1==ARPframe.target_ip.byte1
            &&RecFrame->sender_ip.byte2==ARPframe.target_ip.byte2
            &&RecFrame->sender_ip.byte3==ARPframe.target_ip.byte3
            &&RecFrame->sender_ip.byte4==ARPframe.target_ip.byte4)
            {
                cout<<"对应关系如下:"<<endl;
                printf("%d.%d.%d.%d\n",ARPframe.target_ip.byte1,ARPframe.target_ip.byte2,ARPframe.target_ip.byte3,ARPframe.target_ip.byte4);
                printf("%02x:%02x:%02x:%02x:%02x:%02x\n",RecFrame->sender_mac[0],RecFrame->sender_mac[1],RecFrame->sender_mac[2],RecFrame->sender_mac[3],RecFrame->sender_mac[4],RecFrame->sender_mac[5]);
                system("pause");
                return 0;
            }
        }
    }
    return 0;
}