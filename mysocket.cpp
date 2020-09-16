#include "mysocket.h"
#include "aes-test.h"

CSocket::CSocket()
{
    _sock=-1;
    memset(&(_addr),0,sizeof(_addr));
}

CSocket::~CSocket()
{
    if(is_alive())
	::close(_sock);
}

bool CSocket::close()
{
    if(is_alive())
	::close(_sock);
    return true;
}

/*
bool CSocket::create()
{
    //create socket
    _sock=::socket(AF_INET,SOCK_DGRAM,0);
    if(_sock==-1)
    {
	perror("socket failed\t");
	return false;
    }

    //set port reuse
    int on = 1;
    if (::setsockopt(_sock, SOL_SOCKET, SO_REUSEADDR, (const char*) &on, sizeof (on))== -1)
    {
	perror("setsockopt failed\t");
	return false;
    }
    return true;
}
*/


bool CSocket::create(int sock_type, int protocol)
{
    //create socket
    _sock=::socket(AF_INET,sock_type,protocol);
    if(_sock==-1)
    {
	perror("socket failed\t");
	return false;
    }

    //set port reuse
    int on = 1;
    if (::setsockopt(_sock, SOL_SOCKET, SO_REUSEADDR, (const char*) &on, sizeof (on))== -1)
    {
	perror("setsockopt failed\t");
	return false;
    }
    return true;
}


//bind raw socket to a specific IP address
bool CSocket::bind_rawsock(struct sockaddr_in src)
{
    if(!is_alive())
	return false;
    int bind_ret = ::bind(_sock,(struct sockaddr *) &src,sizeof(src));
    if(bind_ret==-1)
    {
	perror("bind failed\t");
	return false;
    }
    return true;
}


bool CSocket::bind(const int port)
{
    if(!is_alive())
	return false;
    sockaddr_in servaddr;
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    servaddr.sin_port=port;
    int bind_ret = ::bind(_sock,(struct sockaddr * ) &servaddr,sizeof(servaddr));
    if(bind_ret==-1)
    {
	perror("bind failed\t");
	return false;
    }
    else
    {
	int addr_len=sizeof(_addr);
	if(getsockname(_sock, (sockaddr *) &_addr, (socklen_t *)&addr_len) == -1)
	{
	    perror("getsockname failed\t");
	    return false;
	}
	return true;
    }
}

bool CSocket::listen()
{
    if(!is_alive())
	return false;
    int listen_ret = ::listen(_sock, MAX_CONNECTIONS);
    if(listen_ret==-1)
    {
	perror("listen failed\t");
	return false;
    }
    return true;
}

int CSocket::send_data(const char* send_buf)
{
    if(!is_alive())
	return -1;
    int len=strlen(send_buf);
    int send_ret= ::send(_sock,send_buf,len+1,0);
    if(send_ret==-1)
    {
	perror("send error:\t");
    }
    return send_ret;
}

int CSocket::recv_data(char* recv_buf)
{
    if(!is_alive())
	return -1;
    char buf[MAX_BUF_SIZE];
    memset(buf,0,MAX_BUF_SIZE);
    int recv_ret= ::recv(_sock,buf,MAX_BUF_SIZE-1,0);
    if(recv_ret==-1)
    {
	perror("recv error:\t");
    }
    else
    {
	if(recv_ret>0)
	    memcpy(recv_buf,buf,MAX_BUF_SIZE);
    }
    return recv_ret;
}

int CSocket::send_data_UDP(const char* send_buf, const int len, struct sockaddr_in & ser_addr )
{
    if(!is_alive())
	return -1;
    //int len=strlen(send_buf);
   
    int addr_len=sizeof(sockaddr_in);
    int send_ret = ::sendto(_sock, send_buf , len, 0, (const struct sockaddr*)&ser_addr, addr_len);
    if(send_ret==-1)
    {
	perror("sendto error:\t");
    }
    return send_ret;
}


/*
int CSocket::send_data_RAW(const char* send_buf, const int len, struct sockaddr_in & ser_addr )
{
    return send_data_UDP(send_buf, len, ser_addr);
}
*/

//send a tcp packet via raw socket (sendmsg())
int CSocket::send_tcp_rawsock(struct sockaddr_in src_addr, struct sockaddr_in dst_addr1, char* org_packet, int len)
{
    
    /*
    struct Packet {
	struct tcphdr tcp;
    } p;
    */
    
    struct tcphdr* p= (struct tcphdr*)org_packet;

    struct iovec iov;

    //memset(&p, 0, sizeof(struct Packet));
    memset(&iov, 0, sizeof(struct iovec));


    //memcpy(&p, org_packet, len);
    
    struct msghdr m = {
        &dst_addr1, sizeof(struct sockaddr_in), &iov,
	1, 0, 0, 0
	};

    ssize_t bs;
    p->check = 0;
    //p->source = htons(EXT_TCP_PORT);
    
    int tcp_len = ((unsigned int)p->doff) * 4;



    /*
    p->doff = sizeof(struct tcphdr)/4;
    iov.iov_base = p;
    iov.iov_len = sizeof(struct tcphdr);
    p->check = in_cksum_tcp(src_addr.sin_addr.s_addr, dst_addr1.sin_addr.s_addr, (unsigned short *)p, sizeof(struct tcphdr));
    */

    if((unsigned int) p->syn == 1)
    {
    	p->doff = sizeof(struct tcphdr)/4;
    	iov.iov_base = p;
    	iov.iov_len = sizeof(struct tcphdr);
    	p->check = in_cksum_tcp(src_addr.sin_addr.s_addr, dst_addr1.sin_addr.s_addr, (unsigned short *)p, sizeof(struct tcphdr));
    }
    else
    {
    	iov.iov_base = p;
    	iov.iov_len = tcp_len;
    	p->check = in_cksum_tcp(src_addr.sin_addr.s_addr, dst_addr1.sin_addr.s_addr, (unsigned short *)p, tcp_len);
    }
 
    if (0> (bs = sendmsg (_sock, &m, 0))) 
    {
	   perror ("ERROR: sendmsg ()");
    }
    else
    {
	   printf("send tcp packet, size:%d\n",(int)bs);
    }

    memset(&m, 0, sizeof(struct msghdr));
    return bs;
}



//send an ICMP packet via raw socket (sendmsg)
int CSocket::send_icmp_rawsock(struct sockaddr_in dst_addr)
{
    struct Packet {
	struct icmphdr icmp;
	struct timeval tv;
    } p;

    struct iovec iov;
    
    struct msghdr m = {
	&dst_addr, sizeof(struct sockaddr_in), &iov,
	1, 0, 0, 0
	};

    ssize_t bs;
    p.icmp.type = ICMP_ECHO;
    p.icmp.code = 0;
    p.icmp.un.echo.id = 0;
 
    iov.iov_base = &p;
    iov.iov_len = sizeof(struct icmphdr)+ sizeof(struct timeval);
 

    p.icmp.checksum = 0;
    p.icmp.un.echo.sequence = htons (0);
    gettimeofday(&p.tv, NULL);
 
    p.icmp.checksum = in_cksum((uint16_t*)&p, iov.iov_len);
 
    if (0> (bs = sendmsg (_sock, &m, 0))) 
    {
	   perror ("ERROR: sendmsg ()");
    }

    memset(&p, 0, sizeof(struct Packet));
    memset(&iov, 0, sizeof(struct iovec));
    memset(&m, 0, sizeof(struct msghdr));
    return bs;
}



int CSocket::recv_data_RAW(char* recv_buf, struct sockaddr_in & ser_addr )
{
    return recv_data_UDP(recv_buf, ser_addr);
}


int CSocket::recv_data_UDP(char* recv_buf,  struct sockaddr_in& si_other)
{
    if(!is_alive())
	return -1;
    char buf[MAX_BUF_SIZE];
    memset(buf,0,MAX_BUF_SIZE);
    socklen_t addr_len=sizeof(sockaddr_in);

    int recv_ret= ::recvfrom(_sock, buf ,MAX_BUF_SIZE-1,0, (struct sockaddr*)&si_other, &addr_len);
    if(recv_ret==-1)
    {
	perror("recvfrom error:\t");
    }
    else
    {
	if(recv_ret>0)
	    memcpy(recv_buf,buf,MAX_BUF_SIZE);
    }
    return recv_ret;
}


bool CSocket::accept(CSocket& new_sock)
{
    if(!is_alive())
	return false;
    sockaddr_in client_addr;
    socklen_t   addr_len=sizeof(client_addr);
    int client_sock;
    client_sock= ::accept(_sock,(sockaddr*)&client_addr,&addr_len);
    if(client_sock<=0)
	return false;
    else
    {
	new_sock._sock=client_sock;
	memcpy(&(new_sock._addr),&client_addr,sizeof(client_addr));
	return true;
    }
}

bool CSocket::set_socket_nonblock(bool nonblock)
{
    int opts;
    if(!is_alive())
	return false;
    opts = fcntl ( _sock, F_GETFL );
    if ( opts < 0 )
	return false;
    if(nonblock)
	opts = ( opts | O_NONBLOCK );
    else
	opts = ( opts & ~O_NONBLOCK );
    fcntl ( _sock,F_SETFL,opts );
    return true;
}


bool CSocket::set_socket_fill_ipheader(bool on)
{
    if(setsockopt(_sock, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0)
    {
	perror("setsockopt() for IP_HDRINCL error");
	return false;
    }
    return true;
}


bool CSocket::set_socket_bind_dev(char* dev)
{
    ifreq Interface; 
    memset(&Interface, 0, sizeof(Interface)); 
    strncpy(Interface.ifr_ifrn.ifrn_name, dev, IFNAMSIZ); 
    if (setsockopt(_sock, SOL_SOCKET, SO_BINDTODEVICE, &Interface, sizeof(Interface)) < 0) 
    { 

	perror("setsockopt() for SO_BINDTODEVICE error");
	return false;
    }
    return true;
}


bool CSocket::connect(const char* serv_host,const int port)
{
    if(!is_alive())
	return false;

    struct sockaddr_in serv_addr;
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(port);
    if(serv_host==NULL)
    {
	serv_addr.sin_addr.s_addr=htonl(INADDR_ANY);
    }
    else
    {
	serv_addr.sin_addr.s_addr=inet_addr(serv_host);
    }

    if( ::connect(_sock,(sockaddr*)&serv_addr, sizeof(serv_addr))==-1)
    {
	perror("Connect failed\t");
	return false;
    }
    else
    {
	memcpy(&(_addr),&serv_addr,sizeof(serv_addr));
	return true;
    }
}


/*
 *print icmp header, steal from http://www.binarytides.com/packet-sniffer-code-in-c-using-linux-sockets-bsd/
 */
void print_icmp_packet(char* Buffer , int Size)
{
    unsigned short iphdrlen;
    struct iphdr *iph = (struct iphdr *)Buffer;
    iphdrlen = iph->ihl*4;
    struct icmphdr *icmph = (struct icmphdr *)(Buffer + iphdrlen);
    printf("\n***********************ICMP Packet*************************\n");  
    print_ip_header(Buffer , Size);
    printf("ICMP Header\n");
    printf("   |-Type : %d",(icmph->type));
    if((unsigned int)(icmph->type) == 11)
	printf("  (TTL Expired)\n");
    else if((unsigned int)(icmph->type) == ICMP_ECHOREPLY)
	printf("  (ICMP Echo Reply)\n");
    printf("   |-Code : %d\n",(unsigned int)(icmph->code));
    printf("   |-Checksum : %d\n",ntohs(icmph->checksum));
    //printf("   |-ID       : %d\n",ntohs(icmph->id));
    //printf("   |-Sequence : %d\n",ntohs(icmph->sequence));
    printf("\n");

}
    

/*
 *print ip header, steal from http://www.binarytides.com/packet-sniffer-code-in-c-using-linux-sockets-bsd/
 */
void print_ip_header(char* Buffer, int Size)
{
    //unsigned short iphdrlen;
    struct sockaddr_in source,dest;

    struct iphdr *iph = (struct iphdr *)Buffer;
    //iphdrlen =iph->ihl*4;
    memset(&source, 0, sizeof(source));

    source.sin_addr.s_addr = iph->saddr;
    memset(&dest, 0, sizeof(dest));
    dest.sin_addr.s_addr = iph->daddr;

    printf("IP Header\n");
    printf("   |-IP Version        : %d\n",(unsigned int)iph->version);
    printf("   |-IP Header Length  : %d DWORDS or %d Bytes\n",(unsigned int)iph->ihl,((unsigned int)(iph->ihl))*4);
    printf("   |-Type Of Service   : %d\n",(unsigned int)iph->tos);
    printf("   |-IP Total Length   : %d  Bytes(Size of Packet)\n",ntohs(iph->tot_len));
    printf("   |-Identification    : %d\n",ntohs(iph->id));

    printf("   |-TTL      : %d\n",(unsigned int)iph->ttl);
    printf("   |-Protocol : %d\n",(unsigned int)iph->protocol);
    printf("   |-Checksum : %d\n",ntohs(iph->check));
    printf("   |-Source IP        : %s\n",inet_ntoa(source.sin_addr));
    printf("   |-Destination IP   : %s\n",inet_ntoa(dest.sin_addr));
}

void print_tcp_packet(char* Buffer, int Size)
{

    unsigned short iphdrlen;
    struct iphdr *iph = (struct iphdr *)Buffer;
    iphdrlen = iph->ihl*4;
    struct tcphdr *tcph=(struct tcphdr*)(Buffer + iphdrlen);

    printf("\n***********************TCP Packet*************************\n");   
    print_ip_header(Buffer,Size);
    printf("TCP Header\n");
    printf("   |-Source Port      : %u\n",ntohs(tcph->source));
    printf("   |-Destination Port : %u\n",ntohs(tcph->dest));
    printf("   |-Sequence Number    : %u\n",ntohl(tcph->seq));
    printf("   |-Acknowledge Number : %u\n",ntohl(tcph->ack_seq));
    printf("   |-Header Length      : %d DWORDS or %d BYTES\n" ,(unsigned int)tcph->doff,(unsigned int)tcph->doff*4);
    //fprintf(logfile,"   |-CWR Flag : %d\n",(unsigned int)tcph->cwr);
    //fprintf(logfile,"   |-ECN Flag : %d\n",(unsigned int)tcph->ece);
    printf("   |-Urgent Flag          : %d\n",(unsigned int)tcph->urg);
    printf("   |-Acknowledgement Flag : %d\n",(unsigned int)tcph->ack);
    printf("   |-Push Flag            : %d\n",(unsigned int)tcph->psh);
    printf("   |-Reset Flag           : %d\n",(unsigned int)tcph->rst);
    printf("   |-Synchronise Flag     : %d\n",(unsigned int)tcph->syn);
    printf("   |-Finish Flag          : %d\n",(unsigned int)tcph->fin);
    printf("   |-Window         : %d\n",ntohs(tcph->window));
    printf("   |-Checksum       : %d\n",ntohs(tcph->check));
    printf("   |-Urgent Pointer : %d\n",tcph->urg_ptr);
    printf("\n");
}

void print_udp_packet(char *Buffer , int Size)
{
    unsigned short iphdrlen;
    struct iphdr *iph = (struct iphdr *)Buffer;
    iphdrlen = iph->ihl*4;
    struct udphdr *udph = (struct udphdr*)(Buffer + iphdrlen);
    printf("\n***********************UDP Packet*************************\n");
    print_ip_header(Buffer,Size);          
    printf("\nUDP Header\n");
    printf("   |-Source Port      : %d\n" , ntohs(udph->source));
    printf("   |-Destination Port : %d\n" , ntohs(udph->dest));
    printf("   |-UDP Length       : %d\n" , ntohs(udph->len));
    printf("   |-UDP Checksum     : %d\n" , ntohs(udph->check));
    printf("\n");

}



/*
 * compute checksume
 */
unsigned short in_cksum(unsigned short *addr, int len)
{
    register int sum = 0;
    u_short answer = 0;
    register u_short *w = addr;
    register int nleft = len;
	  
    while (nleft > 1)
    {
	sum += *w++;
	nleft -= 2;
    }
    /* mop up an odd byte, if necessary */
    if (nleft == 1)
    {
	*(u_char *) (&answer) = *(u_char *) w;
	sum += answer;
    }
    /* add back carry outs from top 16 bits to low 16 bits */
    sum = (sum >> 16) + (sum & 0xffff);       /* add hi 16 to low 16 */
    sum += (sum >> 16);               /* add carry */
    answer = ~sum;              /* truncate to 16 bits */
    return (answer);
}

unsigned short csum(unsigned short *ptr,int nbytes) 
{
    register long sum;
    unsigned short oddbyte;
    register short answer;
 
    sum=0;
    while(nbytes>1) {
        sum+=*ptr++;
        nbytes-=2;
    }
    if(nbytes==1) {
        oddbyte=0;
        *((u_char*)&oddbyte)=*(u_char*)ptr;
        sum+=oddbyte;
    }
 
    sum = (sum>>16)+(sum & 0xffff);
    sum = sum + (sum>>16);
    answer=(short)~sum;
     
    return(answer);
}

unsigned short in_cksum_tcp(int src, int dst, unsigned short *addr, int len)
{
    struct pseudo_header psh;

    psh.source_address = src;
    psh.dest_address = dst;
    psh.placeholder = 0;
    psh.protocol = IPPROTO_TCP;
    psh.tcp_length = htons(len );
    char* pseudogram;

    int psize = sizeof(struct pseudo_header) + len;
    pseudogram = (char *) malloc(psize);
     
    memcpy(pseudogram , (char*) &psh , sizeof (struct pseudo_header));
    memcpy(pseudogram + sizeof(struct pseudo_header) , addr , len);
     
    return csum( (unsigned short*) pseudogram , psize);

    // struct psd_tcp buf;
    // u_short ans;

    // memset(&buf, 0, sizeof(buf));
    // buf.src.s_addr = src;
    // buf.dst.s_addr = dst;
    // buf.pad = 0;
    // buf.proto = IPPROTO_TCP;
    // buf.tcp_len = htons(len);
    // memcpy(&(buf.tcp), addr, len);
    // ans = in_cksum((unsigned short *)&buf, 12 + len);
    // return (ans);
}


/*
 * read data until the end
 */
int sread(int fd, char *buf, int bufsize)
{
    int	nRecvbytes = 0;
    char szRecvbyte[1];
    int recvdlength = 0;
    int nRecvbufsize = bufsize;
    while(nRecvbufsize > 0)
    {
	if ((nRecvbytes = read(fd, szRecvbyte, 1)) < 0)
	    return -1;
	if (nRecvbytes > 0)
	{
	    buf[recvdlength] = szRecvbyte[0];
	    recvdlength += nRecvbytes;
	    nRecvbufsize -= nRecvbytes;
	    if (szRecvbyte[0] == '\n')
	    {
		break;
	    }
	}
	if (nRecvbytes == 0)
	    break;
    }
    if (nRecvbufsize == 0 && buf[recvdlength-1] != '\n')
	return -2;
    else
	return recvdlength;
}

int get_all_interface_ip(struct router_info* rinfo)
{
    int fd;
    struct if_nameindex *curif, *ifs;
    struct ifreq req;
    if((fd = socket(PF_INET, SOCK_DGRAM, 0)) != -1) 
    {
	ifs = if_nameindex();
	if(ifs)
	{
	    for(curif = ifs; curif && curif->if_name; curif++)
	    {
		strncpy(req.ifr_name, curif->if_name, IFNAMSIZ);
		req.ifr_name[IFNAMSIZ] = 0;
		if (ioctl(fd, SIOCGIFADDR, &req) < 0)
		    perror("ioctl");
		else
		{
		    //printf("%s: [%s]\n", curif->if_name, inet_ntoa(((struct sockaddr_in*) &req.ifr_addr)->sin_addr));
		    if(strncmp(curif->if_name,"ethX",3)==0)
		    {
			char eth_num[2];
			memset(eth_num,0,2);
			strncpy(eth_num,curif->if_name+3,1);
			int index = atoi(eth_num);
			if(index>=MAX_ROUTER_COUNT)
			    printf("Exceed the max number of routers\n");
			else
			{
			    rinfo[index].nIP =  (((struct sockaddr_in*) &req.ifr_addr)->sin_addr).s_addr;
			}
		    }
		}
	    }
	    if_freenameindex(ifs);
	    if(close(fd)!=0)
	    {
		perror("close");
	    }
	}
	else
	{
	    perror("if_nameindex");
	    return 0;
	}
    }
    else
    {
	perror("socket");
	return 0;
    }
    return 1;
}

int compute_circuit_id(int index, int seq)
{
    return (index*256+seq);
}

int construct_relay_msg(char*buf, int buf_len,  unsigned short cID, char*payload, int payload_len, int msg_type, int stage, int flowNumber)
{
    struct iphdr * iph = (struct iphdr *)buf;
    struct cc_relay_msg * ccrelaymsg = ( struct cc_relay_msg *)(iph+1);
    
    iph->protocol = CC_EXT_PROTOCOL;
    // use loop address 
    iph->saddr = inet_addr("127.0.0.1");
    iph->daddr = inet_addr("127.0.0.1");
    iph->tos = flowNumber;
    if(stage == 9)
    {
        iph->ttl = 1;
    }
    if(stage == 10)
    {
        iph->ttl = 2;
    }
    //printf("Putting in flowNumber: %d", iph->tos);
    //iph->check = in_cksum((unsigned short*)buf, sizeof(struct iphdr));

    // msg type: 0x51
    ccrelaymsg->msg_type = msg_type;
    // circuit ID
    ccrelaymsg->cid = htons(cID);
    
    if(stage == 5)
    {
	struct iphdr * riph = (struct iphdr *)(payload);
	riph->check = 0 ;
	riph->check = in_cksum((unsigned short*)payload, sizeof(struct iphdr));
    }
    

    int hlen = sizeof(struct iphdr) + sizeof(struct cc_relay_msg);
    memcpy(buf+hlen, payload, payload_len);
    return (hlen + payload_len);
}


void encrypt_msg(char* inbuf,char* outbuf, int buflen, unsigned char key[])
{
    AES_KEY enc_key;
    class_AES_set_encrypt_key(key, (AES_KEY *)&enc_key);
    class_AES_encrypt((unsigned char*)inbuf, (unsigned char*)outbuf, buflen, (AES_KEY *)&enc_key);
}

void decrypt_msg(char* inbuf,char* outbuf, int buflen, unsigned char key[])
{

    AES_KEY dec_key;
    class_AES_set_decrypt_key(key, (AES_KEY *)&dec_key);
    class_AES_decrypt((unsigned char*)inbuf, (unsigned char*)outbuf, buflen, (AES_KEY *)&dec_key);
}


void encrypt_msg_with_padding(char* inbuf, int inlen, char** outbuf, int* outlen, unsigned char key[])
{
    AES_KEY enc_key;
    class_AES_set_encrypt_key(key, (AES_KEY *)&enc_key);
    class_AES_encrypt_with_padding((unsigned char*)inbuf, inlen,(unsigned char**) outbuf, outlen, (AES_KEY *)&enc_key);
}

void decrypt_msg_with_padding(char* inbuf, int inlen, char** outbuf, int* outlen, unsigned char key[])
{

    AES_KEY dec_key;
    class_AES_set_decrypt_key(key, (AES_KEY *)&dec_key);
    class_AES_decrypt_with_padding((unsigned char*)inbuf, inlen,(unsigned char**) outbuf, outlen, (AES_KEY *)&dec_key);

}


int key_to_hex_buf(unsigned char* key, char* buf, int len)
{
    int index = 0;
    for(int i=0; i< len ;i++)
    {
	index += sprintf(buf+index, "%02x", key[i]);
    }
    index += sprintf(buf+index, "\n");
    return index;
}

void print_packet_hex(char* buf, int len)
{
    char log_buf[MAX_BUF_SIZE];
    memset(log_buf, 0, MAX_BUF_SIZE);
    int index=0;
    index += sprintf(log_buf, "buf length: %d, contents: 0x", len);
    for(int i=0; i<len; i++)
    {
	index += sprintf(log_buf+index, "%02x", (unsigned char)buf[i]);
    }
    sprintf(log_buf+index, "\n");
    printf(log_buf);
}
