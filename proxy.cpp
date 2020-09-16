#include "proxy.h"
#include "router.h"



using namespace std;

/**************************************************************************
 * tun_alloc: allocates or reconnects to a tun/tap device. 
 * steal from simpletun.c
 * refer to http://backreference.org/2010/03/26/tuntap-interface-tutorial/ for more info 
 **************************************************************************/

int tun_alloc(char *dev, int flags) 
{

  struct ifreq ifr;
  int fd, err;
  char *clonedev = (char*)"/dev/net/tun";

  if( (fd = open(clonedev , O_RDWR)) < 0 ) {
    perror("Opening /dev/net/tun");
    return fd;
  }

  memset(&ifr, 0, sizeof(ifr));

  ifr.ifr_flags = flags;

  if (*dev) {
    strncpy(ifr.ifr_name, dev, IFNAMSIZ);
  }

  if( (err = ioctl(fd, TUNSETIFF, (void *)&ifr)) < 0 ) {
    perror("ioctl(TUNSETIFF)");
    close(fd);
    return err;
  }

  strcpy(dev, ifr.ifr_name);
  return fd;
}

/*
 * print error to stderr
 */
void print_err(char *msg, ...) {
  va_list argp;
  va_start(argp, msg);
  vfprintf(stderr, msg, argp);
  va_end(argp);
}


/*
 * split string 
 */
void SplitString(char* cStr, char* cDelim, vector<string> &sItemVec)
{
    char *p;
    p=strtok(cStr,cDelim);
    while (p!=NULL)
    {
	sItemVec.push_back(p);
	p=strtok(NULL,cDelim);
    }
}


CProxy::CProxy()
{
    _stage=0;
    _num_nodes=0;
    _num_hops=0;
    _cc_seq = 2;
    _tun_fd=-1;
    _sock_fd=-1;

    flowCount=0;
    flowNumber=0;
    totalCircuitCount=0;

    unsigned char key[KEY_LEN];
    memset(key, 0,KEY_LEN);
    generate_random_key(key,  KEY_LEN);
}

CProxy::~CProxy()
{
    close(_tun_fd);
    _sock_fd=-1;
}

bool CProxy::get_all_interface_info()
{
    memset(rinfo,0,sizeof(struct router_info)*MAX_ROUTER_COUNT);
    int ret = get_all_interface_ip(rinfo);
    for(int i=0; i<MAX_ROUTER_COUNT;i++)
    {
	struct sockaddr_in addr;
	addr.sin_addr.s_addr = rinfo[i].nIP;
	printf("index:%d, IP:%s\n",i,inet_ntoa(addr.sin_addr));
    }
    if(ret>0)
	return true;
    else
	return false;
}

bool CProxy::initialize_configure(char* config_fn)
{
    FILE* config_fp=fopen(config_fn,"r");
    if(!config_fp)
    {
    	printf("Open config file:%s failed \n",config_fn);
    	return false;
    }

    char buffer[MAX_BUF_SIZE];
    vector<string> sItem;
    char delim[]=" \t";
    while(!feof(config_fp))
    {
	memset(buffer,0,MAX_BUF_SIZE);
	if(fgets(buffer,MAX_BUF_SIZE,config_fp))
	{
	    buffer[strlen(buffer)-1]='\0';
	    if(buffer[0]=='#')
		continue;
	    sItem.clear();
	    SplitString(buffer,delim,sItem);
	    if(sItem.size()<2)
		continue;
	    else
	    {
    		if(sItem[0]=="stage")
    		   _stage=atoi(sItem[1].c_str());
    		if(sItem[0]=="num_routers")
    		    _num_nodes=atoi(sItem[1].c_str());
    		if(sItem[0]=="minitor_hops")
                _num_hops=atoi(sItem[1].c_str());
            if(sItem[0]=="die_after")
                _die_after=atoi(sItem[1].c_str());
	    }

	}
    }
    printf("Stage:%d\t Nodes:%d\t Hops: %lu\n",_stage,_num_nodes,_num_hops);
    fclose(config_fp);
    
    memset(_logfn,0,MAX_FN_LEN);
    sprintf(_logfn,"stage%d.proxy.out",_stage);
    FILE* logfp=fopen(_logfn,"w");
    if(!logfp)
    {
	printf("Open Log File:%s failed \n",_logfn);

    }
    fclose(logfp);
    return true;
}

void CProxy::output_log(char* out_str)
{
    FILE* logfp=fopen(_logfn,"a");
    if(!logfp)
    {
	printf("Open Log File:%s failed \n",_logfn);
	return;

    }
    fputs(out_str,logfp);
    fflush(logfp);
    fclose(logfp);
}


bool CProxy::initialize_tun(char* tun_fn, const int flags)
{
    _tun_fd = tun_alloc(tun_fn, flags | IFF_NO_PI);
    if(_tun_fd<0)
    {
	printf("Error connecting to tun interface %s!\n", tun_fn);
	return false;
    }
    else
	return true;
}


bool CProxy::initialize_socket()
{
    bool status=true;
    status &= _mysock.create(SOCK_DGRAM,0);
    status &= _mysock.bind(0);
    if(status)
    {
	char out_buf[MAX_BUF_SIZE];
	sprintf(out_buf,"proxy port: %d\n", ntohs((_mysock._addr).sin_port));
	printf(out_buf);
	output_log(out_buf);
    }
    else
    {
	return false;
    }

    _sock_fd=_mysock._sock;
    return status;
}


void CProxy::accept_connection()
{
   
    if(!(_mysock.is_alive()))
    {
	printf("manager socket is dead\n");
	return;
    }
    
    
    
    char out_buf[MAX_BUF_SIZE];
    int i=0;
    int newconn_pid;
    while(i<_num_nodes)
    {
	CSocket client_sock;
	bool status=_mysock.accept(client_sock);
	if(!status)
	    continue;
	
	if((newconn_pid=fork())==0)
	{
	    _mysock.close();
	    char send_buf[MAX_BUF_SIZE];
	    char recv_buf[MAX_BUF_SIZE];
	    memset(out_buf,0,MAX_BUF_SIZE);
	    sprintf(out_buf,"client %d port: %d\n",i+1,(int)ntohs((client_sock._addr).sin_port));
	    printf(out_buf);
	    output_log(out_buf);
	    sprintf(send_buf,"%lu\n",_num_hops);
	    client_sock.send_data(send_buf);
	    client_sock.recv_data(recv_buf);
	    memset(out_buf,0,MAX_BUF_SIZE);
	    sprintf(out_buf,"client %d says: %s",i+1,recv_buf);
	    printf(out_buf);
	    output_log(out_buf);
	    client_sock.close();
	    exit(0);

	}
	i++;
    }	
}

//fork routers
bool CProxy::fork_router()
{
    int pid;
    int i=0;

    for(i=0;i<_num_nodes;i++)
    {
	if((pid=fork())==0)
	{
	    /*
	     * fork routers, and tell them the stage number, as well as router index, proxy port, and router's IP.
	     */

	    CRouter *router=new CRouter(_stage, i+1,  _mysock._addr, rinfo[i+1].nIP);
	    bool status = router->initialize_socket();
	    status &= router->initialize_rawsocket();
	    status &= router->initialize_tcpsocket();

	    
	    char send_buf[MAX_BUF_SIZE];
	    int client_pid=getpid();
	    if(status)
	    {
		memset(send_buf,0,MAX_BUF_SIZE);
		struct up_msg* upmsg = (struct up_msg *)send_buf;
		upmsg->_pid = htons(client_pid);
		upmsg->_index = htons(i+1);
		router->send_data_UDP(send_buf, sizeof(struct up_msg), _mysock._addr);

	    }
	    else
	    {
		printf("**Router** %d, PID: %d, failed initialize socket\n", i+1, pid);
	    }
	    
	    router->run();
	    delete router;
	    exit(0);
	}
    }
    return true;
 }

void CProxy::handle_tun_tcp_traffic(char* buf, int len)
{

    struct sockaddr_in source,dest;
    char log_buf[MAX_BUF_SIZE];
    char send_buf[MAX_PACKET_SIZE];
    memset(send_buf,0, MAX_PACKET_SIZE);

    char src_addr_buf[MAX_BUF_SIZE];
    char dst_addr_buf[MAX_BUF_SIZE];
    printf("\nSending Tcp packet to router: \n");   
    int nsend=0;
    //print_tcp_packet(buf,len);
    struct iphdr *iph = (struct iphdr *)buf;
    unsigned short iphdrlen;
    iphdrlen = iph->ihl*4;
    struct tcphdr *tcph=(struct tcphdr*)(buf + iphdrlen);

    source.sin_addr.s_addr = iph->saddr;
    dest.sin_addr.s_addr = iph->daddr;
    memset(log_buf, 0, MAX_BUF_SIZE);
    memset(src_addr_buf, 0, MAX_BUF_SIZE);
    memset(dst_addr_buf, 0, MAX_BUF_SIZE);
    strcpy(src_addr_buf, inet_ntoa(source.sin_addr));
    strcpy(dst_addr_buf, inet_ntoa(dest.sin_addr));
    printf("   |-Source Port      : %u\n",ntohs(tcph->source));
    
    sprintf(log_buf, "TCP from tunnel, src IP/port: %s:%u, dst IP/port: %s:%u, seqno: %u, ackno: %u\n",src_addr_buf,ntohs(tcph->source), dst_addr_buf,ntohs(tcph->dest),ntohs(tcph->seq),ntohs(tcph->ack_seq));
    output_log(log_buf);
    int rindex=0;
    memcpy(send_buf, buf, len);
    if(_stage < 5)
    {
        if(_stage == 3)
            rindex = 1;
        else
            rindex =  ((ntohl(iph->daddr)) % _num_nodes) + 1;
        printf("router index:%d\n", rindex);
        nsend = send_data_UDP(send_buf, len, rinfo[rindex].r_addr);
    }
    else
    {
        unsigned short cID = compute_circuit_id(0, flowNumber+1);
        printf("**Proxy** Circuit: %d", cID);
        int packet_len;
        if(_stage == 5)
        {
            packet_len  = construct_relay_msg(send_buf, MAX_PACKET_SIZE, cID, buf, len, CC_RELAY_MSGTYPE, _stage, flowNumber);
        }

        if (_stage >= 6)
        {
        //remember the old src addr;
        _old_src = iph->saddr;

        //zero the src addr and recompute the checksum;
        iph->saddr = htonl(0);
        iph->check = 0;
        iph->check = in_cksum((unsigned short*)iph, sizeof(struct iphdr));

        //encrypt the entire packet with keys of all routers in the path
        int elen;
        char* ebuf =NULL;
        //print the content of the packet, only for debug
        print_packet_hex(buf, len);
        encrypt_multiround_with_padding(buf, len, &ebuf, &elen, _num_hops);
        //print the content of the packet, only for debug
        print_packet_hex(ebuf, elen);

        //construct the relay message
        printf("Constructing relay message with flow: %d\n",flowNumber);
        packet_len  = construct_relay_msg(send_buf, MAX_PACKET_SIZE, cID, ebuf, elen, CC_ENCRYPTED_RELAY, _stage, flowNumber);
        delete [] ebuf;
        }
        nsend = send_data_UDP(send_buf, packet_len, rinfo[path[0]].r_addr);
    }
    if(nsend <=0)
    {
        printf("**Proxy** failed send packet via UDP\n");
    }
}

// handle icmp traffic from tunnel interface
void CProxy::handle_tun_icmp_traffic(char* buf, int len)
{

    struct sockaddr_in source,dest;
    char log_buf[MAX_BUF_SIZE];
    char send_buf[MAX_PACKET_SIZE];
    memset(send_buf,0, MAX_PACKET_SIZE);

    char src_addr_buf[MAX_BUF_SIZE];
    char dst_addr_buf[MAX_BUF_SIZE];

    int nsend=0;
    //print_icmp_packet(buf,len);
    struct iphdr *iph = (struct iphdr *)buf;
    
    unsigned short iphdrlen;
    iphdrlen = iph->ihl*4;
    struct icmphdr *icmph = (struct icmphdr *)(buf + iphdrlen);


    source.sin_addr.s_addr = iph->saddr;
    dest.sin_addr.s_addr = iph->daddr;
    memset(log_buf, 0, MAX_BUF_SIZE);
    memset(src_addr_buf, 0, MAX_BUF_SIZE);
    memset(dst_addr_buf, 0, MAX_BUF_SIZE);
    strcpy(src_addr_buf, inet_ntoa(source.sin_addr));
    strcpy(dst_addr_buf, inet_ntoa(dest.sin_addr));

    sprintf(log_buf, "ICMP from tunnel, src: %s, dst: %s, type: %d\n",src_addr_buf, dst_addr_buf, icmph->type);

    output_log(log_buf);

    if(icmph->type == ICMP_ECHO)
    {
    	if(_stage < 5)
    	{
    	    /* send to router via UDP socket */
    	    int rindex=0;
    	    memcpy(send_buf, buf, len);
    	    if(_stage == 3)
    		rindex = 1;
    	    else
    		rindex =  ((ntohl(iph->daddr)) % _num_nodes) + 1;
    	    printf("router index:%d\n", rindex);
    	    nsend = send_data_UDP(send_buf, len, rinfo[rindex].r_addr);
        }
    	else
    	{
    	    unsigned short cID = compute_circuit_id(0, flowNumber+1);
    	    int packet_len;
    	    if(_stage == 5)
    	    {
    	    	packet_len  = construct_relay_msg(send_buf, MAX_PACKET_SIZE, cID, buf, len, CC_RELAY_MSGTYPE, _stage, flowNumber);
    	    }

    	    if (_stage >= 6)
    	    {
    		//remember the old src addr;
    		_old_src = iph->saddr;

    		//zero the src addr and recompute the checksum;
    		iph->saddr = htonl(0);
    		iph->check = 0;
    		iph->check = in_cksum((unsigned short*)iph, sizeof(struct iphdr));

    		//encrypt the entire packet with keys of all routers in the path
    		int elen;
    		char* ebuf =NULL;
    		//print the content of the packet, only for debug
    		print_packet_hex(buf, len);
    		encrypt_multiround_with_padding(buf, len, &ebuf, &elen, _num_hops);
    		//print the content of the packet, only for debug
    		print_packet_hex(ebuf, elen);

    		//construct the relay message
    		packet_len  = construct_relay_msg(send_buf, MAX_PACKET_SIZE, cID, ebuf, elen, CC_ENCRYPTED_RELAY, _stage, flowNumber);
    		delete [] ebuf;
    	    }
    	    nsend = send_data_UDP(send_buf, packet_len, rinfo[path[0]].r_addr);
    	}

    	if(nsend <=0)
        {
            printf("**Proxy** failed send packet via UDP\n");
        }

    }
}

void CProxy::handle_router_tcp_traffic(char* buf, int len, struct sockaddr_in si_other)
{
    struct sockaddr_in source,dest;
    char log_buf[MAX_BUF_SIZE];
    char src_addr_buf[MAX_BUF_SIZE];
    char dst_addr_buf[MAX_BUF_SIZE];

    int nsend=0;


    struct iphdr *iph = (struct iphdr *)buf;
    unsigned short iphdrlen;
    iphdrlen = iph->ihl*4;
    struct tcphdr *tcph=(struct tcphdr*)(buf + iphdrlen);

    
    //print_icmp_packet(recv_buf,nread);
    source.sin_addr.s_addr = iph->saddr;
    dest.sin_addr.s_addr = iph->daddr;
    memset(log_buf, 0, MAX_BUF_SIZE);
    memset(src_addr_buf, 0, MAX_BUF_SIZE);
    memset(dst_addr_buf, 0, MAX_BUF_SIZE);
    strcpy(src_addr_buf, inet_ntoa(source.sin_addr));
    strcpy(dst_addr_buf, inet_ntoa(dest.sin_addr));


    iph->check = in_cksum((unsigned short*)iph, sizeof(struct iphdr));

    printf("Size of packet: %d", len);
    printf("Size of iphdr: %lu", sizeof(iphdr));
    printf("Size of tcphdr: %lu", sizeof(tcphdr));
    unsigned long int lens = len - sizeof(iphdr);
    printf("Difference: %lu",lens);
    // identifying the port no of Proxy 
    

    tcph->check=0;
    struct pseudo_header psh;
    char* pseudogram;

    psh.source_address = iph->saddr ;
    psh.dest_address = iph->daddr;
    psh.placeholder = 0;
    psh.protocol = IPPROTO_TCP;
    psh.tcp_length = htons(len - sizeof(iphdr));
     
    int psize = sizeof(struct pseudo_header) + lens;
    pseudogram = (char*)malloc(psize);
     
    memcpy(pseudogram , (char*) &psh , sizeof (struct pseudo_header));
    memcpy(pseudogram + sizeof(struct pseudo_header) , tcph , lens);
     
    tcph->check = csum( (unsigned short*) pseudogram , psize);

    sprintf(log_buf, "TCP from tunnel, src IP/port: %s:%u, dst IP/port: %s:%u, seqno: %u, ackno: %u\n",src_addr_buf,ntohs(tcph->source), dst_addr_buf,ntohs(tcph->dest),ntohs(tcph->seq),ntohs(tcph->ack_seq));
    output_log(log_buf);

    
    /* write received packet to tun */
    nsend = write_data_TUN(buf, _tun_fd, len);
    if(nsend <=0 )
    {
        printf("**Proxy** failed write packet to tun\n");
    }

}

//handle icmp packet from routers
void CProxy::handle_router_icmp_traffic(char* buf, int len, struct sockaddr_in si_other)
{
    struct sockaddr_in source,dest;
    char log_buf[MAX_BUF_SIZE];
    char src_addr_buf[MAX_BUF_SIZE];
    char dst_addr_buf[MAX_BUF_SIZE];

    int nsend=0;


    struct iphdr *iph = (struct iphdr *)buf;
    unsigned short iphdrlen;
    iphdrlen = iph->ihl*4;
    struct icmphdr *icmph = (struct icmphdr *)(buf + iphdrlen);
	
    //print_icmp_packet(recv_buf,nread);
    source.sin_addr.s_addr = iph->saddr;
    dest.sin_addr.s_addr = iph->daddr;
    memset(log_buf, 0, MAX_BUF_SIZE);
    memset(src_addr_buf, 0, MAX_BUF_SIZE);
    memset(dst_addr_buf, 0, MAX_BUF_SIZE);
    strcpy(src_addr_buf, inet_ntoa(source.sin_addr));
    strcpy(dst_addr_buf, inet_ntoa(dest.sin_addr));

    sprintf(log_buf, "ICMP from port: %d, src: %s, dst: %s, type: %d\n",ntohs(si_other.sin_port), src_addr_buf, dst_addr_buf, icmph->type);
    output_log(log_buf);

	
    /* write received packet to tun */
    nsend = write_data_TUN(buf, _tun_fd, len);
    if(nsend <=0 )
    {
        printf("**Proxy** failed write packet to tun\n");
    }

}


void CProxy::handle_relay_msg(char* buf, int len, struct sockaddr_in si_other)
{
    char log_buf[MAX_BUF_SIZE];
    char send_buf[MAX_PACKET_SIZE];
    char ssi[MAX_BUF_SIZE];
    char sdest[MAX_BUF_SIZE];
    struct sockaddr_in si,dest;


    memset(send_buf,0, MAX_PACKET_SIZE);
    int nsend;

    struct iphdr *iph = (struct iphdr *)buf;
    struct cc_relay_msg * ccrelaymsg = (struct cc_relay_msg*)(iph+1);
    unsigned short iID = ntohs(ccrelaymsg->cid);

    struct iphdr *riph = (struct iphdr *)(ccrelaymsg+1);
   

    print_buf_hex((char*)ccrelaymsg, len-(sizeof(struct iphdr)), ntohs(si_other.sin_port)); 
 
    int hlen =  sizeof(struct iphdr) + sizeof(struct cc_relay_msg);
    int plen = len - hlen; 
    int clen;
    if(_stage >= 6)
    {

	
	char * clear_packet;
	//decrypt the packet with keys of all routers in the path.
	decrypt_multiround_with_padding(buf+hlen, plen, &clear_packet, &clen, _num_hops);
	memcpy(buf+hlen, clear_packet, clen);
	//check if the packet is correct, only for debug 
	//print_tcp_packet(buf+hlen, clen);
	//change destination IP and recompute checksum;
	riph->daddr  = _old_src;
	//print_icmp_packet(buf+hlen, clen);
	len = hlen + clen;
	delete [] clear_packet;

    }

    struct iphdr *iph_t= (struct iphdr *)(buf+hlen);
    unsigned short iphdrlen;
    iphdrlen = iph_t->ihl*4;
    struct tcphdr *tcph_t=(struct tcphdr*)(buf + iphdrlen + hlen);

    printf(" Size of packet: %d", len - hlen);
    printf(" Size of iphdr: %lu", sizeof(iphdr));
    printf(" Size of tcphdr: %lu", sizeof(tcphdr));
    unsigned long int lens = len -hlen- sizeof(iphdr);
    printf(" Difference: %lu",lens);
    // identifying the port no of Proxy 
    iph_t->check = 0;
    iph_t->check = in_cksum((unsigned short*)iph_t, sizeof(struct iphdr));
    tcph_t->check=0;
    struct pseudo_header psh;
    char* pseudogram;

    psh.source_address = iph_t->saddr ;
    psh.dest_address = iph_t->daddr;
    psh.placeholder = 0;
    psh.protocol = IPPROTO_TCP;
    psh.tcp_length = htons(len -hlen - sizeof(iphdr));
     
    int psize = sizeof(struct pseudo_header) + lens;
    pseudogram = (char*)malloc(psize);
     
    memcpy(pseudogram , (char*) &psh , sizeof (struct pseudo_header));
    memcpy(pseudogram + sizeof(struct pseudo_header) , tcph_t , lens);
     
    tcph_t->check = csum( (unsigned short*) pseudogram , psize);

    
    // identifying the port no of Proxy 
    
    /* write received packet to tun */
    nsend = write_data_TUN(buf+hlen, _tun_fd, len-hlen);
    if(nsend <=0 )
    {
	   printf("**Proxy** failed write packet to tun\n");
    }

    //log
    si.sin_addr.s_addr = riph->saddr;
    dest.sin_addr.s_addr = riph->daddr;
    strcpy(ssi, inet_ntoa(si.sin_addr));
    strcpy(sdest, inet_ntoa(dest.sin_addr));

    memset(log_buf, 0, MAX_BUF_SIZE);
    if(iph_t-> protocol == 6)
    {
        sprintf(log_buf, "incoming TCP packet, circuit incoming: 0x%d, src IP/port: %s:%u, dst IP/port: %s:%u, seqno: %u, ackno: %u\n", iID, ssi,ntohs(tcph_t->source),sdest,ntohs(tcph_t->dest),ntohs(tcph_t->seq),ntohs(tcph_t->ack_seq));
    }
    else
    sprintf(log_buf, "incoming ICMP packet, circuit incoming: 0x%d, src:%s, dst: %s\n", iID, ssi, sdest);
    printf(log_buf);
    output_log(log_buf);

}

void CProxy::set_router_key(int index)
{
    //router's key = proxy's key ^ 16 copy of router's index
    unsigned char key[KEY_LEN];
    for(int i=0; i< KEY_LEN; i++)
    {
	key[i]=aes_key[i] ^ ((unsigned char)index);
    }
    memcpy(rinfo[index].key, key, KEY_LEN);
    char key_hex_buf[MAX_BUF_SIZE];
    memset(key_hex_buf, 0, MAX_BUF_SIZE);
    key_to_hex_buf(key, key_hex_buf, KEY_LEN);
    printf("router: %d, key: 0x%s", index, key_hex_buf);
}

bool CProxy::collect_router_info()
{

    //"I am up" message from router
    char recv_buf[MAX_BUF_SIZE];
    char log_buf[MAX_BUF_SIZE];
    struct sockaddr_in si_other;
    memset(recv_buf,0,MAX_BUF_SIZE);
    int nread = recv_data_UDP(recv_buf, si_other);
    if(nread == sizeof(struct up_msg))
    {
	memset(log_buf, 0, MAX_BUF_SIZE);
	//memcpy(&_r_addr, &si_other, sizeof( struct sockaddr_in));
	struct up_msg* upmsg = (struct up_msg *)recv_buf;
	int pid = ntohs(upmsg->_pid);
	int index = ntohs(upmsg->_index);
	update_router_addr(index, pid, si_other);
	struct sockaddr_in rip;
	rip.sin_addr.s_addr = rinfo[index].nIP;
	//set the key for the router
	if(_stage >= 6)
	{
	    //assign key to routers, proxy's key ^ (router's index)16
	    set_router_key(index);
	}

	sprintf(log_buf, "router: %d, pid: %d, port: %d, IP: %s\n", index, pid, ntohs(si_other.sin_port), inet_ntoa(rip.sin_addr));
	output_log(log_buf);
	printf("**Proxy** PID: %d, received packet from port: %d, length:%d\n", getpid(), ntohs(si_other.sin_port), nread);
	return true;
    }
    else
    {
	printf("**Proxy** PID: %d, UNKNOWN packet from port: %d, length:%d\n", getpid(), ntohs(si_other.sin_port), nread);
	return false;
    }

}

// proxy routine
void CProxy::run()
{

    int die_counter = 0;

    //receive I'm UP message from routers, make sure all routers are up
    for(int i=0; i< _num_nodes;) 
    {
    	if(collect_router_info())
    	    i++;
    }

    if(_stage <=7 || _stage == 9)
    {

    	//construct circuit path
    	printf("****************build circuit **********************\n");
    	generate_random_path();
    	create_circuit();
    	printf("****************build circuit done*****************\n");
    }
    else
    {
        printf("****************build circuit **********************\n");
        generate_random_path8(totalCircuitCount+1);
        copyPath(totalCircuitCount+1);
        create_circuit();
        totalCircuitCount++;
        printf("****************build circuit done **********************\n");
    }



    /* use select() to deal with two fds at once */
    int maxfd = (_tun_fd > _sock_fd)?_tun_fd: _sock_fd;
    char recv_buf[MAX_BUF_SIZE];
    //char log_buf[MAX_BUF_SIZE];
    //char src_addr_buf[MAX_BUF_SIZE];
    //char dst_addr_buf[MAX_BUF_SIZE];
    //struct sockaddr_in source,dest;

    struct sockaddr_in si_other;
    int nread;

    while(1) 
    {
        int ret;
        fd_set rd_set;

        FD_ZERO(&rd_set);
        FD_SET(_tun_fd, &rd_set); 
        FD_SET(_sock_fd, &rd_set);
        ret = select(maxfd + 1, &rd_set, NULL, NULL, NULL);

        if (ret < 0 && errno == EINTR)
        {
          continue;
        }

        if (ret < 0) 
        {
          perror("select()");
          exit(1);
        }

    if(FD_ISSET(_tun_fd, &rd_set)) 
    {
	   /* data from tun */
    	memset(recv_buf,0,MAX_BUF_SIZE);
    	nread = read_data_TUN(recv_buf, _tun_fd, MAX_BUF_SIZE);
    	printf("**Proxy** PID:%d, received packet from tun, length: %d\n",getpid(), nread);
    	struct iphdr *iph = (struct iphdr *)recv_buf;
        if(_stage == 9)
        {
            die_counter++;
        }
    	if(_stage == 8)
        {
            struct flow tempFlow;
            tempFlow.saddr = iph->saddr;
            tempFlow.daddr = iph->daddr;
            tempFlow.protocol = iph->protocol;

            if(iph->protocol == 6)
            {
                printf("TCP!\n");
                struct tcphdr* tcph = (struct tcphdr*) iph + sizeof(struct iphdr);
                tempFlow.sport = tcph->source;
                tempFlow.dport = tcph->dest;
            }
            else if(iph->protocol == 1)
            {

                printf("ICMP!\n");
                tempFlow.sport = 0;
                tempFlow.dport = 0;
            }
            if(flowCount == 0)
            {
                //This is the first flow, the same circuit should be used.
                //Increase flow count
                printf("**Proxy** This is the first flow !\n");
                
                if(iph->protocol == 1)
                {
                    handle_tun_icmp_traffic(recv_buf, nread);
                    flowCount++;
                    flowNumber = 0;

                    flows[0] = tempFlow;
                }
                else if(iph->protocol == 6) 
                {
                    handle_tun_tcp_traffic(recv_buf,nread);
                    flowCount++;
                    flowNumber = 0;

                    flows[0] = tempFlow;     
                }
                
            }
            else
            {
                //This is not the first flow, compare to all older flows

                printf("Not the first flow!\n");
                
                int repeated = check_repeated_flow(tempFlow.saddr,tempFlow.daddr,tempFlow.sport,tempFlow.dport,tempFlow.protocol);
                //printf("**Proxy** Back from check_repeated_flow\n");
                if(repeated >=0 )
                {
                    printf("Repeated flow! Flow number %d.\n",repeated);
                    flowNumber = repeated;
                    copyPath(flowNumber+1);                        
                }
                else
                {
                    printf("New Flow!\n");
                    flowNumber = flowCount;
                    flowCount++;

                    flows[flowNumber] = tempFlow;
                    printf("******* build circuit %d*******\n", totalCircuitCount+1);
                    generate_random_path8(totalCircuitCount+1);
                    copyPath(totalCircuitCount+1);
                    create_circuit();
                    totalCircuitCount++;
                    printf("******* build circuit complete*******\n");
                }

                if(iph->protocol == 1)
                {
                    handle_tun_icmp_traffic(recv_buf, nread);
                }
                else if(iph->protocol == 6) 
                {
                    handle_tun_tcp_traffic(recv_buf,nread);     
                }
            }

            
        }
        else if(_stage == 9 && die_counter == _die_after+1)
        {
            char send_buf1[MAX_PACKET_SIZE];
            memset(send_buf1,0, MAX_PACKET_SIZE);

                         
            //copy the original icmp packet;
            memcpy(send_buf1, recv_buf, MAX_PACKET_SIZE);
            unsigned short cID = compute_circuit_id(0, flowNumber+1);
            char send_dat[10] = "Die";
            char send_buf[MAX_PACKET_SIZE];
            int packet_len  = construct_relay_msg(send_buf, MAX_PACKET_SIZE, cID, send_dat, strlen(send_dat), KILL_YOURSELF, _stage, flowNumber);
            int nsend = send_data_UDP(send_buf, packet_len, rinfo[path[1]].r_addr);
             packet_len  = construct_relay_msg(send_buf, MAX_PACKET_SIZE, cID, send_dat, strlen(send_dat), KILL_YOURSELF, _stage+1, flowNumber);
             nsend = send_data_UDP(send_buf, packet_len, rinfo[path[0]].r_addr);
            if(nsend<0)
            {
                perror("Failed in sending die message\n");
            }
            printf("\n\n\n\n\n\n\n\n");
            generate_random_path_skipped(path[1]);
            create_circuit();
            struct iphdr *iph = (struct iphdr *)send_buf1;
            printf("Ip protocol %d\n",iph->protocol);
            if(iph->protocol == 1)
            {
                handle_tun_icmp_traffic(send_buf1, nread);
            }
            else if(iph->protocol == 6) 
            {
                handle_tun_tcp_traffic(send_buf1,nread);     
            }
        }
        else
        {
            printf("Stage 7, doing normal stuff.\n");

            struct iphdr *iph = (struct iphdr *)recv_buf;
            if(iph->protocol == 1)
            {
                handle_tun_icmp_traffic(recv_buf, nread);
            }
            else if(iph->protocol == 6) 
            {
                handle_tun_tcp_traffic(recv_buf,nread);     
            }
        }
    }

    if(FD_ISSET(_sock_fd, &rd_set)) 
    {
      	/* data from the routers via UDP socket*/
      	memset(recv_buf,0,MAX_BUF_SIZE);
      	nread = recv_data_UDP(recv_buf, si_other);
      	if(nread >0) 
      	{

	    struct iphdr *iph = (struct iphdr *)recv_buf;

	    /* check if it is an ICMP packet */
	    if(iph->protocol == 1)
	    {
	    
		printf("**Proxy** PID: %d, ICMP from port: %d, length:%d\n", getpid(), ntohs(si_other.sin_port), nread);
		handle_router_icmp_traffic(recv_buf, nread, si_other);
	    }
	    else if(iph->protocol == CC_EXT_PROTOCOL)
	    {

		printf("**Proxy** PID: %d, CIRCUIT from port: %d, length:%d\n", getpid(), ntohs(si_other.sin_port), nread);
		handle_relay_msg(recv_buf, nread, si_other);

	    }
	    else if(iph->protocol == 6) 
	    {
            printf("**Proxy** PID: %d, TCP from port: %d, length:%d\n", getpid(), ntohs(si_other.sin_port), nread);
            handle_router_tcp_traffic(recv_buf, nread, si_other);
            //print_tcp_packet(recv_buf, nread);
		//write tcp packet back to tun;
		//nsend = write_data_TUN(recv_buf, _tun_fd, nread);
	    	//if(nsend <=0 )
	    	//{
		//	printf("**Proxy** failed write packet to tun\n");
	    	//}

	    }
	    else
	    {
		//unknown packet
		printf("**Proxy** PID: %d, UNKNOWN packet from port: %d, length:%d\n", getpid(), ntohs(si_other.sin_port), nread);
	    }

	}
    }
  }
}  


void CProxy::update_router_addr(int index, int pid, struct sockaddr_in si_other)
{

    struct sockaddr_in addr;
    addr.sin_addr.s_addr = rinfo[index].nIP;

    memcpy(&(rinfo[index].r_addr), &si_other, sizeof(struct sockaddr_in));
    rinfo[index].pid = pid;
    rinfo[index].index=index;
    printf("router:%d, pid: %d, IP: %s\n",rinfo[index].index, rinfo[index].pid, inet_ntoa(addr.sin_addr));

}

int CProxy::recv_data_UDP(char* recv_buf, struct sockaddr_in & si_other)
{
    int recv_ret=_mysock.recv_data_UDP(recv_buf, si_other);
    return recv_ret;
}

int CProxy::send_data_UDP(const char* send_buf, const int len, struct sockaddr_in & ser_addr)
{
    int send_ret=_mysock.send_data_UDP(send_buf, len, ser_addr);
    return send_ret;
}

int CProxy::read_data_TUN(char* recv_buf, int fd, int n)
{
   int n_read = read(fd, recv_buf, n);
   if(n_read<0)
   {
       perror("Reading data from tun");
       return -1;
   }
   else
       return n_read;
}

int CProxy::write_data_TUN(char* send_buf, int fd, int n)
{
   int n_write = write(fd, send_buf, n);
   if(n_write<0)
   {
       perror("Writing data to tun");
       return -1;
   }
   else
       return n_write;
}

void CProxy::generate_random_path()
{
    srand ( time(0) );
    memset(path,0,sizeof(int)*MAX_ROUTER_COUNT);
    for(unsigned int i=0; i<_num_hops; )
    {
	int hop = rand() % _num_nodes +1;
	//prevent duplicated routers
	if(is_dup_hop(hop))
	{
	    continue;
	}
	else
	{
	    path[i]=hop;
	    i++;
	}
	
    }

    char log_buf[MAX_BUF_SIZE];
    for(unsigned int i=0; i<_num_hops; i++)
    {

	memset(log_buf, 0, MAX_BUF_SIZE);
	sprintf(log_buf, "hop: %d, router: %d\n",i+1, path[i]);
	printf(log_buf);
	output_log(log_buf);
    }
}

void CProxy::generate_random_path_skipped(int skip)
{
    srand ( time(0) );
    memset(path,0,sizeof(int)*MAX_ROUTER_COUNT);
    for(unsigned int i=0; i<_num_hops; )
    {
    int hop = rand() % _num_nodes +1;
    if( hop == skip)
    {
        i--;
        continue;
    }
    //prevent duplicated routers
    if(is_dup_hop(hop))
    {
        continue;
    }
    else
    {
        path[i]=hop;
        i++;
    }
    
    }

    char log_buf[MAX_BUF_SIZE];
    for(unsigned int i=0; i<_num_hops; i++)
    {

    memset(log_buf, 0, MAX_BUF_SIZE);
    sprintf(log_buf, "hop: %d, router: %d\n",i+1, path[i]);
    printf(log_buf);
    output_log(log_buf);
    }
}
void CProxy::generate_random_path1()
{

    path[0] = 5;
    path[1] = 4;
    path[2] = 3;
    char log_buf[MAX_BUF_SIZE];
    for(unsigned int i=0; i<_num_hops; i++)
    {

    memset(log_buf, 0, MAX_BUF_SIZE);
    sprintf(log_buf, "hop: %d, router: %d\n",i+1, path[i]);
    printf(log_buf);
    output_log(log_buf);
    }
}
void CProxy::generate_random_path2()
{

    path[0] = 5;
    path[1] = 4;
    path[2] = 3;
    char log_buf[MAX_BUF_SIZE];
    for(unsigned int i=0; i<_num_hops; i++)
    {

    memset(log_buf, 0, MAX_BUF_SIZE);
    sprintf(log_buf, "hop: %d, router: %d\n",i+1, path[i]);
    printf(log_buf);
    output_log(log_buf);
    }
}
void CProxy::generate_random_path3()
{

    path[0] = 1;
    path[1] = 2;
    path[2] = 3;
    char log_buf[MAX_BUF_SIZE];
    for(unsigned int i=0; i<_num_hops; i++)
    {

    memset(log_buf, 0, MAX_BUF_SIZE);
    sprintf(log_buf, "hop: %d, router: %d\n",i+1, path[i]);
    printf(log_buf);
    output_log(log_buf);
    }
}



bool CProxy::is_dup_hop(int hop)
{
    for(unsigned int i=0; i< _num_hops; i++)
    {
	if(hop==path[i])
	{
	    return true;
	}
    }
    return false;
}


bool CProxy::create_circuit()
{
    int nsend=0;
    int nread=0;
    char msg[MAX_PACKET_SIZE];
    char recv_buf[MAX_PACKET_SIZE];
    char log_buf[MAX_BUF_SIZE];
    char *p;
    struct sockaddr_in si_other;
    //compute ID:
    unsigned short cID = compute_circuit_id(0, flowNumber+1);
    unsigned short next_hop;
    unsigned short last_hop =strtol("0xffff", &p, 16) ;
    for(unsigned int i=1; i<= _num_hops; i++)
    {
    	if(i==_num_hops)
    	{
    	    next_hop =  last_hop;
    	}
    	else
    	{
    	    //figure out the next hop UDP port;
    	    int nr_index = path[i]; 
    	    next_hop = (rinfo[nr_index].r_addr).sin_port;
    	}

    	memset(msg, 0, MAX_PACKET_SIZE);
    	int packet_len;
    	//first send faked deffie hellman message to distribute keys to routers;
    	if(_stage >= 6)
    	{
    	    //send faked deffie hellman message to router
    	    memset(msg, 0, MAX_PACKET_SIZE);
    	    char* encrypted_key = NULL;
    	    int elen;
    	    //encrypt the key;
    	    encrypt_multiround_with_padding((char *)rinfo[path[i-1]].key, KEY_LEN, &encrypted_key, &elen, i-1);
    	    //construct the faked deffie hellman message
    	    packet_len = construct_deffie_hellman_padding_msg(msg, MAX_PACKET_SIZE, cID, (unsigned char*)encrypted_key, elen,i);
    	    delete [] encrypted_key;

    	    //log
    	    memset(log_buf, 0, MAX_BUF_SIZE);
    	    char key_hex_buf[MAX_BUF_SIZE];
    	    memset(key_hex_buf, 0, MAX_BUF_SIZE);
    	    int key_buf_len = key_to_hex_buf(rinfo[path[i-1]].key, key_hex_buf, KEY_LEN);
    	    int index = sprintf(log_buf, "new-fake-diffe-hellman, router index: %d, circuit outgoing: 0x%d, key: 0x", path[i-1], cID);
    	    memcpy(log_buf+index, key_hex_buf, key_buf_len);
    	    output_log(log_buf);
    	    
    	    //send out the packet, always to the first hop of the path
    	    nsend = send_data_UDP(msg, packet_len, rinfo[path[0]].r_addr);
    	    if(nsend <=0 )
    	    {
    		  printf("**Proxy** failed send Deffie-Hellman message\n");
    	    }
    	}

    	//start building circuit 
    	memset(msg, 0, MAX_PACKET_SIZE);
    	if(_stage >= 6)
    	{
    	    char clear_port[ENC_PORT_LEN];
    	    memset(clear_port, 0, ENC_PORT_LEN);
    	    int port_len = sprintf(clear_port, "%d", next_hop);
    	    char* encrypted_port = NULL;
    	    int elen;
    	    //encrypt the port number;
    	    encrypt_multiround_with_padding(clear_port, port_len, &encrypted_port, &elen, i);

    	    //construct the circuit extend message
    	    packet_len= construct_encrypted_circuit_ext_msg_padding(msg, MAX_PACKET_SIZE, cID, (unsigned char*)encrypted_port, elen, i);
    	    delete [] encrypted_port;
    	}

    	//always send circuit extend message to the first hop of the path
    	nsend = send_data_UDP(msg, packet_len, rinfo[path[0]].r_addr);
    	if(nsend <=0 )
    	{
    	    printf("**Proxy** failed send circuit message\n");
    	}


    	//receive reply from first hop
    	memset(recv_buf,0,MAX_BUF_SIZE);
    	nread = recv_data_UDP(recv_buf, si_other);
    	print_buf_hex((char*)(recv_buf+sizeof(struct iphdr)), nread-(sizeof(struct iphdr)), ntohs(si_other.sin_port)); 
    	if(nread >0) 
    	{
    	    struct iphdr *iph = (struct iphdr *)recv_buf;
    	    struct cc_ext_done_msg * ccextdonemsg = (struct cc_ext_done_msg *)(iph+1);
    	    unsigned short iID = ntohs(ccextdonemsg->cid);
    	    /* check if it is a circuit packet */
    	    if(iph->protocol == CC_EXT_PROTOCOL && (ccextdonemsg->msg_type ==  CC_EXT_DONE_MSGTYPE || ccextdonemsg->msg_type == CC_ENCRYPTED_EXT_DONE))
    	    {
        		printf("**Proxy**, extend-done circuit from port: %d, length: %d\n", ntohs(si_other.sin_port), nread);
        		memset(log_buf, 0, MAX_BUF_SIZE);
        		sprintf(log_buf, "incoming extend-done circuit, incoming: 0x%d from port: %d\n", iID, ntohs(si_other.sin_port));
        		output_log(log_buf);
    	    }
    	}

    }
    return true;
}

int CProxy::construct_deffie_hellman_padding_msg(char* buf, int len, unsigned short cID, unsigned char key[], int keylen,int hop)
{
    memset(buf, 0, len);
    struct iphdr * iph = (struct iphdr *)buf;
    //fill IP header
    iph->protocol = CC_EXT_PROTOCOL;
    // use loop address 
    iph->check = hop;
    iph->saddr = inet_addr("127.0.0.1");
    iph->daddr = inet_addr("127.0.0.1");
	
    struct cc_deffie_hellman_msg * cc_dh_msg = ( struct  cc_deffie_hellman_msg*)(iph+1);
    int hdlen = sizeof(struct iphdr) + sizeof(struct cc_deffie_hellman_msg);

    cc_dh_msg->msg_type = FAKE_DIFFIE_HELLMAN;
    cc_dh_msg->cid = htons(cID);

    memcpy(buf+hdlen, key, keylen);
    return (hdlen + keylen);
}


int CProxy::construct_deffie_hellman_msg(char* buf, int len, unsigned short cID, unsigned char key[] )
{
    memset(buf, 0, len);
    struct iphdr * iph = (struct iphdr *)buf;
    //fill IP header
    iph->protocol = CC_EXT_PROTOCOL;
    // use loop address 
    iph->saddr = inet_addr("127.0.0.1");
    iph->daddr = inet_addr("127.0.0.1");
	
    struct cc_deffie_hellman_msg * cc_dh_msg = ( struct  cc_deffie_hellman_msg*)(iph+1);
    cc_dh_msg->msg_type = FAKE_DIFFIE_HELLMAN;
    cc_dh_msg->cid = htons(cID);
    //memcpy(cc_dh_msg->key, key, KEY_LEN);
    return (sizeof(struct iphdr) + sizeof(struct cc_deffie_hellman_msg));
}

int CProxy::construct_encrypted_circuit_ext_msg_padding(char* buf, int len, unsigned short cID, unsigned char nport[], int port_len,int hop)
{
    memset(buf, 0, len);
    struct iphdr * iph = (struct iphdr *)buf;
    //fill IP header
    iph->protocol = CC_EXT_PROTOCOL;
    // use loop address 
    iph->saddr = inet_addr("127.0.0.1");
    iph->daddr = inet_addr("127.0.0.1");
    iph->check = hop;
    printf("**Proxy** Sending Flow: %d\n", flowNumber);
    iph->tos = flowNumber;
    struct cc_encrypt_ext_msg * cc_eext_msg = ( struct cc_encrypt_ext_msg *)(iph+1);
    int hlen = sizeof(struct iphdr) + sizeof(struct cc_encrypt_ext_msg);

    // msg type: 0x62
    cc_eext_msg->msg_type = CC_ENCRYPTED_EXT;
    // circuit ID
    cc_eext_msg->cid = htons(cID);
    // next hop UDP port number
    memcpy(buf+hlen, nport, port_len);
    //memcpy(cc_eext_msg->encrypted_port, nport, ENC_PORT_LEN);
    return (hlen + port_len);
}

/*
int CProxy::construct_encrypted_circuit_ext_msg(char* buf, int len, unsigned short cID, unsigned char nport[])
{
    memset(buf, 0, len);
    struct iphdr * iph = (struct iphdr *)buf;
    //fill IP header
    iph->protocol = CC_EXT_PROTOCOL;
    // use loop address 
    iph->saddr = inet_addr("127.0.0.1");
    iph->daddr = inet_addr("127.0.0.1");

    struct cc_encrypt_ext_msg * cc_eext_msg = ( struct cc_encrypt_ext_msg *)(iph+1);

    // msg type: 0x62
    cc_eext_msg->msg_type = CC_ENCRYPTED_EXT;

    // circuit ID
    cc_eext_msg->cid = htons(cID);
    // next hop UDP port number
    //memcpy(cc_eext_msg->encrypted_port, nport, ENC_PORT_LEN);
    return (sizeof(struct iphdr) + sizeof(struct cc_encrypt_ext_msg));
}
*/


int CProxy::construct_circuit_ext_msg(char* buf, int len, unsigned short cID, unsigned short nport)
{
    memset(buf, 0, len);
    struct iphdr * iph = (struct iphdr *)buf;
    //fill IP header
    iph->protocol = CC_EXT_PROTOCOL;
    // use loop address 
    iph->saddr = inet_addr("127.0.0.1");
    iph->daddr = inet_addr("127.0.0.1");

    struct cc_ext_msg * cc_ext_msg = ( struct cc_ext_msg *)(iph+1);
    if(_stage == 5)
    {
       	// msg type: 0x52
    	cc_ext_msg->msg_type = CC_EXT_MSGTYPE;
    }

    // circuit ID
    cc_ext_msg->cid = htons(cID);
    // next hop UDP port number
    cc_ext_msg->next_hop = nport; 
    return (sizeof(struct iphdr) + sizeof(struct cc_ext_msg));
}



void CProxy::print_buf_hex(char* buf, int buf_len, int port)
{
    char log_buf[MAX_BUF_SIZE];
    memset(log_buf, 0, MAX_BUF_SIZE);
    int index=0;
    index += sprintf(log_buf, "pkt from port: %d, length: %d, contents: 0x", port, buf_len);
    for(int i=0; i<buf_len; i++)
    {
	index += sprintf(log_buf+index, "%02x", (unsigned char)buf[i]);
    }
    sprintf(log_buf+index, "\n");
    output_log(log_buf);
}


void CProxy::generate_random_key(unsigned char key[], int len)
{
    //generate random key;
    srand ( time(NULL) );
    for(int i=0; i< len; i++)
    {
	key[i] = rand() % 256;
    }
    memset(aes_key, 0, len);
    memcpy(aes_key, key, len);
}

/*
void CProxy::encrypt_port(unsigned short port, char* eport, int round)
{
    memset(eport, 0, ENC_PORT_LEN);
    if(round == 0)
    {
	sprintf(eport, "%d", port);
	return;
    }

    char ctext[ENC_PORT_LEN];
    char etext[ENC_PORT_LEN];
    memset(ctext, 0, ENC_PORT_LEN);
    memset(etext, 0, ENC_PORT_LEN);
    sprintf(ctext, "%d", port);
    encrypt_multiround(ctext, etext, ENC_PORT_LEN, round); 
    memcpy(eport, etext, ENC_PORT_LEN);
}

void CProxy::encrypt_key(char* ctext , char*  etext, int len, int round)
{
    char ckey[KEY_LEN];
    memset(ckey, 0, KEY_LEN);
    memcpy(ckey, ctext, KEY_LEN);
    encrypt_multiround(ckey, etext, len, round);
}


void CProxy::encrypt_multiround(char* ctext , char*  etext, int len, int round)
{

    if(round == 0)
    {
	memcpy(etext, ctext, len);
	return;
    }


    char * clear = new char [len];
    memset(clear, 0, len);
    memcpy(clear, ctext, len);
    memset(etext,0, len );

    for(int i = (round-1); i >= 0; i--)
    {
	memset(etext,0, len);
	encrypt_msg(clear, etext, len, rinfo[path[i]].key);
	memcpy(clear, etext, len);
    }
    delete [] clear;
}

void CProxy::decrypt_multiround(char* ctext , char*  etext, int len, int round)
{

    if(round == 0)
    {
	memcpy(etext, ctext, len);
	return;
    }

        
    char* clear = new char [len];
    memset(clear, 0, len);
    memcpy(clear, ctext, len);

    memset(etext, 0, len);
    for(int i =0; i< round; i++)
    {
	memset(etext, 0, len);
	decrypt_msg(clear, etext, len, rinfo[path[i]].key);
	memcpy(clear, etext, len);
    }
    delete [] clear;
}
*/

void CProxy::encrypt_multiround_with_padding(char* ctext , int inlen, char**  etext, int* outlen,  int round)
{

    if(round == 0)
    {
	*etext = new char [inlen];
	memset(*etext, 0, inlen);
	memcpy(*etext, ctext, inlen);
	*outlen = inlen;
	return;
    }

    char * inbuf = new char [inlen];
    memset(inbuf, 0, inlen);
    memcpy(inbuf, ctext, inlen);


    int ilen = inlen;
    int olen;
    char * outbuf=NULL;
    for(int i = (round-1); i >= 0; i--)
    {
	encrypt_msg_with_padding(inbuf, ilen, &outbuf, &olen, rinfo[path[i]].key);
	//remember the new length
	ilen = olen;
	delete [] inbuf;

	inbuf = new char [ilen];
	memcpy(inbuf, outbuf, ilen);
	delete [] outbuf;
    }
    *etext = inbuf;
    *outlen = olen;
}

void CProxy::decrypt_multiround_with_padding(char* ctext , int inlen, char**  etext, int* outlen,  int round)
{

    if(round == 0)
    {

	*etext = new char [inlen];
	memset(*etext, 0, inlen);
	memcpy(*etext, ctext, inlen);
	*outlen = inlen;
	return;
    }

    char * inbuf = new char [inlen];
    memset(inbuf, 0, inlen);
    memcpy(inbuf, ctext, inlen);


    int ilen = inlen;
    int olen;
    char * outbuf=NULL;
    for(int i = 0;  i < round; i++)
    {

	decrypt_msg_with_padding(inbuf, ilen, &outbuf, &olen, rinfo[path[i]].key);
	//remember the new length
	ilen = olen;
	delete [] inbuf;
	inbuf = new char [ilen];
	memcpy(inbuf, outbuf, ilen);
	delete [] outbuf;
    }
    *etext = inbuf;
    *outlen = olen;
}

void CProxy::generate_random_path8(int pathNumber)
{
    srand ( time(NULL) );
    printf("Generrating Random Path%d\n", pathNumber);
    memset(paths[pathNumber],0,sizeof(int)*MAX_ROUTER_COUNT);
    for(unsigned int i=0; i<_num_hops; )
    {
    int hop = rand() % _num_nodes +1;
        //prevent duplicated routers
        if(is_dup_hop8(hop, pathNumber))
        {
            continue;
        }
        else
        {
            paths[pathNumber][i]=hop;
            i++;
        }
    
    }

    char log_buf[MAX_BUF_SIZE];
    for(unsigned int i=0; i<_num_hops; i++)
    {

    memset(log_buf, 0, MAX_BUF_SIZE);
    sprintf(log_buf, "hop: %d, router: %d\n",i+1, paths[pathNumber][i]);
    printf(log_buf);
    output_log(log_buf);
    }
}
bool CProxy::is_dup_hop8(int hop, int pathNumber)
{
    for(unsigned int i=0; i< _num_hops; i++)
    {
    if(hop==paths[pathNumber][i])
    {
        return true;
    }
    }
    return false;
}
// bool CProxy::create_circuit8(int pathNumber)
// {
//     int nsend=0;
//     int nread=0;
//     char msg[MAX_PACKET_SIZE];
//     char recv_buf[MAX_PACKET_SIZE];
//     char log_buf[MAX_BUF_SIZE];
//     char *p;

//     struct sockaddr_in si_other;
//     //compute ID:
//     unsigned short cID = compute_circuit_id(0, pathNumber);
//     unsigned short next_hop;
//     unsigned short last_hop =strtol("0xffff", &p, 16) ;
//     for(unsigned int i=1; i<= _num_hops; i++)
//     {
//         if(i==_num_hops)
//         {
//             next_hop =  last_hop;
//         }
//         else
//         {
//             //figure out the next hop UDP port;
//             int nr_index = paths[pathNumber][i]; 
//             next_hop = (rinfo[nr_index].r_addr).sin_port;
//             printf("**Proxy** Next hop is: %d\n",next_hop);
//         }

//         memset(msg, 0, MAX_PACKET_SIZE);
//         int packet_len;
//         //first send faked deffie hellman message to distribute keys to routers;
//         if(_stage >= 6)
//         {
//             //send faked deffie hellman message to router
//             memset(msg, 0, MAX_PACKET_SIZE);
//             char* encrypted_key = NULL;
//             int elen;
//             //encrypt the key;
//             encrypt_multiround_with_padding((char *)rinfo[paths[pathNumber][i-1]].key, KEY_LEN, &encrypted_key, &elen, i-1);
//             //construct the faked deffie hellman message
//             packet_len = construct_deffie_hellman_padding_msg(msg, MAX_PACKET_SIZE, cID, (unsigned char*)encrypted_key, elen);
//             delete [] encrypted_key;

//             //log
//             memset(log_buf, 0, MAX_BUF_SIZE);
//             char key_hex_buf[MAX_BUF_SIZE];
//             memset(key_hex_buf, 0, MAX_BUF_SIZE);
//             int key_buf_len = key_to_hex_buf(rinfo[paths[pathNumber][i-1]].key, key_hex_buf, KEY_LEN);
//             int index = sprintf(log_buf, "new-fake-diffe-hellman, router index: %d, circuit outgoing: 0x%02x, key: 0x", paths[pathNumber][i-1], cID);
//             memcpy(log_buf+index, key_hex_buf, key_buf_len);
//             output_log(log_buf);
            
//             //send out the packet, always to the first hop of the path
//             nsend = send_data_UDP(msg, packet_len, rinfo[paths[pathNumber][0]].r_addr);
//             if(nsend <=0 )
//             {
//                 printf("**Proxy** failed send Deffie-Hellman message\n");
//             }
//         }

//         //start building circuit 
//         memset(msg, 0, MAX_PACKET_SIZE);
//         if(_stage >= 6)
//         {
//             char clear_port[ENC_PORT_LEN];
//             memset(clear_port, 0, ENC_PORT_LEN);
//             int port_len = sprintf(clear_port, "%d", next_hop);
//             char* encrypted_port = NULL;
//             int elen;
//             //encrypt the port number;
//             encrypt_multiround_with_padding(clear_port, port_len, &encrypted_port, &elen, i);

//             //construct the circuit extend message
//             packet_len= construct_encrypted_circuit_ext_msg_padding(msg, MAX_PACKET_SIZE, cID, (unsigned char*)encrypted_port, elen, i);
//             delete [] encrypted_port;
//         }

//         if(_stage == 5)
//         {
//             packet_len= construct_circuit_ext_msg(msg, MAX_PACKET_SIZE, cID, next_hop);
//         }

//         //always send circuit extend message to the first hop of the path
//         nsend = send_data_UDP(msg, packet_len, rinfo[paths[pathNumber][0]].r_addr);
//         if(nsend <=0 )
//         {
//             printf("**Proxy** failed send circuit message\n");
//         }


//         //receive reply from first hop
//         memset(recv_buf,0,MAX_BUF_SIZE);
//         nread = recv_data_UDP(recv_buf, si_other);
//         print_buf_hex((char*)(recv_buf+sizeof(struct iphdr)), nread-(sizeof(struct iphdr)), ntohs(si_other.sin_port)); 
//         if(nread >0) 
//         {
//             struct iphdr *iph = (struct iphdr *)recv_buf;
//             struct cc_ext_done_msg * ccextdonemsg = (struct cc_ext_done_msg *)(iph+1);
//             unsigned short iID = ntohs(ccextdonemsg->cid);
//             /* check if it is a circuit packet */
//             if(iph->protocol == CC_EXT_PROTOCOL && (ccextdonemsg->msg_type ==  CC_EXT_DONE_MSGTYPE || ccextdonemsg->msg_type == CC_ENCRYPTED_EXT_DONE))
//             {
//             printf("**Proxy**, extend-done circuit from port: %d, length: %d\n", ntohs(si_other.sin_port), nread);
//             memset(log_buf, 0, MAX_BUF_SIZE);
//             sprintf(log_buf, "incoming extend-done circuit, incoming: 0x%d from port: %d\n", iID, ntohs(si_other.sin_port));
//             output_log(log_buf);
//             }
//         }

//     }
//     return true;
// }

int CProxy::check_repeated_flow(u_int32_t src, u_int32_t dest, u_int16_t sport, u_int16_t dport, u_int8_t protocol) 
{
    printf("**Proxy** Flow Count: %d \n",flowCount);
    printf("**Proxy** Data received: %d %d %u %u %d\n",src,dest,sport,dport,protocol);
    for(int i=0; i<flowCount; i++)
    {
        u_int32_t fSrc = flows[i].saddr;
        u_int32_t fDest = flows[i].daddr;
        u_int16_t fSport = flows[i].sport;
        u_int16_t fDport = flows[i].dport;
        u_int8_t fProtocol = flows[i].protocol;

        printf("Comparing with: %d %d %d %d %d\n",fSrc,fDest,fSport,fDport,fProtocol);
        if(src==fSrc)
        {
            printf("Source match.");
            if(dest==fDest){
                printf(" Destination match.");
                if(sport==fSport){
                    printf(" S poort match.");
                    if(dport==fDport){
                        printf(" D port match.");
                        return i;
                        // if(protocol==6 && fProtocol==6 || protocol==1 && fProtocol==1)
                        // {
                        //     return i;
                        // }
                    }
                }
            }
        }
    }
    printf("**Proxy** Check repeated flow: No match!\n");
    return -1;
}

void CProxy::copyPath(int pathNumber)
{
    printf("Copying path:\n");
    for(unsigned int i=0; i<_num_hops; i++)
    {
        path[i] = paths[pathNumber][i];
        printf("hop: %d router: %d", i+1, path[i]);
    }

}