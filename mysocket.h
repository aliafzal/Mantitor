#ifndef SOCKET_H
#define SOCKET_H

#include "types.h"
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <unistd.h>


class CSocket
{
    public:
	int _sock;
	sockaddr_in _addr;
    public:
	CSocket();
	~CSocket();
	//bool create();
	bool create(int sock_type, int protocol);
	bool close();

	bool bind(const int port);
	bool bind_rawsock(struct sockaddr_in src);


	bool listen();
	bool accept(CSocket& new_sock);
	bool connect(const char* serv_host,const int port);

	int send_data(const char* send_buf);
	int recv_data(char* recv_buf);

	int recv_data_UDP(char* recv_buf, struct sockaddr_in & si_other);
	int send_data_UDP(const char* send_buf, const int len, struct sockaddr_in & ser_addr );


	int send_data_RAW(const char* send_buf, const int len, struct sockaddr_in & ser_addr );
	int recv_data_RAW(char* recv_buf, struct sockaddr_in & ser_addr );


	int send_icmp_rawsock(struct sockaddr_in dst_addr);
	int send_tcp_rawsock(struct sockaddr_in src_addr, struct sockaddr_in dst_addr1, char* org_packet, int len);


	bool set_socket_nonblock(bool nonblock);
	bool set_socket_fill_ipheader(bool on);
	bool set_socket_bind_dev(char* dev);
	bool is_alive(){return _sock!=-1;}
};

#endif
