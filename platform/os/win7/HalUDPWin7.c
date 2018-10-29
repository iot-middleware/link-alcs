#include <stdio.h>
#include <string.h>
#include <winsock2.h>
#include <ws2tcpip.h>


#include "iot_import.h"

#ifdef _MSC_BUILD
#include <Winbase.h>
#pragma comment(lib,"ws2_32")
#endif


#define PLATFORM_WINSOCK_PERROR printf


/**
 * @brief Create a UDP socket.
 *
 * @param [in] port: @n Specify the UDP port of UDP socket
 *
 * @retval  < 0 : Fail.
 * @retval >= 0 : Success, the value is handle of this UDP socket.
 * @see None.
 */
intptr_t HAL_UDP_create(const char *host, unsigned short port)

{
    int ret;
    char flag = 1;
    uintptr_t sockfd;
	WSADATA wsaData;
    struct sockaddr_in local_addr;

	if (0 != WSAStartup(MAKEWORD(2, 2), &wsaData)){
        PLATFORM_WINSOCK_PERROR("WSAStartup failed");
		return -1;
	}

    if ((2 != LOBYTE(wsaData.wVersion)) || (2 != HIBYTE(wsaData.wVersion))){
		WSACleanup( );
        PLATFORM_WINSOCK_PERROR("wVersion error");
		return -1;
    }

    memset(&local_addr, 0x00, sizeof(local_addr));
    local_addr.sin_family = AF_INET;
    if(NULL != host){
        local_addr.sin_addr.s_addr = inet_addr(host);
    }else{
        local_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    }
    local_addr.sin_port = htons(port);

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (INVALID_SOCKET == sockfd){
        WSACleanup();
        PLATFORM_WINSOCK_PERROR("socket failed");
    	return -1;
    }

    ret = setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &flag, sizeof(flag));
    if(SOCKET_ERROR == ret)
    {
        closesocket((SOCKET)sockfd);
        WSACleanup();
        fprintf(stderr,"\r\nsetsockopt SO_REUSEADDR failed");
        return (intptr_t)-1;
    }

    if (-1 == bind(sockfd, (struct sockaddr *)&local_addr, sizeof(local_addr))){
    	closesocket((SOCKET)sockfd);
        WSACleanup();
        PLATFORM_WINSOCK_PERROR("bind failed");
    	return -1;
    }

    return (intptr_t)sockfd;
}


int HAL_UDP_recvfrom(intptr_t          sockfd,
                      NetworkAddr     *p_remote,
                      unsigned char   *p_data,
                      unsigned int     datalen,
                      unsigned int     timeout_ms)
{
    SOCKET socket_id = -1;
    struct sockaddr_in from;
    int count = -1, ret = -1;
    int  addrlen = 0;
    struct timeval      tv;
    fd_set              read_fds;

    if(NULL == p_remote  || NULL == p_data){
        return -1;
    }

    socket_id = (SOCKET)sockfd;

    FD_ZERO(&read_fds);
    FD_SET(socket_id, &read_fds);

    tv.tv_sec  = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;

    ret = select(socket_id + 1, &read_fds, NULL, NULL, timeout_ms == 0 ? NULL : &tv);

    /* Zero fds ready means we timed out */
    if (ret == 0) {
        return -2;    /* receive timeout */
    }

    if (ret < 0) {
        PLATFORM_WINSOCK_PERROR("select-read fail");
        return -3;
    }

    addrlen = sizeof(struct sockaddr);
    count = recvfrom(socket_id,  (char *)p_data, (int)datalen, 0, (struct sockaddr *)&from, &addrlen);
    if(SOCKET_ERROR == count)
    {
        return -1;
    }
    if (from.sin_family == AF_INET)
    {
        struct sockaddr_in *sin = (struct sockaddr_in *)&from;
        char *addr = inet_ntoa(sin->sin_addr);
        strncpy(p_remote->addr, addr, NETWORK_ADDR_LEN-1);
        p_remote->port = ntohs(sin->sin_port);
    }
    return count;
}

int HAL_UDP_sendto(intptr_t            sockfd,
                 const NetworkAddr   *p_remote,
                 const unsigned char *p_data,
                 unsigned int         datalen,
                 unsigned int         timeout_ms)
{
    int rc = -1;
    SOCKET socket_id = -1;
    struct sockaddr_in remote_addr;

    if(NULL == p_remote || NULL == p_data) {
        return -1;
    }

    socket_id = (SOCKET)sockfd;
    remote_addr.sin_family = AF_INET;
    remote_addr.sin_addr.s_addr = inet_addr(p_remote->addr);
    if(INADDR_NONE == remote_addr.sin_addr.S_un.S_addr)
    {
        return -1;
    }
    remote_addr.sin_port = htons(p_remote->port);
    rc = sendto(socket_id, (char *)p_data, (int)datalen, 0,
              (const struct sockaddr *)&remote_addr, sizeof(remote_addr));
    if(SOCKET_ERROR == rc)
    {
        return -1;
    }
    return rc;

}

int HAL_UDP_joinmulticast(intptr_t           sockfd,
                           const char        *p_group)
{
    int err = -1;
    SOCKET socket_id = -1;

    if(NULL == p_group) {
        return -1;
    }

    /*set loopback*/
    char loop = 1;
    socket_id = (SOCKET)sockfd;
    err = setsockopt(socket_id, IPPROTO_IP, IP_MULTICAST_LOOP, &loop, sizeof(loop));
    if(SOCKET_ERROR == err)
    {
         fprintf(stderr,"setsockopt():IP_MULTICAST_LOOP failed\r\n");
         return err;
    }

    struct ip_mreq mreq;
    //mreq.imr_multiaddr.s_addr = inet_addr(p_group);
    mreq.imr_multiaddr.S_un.S_addr = inet_addr(p_group);
    mreq.imr_interface.s_addr = htonl(INADDR_ANY); /*default networt interface*/

    /*join to the mutilcast group*/
    //err = setsockopt(socket_id, IPPROTO_IP, IP_ADD_MEMBERSHIP, (char *)&mreq, sizeof(mreq));
    err = setsockopt(socket_id, IPPROTO_IP, IP_ADD_MEMBERSHIP, (char *)&mreq, sizeof(mreq));
    if (SOCKET_ERROR == err)
    {
         fprintf(stderr,"setsockopt():IP_ADD_MEMBERSHIP failed %u\r\n", WSAGetLastError());
         return err;
    }

    return 0;
}

void HAL_UDP_close(intptr_t sockfd)
{
    int rc;

    /* Shutdown both send and receive operations. */
    rc = shutdown((SOCKET)sockfd, 2);
    if (0 != rc) {
       PLATFORM_WINSOCK_PERROR("shutdown error");
    }

    rc = closesocket((SOCKET)sockfd);
    if (0 != rc) {
       PLATFORM_WINSOCK_PERROR("closesocket error");
    }

    rc = WSACleanup();
    if (0 != rc) {
       PLATFORM_WINSOCK_PERROR("WSACleanup error");
    }
}

