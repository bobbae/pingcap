
#define PORT	 28080
#define MAXLINE 1024

#ifdef _WIN32
#define print_error(msg) printf("%s %d\n",(msg), WSAGetLastError())
#else
#define perror(msg) 
#endif
