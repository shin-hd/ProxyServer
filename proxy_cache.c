//////////////////////////////////////////////////////////////////
// File Name	: proxy_server.c				//
// Date		: 2021/06/01					//
// Os		: Ubuntu 20.04 LTS 64bits			//
// Author	: Shin Hae Dam					//
// Student ID	: 2017202088					//
// ------------------------------------------------------------ //
// Title : System Programing Assignment #3-2 (proxy server)	//
// Desciption	: Server program of Proxy Server.		//
// 		  Receive request from web browser		//
// 		  Get HIT/MISS and Cashing request url		//
// 		  Send response to web browser			//
// 		  Child processes share cache file and log file	//
//////////////////////////////////////////////////////////////////

#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/sem.h>
#include <sys/ipc.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <openssl/sha.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <dirent.h>
#include <signal.h>
#include <fcntl.h>
#include <unistd.h>
#include <pwd.h>
#include <time.h>
#include <netdb.h>
#include <semaphore.h>
#include <pthread.h>

#define BUFFSIZE	1024
#define PORTNO		39999

// global variables for signal handler
pid_t gParentPID;
char* gLogPath;
time_t gStartTime;
int gChildCount;

// thread arguments
struct Thread_arg{
	FILE* log;
	char* message;
};


//////////////////////////////////////////////////////////////////
// run								//
// ============================================================ //
// Output: int	0 success					//
// 		-1 fail						//
// Purpose: Run server work					//
//////////////////////////////////////////////////////////////////
int run();

//////////////////////////////////////////////////////////////////
// cache							//
// ============================================================ //
// Input: char* -> request message,				//
// 	  char* -> URL,						//
// 	  char* -> home directory path,				//
// 	  char* -> log file path,				//
// 	  int	-> client fd,					//
// 	  int	-> semaphore id					//
// Output: int	0 HIT						//
// 		1 MISS						//
// 		-1 fail						//
// Purpose: Get response from web server or cache file and	//
// 	    Send response to web browser			//
//////////////////////////////////////////////////////////////////
int cache(char* request, char* url, char *path, char *logPath, int client_fd, int semid);

//////////////////////////////////////////////////////////////////
// hasFile							//
// ============================================================ //
// Input: DIR* -> Directory Pointer,				//
// 	  char* -> File Name					//
// Output: int	1 has file					//
// 		0 no such file					//
// Purpose: Check if there is a file in the directory		//
//////////////////////////////////////////////////////////////////
int hasFile(DIR *dp, char* fileName);

//////////////////////////////////////////////////////////////////
// getHomeDir							//
// ============================================================ //
// Input: char* -> home that homeDir path will be written	//
// Output: char* -> pointer of home				//
// Purpose: Get home directory path				//
//////////////////////////////////////////////////////////////////
char *getHomeDir(char *home);

//////////////////////////////////////////////////////////////////
// sha1_hash							//
// ============================================================ //
// Input: char* -> input_url before hashed,			//
// 	  char* -> hashed_url that hash data will be written	//
// Output: char* -> porinter of hashed url data			//
// Purpose: Hashing the input url				//
//////////////////////////////////////////////////////////////////
char *sha1_hash(char *input_url, char *hashed_url);

//////////////////////////////////////////////////////////////////
// getIPAddr							//
// ============================================================ //
// Input: char* -> address					//
// Output: char* -> ip address					//
// Purpose: Get ip address of url				//
//////////////////////////////////////////////////////////////////
char* getIPAddr(char* addr);

//////////////////////////////////////////////////////////////////
// sendRequest							//
// ============================================================ //
// Input: char* -> request message,				//
// 	  char* -> ip address of web server			//
// Output: int	-> web server socket fd				//
// Purpose: Connect to web server and				//
// 	    Send request					//
//////////////////////////////////////////////////////////////////
int sendRequest(char* request, char* ip);

//////////////////////////////////////////////////////////////////
// sendResponse							//
// ============================================================	//
// Input: int	-> web server socket fd,			//
//	  int	-> web browser socket fd,			//
//	  FILE*	-> cache file descriptor			//
// Purpose: Get response from web server and			//
// 	    Send response to web browser and			//
// 	    Save response to cache file				//
//////////////////////////////////////////////////////////////////
void sendResponse(int socket_fd, int client_fd, FILE* cacheFile);

//////////////////////////////////////////////////////////////////
// p								//
// ============================================================ //
// Input: int -> semaphore id					//
// Purpose: sepaphore P function				//
//////////////////////////////////////////////////////////////////
void p(int semid);

//////////////////////////////////////////////////////////////////
// v								//
// ============================================================ //
// Input: int -> semaphore id					//
// Purpose: semaphore V function				//
//////////////////////////////////////////////////////////////////
void v(int semid);

//////////////////////////////////////////////////////////////////
// thr_log							//
// ============================================================ //
// Input: void*	-> log fd, log msg structure			//
// Purpose: write Hit/Miss messages to log			//
//////////////////////////////////////////////////////////////////
void* thr_log(void* arg);

//////////////////////////////////////////////////////////////////
// sig_chld							//
// ============================================================ //
// Purpose: SIGCHLD handler					//
//////////////////////////////////////////////////////////////////
static void sig_chld()
{
	// wait
	pid_t pid;
	int status;
	while((pid = waitpid(-1, &status, WNOHANG)) > 0);
}

//////////////////////////////////////////////////////////////////
// sig_alrm							//
// ============================================================ //
// Purpose: SIGALARM handler					//
//////////////////////////////////////////////////////////////////
static void sig_alrm()
{
	// print message and exit
	printf("응답없음\n");
	exit(0);
}

//////////////////////////////////////////////////////////////////
// sig_int							//
// ============================================================ //
// Purpose: SIGINT handler					//
//////////////////////////////////////////////////////////////////
static void sig_int()
{
	printf("\n");

	// if child process, exit
	if(gParentPID != getpid()) exit(0);

	// get end time
	time_t endtime;
	time(&endtime);
	
	// log terminate msg
	FILE* log = fopen(gLogPath, "a");
	fprintf(log, "**SERVER** [Terminated] run time: %ld sec. #sub process: %d\n", endtime-gStartTime, gChildCount);

	exit(0);
}

//////////////////////////////////////////////////////////////////
// sig_alrm							//
// Main								//
// ============================================================ //
// Output: int	0 success					//
// 		-1 fail						//
// Purpose: Main of Proxy Server Program			//
//////////////////////////////////////////////////////////////////
int main()
{
	if(run() < 0)	// run
	{ // error
		printf("Unexpected Error\n");
		return -1;
	}
	return 0;
}

int run()
{

	// socket variable
	struct sockaddr_in server_addr, client_addr; // addr
	int socket_fd, client_fd;	// server, client fd
	int len, len_out;		// client addr size, recieved url size
	int state;			
	char buf[BUFFSIZE];		// buffer
	pid_t pid;			// child process pid

	// working variable
	char homePath[100] = {0,};	// home path
	char logPath[50];		// log path
	DIR *log_dp;			// log dir
	FILE* log;			// log file

	// SIGCHLD, SIGALRM, SIGINT signal handling
	if( (signal(SIGCHLD, sig_chld) == SIG_ERR)
			|| (signal(SIGALRM, sig_alrm) == SIG_ERR)
			|| (signal(SIGINT, sig_int) == SIG_ERR) )
	{
		fprintf(stderr, "signal error");	
		return -1;
	}

/////////////// Get home path and log path ///////////////	
	
	// get home dir path
	getHomeDir(homePath);

	// umask = 000
	umask(0);

	// open log directory
	strcpy(logPath, homePath);
	if((log_dp = opendir(strcat(logPath, "/logfile/"))) == NULL)
	{ // if log directory does not exist, make directory
		mkdir(logPath, 0777);
	}
	else
	{ // close directory
		closedir(log_dp);
	}
	// get log file path
	strcat(logPath, "logfile.txt");
	
/////////////// End of Get path ///////////////

	// set global variables for sig_int
	gParentPID = getpid();
	gLogPath = logPath;
	time(&gStartTime); 
	gChildCount = 0;

/////////////// Set socket ///////////////	

	// create socket
	int opt = 1;
	if((socket_fd = socket(PF_INET, SOCK_STREAM, 0)) < 0)
	{
		printf("Server : Can't open stream socket\n");
		return -1;
	}
	// set socket option
	setsockopt(socket_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

	// set server address
	bzero((char*)&server_addr, sizeof(server_addr));
	server_addr.sin_family = AF_INET;
	server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
	server_addr.sin_port = htons(PORTNO);

	// bind
	if(bind(socket_fd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0)
	{
		printf("Server : Can't bind local address\n");
		close(socket_fd);
		return -1;
	}

	// listen
	listen(socket_fd, 5);

/////////////// End of Set socket ///////////////

/////////////// Set semaphore ///////////////

	int semid;
	union semun{
		int val;
		struct semid_ds *buf;
		unsigned short int *array;
	} arg;

	// create semaphore set and get semaphore set id
	if((semid = semget((key_t)PORTNO, 1, IPC_CREAT|0666)) == -1)
	{
		perror("semget failed");
		exit(1);
	}

	// set semaphore value
	arg.val = 1;
	if((semctl(semid, 0, SETVAL, arg)) == -1)
	{
		perror("semctl failed");
		exit(1);
	}
	
/////////////// End of Set semaphore //////////////

/////////////// Server Loop ///////////////

	// server loop
	while(1)
	{
		// accept
		bzero((char*)&client_addr, sizeof(client_addr));
		len = sizeof(client_addr);
		client_fd = accept(socket_fd, (struct sockaddr*)&client_addr, &len);

		// accept error
		if(client_fd < 0)
		{
			printf("Server : accept failed	%d\n", getpid());
			close(socket_fd);
			return -1;
		}

		// connect success
//		printf("[%s : %d] client was connected\n", inet_ntoa(client_addr.sin_addr), client_addr.sin_port);
		pid = fork();

		// fork error
		if(pid == -1)
		{
			close(client_fd);
			close(socket_fd);
			continue;
		}
		
	/////////////// Child Process ///////////////

		if(pid == 0)
		{
			// request variables
			char tmp[BUFFSIZE] = {0, };
			char method[20] = {0, };
			char url[BUFFSIZE] = {0, };
			char* tok = NULL;

			// read request
			len_out = read(client_fd, buf, BUFFSIZE);

			// for printing client address
			struct in_addr inet_client_address;
			inet_client_address.s_addr = client_addr.sin_addr.s_addr;

			/*
			// print request
			puts("=========================================");
			printf("Request from [%s : %d]\n", inet_ntoa(inet_client_address), client_addr.sin_port);
			puts(buf);
			puts("=========================================");
			*/

			// get method
			strcpy(tmp, buf);
			tok = strtok(tmp, " ");
			strcpy(method, tok);
			
			// request method == "GET"
			if(strcmp(method, "GET") == 0)
			{
				tok = strtok(NULL, " ");
				strcpy(url, tok);
			}

			// caching
			cache(buf, url, homePath, logPath, client_fd, semid);
			
			// disconnect
//			printf("[%s : %d] client was disconnected\n", inet_ntoa(client_addr.sin_addr), client_addr.sin_port);
			close(client_fd);
			exit(0);
		}

	/////////////// End of Child Process ///////////////

		gChildCount++;
		close(client_fd);
	} // end of while	
	
	// remove semaphore
	if((semctl(semid, 0, IPC_RMID, arg)) == -1)
	{
		perror("semctl failed");
		exit(1);
	}
	close(socket_fd);

/////////////// End of Server Loop ///////////////

	return 0;
}

int cache(char* request, char *url, char *path, char *logPath, int client_fd, int semid)
{
	char hashed_url[41] = {0,};	// hashed url data
	DIR *cache_dp,			// cache directory pointer
	    *hash_dp;			// hashed data directory pointer
	char cacheDirPath[100],		// cache directory path
	     hashDirName[4] = {0,},	// hashed data directory name
	     hashDirPath[100]; 		// hashed data directory path
	FILE *cacheFile,		// cache file descriptor
	     *log;			// log file descriptor
	time_t 	current_time;		// current time
	struct tm* cur_tm;		// current tm
	pid_t pid = getpid();		// my pid

	// url is empty
	if(strcmp(url, "") == 0)
		return -1;

	// split url variables
	char addr[BUFFSIZE] = {0,};	
	char serverPath[BUFFSIZE] = {0,};
	char temp[BUFFSIZE] = {0,};
	char* tok = NULL;	

	// remove https:// or http://
	strcpy(temp, url);
	if(strncmp(temp, "https://", 8) == 0)
		strcpy(temp, &temp[8]);	
	else if(strncmp(temp, "http://", 7) == 0)
		strcpy(temp, &temp[7]);
		
	// get address of url
	tok = strtok(temp, "/");
	strcpy(addr, tok);
	
	// get path of url
	strcpy(serverPath, "/");
	tok = strtok(NULL, "/");	
	while(tok != NULL)
	{
		strcat(serverPath, tok);
		strcat(serverPath, "/");
		tok = strtok(NULL, "/");
	}
	
	// temp = addr + path
	strcpy(temp, addr);
	strcat(temp, serverPath);
	
	// umask = 000
	umask(0);

	// open cache directory
	strcpy(cacheDirPath, path);
	if((cache_dp = opendir(strcat(cacheDirPath, "/cache/"))) == NULL)
	{ // if cache directory does not exist, make directory
		mkdir(cacheDirPath, 0777);
		cache_dp = opendir(cacheDirPath);
	}

	// open log file for append mode
	log = fopen(logPath, "a");

	// if server path is "/", hash(url)
	if(strcmp(serverPath, "/") == 0)
		sha1_hash(addr, hashed_url);
	// if server path is "/~", hash(url + path)
	else
		sha1_hash(temp, hashed_url);

	// hashDirName = hashed_url[0:2]
	strncpy(hashDirName, hashed_url, 3);
	
	// hashDirPath = ~/cache/hashDirName/
	strcpy(hashDirPath, cacheDirPath);
	strcat(hashDirPath, hashDirName);
	strcat(hashDirPath, "/");

	// get current local time
	time(&current_time);
	cur_tm = localtime(&current_time);

/////////////// Create cache directory and file ///////////////	

	// umask = 000
	umask(0);

	// if hashed url directory does not exist, make dir
	if(!hasFile(cache_dp, hashDirName))
	{
		mkdir(hashDirPath, 0777);
	}

	// open hashed url directory
	hash_dp = opendir(hashDirPath);

	// hit-miss state, web server socket fd
	int state, socket_fd;
	if(hasFile(hash_dp, &hashed_url[3]))
		state = 0;	// hit	// have cache file
	else
	{
		state = 1;	// miss	// no cache file

		// make cache file and open
		creat(strcat(hashDirPath, &hashed_url[3]), 0666);
		cacheFile = fopen(hashDirPath, "w");

		// connect to web server and send request
		socket_fd = sendRequest(request, getIPAddr(addr));
	}

	// p func of semaphore(waiting)
	printf("*PID# %d is waiting for the semaphore.\n", pid);
	p(semid);
	// in critical zone
	printf("*PID# %d is in the critical zone.\n", pid);

	// thread variables
	int err;
	pthread_t tid;
	struct Thread_arg arg;
	char msg[BUFFSIZE];
	memset(msg, 0, BUFFSIZE);

	if(!state)
	{ // HIT
		// open cache file
		cacheFile = fopen(strcat(hashDirPath, &hashed_url[3]), "r");
		// get response data from cache file and send to browser
		char response[BUFFSIZE] = {0,};
		int len;
		while(feof(cacheFile) == 0)
		{
			// read cache file
			len = fread(response, BUFFSIZE, 1, cacheFile);

			// send to browser
		//	fwrite(response, BUFFSIZE, 1, stdout);
			write(client_fd, response, BUFFSIZE);
			memset(response, 0, BUFFSIZE);
		}

		// if serverPath == "/"
		if(strcmp(serverPath, "/") == 0)
		{
			// create log message
			sprintf(msg, "[HIT]%s/%s-[%04d/%d/%d, %02d:%02d:%02d]\n", hashDirName, &hashed_url[3], cur_tm->tm_year + 1900, cur_tm->tm_mon + 1, cur_tm->tm_mday, cur_tm->tm_hour, cur_tm->tm_min, cur_tm->tm_sec);
			strcat(msg, "[HIT]");
			strcat(msg, addr);
			strcat(msg, "\n");

			// set arguments of thread func
			arg.log = log;
			arg.message = msg;

			// create thread
			err = pthread_create(&tid, NULL, thr_log, (void*)&arg);
			if(err != 0){
				printf("pthread_create() error.\n");
				return -1;
			}
			printf("*PID# %d create the *TID# %lu.\n", pid, tid);
			// waiting for thread termination
			pthread_join(tid, NULL);
			printf("*TID# %lu is exited.\n", tid);
		}
//sleep(10);
		// v func of semaphore(post)
		printf("*PID# %d exited the critical zone.\n", pid);
		v(semid);

		// close
		closedir(hash_dp);
		closedir(cache_dp);
		fclose(log);
		fclose(cacheFile);
		return 0;
	}
	else
	{ // MISS
	
		// get respone from web server
		// write to cache file and send to browser
		sendResponse(socket_fd, client_fd, cacheFile);

		// if serverPath == "/"
		if(strcmp(serverPath, "/") == 0)
		{
			// create log message
			sprintf(msg, "[Miss]%.*s-[%04d/%d/%d, %02d:%02d:%02d]\n", (int)strlen(addr), addr, cur_tm->tm_year + 1900, cur_tm->tm_mon + 1, cur_tm->tm_mday, cur_tm->tm_hour, cur_tm->tm_min, cur_tm->tm_sec);
			
			// set arguments of thread func
			arg.log = log;
			arg.message = msg;

			// create thread
			err = pthread_create(&tid, NULL, thr_log, (void*)&arg);
			if(err != 0){
				printf("pthread_create() error.\n");
				return -1;
			}
			printf("*PID# %d create the *TID# %lu.\n", pid, tid);
			
			// waiting for thread termination
			pthread_join(tid, NULL);
			printf("*TID# %lu is exited.\n", tid);
		}

		// v func of semaphore(post)
		printf("*PID# %d exited the critical zone.\n", pid);
		v(semid);

		//close
		close(socket_fd);
		closedir(hash_dp);
		closedir(cache_dp);
		fclose(log);
		fclose(cacheFile);
		return 1;
	}

/////////////// End of create cache directory and file ///////////////	

}

int hasFile(DIR *dp, char* fileName)
{
	struct dirent *d;	// directory entry d

	while(d = readdir(dp))	// directory entry is not null
	{
		if(strcmp(d->d_name, fileName) == 0)
		{ // directoy has file
			rewinddir(dp);
			return 1;
		}
	}

	// no such file
	rewinddir(dp);
	return 0;
}

char *getHomeDir(char *home)
{
	struct passwd *usr_info = getpwuid(getuid());
	strcpy(home, usr_info->pw_dir);

	return home;
}

char *sha1_hash(char *input_url, char *hashed_url)
{
	unsigned char hashed_160bits[20];	// raw hashed url
	char hashed_hex[41];			// hexadecimal hashed url
	int i;
	
	// sha-1 hashing
	SHA1(input_url,strlen(input_url),hashed_160bits);
	
	// convert hashed data to hexadecimal
	for(i = 0; i <sizeof(hashed_160bits); i++)
		sprintf(hashed_hex + i*2, "%02x", hashed_160bits[i]);

	// hashed_url = hashed_hex
	strcpy(hashed_url, hashed_hex);

	return hashed_url;
}

char* getIPAddr(char* addr)
{
	struct hostent* hent;
	char* haddr;
	int len = strlen(addr);

	// get host entry of url
	if( (hent = (struct hostent*)gethostbyname(addr)) != NULL)
	{
		// get ip address from host entry
		haddr = inet_ntoa(*((struct in_addr*)hent->h_addr_list[0]));
	}
	// return ip address
	return haddr;
}

int sendRequest(char* request, char* ip)
{
	// socket variables
	int socket_fd;
	struct sockaddr_in server_addr;
	
	// create socket
	if( (socket_fd = socket(PF_INET, SOCK_STREAM, 0)) < 0 )
		exit(1);

	// set server address
	memset( (char*)&server_addr, 0, sizeof(server_addr) );
	server_addr.sin_family = AF_INET;
	server_addr.sin_addr.s_addr = inet_addr(ip);
	server_addr.sin_port = htons(80);

	// alarm 10 seconds
	alarm(10);

	// try until connected
	while(connect(socket_fd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0);

	// clear
	alarm(0);

	// send request message to web server
	write(socket_fd, request, strlen(request));

	// return file descriptor
	return socket_fd;
}

void sendResponse(int socket_fd, int client_fd, FILE* cacheFile)
{
	// alarm 10 seconds
	alarm(20);

	// receive response message to web server
	char response[BUFFSIZE];
	int len;
	if(len = read(socket_fd, response, BUFFSIZE))
		alarm(0); // clear
	while(1)
	{
		// send and write
		write(client_fd, response, len);
		fwrite(response, len, 1, cacheFile);

//fwrite(response, BUFFSIZE, 1, stdout);
		// end of reading
		if(len < BUFFSIZE) break;

		// mem set 0
		memset(response, 0, BUFFSIZE);

		// receive response from web server
		len = read(socket_fd, response, BUFFSIZE);
	}
}

void p(int semid)
{
	// set sembuf
	struct sembuf pbuf;
	pbuf.sem_num = 0;		// 1st sem
	pbuf.sem_op = -1;		// want to use resource
	pbuf.sem_flg = SEM_UNDO;	// automatically undo
	// perform semaphore operations
	if((semop(semid, &pbuf, 1)) == -1)
	{
		printf("p : semop failed\n");
		exit(1);
	}
}

void v(int semid)
{
	// set sembuf
	struct sembuf vbuf;
	vbuf.sem_num = 0;		// 1st sem
	vbuf.sem_op = 1;		// end of use
	vbuf.sem_flg = SEM_UNDO;	// automatically undo
	// perform semaphore operations
	if((semop(semid, &vbuf, 1)) == -1)
	{
		printf("v : semop failed\n");
		exit(1);
	}
}

void* thr_log(void* arg)
{
	// casting arg to Thread_arg structure
	struct Thread_arg* log = arg;

	// write log file
	fputs(log->message, log->log);
	
	// exit thread
	pthread_exit((void*)0);
}
