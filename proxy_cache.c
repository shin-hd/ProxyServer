//////////////////////////////////////////////////////////////////
// File Name	: proxy_cache.c					//
// Date		: 2021/03/27					//
// Os		: Ubuntu 20.04 LTS 64bits			//
// Author	: Shin Hae Dam					//
// Student ID	: 2017202088					//
// ------------------------------------------------------------ //
// Title : System Programing Assignment #1-2 (proxy server)	//
// Desciption	: Proxy Cache Server Program.			//
// 		  Receives an input_URL and			//
// 		  stores the hashed data of the URL.		//
//////////////////////////////////////////////////////////////////

#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <openssl/sha.h>
#include <stdio.h>
#include <string.h>
#include <dirent.h>
#include <fcntl.h>
#include <unistd.h>
#include <pwd.h>
#include <time.h>

//////////////////////////////////////////////////////////////////
// run								//
// ============================================================ //
// Output: int	0 success					//
// 		-1 fail						//
// Purpose: Run main porcess					//
//////////////////////////////////////////////////////////////////
int run();

//////////////////////////////////////////////////////////////////
// run_sub							//
// ============================================================ //
// Input: char* -> Home Directory Path,				//
// 	  char* -> Log File Path				//
// Output: int	0 success					//
// 		-1 fail						//
// Purpose: Run sub process					//
//////////////////////////////////////////////////////////////////
int run_sub(char *path, char *logPath);

//////////////////////////////////////////////////////////////////
// hasFile							//
// ============================================================ //
// Input: DIR* -> Directory Pointer,				//
// 	  char* -> File Name					//
// Output: int	1 has file					//
// 		0 no such file					//
// Purpose: Check if directory contains file			//
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
// Input: char* -> input_url before hashed			//
// 	  char* -> hashed_url that hash data will be written	//
// Output: char* -> porinter of hashed url data			//
// Purpose: Hashing the input url				//
//////////////////////////////////////////////////////////////////
char *sha1_hash(char *input_url, char *hashed_url);

//////////////////////////////////////////////////////////////////
// Main								//
// ============================================================ //
// Purpose: Main of Proxy Cache Server				//
//////////////////////////////////////////////////////////////////
void main()
{
	if(run() < 0)	// run
	{ // error
		printf("Unexpected Error\n");
	}
}

int run()
{
	char homePath[100] = {0,},	// home path
	     input_cmd[100] = {0,};	// input command
	time_t start_time, end_time;	// time of start, end
	int status,			// wait status
	    sub_process_count = 0;	// sub process count
	pid_t myPID, subPID;		// my pid, sub pid

	char logPath[50];		// log path
	DIR *log_dp;			// log dir
	FILE* log;			// log file

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
	
	// get my pid
	myPID = getpid();

	// start time
	time(&start_time);

	// recieving command loop
	while(1)
	{
		// recieve cmd
		printf("[%d]input CMD> ", myPID);
		scanf("%s", input_cmd);

		if(strcmp(input_cmd, "connect") == 0)
		{	// connect
			if((subPID = fork()) < 0)
			{ // error
				printf("fork error\n");
			}
			else if(subPID == 0)
			{ // child
				// run sub act
				if(run_sub(homePath, logPath) < 0)
				{ // error
					printf("cache error\n");
					return -1;
				}
				return 0;
			}
			else
			{ // parent
				// sub count + 1
				sub_process_count++;
				if(subPID = waitpid(subPID, &status, 0) < 0)
				{ // waitpid error
					printf("waitpid error\n");
				}
			}				
		}
		else if(strcmp(input_cmd, "quit") == 0)
		{	// quit
			time(&end_time);	// end time
			break;
		}
		else
		{	// no such cmd
			printf("%s: command not found\n", input_cmd);
		}
	} // while end

	// open log file for append mode
	log = fopen(logPath, "a");

	// write server end log msg
	fprintf(log, "**SERVER** [Terminated] run time: %ld sec. #sub process: %d\n", end_time - start_time, sub_process_count);

	// file close 
	fclose(log);
	return 0;
}

int run_sub(char *path, char *logPath)
{
	char input_url[100] = {0,},	// input url
	     hashed_url[41] = {0,};	// hashed url data
	DIR *cache_dp,			// cache directory pointer
	    *hash_dp;			// hashed data directory pointer
	char hashDirName[4] = {0,},	// hashed data directory name
	     hashDirPath[100]; 		// hashed data directory path
	FILE* log;			// logfile
	int hit = 0, miss = 0;		// hit, miss count
	time_t start_time,		// start time
		current_time;		// current time
	struct tm* cur_tm;		// current tm
	pid_t myPID = getpid();		// my pid

	// start time
	time(&start_time);

	// umask = 000
	umask(0);

	// open log file for append mode
	log = fopen(logPath, "a");

	// open cache directory
	if((cache_dp = opendir(strcat(path, "/cache/"))) == NULL)
	{ // if cache directory does not exist, make directory
		mkdir(path, 0777);
		cache_dp = opendir(path);
	}

	// receiving url loop
	while(1)
	{
		// receive url
		printf("[%d]input URL> ", myPID);
		scanf("%s", input_url);

		// get current time struct
		time(&current_time);
		cur_tm = localtime(&current_time);

		// receive Bye command
		if(strcmp(input_url, "bye") == 0)
			break;

		// hashDirName = hashed_url[0:3]
		strncpy(hashDirName, sha1_hash(input_url, hashed_url), 3);
		
		// hashDirPath = ~/cache/hashDirName/
		strcpy(hashDirPath, path);
		strcat(hashDirPath, hashDirName);
		strcat(hashDirPath, "/");

		// umask = 000
		umask(0);

	/////////////// Create cache directory and file ///////////////	

		// if hashed url directory does not exist, make it
		if(!hasFile(cache_dp, hashDirName))
		{
			mkdir(hashDirPath, 0777);
		}

		// open hashed url directory
		hash_dp = opendir(hashDirPath);
		
		if(hasFile(hash_dp, &hashed_url[3]))
		{ // hashed url file already exists // HIT
			hit++;

			// write hit log msg
			fprintf(log, "[HIT]%s/%s-[%04d/%02d/%02d, %02d:%02d:%02d]\n", hashDirName, &hashed_url[3], cur_tm->tm_year + 1900, cur_tm->tm_mon + 1, cur_tm->tm_mday, cur_tm->tm_hour, cur_tm->tm_min, cur_tm->tm_sec);
			fprintf(log, "[HIT]%s\n", input_url);
		}
		else
		{ // no hashed url file // MISS
			creat(strcat(hashDirPath, &hashed_url[3]), 0666);
			miss++;
			
			// write miss log msg
			fprintf(log, "[Miss]%s-[%04d/%02d/%02d, %02d:%02d:%02d]\n", input_url, cur_tm->tm_year + 1900, cur_tm->tm_mon + 1, cur_tm->tm_mday, cur_tm->tm_hour, cur_tm->tm_min, cur_tm->tm_sec);
		}

		// close hashed url directory
		closedir(hash_dp);

	/////////////// End of create cache directory and file ///////////////	
	
	}

	// write end log msg
	fprintf(log, "[Terminated] run time: %ld sec. #request hit : %d, miss : %d\n", current_time - start_time, hit, miss);

	// close
	closedir(cache_dp);
	fclose(log);
	return 0;
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
