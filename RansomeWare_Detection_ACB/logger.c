#define _GNU_SOURCE
#include <time.h>
#include <stdio.h>
#include <dlfcn.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/stat.h>
#include <openssl/md5.h>
#include <errno.h>

FILE *
fopen64(const char *path, const char *mode) 
{
	return fopen(path, mode);
}

/*
fopen function

The fopen function collects info about the action that is going to be made before it happens. It collects the uid of the user, the date and time the file tried to get oppened, 
if the user had the rights to open it and what's the fingerprint of the file. Then it stores all this info to a .log file in order to keep track of possible malicious actions 
in the files and file modifications. After this process the function calls the original fopen in orded to complete the opening of the file.
*/


FILE *
fopen(const char *path, const char *mode) 
{

	FILE *original_fopen_ret;
	FILE *(*original_fopen)(const char*, const char*);

	// now that we have the path we can check everything about existence and access points.
	int access_type=0;
	int action_denied_flag;
	/* call the original fopen function */
	// beginning of the check
	original_fopen = dlsym(RTLD_NEXT, "fopen");
	if (access(path, F_OK) == 0) 
	{
		access_type =1;
		// check all the flags first so i don't have to run the functions again and again
		int read_right = access(path, R_OK);
		int write_right = access(path,W_OK);
		// now that i have all the rights all i have to do is check the values for every mode
		if(strcmp(mode,"r")==0 || strcmp(mode,"rb")==0)
		{
			if(read_right == 0)
			{
				action_denied_flag = 0;
			}
			else
			{
				action_denied_flag = 1;
			}
		}
		else if(strcmp(mode,"r+") ==0 || strcmp(mode,"w+") ==0 || strcmp(mode, "wb+")==0 || strcmp(mode,"rb+") ==0)
		{
			if(write_right == 0 && read_right == 0)
			{
				action_denied_flag = 0;
			}
			else
			{				
				action_denied_flag = 1;
			}
		}
		else if(strcmp(mode,"w") ==0 || strcmp(mode,"wb") ==0 || strcmp(mode, "a")==0 || strcmp(mode,"ab") ==0)
		{
			if(write_right ==0)
				action_denied_flag = 0;
			else
				action_denied_flag = 1;
		}
	}
	else // case the file does not exist.
	{
		access_type =0;
		if(mode[0] == 'r') // 
			action_denied_flag =1;
		else
			action_denied_flag =0;
	}
	

	/* add your code here */

	original_fopen = dlsym(RTLD_NEXT, "fopen");
	original_fopen_ret = (*original_fopen)(path, mode);
	// get the uid.
	int uid_user = (int)getuid();

	// to take the full path of the file i use the realpath().
	char *real_path  = realpath(path, NULL);
	int real_path_flag=1;
	// prevent the NULL path case -> file does not exist
	if(real_path == NULL)
	{
		real_path_flag = 0;
	}
	else
	{
		real_path_flag = 1;
	}

	time_t datetime = time(NULL);
	// fix the time
	struct tm localtm = *localtime(&datetime);


	// file fingerprint 
	unsigned char fingerprintHash[32] ={0};
	
	// all that is remaining is to store the info to the file logger.
	FILE* original_fopen_ret_hash = (*original_fopen)(path, "rb");
	if(original_fopen_ret_hash != NULL)
	{
		fseek(original_fopen_ret,0,SEEK_END); // find the end of the file
		int file_size = ftell(original_fopen_ret); // take the size of the file.s
		fseek(original_fopen_ret, 0, SEEK_SET); // reset the pointer at the start of the file
		
		// i need the array in order to save the contents of the file
		unsigned char* filecontents = (unsigned char*)malloc(file_size*sizeof(unsigned char));
		// store the contents of the file in the array i created
		fread(filecontents,file_size,1,original_fopen_ret_hash);

		MD5(filecontents, file_size, fingerprintHash);
		fclose(original_fopen_ret_hash);
	}
	// i use append so that i both create and append text into the file.
	FILE *file_logging = (*original_fopen)("file_logging.log", "a"); 
	if(real_path_flag == 1) // to prevent the file does not exist and the real_path will be written as null
	{
		fprintf(file_logging,"%u\t%s\t%02d/%02d/%d\t%02d:%02d:%02d\t%d\t%d\t",uid_user,real_path,localtm.tm_mday,localtm.tm_mon+1,localtm.tm_year+1900, localtm.tm_hour,localtm.tm_min, localtm.tm_sec,access_type ,action_denied_flag);
		for(int i=0; i<32; i++)
		{
			fprintf(file_logging,"%02x", fingerprintHash[i]);
		}
		fprintf(file_logging,"\n");
	}
	else 
	{
		
		fprintf(file_logging,"%u\t%s\t%02d/%02d/%d\t%02d:%02d:%02d\t%d\t%d\t",uid_user,path,localtm.tm_mday,localtm.tm_mon+1,localtm.tm_year+1900, localtm.tm_hour,localtm.tm_min, localtm.tm_sec, access_type,action_denied_flag);
		for(int i=0; i<32; i++)
		{
			fprintf(file_logging,"%02x", fingerprintHash[i]);
		}
		fprintf(file_logging,"\n");
	}	
	// close the file
	fclose(file_logging);

	return original_fopen_ret;
}
/*
Fwrite function 

Then function does the same thing as the fopen above but in this time it writes to the file. The function will write all the info including the uid, time and  date 
real path etc and store this information to the .log file. The fingerprint hash will be created based on the new text that is going to be imported. To find the real path
the function finds the file descriptor and through a process the file descriptor path and then the realpath.
*/
size_t 
fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream) 
{
	size_t original_fwrite_ret;
	size_t (*original_fwrite)(const void*, size_t, size_t, FILE*);


	/* add your code here */
	int access_type =2; // since we know we are writing. 

	// in order to find the name of the file i need to check the file* and get its 
	// file descriptor
	int file_descriptor = fileno(stream);

	// find the real path	
	char file_descriptor_path[255];
	char *real_path = malloc(255);

	sprintf(file_descriptor_path,"/proc/self/fd/%d", file_descriptor);
	int path_line = readlink(file_descriptor_path,real_path, 255);
	real_path[path_line] = '\0';


	// now i have to check for action denied.
	int action_denied_flag;

	if(access(real_path, W_OK) == 0) // it has write rights
	{
		action_denied_flag =0;
	}
	else
	{
		action_denied_flag = 1;
	}
	// get the uid
	int uid_user = (int)getuid();

	// time 
	time_t datetime = time(NULL);
	// fix the time
	struct tm localtm = *localtime(&datetime);


	// now the fingerprint
	unsigned char fingerprintHash[32] ={0};

	// we make the hashing based on the added content
	MD5_CTX ctx;
	MD5_Init(&ctx);

	// continue the md5 process 
	MD5_Update(&ctx,ptr,size*nmemb);

	MD5_Final(fingerprintHash, &ctx);

	// now i have to open the file logging and store the values i collected inside
	
	// i use append so that i both create and append text into the file. Use the original fopen so i don't write in the filelogging file.
	FILE *(*original_fopen)(const char*, const char*);
	original_fopen = dlsym(RTLD_NEXT, "fopen");
	
	FILE *file_logging = (*original_fopen)("file_logging.log", "a"); 
	fprintf(file_logging,"%u\t%s\t%02d/%02d/%d\t%02d:%02d:%02d\t%d\t%d\t",uid_user,real_path,localtm.tm_mday,localtm.tm_mon+1,localtm.tm_year+1900, localtm.tm_hour,localtm.tm_min, localtm.tm_sec, access_type,action_denied_flag);
	for(int i=0; i<32; i++)
	{
		fprintf(file_logging,"%02x", fingerprintHash[i]);
	}
	fprintf(file_logging, "\n");
	fclose(file_logging);
	/* call the original fwrite function */ // if the function tries to write while the action_denied_flag is up it will end up to seg fault
	original_fwrite = dlsym(RTLD_NEXT, "fwrite");
	original_fwrite_ret = (*original_fwrite)(ptr, size, nmemb, stream);
	return original_fwrite_ret;
}
