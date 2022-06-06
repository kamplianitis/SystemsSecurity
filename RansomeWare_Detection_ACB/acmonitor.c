#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

struct entry {

	int uid; /* user id (positive integer) */
	int access_type; /* access type values [0-2] */
	int action_denied; /* is action denied values [0-1] */

	char* date; /* file access date */
	char* time; /* file access time */

	char *file; /* filename (string) */
	char *fingerprint; /* file fingerprint */
};


void
usage(void)
{
	printf(
	       "\n"
	       "usage:\n"
	       "\t./monitor \n"
		   "Options:\n"
		   "-m, Prints malicious users\n"
		   "-i <filename>, Prints table of users that modified "
		   "the file <filename> and the number of modifications\n"
		   "-h, Help message\n\n"
		   );

	exit(1);
}

/*
file_notlisted function 

This function is created in order to check if the file that is examined right now  is in the list of maliciously processed files 
by the same user. 
*/
int file_notlisted(char * filepath, char files[][255], int lines)
{
	for(int i=0; i<lines; i++)
	{
		int check = strcmp(files[i], filepath);

		if(check == 0)
		{
			return 0;
		}
	}
	return 1;
}


/*
uid_notlisted function

This function is used in order to check if the specific user's uid is in the list of the uids we keep for a specific reason 
in the following funcions
*/
int uid_notlisted(int uid, int *uids, int lines)
{
	for(int i=0; i<lines; i++)
	{
		if(uids[i] == uid)
		{
			return 0;
		}
	}
	return 1;
}


/*
load from file function 
takes the file log and then spilts each line to parts in order to pass it into structs given
*/
struct entry * load_from_file(FILE* log, int* lines1)
{
    int lines =0;
    char c; // there is the tmp char that will be checked every time until eof.


	c = getc(log);
	while(c!= EOF)
	{
		if(c == '\n')
		{
			lines++;
		}
		c = getc(log);
	}
	fseek(log, 0, SEEK_SET);
    (*lines1) = lines;
	// now that i have the number of lines i can create the same amount of entry structs
	struct entry *total_entries = (struct entry *)malloc(lines*sizeof(struct entry));

	// now i created enough space for every entry that has been done. 
	// so i have to fill them with the info of each line.
	ssize_t read;
	int entry_counter=0;
	char *line;
	size_t line_len=0;

	while((read = getline(&line, &line_len, log))!= -1) // read each line
	{
		// fill the uid
		total_entries[entry_counter].uid = atoi(strsep(&line,"\t"));
		// fill the file including the file path
		total_entries[entry_counter].file = strsep(&line,"\t");
		// take the date
		total_entries[entry_counter].date = strsep(&line,"\t");
		// take the hour 
		total_entries[entry_counter].time = strsep(&line,"\t");
		// take the access type
		total_entries[entry_counter].access_type = atoi(strsep(&line,"\t"));
		// take the action denied flag
		total_entries[entry_counter].action_denied = atoi(strsep(&line,"\t"));
		// take the fingerprint
		total_entries[entry_counter].fingerprint = strsep(&line,"\t");
		// now that i passed all the data increase the counter
		entry_counter++;
	}
    return total_entries;
}






/*
list_unauthorized_accesses function

The function does the following.

As long as the .log file keeps track of the entries that have been done all it has to be done to find the entries is to find the amount of lines in the file.
after that with a malloc function it creates enough space for (line) entries in order to fill all the information from the file. Then for each entry it takes the user
and check for each line for malicious acts (action_denied ==1). If the actions are more than 7 it prints the user.
*/

void 
list_unauthorized_accesses(FILE *log)
{

	/* add your code here */
	// the log file contains all the entries so i can know the number of entries by counting the amount of the lines in the file.
	int lines =0;
	// call the function to load the data into structs 
	struct entry *total_entries = load_from_file(log, &lines);
	// now that the data are filled. I have to check for every user how many malicious acts have been done by him.
	char files[lines][255]; // i will keep the files for each user 
	for(int i=0; i<lines; i++) // initialize the files array in order to print only the malicious lines.
	{
		files[i][0] = 'e';
	}
	int* users = (int *)calloc(lines, sizeof(int)); // keep track of the users with malicious acts so we don't print them again.

	for(int i=0; i<lines; i++)
	{
		int uid_user = total_entries[i].uid; // get the uid of the user and search by it
		int denied_in_diff_files = 0;
		// for the entries
		for(int c =0; c<lines; c++)
		{
			if(total_entries[c].action_denied == 1) // check the flag
			{
				if(uid_user == total_entries[c].uid && file_notlisted(total_entries[i].file, files, lines) == 1) 
				{
					denied_in_diff_files ++; // keep track of the malicious actions of the user
					strcpy(files[c], total_entries[c].file); // not sure about this line. Have to  debug it
				}
			}
		}
		if(denied_in_diff_files >= 7) // Print the malicious user, the number of malicious actions and the files that he's done that
		{
			if(uid_notlisted(uid_user, users,lines) ==1)
			{
				printf("User with uid %d has too much malicious activity (%d tries)\n",uid_user, denied_in_diff_files);
				users[i] = uid_user;
				printf("The files that he tried to maliciously edit are:\n");
				for(int i=0; i<lines; i++)
				{
					if(files[i][0] != 'e')
					{
						printf("%s\n", files[i]);
					}
				}
			}
			
		}
	}
	return;
}

/*
list_file_modifications function

The function does the following.

again the function takes the the number of lines and pases the data into the struct array. After that the function creates again dynamically an array 
for the fingerprint and two more one for the users and one for the modifications. Then, given the name of the file it checks in the entries array if there 
are other entries in the file. If there are, it checks the fingerpint of the entry with the last fingerprint found. If the fingerprints are not alike then the user
either is getting written in the users array and makes the coresponding mods 1 or getting found in the user array and increases the coresponding mods by one. 
In the end the function prints the users and the amount of modifications they did in the specific file.
*/
void
list_file_modifications(FILE *log, char *file_to_scan)
{
	// take the real path so i can check everything
	char* path = realpath(file_to_scan,NULL);
	/* add your code here */
		// the log file contains all the entries so i can know the number of entries by counting the amount of the lines in the file.
	int lines =0;
	struct entry *total_entries = load_from_file(log, &lines);
	// i use calloc to create those cause it iniitialises to 0
	int* users = (int*)calloc(lines, sizeof(int)); 
	int* mods = (int*)calloc(lines, sizeof(int));

	int len_fingerprint = strlen(total_entries[0].fingerprint);  // use it as a meter cause the fingerprint has standard size
	char * fingerprint_last = (char *)calloc(len_fingerprint, sizeof(char));

	for(int i=0; i< lines; i++)
	{
		if(strcmp(total_entries[i].file, path) == 0) 
		{
			if(total_entries[i].action_denied == 0 && uid_notlisted(total_entries[i].uid, users,lines) == 1)
			{
				if( strcmp(total_entries[i].fingerprint, fingerprint_last) != 0) // check the fingerprints
				{ 
					// if new then rememeber the user and fingerprint to check in the next one
					users[i] = total_entries[i].uid;
					strcpy(fingerprint_last, total_entries[i].fingerprint);
					mods[i] = mods[i] +1;
				}
			}
			else if(total_entries[i].action_denied == 0 &&uid_notlisted(total_entries[i].uid, users,lines) == 0) // if the user is already listed add its modifications 
			{	
				// i need to find the user that is in the table and update the modifications he has
				if(strcmp(total_entries[i].fingerprint, fingerprint_last) != 0)
				{
					for(int j=0; j<lines; j++)
					{
						strcpy(fingerprint_last, total_entries[i].fingerprint);
						if(users[j] == total_entries[i].uid)
						{
							mods[j] = mods[j] +1; // increase the modifications of the user by one
						}
					}
				}	
			}
		}
	}

	printf("For the file %s the user modification table is:\n", file_to_scan); // print the user and the amount of modifications
	for(int i=0; i<lines; i++)
	{
		if(users[i] == 0 || mods[i] ==0)
		{
			continue;
		}
		else
		{
			printf("User: %d \t Modifications %d\n", users[i], mods[i]);
		}
	}
	// free he dynamically alocated memory
	free(users);
	free(mods);
	free(fingerprint_last);
}
/*
	twenty_min_check

	arg0: struct entry * total_entries -> entries of the log file
	arg1: int lines -> the amount of lines in a file 

	checks if every entry in the entries given has a date and time that is at most 20 mins before the date and time this function has been called
*/
int twenty_min_check(struct entry * total_entries, int lines)
{
    time_t t = time(NULL);
  	struct tm tm = *localtime(&t);

	int numoffiles = 0;
	for(int i=0; i<lines; i++)
	{
		if(total_entries[i].access_type == 0 && total_entries[i].action_denied != 1)
		{
			int month; 
			int day;
			int year;
			int hours;
			int min;
			long int sec;
			
			day = atoi(strsep(&total_entries[i].date, "/"));
			month = atoi(strsep(&total_entries[i].date, "/"));
			year = atoi(strsep(&total_entries[i].date, "/"));

			hours = atoi(strsep(&total_entries[i].time, ":"));
			min = atoi(strsep(&total_entries[i].time, ":"));
			sec = atoi(strsep(&total_entries[i].time, ":"));

			sec += 60*min;
			long int secnow = tm.tm_sec + tm.tm_min*60;
			
			if(year == (tm.tm_year+1900))
			{
				if(month == (tm.tm_mon +1))
				{
					if(day == tm.tm_mday)
					{
						
						if(secnow - sec <= 1200)
						{
							numoffiles++;
						}
					}
					else if(day == (tm.tm_mday +1) && tm.tm_hour == 0 && hours == 23 && tm.tm_min < 20 && min > 40)
					{
						secnow += 3600;
						if(secnow - sec <= 1200)
						{
							numoffiles++;
						}
					}
				}
				else if(month == (tm.tm_mon +2) && tm.tm_mday == 1 && tm.tm_hour == 0 && hours == 23 && tm.tm_min < 20 && min > 40)
				{
					if(day == 31 && (month == 0 || month == 2 || month == 4 || month == 6 || month == 7 || month ==9 || month == 11))
					{
						secnow += 3600;
						if(secnow - sec <= 1200)
						{
							numoffiles++;
						}
					}
					else if(day == 30 && (month == 3 || month == 5 || month == 8 || month == 10))
					{
						secnow += 3600;
						if(secnow - sec <= 1200)
						{
							numoffiles++;
						}
					}
					else if( (day == 29 && (year%4) ==0) || (day==28 && (year%4) !=0))
					{
						secnow += 3600;
						if(secnow - sec <= 1200)
						{
							numoffiles++;
						}
					}
				}
			}
			else if( year == (tm.tm_year + 1901) && day == 31 && month == 12 && hours == 23 && min > 40 && (tm.tm_mday +1) == 1 && tm.tm_hour == 0 && tm.tm_min < 20)
			{

				secnow += 3600;
				if(secnow - sec <= 1200)
				{
					numoffiles++;
				}
			}
		}
	}
    return numoffiles;
}
/*
	files_created_detector

	arg0: FILE *log -> the logger that the function will read the actions
	arg1: int optarg -> The number that above that the pogramm considers it a malicious action

	The function check if each entry that is about file creation (access_type == 0) and checks if it has been created at most 20 minutes before  
*/
void files_created_detector(FILE *log, int optarg)
{
	// the log file contains all the entries so i can know the number of entries by counting the amount of the lines in the file.
	int lines =0;
	struct entry *total_entries = load_from_file(log, &lines);

	int numoffiles = twenty_min_check(total_entries,lines);
	
	printf("%d files are created the last 20 minutes!\n", numoffiles);
	if( numoffiles >= optarg)
	{
		printf("Too many file created. Possible malicious activity\n");
	}
	else
	{
		printf("No sign of malicious activity!");
	}
}

/*
	detect_enc_files

	arg1: FILE* log -> the logger that the function will read the actions

	The function checks each entry for detecting if there is a creation of a .txt.encrypt file after the opening of a file with the same path-name.
*/
void detect_enc_files(FILE* log)
{
		// the log file contains all the entries so i can know the number of entries by counting the amount of the lines in the file.
	int lines =0;
	// load from the file to entries
	struct entry *total_entries = load_from_file(log, &lines);
	printf("The files that opened and then .encrypt file created were: \n\n");
	
	for(int i=1; i<lines; i++)
	{		
		if(total_entries[i].access_type == 0 && total_entries[i].action_denied !=1) // check for valid action_denied_flag and that the file is beeing created
		{
			char* filename_tmp = (char*)malloc(strlen(total_entries[i].file)*sizeof(char));
			strcpy(filename_tmp, total_entries[i].file); // copy the string in order to not ruin the entry after
			
			char *tmpcut = strstr(filename_tmp, ".txt.encrypt");
			
			if(tmpcut != NULL)
			{
				// modify the entry to check for the previous file
				long int position = strlen(total_entries[i].file)-strlen(tmpcut); 

				filename_tmp[position] ='\0';

				int result = strcmp(filename_tmp, total_entries[i-1].file);
				if(result == 0)
				{
					printf("%s \n", total_entries[i-1].file);
				}
			}
		}
	}
}


int 
main(int argc, char *argv[])
{

	int ch;
	FILE *log;

	if (argc < 2)
		usage();

	log = fopen("./file_logging.log", "r");
	if (log == NULL) {
		printf("Error opening log file \"%s\"\n", "./log");
		return 1;
	}

	while ((ch = getopt(argc, argv, "hi:v:em")) != -1) {
		switch (ch) {		
		case 'i':
			list_file_modifications(log, optarg);
			break;
		case 'm':
			list_unauthorized_accesses(log);
			break;
		case 'e':
			detect_enc_files(log);
			break;
		case 'v':
			files_created_detector(log, atoi(optarg));
			break;
		default:
			usage();
		}

	}
	fclose(log);
	argc -= optind;
	argv += optind;	
	
	return 0;
}
