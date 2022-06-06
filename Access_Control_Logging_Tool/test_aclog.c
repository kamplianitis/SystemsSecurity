#include <stdio.h>
#include <string.h>
#include <sys/stat.h>


int main() 
{
	int i;
	size_t bytes;
	FILE *file;
	char filenames[10][7] = {"file_0", "file_1", 
			"file_2", "file_3", "file_4",
			"file_5", "file_6", "file_7", 		
			"file_8", "file_9"};


	/* example source code */

	for (i = 0; i < 10; i++) {

		file = fopen(filenames[i], "w+");
		if (file == NULL) 
			printf("fopen error\n");
		else {
			bytes = fwrite(filenames[i], strlen(filenames[i]), 1, file);
			fclose(file);
		}

	}
	/* add your code here */
	char files_2[7][8]={"file_16","file_17","file_18","file_19","file_20","file_21","file_22"};
	
	// testing opening a file that does not exist... should be written in the file log
	// this  is mostly for checking the malicious user
	for(int i=0; i<7; i++)
	{
		file = fopen(files_2[i],"r");
	}
	// for checking the modification... we see that in the open the fingerprints match with the last fwrite
	file = fopen(filenames[1], "w");
	bytes = fwrite(filenames[1], strlen(filenames[1]), 1, file);
	fclose(file);


	// try to write with no write priviledges
	chmod(filenames[0], S_IRUSR); // only read for user
	file = fopen(filenames[0], "r");
	bytes =  fwrite(filenames[1], strlen(filenames[1]), 1, file); 
	fclose(file);


	// try to read a file that has not read priviledges
	int check = chmod(filenames[0], S_IWUSR); // only write for user
	file = fopen(filenames[0],"r");
	fclose(file);

}
