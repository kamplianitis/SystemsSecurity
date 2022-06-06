#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>

int main(int argc, char *argv[])
{

    if(argc != 3 )
    {
        return -1;
    }
    char *filename = argv[1];
    int nooffiles = atoi(argv[2]);
    // now all i need is to create random files 
    for(int i=0; i< nooffiles; i++)
    {
        // create the name of the file
    	char *filenames = (char*)calloc(30, sizeof(char));
    	sprintf(filenames, "RansomFile_%d",i);
    	
        // create the file name to create the file in the right directory
        char *realFile = (char*)calloc(100, sizeof(char));
        // pass the path 
        strcat(realFile, argv[1]);

        // now pass the file name
        strcat(realFile, filenames);


        // create the file
        FILE* filenew = fopen(realFile, "w");

        // create the buffer to write to the files
    	char* contentsfile = (char*)calloc(50, sizeof(char));


        int fd = open("/dev/urandom", O_RDONLY);
        read(fd, contentsfile, 30);
        //buffer now contains the random data
        contentsfile[31] = '\0';
        close(fd);

        fwrite(contentsfile, 1, strlen(contentsfile), filenew);
        fclose(filenew);
        
        free(filenames);
        free(realFile);
        free(contentsfile);
    }
    return 0;
}
