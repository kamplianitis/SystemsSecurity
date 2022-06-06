#include "utils.h"

/*
 * Prints the hex value of the input
 *
 * arg0: data
 * arg1: data len
 */
void
print_hex(unsigned char *data, size_t len)
{
	size_t i;

	if (!data)
		printf("NULL data\n");
	else {
		for (i = 0; i < len; i++) {
			if (!(i % 16) && (i != 0))
				printf("%02X ", data[i]);
			printf("%02X ", data[i]);
		}
		printf("\n");
	}
}


/*
 * Prints the input as string
 *
 * arg0: data
 * arg1: data len
 */
void
print_string(unsigned char *data, size_t len)
{
	size_t i;

	if (!data)
		printf("NULL data\n");
	else {
		for (i = 0; i < len; i++)
			printf("%c", data[i]);
		printf("\n");
	}
}


/*
 * Prints the usage message
 */
void
usage(void)
{
	printf(
	    "\n"
	    "Usage:\n"
	    "    assign_3 -g \n" 
	    "    assign_3 -i in_file -o out_file -k key_file [-d | -e]\n" 
	    "    assign_3 -h\n"
	);
	printf(
	    "\n"
	    "Options:\n"
	    " -i    path    Path to input file\n"
	    " -o    path    Path to output file\n"
	    " -k    path    Path to key file\n"
	    " -d            Decrypt input and store results to output\n"
	    " -e            Encrypt input and store results to output\n"
	    " -g            Generates a keypair and saves to 2 files\n"
	    " -h            This help message\n"
	);
	exit(EXIT_FAILURE);
}


/*
 * Checks the validity of the arguments
 *
 * arg0: path to input file
 * arg1: path to output file
 * arg2: path to key file
 * arg3: operation mode
 */
void
check_args(char *input_file, char *output_file, char *key_file, int op_mode)
{
	if ((!input_file) && (op_mode != 2)) {
		printf("Error: No input file!\n");
		usage();
	}

	if ((!output_file) && (op_mode != 2)) {
		printf("Error: No output file!\n");
		usage();
	}

	if ((!key_file) && (op_mode != 2)) {
		printf("Error: No user key!\n");
		usage();
	}

	if (op_mode == -1) {
		printf("Error: No mode\n");
		usage();
	}
}


// i have  to create functions that will read from the file  and write to a  file
// used them in previous excercises

int
file_size(FILE *fp)
{
	int len;
	fseek(fp, 0, SEEK_END);
	len = ftell(fp);
	fseek (fp, 0, SEEK_SET);
	return len;
}




unsigned  char* 
InputFile_Read(char *input_file, int* file_len)
{
	FILE *fp;

	if(!(fp =fopen(input_file, "rb+"))) // case it cannot open the file
	{
		printf("Cannot open the file");
		return NULL;
	}
	else 
	{
		unsigned char* data;
		long int len = file_size(fp);

		data = (unsigned char*)calloc(len,sizeof(unsigned char));

		if(fread(data,1,len,fp))
		{
			fclose(fp);
			(*file_len) = len;
			return data;
		}
		else
		{
			return NULL;
		}
	}

}

void 
Write_Data(char* output_file, unsigned char* data, int data_len, char* mode)
{
	FILE *fp;

	if(!(fp = fopen(output_file, mode))) // in case of something goes wrong in the opening
	{
		printf("Something went wrong with opening the file\n");
	}
	else
	{
		if(!fwrite(data,1,data_len, fp)) // same here but for writing
		{
			printf("Something went wrong on writing the file\n");
			fclose(fp);
		}
		else
		{
			fclose(fp);
		}
	}
}


// carefull this will only write one size_t in the file at time
// mode added so I can append the next size_t if I need  to 
void Write_sizeT(char* output_file, size_t* data, char * mode)
{
	FILE *fp;

	if(!(fp = fopen(output_file, mode)))
	{
		printf("Something went wrong with opening the file\n");
	}
	else
	{
		if(!fwrite(data,sizeof(size_t) ,1, fp))
		{
			printf("Something went wrong on writing the file\n");
			fclose(fp);
		}
		else
		{
			fclose(fp);
		}
	}
}
