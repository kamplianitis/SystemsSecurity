#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>


#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/conf.h>
#include <openssl/cmac.h>

#define BLOCK_SIZE 16


/* function prototypes */
void print_hex(unsigned char *, size_t);
void print_string(unsigned char *, size_t); 
void usage(void);
void check_args(char *, char *, unsigned char *, int, int);
void keygen(unsigned char *, unsigned char *, unsigned char *, int);
int encrypt(unsigned char *, int, unsigned char *, unsigned char *, 
    unsigned char *, int );
int decrypt(unsigned char *, int, unsigned char *, unsigned char *, 
    unsigned char *, int);
void gen_cmac(unsigned char *, size_t, unsigned char *, unsigned char *, int);
int verify_cmac(unsigned char *, unsigned char *);
unsigned char* InputFile_Read(char *, int *);
int file_size(FILE *);
void Write_Data(char *, unsigned char *, int);
void concatenate_strings(unsigned char *, size_t, unsigned char * , size_t , unsigned char *);

/* TODO Declare your function prototypes here... */



/*
 * Prints the hex value of the input
 * 16 values per line
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
				printf("\n");
			printf("%02X ", data[i]);
		}
		printf("\n");
	}
}


/*
 * Prints the input as string
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
 * Describe the usage of the new arguments you introduce
 */
void
usage(void)
{
	printf(
	    "\n"
	    "Usage:\n"
	    "    assign_1 -i in_file -o out_file -p passwd -b bits" 
	        " [-d | -e | -s | -v]\n"
	    "    assign_1 -h\n"
	);
	printf(
	    "\n"
	    "Options:\n"
	    " -i    path    Path to input file\n"
	    " -o    path    Path to output file\n"
	    " -p    psswd   Password for key generation\n"
	    " -b    bits    Bit mode (128 or 256 only)\n"
	    " -d            Decrypt input and store results to output\n"
	    " -e            Encrypt input and store results to output\n"
	    " -s            Encrypt+sign input and store results to output\n"
	    " -v            Decrypt+verify input and store results to output\n"
	    " -h            This help message\n"
	);
	exit(EXIT_FAILURE);
}


/*
 * Checks the validity of the arguments
 * Check the new arguments you introduce
 */
void
check_args(char *input_file, char *output_file, unsigned char *password, 
    int bit_mode, int op_mode)
{
	if (!input_file) {
		printf("Error: No input file!\n");
		usage();
	}

	if (!output_file) {
		printf("Error: No output file!\n");
		usage();
	}

	if (!password) {
		printf("Error: No user key!\n");
		usage();
	}

	if ((bit_mode != 128) && (bit_mode != 256)) {
		printf("Error: Bit Mode <%d> is invalid!\n", bit_mode);
		usage();
	}

	if (op_mode == -1) {
		printf("Error: No mode\n");
		usage();
	}
}


/*
 * Generates a key using a password
 */
void
keygen(unsigned char *password, unsigned char *key, unsigned char *iv,
    int bit_mode)
{
	/* TODO Task A */
	// EVP_BytesToKey function that will be used
	if(bit_mode == 128)
	{
		EVP_BytesToKey(EVP_aes_128_ecb(), EVP_sha1(), NULL, password, strlen((char*)password),1,key,iv);
	}
	else if(bit_mode == 256) 
	{
		EVP_BytesToKey(EVP_aes_256_ecb(), EVP_sha1(), NULL, password, strlen((char*)password),1,key,iv);
	}
	else 
	{
		printf("Wrong byte mode.");
	}
}


/*
 * Encrypts the data
 */
int
encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
    unsigned char *iv, unsigned char *ciphertext, int bit_mode)
{

	/* TODO Task B */
	// initialize a pointer for ctx
	EVP_CIPHER_CTX *cipherctx;
	int len;
    int ciphertext_len;
	// initialize the new ctx cipher
	cipherctx = EVP_CIPHER_CTX_new(); 

	if(cipherctx == NULL)
	{
		printf("Error in creating new cipher ctx");
	}

	// now initialize the encryption 
	if(bit_mode == 128)
	{
		EVP_EncryptInit_ex(cipherctx, EVP_aes_128_ecb(), NULL, key, iv);
	}
	else if(bit_mode == 256)
	{

		EVP_EncryptInit_ex(cipherctx, EVP_aes_256_ecb(), NULL, key, iv);
	}

	// now keep the process based on openssl wiki
	EVP_EncryptUpdate(cipherctx, ciphertext, &len, plaintext,plaintext_len);
	ciphertext_len = len;
	EVP_EncryptFinal(cipherctx,ciphertext + len , &len);
	ciphertext_len += len;

	EVP_CIPHER_CTX_free(cipherctx);
    return ciphertext_len;
}


/*
 * Decrypts the data and returns the plaintext size
 */
int
decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
    unsigned char *iv, unsigned char *plaintext, int bit_mode)
{
	int plaintext_len;

	plaintext_len = 0;
	int len;
	/*TODO Task C */
	EVP_CIPHER_CTX *cipherctx;

	cipherctx = EVP_CIPHER_CTX_new(); 

	if(cipherctx == NULL)
	{
		printf("Error in creating new cipher ctx");
	}
	
	if(bit_mode == 128)
	{
		EVP_DecryptInit_ex(cipherctx, EVP_aes_128_ecb(), NULL, key, iv);
	}
	else if(bit_mode == 256)
	{

		EVP_DecryptInit_ex(cipherctx, EVP_aes_256_ecb(), NULL, key, iv);
	}

	EVP_DecryptUpdate(cipherctx, plaintext, &len, ciphertext, ciphertext_len);
	plaintext_len = len;

	EVP_DecryptFinal_ex(cipherctx, plaintext + len, &len);
	plaintext_len += len;

	/* Clean up */
    EVP_CIPHER_CTX_free(cipherctx);
	return plaintext_len;
}


/*
 * Generates a CMAC
 */
void
gen_cmac(unsigned char *data, size_t data_len, unsigned char *key, 
    unsigned char *cmac, int bit_mode)
{

	/* TODO Task D */
	CMAC_CTX * cmac_ctx = CMAC_CTX_new();
	if(cmac_ctx == NULL)
	{
		printf("Something went wrong the process cannot be continued \n");
	}
	switch (bit_mode)
	{
	case 128:
		CMAC_Init(cmac_ctx, key, 16, EVP_aes_128_ecb(),NULL);
		break;
	case 256:
		CMAC_Init(cmac_ctx, key, 32, EVP_aes_256_ecb(),NULL);
		break;
	default:
		printf("Wrong bit_mode");
		break;
	}
	size_t cmac_len;
	CMAC_Update(cmac_ctx, data, data_len);
	CMAC_Final(cmac_ctx, cmac, &cmac_len); 
	CMAC_CTX_free(cmac_ctx);
}


/*
 * Verifies a CMAC
 */
int
verify_cmac(unsigned char *cmac1, unsigned char *cmac2)
{
	int verify;

	verify = -1;
	/* TODO Task E */
	verify = memcmp(cmac1, cmac2, 16);
	return verify;
}



/* TODO Develop your functions here... */
// create a function to send the file size
int
file_size(FILE *fp)
{
	int len;
	fseek(fp, 0, SEEK_END);
	len = ftell(fp);
	fseek (fp, 0, SEEK_SET);
	return len;
}




unsigned char* 
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
Write_Data(char* output_file, unsigned char* data, int data_len)
{
	FILE *fp;

	if(!(fp = fopen(output_file, "wb+")))
	{
		printf("Something went wrong with opening the file\n");
	}
	else
	{
		if(!fwrite(data, 1,data_len, fp))
		{
			printf("Something went wrong on writing the file\n");
			fclose(fp);
		}
		else
		{
			printf("Writting complete\n");
			fclose(fp);
		}
	}
}

void
concatenate_strings(unsigned char* string1, size_t string1_len, unsigned char* string2 , size_t string2_len , unsigned char* final_str)
{
	for(int i=0; i< string1_len; i++)
	{
		final_str[i] = string1[i];
	}
	for(int i=0; i< string2_len; i++)
	{
		final_str[string1_len+i] = string2[i];
	}
}

/*
 * Encrypts the input file and stores the ciphertext to the output file
 *
 * Decrypts the input file and stores the plaintext to the output file
 *
 * Encrypts and signs the input file and stores the ciphertext concatenated with 
 * the CMAC to the output file
 *
 * Decrypts and verifies the input file and stores the plaintext to the output
 * file
 */
int
main(int argc, char **argv)
{
	int opt;			/* used for command line arguments */
	int bit_mode;			/* defines the key-size 128 or 256 */
	int op_mode;			/* operation mode */
	char *input_file;		/* path to the input file */
	char *output_file;		/* path to the output file */
	unsigned char *password;	/* the user defined password */

	/* Init arguments */
	input_file = NULL;
	output_file = NULL;
	password = NULL;
	bit_mode = -1;
	op_mode = -1;


	/*
	 * Get arguments
	 */
	while ((opt = getopt(argc, argv, "b:i:m:o:p:desvh:")) != -1) {
		switch (opt) {
		case 'b':
			bit_mode = atoi(optarg);
			break;
		case 'i':
			input_file = strdup(optarg);
			break;
		case 'o':
			output_file = strdup(optarg);
			break;
		case 'p':
			password = (unsigned char *)strdup(optarg);
			break;
		case 'd':
			/* if op_mode == 1 the tool decrypts */
			op_mode = 1;
			break;
		case 'e':
			/* if op_mode == 1 the tool encrypts */
			op_mode = 0;
			break;
		case 's':
			/* if op_mode == 1 the tool signs */
			op_mode = 2;
			break;
		case 'v':
			/* if op_mode == 1 the tool verifies */
			op_mode = 3;
			break;
		case 'h':
		default:
			usage();
		}
	}


	/* check arguments */
	check_args(input_file, output_file, password, bit_mode, op_mode);



	/* TODO Develop the logic of your tool here... */
	// initializations
	unsigned char iv[16] = {0}; // initialize everything to zero
	unsigned char key[bit_mode/8 +1];  // key depends on the encryption type
	unsigned char *data;
	unsigned char * encr_data;
	unsigned char * decr_data;
	unsigned char *cmac;
	int cipher_len;
	int data_len;
	int plain_len;
	
	/* Keygen from password */
	keygen(password, key,iv,bit_mode);  // in any case i need to take the key eitherway
	/* Operate on the data according to the mode */
	switch(op_mode)
	{
		case 0: 	/* encrypt */
			// call the input reader
			data = InputFile_Read(input_file, &data_len);
			//allocate the space for the encrypted data
			encr_data = (unsigned char*)malloc((data_len+16)*sizeof(unsigned char));
			// encrypt the data
			cipher_len = encrypt(data,data_len,key, iv,encr_data, bit_mode);
			// now write the encryption into a new file
			Write_Data(output_file, encr_data, cipher_len);
			
		break;
		
		case 1: 	/* decrypt */
			data = InputFile_Read(input_file,&data_len);

			decr_data = (unsigned char*)malloc(data_len*sizeof(unsigned char));

			plain_len = decrypt(data , data_len,key,iv,decr_data,bit_mode);

			Write_Data(output_file, decr_data, plain_len);
			
		break;

		case 2: /* sign */

			// call the input reader
			data = InputFile_Read(input_file, &data_len);
			
			//allocate the space for the encrypted data
			encr_data = malloc(2*data_len*sizeof(char));
			
			// encrypt the data
			cipher_len = encrypt(data,data_len,key, iv,encr_data, bit_mode);
			
			cmac = (unsigned char*)malloc(16*sizeof(unsigned char));
			
			gen_cmac(data, data_len, key,cmac,bit_mode);
			// now i need to concatenate the two strings
			unsigned char* string_to_write = (unsigned char*)malloc((cipher_len+16)*sizeof(unsigned char));
			
			concatenate_strings(encr_data, cipher_len, cmac, 16, string_to_write);
			// now write the encryption into a new file
			Write_Data(output_file, string_to_write, cipher_len+16);
		break;

		case 3: /* verify */
				data = InputFile_Read(input_file,&data_len);

				int data_cmacpointer = data_len -16; // take the position of the cmac start
				cmac = (unsigned char*)malloc(16*sizeof(unsigned char));
				// get the cmac of the file
				memcpy(cmac, data+(data_cmacpointer),16);
				decr_data = (unsigned char*)malloc(data_len*sizeof(unsigned char));

				plain_len = decrypt(data , data_cmacpointer,key,iv,decr_data,bit_mode);

				unsigned char* cmac2 = (unsigned char*)malloc(16*sizeof(unsigned char));
				gen_cmac(decr_data, plain_len, key,cmac2,bit_mode);

				int vfcmacs= verify_cmac(cmac,cmac2);
				if(vfcmacs == 0)
				{
					printf("The file is safe\n");
					Write_Data(output_file, decr_data, plain_len);
				}
				else
				{
					printf("You have been compromised. The file will not get written\n");
				}
		break;
		default:
			break;
	}

	/* Clean up */
	free(input_file);
	free(output_file);
	free(password);
	free(key);
	free(decr_data);
	free(encr_data);
	free(cmac);
	free(data);
	/* END */
	return 0;
}
