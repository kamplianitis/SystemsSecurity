#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "rsa.h"
#include "utils.h"


/*
 * Performs RSA key generation and stores the keys into 2 files
 *
 * Encrypts the input file and stores the ciphertext to the output file
 *
 * Decrypts the input file and stores the plaintext to the output file
 */
int
main(int argc, char **argv)
{
	int opt;			/* used for command line arguments */
	int op_mode;			/* operation mode                  */
	char *input_file;		/* path to the input file          */
	char *output_file;		/* path to the output file         */
	char *key_file;			/* path to the key file            */

	/* Init arguments */
	input_file = NULL;
	output_file = NULL;
	key_file = NULL;
	op_mode = -1;


	/*
	 * Get arguments
	 */
	while ((opt = getopt(argc, argv, "i:o:k:degh:")) != -1) {
		switch (opt) {
		case 'i':
			input_file = strdup(optarg);
			break;
		case 'o':
			output_file = strdup(optarg);
			break;
		case 'k':
			key_file = strdup(optarg);
			break;
		case 'd':
			/* if op_mode == 0 the tool decrypts */
			op_mode = 0;
			break;
		case 'e':
			/* if op_mode == 1 the tool encrypts */
			op_mode = 1;
			break;
		case 'g':
			/* if op_mode == 2 the tool performs keygen */
			op_mode = 2;
			break;
		case 'h':
		default:
			usage();
		}
	}


	/* check arguments */
	check_args(input_file, output_file, key_file, op_mode);


	/* serve each mode... */
	switch (op_mode) {
	case 0:
		rsa_decrypt(input_file, output_file, key_file);
		break;
	case 1:
		rsa_encrypt(input_file, output_file, key_file);
		break;
	case 2:
		rsa_keygen();
		break;
	default:
		break;
	}

		

	/* Clean up */
	free(input_file);
	free(output_file);
	free(key_file);


	/* END */
	return 0;
}
