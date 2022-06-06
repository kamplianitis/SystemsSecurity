#ifndef _UTILS_H
#define _UTILS_H

#include <stdio.h>
#include <stdlib.h>


/*
 * Prints the hex value of the input, 16 values per line
 *
 * arg0: data
 * arg1: data len
 */
void
print_hex(unsigned char *, size_t);


/*
 * Prints the input as string
 *
 * arg0: data
 * arg1: data len
 */
void
print_string(unsigned char *, size_t);


/*
 * Prints the usage message
 */
void
usage(void);


/*
 * Checks the validity of the arguments
 *
 * arg0: path to input file
 * arg1: path to output file
 * arg2: path to key file
 * arg3: operation mode
 */
void
check_args(char *, char *, char *, int);


/*
 * Returns the size of a file
 *
 * arg0: File pointer of the file we want to see the size
 */
int
file_size(FILE *fp);



/*
 * Reads the file and returns the content
 * of the file in an unsigned char pointer
 *
 * arg0: Name of the input file
 * arg1: Length of the file after the read
 */
unsigned char* 
InputFile_Read(char *input_file, int* file_len);

/*
 * Writes a buffer of data with a specific mode
 * to the output file
 *
 * arg0: Name of the output file
 * arg1: Buffer that will be writed
 * arg2: Length of the buffer
 * arg3: Mode that will open the file with
 * 
 */

void 
Write_Data(char* output_file, unsigned char* data, int data_len, char* mode);


/*
 * Writes a size_t into the output file
 *
 * arg0: Name of the output file
 * arg1: The size_t that will be written
 * arg2: mode that will open the file
 * 
 */
void Write_sizeT(char* output_file, size_t* data, char * mode);
#endif /* _UTILS_H */
