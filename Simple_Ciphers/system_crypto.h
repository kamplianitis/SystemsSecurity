#include <string.h>
#include <unistd.h>
#include <fcntl.h>

#ifndef System_Crypto_H   /* Include guard */
#define System_Crypto_H

#define arraylength 50
#define characters 62

// general functions
void print_Menu();
void special_Chars_Remover(char* plaintext);

// otp functions
void keygen_otp(unsigned char* key, int lengthofplaintext);
void encypt_text_otp(unsigned char* key, char* plaintext, char* encryptedtext);
void decrypt_text_otp(unsigned char* key, char* encypted_text, char* decrypted_text);

//ceasars functions
void ceasarsencryption(char* array, int key);
void ceasarsdecryption(char* array, int key);

// vigenere functions
void StringToUpper(char * array);
void keystringfill(char* key, int array_length);
void encryptVigenere (char* array, char* encryptedMsg, char* key);
void decryptVigenere (char* array, char* encryptedMsg, char* key);
#endif