#include <stdio.h>
#include <stdlib.h>
#include "system_crypto.h"
#include <unistd.h>

#define arraylen 50


int main()
{
    /* variables */
    char users_text[arraylen];
    unsigned char keyotp[arraylength];
    char key_vigenere[arraylength];
    
    //int len;
    char encryptedtext[arraylength];
    char decryptedtext[arraylength];
    int key_second_third=0;
    
    printf("-------------------OTP ENCRYPTION-------------------\n");
    printf("Give the plain or chipher text you want to encrypt: \n");
    fgets(users_text, sizeof(users_text), stdin);
            
    // call the special char remover
    special_Chars_Remover(users_text); 
            

    // call the key generator 
    keygen_otp(keyotp, strlen(users_text));

    // call the encryption
    encypt_text_otp(keyotp,users_text,encryptedtext);
            
    // call the decryptor
    decrypt_text_otp(keyotp,encryptedtext,decryptedtext);
            
            
    printf("RESULTS\n\n");
    printf("The text that is going to be encrypted will be: %s \n",users_text);
    printf("Encrypted text will be: %02x\n", encryptedtext);
    printf("Decrypted text will be: %s\n", decryptedtext);
    
    printf("------------------CEASAR ENCRYPTION------------------\n");
    printf("Give the text you want to encrypt: \n");
    fgets(users_text, sizeof(users_text), stdin);
    //call the special Char remover
    special_Chars_Remover(users_text); 
    printf("The text that is going to be encrypted will be: %s \n",users_text);

    // now get the key
    printf("Give the key you want it encrypted with: ");
    scanf("%d", &key_second_third);
    getchar(); // get the new line

    // now call the encrytion method
    ceasarsencryption(users_text, key_second_third);
    printf("The encrypted text is: %s\n", users_text);
    // ceasars decryption
    ceasarsdecryption(users_text, key_second_third);
    printf("The decrypted text is: %s \n", users_text);
    printf("----------------------------------------------------\n");

    printf("-----------------VIGENERE ENCRYPTION-----------------\n");
    printf("Give the plain or chipher text you want to encrypt: \n");
    fgets(users_text, sizeof(users_text), stdin);

    // call the special char remover
    special_Chars_Remover(users_text);
    // call the function to make everything uppercase
    StringToUpper(users_text);
    // now the same procedure for the key
    printf("Give the key you want it encrypted with: ");
    fgets(key_vigenere, sizeof(key_vigenere), stdin);
    // same procedure
    special_Chars_Remover(key_vigenere);
    StringToUpper(key_vigenere);
    // filler 
    keystringfill(key_vigenere, strlen(users_text));
    // encryption
    printf("The text for encryption is: %s \n", users_text);

    encryptVigenere(users_text,encryptedtext,key_vigenere);
    printf("The encrypted text is: %s \n", encryptedtext);
    decryptVigenere(users_text,encryptedtext,key_vigenere);
    printf("The decrypted text is: %s \n", encryptedtext);
    printf("----------------------------------------------------\n");
    return 0;
}