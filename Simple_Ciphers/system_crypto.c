#include <stdio.h>
#include <stdlib.h>
#include "system_crypto.h"
#include <ctype.h>




/*
    Print menu:
        type: void
    Function that prints the menu. No arguements 
*/
void print_Menu()
{
    printf("Choose the algorith you want\n");
    printf("1). OTP Algorith\n");
    printf("2). CEASAR Algorith\n");
    printf("3). VIGENERE Algorith\n");
    printf("4). Exit\n");
}





/*
    basically changes the text arguement cause i don't need it anymore as it is
    Type: 
        void
    Arguements:
                char* plain_text -> the unformated text given by the user
    Functionality:
                The given text(plain_text) goes through a for loop in order to check every character. If the char belongs to the 
                specific ascii codes that are allowed then it will be stored in the same array but in maybe a new position (based on if there are deleted chars
                or not).
*/
void special_Chars_Remover(char* plain_text)
{
    int oldtextplacer, newtextplacer = 0; // keep track of where i am 

        for(oldtextplacer= 0; plain_text[oldtextplacer] != '\0'; oldtextplacer++) // the loop to check every char of the plain_text
    {
        if((plain_text[oldtextplacer] >='a' && plain_text[oldtextplacer] <='z') || (plain_text[oldtextplacer] >='A' && plain_text[oldtextplacer] <='Z'))
        {
            plain_text[newtextplacer] = plain_text[oldtextplacer]; // if the char is allowed then store it to its new position in the array
            newtextplacer ++;
        }
        else
        {
            int x = plain_text[oldtextplacer]; // transform the char into ascii code
            if(x>= 48 && x<=57) // ascii for the numbers
            {
                plain_text[newtextplacer] = plain_text[oldtextplacer];
                newtextplacer ++;
            }
        }
    }
    plain_text[newtextplacer] = '\0'; // declares the end of the array
}


/*
    Key generator for the otp encryption.
    Arguements:
            char* key: will be used to store a key
            user_text_len: the length of the user's text after the special char removal
    Using the open function (opens a file with file descriptor) it opens dev/urandom from which it
    reads (read function) the first  arg:user_text_len characters and stores them to the key.

*/
void keygen_otp(unsigned char* key, int user_text_len)
{
     int fd = open("/dev/urandom", O_RDONLY);
    read(fd, key, user_text_len);
    //buffer now contains the random data
    key[user_text_len] = '\0';
    close(fd);
}


/*
    Encryption Function OTP Algorithm
    Arguements:
            key : unsigned char array that contains the key
            plain_text: char array that contains the user's text after the special char removal
            encrypted_text: char array that will store the encrypted text
    With a for loop i make xor every bit of the plaintext with the counterpart of the key.
*/
void encypt_text_otp(unsigned char* key , char* plain_text, char* encrypted_text)
{
    int len = strlen(plain_text);
    int i; // need to use it to end the array
    for(i=0; i<len; i++)
    {
        encrypted_text[i]= plain_text[i]^key[i]; // plaintext XOR key bit by bit
    }
    encrypted_text[i]='\0'; //end of the array
}

/*
    Decryption function for OTP.
    Arguements:
            key: unsigned char array that contains the key
            encypted_text: char array that contains the encrypted text
            decrypted_text: char array that will store the decrypted text.
    Same procedure as the encrypted one as we know that A xor B xor A = B.
*/
void decrypt_text_otp(unsigned char* key, char* encypted_text, char* decrypted_text)
{
    int len = strlen(encypted_text);
    int i; // need to use it to end the array
    for(i=0; i<len; i++)
    {
        decrypted_text[i]= encypted_text[i]^key[i]; // plaintext XOR key bit by bit
    }
    decrypted_text[i]='\0'; //end of the array
}




/*
    CEASARS FUNCTIONS
*/


/*
    Funtion to encrypt the array based on the key
    Arguements: 
        char* array: the char array given by the user after the char removal
        int key: the integer that determines the amount of the shift.
    The first thing that the function does is to mod the key with the total available chars
    that can be used. Then with a for loop the function takes the each char and adds the shift value 
    that's on the key. Each time it's checked if the char has to "bounce" from a specific group of ascii
    chars to another.
*/

void ceasarsencryption(char* array, int key)
{
    int keymod = key%characters;
    int ch2,i;
    char ch;

     for(i = 0; array[i] != '\0'; i++) // begin a loop that will
    {
        ch = array[i];
        if(ch >= 'A' && ch<='Z')
        {
            ch2 = ch + keymod; // makes the shift

            // if the shift excels the a-z modules i have to go to the A and push the key
            if(ch2>'Z')
            {
                int steps = keymod;
                steps = steps - ('Z' - ch);

                if(steps >26 && steps <= 36)
                {
                    steps = steps - 26-1;
                    ch='0'; // reset the timer
                    ch= ch+steps;
                }
                else if (steps >36)
                {
                    steps = steps- 36-1;
                    ch = 'A';
                    ch = ch +steps;
                }
                else
                {
                    ch = ch2 - 'Z' + 'a' -1;
                }
            }
            else
            {
                ch = ch2;
            }
        }
        else if( ch >= 'a' && ch<='z')
        {
            ch2 = ch + keymod; // makes the shift

            // if the shift excels the a-z modules i have to go to the A and push the key
            if(ch2>'z')
            {
                int steps = keymod;
                steps = steps - ('z' - ch);

                if(steps >10 && steps <= 36)
                {
                    steps = steps - 10-1;
                    ch='A'; // reset the timer
                    ch= ch+steps;
                }
                else if (steps >=36)
                {
                    steps = steps - 36-1;
                    ch = 'a';
                    ch = ch +steps;
                }
                else
                {
                    ch = ch2 - 'z' + '0' -1;
                }
            }
            else
            {
                ch = ch2;
            }
        }
        else
        {
            ch2 = ch + keymod; // makes the shift

            // if the shift excels the a-z modules i have to go to the A and push the key
            if(ch2>'9')
            {
                int steps = keymod;
                steps = steps - ('9' - ch);

                if(steps >26 && steps <= 52)
                {
                    steps = steps - 26-1;
                    ch='a'; // reset the timer
                    ch= ch+steps;
                }
                else if (steps >52)
                {
                    steps = steps -52-1;
                    ch = '0';
                    ch = ch +steps;
                }
                else
                {
                    ch = ch2 - 'Z' + 'A' -1;
                }
            }
            else
            {
                ch = ch2;
            }
        }
        array[i] = ch;
    }

}

/*
    Funtion to decrypt the array based on the key
    Arguements: 
        char* array: the char array given by the user after the char removal
        int key: the integer that determines the amount of the shift.
    Same procedure as the ceasarsencryption.
    The first thing that the function does is to mod the key with the total available chars
    that can be used. Then with a for loop the function takes the each char and subtracts the shift value 
    that's on the key. Each time it's checked if the char has to "bounce" from a specific group of ascii
    chars to another.
*/

void ceasarsdecryption(char* array, int key)
{

    int keymod = key%characters;
    int ch2,i;
    char ch;

    for(i = 0; array[i] != '\0'; i++)
    {
        ch = array[i];
        if(ch >= 'A' && ch<='Z')
        {
            ch2 = ch - keymod; // makes the shift

            // if the shift excels the a-z modules i have to go to the A and push the key
            if(ch2<'A')
            {
                int steps = keymod;
                int absn =  abs('A' - ch);

                steps = steps -absn;

                if(steps >10 && steps <= 36)
                {
                    steps = steps - 10-1;
                    ch='z'; // reset the timer
                    ch= ch-steps;
                }
                else if (steps >36)
                {
                    steps = steps - 36 -1;
                    ch = 'Z';
                    ch = ch -steps;
                }
                else
                {
                    ch = '9';
                    ch = ch - steps+1;
                }
            }
            else
            {
                ch = ch2;
            }
        }
        else if( ch >= 'a' && ch<='z')
        {
            ch2 = ch - keymod; // makes the shift

            // if the shift excels the a-z modules i have to go to the A and push the key
            if(ch2<'a')
            {
                int steps = keymod;
                steps = steps - abs('a' - ch);

                if(steps >26 && steps <= 36)
                {
                    steps = steps - 26 -1;
                    ch='9'; // reset the timer
                    ch= ch-steps;
                }
                else if (steps >36)
                {
                    steps = steps - 36 -1;
                    ch = 'z';
                    ch = ch -steps;
                }
                else
                {
                    ch = 'Z';
                    ch = ch - steps+1;
                }
            }
            else
            {
                ch = ch2;
            }
        }
        else
        {
            ch2 = ch - keymod; // makes the shift

            // if the shift excels the a-z modules i have to go to the A and push the key
            if(ch2<'0')
            {
                int steps = keymod;
                steps = steps - abs('0' - ch);

                if(steps >26 && steps <= 52)
                {
                    steps = steps - 26-1;
                    ch='Z'; // reset the timer
                    ch= ch-steps;
                }
                else if (steps >=52)
                {
                    steps = steps - 52-1;
                    ch = '9';
                    ch = ch -steps;
                }
                else
                {
                    ch = 'z';
                    ch = ch - steps+1;
                }
            }
            else
            {
                ch = ch2;
            }
        }
        array[i] = ch;
    }
}

/*
    VIGENERE FUNCTIONS
*/


/*
    funtion that makes the lowercase chars of a string to uppercase
    Arguements:
            char* array: the string the the user gave after the special char removal
*/


void StringToUpper(char * array)
{
    for(int i =0; i< strlen(array); i++)
        array[i] = toupper(array[i]);
}


/*
	fucntion that makes the key the same length the user's text by repeating the letters of 		it again and again. This is happening with a for loop checking in every character, the 	  length of the key until this point. if the length is smaller than the array it adds the 	   next one. In case the key word is completed the variable responsible for the position of
	of where we are in the key starts over from the beggining.
    Arguements:
            char* key: the string that the user gave as a key for the encryption
            int array_length: the length of the array of the user's text
*/

void keystringfill(char* key, int array_length)
{
    int i,j;
    for(i = 0, j = 0; i < array_length; ++i, ++j)
    {
        if(j == strlen(key))
        {
            j = 0;
        }

        key[i] = key[j];
    }
    key[i] = '\0';
}


/*
    funtion responsible for the vigenere encryption. The function puts in each char of encrypted 
    text the counterpart of the user's text plus the counterpart of the key. Then mods the sum 
    with 26 (amount of english letters) and adds the ascii value of the 'A' to go to the right
    position.
    Arguements:
            char* array: the string that keeps the user's text after the the special char removal
            and the uppercase edit.
            char* encryptedMsg: the encrypted text that is going to be returned to the user by 
            reference
            char* key: the string that keeps the key
*/


void encryptVigenere (char* array, char* encryptedMsg, char* key)
{
    int i=0;
    for(i = 0; i < strlen(array); ++i)
     {
        encryptedMsg[i] = ((array[i] + key[i]) % 26) + 'A';
     }
    encryptedMsg[i] = '\0';
}


/*
    funtion responsible for the vigenere decryption. The function puts in each char of encrypted 
    text the counterpart of the user's text MINUS the counterpart of the key. Because of the
    subtraction 26 has to be added in order to not lose position. Then mods the new sum 
    with 26 (amount of english letters) and adds the ascii value of the 'A' to go to the right
    position.
    Arguements:
            char* array: the string that keeps the user's text after the the special char removal
            and the uppercase edit. will be used to take the length of the string
            char* encryptedMsg: the encrypted text that is going to be returned decrypted to the
            user by reference
            char* key: the string that keeps the key
*/
void decryptVigenere (char* array, char* encryptedMsg, char* key)
{
   int i;
   for(i = 0; i < strlen(array); i++)
        encryptedMsg[i] = (((encryptedMsg[i] - key[i]) + 26) % 26) + 'A';

    encryptedMsg[i] = '\0';
}
