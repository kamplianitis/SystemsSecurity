readmee file for project_1
gcc (Ubuntu 9.3.0-17ubuntu1~20.04) 9.3.0


The file contains the way that the functions have been written and how the demo and makefile has been written.


All the properties asked have been implemented.


General Functions(functions that are used for multiple algorithms or in the menu)


//////////////////////////////////////////////////////////////////////////////
void print_Menu(void)
    Function that prints the menu. No arguements 

////////////////////////////////////////////////////////////////////////////
void special_Chars_Remover(char* plain_text)
	The given text(plain_text) goes through a for loop in order to check every character. If the char belongs to the 
                specific ascii codes that are allowed then it will be stored in the same array but in maybe a new position (based on if there are deleted chars
                or not).
char* plain_text -> the unformated text given by the user



/////////////////////////////////////////////////////////////////////////////
OTP ENCRYPTION-DECRYPTION
*in otp encryption to avoid showing special chars I used the 02x.
/////////////////////////////////////////////////////////////////////////////


void keygen_otp(unsigned char* key, int user_text_len)
	 Using the open function (opens a file with file descriptor) it opens dev/urandom from which it
    reads (read function) the first  arg:user_text_len characters and stores them to the key.
char* key: will be used to store a key
user_text_len: the length of the user's text after the special char removal

///////////////////////////////////////////////////////////////////////////
void encypt_text_otp(unsigned char* key , char* plain_text, char* encrypted_text)
	With a for loop i make xor every bit of the plaintext with the counterpart of the key.
	   key : unsigned char array that contains the key
           plain_text: char array that contains the user's text after the special char removal
           encrypted_text: char array that will store the encrypted text
            
/////////////////////////////////////////////////////////////////////////
void decrypt_text_otp(unsigned char* key, char* encypted_text, char* decrypted_text)
	same procedure with the encrypt function. With a for loop i make xor every bit of the 		plaintext with the counterpart of the key to invert the process.
	key: unsigned char array that contains the key
        encypted_text: char array that contains the encrypted text
        decrypted_text: char array that will store the decrypted text.


/////////////////////////////////////////////////////////////////////////////
CEASAR'S ENCRYPTION-DECRYPTION
/////////////////////////////////////////////////////////////////////////////
void ceasarsencryption(char* array, int key)
	The first thing that the function does is to mod the key with the total available chars
    	that can be used. Then with a for loop the function takes the each char and adds the shift 		value that's on the key. Each time it's checked if the char has to "bounce" from a 		specific group of ascii chars to another.
        char* array: the char array given by the user after the char removal
        int key: the integer that determines the amount of the shift.
        
/////////////////////////////////////////////////////////////////////////
void ceasarsdecryption(char* array, int key)
	Same procedure as the ceasarsencryption. The first thing that the function does is to mod 		the key with the total available chars that can be used. Then with a for loop the function 		takes the each char and subtracts the shift value that's on the key. Each time it's 	checked if the char has to "bounce" from a specific group of asci chars to another.
        char* array: the char array given by the user after the char removal
        int key: the integer that determines the amount of the shift.



/////////////////////////////////////////////////////////////////////////////
VIGENERE ENCRYPTION-DECRYPTION
/////////////////////////////////////////////////////////////////////////////   

void StringToUpper(char * array)
	funtion that makes the lowercase chars of a string to uppercase
	char* array: the string the the user gave after the special char removal

/////////////////////////////////////////////////////////////////////////
void keystringfill(char* key, int array_length)
	fucntion that makes the key the same length the user's text by repeating the letters of 		it again and again. This is happening with a for loop checking in every character, the 	  length of the key until this point. if the length is smaller than the array it adds the 	   next one. In case the key word is completed the variable responsible for the position of
	of where we are in the key starts over from the beggining.
	
       char* key: the string that the user gave as a key for the encryption
       int array_length: the length of the array of the user's text

/////////////////////////////////////////////////////////////////////////
void encryptVigenere (char* array, char* encryptedMsg, char* key)
	funtion responsible for the vigenere encryption. The function puts in each char of
	encrypted text the counterpart of the user's text plus the counterpart of the key. Then
	mods the sum with 26 (amount of english letters) and adds the ascii value of the 'A' to go
	to the right position.
	char* array: the string that keeps the user's text after the the special char removal
        and the uppercase edit.
        char* encryptedMsg: the encrypted text that is going to be returned to the user by 
        reference
        char* key: the string that keeps the key

/////////////////////////////////////////////////////////////////////////        
void decryptVigenere (char* array, char* encryptedMsg, char* key)
	funtion responsible for the vigenere decryption. The function puts in each char of
	encrypted text the counterpart of the user's text MINUS the counterpart of the key.
	Because of the subtraction 26 has to be added in order to not lose position. Then mods
	the new sum with 26 (amount of english letters) and adds the ascii value of the 'A' to go
	to the right position.
	char* array: the string that keeps the user's text after the the special char removal
        and the uppercase edit. will be used to take the length of the string
        char* encryptedMsg: the encrypted text that is going to be returned decrypted to the
        user by reference
        char* key: the string that keeps the key
        
        

/////////////////////////////////////////////////////////////////////////////
Makefile
/////////////////////////////////////////////////////////////////////////////

I also created a make file that in case of make it will create an executable. The executable's name will be outfile.o. The flag on the compile is only -Wall. I also implemented a make clean function that will just remove all the .o files.




