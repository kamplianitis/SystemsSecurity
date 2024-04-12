Amplianitis Konstantinos
gcc (Ubuntu 9.3.0-17ubuntu1~20.04)


Assignment 3 -- Creation of a file logging tool

I will briefly describe what I added in the files given file by file.

//////////////////////////////////////////////////////////////////////////////
logger.c
//////////////////////////////////////////////////////////////////////////////

fopen function.
//////////////////////////////////////////////////////////////////////////////

I used the access function which is provided by the unistd.h library. With the 
access function i firstly check if the file with the path given as an arguement 
exists(F_OK, determines the access_type flag) and then i check if it has read and 
write priviledges. Depending on the mode given I determine the the action_denied_flag.
The process is being done with the use of if-else statements and the use of strcompare
for the mode comparison with the available modes defined by the system. After this, I take 
the uid of the user by using the function getuid(). For getting the path i used the realpath()
function. I realised that if the file does not exist the real path will have a null value. In order
to change that I made an if-else statement that triggers a flag that when the realpath is null write to the
log file the path that is given as an arguement. Took time and date using a struct of time_t varialbes.

For the Fingerprint Hash i used the functions MD5_Init, MD5_Update, MD5_Final.

In the end i used the fprintf function to write all the data I collected to the log file.
I realised that if I try to write the Fingerprint as a whole in 02x form there are some warnings.
In order to fix that i made a for loop that will write to the file each character of the loop in 
02x form.



fwrite function.
//////////////////////////////////////////////////////////////////////////////
In this function first thing I made was making the access_type =2. To take the 
name of the file i had to take the file descriptor first (fileno function). After 
finding the file i check if there are writing priviledges on this file and determine The
action_denied_flag. Then, I use the same method to take date, time , Fingerprint.
In the Fingerprint function I used the arguement of the fwrite as the text cause the 'w' mode
will delete all the contents and write the file from the beginning. In order to not write the 
access to the .log file i call the original fopen to open the file and with the same method i print
the info.


//////////////////////////////////////////////////////////////////////////////
acmonitor.c
//////////////////////////////////////////////////////////////////////////////

list_unauthorized_accesses function.
//////////////////////////////////////////////////////////////////////////////

In the beginning i have to find the lines cause the number of lines indicates 
me the number of entries in the .log file. To do that all I have done is a for loop
that gets a char each time and every \n counts as a plus one line. Then I create a struct
of entry stuck type in order to store all the data that the file has.

To store the data i used the strsep over the strtok. The reason is that by giving the pointer
of each line the strsep will remove the part of the line that was before the delimeter after use.


After storing the lines to the malloc of the struct I made a files[lines][255] array.
The reason was that i wanted to store all the malicious processed files in order to not count them 
again and again. With a for loop i take each time the uid and compare it with the uid of the rest ones
in the following lines. If their id match and the access_denied is true then i check if the file is in the files
array. If not I add it and count +1 in the dennied_in_diff_files.  In the end if this variable is above 7 the programm
will print the malicious user and all the files that he tried to use maliciously.


list_file_modifications function.
//////////////////////////////////////////////////////////////////////////////

I use the same method of counting the lines and and parsing the data from the .log
file.

Then i take the length of the Fingerprint(0) to use it as a length value in the oldfingerprint
that i will create to keep the last Fingerprint of each file we saw. I initialize two int arrays 
(users and mods) to keep track of each user number of modifications. I used calloc to initialize
everything on 0. 

Then with a for loop i check each time if the file name matches the path given as an arguement.
if they match I check the last Fingerprint I saw. if they are not identical i increase the mods[i]
by one and i write the user (if not written) in the users array. In the end I print the users and the mods
arrays. If users[i] or mods[i] are zero then they don't get printed.


//////////////////////////////////////////////////////////////////////////////
test_aclog.c
//////////////////////////////////////////////////////////////////////////////

For testing I used the file given with the excersise and I added a chmod function
in orded to try and open a file with write+ mode but no write rights. The action_denied_flag
returned as 1 as it should be. Because I couldn't find a way to change the uid I changed it in the 
.log file for the purpose of testing the acmonitor and it works fine. I tested both the acmonitor -m
and the acmonitor -i <filename>. Both functions are working corectly. I also used chmod to test that 
the action denied flag is working. To do that firstly I alternate the file[0] priviledges to readonly
and I called fwrite which returned 0 (original fwrite is called only when the action_denied_flag is down).
Then I did the same thing  for the read mode. I changed the file1 priviledges to only write and I tried to 
read it.