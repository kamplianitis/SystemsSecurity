
Amplianitis Konstantinos
gcc (Ubuntu 9.3.0-17ubuntu1~20.04) 9.3.0
//////////////////////////////////////////////////////

Changes from the assignment 3
//////////////////////////////////////////////////////

logger.c
//////////////////////////////////////////////////////
Two things changed in the logger.c and they are the 
following:


First of all the MD5 process( init update ,final) was
replaced by MD5 cause for some reason i couldn't 
descript the files with openssl. 

Secondly, for the fingerprint creation I opened the
file_logging with "rb" mode cause again openssl had 
a problem with the decryption


test_aclog.c
//////////////////////////////////////////////////////
FOR THE ASSIGNMENT 3 I MADE A MISTAKE AND THE LAST LINE
OF THE FILE (fclose(file)) SHOULD NOT BEEN THERE. IT 
PROBABLY HAS BEEN IN COMMENTS AND I UNCOMMENTED IT BY 
MISTAKE. IF REMOVED THE PROJECT RUNS CORRECTLY. SORRY 
FOR THE INCONVENIENCE.


acmonitor.c
//////////////////////////////////////////////////////
I made a function for passing the entries written in 
the file cause it was wrong to be left like that and
i should have done in in the assignment 3 but there was
lack of time.


NEW IMPLEMENTATIONS
//////////////////////////////////////////////////////

ransomware.sh
//////////////////////////////////////////////////////

A bash script for the puposes of testing the acmonitor.
The script has three options that have to be given
when calling the script. if argv[0] =1 it encrypts all the 
current files in a directory (argv[1]) and generates argv[2] 
ransom files in order to fullfil the exercise requirements.
if argv[0] =2 the script will first remove all the 
ransom files and then decrypt the rest of the remaining.
if argv[0] =3 then the script will generate in the 
argv[1] path argv[2] number of files using the filegenerator 
executable. if argv[0] =4 the process will exit. In order to 
write into the file logging when encrypting/decrypting and 
when generating the ransom files I import the 
LD_PRELOAD by the command export LD_PRELOAD=./logger.so

openssl command used
openssl aes-256-cbc -pbkdf2 -k 1234 -salt -a -{d/e} -in inputfile -out outfile

filegenerator.c
//////////////////////////////////////////////////////

The file simply creates a specific amount of files 
given from the terminal (called in the bash script).
The purpose of the file is to be able to call the 
LD_PRELOAD=logger.so (fopen fwrite writing to file_logging)

Makefile
//////////////////////////////////////////////////////
Simply added the filegenerator to get compiled in order
to be abled to get called in the script after.


acmonitor.c
//////////////////////////////////////////////////////
Beyond all the changes described above about this file
I created 3 more functions. They are described below:

detect_enc_files
------------------------------------------------------
The function reads the log file and checks entry by 
entry. If the access_type of entry and the action_denied
are valid the name of the file is checked. If the file 
has a substring ".txt.encrypt" in it then it checks if the 
previous entry is has the same path-name without the 
.txt.encrypt. If the above condition is true then prints the 
file path of the file that has been encrypted.


files_created_detector
------------------------------------------------------
The function reads the log file and checks entry by 
entry. Then calls the function twenty_min_check(will
be explained after) to find the amount of files 
that have been created in the last 20 mins. If the 
number of files are more than the arguement given
it prints a message that there is possible malicious
activity.


twenty_min_check
------------------------------------------------------
The function takes every possible scenario to find if 
there are files created in the last 20 mins. In order
to do that I transform the minutes into seconds and check
all the possibilities between days difference month
difference and year difference.