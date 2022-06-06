#include "rsa.h"
#include "utils.h"

/*
 * Sieve of Eratosthenes Algorithm
 * https://en.wikipedia.org/wiki/Sieve_of_Eratosthenes
 *
 * arg0: A limit
 * arg1: The size of the generated primes list. Empty argument used as ret val
 *
 * ret:  The prime numbers that are less or equal to the limit
 */
size_t *
sieve_of_eratosthenes(int limit, int *primes_sz)
{
	size_t *primes;

	/* TODO */	
	int prime[limit+1];

	// create a list of all numbers
	for(int i=0; i<=limit; i++)
	{
		if(i<2)
			prime[i] =0;
		else
			prime[i] =i;
	}
	// check the numbers  divisible by each number
	// and are greater or equal to the square of it
	int nums=0;
	for(int i=2; i*i<=limit; i++)
	{
		for(int j = i*i; j<=limit; j= j+i)
		{
			if(prime[j]!=0)
			{
				prime[j]=0;
				nums= nums+1;
			}
		}
	}
	// all the primes numbers are not 0 so I store them in 
	// an array and return it
	int sizeprimes = (limit-nums-1);
	(*primes_sz) = sizeprimes;
	size_t* label = malloc((limit-nums-1)*sizeof(size_t));

	primes = label;
	// fill the array
	int j=0;
	for (int i = 0; i < limit; i++)
	{
		if(prime[i] != 0)
		{
			primes[j] = prime[i];
			j+= 1;
		}
		else
		{
			continue;
		}
	}
	return primes;
}


/*
 * Greatest Common Denominator
 *
 * arg0: first number
 * arg1: second number
 *
 * ret: the GCD
 */
int
gcd(int a, int b)
{
	/* TODO */
	int hcf;
	for(int i=1; i<=a && i<=b; i++)
	{
		if(a%i==0 && b%i==0)
		{
			hcf = i;
		}
	}
	return hcf;
}


/*
 * Chooses 'e' where 
 *     1 < e < fi(n) AND gcd(e, fi(n)) == 1
 *
 * arg0: fi(n)
 *
 * ret: 'e'
 */
size_t
choose_e(size_t fi_n)
{
	size_t e;

	/* TODO */
	// since e has to  be a prime i have to call the function that finds the primes with maxlimit
	size_t *primes;
	int primesize =0;
	// I could also change the arguements of the function and give the prime array that is computed
	// at the start of the keygen always
	primes = sieve_of_eratosthenes(RSA_SIEVE_LIMIT,&primesize);

	// taking the primes I have to choose a random number from the array every time the given 
	// conditions given are not matched. I reversed the condition given to do the do while
	int random_poss_e_index;
	do
	{
		random_poss_e_index = rand() % primesize; // so i can get valid index
		e = primes[random_poss_e_index];
	} while (e%fi_n == 0 || gcd(e,fi_n)!=1);
	
	return e;
}


/*
 * Calculates the modular inverse
 *
 * arg0: first number
 * arg1: second number
 *
 * ret: modular inverse
 */
size_t
mod_inverse(size_t a, size_t b)
{

	/* TODO */
	for(int i=1; i<b; i++)
	{
		if(((a%b)*(i%b))%b == 1)
			return i;
	}
	// case something goes wrong
	return -1;
}


/*
 * Generates an RSA key pair and saves
 * each key in a different file
 */
void
rsa_keygen(void)
{
	size_t p;
	size_t q;
	size_t n;
	size_t fi_n;
	size_t e;
	size_t d;

	/* TODO */
	size_t *primes;
	int primesize=0;

	// find all the primes through the limit
	primes = sieve_of_eratosthenes(RSA_SIEVE_LIMIT, &primesize);

	// take two prime numbers at random. First take the indexes
	size_t p_index = rand()%primesize;  // so we  don't exeed the  index
	size_t q_index = rand()%primesize; 

	// take  the p,q. Don't know if it matters if they're the same
	p = primes[p_index];
	q = primes[q_index];

	// compute n
	n = p*q;

	// compute fi(n) -> Euler's totient
	fi_n = (p-1)*(q-1);

	e = choose_e(fi_n);

	d = mod_inverse(e,fi_n);

	// write to file the  keys
	Write_sizeT("Public.key", &n, "wb");
	Write_sizeT("Public.key", &d, "ab");
	Write_sizeT("Private.key", &n, "wb");
	Write_sizeT("Private.key", &e, "ab");
	
}


/*
 * Encrypts an input file and dumps the ciphertext into an output file
 *
 * arg0: path to input file
 * arg1: path to output file
 * arg2: path to key file
 */
void
rsa_encrypt(char *input_file, char *output_file, char *key_file)
{

	/* TODO */
	
	//take the contents of the input file
	unsigned char* file_contents;
	int content_size=0;

	file_contents = InputFile_Read(input_file, &content_size);

	// same for the key
	int garbage=0;
	unsigned char * key = InputFile_Read(key_file, &garbage);

	// create space for cipher
	size_t* cipher_text =  (size_t*)malloc(content_size*sizeof(size_t));
	// separate the two numbers of the key
	size_t n,d;
	memcpy(&n, key , sizeof(size_t));
	memcpy(&d, key+8 , sizeof(size_t));
	// pass the text to a size_t pointer and write to file
	for(int i=0; i<content_size; i++)
	{
		cipher_text[i] = modular_power((size_t)file_contents[i], d,n);
		Write_sizeT(output_file, &cipher_text[i],"a"); // make a proper function
	}
}


/*
 * Decrypts an input file and dumps the plaintext into an output file
 *
 * arg0: path to input file
 * arg1: path to output file
 * arg2: path to key file
 */
void
rsa_decrypt(char *input_file, char *output_file, char *key_file)
{

	/* TODO */
	// same procedure
	//take the contents of the input file
	unsigned char* file_contents;
	int content_size=0;

	file_contents = InputFile_Read(input_file, &content_size);

	// create a malloc to transform the unsigned char to size_t
	size_t* tempcontent = (size_t* )malloc(content_size);
	memcpy(tempcontent, file_contents, content_size);
	// same for the key
	int garbage=0;
	unsigned char * key = InputFile_Read(key_file, &garbage);

	size_t n,e;
	memcpy(&n, key , sizeof(size_t));
	memcpy(&e, key+8 , sizeof(size_t));

	// store the plaintext here to write it.
	unsigned char* plaintext = (unsigned char*)malloc((content_size/sizeof(size_t))*sizeof(unsigned char));

	// decryprtion process
	for(int i=0; i<content_size/sizeof(size_t); i++)
	{
		plaintext[i]= (unsigned char)modular_power(tempcontent[i], e, n);
	}
	// write to file
	Write_Data(output_file,plaintext, content_size/sizeof(size_t), "wb");
}


size_t modular_power(size_t a, size_t pow, size_t modulus)
{
	// make the out =1 so I can create the for loop
	size_t out = 1;

	for(int i=0; i<pow; i++)
	{
		out = (out*a)%modulus;
	}
	return out;
}