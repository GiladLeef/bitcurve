#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>

typedef struct str_list	{
	int n;
	char **data;
	int *lengths;
} List;

typedef struct str_tokenizer	{
	int current;
	int n;
	char **tokens;
} Tokenizer;


char *ltrim(char *str, const char *seps)	{
	size_t totrim;
	if (seps == NULL) {
		seps = "\t\n\v\f\r ";
	}
	totrim = strspn(str, seps);
	if (totrim > 0) {
		size_t len = strlen(str);
		if (totrim == len) {
			str[0] = '\0';
		}
		else {
			memmove(str, str + totrim, len + 1 - totrim);
		}
	}
	return str;
}

char *rtrim(char *str, const char *seps)	{
	int i;
	if (seps == NULL) {
		seps = "\t\n\v\f\r ";
	}
	i = strlen(str) - 1;
	while (i >= 0 && strchr(seps, str[i]) != NULL) {
		str[i] = '\0';
		i--;
	}
	return str;
}

char *trim(char *str, const char *seps)	{
	return ltrim(rtrim(str, seps), seps);
}

int indexOf(char *s,const char **array,int length_array)	{
	int index = -1,i,continuar = 1;
	for(i = 0; i <length_array && continuar; i++)	{
		if(strcmp(s,array[i]) == 0)	{
			index = i;
			continuar = 0;
		}
	}
	return index;
}

char *nextToken(Tokenizer *t)	{
	if(t->current < t->n)	{
		t->current++;
		return t->tokens[t->current-1];
	}
	else {
		return  NULL;
	}
}
int hasMoreTokens(Tokenizer *t)	{
	return (t->current < t->n);
}

void stringtokenizer(char *data,Tokenizer *t)	{
	char *token;
	t->tokens = NULL;
	t->n = 0;
	t->current = 0;
	trim(data,"\t\n\r ");
	token = strtok(data," \t:");
	while(token != NULL)	{
		t->n++;
		t->tokens = (char**) realloc(t->tokens,sizeof(char*)*t->n);
		if(t->tokens == NULL)	{
			printf("Out of memory\n");
			exit(0);
		}
		t->tokens[t->n - 1] = token;
		token = strtok(NULL," \t");
	}
}

void freetokenizer(Tokenizer *t)	{
	if(t->n > 0)	{
		free(t->tokens);
	}
	memset(t,0,sizeof(Tokenizer));
}


/*
	Aux function to get the hexvalues of the data
*/
char* tohex(char *ptr, int length) {
	if(ptr == NULL || length <= 0)
		return NULL;
	// Allocate memory for the hexadecimal string and initialize it to zero
	char *hex_string = (char *)calloc((2 * length) + 1, sizeof(char));
	if(hex_string == NULL)
		fprintf(stderr,"Erro calloc()\n");
	// Convert the input string to a hexadecimal string
	for (int i = 0; i < length; i++) {
		snprintf((char*)(hex_string + (2 * i)), 3, "%.2x",(uint8_t) ptr[i]);
	}
	return hex_string;
}


void tohex_dst(char *ptr, int length,char *dst) {
	if(ptr == NULL || length <= 0)
		return;
	// Convert the input string to a hexadecimal string
	for (int i = 0; i < length; i++) {
		snprintf((char*)(dst + (2 * i)), 3, "%.2x",(uint8_t) ptr[i]);
		//snprintf(dst + 2 * i, 3, "%.2x", ptr[i]);
	}
	dst[length*2] = 0;
}

int hexchr2bin(const char hex, char *out)	{
	if (out == NULL){
		return 0;
	}

	if (hex >= '0' && hex <= '9') {
		*out = hex - '0';
	} else if (hex >= 'A' && hex <= 'F') {
		*out = hex - 'A' + 10;
	} else if (hex >= 'a' && hex <= 'f') {
		*out = hex - 'a' + 10;
	} else {
		return 0;
	}

	return 1;
}

int hexs2bin(char *hex, unsigned char *out)	{
	int len;
	char b1;
	char b2;
	int i;
	if (hex == NULL || *hex == '\0' || out == NULL)
		return 0;

	len = strlen(hex);
	if (len % 2 != 0)
		return 0;
	len /= 2;
	memset(out, 0, len);
	for (i=0; i<len; i++) {
		if (!hexchr2bin(hex[i*2], &b1) || !hexchr2bin(hex[i*2+1], &b2)) {
			return 0;
		}
		out[i] = (b1 << 4) | b2;
	}
	return len;
}

void addItemList(char *data, List *l)	{
	l->data = (char**) realloc(l->data,sizeof(char*)* (l->n +1));
	l->data[l->n] = data;
	l->n++;
}

int isValidHex(char *data)	{
	char c;
	int len,i,valid = 1;
	len = strlen(data);
	for(i = 0 ; i <  len && valid ;i++ )	{
		c = data[i];
		valid = ( (c >= '0' && c <='9') || (c >= 'A' && c <='F' ) || (c >= 'a' && c <='f' ) );
	}
	return valid;
}

void generate_strpublickey(struct Point *publickey,bool compress,char *dst)	{
	memset(dst,0,131);
	if(compress)	{
		if(mpz_tstbit(publickey->y, 0) == 0)	{	// Even
			gmp_snprintf (dst,67,"02%0.64Zx",publickey->x);
		}
		else	{
			gmp_snprintf(dst,67,"03%0.64Zx",publickey->x);
		}
	}
	else	{
		gmp_snprintf(dst,131,"04%0.64Zx%0.64Zx",publickey->x,publickey->y);
	}
}

void set_publickey(char *param,struct Point *publickey)	{
	char hexvalue[65];
	char *dest;
	int len;
	len = strlen(param);
	dest = (char*) calloc(len+1,1);
	if(dest == NULL)	{
		fprintf(stderr,"[E] Error calloc\n");
		exit(0);
	}
	memset(hexvalue,0,65);
	memcpy(dest,param,len);
	trim(dest," \t\n\r");
	len = strlen(dest);
	switch(len)	{
		case 66:
			mpz_set_str(publickey->x,dest+2,16);
		break;
		case 130:
			memcpy(hexvalue,dest+2,64);
			mpz_set_str(publickey->x,hexvalue,16);
			memcpy(hexvalue,dest+66,64);
			mpz_set_str(publickey->y,hexvalue,16);
		break;
	}
	if(mpz_cmp_ui(publickey->y,0) == 0)	{
		mpz_t mpz_aux,mpz_aux2,Ysquared;
		mpz_init(mpz_aux);
		mpz_init(mpz_aux2);
		mpz_init(Ysquared);
		mpz_pow_ui(mpz_aux,publickey->x,3);
		mpz_add_ui(mpz_aux2,mpz_aux,7);
		mpz_mod(Ysquared,mpz_aux2,EC.p);
		mpz_add_ui(mpz_aux,EC.p,1);
		mpz_fdiv_q_ui(mpz_aux2,mpz_aux,4);
		mpz_powm(publickey->y,Ysquared,mpz_aux2,EC.p);
		mpz_sub(mpz_aux, EC.p,publickey->y);
		switch(dest[1])	{
			case '2':
				if(mpz_tstbit(publickey->y, 0) == 1)	{
					mpz_set(publickey->y,mpz_aux);
				}
			break;
			case '3':
				if(mpz_tstbit(publickey->y, 0) == 0)	{
					mpz_set(publickey->y,mpz_aux);
				}
			break;
			default:
				fprintf(stderr,"[E] Some invalid bit in the publickey: %s\n",dest);
				exit(0);
			break;
		}
		mpz_clear(mpz_aux);
		mpz_clear(mpz_aux2);
		mpz_clear(Ysquared);
	}
	free(dest);
}


void hex_to_bytes(const char *hex_string, unsigned char *bytes) {
    int length = strlen(hex_string);
    for (int i = 0; i < length; i += 2) {
        sscanf(hex_string + i, "%2hhx", &bytes[i / 2]);
    }
}

// Convert bytes to an integer
void bytes_to_int(const unsigned char *byte_array, mpz_t result, int length) {
    mpz_set_ui(result, 0);
    for (int i = 0; i < length; i++) {
        mpz_mul_ui(result, result, 256);
        mpz_add_ui(result, result, byte_array[i]);
    }
}

int legendre_symbol(mpz_t a, mpz_t p) {
    mpz_t symbol, exp, half_p, minus_one;
    mpz_inits(symbol, exp, half_p, minus_one, NULL);

    mpz_sub_ui(exp, p, 1);
    mpz_fdiv_q_ui(exp, exp, 2);

    mpz_mod(a, a, p); // Ensure 'a' is within the range [0, p-1]

    mpz_powm(symbol, a, exp, p);

    mpz_set_str(half_p, "7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16);
    mpz_set_str(minus_one, "-1", 16);

    int cmp = mpz_cmp(symbol, half_p);
    if (cmp == 0) {
        mpz_clears(symbol, exp, half_p, minus_one, NULL);
        return -1;
    } else if (cmp > 0) {
        mpz_clears(symbol, exp, half_p, minus_one, NULL);
        return 0;
    } else {
        mpz_clears(symbol, exp, half_p, minus_one, NULL);
        return 1;
    }
}

// Calculate the square root of 'a' modulo 'p' using the Tonelli-Shanks algorithm
void modular_sqrt(mpz_t result, mpz_t a, mpz_t p) {
    mpz_t q, s, z, c, r, t, m, b, i;
    mpz_inits(q, s, z, c, r, t, m, b, i, NULL);

    if (legendre_symbol(a, p) != 1) {
        // No square root exists
        mpz_set_ui(result, 0);
        return;
    }

    mpz_set(q, p);
    mpz_sub_ui(q, q, 1);
    mpz_set_ui(s, 0);

    while (mpz_even_p(q)) {
        mpz_fdiv_q_ui(q, q, 2);
        mpz_add_ui(s, s, 1);
    }

    if (mpz_cmp_ui(s, 1) == 0) {
        mpz_add_ui(q, p, 1);
        mpz_fdiv_q_ui(q, q, 4);
        mpz_powm(result, a, q, p);
        return;
    }

    mpz_set_ui(z, 2);

    while (1) {
        mpz_set_ui(i, 2);

        while (mpz_cmp(i, p) < 0) {
            if (mpz_cmp_ui(p - 1, legendre_symbol(i, p)) == 0) {
                break;
            }
            mpz_add_ui(i, i, 1);
        }

        mpz_powm(c, z, q, p);
        mpz_powm(r, a, m, p);
        mpz_powm(t, a, q, p);
        mpz_set(i, s);

        while (1) {
            if (mpz_cmp_ui(t, 1) == 0) {
                mpz_set(result, r);
                return;
            }

            mpz_set_ui(i, 0);

            while (mpz_cmp(i, m) < 0) {
                if (mpz_cmp_ui(t, 1) == 0) {
                    break;
                }
                mpz_add_ui(i, i, 1);
                mpz_pow_ui(b, c, 2);
                mpz_mod(c, b, p);
                mpz_mul(r, r, b);
                mpz_mod(r, r, p);
                mpz_mul(t, t, b);
                mpz_mod(t, t, p);
                mpz_set(m, i);
            }

            mpz_mul_ui(z, z, 2);
            mpz_mod(z, z, p);
        }
    }

    mpz_clears(q, s, z, c, r, t, m, b, i, NULL);
}

ssize_t getline(char **lineptr, size_t *n, FILE *stream) {
    if (*lineptr == NULL || *n == 0) {
        *n = 128; // Initial buffer size (adjust as needed)
        *lineptr = (char *)malloc(*n);
        if (*lineptr == NULL) {
            return -1; // Error: Unable to allocate memory
        }
    }

    int c;
    size_t i = 0;

    while (1) {
        c = fgetc(stream);

        if (c == EOF || c == '\n') {
            (*lineptr)[i] = '\0'; // Null-terminate the line
            break;
        }

        (*lineptr)[i] = (char)c;
        i++;

        // Resize the buffer if necessary
        if (i >= *n - 1) {
            *n *= 2; // Double the buffer size
            char *new_ptr = (char *)realloc(*lineptr, *n);
            if (new_ptr == NULL) {
                return -1; // Error: Unable to reallocate memory
            }
            *lineptr = new_ptr;
        }
    }

    if (c == EOF && i == 0) {
        return -1; // Error or end of file
    }

    return i; // Number of characters read (excluding null-terminator)
}
bool is_in_array(mpz_t x, struct Point points_array[], int keyCount) {
	for (int i = 0; i < keyCount; i++) {
		if (mpz_cmp(x, points_array[i].x) == 0) {
			return true;
		}
	}

	return false;
}

bool is_hex(const char *str) {
    // Check if the string is empty.
    if (str == NULL || strlen(str) == 0) {
        return false;
    }

    // Check if all characters in the string are hexadecimal digits.
    for (int i = 0; i < strlen(str); i++) {
        if (!isxdigit(str[i])) {
            return false;
        }
    }

    return true;
}