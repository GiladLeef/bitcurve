#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <gmp.h>
#include <string.h>
#include <unistd.h>
#include <math.h>
#include <time.h>
#include <ctype.h>
#include <stdbool.h>
#include <signal.h>

#include "include/curve.h"
#include "include/utils.h"


int main(int argc, char **argv) {
    if (argc != 2) {
        printf("Usage: %s <T>\n", argv[0]);
        return 1;
    }

    int T = atoi(argv[1]);

	mpz_init_set_str(EC.a, EC_constant_A, 16);
	mpz_init_set_str(EC.p, EC_constant_P, 16);
	mpz_init_set_str(EC.n, EC_constant_N, 16);
	mpz_init_set_str(G.x, EC_constant_Gx, 16);
	mpz_init_set_str(G.y, EC_constant_Gy, 16);
	init_doublingG(&G);

    FILE *outputFile = fopen("list.txt", "w"); // Open a file for writing

    if (outputFile == NULL) {
        perror("Error opening file");
        return 1;
    }
	struct Point A;
	mpz_init(A.x);
	mpz_init(A.y);
	mpz_t result, N;
	mpz_init(result);
	mpz_init(N);
	mpz_set_ui(N, 1);

    for (int i = 0; i < T; i++) { // Loop T times
        mpz_init(result);
        Scalar_Multiplication(G, &A, N);
        mpz_out_str(outputFile, 10, A.x);
        fprintf(outputFile, "\n");

        mpz_add_ui(N, N, 1);
    }

    fclose(outputFile); // Close the output file

	return 0;
}