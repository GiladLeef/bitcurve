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
#include <pthread.h>

#include "include/curve.h"
#include "include/utils.h"
#include "include/set.h"
#include "include/set.c"

typedef struct {
    mpz_t start;
    mpz_t step;
    mpz_t end;
    SimpleSet *public_keys_set;
    struct Point target_point;
    pthread_t* threads;
    int threads_num;
} ThreadData;

void *search_thread(void *arg) {
    ThreadData *data = (ThreadData *)arg;
    mpz_t N, result;
    mpz_init(N);
    mpz_init(result);

    mpz_set(N, data->start);
    
    int match_found = 0;  // Flag to indicate whether a match is found

    for (; mpz_cmp(data->end, N) > 0; mpz_add_ui(N, N, 1)) {
        mpz_mul(result, N, data->step);

        struct Point B, C;
        mpz_init(B.x);
        mpz_init(B.y);
        mpz_init(C.x);
        mpz_init(C.y);

        Scalar_Multiplication(G, &B, result);
        Point_Negation(&B, &C);
        mpz_set(B.x, C.x);
        mpz_set(B.y, C.y);
        Point_Addition(&data->target_point, &B, &C);

        char *x_str = mpz_get_str(NULL, 10, C.x);
        if (set_contains(data->public_keys_set, x_str) == 0) {
            printf("Found a matching public key:\n");
            gmp_printf("N*STEP: %Zd\n", result);
            printf("The private key is somewhere in minimum N*STEP - STEP and maximum of N*STEP + STEP\n");
            mpz_clear(N);
            mpz_clear(result);
            mpz_clear(B.x);
            mpz_clear(B.y);
            mpz_clear(C.x);
            mpz_clear(C.y);
            // Set the flag to true
            match_found = 1;
            break;  // Exit the loop when a match is found
        }

        // Free memory for temporary points
        mpz_clear(B.x);
        mpz_clear(B.y);
        mpz_clear(C.x);
        mpz_clear(C.y);
    }

    // Cancel other threads after a match is found
    if (match_found) {
        for (int i = 0; i < data->threads_num; i++) {
            if (pthread_self() != data->threads[i]) {
                pthread_cancel(data->threads[i]);
            }
        }
    }

    mpz_clear(N);
    mpz_clear(result);
    return NULL;
}

bool load_public_keys(const char *filename, SimpleSet *public_keys_set, int step_size) {
  FILE *file = fopen(filename, "r");
  if (file == NULL) {
    perror("Error opening file");
    return false;
  }

  char *public_key_buffer = NULL;
  size_t buffer_size = 0;

  printf("Debug: Opening file '%s'\n", filename);

  for (int i = 0; i < step_size; i++) {
    ssize_t read = getline(&public_key_buffer, &buffer_size, file);

    if (read == -1) {
      if (feof(file)) {
        // End of file reached
        printf("Debug: End of file reached\n");
        break;
      } else {
        perror("Error reading from file");
        free(public_key_buffer);
        fclose(file);
        return false;
      }
    }

    // Remove the newline character from the end of the line.
    if (public_key_buffer[read - 1] == '\n') {
      public_key_buffer[read - 1] = '\0';
    }

    int add_result = set_add(public_keys_set, public_key_buffer);

    // Handle the result of set_add
    if (add_result == SET_TRUE) {
      // Element was added successfully
    } else if (add_result == SET_ALREADY_PRESENT) {
      // Element was already present in the set
    } else if (add_result == SET_CIRCULAR_ERROR) {
      // This should not happen under normal circumstances
      fprintf(stderr, "Error: Circular error in set_add\n");
      free(public_key_buffer); // Free allocated memory
      fclose(file);
      return false;
    } else if (add_result == SET_MALLOC_ERROR) {
      // Memory allocation error, handle it as needed
      perror("Error adding public key to set");
      free(public_key_buffer); // Free allocated memory
      fclose(file);
      return false;
    } else {
      // Handle any other unexpected error
      fprintf(stderr, "Error: Unexpected error in set_add\n");
      free(public_key_buffer); // Free allocated memory
      fclose(file);
      return false;
    }
  }

  free(public_key_buffer); // Free allocated memory
  fclose(file);
  printf("Debug: Closed file\n");
  return true;
}


bool decompress_public_key(const char *hex_compressed_key, mpz_t x, mpz_t y) {
	if (!is_hex(hex_compressed_key)) {
		return false;
	}
	unsigned char compressed_key[33];
	hex_to_bytes(hex_compressed_key, compressed_key);
	mpz_t p;
	mpz_init_set_str(p, "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16);

	unsigned char prefix = compressed_key[0];
	unsigned char x_bytes[32];
	memcpy(x_bytes, compressed_key + 1, 32);

	bytes_to_int(x_bytes, x, 32);

	int y_parity;
	if (prefix == 0x02) {
		y_parity = 0;
	} else if (prefix == 0x03) {
		y_parity = 1;
	} else {
		mpz_set_ui(y, 0); // Invalid prefix
		return false;
	}

	mpz_t y_squared;
	mpz_init(y_squared);
	mpz_powm_ui(y_squared, x, 3, p);
	mpz_add_ui(y_squared, y_squared, 7);
	mpz_mod(y_squared, y_squared, p);

	modular_sqrt(y, y_squared, p);

	if (y_parity != (mpz_odd_p(y) ? 1 : 0)) {
		mpz_sub(y, p, y);
	}
	mpz_clear(y_squared);
	return true;
}

// Function to compress x and y coordinates into a compressed public key
void compress_public_key(mpz_t x, mpz_t y, char compressed_key[]) {
	// Determine the prefix byte
	char prefix = (mpz_tstbit(y, 0)) ? 0x03 : 0x02;

	// Convert x coordinate to a hexadecimal string
	char* x_str = mpz_get_str(NULL, 16, x);

	// Pad x coordinate with leading zeros to make it 64 characters long
	size_t x_len = strlen(x_str);
	if (x_len < 64) {
		char padded_x[65];
		memset(padded_x, '0', 64 - x_len);
		strcpy(padded_x + 64 - x_len, x_str);
		snprintf(compressed_key, 67, "%02X%s", prefix, padded_x);
	} else {
		snprintf(compressed_key, 67, "%02X%s", prefix, x_str);
	}

	free(x_str);
}


int main(int argc, char **argv) {
    if (argc != 5) {
        printf("Usage: %s <public_key> <step_size> <search_size> <threads_num>\n", argv[0]);
        return 1;
    }

    const int step_size = atoi(argv[2]);
    if (step_size <= 0) {
        printf("Error: Invalid step_size\n");
        return 1;
    }

    const int threads_num = atoi(argv[4]);
    mpz_t search_size;
    mpz_init(search_size);
    mpz_set_str(search_size, argv[3], 10); // Assuming search_size is provided as a decimal string

    mpz_init_set_str(EC.a, EC_constant_A, 16);
    mpz_init_set_str(EC.p, EC_constant_P, 16);
    mpz_init_set_str(EC.n, EC_constant_N, 16);
    mpz_init_set_str(G.x, EC_constant_Gx, 16);
    mpz_init_set_str(G.y, EC_constant_Gy, 16);
    init_doublingG(&G);

    gmp_printf("Gx = %Zx\n", G.x);
    gmp_printf("Gy = %Zx\n", G.y);

    mpz_t target_x, target_y;
    mpz_init(target_x);
    mpz_init(target_y);

    printf("Target Pubkey argument: %s\n", argv[1]);

    // Check if decompression succeeds
    if (!decompress_public_key(argv[1], target_x, target_y)) {
        printf("Error: Failed to decompress public key\n");
        mpz_clear(target_x);
        mpz_clear(target_y);
        return 1;
    }

    SimpleSet public_keys_set;
    set_init(&public_keys_set); // Initialize the set

    if (!load_public_keys("list.txt", &public_keys_set, step_size)) {
        printf("Error: Failed to load public keys from file\n");
        mpz_clear(target_x);
        mpz_clear(target_y);
        return 1;
    }
    printf("Finished loading keys\n");

    struct Point target_point;
    mpz_init(target_point.x);
    mpz_init(target_point.y);

    mpz_set(target_point.x, target_x);
    mpz_set(target_point.y, target_y);

    // Calculate range for each thread
    mpz_t chunk;
    mpz_init(chunk);
    mpz_tdiv_q_ui(chunk, search_size, threads_num);
    pthread_t threads[threads_num];
    ThreadData thread_data[threads_num];

    for (int i = 0; i < threads_num; i++) {
        mpz_init(thread_data[i].start);
        mpz_mul_ui(thread_data[i].start, chunk, i);
        mpz_add_ui(thread_data[i].start, thread_data[i].start, 1);

        mpz_init(thread_data[i].end);
        mpz_add(thread_data[i].end, thread_data[i].start, chunk);

        mpz_init(thread_data[i].step);
        mpz_set_ui(thread_data[i].step, step_size);

        thread_data[i].public_keys_set = &public_keys_set;
        thread_data[i].target_point = target_point;
        thread_data[i].threads = threads;
        thread_data[i].threads_num = threads_num;
		
        pthread_create(&threads[i], NULL, search_thread, (void *)&thread_data[i]);
        printf("\n");
        printf("Thread ID: %d, Start: ", i);
        gmp_printf("%Zd\n", thread_data[i].start);
    }

    // Wait for all threads to finish
    for (int i = 0; i < threads_num; i++) {
        pthread_join(threads[i], NULL);
    }

    // Clear allocated memory
    mpz_clear(chunk);

    set_destroy(&public_keys_set);

    // Free memory for the target_point
    mpz_clear(target_x);
    mpz_clear(target_y);

    return 0;
}
