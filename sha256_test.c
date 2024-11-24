#include "kernel/types.h"
#include "user/user.h"
#include <stddef.h>
#include "kernel/stat.h"

#define MAX_INPUT 100

int main(int argc, char *argv[]) {
    // Check if there are enough arguments
    if (argc < 2) {
        printf("Usage: program_name \"string\"\n");
        exit(0);
    }

    char input[MAX_INPUT];
    int index = 0;

    // Handle case for single argument
    if (argc == 2 && argv[1][0] == '"' && argv[1][strlen(argv[1]) - 1] == '"') {
        // Copy the single argument (excluding the starting and ending quotes)
        for (int i = 1; i < strlen(argv[1]) - 1; i++) {
            input[index++] = argv[1][i];
        }
        input[index] = '\0'; // Null-terminate the string
    }
    // Handle case for multiple arguments (e.g., "hello world")
    else if (argv[1][0] == '"' && argv[argc - 1][strlen(argv[argc - 1]) - 1] == '"') {
        // Copy the first argument (excluding the starting quote)
        for (int i = 1; argv[1][i] != '\0'; i++) {
            input[index++] = argv[1][i];
        }

        // Copy any intermediate arguments,, with spaces in between
        for (int j = 2; j < argc - 1; j++) {
            input[index++] = ' '; // Add a space before the next argument
            for (int k = 0; argv[j][k] != '\0'; k++) {
                input[index++] = argv[j][k];
            }
        }

        // Copy the last argument (excluding the ending quote)
        input[index++] = ' ';  // Add a space before the last argument
        for (int i = 0; i < strlen(argv[argc - 1]) - 1; i++) {
            input[index++] = argv[argc - 1][i];
        }
        input[index] = '\0'; // Null-terminate the input string
    } else {
        printf("Input must start and end with quotation marks.\n");
        exit(0);
    }

    printf("\n");
    printf("--------------------------------System Call Implementation--------------------------------\n");
    printf("Input string: %s\n", input);


    sha256_for_sys(input);
    printf("------------------------------------------------------------------------------------------\n");
    printf("\n");

    exit(0);
}
