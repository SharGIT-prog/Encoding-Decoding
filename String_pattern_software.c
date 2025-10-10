#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <time.h>
#include <stdint.h>



#define MAX_WORD 100
#define MAX_LINE 1024
#define TIMEOUT 5
#define MAX_INPUT 1024
#define MIN_PASSWORD_LENGTH 4

//Pradeep//
void generatePassword(char *password, int length, char *charset) {
int charsetSize = 0;
while (charset[charsetSize] != '\0') {
charsetSize++;
}
for (int i = 0; i < length; i++) {
password[i] = charset[rand() % charsetSize];
}
password[length] = '\0'; 
}

//Shashank//
void sortString(char *str) {
    int len = strlen(str);
    for (int i = 0; i < len-1; i++) {
        for (int j = i+1; j < len; j++) {
            if (str[i] > str[j]) {
                char temp = str[i];
                str[i] = str[j];
                str[j] = temp;
            }
        }
    }
}


int isAnagram(const char *a, const char *b) {
    if (strlen(a) != strlen(b)) return 0;
    char *copyA = strdup(a);
    char *copyB = strdup(b);

    for (int i = 0; copyA[i]; i++) copyA[i] = tolower(copyA[i]);
    for (int i = 0; copyB[i]; i++) copyB[i] = tolower(copyB[i]);

    sortString(copyA);
    sortString(copyB);

    int result = strcmp(copyA, copyB) == 0;
    free(copyA);
    free(copyB);
    return result;
}


void findAnagramGroups(const char *filename) {
    FILE *fp = fopen(filename, "r");
    if (!fp) {
        printf("Error opening file.\n");
        return;
    }

    char **words = malloc(MAX_LINE * sizeof(char *));
    int wordCount = 0;
    char buffer[MAX_WORD];

    while (fscanf(fp, "%s", buffer) != EOF) {
        words[wordCount++] = strdup(buffer);
    }
    fclose(fp);

    if (wordCount == 0) {
        printf("No words found in the file.\n");
        free(words);
        return;
    }

    printf("\nAnagram Groups:\n");
    int *visited = calloc(wordCount, sizeof(int));
    time_t startTime = time(NULL);
    int foundGroup = 0;

    for (int i = 0; i < wordCount; i++) {
        if (visited[i]) continue;

        printf("[%s", words[i]);
        visited[i] = 1;
        int groupFound = 0;

        for (int j = i+1; j < wordCount; j++) {
            if (difftime(time(NULL), startTime) > TIMEOUT) {
                printf("\nTimeout occurred. Partial results shown.\n");
                goto END_SEARCH;
            }
            if (!visited[j] && isAnagram(words[i], words[j])) {
                printf(", %s", words[j]);
                visited[j] = 1;
                groupFound = 1;
            }
        }

        if (groupFound)
            printf("]\n");
        else
            printf("] (No anagrams)\n");
    }

END_SEARCH:
    
    for (int i = 0; i < wordCount; i++) {
        free(words[i]);
    }
    free(words);
    free(visited);
}


//Shesanth//
void generate_key_from_pattern(const char *input, uint8_t *key) {
    int frequency[256] = {0};
    int length = strlen(input);

    for (int i = 0; i < length; i++) {
        frequency[(unsigned char)input[i]]++;
    }

    for (int i = 0; i < 16; i++) {
        int max_index = 0;
        for (int j = 1; j < 256; j++) {
            if (frequency[j] > frequency[max_index]) {
                max_index = j;
            }
        }
        key[i] = (uint8_t)max_index;
        frequency[max_index] = 0; 
    }
}

uint8_t substitute(uint8_t byte) {
    return (byte * 13 + 37) % 256;
}

uint8_t inverse_substitute(uint8_t byte) {
    for (int i = 0; i < 256; i++) {
        if (substitute(i) == byte) return i;
    }
    return 0; 
}

void shift_rows(uint8_t *block) {
    uint8_t temp[16];
    memcpy(temp, block, 16);

    block[1]  = temp[5];  block[5]  = temp[9];  block[9]  = temp[13]; block[13] = temp[1];
    block[2]  = temp[10]; block[6]  = temp[14]; block[10] = temp[2];  block[14] = temp[6];
    block[3]  = temp[15]; block[7]  = temp[3];  block[11] = temp[7];  block[15] = temp[11];
}

void inverse_shift_rows(uint8_t *block) {
    uint8_t temp[16];
    memcpy(temp, block, 16);

    block[1]  = temp[13]; block[5]  = temp[1];  block[9]  = temp[5];  block[13] = temp[9];
    block[2]  = temp[10]; block[6]  = temp[14]; block[10] = temp[2];  block[14] = temp[6];
    block[3]  = temp[7];  block[7]  = temp[11]; block[11] = temp[15]; block[15] = temp[3];
}

void encrypt_block(uint8_t *block, const uint8_t *key) {
    for (int i = 0; i < 16; i++) {
        block[i] ^= key[i];
    }

    for (int i = 0; i < 16; i++) {
        block[i] = substitute(block[i]);
    }

    shift_rows(block);
}

void decrypt_block(uint8_t *block, const uint8_t *key) {
    inverse_shift_rows(block);

    for (int i = 0; i < 16; i++) {
        block[i] = inverse_substitute(block[i]);
    }

    for (int i = 0; i < 16; i++) {
        block[i] ^= key[i];
    }
}

void print_hex(const uint8_t *data, int length) {
    for (int i = 0; i < length; i++) {
        printf("%02x ", data[i]);
    }
    printf("\n");
}

//Sharanya//
void encryptFile(const char *inputFile, const char *keyFile, const char *outputFile) {
    FILE *fKey = fopen(keyFile, "r");
    if (!fKey) {
        printf("Error opening key file.\n");
        return;
    }

    char **keys = malloc(MAX_LINE * sizeof(char *));
    char **values = malloc(MAX_LINE * sizeof(char *));
    int keyCount = 0;
    char buffer[MAX_LINE];

    while (fgets(buffer, MAX_LINE, fKey)) {
        char *key = strtok(buffer, ":");
        char *value = strtok(NULL, "\n");
        if (key && value) {
            keys[keyCount] = strdup(key);
            values[keyCount] = strdup(value);
            keyCount++;
        }
    }
    fclose(fKey);

    if (keyCount == 0) {
        printf("Key file is empty or has no valid key-value pairs. Aborting.\n");
        return;
    }

    FILE *fInput = fopen(inputFile, "r");
    if (!fInput) {
        printf("Error opening input file.\n");
        return;
    }

    FILE *fOutput = fopen(outputFile, "w");
    if (!fOutput) {
        printf("Error opening output file.\n");
        return;
    }

    while (fgets(buffer, MAX_LINE, fInput)) {
        for (int i = 0; buffer[i] != '\0'; i++) {
            char ch = buffer[i];
            int found = 0;
            if (ch == '\n') {
                fputc('\n', fOutput);  
                continue;
            }
            for (int j = 0; j < keyCount; j++) {
            	if (ch == keys[j][0]) {
                    fprintf(fOutput, "%s", values[j]);
                    found = 1;
                    break;
                }
            }
            if (!found) {
                 fputc('?', fOutput);  
            }
        }
    }

    fclose(fInput);
    fclose(fOutput);

    printf("Success. Encrypted file contents:\n");
    fOutput = fopen(outputFile, "r");
    while (fgets(buffer, MAX_LINE, fOutput)) {
        printf("%s", buffer);
    }
    fclose(fOutput);
}

void decryptFile(const char *inputFile, const char *keyFile, const char *outputFile) {
    FILE *fKey = fopen(keyFile, "r");
    if (!fKey) {
        printf("Error opening key file.\n");
        return;
    }

    char **keys = malloc(MAX_LINE * sizeof(char *));
    char **values = malloc(MAX_LINE * sizeof(char *));
    int keyCount = 0;
    char buffer[MAX_LINE];

    while (fgets(buffer, MAX_LINE, fKey)) {
        char *key = strtok(buffer, ":");
        char *value = strtok(NULL, "\n");
        if (key && value) {
            keys[keyCount] = strdup(key);
            values[keyCount] = strdup(value);
            keyCount++;
        }
    }
    fclose(fKey);

    if (keyCount == 0) {
        printf("Key file is empty or has no valid key-value pairs. Aborting.\n");
        return;
    }

    FILE *fInput = fopen(inputFile, "r");
    if (!fInput) {
        printf("Error opening input file.\n");
        return;
    }

    FILE *fOutput = fopen(outputFile, "w");
    if (!fOutput) {
        printf("Error opening output file.\n");
        fclose(fInput);
        return;
    }

    char fullText[MAX_LINE * 10] = "";
    while (fgets(buffer, MAX_LINE, fInput)) {
        strcat(fullText, buffer);
    }
    fclose(fInput);

    time_t startTime = time(NULL);
    int i = 0;
    int timedOut = 0;
    int didDecryptAnything = 0;

    while (i < strlen(fullText)) {
        if (difftime(time(NULL), startTime) > TIMEOUT) {
            timedOut = 1;
            break;
        }

        if (fullText[i] == '\n') {
            fputc('\n', fOutput);
            i++;
            continue;
        }

        int matched = 0;
        for (int j = 0; j < keyCount; j++) {
            int valueLen = strlen(values[j]);
            if (strncmp(&fullText[i], values[j], valueLen) == 0) {
                fprintf(fOutput, "%s", keys[j]);
                i += valueLen;
                matched = 1;
                didDecryptAnything = 1;
                break;
            }
        }
        if (!matched) {
            i++; 
        }
    }

    fclose(fOutput);

    if (timedOut || !didDecryptAnything) {
        remove(outputFile);
        printf("Decryption failed. Either it timed out or nothing was matched.\n");
        return;
    }

    printf("Success. Decrypted file contents:\n");
    fOutput = fopen(outputFile, "r");
    while (fgets(buffer, MAX_LINE, fOutput)) {
        printf("%s", buffer);
    }
    fclose(fOutput);
}





void main() {
    char choice1;
    do {
        printf("\n1. Password Generation\n2. Anagrams\n3. Encryption using Files\n4. Encryption using patterns\n");
        int option1;
        if (scanf("%d", &option1) != 1) {
            printf("Invalid input. Please enter a number between 1 and 4.\n");
            while (getchar() != '\n');
            option1 = -1;
        } else {
            getchar();
        }

        char inputFile[256], keyFile[256], outputFile[256];
        if (option1 == 1) {

            int length, choice, numPasswords;
            char includeSpecial;
            printf("Enter the length of the password (minimum %d): ", 8);
            if (scanf("%d", &length) != 1 || length < 8) {
                printf("Invalid input. Using minimum length of %d.\n", 8);
                length = 8;
                while (getchar() != '\n');
            } else {
                getchar();
            }
            printf("\nChoose the type of password:\n");
            printf("1. Only alphabets\n");
            printf("2. Only numbers\n");
            printf("3. Alphabets and numbers\n");
            printf("4. Alphabets, numbers, and special characters\n");
            printf("5. Only lowercase letters\n");
            printf("6. Only uppercase letters\n");
            printf("Enter your choice (1-6): ");
            if (scanf("%d", &choice) != 1 || choice < 1 || choice > 6) {
                printf("Invalid choice. Defaulting to Alphabets, numbers, and special characters.\n");
                choice = 4;
                while (getchar() != '\n');
            } else {
                getchar();
            }
            printf("\nHow many passwords do you want to generate? ");
            if (scanf("%d", &numPasswords) != 1 || numPasswords < 1) {
                printf("Invalid number. Generating 1 password.\n");
                numPasswords = 1;
                while (getchar() != '\n');
            } else {
                getchar();
            }

            char uppercase[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
            char lowercase[] = "abcdefghijklmnopqrstuvwxyz";
            char numbers[] = "0123456789";
            char special[] = "!@#$%^&*()";

            char charset[100] = "";

            switch (choice) {
                case 1:
                    sprintf(charset, "%s%s", uppercase, lowercase);
                    break;
                case 2:
                    sprintf(charset, "%s", numbers);
                    break;
                case 3:
                    sprintf(charset, "%s%s%s", uppercase, lowercase, numbers);
                    break;
                case 4:
                    sprintf(charset, "%s%s%s%s", uppercase, lowercase, numbers, special);
                    break;
                case 5:
                    sprintf(charset, "%s", lowercase);
                    break;
                case 6:
                    sprintf(charset, "%s", uppercase);
                    break;
                default:
                    sprintf(charset, "%s%s%s%s", uppercase, lowercase, numbers, special);
            }

            srand(time(NULL));

            for (int i = 0; i < numPasswords; i++) {
                char password[length + 1];
                generatePassword(password, length, charset);
                printf("\nPassword %d: %s", i + 1, password);
            }

            printf("\n");


        } else if (option1 == 2) {
            char choice;
            do {
                printf("\n1. Check if two words are anagrams\n");
                printf("2. Find all anagram groups from file\n");
                printf("Enter your choice: ");

                int option;
                if (scanf("%d", &option) != 1) {
                    printf("Invalid choice.\n");
                    while (getchar() != '\n');
                    option = -1;
                } else {
                    getchar();
                }

                if (option == 1) {
                    char word1[256], word2[256];
                    printf("Enter first word: ");
                    scanf("%s", word1);
                    printf("Enter second word: ");
                    scanf("%s", word2);
                    getchar();
                    if (isAnagram(word1, word2))
                        printf("The words are anagrams.\n");
                    else
                        printf("The words are NOT anagrams.\n");
                } else if (option == 2) {
                    char filename[256];
                    printf("Enter filename: ");
                    scanf("%s", filename);
                    getchar();
                    findAnagramGroups(filename);
                } else if (option != -1) {
                    printf("Invalid choice.\n");
                }

                printf("Do you want to continue with ANAGRAMS? (y/n): ");
                if (scanf("%c", &choice) != 1) {
                    while (getchar() != '\n');
                    choice = 'n';
                } else {
                    getchar();
                }

            } while (tolower(choice) == 'y');

        } else if (option1 == 4) {

            char input[256];

            printf("Enter a message to encrypt: ");
            fgets(input, 256, stdin);

            size_t input_length = strlen(input);
            if (input[input_length - 1] == '\n') {
                input[input_length - 1] = '\0';
                input_length--;
            }

            int padded_length = ((input_length + 15) / 16) * 16;
            uint8_t *buffer = calloc(padded_length, 1);
            memcpy(buffer, input, input_length);
            uint8_t key[16];
            generate_key_from_pattern(input, key);

            printf("\nGenerated Key (Hex):\n");
            print_hex(key, 16);

            for (int i = 0; i < padded_length; i += 16) {
                encrypt_block(&buffer[i], key);
            }

            printf("\nEncrypted Data (Hex):\n");
            print_hex(buffer, padded_length);

            for (int i = 0; i < padded_length; i += 16) {
                decrypt_block(&buffer[i], key);
            }

            printf("\nDecrypted Message:\n%s\n", buffer);
            free(buffer);


        } else if (option1 == 3) {
            char choice;
            do {
                printf("\n1. Encrypt\n2. Decrypt\n");
                int option;
                if (scanf("%d", &option) != 1) {
                    printf("Enter valid input.\n");
                    while (getchar() != '\n');
                    option = -1;
                } else {
                    getchar();
                }

                char inputFile[256], keyFile[256], outputFile[256];
                if (option == 1) {
                    printf("Enter name of file to be encrypted: ");
                    scanf("%255s", inputFile);
                    getchar();
                    printf("Enter name of key file: ");
                    scanf("%255s", keyFile);
                    getchar();
                    printf("Enter name of file into which text has to be entered: ");
                    scanf("%255s", outputFile);
                    getchar();
                    encryptFile(inputFile, keyFile, outputFile);
                } else if (option == 2) {
                    printf("Enter name of file to be decrypted: ");
                    scanf("%255s", inputFile);
                    getchar();
                    printf("Enter name of key file: ");
                    scanf("%255s", keyFile);
                    getchar();
                    printf("Enter name of file into which text has to be entered: ");
                    scanf("%255s", outputFile);
                    getchar();
                    decryptFile(inputFile, keyFile, outputFile);
                } else if (option != -1) {
                    printf("Enter valid input.\n");
                }

                printf("Do you want to continue with ENCRYPTION? y/n: ");
                if (scanf("%c", &choice) != 1) {
                    while (getchar() != '\n');
                    choice = 'n';
                } else {
                    getchar();
                }
            } while (tolower(choice) == 'y');
        } else if (option1 != -1) {
            printf("Enter valid input.\n");
        }

        printf("Do you want to continue exploring new string patterns? y/n: ");
        if (scanf("%c", &choice1) != 1) {
            while (getchar() != '\n');
            choice1 = 'n';
        } else {
            getchar();
        }
    } while (tolower(choice1) == 'y');
}

