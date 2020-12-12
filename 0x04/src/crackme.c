#include <string.h>
#include <stdio.h>
#include <stdlib.h>

void sair(const char* msg) {
    if(msg != (void*)0) {
        fprintf(stderr, "%s\n", msg);
    }
    exit(1);
}

const char* __attribute__((optimize("O0"))) decrypt(char *array, size_t sz, volatile unsigned int partial, volatile unsigned int after) {
    
    volatile static char key = 0x10;  /* Need to be: 0x24 (36 decimal) */
    
    /* Logic for partial key value: (partial) */
    if(partial > 0)
        key += partial;
    
    /* printf("Key: %#.2x\n", key); */

    for(int i = 0; i < sz - 1; i++) {
        array[i] ^= key;
    }

    /* Changing key value */
    key = after;

    return array;
}

void funcao(const char* msg) {
    printf("%s\n", msg);
    exit(1);
}

int main(void) {

    /* Input: 
     *  pass: chewbacca
     *  code: 1262
     */

    char str1[] = { 0x2e, 0x2e, 0x74, 0x45, 0x56,
                    0x45, 0x46, 0x41, 0x4a, 0x57,
                    0x05, 0x2e, 0x2e, 0x00 };

    char str2[] = { 0x74, 0x48, 0x41, 0x45, 0x57,
                    0x41, 0x04, 0x41, 0x4a, 0x50,
                    0x41, 0x56, 0x04, 0x53, 0x4d,
                    0x50, 0x4c, 0x04, 0x50, 0x4c,
                    0x41, 0x04, 0x54, 0x45, 0x57,
                    0x57, 0x54, 0x4c, 0x56, 0x45,
                    0x57, 0x41, 0x1e, 0x04, 0x00 };

    char str3[] = { 0x74, 0x48, 0x41, 0x45, 0x57,
                    0x41, 0x04, 0x41, 0x4a, 0x50,
                    0x41, 0x56, 0x04, 0x53, 0x4d,
                    0x50, 0x4c, 0x04, 0x50, 0x4c,
                    0x41, 0x04, 0x74, 0x6d, 0x6a,
                    0x1e, 0x04, 0x00 };

    char str4[] = { 0x73, 0x56, 0x4b, 0x4a, 0x43,
                    0x04, 0x54, 0x45, 0x57, 0x57,
                    0x54, 0x4c, 0x56, 0x45, 0x57,
                    0x41, 0x04, 0x4b, 0x56, 0x04,
                    0x74, 0x6d, 0x6a, 0x05, 0x00 };

    char buffer[256];
    int intBuff = 0;
    volatile const short int p[9] = { 0x48d, 0x486, 0x48b, 0x499, 0x48c,
                             0x48f, 0x48d, 0x48d, 0x48f }; /* chewbacca string */
    
    printf("%s", decrypt(str2, sizeof(str2), 0x14, 0x12));
    fgets(buffer, sizeof(buffer), stdin);

    printf("%s", decrypt(str3, sizeof(str3), 0x12, 0x01));
    scanf("%d", &intBuff);

    for(int i = 0; i < 9; i++) {
        char o = p[i] ^ intBuff;
        if(buffer[i] != o) {
            sair(decrypt(str4, sizeof(str4), 0x23, 0x24));
        }
    }

    funcao(decrypt(str1, sizeof(str1), 0x23, 0x12));

    return 0;
}
