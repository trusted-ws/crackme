/* Adaptation for Hack The Box */

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

void funcao(const char* buffer) {


    //const char* flag = "HTB{0x04_Your_Sk1lls_R_am4z1ng}";
    const char flag[32] = { 0x2b, 0x3c, 0x27, 0x0c, 0x52,
                      0x19, 0x53, 0x57, 0x3e, 0x3a,
                      0x07, 0x10, 0x05, 0x3d, 0x32,
                      0x08, 0x52, 0x0d, 0x0f, 0x1b,
                      0x3a, 0x25, 0x3d, 0x00, 0x0e,
                      0x57, 0x1b, 0x52, 0x06, 0x02,
                      0x0a, 0x00 };

    int index = 0;
    for(int i = 0; i < sizeof(flag) - 1; i++) {
        if(index == sizeof(buffer) + 1)
            index = 0;

        putchar(buffer[index] ^ flag[i]);
        index++;
    }
    putchar(0x0a);
}

int main(void) {

    /*  Correct Inputs: 
     *  passphrase: chewbacca
     *  PIN:        1262
     */

    /* Please enter with the passphrase String */
    char str2[] = { 0x74, 0x48, 0x41, 0x45, 0x57,
                    0x41, 0x04, 0x41, 0x4a, 0x50,
                    0x41, 0x56, 0x04, 0x53, 0x4d,
                    0x50, 0x4c, 0x04, 0x50, 0x4c,
                    0x41, 0x04, 0x54, 0x45, 0x57,
                    0x57, 0x54, 0x4c, 0x56, 0x45,
                    0x57, 0x41, 0x1e, 0x04, 0x00 };

    /* Please enter with the PIN String */
    char str3[] = { 0x74, 0x48, 0x41, 0x45, 0x57,
                    0x41, 0x04, 0x41, 0x4a, 0x50,
                    0x41, 0x56, 0x04, 0x53, 0x4d,
                    0x50, 0x4c, 0x04, 0x50, 0x4c,
                    0x41, 0x04, 0x74, 0x6d, 0x6a,
                    0x1e, 0x04, 0x00 };

    /* Wrong passphrase String */
    char str4[] = { 0x73, 0x56, 0x4b, 0x4a, 0x43,
                    0x04, 0x54, 0x45, 0x57, 0x57,
                    0x54, 0x4c, 0x56, 0x45, 0x57,
                    0x41, 0x04, 0x4b, 0x56, 0x04,
                    0x74, 0x6d, 0x6a, 0x05, 0x00 };

    char buffer[256];
    int intBuff = 0;

    /* Chewbacca's String */
    volatile const short int p[9] = { 0x48d, 0x486, 0x48b, 0x499, 0x48c,
                                      0x48f, 0x48d, 0x48d, 0x48f };
    
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

    funcao(buffer);

    return 0;
}
