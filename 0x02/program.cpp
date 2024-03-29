#include <cstdlib>
#include <iostream>
#include <stdio.h>
#include <string.h>

/* Logic: String is decrypted with decremented XOR operation.
 * ------------------------------------------------------------
 *
 * To win: ./program -p <password>
 * 
 * */

class The_Main {
private:
    /* Code: 156 (0x9C) (Won) / 154 (0x9A) (Lost) */
    int code = 0;

public:
    The_Main(int c)
        : code(c) {
    }

    void setCode(int c) {
        code = c;
    }

    int getCode(void) const {
        return code;
    }

    void checkValue(const char *password, int size_of_password) {
        int n = 256; /* Base value for XOR operation */
        if((int)strlen(password) != size_of_password) { 
            /* Mismatch password size */
            setCode(0x9A);
            return;
        }

        /* Values 'll only match with 'chewbacca' */
        if((password[0] ^ (n - 0)) == 355 &&
           (password[1] ^ (n - 1)) == 151 &&
           (password[2] ^ (n - 2)) == 155 &&
           (password[3] ^ (n - 3)) == 138 && 
           (password[4] ^ (n - 4)) == 158 &&
           (password[5] ^ (n - 5)) == 154 &&
           (password[6] ^ (n - 6)) == 153 &&
           (password[7] ^ (n - 7)) == 154 &&
           (password[8] ^ (n - 8)) == 153) { setCode(0x9C); } else { setCode(0x9A); }}
};

static void fatal(int r, const char* msg) {
    if(msg != (void*)0) {
        fprintf(stderr, "%s\n", msg);
    }
    exit(r);
}

void win(void) {
    std::cout << "Congratulations!" << std::endl;
    fatal(0, "YOU WIN!");
}

void defeat(void) {
    fatal(1, "Password was incorrect!");
}

void processArgument(int argc, char **args) {

    The_Main x(0x9A);

    for(int i = 0; i < argc; i++) {
        
        // Trying to parse '-p <password>'
        if(strcmp(args[i], "-p") == 0) {
            if(args[i + 1]) {
                if(strlen(args[i + 1]) == 9) {
                    x.checkValue(args[i + 1], 9);
                }
            } 
        }
    }

    /* Final comparison of password */
    if((x.getCode() ^ 0x9C) == (0x9C ^ (0x84 + 0x18))) {
        win();
    } else {
        defeat();
    }
}


signed main(int argc, char *argv[], [[maybe_unused]] char *envp[]) {

    if(argc < 2) {
        fatal(1, "usage: ./program -p <password>");
    } else {
        processArgument(argc, argv);
    }

    return 0;
}
