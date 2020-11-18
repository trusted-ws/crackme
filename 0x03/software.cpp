#include <iostream>
#include <cstdlib>
#include <cstring>

#ifdef _WIN32
#include <windows.h>
#endif

#ifdef linux
#include <unistd.h>
#include <termios.h>
#endif

/* Max attempts for userInput function */
#define MAX_ATTEMPTS 3

bool checkPassword(std::string);
void dashboard(void);
void fatal(const char*);
void userInput(void);


/* Main function */
int main(void) {

    userInput();

    return 0;
}

/* Fatal function (for exit) */
void fatal(const char* msg) {
    if(msg != (void*)0) {
        fprintf(stderr, "%s\n", msg);
    }
    exit(1);
}

/* Function for grab the user input */
void userInput(void) {

#ifdef _WIN32
    HANDLE hStdin = GetStdHandle(STD_INPUT_HANDLE);
    DWORD mode = 0;
    GetConsoleMode(hStdin, &mode);
    SetConsoleMode(hStdin, mode & (~ENABLE_ECHO_INPUT));
#endif

#ifdef linux
    termios oldt;
    tcgetattr(STDIN_FILENO, &oldt);
    termios newt = oldt;
    newt.c_lflag &= ~ECHO;
    tcsetattr(STDIN_FILENO, TCSANOW, &newt);
#endif
    std::string entrada;
    int attempts = 0;

    while(attempts < MAX_ATTEMPTS) {
        attempts++;
        std::cout << "Password: ";
        std::getline(std::cin, entrada);


        if(checkPassword(entrada)) {
            
            /* Reset terminal fileno state */
#ifdef _WIN32
            SetConsoleMode(hStdin, mode);
#endif
#ifdef linux
            tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
#endif 
            dashboard();
            return;
        } else {
            std::cout << "\nPassword was incorrect!\n" << std::endl;
        }
    }

            /* Reset terminal fileno state */
#ifdef _WIN32
            SetConsoleMode(hStdin, mode);
#endif
#ifdef linux
            tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
#endif 

    fatal("You entered wrong password 3 times.");

}

/* Adminstration function (password needed for entry) */
void dashboard(void) {
    std::cout << "Welcome, Admin!" << std::endl;
}

/* Function to perform password check */
bool checkPassword(std::string entrada) {

    /* Logic:
     *      Calculate the sum of all chars and compare it with sum
     *      of correct password which is 'porra' (0x224)
     */

    const char *input = entrada.c_str();        /* User input converted to C string */
    unsigned long int HardSum = 0x224;          /* Sum of Password 'porra' */
    unsigned long int Sum = 0;                  /* Sum of user input */
    int c = 0;
    
    /* Sum calculate */
    while(input[c] != '\0') {
        Sum += (unsigned long int) input[c];
        ++c;
    }
 
    /* Sum comparison */
    if(Sum == HardSum) {
        return true;
    } else {
        return false;
    }
}
