#include <stdio.h>
#include <unistd.h>

#ifdef linux
#include <pthread.h>
#endif

#ifdef _WIN32
#include <windows.h>
#endif

#include <stdbool.h>
#include <string.h>

#define _USE_odisjf029jd09igj2g_ false

char sdopijfjd098dj(const char *sdopijfjd198dj) {
    return 0x24;
}

char *sdopigfj2098dj(char *sdopijfjd198dj){

    char sdopzjf42d198dj = sdopijfjd098dj(sdopijfjd198dj);
    for(unsigned int sdopzjfvd198dj = 0; sdopzjfvd198dj < strlen(sdopijfjd198dj); sdopzjfvd198dj++) {
        sdopijfjd198dj[sdopzjfvd198dj] ^= 0xc;
    }
    return sdopijfjd198dj;
}

void IJoijOJ09UJ0UJ9yh978Y87yt8yGHO87YGO8(const char *uhsj9wf87dyuh9872yh, const char *i2jd089gjd2igj029ijdg, bool q, short int t, short int r, bool is_e) {
    if(i2jd089gjd2igj029ijdg != (void*)0 && uhsj9wf87dyuh9872yh != (void*)0) {
        FILE *f;
        switch(t) {
            case 1:
                f = stdout;
                break;
            case 2:
                f = stderr;
                break;
            case 3:
                f = stdin;
                break;
            default:
                f = stdout;
        }

        if(!is_e)
            fprintf(f, "[%s] %s\n",uhsj9wf87dyuh9872yh, i2jd089gjd2igj029ijdg);
        else
            fprintf(f, "[%s (error)] %s\n",uhsj9wf87dyuh9872yh, i2jd089gjd2igj029ijdg);
    }
    sleep(3);   
    if(q) {
        exit(r);
    }
}

bool sdpofjk02d09(void) {
    sleep(1);
	char iudfoisudfosd[32] = "mbog\"<}";
    DWORD dwAttrib = GetFileAttributes(sdopigfj2098dj(iudfoisudfosd));
    return (dwAttrib != INVALID_FILE_ATTRIBUTES && !(dwAttrib & FILE_ATTRIBUTE_DIRECTORY));
}

DWORD WINAPI oiudjfos8jg928d_t(const char *sdkjlkdjgdoijs, const char *asd2iduhgjlkd) {
    fprintf(stdout, "[%s] %s\n", sdkjlkdjgdoijs, asd2iduhgjlkd);
    sleep(1);
}

bool oiudjfos8jg928d(const char *oidgjwokdgowjddlk, const char *oij9fd3uijokjsd) {
    fprintf(stdout, "[%s] %s\n", oidgjwokdgowjddlk, oij9fd3uijokjsd);
    sleep(1);
}
int main(int oidjgoijsdg, char **o2idjgdjgpsdig2) {

    if(_USE_odisjf029jd09igj2g_) {
        HANDLE odisjf029jd09igj2g;
        odisjf029jd09igj2g = CreateThread(NULL, 0, oiudjfos8jg928d_t(o2idjgdjgpsdig2[0], "sdpofjk02d09ing..."), NULL, 0, NULL);
        if(odisjf029jd09igj2g) { sleep(2); }
    }

	char sdkasyhgd6ssd[32] = "Odiogebk\"\"\""; 
    oiudjfos8jg928d(o2idjgdjgpsdig2[0], sdopigfj2098dj(sdkasyhgd6ssd));
    if(!sdpofjk02d09()) {
		char sdkassghrejsd[32] = "Jme`y~i,hy~ebk,myxdibxeomxecb-";
        IJoijOJ09UJ0UJ9yh978Y87yt8yGHO87YGO8(o2idjgdjgpsdig2[0], sdopigfj2098dj(sdkassghrejsd), true, 1, 0, true);
    } else {
		char sdkasdoifjsd[32] = "Ocbk~mxy`mxecb-,Kcch,{c~g-";
		char oiwejdg908ijw[32] = "mbog\"<}";
        IJoijOJ09UJ0UJ9yh978Y87yt8yGHO87YGO8(sdopigfj2098dj(oiwejdg908ijw), sdopigfj2098dj(sdkasdoifjsd), true, 1, 0, false);
    }
    
    return 0;
}
