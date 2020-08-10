/* 
 *  Please do not modify 
 * 
 *  Não modificar
 *
 *  trusted-ws - 09/08/2020
 */

typedef unsigned char   undefined;

typedef unsigned int    ImageBaseOffset32;
typedef unsigned char    byte;
typedef unsigned int    dword;
typedef unsigned char    uchar;
typedef unsigned int    uint;
typedef unsigned long    ulong;
typedef unsigned char    undefined1;
typedef unsigned short    undefined2;
typedef unsigned int    undefined4;
typedef unsigned long long    undefined8;
typedef unsigned short    ushort;
typedef short    wchar_t;
typedef unsigned short    word;
typedef struct _WIN32_FIND_DATAA _WIN32_FIND_DATAA, *P_WIN32_FIND_DATAA;

typedef ulong DWORD;

typedef struct _FILETIME _FILETIME, *P_FILETIME;

typedef struct _FILETIME FILETIME;

typedef char CHAR;

struct _FILETIME {
    DWORD dwLowDateTime;
    DWORD dwHighDateTime;
};

struct _WIN32_FIND_DATAA {
    DWORD dwFileAttributes;
    FILETIME ftCreationTime;
    FILETIME ftLastAccessTime;
    FILETIME ftLastWriteTime;
    DWORD nFileSizeHigh;
    DWORD nFileSizeLow;
    DWORD dwReserved0;
    DWORD dwReserved1;
    CHAR cFileName[260];
    CHAR cAlternateFileName[14];
};

typedef struct _RTL_CRITICAL_SECTION _RTL_CRITICAL_SECTION, *P_RTL_CRITICAL_SECTION;

typedef struct _RTL_CRITICAL_SECTION * PRTL_CRITICAL_SECTION;

typedef PRTL_CRITICAL_SECTION LPCRITICAL_SECTION;

typedef struct _RTL_CRITICAL_SECTION_DEBUG _RTL_CRITICAL_SECTION_DEBUG, *P_RTL_CRITICAL_SECTION_DEBUG;

typedef struct _RTL_CRITICAL_SECTION_DEBUG * PRTL_CRITICAL_SECTION_DEBUG;

typedef long LONG;

typedef void * HANDLE;

typedef ulong ULONG_PTR;

typedef ushort WORD;

typedef struct _LIST_ENTRY _LIST_ENTRY, *P_LIST_ENTRY;

typedef struct _LIST_ENTRY LIST_ENTRY;

struct _RTL_CRITICAL_SECTION {
    PRTL_CRITICAL_SECTION_DEBUG DebugInfo;
    LONG LockCount;
    LONG RecursionCount;
    HANDLE OwningThread;
    HANDLE LockSemaphore;
    ULONG_PTR SpinCount;
};

struct _LIST_ENTRY {
    struct _LIST_ENTRY * Flink;
    struct _LIST_ENTRY * Blink;
};

struct _RTL_CRITICAL_SECTION_DEBUG {
    WORD Type;
    WORD CreatorBackTraceIndex;
    struct _RTL_CRITICAL_SECTION * CriticalSection;
    LIST_ENTRY ProcessLocksList;
    DWORD EntryCount;
    DWORD ContentionCount;
    DWORD Flags;
    WORD CreatorBackTraceIndexHigh;
    WORD SpareWORD;
};

typedef struct _WIN32_FIND_DATAA * LPWIN32_FIND_DATAA;

typedef struct _EXCEPTION_POINTERS _EXCEPTION_POINTERS, *P_EXCEPTION_POINTERS;

typedef LONG (* PTOP_LEVEL_EXCEPTION_FILTER)(struct _EXCEPTION_POINTERS *);

typedef struct _EXCEPTION_RECORD _EXCEPTION_RECORD, *P_EXCEPTION_RECORD;

typedef struct _EXCEPTION_RECORD EXCEPTION_RECORD;

typedef EXCEPTION_RECORD * PEXCEPTION_RECORD;

typedef struct _CONTEXT _CONTEXT, *P_CONTEXT;

typedef struct _CONTEXT CONTEXT;

typedef CONTEXT * PCONTEXT;

typedef void * PVOID;

typedef struct _FLOATING_SAVE_AREA _FLOATING_SAVE_AREA, *P_FLOATING_SAVE_AREA;

typedef struct _FLOATING_SAVE_AREA FLOATING_SAVE_AREA;

typedef uchar BYTE;

struct _FLOATING_SAVE_AREA {
    DWORD ControlWord;
    DWORD StatusWord;
    DWORD TagWord;
    DWORD ErrorOffset;
    DWORD ErrorSelector;
    DWORD DataOffset;
    DWORD DataSelector;
    BYTE RegisterArea[80];
    DWORD Cr0NpxState;
};

struct _CONTEXT {
    DWORD ContextFlags;
    DWORD Dr0;
    DWORD Dr1;
    DWORD Dr2;
    DWORD Dr3;
    DWORD Dr6;
    DWORD Dr7;
    FLOATING_SAVE_AREA FloatSave;
    DWORD SegGs;
    DWORD SegFs;
    DWORD SegEs;
    DWORD SegDs;
    DWORD Edi;
    DWORD Esi;
    DWORD Ebx;
    DWORD Edx;
    DWORD Ecx;
    DWORD Eax;
    DWORD Ebp;
    DWORD Eip;
    DWORD SegCs;
    DWORD EFlags;
    DWORD Esp;
    DWORD SegSs;
    BYTE ExtendedRegisters[512];
};

struct _EXCEPTION_RECORD {
    DWORD ExceptionCode;
    DWORD ExceptionFlags;
    struct _EXCEPTION_RECORD * ExceptionRecord;
    PVOID ExceptionAddress;
    DWORD NumberParameters;
    ULONG_PTR ExceptionInformation[15];
};

struct _EXCEPTION_POINTERS {
    PEXCEPTION_RECORD ExceptionRecord;
    PCONTEXT ContextRecord;
};

typedef PTOP_LEVEL_EXCEPTION_FILTER LPTOP_LEVEL_EXCEPTION_FILTER;

typedef struct _MEMORY_BASIC_INFORMATION _MEMORY_BASIC_INFORMATION, *P_MEMORY_BASIC_INFORMATION;

typedef ULONG_PTR SIZE_T;

struct _MEMORY_BASIC_INFORMATION {
    PVOID BaseAddress;
    PVOID AllocationBase;
    DWORD AllocationProtect;
    SIZE_T RegionSize;
    DWORD State;
    DWORD Protect;
    DWORD Type;
};

typedef CHAR * LPCSTR;

typedef struct _MEMORY_BASIC_INFORMATION * PMEMORY_BASIC_INFORMATION;

typedef CHAR * LPSTR;

typedef struct IMAGE_DOS_HEADER IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;

struct IMAGE_DOS_HEADER {
    char e_magic[2]; // Magic number
    word e_cblp; // Bytes of last page
    word e_cp; // Pages in file
    word e_crlc; // Relocations
    word e_cparhdr; // Size of header in paragraphs
    word e_minalloc; // Minimum extra paragraphs needed
    word e_maxalloc; // Maximum extra paragraphs needed
    word e_ss; // Initial (relative) SS value
    word e_sp; // Initial SP value
    word e_csum; // Checksum
    word e_ip; // Initial IP value
    word e_cs; // Initial (relative) CS value
    word e_lfarlc; // File address of relocation table
    word e_ovno; // Overlay number
    word e_res[4][4]; // Reserved words
    word e_oemid; // OEM identifier (for e_oeminfo)
    word e_oeminfo; // OEM information; e_oemid specific
    word e_res2[10][10]; // Reserved words
    dword e_lfanew; // File address of new exe header
    byte e_program[64]; // Actual DOS program
};

typedef int (* FARPROC)(void);

typedef struct HINSTANCE__ HINSTANCE__, *PHINSTANCE__;

typedef struct HINSTANCE__ * HINSTANCE;

struct HINSTANCE__ {
    int unused;
};

typedef void * LPCVOID;

typedef void * LPVOID;

typedef struct HWND__ HWND__, *PHWND__;

typedef struct HWND__ * HWND;

struct HWND__ {
    int unused;
};

typedef HINSTANCE HMODULE;

typedef DWORD * PDWORD;

typedef int BOOL;

typedef uint UINT;

typedef struct IMAGE_OPTIONAL_HEADER32 IMAGE_OPTIONAL_HEADER32, *PIMAGE_OPTIONAL_HEADER32;

typedef struct IMAGE_DATA_DIRECTORY IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;

struct IMAGE_DATA_DIRECTORY {
    ImageBaseOffset32 VirtualAddress;
    dword Size;
};

struct IMAGE_OPTIONAL_HEADER32 {
    word Magic;
    byte MajorLinkerVersion;
    byte MinorLinkerVersion;
    dword SizeOfCode;
    dword SizeOfInitializedData;
    dword SizeOfUninitializedData;
    ImageBaseOffset32 AddressOfEntryPoint;
    ImageBaseOffset32 BaseOfCode;
    ImageBaseOffset32 BaseOfData;
    pointer32 ImageBase;
    dword SectionAlignment;
    dword FileAlignment;
    word MajorOperatingSystemVersion;
    word MinorOperatingSystemVersion;
    word MajorImageVersion;
    word MinorImageVersion;
    word MajorSubsystemVersion;
    word MinorSubsystemVersion;
    dword Win32VersionValue;
    dword SizeOfImage;
    dword SizeOfHeaders;
    dword CheckSum;
    word Subsystem;
    word DllCharacteristics;
    dword SizeOfStackReserve;
    dword SizeOfStackCommit;
    dword SizeOfHeapReserve;
    dword SizeOfHeapCommit;
    dword LoaderFlags;
    dword NumberOfRvaAndSizes;
    struct IMAGE_DATA_DIRECTORY DataDirectory[16];
};

typedef struct IMAGE_SECTION_HEADER IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;

typedef union Misc Misc, *PMisc;

typedef enum SectionFlags {
    IMAGE_SCN_ALIGN_1024BYTES=11534336,
    IMAGE_SCN_ALIGN_128BYTES=8388608,
    IMAGE_SCN_ALIGN_16BYTES=5242880,
    IMAGE_SCN_ALIGN_1BYTES=1048576,
    IMAGE_SCN_ALIGN_2048BYTES=12582912,
    IMAGE_SCN_ALIGN_256BYTES=9437184,
    IMAGE_SCN_ALIGN_2BYTES=2097152,
    IMAGE_SCN_ALIGN_32BYTES=6291456,
    IMAGE_SCN_ALIGN_4096BYTES=13631488,
    IMAGE_SCN_ALIGN_4BYTES=3145728,
    IMAGE_SCN_ALIGN_512BYTES=10485760,
    IMAGE_SCN_ALIGN_64BYTES=7340032,
    IMAGE_SCN_ALIGN_8192BYTES=14680064,
    IMAGE_SCN_ALIGN_8BYTES=4194304,
    IMAGE_SCN_CNT_CODE=32,
    IMAGE_SCN_CNT_INITIALIZED_DATA=64,
    IMAGE_SCN_CNT_UNINITIALIZED_DATA=128,
    IMAGE_SCN_GPREL=32768,
    IMAGE_SCN_LNK_COMDAT=4096,
    IMAGE_SCN_LNK_INFO=512,
    IMAGE_SCN_LNK_NRELOC_OVFL=16777216,
    IMAGE_SCN_LNK_OTHER=256,
    IMAGE_SCN_LNK_REMOVE=2048,
    IMAGE_SCN_MEM_16BIT=131072,
    IMAGE_SCN_MEM_DISCARDABLE=33554432,
    IMAGE_SCN_MEM_EXECUTE=536870912,
    IMAGE_SCN_MEM_LOCKED=262144,
    IMAGE_SCN_MEM_NOT_CACHED=67108864,
    IMAGE_SCN_MEM_NOT_PAGED=134217728,
    IMAGE_SCN_MEM_PRELOAD=524288,
    IMAGE_SCN_MEM_PURGEABLE=131072,
    IMAGE_SCN_MEM_READ=1073741824,
    IMAGE_SCN_MEM_SHARED=268435456,
    IMAGE_SCN_MEM_WRITE=2147483648,
    IMAGE_SCN_RESERVED_0001=16,
    IMAGE_SCN_RESERVED_0040=1024,
    IMAGE_SCN_TYPE_NO_PAD=8
} SectionFlags;

union Misc {
    dword PhysicalAddress;
    dword VirtualSize;
};

struct IMAGE_SECTION_HEADER {
    char Name[8];
    union Misc Misc;
    ImageBaseOffset32 VirtualAddress;
    dword SizeOfRawData;
    dword PointerToRawData;
    dword PointerToRelocations;
    dword PointerToLinenumbers;
    word NumberOfRelocations;
    word NumberOfLinenumbers;
    enum SectionFlags Characteristics;
};

typedef struct IMAGE_THUNK_DATA32 IMAGE_THUNK_DATA32, *PIMAGE_THUNK_DATA32;

struct IMAGE_THUNK_DATA32 {
    dword StartAddressOfRawData;
    dword EndAddressOfRawData;
    dword AddressOfIndex;
    dword AddressOfCallBacks;
    dword SizeOfZeroFill;
    dword Characteristics;
};

typedef struct IMAGE_FILE_HEADER IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;

struct IMAGE_FILE_HEADER {
    word Machine; // 332
    word NumberOfSections;
    dword TimeDateStamp;
    dword PointerToSymbolTable;
    dword NumberOfSymbols;
    word SizeOfOptionalHeader;
    word Characteristics;
};

typedef struct IMAGE_NT_HEADERS32 IMAGE_NT_HEADERS32, *PIMAGE_NT_HEADERS32;

struct IMAGE_NT_HEADERS32 {
    char Signature[4];
    struct IMAGE_FILE_HEADER FileHeader;
    struct IMAGE_OPTIONAL_HEADER32 OptionalHeader;
};

typedef struct _iobuf _iobuf, *P_iobuf;

struct _iobuf {
    char * _ptr;
    int _cnt;
    char * _base;
    int _flag;
    int _file;
    int _charbuf;
    int _bufsiz;
    char * _tmpfname;
};

typedef struct _iobuf FILE;

typedef char * va_list;

typedef int (* _onexit_t)(void);

typedef uint size_t;

typedef struct _startupinfo _startupinfo, *P_startupinfo;

struct _startupinfo {
    int newmode;
};




void Funcao_11a0(void)

{
  code *pcVar1;
  int *piVar2;
  char **ppcVar3;
  UINT uExitCode;
  int extraout_EAX;
  int _Mode;
  undefined *local_1c;
  undefined4 local_18;
  undefined4 local_14;
  
  local_14 = 0;
  local_18 = 2;
  ___dyn_tls_init_12(0,2);
  local_1c = &LAB_00401000;
  _SetUnhandledExceptionFilter_4((LPTOP_LEVEL_EXCEPTION_FILTER)&LAB_00401000);
  ___cpu_features_init(local_1c,local_18,local_14);
  _fesetenv(__CRT_fenv);
  __setargv();
  _Mode = __CRT_fmode;
  if (__CRT_fmode != 0) goto LAB_00401242;
  do {
    piVar2 = (int *)___p__fmode();
    *piVar2 = __fmode;
    __pei386_runtime_relocator();
    ___main();
    ppcVar3 = (char **)___p__environ();
    uExitCode = _main(__argc,DAT_00407000,(char **)*ppcVar3);
    __cexit();
    _ExitProcess_4(uExitCode);
    _Mode = extraout_EAX;
LAB_00401242:
    pcVar1 = _iob_exref;
    __fmode = _Mode;
    __setmode(*(int *)(_iob_exref + 0x10),_Mode);
    __setmode(*(int *)(pcVar1 + 0x30),__CRT_fmode);
    __setmode(*(int *)(pcVar1 + 0x50),__CRT_fmode);
  } while( true );
}



void __mingw32_init_mainargs(void)

{
  char **local_14;
  _startupinfo local_10 [4];
  
  local_10[0] = (_startupinfo)0x0;
  ___getmainargs(&__argc,(char ***)&DAT_00407000,&local_14,__CRT_glob & 1,local_10);
  return;
}




void _mainCRTStartup(void)

{
  __set_app_type(1);
  Funcao_11a0();
  __set_app_type(2);
  Funcao_11a0();
  atexit();
  return;
}




int __cdecl _atexit(void *param_1)

{
  int iVar1;
  
  iVar1 = atexit();
  return iVar1;
}



int __cdecl _main(int _Argc,char **_Argv,char **_Env)

{
  ___main();
  if (_Argc == 2) {
    _strcmp("Haxkic",_Argv[1]);
    _MessageBoxA_16((HWND)0x0,"Voce conseguiu!\nMuito bom mesmo.","Parabens!!!!",0x30);
  }
  else {
    _fprintf((FILE *)(_iob_exref + 0x20),"Nao sei %s. Tente com argumentos...\n","hassx");
  }
  return 0;
}



// WARNING (jumptable): Unable to track spacebase fully for stack

int __cdecl __setargv(void)

{
  int iVar1;
  LPSTR _Str;
  char *pcVar2;
  int iVar3;
  char *pcVar4;
  char *pcVar5;
  bool bVar6;
  uint uVar7;
  char *pcVar8;
  char cVar9;
  int iVar10;
  uint auStack88 [2];
  char *pcStack80;
  char acStack76 [8];
  undefined *local_44;
  uint local_40;
  char *local_3c;
  int local_38;
  uint local_34;
  char *local_30;
  char local_2c [4];
  undefined4 local_28;
  int local_24;
  undefined4 local_20;
  
  local_44 = &stack0xffffffa4;
  if ((__CRT_glob & 2) == 0) {
    iVar1 = __mingw32_init_mainargs();
    return iVar1;
  }
  _Str = _GetCommandLineA_0();
  _strlen(_Str);
  iVar1 = ___chkstk_ms();
  iVar1 = -iVar1;
  local_20 = 0;
  iVar10 = (int)*_Str;
  pcVar5 = acStack76 + iVar1;
  local_3c = pcVar5;
  local_40 = __CRT_glob & 0x4400 | 0x10;
  local_30 = _Str + 1;
  if (iVar10 != 0) {
    local_38 = 0;
    uVar7 = 0;
    local_34 = 0;
    do {
      cVar9 = (char)iVar10;
      if (cVar9 < '@') {
        if (cVar9 < '\"') {
switchD_004017e8_caseD_2:
          pcVar8 = pcVar5 + uVar7;
          pcVar4 = pcVar5;
          if (uVar7 != 0) {
            do {
              pcVar2 = pcVar5 + 1;
              *pcVar5 = '\\';
              pcVar5 = pcVar2;
              pcVar4 = pcVar8;
            } while (pcVar2 != pcVar8);
          }
          pcVar5 = pcVar4;
          if (local_34 != 0) goto LAB_00401668;
          if (*(int *)__mb_cur_max_exref == 1) {
            if ((*(byte *)(*(int *)_pctype_exref + iVar10 * 2) & 0x40) == 0) {
LAB_00401658:
              if (iVar10 != 9) goto LAB_00401668;
            }
          }
          else {
            *(uint *)((int)auStack88 + iVar1) = 0x40;
            *(int *)(&stack0xffffffa4 + iVar1) = iVar10;
            *(undefined4 *)(&stack0xffffffa0 + iVar1) = 0x401650;
            iVar3 = __isctype(*(int *)(&stack0xffffffa4 + iVar1),*(uint *)((int)auStack88 + iVar1));
            if (iVar3 == 0) goto LAB_00401658;
          }
          if ((local_3c < pcVar5) || (local_38 != 0)) {
            *pcVar5 = '\0';
            *(char **)((int)&pcStack80 + iVar1) = local_2c;
            *(undefined4 *)((int)auStack88 + iVar1 + 4) = 0;
            uVar7 = local_40;
            *(uint *)((int)auStack88 + iVar1) = local_40;
            pcVar5 = local_3c;
            *(char **)(&stack0xffffffa4 + iVar1) = local_3c;
            *(undefined4 *)(&stack0xffffffa0 + iVar1) = 0x4016c7;
            ___mingw_glob(*(char **)(&stack0xffffffa4 + iVar1),*(uint *)((int)auStack88 + iVar1),
                          *(undefined4 *)((int)auStack88 + iVar1 + 4),
                          *(char ***)((int)&pcStack80 + iVar1));
            local_40 = uVar7 | 1;
            uVar7 = 0;
            local_38 = 0;
          }
          else {
            local_38 = 0;
            uVar7 = 0;
          }
        }
        else {
          iVar3 = (int)uVar7 >> 1;
          switch(iVar10 - 0x22U & 0xff) {
          case 0:
            if (iVar3 != 0) {
              pcVar4 = pcVar5 + iVar3;
              pcVar8 = pcVar5;
              do {
                pcVar2 = pcVar8 + 1;
                *pcVar8 = '\\';
                pcVar8 = pcVar2;
                pcVar5 = pcVar4;
              } while (pcVar2 != pcVar4);
            }
            if ((local_34 == 0x27) || ((uVar7 & 1) != 0)) {
              *pcVar5 = '\"';
              pcVar5 = pcVar5 + 1;
              uVar7 = 0;
              local_38 = 1;
            }
            else {
              local_34 = local_34 ^ 0x22;
              uVar7 = 0;
              local_38 = 1;
            }
            break;
          default:
            goto switchD_004017e8_caseD_2;
          case 5:
            if ((__CRT_glob & 0x10) == 0) goto switchD_004017e8_caseD_2;
            if (iVar3 != 0) {
              pcVar4 = pcVar5 + iVar3;
              pcVar8 = pcVar5;
              do {
                pcVar2 = pcVar8 + 1;
                *pcVar8 = '\\';
                pcVar8 = pcVar2;
                pcVar5 = pcVar4;
              } while (pcVar2 != pcVar4);
            }
            if ((local_34 == 0x22) || ((uVar7 & 1) != 0)) {
              *pcVar5 = '\'';
              pcVar5 = pcVar5 + 1;
              uVar7 = 0;
              local_38 = 1;
            }
            else {
              local_34 = local_34 ^ 0x27;
              uVar7 = 0;
              local_38 = 1;
            }
            break;
          case 8:
          case 10:
          case 0x1d:
            goto LAB_004016f9;
          }
        }
      }
      else {
        if (cVar9 < '[') goto switchD_004017e8_caseD_2;
        switch(iVar10 - 0x5bU & 0xff) {
        case 0:
          if ((__CRT_glob & 0x20) != 0) goto LAB_004016f9;
          bVar6 = true;
          if (uVar7 != 0) goto LAB_00401713;
LAB_00401735:
          *pcVar5 = '\x7f';
          pcVar5 = pcVar5 + 1;
          break;
        case 1:
          if (local_34 == 0x27) {
            *pcVar5 = '\\';
            pcVar5 = pcVar5 + 1;
          }
          else {
            uVar7 = uVar7 + 1;
          }
          goto LAB_0040166f;
        default:
          goto switchD_004017e8_caseD_2;
        case 0x20:
        case 0x22:
        case 0x24:
LAB_004016f9:
          bVar6 = local_34 != 0 || iVar10 == 0x7f;
          if (uVar7 != 0) {
LAB_00401713:
            pcVar8 = pcVar5 + uVar7;
            pcVar4 = pcVar5;
            do {
              pcVar2 = pcVar4 + 1;
              *pcVar4 = '\\';
              pcVar4 = pcVar2;
              pcVar5 = pcVar8;
            } while (pcVar2 != pcVar8);
          }
          if (bVar6) goto LAB_00401735;
        }
LAB_00401668:
        *pcVar5 = cVar9;
        pcVar5 = pcVar5 + 1;
        uVar7 = 0;
      }
LAB_0040166f:
      pcVar8 = local_30;
      local_30 = local_30 + 1;
      iVar10 = (int)*pcVar8;
    } while (iVar10 != 0);
    pcVar8 = pcVar5;
    if (uVar7 != 0) {
      pcVar8 = pcVar5 + uVar7;
      do {
        pcVar4 = pcVar5 + 1;
        *pcVar5 = '\\';
        pcVar5 = pcVar4;
      } while (pcVar4 != pcVar8);
    }
    if ((local_3c < pcVar8) || (local_38 != 0)) {
      *pcVar8 = '\0';
      *(char **)((int)&pcStack80 + iVar1) = local_2c;
      *(undefined4 *)((int)auStack88 + iVar1 + 4) = 0;
      *(uint *)((int)auStack88 + iVar1) = local_40;
      *(char **)(&stack0xffffffa4 + iVar1) = local_3c;
      *(undefined4 *)(&stack0xffffffa0 + iVar1) = 0x401620;
      ___mingw_glob(*(char **)(&stack0xffffffa4 + iVar1),*(uint *)((int)auStack88 + iVar1),
                    *(undefined4 *)((int)auStack88 + iVar1 + 4),*(char ***)((int)&pcStack80 + iVar1)
                   );
    }
  }
  DAT_00407000 = local_24;
  __argc = local_28;
  return local_24;
}




void ___cpu_features_init(void)

{
  int *piVar1;
  int iVar2;
  uint *puVar3;
  uint uVar4;
  uint uVar5;
  byte in_VIP;
  byte in_ID;
  undefined in_XMM2 [16];
  int local_148;
  
  uVar4 = (uint)(in_ID & 1) * 0x200000 | (uint)(in_VIP & 1) * 0x100000;
  if (((((uint)(((uVar4 ^ 0x200000) & 0x200000) != 0) * 0x200000 ^ uVar4) & 0x200000) != 0) &&
     (piVar1 = (int *)cpuid_basic_info(0), *piVar1 != 0)) {
    iVar2 = cpuid_Version_info(1);
    uVar5 = *(uint *)(iVar2 + 8);
    uVar4 = (uint)((uVar5 & 0x100) != 0);
    if ((*(uint *)(iVar2 + 0xc) & 0x2000) != 0) {
      uVar4 = uVar4 | 0x80;
    }
    if ((uVar5 & 0x8000) != 0) {
      uVar4 = uVar4 | 2;
    }
    if ((uVar5 & 0x800000) != 0) {
      uVar4 = uVar4 | 4;
    }
    ____cpu_features = uVar4;
    if ((uVar5 & 0x1000000) != 0) {
      ____cpu_features = uVar4 | 8;
      local_148 = SUB164(in_XMM2 >> 0x40,0);
      if (local_148 == 0) {
        if ((uVar5 & 0x2000000) != 0) {
          ____cpu_features = uVar4 | 0x18;
        }
        if ((uVar5 & 0x4000000) != 0) {
          ____cpu_features = ____cpu_features | 0x20;
        }
        if ((*(uint *)(iVar2 + 0xc) & 1) != 0) {
          ____cpu_features = ____cpu_features | 0x40;
        }
      }
    }
    puVar3 = (uint *)cpuid(0x80000000);
    if (0x80000000 < *puVar3) {
      iVar2 = cpuid(0x80000001);
      uVar4 = 0;
      if ((int)*(uint *)(iVar2 + 8) < 0) {
        uVar4 = 0x100;
      }
      if ((*(uint *)(iVar2 + 8) & 0x40000000) != 0) {
        uVar4 = uVar4 | 0x200;
      }
      ____cpu_features = ____cpu_features | uVar4;
    }
  }
  return;
}



void ___main(void)

{
  int iVar1;
  int iVar2;
  
  if (_bss != 0) {
    return;
  }
  _bss = 1;
  iVar1 = 0;
  do {
    iVar2 = iVar1;
    iVar1 = iVar2 + 1;
  } while ((&___CTOR_LIST__)[iVar2 + 1] != 0);
  while (iVar2 != 0) {
    (*(code *)(&___CTOR_LIST__)[iVar2])();
    iVar2 = iVar2 + -1;
  }
  _atexit(&___do_global_dtors);
  return;
}



undefined4 tls_callback_1(undefined4 param_1,int param_2)

{
  if ((param_2 != 3) && (param_2 != 0)) {
    return 1;
  }
  ___mingw_TLScallback(param_1,param_2);
  return 1;
}




undefined4 ___dyn_tls_init_12(undefined4 param_1,int param_2)

{
  if (___CRT_MT != 2) {
    ___CRT_MT = 2;
  }
  if ((param_2 != 2) && (param_2 == 1)) {
    ___mingw_TLScallback(param_1,1);
    return 1;
  }
  return 1;
}



void _text(void)

{
  DWORD *pDVar1;
  LPVOID pvVar2;
  DWORD DVar3;
  
  _EnterCriticalSection_4((LPCRITICAL_SECTION)&DAT_00407044);
  pDVar1 = _bss;
  while (pDVar1 != (DWORD *)0x0) {
    pvVar2 = _TlsGetValue_4(*pDVar1);
    DVar3 = _GetLastError_0();
    if ((DVar3 == 0) && (pvVar2 != (LPVOID)0x0)) {
      (*(code *)pDVar1[1])(pvVar2);
    }
    pDVar1 = (DWORD *)pDVar1[2];
  }
  _LeaveCriticalSection_4((LPCRITICAL_SECTION)&DAT_00407044);
  return;
}



undefined4 __cdecl ___mingw_TLScallback(undefined4 param_1,int param_2)

{
  if (param_2 == 1) {
    if (DAT_00407040 == 0) {
      _InitializeCriticalSection_4((LPCRITICAL_SECTION)&DAT_00407044);
    }
    DAT_00407040 = 1;
    return 1;
  }
  if (param_2 == 3) {
    if (DAT_00407040 != 0) {
      _text();
      return 1;
    }
  }
  else {
    if (((param_2 == 0) && (DAT_00407040 != 0)) && (_text(), DAT_00407040 == 1)) {
      DAT_00407040 = 0;
      _DeleteCriticalSection_4((LPCRITICAL_SECTION)&DAT_00407044);
    }
  }
  return 1;
}




uint _text(char *param_1)

{
  FILE *_File;
  LPCVOID lpAddress;
  SIZE_T SVar1;
  uint uVar2;
  uint extraout_ECX;
  int extraout_EDX;
  uint uVar3;
  DWORD in_stack_ffffffa8;
  LPVOID in_stack_ffffffac;
  SIZE_T in_stack_ffffffb8;
  uint in_stack_ffffffc0;
  
  _File = (FILE *)(_iob_exref + 0x40);
  _fwrite("Mingw runtime failure:\n",1,0x17,_File);
  _vfprintf(_File,param_1,&stack0x00000008);
  _abort();
  SVar1 = _VirtualQuery_12(lpAddress,(PMEMORY_BASIC_INFORMATION)&stack0xffffffac,0x1c);
  if (SVar1 == 0) {
    _text("  VirtualQuery failed for %d bytes at address %p");
    uVar2 = _bss;
    if (_bss == 0) {
      _bss = 1;
      uVar2 = 0;
    }
    return uVar2;
  }
  if ((in_stack_ffffffc0 == 0x40) || (in_stack_ffffffc0 == 4)) {
    if (extraout_ECX != 0) {
      in_stack_ffffffc0 = 0;
      do {
        *(undefined *)((int)lpAddress + in_stack_ffffffc0) =
             *(undefined *)(extraout_EDX + in_stack_ffffffc0);
        in_stack_ffffffc0 = in_stack_ffffffc0 + 1;
      } while (in_stack_ffffffc0 < extraout_ECX);
    }
  }
  else {
    uVar2 = in_stack_ffffffc0;
    in_stack_ffffffc0 =
         _VirtualProtect_16(in_stack_ffffffac,in_stack_ffffffb8,0x40,(PDWORD)&stack0xffffffa8);
    if (extraout_ECX != 0) {
      uVar3 = 0;
      do {
        in_stack_ffffffc0 = (uint)*(byte *)(extraout_EDX + uVar3);
        *(byte *)((int)lpAddress + uVar3) = *(byte *)(extraout_EDX + uVar3);
        uVar3 = uVar3 + 1;
      } while (uVar3 < extraout_ECX);
    }
    if ((uVar2 != 0x40) && (uVar2 != 4)) {
      uVar2 = _VirtualProtect_16(in_stack_ffffffac,in_stack_ffffffb8,in_stack_ffffffa8,
                                 (PDWORD)&stack0xffffffa8);
      return uVar2;
    }
  }
  return in_stack_ffffffc0;
}




uint __fastcall Funcao_1de0(uint param_1,int param_2)

{
  LPCVOID in_EAX;
  SIZE_T SVar1;
  uint uVar2;
  BOOL BVar3;
  int iVar4;
  uint uVar5;
  DWORD local_3c;
  _MEMORY_BASIC_INFORMATION local_38;
  
  SVar1 = _VirtualQuery_12(in_EAX,(PMEMORY_BASIC_INFORMATION)&local_38,0x1c);
  if (SVar1 == 0) {
    _text("  VirtualQuery failed for %d bytes at address %p");
    iVar4 = _bss;
    if (_bss == 0) {
      _bss = 1;
      iVar4 = 0;
    }
    return iVar4;
  }
  if ((local_38.Protect == 0x40) || (local_38.Protect == 4)) {
    uVar2 = local_38.Protect;
    if (param_1 != 0) {
      uVar2 = 0;
      do {
        *(undefined *)((int)in_EAX + uVar2) = *(undefined *)(param_2 + uVar2);
        uVar2 = uVar2 + 1;
      } while (uVar2 < param_1);
    }
  }
  else {
    uVar2 = _VirtualProtect_16(local_38.BaseAddress,local_38.RegionSize,0x40,&local_3c);
    if (param_1 != 0) {
      uVar5 = 0;
      do {
        uVar2 = (uint)*(byte *)(param_2 + uVar5);
        *(byte *)((int)in_EAX + uVar5) = *(byte *)(param_2 + uVar5);
        uVar5 = uVar5 + 1;
      } while (uVar5 < param_1);
    }
    if ((local_38.Protect != 0x40) && (local_38.Protect != 4)) {
      BVar3 = _VirtualProtect_16(local_38.BaseAddress,local_38.RegionSize,local_3c,&local_3c);
      return BVar3;
    }
  }
  return uVar2;
}




int __pei386_runtime_relocator(void)

{
  int iVar1;
  
  iVar1 = _bss;
  if (_bss == 0) {
    _bss = 1;
    iVar1 = 0;
  }
  return iVar1;
}



undefined4 __cdecl _fesetenv(int param_1)

{
  if (param_1 == -3) {
    _data = -1;
  }
  else {
    if (param_1 == -4) {
      _data = -2;
    }
    else {
      if (param_1 == 0) {
        param_1 = _data;
      }
      if (param_1 == -1) {
        return 0;
      }
      if (param_1 != -2) {
        return 0;
      }
    }
    _fpreset();
  }
  return 0;
}



void __cdecl ___mingw_free(undefined4 *param_1)

{
  undefined4 *_Memory;
  undefined4 local_1c [7];
  
  _Memory = ___mingw_memalign_base(param_1,local_1c);
  free(_Memory);
  return;
}



char * __fastcall _text(uint param_1,uint param_2)

{
  byte bVar1;
  char *in_EAX;
  uint uVar2;
  int iVar3;
  int iVar4;
  char *pcVar5;
  char *pcVar6;
  char cVar7;
  char *pcVar8;
  uint uVar9;
  uint _C;
  uint _C_00;
  bool bVar10;
  
  _C = SEXT14(*in_EAX);
  if ((_C == 0x2d) || (uVar9 = _C, _C == 0x5d)) {
    cVar7 = in_EAX[1];
    in_EAX = in_EAX + 1;
    if (_C == param_2) {
      do {
        pcVar6 = in_EAX + 1;
        if (cVar7 == ']') {
          return pcVar6;
        }
        pcVar5 = in_EAX;
        if (cVar7 == '\x7f') goto LAB_00402457;
        while( true ) {
          do {
            pcVar5 = pcVar6;
            if (cVar7 == '\0') {
              return (char *)0;
            }
            cVar7 = in_EAX[1];
            pcVar6 = pcVar5 + 1;
            if (cVar7 == ']') {
              return pcVar6;
            }
            in_EAX = pcVar5;
          } while (cVar7 != '\x7f');
LAB_00402457:
          cVar7 = pcVar5[1];
          in_EAX = pcVar6;
          if ((param_1 & 0x20) != 0) break;
          pcVar6 = pcVar5 + 2;
        }
      } while( true );
    }
    uVar9 = SEXT14(cVar7);
  }
  uVar2 = param_1 & 0x4000;
LAB_004021ba:
  do {
    pcVar6 = in_EAX + 1;
    if (uVar9 == 0x5d) {
      return (char *)0;
    }
    if (uVar9 == 0x2d) {
      cVar7 = in_EAX[1];
      if (cVar7 != ']') {
        uVar9 = SEXT14(cVar7);
        if (uVar9 == 0) {
          return (char *)0;
        }
        pcVar6 = in_EAX + 2;
        _C_00 = _C;
        while ((int)_C_00 < (int)uVar9) {
          if (uVar2 == 0) {
            iVar3 = _tolower(_C_00);
            iVar4 = _tolower(param_2);
            _C_00 = _C_00 + 1;
            if (iVar3 == iVar4) goto LAB_00402304;
          }
          else {
            bVar10 = _C_00 == param_2;
            _C_00 = _C_00 + 1;
            if (bVar10) {
LAB_00402304:
              cVar7 = in_EAX[2];
              do {
                pcVar5 = pcVar6 + 1;
                if (cVar7 == ']') {
                  return pcVar5;
                }
                pcVar8 = pcVar6;
                if (cVar7 == '\x7f') goto LAB_00402347;
                while( true ) {
                  do {
                    pcVar8 = pcVar5;
                    if (cVar7 == '\0') {
                      return (char *)0;
                    }
                    cVar7 = pcVar6[1];
                    pcVar5 = pcVar8 + 1;
                    if (cVar7 == ']') {
                      return pcVar5;
                    }
                    pcVar6 = pcVar8;
                  } while (cVar7 != '\x7f');
LAB_00402347:
                  cVar7 = pcVar8[1];
                  pcVar6 = pcVar5;
                  if ((param_1 & 0x20) != 0) break;
                  pcVar5 = pcVar8 + 2;
                }
              } while( true );
            }
          }
        }
        while (_C = uVar9, (int)uVar9 < (int)_C_00) {
          if (uVar2 == 0) {
            iVar3 = _tolower(_C_00);
            iVar4 = _tolower(param_2);
            _C_00 = _C_00 - 1;
            if (iVar3 == iVar4) goto LAB_004023b8;
          }
          else {
            bVar10 = _C_00 == param_2;
            _C_00 = _C_00 - 1;
            if (bVar10) {
LAB_004023b8:
              cVar7 = in_EAX[2];
              do {
                pcVar5 = pcVar6 + 1;
                if (cVar7 == ']') {
                  return pcVar5;
                }
                pcVar8 = pcVar6;
                if (cVar7 == '\x7f') goto LAB_004023fb;
                while( true ) {
                  do {
                    pcVar8 = pcVar5;
                    if (cVar7 == '\0') {
                      return (char *)0;
                    }
                    cVar7 = pcVar6[1];
                    pcVar5 = pcVar8 + 1;
                    if (cVar7 == ']') {
                      return pcVar5;
                    }
                    pcVar6 = pcVar8;
                  } while (cVar7 != '\x7f');
LAB_004023fb:
                  cVar7 = pcVar8[1];
                  pcVar6 = pcVar5;
                  if ((param_1 & 0x20) != 0) break;
                  pcVar5 = pcVar8 + 2;
                }
              } while( true );
            }
          }
        }
        goto LAB_004021d9;
      }
      _C = 0x2d;
    }
    else {
      _C = uVar9;
      if (uVar9 == 0) {
        return (char *)0;
      }
LAB_004021d9:
      if (_C == 0x2f) {
        return (char *)0;
      }
      if (_C == 0x5c) {
        return (char *)0;
      }
      cVar7 = *pcVar6;
    }
    uVar9 = SEXT14(cVar7);
    in_EAX = pcVar6;
    if (uVar2 != 0) {
      if (_C == param_2) goto LAB_0040221e;
      goto LAB_004021ba;
    }
    iVar3 = _tolower(_C);
    iVar4 = _tolower(param_2);
    if (iVar3 == iVar4) {
LAB_0040221e:
      do {
        pcVar5 = pcVar6 + 1;
        if ((char)uVar9 == ']') {
          return pcVar5;
        }
        pcVar8 = pcVar6;
        if ((char)uVar9 == '\x7f') goto LAB_0040224d;
        while( true ) {
          do {
            pcVar8 = pcVar5;
            if ((char)uVar9 == '\0') {
              return (char *)0;
            }
            bVar1 = pcVar6[1];
            uVar9 = (uint)bVar1;
            pcVar5 = pcVar8 + 1;
            if (bVar1 == 0x5d) {
              return pcVar5;
            }
            pcVar6 = pcVar8;
          } while (bVar1 != 0x7f);
LAB_0040224d:
          uVar9 = (uint)(byte)pcVar8[1];
          pcVar6 = pcVar5;
          if ((param_1 & 0x20) != 0) break;
          pcVar5 = pcVar8 + 2;
        }
      } while( true );
    }
  } while( true );
}



uint __fastcall Funcao_24a0(uint param_1,char *param_2)

{
  char cVar1;
  byte bVar2;
  byte *in_EAX;
  int _C;
  int iVar3;
  int iVar4;
  uint uVar5;
  uint _C_00;
  byte *pbVar6;
  byte *pbVar7;
  byte *pbVar8;
  char *pcVar9;
  
  cVar1 = *param_2;
  uVar5 = SEXT14((char)*in_EAX);
  if (cVar1 == '.') {
    if (*in_EAX != 0x2e) {
      if ((param_1 & 0x10000) == 0) {
        return uVar5 - 0x2e;
      }
      goto LAB_004024be;
    }
  }
  else {
LAB_004024be:
    if (uVar5 == 0) goto LAB_004025c2;
  }
  pbVar6 = in_EAX + 1;
  _C_00 = uVar5;
  do {
    pcVar9 = param_2;
    cVar1 = (char)uVar5;
    if (cVar1 == '?') {
      if (*pcVar9 == '\0') {
        return 0x3f;
      }
LAB_004025d9:
      uVar5 = (uint)*pbVar6;
      pbVar7 = pbVar6;
    }
    else {
      if (cVar1 != '[') {
        if (cVar1 == '*') {
          while (*pbVar6 == 0x2a) {
            pbVar6 = pbVar6 + 1;
          }
          if (*pbVar6 == 0) {
            return 0;
          }
          do {
            _C = Funcao_24a0();
            if (_C == 0) {
              return 0;
            }
            cVar1 = *pcVar9;
            pcVar9 = pcVar9 + 1;
          } while (cVar1 != '\0');
          return _C;
        }
        if ((((param_1 & 0x20) == 0) && (_C_00 == 0x7f)) &&
           (_C_00 = SEXT14((char)in_EAX[1]), _C_00 != 0)) {
          pbVar6 = in_EAX + 2;
        }
        _C = (int)*pcVar9;
        if (*pcVar9 == '\0') {
          return _C_00;
        }
        if ((param_1 & 0x4000) == 0) {
          iVar3 = _tolower(_C_00);
          iVar4 = _tolower(_C);
          iVar3 = iVar3 - iVar4;
        }
        else {
          iVar3 = _C_00 - _C;
        }
        if (iVar3 != 0) {
          return _C_00 - _C;
        }
        goto LAB_004025d9;
      }
      if (*pcVar9 == '\0') {
        return 0x5b;
      }
      if (in_EAX[1] == 0x21) {
        pbVar7 = in_EAX + 2;
        _C = _text();
        uVar5 = (uint)in_EAX[2];
        if (_C == 0) {
          if (in_EAX[2] == 0x5d) {
            uVar5 = (uint)in_EAX[3];
            pbVar7 = in_EAX + 3;
          }
LAB_00402668:
          pbVar6 = pbVar7 + 1;
          pbVar8 = pbVar7;
          pbVar7 = pbVar6;
          if ((char)uVar5 != ']') {
            do {
              bVar2 = (byte)uVar5;
              pbVar6 = pbVar8;
              if (bVar2 == 0x7f) {
                bVar2 = pbVar8[1];
                uVar5 = (uint)bVar2;
                if ((param_1 & 0x20) != 0) goto LAB_00402668;
                pbVar6 = pbVar7;
                pbVar7 = pbVar8 + 2;
              }
              pbVar8 = pbVar7;
              if (bVar2 == 0) {
                return 0x5d;
              }
              uVar5 = (uint)pbVar6[1];
              pbVar7 = pbVar8 + 1;
              if (pbVar6[1] == 0x5d) break;
            } while( true );
          }
          uVar5 = (uint)pbVar8[1];
        }
      }
      else {
        pbVar7 = (byte *)_text();
        if (pbVar7 == (byte *)0x0) {
          return 0x5d;
        }
        uVar5 = (uint)*pbVar7;
      }
    }
    _C_00 = SEXT14((char)uVar5);
    pbVar6 = pbVar7 + 1;
    in_EAX = pbVar7;
    param_2 = pcVar9 + 1;
  } while (_C_00 != 0);
  cVar1 = pcVar9[1];
LAB_004025c2:
  return -(int)cVar1;
}




undefined4 __fastcall Funcao_26d0(undefined4 param_1,uint param_2)

{
  char *pcVar1;
  char cVar2;
  char *in_EAX;
  char *pcVar3;
  uint uVar4;
  
  cVar2 = *in_EAX;
  if (cVar2 == '\0') {
    return 0;
  }
  uVar4 = 0;
  pcVar1 = in_EAX + 1;
  do {
    while ((pcVar3 = pcVar1, cVar2 != '\x7f' || ((((byte)(param_2 >> 5) ^ 1) & 1) == 0))) {
      if (uVar4 == 0) {
        if (cVar2 == '*') {
          return 1;
        }
        if (cVar2 == '?') {
          return 1;
        }
        goto LAB_004026fa;
      }
      if ((1 < (int)uVar4) && (cVar2 == ']')) {
        return 1;
      }
      if (cVar2 != '!') goto LAB_00402731;
LAB_00402707:
      cVar2 = *pcVar3;
      pcVar1 = pcVar3 + 1;
      in_EAX = pcVar3;
      if (cVar2 == '\0') {
        return 0;
      }
    }
    pcVar3 = in_EAX + 2;
    if (in_EAX[1] == '\0') {
      return 0;
    }
    if (uVar4 == 0) {
LAB_004026fa:
      uVar4 = (uint)(cVar2 == '[');
      goto LAB_00402707;
    }
LAB_00402731:
    uVar4 = uVar4 + 1;
    cVar2 = *pcVar3;
    pcVar1 = pcVar3 + 1;
    in_EAX = pcVar3;
    if (cVar2 == '\0') {
      return 0;
    }
  } while( true );
}



undefined4 __fastcall Funcao_2770(undefined4 param_1,int param_2)

{
  int iVar1;
  int iVar2;
  int iVar3;
  undefined4 in_EAX;
  void *pvVar4;
  
  pvVar4 = ___mingw_realloc(*(undefined4 **)(param_2 + 8),
                            (*(int *)(param_2 + 0xc) + *(int *)(param_2 + 4)) * 4 + 8);
  if (pvVar4 != (void *)0x0) {
    iVar2 = *(int *)(param_2 + 4);
    iVar3 = *(int *)(param_2 + 0xc);
    *(void **)(param_2 + 8) = pvVar4;
    iVar1 = iVar2 + 1;
    *(int *)(param_2 + 4) = iVar1;
    *(undefined4 *)((int)pvVar4 + (iVar2 + iVar3) * 4) = in_EAX;
    *(undefined4 *)((int)pvVar4 + (iVar3 + iVar1) * 4) = 0;
    return 0;
  }
  return 1;
}



void __fastcall Funcao_27d0(undefined4 param_1,int param_2)

{
  int *in_EAX;
  
  if (*in_EAX != 0) {
    Funcao_27d0();
  }
  if ((in_EAX[2] != 0) && (param_2 != 0)) {
    Funcao_2770();
  }
  if (in_EAX[1] != 0) {
    Funcao_27d0();
  }
  ___mingw_free(in_EAX);
  return;
}



undefined4 Funcao_2820(void)

{
  int in_EAX;
  void *pvVar1;
  undefined4 uVar2;
  int iVar3;
  
  iVar3 = *(int *)(in_EAX + 0xc) + 1;
  pvVar1 = _malloc(iVar3 * 4);
  *(void **)(in_EAX + 8) = pvVar1;
  if (pvVar1 == (void *)0x0) {
    uVar2 = 3;
  }
  else {
    *(undefined4 *)(in_EAX + 4) = 0;
    if (0 < iVar3) {
      do {
        iVar3 = iVar3 + -1;
        *(undefined4 *)((int)pvVar1 + iVar3 * 4) = 0;
      } while (iVar3 != 0);
    }
    uVar2 = 0;
  }
  return uVar2;
}




uint __fastcall Funcao_2870(code *param_1,uint param_2,int param_1_00)

{
  char *pcVar1;
  undefined4 uVar2;
  char cVar3;
  code *pcVar4;
  char cVar5;
  char *in_EAX;
  void *pvVar6;
  undefined4 *puVar7;
  int iVar8;
  char *pcVar9;
  char *pcVar10;
  size_t sVar11;
  char **ppcVar12;
  uint uVar13;
  int iVar14;
  int extraout_ECX;
  char *pcVar15;
  char cVar16;
  int *piVar17;
  char **ppcVar18;
  int **ppiVar19;
  char *pcVar20;
  undefined4 *puVar21;
  bool bVar22;
  undefined8 uVar23;
  char *pcStack120;
  size_t sStack116;
  char acStack112 [4];
  int local_6c;
  char local_65;
  int local_64;
  char *local_60;
  int *local_5c;
  undefined *local_58;
  undefined4 *local_54;
  size_t local_50;
  char *local_4c;
  char *local_48;
  undefined4 *local_44;
  char *local_40;
  code *local_3c;
  undefined4 *local_38;
  uint local_34;
  char *local_30;
  undefined local_2c [8];
  int *local_24;
  undefined4 local_20;
  
  local_40 = in_EAX;
  local_3c = param_1;
  local_34 = param_2;
  if ((param_2 & 0x400) != 0) {
    local_4c = &stack0xffffff84;
    _strlen(in_EAX);
    iVar14 = ___chkstk_ms();
    cVar16 = *in_EAX;
    iVar14 = -iVar14;
    pcVar9 = acStack112 + iVar14;
    local_48 = pcVar9;
LAB_004029ef:
    pcVar20 = in_EAX + 1;
    pcVar10 = pcVar20;
    if (cVar16 == '\x7f') goto LAB_00402a19;
    while (pcVar20 = in_EAX, in_EAX = pcVar10, cVar16 != '{') {
      while( true ) {
        *pcVar9 = cVar16;
        pcVar9 = pcVar9 + 1;
        if (cVar16 == '\0') goto LAB_0040288b;
        cVar16 = pcVar20[1];
        pcVar20 = in_EAX + 1;
        pcVar10 = pcVar20;
        if (cVar16 != '\x7f') break;
LAB_00402a19:
        cVar16 = in_EAX[1];
        *pcVar9 = '\x7f';
        if (cVar16 != '\0') {
          pcVar9[1] = cVar16;
          in_EAX = in_EAX + 2;
          cVar16 = *in_EAX;
          pcVar9 = pcVar9 + 2;
          goto LAB_004029ef;
        }
        in_EAX = in_EAX + 2;
        pcVar9 = pcVar9 + 1;
      }
    }
    cVar16 = pcVar20[1];
    local_44 = (undefined4 *)pcVar20;
    pcVar10 = pcVar20 + 1;
    iVar8 = 1;
    local_38 = (undefined4 *)0x2c;
    cVar3 = cVar16 + -0x7b;
    bVar22 = cVar16 == '{';
    pcVar15 = pcVar20;
    cVar5 = cVar16;
    if (bVar22) goto LAB_00402a8c;
    do {
      if (bVar22 || SBORROW1(cVar5,'{') != cVar3 < '\0') {
        if (cVar5 == '\0') goto LAB_00402b93;
        if ((cVar5 != ',') || (iVar8 != 1)) goto LAB_00402a7f;
        cVar5 = pcVar15[2];
        local_38 = (undefined4 *)0x7b;
      }
      else {
        if (cVar5 == '}') {
          iVar8 = iVar8 + -1;
          if (iVar8 == 0) goto code_r0x00402aad;
        }
        else {
          if (cVar5 == '\x7f') {
            cVar5 = pcVar15[2];
            if (cVar5 != '\0') {
              pcVar10 = pcVar15 + 2;
              cVar5 = pcVar15[3];
            }
            goto LAB_00402a85;
          }
        }
LAB_00402a7f:
        cVar5 = pcVar15[2];
      }
LAB_00402a85:
      while( true ) {
        pcVar1 = pcVar10 + 1;
        cVar3 = cVar5 + -0x7b;
        bVar22 = cVar3 == '\0';
        pcVar15 = pcVar10;
        pcVar10 = pcVar1;
        if (!bVar22) break;
LAB_00402a8c:
        cVar5 = pcVar15[2];
        iVar8 = iVar8 + 1;
      }
    } while( true );
  }
LAB_0040288b:
  pcVar9 = local_40;
  local_48 = &stack0xffffff84;
  _strlen(local_40);
  uVar23 = ___chkstk_ms();
  iVar14 = -(int)uVar23;
  ppcVar18 = (char **)(&stack0xffffff84 + iVar14);
  *(size_t *)((int)&sStack116 + iVar14) = (size_t)((ulonglong)uVar23 >> 0x20);
  *(char **)((int)&pcStack120 + iVar14) = pcVar9;
  *(char **)(&stack0xffffff84 + iVar14) = acStack112 + iVar14;
  *(undefined4 *)(&stack0xffffff80 + iVar14) = 0x4028c0;
  pvVar6 = _memcpy(*(void **)(&stack0xffffff84 + iVar14),*(char **)((int)&pcStack120 + iVar14),
                   *(size_t *)((int)&sStack116 + iVar14));
  *(void **)(&stack0xffffff84 + iVar14) = pvVar6;
  *(undefined4 *)(&stack0xffffff80 + iVar14) = 0x4028c8;
  puVar7 = ___mingw_dirname(*(undefined4 **)(&stack0xffffff84 + iVar14));
  local_20 = 0;
  local_44 = puVar7;
  *(undefined4 *)(&stack0xffffff80 + iVar14) = 0x4028dc;
  local_30 = (char *)Funcao_2820();
  if (local_30 != (char *)0x0) {
    return (int)local_30;
  }
  if (puVar7 == (undefined4 *)0x0) {
LAB_004028fd:
    puVar7 = local_44;
    *(undefined4 **)(&stack0xffffff84 + iVar14) = local_44;
    *(undefined4 *)(&stack0xffffff80 + iVar14) = 0x40290a;
    _strlen(*(char **)(&stack0xffffff84 + iVar14));
    *(undefined4 *)(&stack0xffffff80 + iVar14) = 0x402918;
    iVar8 = ___chkstk_ms();
    iVar8 = -iVar8;
    pcVar9 = &stack0xffffff84 + iVar8 + iVar14 + 0xc;
    pcVar20 = pcVar9;
    do {
      while( true ) {
        cVar16 = *(char *)puVar7;
        if (cVar16 != '\x7f') break;
        cVar16 = *(char *)((int)puVar7 + 1);
        *pcVar20 = cVar16;
        pcVar20 = pcVar20 + 1;
        puVar7 = (undefined4 *)((int)puVar7 + 2);
        if (cVar16 == '\0') goto LAB_0040294f;
      }
      *pcVar20 = cVar16;
      pcVar20 = pcVar20 + 1;
      puVar7 = (undefined4 *)((int)puVar7 + 1);
    } while (cVar16 != '\0');
LAB_0040294f:
    *(char **)(&stack0xffffff84 + iVar8 + iVar14) = pcVar9;
    *(undefined4 *)(&stack0xffffff84 + iVar8 + iVar14 + -4) = 0x402957;
    pcVar9 = _strdup(*(char **)(&stack0xffffff84 + iVar8 + iVar14));
    local_30 = (char *)0x1;
    if (pcVar9 == (char *)0x0) {
      return 1;
    }
    *(undefined4 *)(&stack0xffffff80 + iVar14) = 0x402970;
    local_30 = (char *)Funcao_2770();
  }
  else {
    *(undefined4 *)(&stack0xffffff80 + iVar14) = 0x4028f5;
    iVar8 = Funcao_26d0();
    if (iVar8 == 0) goto LAB_004028fd;
    *(undefined **)(&stack0xffffff84 + iVar14) = local_2c;
    *(undefined4 *)(&stack0xffffff80 + iVar14) = 0x402f0d;
    local_30 = (char *)Funcao_2870();
  }
  pcVar9 = local_40;
  if (local_30 != (char *)0x0) {
    return (int)local_30;
  }
  if ((((local_40[1] == '/') || (local_40[1] == '\\')) || (*(char *)local_44 != '.')) ||
     (*(char *)((int)local_44 + 1) != '\0')) {
    *(undefined4 **)(&stack0xffffff84 + iVar14) = local_44;
    *(undefined4 *)(&stack0xffffff80 + iVar14) = 0x402ccb;
    sVar11 = _strlen(*(char **)(&stack0xffffff84 + iVar14));
    pcVar9 = local_40 + sVar11;
    cVar16 = *pcVar9;
    if (local_40 < pcVar9) {
      do {
        if (cVar16 == '/') goto LAB_00402d00;
        if (cVar16 == '\\') break;
        pcVar9 = pcVar9 + -1;
        cVar16 = *pcVar9;
      } while (local_40 != pcVar9);
    }
    if ((cVar16 == '/') || (cVar16 == '\\')) {
LAB_00402d00:
      do {
        do {
          local_65 = cVar16;
          pcVar9 = pcVar9 + 1;
          cVar16 = *pcVar9;
        } while (cVar16 == '/');
      } while (cVar16 == '\\');
    }
    else {
      local_65 = '\\';
    }
  }
  else {
    if ((local_34 & 0x10) != 0) {
      *(undefined4 *)(&stack0xffffff80 + iVar14) = 0x403071;
      local_30 = (char *)Funcao_26d0();
      if (local_30 == (char *)0x0) {
        *(char **)(&stack0xffffff84 + iVar14) = pcVar9;
        *(undefined4 *)(&stack0xffffff80 + iVar14) = 0x40308a;
        _strlen(*(char **)(&stack0xffffff84 + iVar14));
        *(undefined4 *)(&stack0xffffff80 + iVar14) = 0x403098;
        iVar8 = ___chkstk_ms();
        iVar8 = -iVar8;
        pcVar20 = &stack0xffffff84 + iVar8 + iVar14 + 0xc;
        pcVar10 = pcVar20;
        do {
          cVar16 = *pcVar9;
          pcVar15 = pcVar9 + 1;
          if (cVar16 == '\x7f') {
            cVar16 = pcVar9[1];
            pcVar15 = pcVar9 + 2;
          }
          *pcVar10 = cVar16;
          pcVar9 = pcVar15;
          pcVar10 = pcVar10 + 1;
        } while (cVar16 != '\0');
        *(char **)(&stack0xffffff84 + iVar8 + iVar14) = pcVar20;
        *(undefined4 *)(&stack0xffffff84 + iVar8 + iVar14 + -4) = 0x402f43;
        pcVar9 = _strdup(*(char **)(&stack0xffffff84 + iVar8 + iVar14));
        ppiVar19 = (int **)(&stack0xffffff84 + iVar14);
        if ((pcVar9 != (char *)0x0) &&
           (ppiVar19 = (int **)(&stack0xffffff84 + iVar14), param_1_00 != 0)) {
          *(undefined4 *)(&stack0xffffff80 + iVar14) = 0x402f58;
          Funcao_2770();
          ppiVar19 = (int **)(&stack0xffffff84 + iVar14);
        }
        goto LAB_00402f5d;
      }
    }
    local_65 = '\\';
    local_44 = (undefined4 *)0x0;
    pcVar9 = local_40;
  }
  local_30 = (char *)0x2;
  iVar8 = *local_24;
  ppiVar19 = (int **)(&stack0xffffff84 + iVar14);
  if (iVar8 != 0) {
    local_4c = pcVar9;
    local_40 = (char *)(local_34 & 0x8000);
    piVar17 = local_24;
    do {
      if (local_30 == (char *)0x1) {
LAB_00402d68:
        local_30 = (char *)0x1;
      }
      else {
        *(int *)ppcVar18 = iVar8;
        ppcVar18[-1] = 0x402d94;
        local_38 = ___mingw_opendir(*ppcVar18);
        pcVar4 = local_3c;
        if (local_38 == (undefined4 *)0x0) {
          if ((local_34 & 4) != 0) goto LAB_00402d68;
          if (local_3c != (code *)0x0) {
            ppcVar18[-1] = 0x402d52;
            ppcVar12 = (char **)__errno(*(undefined *)(ppcVar18 + -1));
            ppcVar18[1] = *ppcVar12;
            *(int *)ppcVar18 = *piVar17;
            ppcVar18 = ppcVar18 + -1;
            ppcVar18 = ppcVar18 + -1;
            *ppcVar18 = 0x402d5f;
            iVar14 = (*pcVar4)();
            if (iVar14 != 0) goto LAB_00402d68;
          }
        }
        else {
          local_50 = 0;
          if (local_44 != (undefined4 *)0x0) {
            *(int *)ppcVar18 = *piVar17;
            ppcVar18[-1] = 0x402db3;
            local_50 = _strlen(*ppcVar18);
          }
          local_54 = (undefined4 *)0x0;
          local_64 = local_50 + 2;
          ppcVar12 = ppcVar18;
          while( true ) {
            ppcVar18 = ppcVar12;
            *(undefined4 **)ppcVar18 = local_38;
            ppcVar18[-1] = 0x402ddb;
            uVar13 = ___mingw_readdir((uint)*ppcVar18);
            if (uVar13 == 0) break;
            ppcVar12 = ppcVar18;
            if ((local_40 == (char *)0x0) || (*(int *)(uVar13 + 8) == 0x10)) {
              ppcVar18[-1] = 0x402e02;
              iVar14 = Funcao_24a0();
              if (iVar14 == 0) {
                local_58 = (undefined *)ppcVar18;
                ppcVar18[-1] = 0x402e1f;
                iVar14 = ___chkstk_ms();
                sVar11 = local_50;
                iVar14 = -iVar14;
                pcVar9 = (char *)((int)ppcVar18 + iVar14 + 0xc);
                local_5c = (int *)pcVar9;
                iVar8 = extraout_ECX;
                local_60 = pcVar9;
                if (local_50 != 0) {
                  iVar8 = *piVar17;
                  local_6c = extraout_ECX;
                  *(char **)((int)ppcVar18 + iVar14) = pcVar9;
                  *(size_t *)((int)ppcVar18 + iVar14 + 8) = sVar11;
                  *(int *)((int)ppcVar18 + iVar14 + 4) = iVar8;
                  *(undefined4 *)((int)ppcVar18 + iVar14 + -4) = 0x402f8f;
                  _memcpy(*(void **)((int)ppcVar18 + iVar14),*(void **)((int)ppcVar18 + iVar14 + 4),
                          *(size_t *)((int)ppcVar18 + iVar14 + 8));
                  cVar16 = *(char *)((int)ppcVar18 + sVar11 + iVar14 + 0xb);
                  iVar8 = local_6c;
                  if ((cVar16 == '/') || (cVar16 == '\\')) {
                    pcVar9 = local_60 + local_50;
                  }
                  else {
                    local_60[local_50] = local_65;
                    pcVar9 = local_60 + local_50 + 1;
                  }
                }
                *(int *)((int)ppcVar18 + iVar14 + 8) = iVar8 + 1;
                *(int *)((int)ppcVar18 + iVar14 + 4) = uVar13 + 0xc;
                *(char **)((int)ppcVar18 + iVar14) = pcVar9;
                *(undefined4 *)((int)ppcVar18 + iVar14 + -4) = 0x402e4d;
                _memcpy(*(void **)((int)ppcVar18 + iVar14),*(void **)((int)ppcVar18 + iVar14 + 4),
                        *(size_t *)((int)ppcVar18 + iVar14 + 8));
                *(char **)((int)ppcVar18 + iVar14) = local_60;
                *(undefined4 *)((int)ppcVar18 + iVar14 + -4) = 0x402e58;
                _strlen(*(char **)((int)ppcVar18 + iVar14));
                *(undefined4 *)((int)ppcVar18 + iVar14 + -4) = 0x402e66;
                iVar8 = ___chkstk_ms();
                iVar8 = -iVar8;
                local_60 = (char *)((int)ppcVar18 + iVar8 + iVar14 + 0xc);
                pcVar9 = local_60;
                pcVar20 = (char *)local_5c;
                do {
                  while( true ) {
                    cVar16 = *pcVar20;
                    if (cVar16 != '\x7f') break;
                    cVar16 = pcVar20[1];
                    *pcVar9 = cVar16;
                    pcVar9 = pcVar9 + 1;
                    pcVar20 = pcVar20 + 2;
                    if (cVar16 == '\0') goto LAB_00402ea7;
                  }
                  *pcVar9 = cVar16;
                  pcVar9 = pcVar9 + 1;
                  pcVar20 = pcVar20 + 1;
                } while (cVar16 != '\0');
LAB_00402ea7:
                *(char **)((int)ppcVar18 + iVar8 + iVar14) = local_60;
                *(undefined4 *)((int)ppcVar18 + iVar8 + iVar14 + -4) = 0x402eb2;
                pcVar9 = _strdup(*(char **)((int)ppcVar18 + iVar8 + iVar14));
                ppcVar12 = (char **)local_58;
                if (pcVar9 == (char *)0x0) {
                  local_30 = (char *)0x3;
                }
                else {
                  local_30 = (char *)((uint)local_30 & (uint)(local_30 == (char *)0x2) - 1);
                  if ((local_34 & 0x40) == 0) {
                    if (local_54 == (undefined4 *)0x0) {
                      *(uint *)((int)ppcVar18 + iVar14) = 0xc;
                      *(undefined4 *)((int)ppcVar18 + iVar14 + -4) = 0x4030d3;
                      local_54 = (undefined4 *)_malloc(*(uint *)((int)ppcVar18 + iVar14));
                      ppcVar12 = (char **)local_58;
                      if (local_54 != (undefined4 *)0x0) {
                        *(char **)(local_54 + 2) = pcVar9;
                        local_54[1] = 0;
                        *local_54 = 0;
                      }
                    }
                    else {
                      local_5c = piVar17;
                      uVar13 = local_34 & 0x4000;
                      puVar7 = local_54;
                      do {
                        puVar21 = puVar7;
                        uVar2 = puVar21[2];
                        *(char **)((int)ppcVar18 + iVar14) = pcVar9;
                        *(undefined4 *)((int)ppcVar18 + iVar14 + 4) = uVar2;
                        if (uVar13 == 0) {
                          *(undefined4 *)((int)ppcVar18 + iVar14 + -4) = 0x403009;
                          pcVar20 = (char *)_stricoll(*(char **)((int)ppcVar18 + iVar14),
                                                      *(char **)((int)ppcVar18 + iVar14 + 4));
                        }
                        else {
                          *(undefined4 *)((int)ppcVar18 + iVar14 + -4) = 0x402fe5;
                          pcVar20 = (char *)_strcoll(*(char **)((int)ppcVar18 + iVar14),
                                                     *(char **)((int)ppcVar18 + iVar14 + 4));
                        }
                        piVar17 = local_5c;
                        puVar7 = (undefined4 *)puVar21[1];
                        if ((int)pcVar20 < 1) {
                          puVar7 = (undefined4 *)*puVar21;
                        }
                      } while (puVar7 != (undefined4 *)0x0);
                      local_5c = (int *)pcVar20;
                      *(uint *)((int)ppcVar18 + iVar14) = 0xc;
                      *(undefined4 *)((int)ppcVar18 + iVar14 + -4) = 0x40301d;
                      puVar7 = (undefined4 *)_malloc(*(uint *)((int)ppcVar18 + iVar14));
                      ppcVar12 = (char **)local_58;
                      if (puVar7 != (undefined4 *)0x0) {
                        *(char **)(puVar7 + 2) = pcVar9;
                        puVar7[1] = 0;
                        *puVar7 = 0;
                        if ((int)local_5c < 1) {
                          *(undefined4 **)puVar21 = puVar7;
                        }
                        else {
                          *(undefined4 **)(puVar21 + 1) = puVar7;
                        }
                      }
                    }
                  }
                  else {
                    if (param_1_00 != 0) {
                      *(undefined4 *)((int)ppcVar18 + iVar14 + -4) = 0x40304e;
                      Funcao_2770();
                      ppcVar12 = (char **)local_58;
                    }
                  }
                }
              }
            }
          }
          *(undefined4 **)ppcVar18 = local_38;
          ppcVar18[-1] = 0x402f20;
          ___mingw_closedir((undefined4 *)*ppcVar18);
          if (local_54 != (undefined4 *)0x0) {
            ppcVar18[-1] = 0x402f36;
            Funcao_27d0();
          }
        }
      }
      iVar14 = *piVar17;
      piVar17 = piVar17 + 1;
      *(int *)ppcVar18 = iVar14;
      ((int *)ppcVar18)[-1] = 0x402d7c;
      ___mingw_free((undefined4 *)*ppcVar18);
      iVar8 = *piVar17;
      ppiVar19 = (int **)ppcVar18;
    } while (iVar8 != 0);
  }
LAB_00402f5d:
  *ppiVar19 = local_24;
  ppiVar19[-1] = 0x402f65;
  ___mingw_free(*ppiVar19);
  return (uint)local_30;
code_r0x00402aad:
  if (local_38 != (undefined4 *)0x7b) {
LAB_00402b93:
    local_30 = in_EAX;
    *pcVar9 = '{';
    pcVar9 = pcVar9 + 1;
    goto LAB_004029ef;
  }
  local_30 = pcVar9;
LAB_00402ac3:
  iVar8 = 1;
  pcVar9 = local_30;
  pcVar10 = local_30;
  if (cVar16 == '\x7f') goto LAB_00402b6c;
  do {
    pcVar20 = pcVar20 + 1;
    while( true ) {
      pcVar10 = pcVar20;
      if (cVar16 == '}') {
        iVar8 = iVar8 + -1;
        if (iVar8 == 0) goto LAB_00402c28;
        *pcVar9 = '}';
      }
      else {
        if ((cVar16 == ',') && (iVar8 == 1)) {
          iVar8 = 1;
          goto LAB_00402b00;
        }
        if (cVar16 == '{') {
          *pcVar9 = '{';
          iVar8 = iVar8 + 1;
        }
        else {
          *pcVar9 = cVar16;
          if (cVar16 == '\0') {
            return 1;
          }
        }
      }
      pcVar10 = pcVar9 + 1;
      cVar16 = pcVar20[1];
      pcVar9 = pcVar10;
      if (cVar16 != '\x7f') break;
LAB_00402b6c:
      cVar16 = pcVar20[2];
      *pcVar10 = '\x7f';
      pcVar9 = pcVar10 + 2;
      pcVar10[1] = cVar16;
      if (cVar16 == '\0') {
        pcVar10[2] = '\0';
        return 1;
      }
      cVar16 = pcVar20[3];
      pcVar20 = pcVar20 + 3;
    }
  } while( true );
  while (iVar8 = iVar8 + -1, iVar8 != 0) {
LAB_00402b00:
    cVar16 = pcVar10[1];
    pcVar10 = pcVar10 + 1;
    while (cVar16 == '\x7f') {
      if (pcVar10[1] == '\0') goto LAB_00402b2e;
      cVar16 = pcVar10[2];
      pcVar10 = pcVar10 + 2;
    }
    if (cVar16 == '{') {
      iVar8 = iVar8 + 1;
      goto LAB_00402b00;
    }
    if (cVar16 != '}') {
      if (cVar16 == '\0') {
LAB_00402b2e:
        *pcVar9 = '\0';
        return 1;
      }
      goto LAB_00402b00;
    }
  }
LAB_00402c28:
  do {
    cVar16 = pcVar10[1];
    *pcVar9 = cVar16;
    pcVar9 = pcVar9 + 1;
    pcVar10 = pcVar10 + 1;
  } while (cVar16 != '\0');
  *(int *)(&stack0xffffff84 + iVar14) = param_1_00;
  *(undefined4 *)(&stack0xffffff80 + iVar14) = 0x402c4e;
  iVar8 = Funcao_2870();
  if (iVar8 == 1) {
    return 1;
  }
  if (*pcVar20 != ',') {
    return iVar8;
  }
  cVar16 = pcVar20[1];
  goto LAB_00402ac3;
}




int __cdecl ___mingw_glob(char *param_1,uint param_2,undefined4 param_3,char **param_4)

{
  char cVar1;
  undefined *puVar2;
  int iVar3;
  char *pcVar4;
  char acStack56 [16];
  int local_28;
  char *local_24;
  undefined *local_20;
  
  local_20 = &stack0xffffffc4;
  if ((param_4 != (char **)0x0) && ((param_2 & 2) == 0)) {
    param_4[3] = (char *)0x0;
  }
  if (*param_4 != "glob-1.0-mingw32") {
    Funcao_2820();
    *param_4 = "glob-1.0-mingw32";
  }
  local_28 = Funcao_2870();
  if ((local_28 == 2) && ((param_2 & 0x10) != 0)) {
    _strlen(param_1);
    iVar3 = ___chkstk_ms();
    iVar3 = -iVar3;
    local_24 = acStack56 + iVar3;
    pcVar4 = acStack56 + iVar3;
    do {
      while( true ) {
        cVar1 = *param_1;
        if (cVar1 != '\x7f') break;
        cVar1 = param_1[1];
        *pcVar4 = cVar1;
        pcVar4 = pcVar4 + 1;
        param_1 = param_1 + 2;
        if (cVar1 == '\0') goto LAB_004031d7;
      }
      *pcVar4 = cVar1;
      pcVar4 = pcVar4 + 1;
      param_1 = param_1 + 1;
    } while (cVar1 != '\0');
LAB_004031d7:
    *(char **)(&stack0xffffffc4 + iVar3) = local_24;
    *(undefined4 *)(&stack0xffffffc0 + iVar3) = 0x4031e5;
    pcVar4 = _strdup(*(char **)(&stack0xffffffc4 + iVar3));
    puVar2 = local_20;
    if (pcVar4 != (char *)0x0) {
      local_20 = (undefined *)local_28;
      *(undefined4 *)(puVar2 + -4) = 0x4031fd;
      Funcao_2770();
      local_28 = (int)local_20;
    }
  }
  return local_28;
}




undefined4 * __cdecl ___mingw_dirname(undefined4 *param_1)

{
  short *psVar1;
  size_t *psVar2;
  int iVar3;
  size_t sVar4;
  size_t *psVar5;
  size_t *psVar6;
  size_t *psVar7;
  short sVar8;
  short sVar9;
  size_t *_Src;
  bool bVar10;
  undefined8 uVar11;
  undefined4 uStack48;
  size_t local_2c;
  undefined *local_28;
  short local_22;
  size_t *local_20;
  
  _Src = (size_t *)_setlocale(2,(char *)0x0);
  if (_Src != (size_t *)0x0) {
    _Src = (size_t *)_strdup((char *)_Src);
  }
  _setlocale(2,"");
  if ((param_1 == (undefined4 *)0x0) || (*(char *)param_1 == '\0')) {
LAB_004032c0:
    sVar4 = _wcstombs((char *)0x0,L".",0);
    _bss = (undefined4 *)___mingw_realloc(_bss,sVar4 + 1);
    _wcstombs((char *)_bss,L".",sVar4 + 1);
    _setlocale(2,(char *)_Src);
    ___mingw_free(_Src);
    return _bss;
  }
  local_28 = &stack0xffffffc4;
  _mbstowcs((wchar_t *)0x0,(char *)param_1,0);
  uVar11 = ___chkstk_ms();
  iVar3 = -(int)uVar11;
  *(int *)(&stack0xffffffcc + iVar3) = (int)((ulonglong)uVar11 >> 0x20);
  psVar2 = (size_t *)((int)&uStack48 + iVar3);
  *(size_t **)(&stack0xffffffc4 + iVar3) = psVar2;
  *(undefined4 **)(&stack0xffffffc8 + iVar3) = param_1;
  *(undefined4 *)(&stack0xffffffc0 + iVar3) = 0x403380;
  sVar4 = _mbstowcs(*(wchar_t **)(&stack0xffffffc4 + iVar3),*(char **)(&stack0xffffffc8 + iVar3),
                    *(size_t *)(&stack0xffffffcc + iVar3));
  local_2c = sVar4;
  *(short *)((int)psVar2 + sVar4 * 2) = 0;
  local_22 = *(short *)psVar2;
  if (sVar4 < 2) {
    local_20 = psVar2;
  }
  else {
    sVar8 = *(short *)((int)&uStack48 + iVar3 + 2);
    local_20 = psVar2;
    if ((local_22 == 0x2f) || (local_22 == 0x5c)) {
      if ((local_22 == sVar8) && (*(short *)((int)&local_2c + iVar3) == 0)) {
        *(size_t **)(&stack0xffffffc8 + iVar3) = _Src;
        *(undefined4 *)(&stack0xffffffc4 + iVar3) = 2;
        *(undefined4 *)(&stack0xffffffc0 + iVar3) = 0x4035d5;
        _setlocale(*(int *)(&stack0xffffffc4 + iVar3),*(char **)(&stack0xffffffc8 + iVar3));
        *(size_t **)(&stack0xffffffc4 + iVar3) = _Src;
        *(undefined4 *)(&stack0xffffffc0 + iVar3) = 0x4035dd;
        ___mingw_free(*(undefined4 **)(&stack0xffffffc4 + iVar3));
        return param_1;
      }
    }
    else {
      if (sVar8 == 0x3a) {
        local_20 = (size_t *)((int)&local_2c + iVar3);
        local_22 = *(short *)((int)&local_2c + iVar3);
      }
    }
  }
  psVar5 = local_20;
  psVar6 = local_20;
  sVar8 = local_22;
  if (local_22 == 0) goto LAB_004032c0;
  do {
    if (sVar8 == 0x2f) {
      sVar8 = *(short *)psVar5;
      if (sVar8 != 0x2f) goto LAB_00403434;
      do {
        do {
          psVar5 = (size_t *)((int)psVar5 + 2);
LAB_0040342b:
          sVar8 = *(short *)psVar5;
        } while (sVar8 == 0x2f);
LAB_00403434:
      } while (sVar8 == 0x5c);
      psVar7 = psVar5;
      if (sVar8 == 0) break;
    }
    else {
      psVar7 = psVar6;
      if (sVar8 == 0x5c) goto LAB_0040342b;
    }
    psVar1 = (short *)((int)psVar5 + 2);
    psVar5 = (size_t *)((int)psVar5 + 2);
    psVar6 = psVar7;
    sVar8 = *psVar1;
  } while (*psVar1 != 0);
  if (psVar6 <= local_20) {
    if ((local_22 != 0x2f) && (local_22 != 0x5c)) {
      *(short *)local_20 = 0x2e;
    }
    *(short *)((int)local_20 + 2) = 0;
    *(undefined4 *)(&stack0xffffffcc + iVar3) = 0;
    *(size_t **)(&stack0xffffffc8 + iVar3) = psVar2;
    *(undefined4 *)(&stack0xffffffc4 + iVar3) = 0;
    *(undefined4 *)(&stack0xffffffc0 + iVar3) = 0x40348d;
    sVar4 = _wcstombs(*(char **)(&stack0xffffffc4 + iVar3),*(wchar_t **)(&stack0xffffffc8 + iVar3),
                      *(size_t *)(&stack0xffffffcc + iVar3));
    *(size_t **)(&stack0xffffffc8 + iVar3) = (size_t *)(sVar4 + 1);
    local_20 = (size_t *)(sVar4 + 1);
    *(undefined4 **)(&stack0xffffffc4 + iVar3) = _bss;
    *(undefined4 *)(&stack0xffffffc0 + iVar3) = 0x4034a4;
    param_1 = (undefined4 *)
              ___mingw_realloc(*(undefined4 **)(&stack0xffffffc4 + iVar3),
                               *(uint *)(&stack0xffffffc8 + iVar3));
    *(size_t **)(&stack0xffffffcc + iVar3) = local_20;
    *(size_t **)(&stack0xffffffc8 + iVar3) = psVar2;
    *(undefined4 **)(&stack0xffffffc4 + iVar3) = param_1;
    *(undefined4 *)(&stack0xffffffc0 + iVar3) = 0x4034be;
    _bss = param_1;
    _wcstombs(*(char **)(&stack0xffffffc4 + iVar3),*(wchar_t **)(&stack0xffffffc8 + iVar3),
              *(size_t *)(&stack0xffffffcc + iVar3));
    goto LAB_004034be;
  }
  do {
    psVar5 = (size_t *)((int)psVar6 + -2);
    if (psVar5 <= local_20) {
      if ((local_20 == psVar5) &&
         ((((local_22 == 0x2f || (local_22 == 0x5c)) && (*(short *)psVar6 == local_22)) &&
          ((*(short *)((int)psVar6 + 2) != 0x2f && (*(short *)((int)psVar6 + 2) != 0x5c)))))) {
        psVar5 = psVar6;
      }
      break;
    }
    psVar6 = psVar5;
  } while ((*(short *)psVar5 == 0x2f) || (*(short *)psVar5 == 0x5c));
  *(short *)((int)psVar5 + 2) = 0;
  sVar8 = *(short *)psVar2;
  psVar6 = psVar2;
  psVar5 = psVar2;
  if ((sVar8 == 0x2f) || (sVar8 == 0x5c)) {
    do {
      do {
        psVar1 = (short *)((int)psVar6 + 2);
        psVar6 = (size_t *)((int)psVar6 + 2);
      } while (*psVar1 == 0x2f);
    } while (*psVar1 == 0x5c);
    if ((int)((int)psVar6 - (int)psVar2) < 5) goto LAB_004035e5;
  }
  else {
LAB_004035e5:
    if (*(short *)((int)&uStack48 + iVar3 + 2) == sVar8) {
      sVar8 = *(short *)psVar6;
      psVar5 = psVar6;
    }
  }
  if (sVar8 != 0) {
    local_20 = _Src;
    psVar7 = psVar5;
    psVar6 = psVar5;
    do {
      psVar5 = (size_t *)((int)psVar7 + 2);
      *(short *)psVar7 = sVar8;
      if (sVar8 == 0x2f) {
        sVar9 = *(short *)psVar6;
LAB_00403586:
        if ((sVar9 == 0x5c) || (sVar8 = sVar9, sVar9 == 0x2f)) {
          do {
            do {
              sVar8 = *(short *)((int)psVar6 + 2);
              psVar6 = (size_t *)((int)psVar6 + 2);
            } while (sVar8 == 0x2f);
          } while (sVar8 == 0x5c);
        }
      }
      else {
        sVar9 = *(short *)((int)psVar6 + 2);
        psVar6 = (size_t *)((int)psVar6 + 2);
        bVar10 = sVar8 == 0x5c;
        sVar8 = sVar9;
        if (bVar10) goto LAB_00403586;
      }
      psVar7 = psVar5;
      _Src = local_20;
    } while (sVar8 != 0);
  }
  sVar4 = local_2c;
  *(short *)psVar5 = 0;
  *(size_t *)(&stack0xffffffcc + iVar3) = sVar4;
  *(size_t **)(&stack0xffffffc8 + iVar3) = psVar2;
  *(undefined4 **)(&stack0xffffffc4 + iVar3) = param_1;
  *(undefined4 *)(&stack0xffffffc0 + iVar3) = 0x403626;
  sVar4 = _wcstombs(*(char **)(&stack0xffffffc4 + iVar3),*(wchar_t **)(&stack0xffffffc8 + iVar3),
                    *(size_t *)(&stack0xffffffcc + iVar3));
  if (sVar4 != 0xffffffff) {
    *(undefined *)((int)param_1 + sVar4) = 0;
  }
LAB_004034be:
  *(size_t **)(&stack0xffffffc8 + iVar3) = _Src;
  *(undefined4 *)(&stack0xffffffc4 + iVar3) = 2;
  *(undefined4 *)(&stack0xffffffc0 + iVar3) = 0x4034ce;
  _setlocale(*(int *)(&stack0xffffffc4 + iVar3),*(char **)(&stack0xffffffc8 + iVar3));
  *(size_t **)(&stack0xffffffc4 + iVar3) = _Src;
  *(undefined4 *)(&stack0xffffffc0 + iVar3) = 0x4034d6;
  ___mingw_free(*(undefined4 **)(&stack0xffffffc4 + iVar3));
  return param_1;
}



HANDLE __fastcall _text(undefined4 param_1,int param_2)

{
  char cVar1;
  short sVar2;
  LPCSTR in_EAX;
  HANDLE pvVar3;
  DWORD DVar4;
  DWORD *pDVar5;
  int *piVar6;
  char *pcVar7;
  _WIN32_FIND_DATAA local_14c;
  
  pvVar3 = _FindFirstFileA_8(in_EAX,(LPWIN32_FIND_DATAA)&local_14c);
  if (pvVar3 == (HANDLE)0xffffffff) {
    DVar4 = _GetLastError_0();
    pDVar5 = (DWORD *)__errno();
    *pDVar5 = DVar4;
    if (DVar4 == 3) {
      piVar6 = __errno();
      *piVar6 = 2;
    }
    else {
      piVar6 = __errno();
      if (*piVar6 == 0x10b) {
        piVar6 = __errno();
        *piVar6 = 0x14;
      }
      else {
        piVar6 = __errno();
        if (*piVar6 != 2) {
          piVar6 = __errno();
          *piVar6 = 0x16;
        }
      }
    }
  }
  else {
    pcVar7 = (char *)(param_2 + 0xc);
    *(undefined2 *)(param_2 + 6) = 0;
    *(char *)(param_2 + 0xc) = local_14c.cFileName[0];
    if (local_14c.cFileName[0] != '\0') {
      sVar2 = 0;
      while( true ) {
        sVar2 = sVar2 + 1;
        *(ushort *)(param_2 + 6) = sVar2;
        cVar1 = local_14c.cFileName[sVar2];
        pcVar7 = pcVar7 + (sVar2 < 0x104);
        *pcVar7 = cVar1;
        if (cVar1 == '\0') break;
        sVar2 = *(short *)(param_2 + 6);
      }
    }
    if (0x10 < (local_14c.dwFileAttributes & 0xffffff58)) {
      *(undefined4 *)(param_2 + 8) = 0x18;
      return pvVar3;
    }
    *(uint *)(param_2 + 8) = local_14c.dwFileAttributes & 0xffffff58;
  }
  return pvVar3;
}



BOOL __fastcall Funcao_3780(undefined4 param_1,int param_2)

{
  char cVar1;
  short sVar2;
  HANDLE in_EAX;
  BOOL BVar3;
  DWORD DVar4;
  int *piVar5;
  char *pcVar6;
  _WIN32_FIND_DATAA local_14c;
  
  BVar3 = _FindNextFileA_8(in_EAX,(LPWIN32_FIND_DATAA)&local_14c);
  if (BVar3 == 0) {
    DVar4 = _GetLastError_0();
    if (DVar4 != 0x12) {
      piVar5 = __errno();
      *piVar5 = 2;
      return 0;
    }
  }
  else {
    pcVar6 = (char *)(param_2 + 0xc);
    *(undefined2 *)(param_2 + 6) = 0;
    *(char *)(param_2 + 0xc) = local_14c.cFileName[0];
    if (local_14c.cFileName[0] != '\0') {
      sVar2 = 0;
      while( true ) {
        sVar2 = sVar2 + 1;
        *(ushort *)(param_2 + 6) = sVar2;
        cVar1 = local_14c.cFileName[sVar2];
        pcVar6 = pcVar6 + (sVar2 < 0x104);
        *pcVar6 = cVar1;
        if (cVar1 == '\0') break;
        sVar2 = *(short *)(param_2 + 6);
      }
    }
    if (0x10 < (local_14c.dwFileAttributes & 0xffffff58)) {
      *(undefined4 *)(param_2 + 8) = 0x18;
      return BVar3;
    }
    *(uint *)(param_2 + 8) = local_14c.dwFileAttributes & 0xffffff58;
  }
  return BVar3;
}



undefined4 * __cdecl ___mingw_opendir(char *param_1)

{
  undefined *puVar1;
  byte bVar2;
  uint uVar3;
  undefined2 *puVar4;
  int *piVar5;
  uint *puVar6;
  int iVar7;
  undefined4 *puVar8;
  uint *puVar9;
  char acStack292 [4];
  uint local_120 [68];
  
  if (param_1 == (char *)0x0) {
    piVar5 = __errno();
    puVar8 = (undefined4 *)0x0;
    *piVar5 = 0x16;
  }
  else {
    if (*param_1 == '\0') {
      piVar5 = __errno();
      *piVar5 = 2;
      return (undefined4 *)0x0;
    }
    __fullpath(local_120,param_1,0x104);
    puVar6 = (uint *)local_120;
    if ((char)local_120[0] == '\0') {
      do {
        puVar9 = puVar6;
        puVar6 = puVar9 + 1;
        uVar3 = *puVar9 + 0xfefefeff & ~*puVar9;
        _bVar2 = uVar3 & 0x80808080;
        bVar2 = (byte)_bVar2;
      } while (_bVar2 == 0);
      if ((uVar3 & 0x8080) == 0) {
        bVar2 = (byte)(_bVar2 >> 0x10);
        puVar6 = (uint *)((int)puVar9 + 6);
      }
      puVar4 = (undefined2 *)((int)puVar6 + (-3 - (uint)CARRY1(bVar2,bVar2)));
    }
    else {
      do {
        puVar9 = puVar6;
        puVar6 = puVar9 + 1;
        uVar3 = *puVar9 + 0xfefefeff & ~*puVar9;
        _bVar2 = uVar3 & 0x80808080;
        bVar2 = (byte)_bVar2;
      } while (_bVar2 == 0);
      if ((uVar3 & 0x8080) == 0) {
        bVar2 = (byte)(_bVar2 >> 0x10);
        puVar6 = (uint *)((int)puVar9 + 6);
      }
      iVar7 = (int)puVar6 + ((-3 - (uint)CARRY1(bVar2,bVar2)) - (int)local_120);
      puVar4 = (undefined2 *)((int)local_120 + iVar7);
      if (((&stack0xfffffeda)[iVar7 + 5] != '/') && ((&stack0xfffffeda)[iVar7 + 5] != '\\')) {
        *puVar4 = 0x5c;
        puVar4 = (undefined2 *)(local_120 + iVar7 + 1);
      }
    }
    *puVar4 = 0x2a;
    puVar6 = (uint *)local_120;
    do {
      puVar9 = puVar6;
      puVar6 = puVar9 + 1;
      uVar3 = *puVar9 + 0xfefefeff & ~*puVar9;
      _bVar2 = uVar3 & 0x80808080;
      bVar2 = (byte)_bVar2;
    } while (_bVar2 == 0);
    if ((uVar3 & 0x8080) == 0) {
      bVar2 = (byte)(_bVar2 >> 0x10);
      puVar6 = (uint *)((int)puVar9 + 6);
    }
    uVar3 = (int)puVar6 + ((-3 - (uint)CARRY1(bVar2,bVar2)) - (int)local_120);
    puVar8 = (undefined4 *)_malloc(uVar3 + 0x11c);
    if (puVar8 == (undefined4 *)0x0) {
      piVar5 = __errno();
      *piVar5 = 0xc;
    }
    else {
      puVar1 = (undefined *)(uVar3 + 1);
      if (puVar1 < &DAT_00000004) {
        if ((puVar1 != (undefined *)0x0) &&
           (*(char *)(puVar8 + 0x46) = (char)local_120[0], ((uint)puVar1 & 2) != 0)) {
          *(undefined2 *)(puVar1 + (int)puVar8 + 0x116) =
               *(undefined2 *)(puVar1 + (int)(&stack0xfffffeda + 4));
        }
      }
      else {
        uVar3 = uVar3 >> 2;
        *(undefined4 *)((int)((int)puVar8 + 0x114) + (int)puVar1) =
             *(undefined4 *)(puVar1 + (int)(&stack0xfffffeda + 2));
        puVar6 = (uint *)local_120;
        puVar9 = puVar8 + 0x46;
        while (uVar3 != 0) {
          uVar3 = uVar3 - 1;
          *puVar9 = *puVar6;
          puVar6 = puVar6 + 1;
          puVar9 = puVar9 + 1;
        }
      }
      iVar7 = _text();
      puVar8[0x44] = iVar7;
      if (iVar7 == -1) {
        ___mingw_free(puVar8);
        puVar8 = (undefined4 *)0x0;
      }
      else {
        *puVar8 = 0;
        puVar8[0x45] = 0;
        *(undefined2 *)(puVar8 + 1) = 0x110;
      }
    }
  }
  return puVar8;
}



uint __cdecl ___mingw_readdir(uint param_1)

{
  int iVar1;
  int *piVar2;
  
  if (param_1 == 0) {
    piVar2 = __errno();
    param_1 = 0;
    *piVar2 = 9;
  }
  else {
    iVar1 = *(int *)(param_1 + 0x114);
    *(int *)(param_1 + 0x114) = iVar1 + 1;
    if (0 < iVar1) {
      iVar1 = Funcao_3780();
      param_1 = param_1 & ~-(uint)(iVar1 == 0);
    }
  }
  return param_1;
}



undefined4 __cdecl ___mingw_closedir(undefined4 *param_1)

{
  BOOL BVar1;
  int *piVar2;
  
  if ((param_1 != (undefined4 *)0x0) && (BVar1 = _FindClose_4((HANDLE)param_1[0x44]), BVar1 != 0)) {
    ___mingw_free(param_1);
    return 0;
  }
  piVar2 = __errno();
  *piVar2 = 9;
  return 0xffffffff;
}



void __cdecl ___mingw_rewinddir(int param_1)

{
  BOOL BVar1;
  int *piVar2;
  int iVar3;
  
  if ((param_1 != 0) && (BVar1 = _FindClose_4(*(HANDLE *)(param_1 + 0x110)), BVar1 != 0)) {
    iVar3 = _text();
    *(int *)(param_1 + 0x110) = iVar3;
    if (iVar3 == -1) {
      return;
    }
    *(undefined4 *)(param_1 + 0x114) = 0;
    return;
  }
  piVar2 = __errno();
  *piVar2 = 9;
  return;
}



undefined4 * __cdecl ___mingw_memalign_base(undefined4 *param_1,undefined4 *param_2)

{
  int *piVar1;
  int *piVar2;
  uint uVar3;
  uint uVar4;
  int iVar5;
  int iVar6;
  uint local_18;
  
  piVar2 = ___mingw_memalign_lwm;
  if (((param_1 != (undefined4 *)0x0) && (___mingw_memalign_lwm != (int *)0x0)) &&
     (___mingw_memalign_lwm + 2 <= param_1)) {
    uVar3 = *(uint *)((uint)(param_1 + -1) & 0xfffffffc);
    uVar4 = uVar3 & 3;
    piVar1 = (int *)(uVar3 & 0xfffffffc);
    param_2[1] = uVar4;
    *(int **)param_2 = piVar1;
    if ((piVar2 <= piVar1) && (piVar1 <= param_1 + -2)) {
      if ((uVar3 & 1) == 0) {
        local_18 = 0xfffffff8;
        iVar5 = 0xf;
        iVar6 = 8;
      }
      else {
        iVar6 = *piVar1;
        iVar5 = iVar6 + 7;
        local_18 = -iVar6;
      }
      param_2[2] = iVar6;
      uVar3 = uVar3 & 2;
      piVar2 = piVar1;
      if (uVar3 != 0) {
        uVar3 = *(uint *)((int)piVar1 + (uVar4 + 1 & 0xfffffffc));
        piVar2 = (int *)((int)piVar1 + uVar3);
      }
      param_2[3] = uVar3;
      if (uVar4 == 3) {
        iVar5 = iVar6 + 0xb;
      }
      if (param_1 == (undefined4 *)((local_18 & (int)piVar2 + iVar5) - uVar3)) {
        param_1 = piVar1;
      }
    }
  }
  return param_1;
}



void * __cdecl ___mingw_realloc(undefined4 *param_1,uint param_2)

{
  undefined4 *puVar1;
  int *piVar2;
  void *pvVar3;
  undefined4 *_Memory;
  undefined4 *local_1c [3];
  uint local_10;
  
  _Memory = param_1;
  if (param_1 != (undefined4 *)0x0) {
    puVar1 = ___mingw_memalign_base(param_1,local_1c);
    if ((param_1 != puVar1) && (_Memory = local_1c[0], param_2 != 0)) {
      if (local_10 < param_2) {
        pvVar3 = ___mingw_memalign_realloc((int)param_1,local_1c,param_2);
        return pvVar3;
      }
      piVar2 = __errno();
      *piVar2 = 0x16;
      return (void *)0x0;
    }
  }
  pvVar3 = realloc(_Memory,param_2);
  return pvVar3;
}



void * __cdecl ___mingw_memalign_realloc(int param_1,void **param_2,uint param_3)

{
  void *pvVar1;
  size_t sVar2;
  void *pvVar3;
  void *_Src;
  int iVar4;
  void *_Dst;
  uint _Size;
  
  sVar2 = __msize(*param_2);
  iVar4 = (int)param_2[2] + 7;
  if (((uint)param_2[1] & 3) == 3) {
    iVar4 = (int)param_2[2] + 0xb;
  }
  pvVar3 = realloc(*param_2,param_3 + iVar4);
  pvVar1 = *param_2;
  if (pvVar1 != pvVar3) {
    _Dst = (void *)0x0;
    if (pvVar3 != (void *)0x0) {
      if ((___mingw_memalign_lwm == (void *)0x0) || (pvVar3 < ___mingw_memalign_lwm)) {
        ___mingw_memalign_lwm = pvVar3;
      }
      _Src = (void *)((int)pvVar3 + (param_1 - (int)pvVar1));
      *param_2 = (void *)((uint)param_2[1] | (uint)pvVar3);
      _Dst = (void *)((iVar4 + (int)param_2[3] + (int)pvVar3 & -(int)param_2[2]) - (int)param_2[3]);
      if (_Dst != _Src) {
        _Size = (int)pvVar1 + (sVar2 - param_1);
        if (param_3 < _Size) {
          _Size = param_3;
        }
        _memmove(_Dst,_Src,_Size);
      }
      *(void **)((int)_Dst - 4U & 0xfffffffc) = *param_2;
    }
    return _Dst;
  }
  return (void *)param_1;
}



uint ___chkstk_ms(void)

{
  uint in_EAX;
  uint uVar1;
  undefined4 *puVar2;
  uint uStack8;
  
  puVar2 = (undefined4 *)&stack0x00000004;
  uVar1 = in_EAX;
  if (0xfff < in_EAX) {
    do {
      puVar2 = puVar2 + -0x400;
      *puVar2 = *puVar2;
      uVar1 = uVar1 - 0x1000;
    } while (0x1000 < uVar1);
  }
  uStack8 = in_EAX;
  *(undefined4 *)((int)puVar2 - uVar1) = *(undefined4 *)((int)puVar2 - uVar1);
  return uStack8;
}




int __cdecl _stricoll(char *_Str1,char *_Str2)

{
  int iVar1;
  
  iVar1 = _stricoll();
  return iVar1;
}




char * __cdecl _strdup(char *_Src)

{
  char *pcVar1;
  
  pcVar1 = (char *)_strdup();
  return pcVar1;
}




size_t __cdecl _wcstombs(char *_Dest,wchar_t *_Source,size_t _MaxCount)

{
  size_t sVar1;
  
  sVar1 = wcstombs();
  return sVar1;
}




int __cdecl _vfprintf(FILE *_File,char *_Format,va_list _ArgList)

{
  int iVar1;
  
  iVar1 = vfprintf();
  return iVar1;
}




int __cdecl _tolower(int _C)

{
  int iVar1;
  
  iVar1 = tolower();
  return iVar1;
}




size_t __cdecl _strlen(char *_Str)

{
  size_t sVar1;
  
  sVar1 = strlen();
  return sVar1;
}




int __cdecl _strcoll(char *_Str1,char *_Str2)

{
  int iVar1;
  
  iVar1 = strcoll();
  return iVar1;
}




int __cdecl _strcmp(char *_Str1,char *_Str2)

{
  int iVar1;
  
  iVar1 = strcmp();
  return iVar1;
}




void _signal(int param_1)

{
  signal(param_1);
  return;
}




char * __cdecl _setlocale(int _Category,char *_Locale)

{
  char *pcVar1;
  
  pcVar1 = (char *)setlocale();
  return pcVar1;
}




void * __cdecl _memmove(void *_Dst,void *_Src,size_t _Size)

{
  void *pvVar1;
  
  pvVar1 = (void *)memmove();
  return pvVar1;
}




void * __cdecl _memcpy(void *_Dst,void *_Src,size_t _Size)

{
  void *pvVar1;
  
  pvVar1 = (void *)memcpy();
  return pvVar1;
}




size_t __cdecl _mbstowcs(wchar_t *_Dest,char *_Source,size_t _MaxCount)

{
  size_t sVar1;
  
  sVar1 = mbstowcs();
  return sVar1;
}




void * __cdecl _malloc(size_t _Size)

{
  void *pvVar1;
  
  pvVar1 = (void *)malloc();
  return pvVar1;
}




size_t __cdecl _fwrite(void *_Str,size_t _Size,size_t _Count,FILE *_File)

{
  size_t sVar1;
  
  sVar1 = fwrite();
  return sVar1;
}




int __cdecl _fprintf(FILE *_File,char *_Format,...)

{
  int iVar1;
  
  iVar1 = fprintf();
  return iVar1;
}




void * __cdecl _calloc(size_t _Count,size_t _Size)

{
  void *pvVar1;
  
  pvVar1 = (void *)calloc();
  return pvVar1;
}




void __cdecl _abort(void)

{
  abort();
  return;
}




int __cdecl __setmode(int _FileHandle,int _Mode)

{
  int iVar1;
  
  iVar1 = _setmode();
  return iVar1;
}




size_t __cdecl __msize(void *_Memory)

{
  size_t sVar1;
  
  sVar1 = _msize();
  return sVar1;
}




int __cdecl __isctype(int _C,int _Type)

{
  int iVar1;
  
  iVar1 = _isctype();
  return iVar1;
}




char * __cdecl __fullpath(char *_FullPath,char *_Path,size_t _SizeInBytes)

{
  char *pcVar1;
  
  pcVar1 = (char *)_fullpath();
  return pcVar1;
}




int * __cdecl __errno(void)

{
  int *piVar1;
  
  piVar1 = (int *)_errno();
  return piVar1;
}




void __cdecl __cexit(void)

{
  _cexit();
  return;
}



void ___p__fmode(void)

{
  __p__fmode();
  return;
}



void ___p__environ(void)

{
  __p__environ();
  return;
}




int __cdecl
___getmainargs(int *_Argc,char ***_Argv,char ***_Env,int _DoWildCard,_startupinfo *_StartInfo)

{
  int iVar1;
  
  iVar1 = __getmainargs();
  return iVar1;
}



int _MessageBoxA_16(HWND hWnd,LPCSTR lpText,LPCSTR lpCaption,UINT uType)

{
  int iVar1;
  
  iVar1 = MessageBoxA(hWnd,lpText,lpCaption,uType);
  return iVar1;
}



SIZE_T _VirtualQuery_12(LPCVOID lpAddress,PMEMORY_BASIC_INFORMATION lpBuffer,SIZE_T dwLength)

{
  SIZE_T SVar1;
  
  SVar1 = VirtualQuery(lpAddress,lpBuffer,dwLength);
  return SVar1;
}



BOOL _VirtualProtect_16(LPVOID lpAddress,SIZE_T dwSize,DWORD flNewProtect,PDWORD lpflOldProtect)

{
  BOOL BVar1;
  
  BVar1 = VirtualProtect(lpAddress,dwSize,flNewProtect,lpflOldProtect);
  return BVar1;
}



LPVOID _TlsGetValue_4(DWORD dwTlsIndex)

{
  LPVOID pvVar1;
  
  pvVar1 = TlsGetValue(dwTlsIndex);
  return pvVar1;
}



LPTOP_LEVEL_EXCEPTION_FILTER
_SetUnhandledExceptionFilter_4(LPTOP_LEVEL_EXCEPTION_FILTER lpTopLevelExceptionFilter)

{
  LPTOP_LEVEL_EXCEPTION_FILTER pPVar1;
  
  pPVar1 = SetUnhandledExceptionFilter(lpTopLevelExceptionFilter);
  return pPVar1;
}



HMODULE _LoadLibraryA_4(LPCSTR lpLibFileName)

{
  HMODULE pHVar1;
  
  pHVar1 = LoadLibraryA(lpLibFileName);
  return pHVar1;
}



void _LeaveCriticalSection_4(LPCRITICAL_SECTION lpCriticalSection)

{
  LeaveCriticalSection(lpCriticalSection);
  return;
}



void _InitializeCriticalSection_4(LPCRITICAL_SECTION lpCriticalSection)

{
  InitializeCriticalSection(lpCriticalSection);
  return;
}



FARPROC _GetProcAddress_8(HMODULE hModule,LPCSTR lpProcName)

{
  FARPROC pFVar1;
  
  pFVar1 = GetProcAddress(hModule,lpProcName);
  return pFVar1;
}



HMODULE _GetModuleHandleA_4(LPCSTR lpModuleName)

{
  HMODULE pHVar1;
  
  pHVar1 = GetModuleHandleA(lpModuleName);
  return pHVar1;
}



DWORD _GetLastError_0(void)

{
  DWORD DVar1;
  
  DVar1 = GetLastError();
  return DVar1;
}



LPSTR _GetCommandLineA_0(void)

{
  LPSTR pCVar1;
  
  pCVar1 = GetCommandLineA();
  return pCVar1;
}



BOOL _FreeLibrary_4(HMODULE hLibModule)

{
  BOOL BVar1;
  
  BVar1 = FreeLibrary(hLibModule);
  return BVar1;
}



BOOL _FindNextFileA_8(HANDLE hFindFile,LPWIN32_FIND_DATAA lpFindFileData)

{
  BOOL BVar1;
  
  BVar1 = FindNextFileA(hFindFile,lpFindFileData);
  return BVar1;
}



HANDLE _FindFirstFileA_8(LPCSTR lpFileName,LPWIN32_FIND_DATAA lpFindFileData)

{
  HANDLE pvVar1;
  
  pvVar1 = FindFirstFileA(lpFileName,lpFindFileData);
  return pvVar1;
}



BOOL _FindClose_4(HANDLE hFindFile)

{
  BOOL BVar1;
  
  BVar1 = FindClose(hFindFile);
  return BVar1;
}



void _ExitProcess_4(UINT uExitCode)

{
  ExitProcess(uExitCode);
  return;
}



void _EnterCriticalSection_4(LPCRITICAL_SECTION lpCriticalSection)

{
  EnterCriticalSection(lpCriticalSection);
  return;
}



void _DeleteCriticalSection_4(LPCRITICAL_SECTION lpCriticalSection)

{
  DeleteCriticalSection(lpCriticalSection);
  return;
}


