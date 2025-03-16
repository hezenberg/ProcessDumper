#pragma comment (lib, "Psapi.lib")
#pragma comment (lib, "Dbghelp.lib")
#pragma commect (lib, "Dbgcore.lib")
#pragma commect (lib, "User32.lib")

#include <windows.h>
#include <stdio.h>
#include <psapi.h>
#include <string.h>
#include <iso646.h>
#include <minidumpapiset.h>
#include <tlhelp32.h>

#define MIN_STR_PATH_LEN  3
#define PARAM_COUNT       7
#define FLAG_COUNT        1
#define SE_DEBUG_PRIVILEGE   20L 
#define AdjustCurrentProcess 0


const CHAR* exit_command   = "exit\n";
const CHAR* exit_command_u = "EXIT\n";


static DWORD ReadSelectedPID(CHAR* processID);
static INT   ReadFileName(CHAR* filename);
static BOOL  DoRtlAdjustPrivilege(VOID);
static VOID  ExitHandle(VOID);
static VOID  IssueParams(int argc, const char *argv[]);
static VOID  PrintHelp(VOID);
static VOID  WriteMemDumpInFile(DWORD processID, const CHAR* path_file);
static VOID  HandleErrorAndExit(CHAR* last_message, HANDLE* f, HANDLE* p);
static VOID  PrintProcessNameAndID(DWORD processID);


INT ParamMiniDumpWithDataSegs = 0;        INT ParamMiniDumpWithProcessThreadData = 0;
INT ParamMiniDumpWithHandleData = 0;      INT ParamMiniDumpWithPrivateReadWriteMemory = 0;
INT ParamMiniDumpWithUnloadedModules = 0; INT ParamMiniDumpWithFullMemoryInfo = 0;
INT ParamMiniDumpNormal = 0;

const CHAR* _help_flag  = "--help" ;
const CHAR* _show_flag  = "--showproc" ;

CHAR* param[PARAM_COUNT] = {"-wds", "-whd", "-wum", "-ptd", "-prm", "-fmi", "-norm"};


int main(int argc, const char *argv[])
{   
    if(argc == 1 or !strcmp(argv[1], _help_flag))
       PrintHelp();

    if(!strcmp(argv[1], _show_flag ))
    {
        DWORD aProcesses[1024], cbNeeded, cProcesses;
        if (!EnumProcesses( aProcesses, sizeof(aProcesses), &cbNeeded))
        {
            printf("Failed load list process.");
            exit(1);
        }

        cProcesses = cbNeeded / sizeof(DWORD);

        for (UINT64 i = 0; i < cProcesses; i++)
            if(aProcesses[i] != 0)
                PrintProcessNameAndID(aProcesses[i]);

        exit(0);
    }

    DWORD pid = 0;

    if(argc > 3)
    {    
        DoRtlAdjustPrivilege();

        if(!ReadFileName(argv[2]))
        {
            printf("prcdmp - Invalid file path. [%s]", argv[2]);
            exit(0);
        }

        if((pid = ReadSelectedPID(argv[1])) < 1)
        {
            printf("prcdmp - Invalid process id(PID) [%lu]", pid);
            exit(0);
        }

        IssueParams(argc, argv);
        WriteMemDumpInFile(pid, argv[2]);
    }
 

    return 0;
}


static INT ReadFileName(CHAR* filename)
{   
    size_t size = strlen(filename);
    if(size > 0){
        if(size > MIN_STR_PATH_LEN)
            return 1;
        else
            return 0; 
    }
}


static VOID WriteMemDumpInFile(DWORD pid, const CHAR* path_file)
{
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | 
                                  PROCESS_VM_READ | 
                                  PROCESS_DUP_HANDLE | 
                                  THREAD_ALL_ACCESS, 
                                  TRUE, 
                                  pid);


    HANDLE hFile = CreateFileA(path_file,              
                               GENERIC_WRITE,        
                               0,     
                               NULL,                  
                               OPEN_ALWAYS,         
                               FILE_ATTRIBUTE_NORMAL, 
                               NULL);            
                                

    if(!hProcess)
        HandleErrorAndExit("\n  Failed open proceess.", hFile, hProcess);
                                                          
    if(hFile == INVALID_HANDLE_VALUE)
        HandleErrorAndExit("\n  Failed create file.", hFile, hProcess);

    BOOL result = MiniDumpWriteDump(hProcess, pid, hFile,  ParamMiniDumpWithDataSegs        
                                                         | ParamMiniDumpWithHandleData      
                                                         | ParamMiniDumpWithUnloadedModules
                                                         | ParamMiniDumpWithPrivateReadWriteMemory
                                                         | ParamMiniDumpWithProcessThreadData
                                                         | ParamMiniDumpWithFullMemoryInfo, NULL, NULL, NULL);
       
    if(!result)
        HandleErrorAndExit("\n  Failed read dump.", hFile, hProcess);

    printf("\n  Done!\n  Dump path: [%s]\n\n", path_file);

    CloseHandle(hFile);
    CloseHandle(hProcess);
    exit(0);
}


static DWORD ReadSelectedPID(CHAR* processID)
{
    INT64 pid = 0;
    CHAR  pid_str[100] = {0};

    if(processID != NULL)
    {
        pid = atoll(processID);

        if(pid < ULONG_MAX and pid > 0) 
            return pid;
        return 0;
    } else
        return 0;

}


static VOID PrintProcessNameAndID(DWORD processID)
{
    TCHAR szProcessName[MAX_PATH] = TEXT("<unknown>");
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processID);
    
    if (NULL != hProcess )
    {
        HMODULE hMod;
        DWORD cbNeeded;

        if ( EnumProcessModules( hProcess, &hMod, sizeof(hMod), 
             &cbNeeded) )
        {
            GetModuleBaseName( hProcess, hMod, szProcessName, 
                               sizeof(szProcessName)/sizeof(TCHAR) );
        }
    }

    printf( TEXT("\t%s  (PID: %lu)\n"), szProcessName, processID );
    CloseHandle(hProcess);
}


static BOOL DoRtlAdjustPrivilege(VOID)
 {

    BOOL bPrev = FALSE;
    LONG(WINAPI * RtlAdjustPrivilege)(DWORD, BOOL, INT, PBOOL);
    *(FARPROC * ) & RtlAdjustPrivilege = GetProcAddress(GetModuleHandle("ntdll.dll"), "RtlAdjustPrivilege");
    if (!RtlAdjustPrivilege) return FALSE;
    RtlAdjustPrivilege(SE_DEBUG_PRIVILEGE, TRUE, AdjustCurrentProcess, &bPrev);
    return TRUE;
}
  

static VOID HandleErrorAndExit(CHAR* last_message, HANDLE* f, HANDLE* p)
{
    
    printf("\n  %s code: %lu", last_message, GetLastError()); 
    CloseHandle(f);
    CloseHandle(p);
    exit(1);
}


static VOID IssueParams(int argc, char const *argv[])
{
    int f = 0;
    for(int i = 3; i < argc; i++)
    {   
        f = 0;
        for(;f < PARAM_COUNT; f++)
            if(!strcmp(param[f], argv[i]))
                break;
               
        switch (f)
        {
            case 0: ParamMiniDumpWithDataSegs               = MiniDumpWithDataSegs;               break;
            case 1: ParamMiniDumpWithHandleData             = MiniDumpWithHandleData;             break;
            case 2: ParamMiniDumpWithUnloadedModules        = MiniDumpWithUnloadedModules;        break;
            case 3: ParamMiniDumpWithProcessThreadData      = MiniDumpWithProcessThreadData;      break;
            case 4: ParamMiniDumpWithPrivateReadWriteMemory = MiniDumpWithPrivateReadWriteMemory; break;
            case 5: ParamMiniDumpWithFullMemoryInfo         = MiniDumpWithFullMemoryInfo;         break;
            case 6: ParamMiniDumpNormal                     = MiniDumpNormal;                     break;

            default:
                printf("'%s' - Unknown parameter, use '--help' to get a list of parameters.\n", argv[i]);
                exit(0);
        }
    }
}


static VOID PrintHelp(VOID)
{
    printf("\n prcdmp.exe [process id] [path to file dump] [-param -param...]");
    printf("\n   [-wds] - Dump with data segs.\n   [-whd] - Dump with handle data.\n   [-wum] - Dump with unloaded modules.\n   [-ptd] - Dump with process thread data.");
    printf("\n   [-prm] - Dump with private read write memory.\n   [-fmi] - Dump with full memory info.\n   [-norm] - Default dump.\n\n   [--help] - Show this message.\n   [--showproc] - Show process list\n\n");
    exit(0);
}