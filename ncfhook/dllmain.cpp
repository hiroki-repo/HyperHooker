// dllmain.cpp : DLL アプリケーションのエントリ ポイントを定義します。
#include "pch.h"
#include <windows.h>
#include <winternl.h>

DWORD JMPPTR4ARM = 0;

BYTE JMPCodeOLD[32] = { 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90 };
BYTE JMPCodeOLD_2[32] = { 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90 };
#ifdef _WIN64
BYTE JMPCode[] = { 0xFF, 0x25, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88 };
#else
#ifdef _ARM_
BYTE JMPCode[] = { 0xDF, 0xF8, 0, 0xF0, 0x11, 0x22, 0x33, 0x44 };
#else
BYTE JMPCode[] = { 0xb8,0xcc,0xcc,0xcc, 0xcc,0xff,0xe0,0xcc };
#endif
#endif

#ifdef _WIN64
BYTE JMPCode_2[] = { 0xFF, 0x25, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88 };
#else
#ifdef _ARM_
BYTE JMPCode_2[] = { 0xDF, 0xF8, 0, 0xF0, 0x11, 0x22, 0x33, 0x44 };
#else
BYTE JMPCode_2[] = { 0xb8,0xcc,0xcc,0xcc, 0xcc,0xff,0xe0,0xcc };
#endif
#endif

BYTE* target;
BYTE* target2;

UINT64 target123[2];

//#define target NtCreateFile


typedef struct _RTLP_CURDIR_REF
{
    LONG RefCount;
    HANDLE Handle;
} RTLP_CURDIR_REF, * PRTLP_CURDIR_REF;

typedef struct _RTL_RELATIVE_NAME_U
{
    UNICODE_STRING RelativeName;
    HANDLE ContainingDirectory;
    PRTLP_CURDIR_REF CurDirRef;
} RTL_RELATIVE_NAME_U, * PRTL_RELATIVE_NAME_U;

/*typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING, * PUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES {
    ULONG           Length;
    HANDLE          RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG           Attributes;
    PVOID           SecurityDescriptor;
    PVOID           SecurityQualityOfService;
} OBJECT_ATTRIBUTES;*/


BOOLEAN (NTAPI *RtlDosPathNameToNtPathName_U) (PCWSTR DosPathName, PUNICODE_STRING NtPathName,PWSTR NtFileNamePart, PRTL_RELATIVE_NAME_U DirectoryInfo);

typedef BOOLEAN NTAPI typeofRtlDosPathNameToNtPathName_U(PCWSTR, PUNICODE_STRING, PWSTR, PRTL_RELATIVE_NAME_U);

typedef NTSTATUS NTAPI typeofMyNtCreateFile(
    PHANDLE            FileHandle,
    ACCESS_MASK        DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PIO_STATUS_BLOCK   IoStatusBlock,
    PLARGE_INTEGER     AllocationSize,
    ULONG              FileAttributes,
    ULONG              ShareAccess,
    ULONG              CreateDisposition,
    ULONG              CreateOptions,
    PVOID              EaBuffer,
    ULONG              EaLength
);
typedef NTSTATUS NTAPI typeofMyNtOpenFile(
    PHANDLE            FileHandle,
    ACCESS_MASK        DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PIO_STATUS_BLOCK   IoStatusBlock,
    ULONG              ShareAccess,
    ULONG              OpenOptions
);

NTSTATUS NTAPI MyNtCreateFile(
    PHANDLE            FileHandle,
    ACCESS_MASK        DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PIO_STATUS_BLOCK   IoStatusBlock,
    PLARGE_INTEGER     AllocationSize,
    ULONG              FileAttributes,
    ULONG              ShareAccess,
    ULONG              CreateDisposition,
    ULONG              CreateOptions,
    PVOID              EaBuffer,
    ULONG              EaLength
) {
    memcpy(target, JMPCodeOLD, sizeof(JMPCode));
    FlushInstructionCache(GetCurrentProcess(), target, sizeof(JMPCode));
    OBJECT_ATTRIBUTES attr;
    UNICODE_STRING objektnamex;
    memcpy(&attr, ObjectAttributes, sizeof(OBJECT_ATTRIBUTES));
    WCHAR ObjectName4chks[1024];
    GetModuleFileNameW(0, ObjectName4chks, (sizeof(ObjectName4chks)/2));
    wchar_t* P4ObjectName4chks = wcsrchr(ObjectName4chks, '\\');
    if (P4ObjectName4chks)
        *P4ObjectName4chks = 0;
    wcscat_s<1024>(ObjectName4chks, L"\\System32");
    WCHAR* ObjectName4chks3;
    UNICODE_STRING ObjectName4chks2;
    RtlDosPathNameToNtPathName_U((PCWSTR)&ObjectName4chks, (PUNICODE_STRING)&ObjectName4chks2,0,0);
    ObjectName4chks3 = ObjectName4chks2.Buffer;
    WCHAR Temp4WCSICMP[2048];
    memcpy(Temp4WCSICMP, attr.ObjectName->Buffer, (wcslen(attr.ObjectName->Buffer)*2));
    wchar_t* P4Temp4WCSICMP = wcsrchr(Temp4WCSICMP, '\\');
    if (P4Temp4WCSICMP)
        *P4Temp4WCSICMP = 0;
    if (_wcsicmp(ObjectName4chks3, Temp4WCSICMP) == 0) {
        memcpy(Temp4WCSICMP, attr.ObjectName->Buffer, (wcslen(attr.ObjectName->Buffer)*2));
        memcpy(&Temp4WCSICMP[wcslen(ObjectName4chks3) - 8],L"SysWOW64",16);
        objektnamex.Length = attr.ObjectName->Length;
        objektnamex.MaximumLength = attr.ObjectName->MaximumLength;
        attr.ObjectName = &objektnamex;
        attr.ObjectName->Buffer = Temp4WCSICMP;
    }
    NTSTATUS ret = NtCreateFile(FileHandle,DesiredAccess,&attr,IoStatusBlock,AllocationSize,FileAttributes,ShareAccess,CreateDisposition,CreateOptions,EaBuffer,EaLength);
    RtlFreeUnicodeString(&ObjectName4chks2);
    memcpy(target, JMPCode, sizeof(JMPCode));
    FlushInstructionCache(GetCurrentProcess(), target, sizeof(JMPCode));
    return ret;
}

NTSTATUS NTAPI MyNtOpenFile(
    PHANDLE            FileHandle,
    ACCESS_MASK        DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PIO_STATUS_BLOCK   IoStatusBlock,
    ULONG              ShareAccess,
    ULONG              OpenOptions
) {
    memcpy(target2, JMPCodeOLD_2, sizeof(JMPCode_2));
    FlushInstructionCache(GetCurrentProcess(), target2, sizeof(JMPCode_2));
    OBJECT_ATTRIBUTES attr;
    UNICODE_STRING objektnamex;
    memcpy_s(&attr, sizeof(OBJECT_ATTRIBUTES), ObjectAttributes, sizeof(OBJECT_ATTRIBUTES));
    WCHAR ObjectName4chks[1024];
    GetModuleFileNameW(0, ObjectName4chks, (sizeof(ObjectName4chks)/2));
    wchar_t* P4ObjectName4chks = wcsrchr(ObjectName4chks, '\\');
    if (P4ObjectName4chks)
        *P4ObjectName4chks = 0;
    wcscat_s<1024>(ObjectName4chks, L"\\System32");
    WCHAR* ObjectName4chks3;
    UNICODE_STRING ObjectName4chks2;
    RtlDosPathNameToNtPathName_U((PCWSTR)&ObjectName4chks, (PUNICODE_STRING)&ObjectName4chks2, 0, 0);
    ObjectName4chks3 = ObjectName4chks2.Buffer;
    WCHAR Temp4WCSICMP[2048];
    memcpy(Temp4WCSICMP, attr.ObjectName->Buffer, (wcslen(attr.ObjectName->Buffer)*2));
    wchar_t* P4Temp4WCSICMP = wcsrchr(Temp4WCSICMP, '\\');
    if (P4Temp4WCSICMP)
        *P4Temp4WCSICMP = 0;
    if (_wcsicmp(ObjectName4chks3, Temp4WCSICMP) == 0) {
        memcpy(Temp4WCSICMP, attr.ObjectName->Buffer, (wcslen(attr.ObjectName->Buffer)*2));
        memcpy(&Temp4WCSICMP[wcslen(ObjectName4chks3) - 8], L"SysWOW64", 16);
        objektnamex.Length = attr.ObjectName->Length;
        objektnamex.MaximumLength = attr.ObjectName->MaximumLength;
        attr.ObjectName = &objektnamex;
        attr.ObjectName->Buffer = Temp4WCSICMP;
    }
    NTSTATUS ret = NtOpenFile(FileHandle,DesiredAccess,&attr,IoStatusBlock,ShareAccess,OpenOptions);
    RtlFreeUnicodeString(&ObjectName4chks2);
    memcpy(target2, JMPCode_2, sizeof(JMPCode_2));
    FlushInstructionCache(GetCurrentProcess(), target2, sizeof(JMPCode_2));
    return ret;
}


bool ncfhooked = false;

extern "C" __declspec(dllexport) bool ncfhook() {
    if (ncfhooked == true) { return true; }
    ncfhooked = true;

    HMODULE HM = LoadLibraryA("ntdll.dll");
    if (HM == 0)
        return false;

    target = (BYTE*)GetProcAddress(HM, "NtCreateFile");
    target2 = (BYTE*)GetProcAddress(HM, "NtOpenFile");
    target123[0] = (UINT64)(&target);
    target123[1] = (UINT64)(&target2);
    RtlDosPathNameToNtPathName_U = (typeofRtlDosPathNameToNtPathName_U*)GetProcAddress(HM, "RtlDosPathNameToNtPathName_U");
    if (RtlDosPathNameToNtPathName_U == 0)
        return false;
    if (target == 0)
        return false; 
#ifdef _ARM_
    if (((DWORD)(&target)) & 1) {
        target--;	// THUMB
    }
    else { JMPCode[0] = 0x04; JMPCode[1] = 0xF0; JMPCode[2] = 0x1F; JMPCode[3] = 0xE5; }

    if (((DWORD)(&target2)) & 1) {
        target2--;	// THUMB
    }
    else { JMPCode_2[0] = 0x04; JMPCode_2[1] = 0xF0; JMPCode_2[2] = 0x1F; JMPCode_2[3] = 0xE5; }
#endif

#ifdef _WIN64
    * (UINT64*)(JMPCode + 2) = ((UINT64)(&MyNtCreateFile));
#else
#ifdef _ARM_
    * (DWORD*)(JMPCode + 4) = 1 | ((DWORD)(&MyNtCreateFile));
#else
    * (DWORD*)(JMPCode + 1) = ((DWORD)(&MyNtCreateFile));
#endif
#endif
#ifdef _WIN64
    * (UINT64*)(JMPCode_2 + 2) = ((UINT64)(&MyNtOpenFile));
#else
#ifdef _ARM_
    * (DWORD*)(JMPCode_2 + 4) = 1 | ((DWORD)(&MyNtOpenFile));
#else
    * (DWORD*)(JMPCode_2 + 1) = ((DWORD)(&MyNtOpenFile));
#endif
#endif


#if 0
    if (cpihookx == true) {
        VirtualProtect(&cpi - 7, 7, PAGE_EXECUTE_READWRITE, &Tmp);
        memcpy(&cpi - 7, JMPCodeOLD, 7);
    }
#endif

    DWORD Tmp;
    VirtualProtect(target, sizeof(JMPCode), PAGE_EXECUTE_READWRITE, &Tmp);

    memcpy(JMPCodeOLD, target, sizeof(JMPCode));
    memcpy(target, JMPCode, sizeof(JMPCode));
    FlushInstructionCache(GetCurrentProcess(), target, sizeof(JMPCode));

    VirtualProtect(target2, sizeof(JMPCode_2), PAGE_EXECUTE_READWRITE, &Tmp);

    memcpy(JMPCodeOLD_2, target2, sizeof(JMPCode_2));
    memcpy(target2, JMPCode_2, sizeof(JMPCode_2));
    FlushInstructionCache(GetCurrentProcess(), target2, sizeof(JMPCode_2));

    return true;
}


BOOL APIENTRY DllMain(HMODULE hModule,
    DWORD  ul_reason_for_call,
    LPVOID lpReserved
)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        return ncfhook();
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
