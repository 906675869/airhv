#pragma warning( disable : 4201 4805)
#include <ntifs.h>
#include <ntddk.h>


#include <intrin.h>


#include "Ntenums.h"
#include "NtStruct.h"

#include <minwindef.h>
#include "utils.h"
#include "log.h"
//#include "kmclass_common.h"

/// <summary>
/// Allocate new Unicode string from Paged pool
/// </summary>
/// <param name="result">Resulting string</param>
/// <param name="size">Buffer size in bytes to alloacate</param>
/// <returns>Status code</returns>
NTSTATUS SafeAllocateString(OUT PUNICODE_STRING result, IN USHORT size)
{
    ASSERT(result != NULL);
    if (result == NULL || size == 0)
        return STATUS_INVALID_PARAMETER;

    result->Buffer = (PWCH)ExAllocatePoolWithTag(PagedPool, size, 'A');
    result->Length = 0;
    result->MaximumLength = size;

    if (result->Buffer)
        RtlZeroMemory(result->Buffer, size);
    else
        return STATUS_NO_MEMORY;

    return STATUS_SUCCESS;
}

/// <summary>
/// Allocate and copy string
/// </summary>
/// <param name="result">Resulting string</param>
/// <param name="source">Source string</param>
/// <returns>Status code</returns>
NTSTATUS SafeInitString(OUT PUNICODE_STRING result, IN PUNICODE_STRING source)
{
    ASSERT(result != NULL && source != NULL);
    if (result == NULL || source == NULL || source->Buffer == NULL)
        return STATUS_INVALID_PARAMETER;

    // No data to copy
    if (source->Length == 0)
    {
        result->Length = result->MaximumLength = 0;
        result->Buffer = NULL;
        return STATUS_SUCCESS;
    }

    result->Buffer = (PWCH)ExAllocatePoolWithTag(PagedPool, source->MaximumLength, 'A');
    result->Length = source->Length;
    result->MaximumLength = source->MaximumLength;

    memcpy(result->Buffer, source->Buffer, source->Length);

    return STATUS_SUCCESS;
}

/// <summary>
/// Search for substring
/// </summary>
/// <param name="source">Source string</param>
/// <param name="target">Target string</param>
/// <param name="CaseInSensitive">Case insensitive search</param>
/// <returns>Found position or -1 if not found</returns>
LONG SafeSearchString(IN PUNICODE_STRING source, IN PUNICODE_STRING target, IN BOOLEAN CaseInSensitive)
{
    ASSERT(source != NULL && target != NULL);
    if (source == NULL || target == NULL || source->Buffer == NULL || target->Buffer == NULL)
        return STATUS_INVALID_PARAMETER;

    // Size mismatch
    if (source->Length < target->Length)
        return -1;

    USHORT diff = source->Length - target->Length;
    for (USHORT i = 0; i <= (diff / sizeof(WCHAR)); i++)
    {
        if (RtlCompareUnicodeStrings(
            source->Buffer + i,
            target->Length / sizeof(WCHAR),
            target->Buffer,
            target->Length / sizeof(WCHAR),
            CaseInSensitive
        ) == 0)
        {
            return i;
        }
    }

    return -1;
}

/// <summary>
/// Get file name from full path
/// </summary>
/// <param name="path">Path.</param>
/// <param name="name">Resulting name</param>
/// <returns>Status code</returns>
NTSTATUS StripPath(IN PUNICODE_STRING path, OUT PUNICODE_STRING name)
{
    ASSERT(path != NULL && name);
    if (path == NULL || name == NULL)
        return STATUS_INVALID_PARAMETER;

    // Empty string
    if (path->Length < 2)
    {
        *name = *path;
        return STATUS_NOT_FOUND;
    }

    for (USHORT i = (path->Length / sizeof(WCHAR)) - 1; i != 0; i--)
    {
        if (path->Buffer[i] == L'\\' || path->Buffer[i] == L'/')
        {
            name->Buffer = &path->Buffer[i + 1];
            name->Length = name->MaximumLength = path->Length - (i + 1) * sizeof(WCHAR);
            return STATUS_SUCCESS;
        }
    }

    *name = *path;
    return STATUS_NOT_FOUND;
}

/// <summary>
/// Get directory path name from full path
/// </summary>
/// <param name="path">Path</param>
/// <param name="name">Resulting directory path</param>
/// <returns>Status code</returns>
NTSTATUS StripFilename(IN PUNICODE_STRING path, OUT PUNICODE_STRING dir)
{
    ASSERT(path != NULL && dir);
    if (path == NULL || dir == NULL)
        return STATUS_INVALID_PARAMETER;

    // Empty string
    if (path->Length < 2)
    {
        *dir = *path;
        return STATUS_NOT_FOUND;
    }

    for (USHORT i = (path->Length / sizeof(WCHAR)) - 1; i != 0; i--)
    {
        if (path->Buffer[i] == L'\\' || path->Buffer[i] == L'/')
        {
            dir->Buffer = path->Buffer;
            dir->Length = dir->MaximumLength = i * sizeof(WCHAR);
            return STATUS_SUCCESS;
        }
    }

    *dir = *path;
    return STATUS_NOT_FOUND;
}

/// <summary>
/// Check if file exists
/// </summary>
/// <param name="path">Fully qualifid path to a file</param>
/// <returns>Status code</returns>
NTSTATUS FileExists(IN PUNICODE_STRING path)
{
    HANDLE hFile = NULL;
    IO_STATUS_BLOCK statusBlock = { 0 };
    OBJECT_ATTRIBUTES obAttr = { 0 };
    InitializeObjectAttributes(&obAttr, path, OBJ_KERNEL_HANDLE, NULL, NULL);

    NTSTATUS status = ZwCreateFile(
        &hFile, FILE_READ_DATA | SYNCHRONIZE, &obAttr,
        &statusBlock, NULL, FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ, FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0
    );

    if (NT_SUCCESS(status))
        ZwClose(hFile);

    return status;
}

/// <summary>
/// Search for pattern
/// </summary>
/// <param name="pattern">Pattern to search for</param>
/// <param name="wildcard">Used wildcard</param>
/// <param name="len">Pattern length</param>
/// <param name="base">Base address for searching</param>
/// <param name="size">Address range to search in</param>
/// <param name="ppFound">Found location</param>
/// <returns>Status code</returns>
NTSTATUS SearchPattern(IN PCUCHAR pattern, IN UCHAR wildcard, IN ULONG_PTR len, IN const VOID* base, IN ULONG_PTR size, OUT PVOID* ppFound)
{
    ASSERT(ppFound != NULL && pattern != NULL && base != NULL);
    if (ppFound == NULL || pattern == NULL || base == NULL)
        return STATUS_INVALID_PARAMETER;

    for (ULONG_PTR i = 0; i < size - len; i++)
    {
        BOOLEAN found = TRUE;
        for (ULONG_PTR j = 0; j < len; j++)
        {
            if (pattern[j] != wildcard && pattern[j] != ((PCUCHAR)base)[i + j])
            {
                found = FALSE;
                break;
            }
        }

        if (found != FALSE)
        {
            *ppFound = (PUCHAR)base + i;
            return STATUS_SUCCESS;
        }
    }

    return STATUS_NOT_FOUND;
}

/*
    GetKernelExportAddr
*/
PVOID GetKernelExportAddr(PCWSTR fName) {
    UNICODE_STRING fNameUStr;
    RtlInitUnicodeString(&fNameUStr, fName);
    PVOID result = MmGetSystemRoutineAddress(&fNameUStr);
    if (!result || !MmIsAddressValid(result)) {
        LogError("MmGetSystemRoutineAddress Get Address Fail %wZ", fNameUStr);
    }
    return result;
}

typedef struct _IMAGE_FILE_HEADER {
    WORD    Machine;
    WORD    NumberOfSections;
    DWORD   TimeDateStamp;
    DWORD   PointerToSymbolTable;
    DWORD   NumberOfSymbols;
    WORD    SizeOfOptionalHeader;
    WORD    Characteristics;
} IMAGE_FILE_HEADER, * PIMAGE_FILE_HEADER;

typedef struct _IMAGE_DATA_DIRECTORY {
    DWORD   VirtualAddress;
    DWORD   Size;
} IMAGE_DATA_DIRECTORY, * PIMAGE_DATA_DIRECTORY;

#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES    16

typedef struct _IMAGE_OPTIONAL_HEADER64 {
    WORD        Magic;
    BYTE        MajorLinkerVersion;
    BYTE        MinorLinkerVersion;
    DWORD       SizeOfCode;
    DWORD       SizeOfInitializedData;
    DWORD       SizeOfUninitializedData;
    DWORD       AddressOfEntryPoint;
    DWORD       BaseOfCode;
    ULONGLONG   ImageBase;
    DWORD       SectionAlignment;
    DWORD       FileAlignment;
    WORD        MajorOperatingSystemVersion;
    WORD        MinorOperatingSystemVersion;
    WORD        MajorImageVersion;
    WORD        MinorImageVersion;
    WORD        MajorSubsystemVersion;
    WORD        MinorSubsystemVersion;
    DWORD       Win32VersionValue;
    DWORD       SizeOfImage;
    DWORD       SizeOfHeaders;
    DWORD       CheckSum;
    WORD        Subsystem;
    WORD        DllCharacteristics;
    ULONGLONG   SizeOfStackReserve;
    ULONGLONG   SizeOfStackCommit;
    ULONGLONG   SizeOfHeapReserve;
    ULONGLONG   SizeOfHeapCommit;
    DWORD       LoaderFlags;
    DWORD       NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER64, * PIMAGE_OPTIONAL_HEADER64;


typedef struct _IMAGE_NT_HEADERS64 {
    DWORD Signature;
    IMAGE_FILE_HEADER FileHeader;
    IMAGE_OPTIONAL_HEADER64 OptionalHeader;
} IMAGE_NT_HEADERS64, * PIMAGE_NT_HEADERS64;

typedef IMAGE_NT_HEADERS64                  IMAGE_NT_HEADERS;
typedef PIMAGE_NT_HEADERS64                 PIMAGE_NT_HEADERS;
#define IMAGE_FIRST_SECTION( ntheader ) ((PIMAGE_SECTION_HEADER)        \
    ((ULONG_PTR)(ntheader) +                                            \
     FIELD_OFFSET( IMAGE_NT_HEADERS, OptionalHeader ) +                 \
     ((ntheader))->FileHeader.SizeOfOptionalHeader   \
    ))

NTSTATUS GetTextRegion(PDRIVER_OBJECT DriverObject, PAddressRegion region) {
    // 获取当前驱动模块信息
    PLDR_DATA_TABLE_ENTRY module_entry = (PLDR_DATA_TABLE_ENTRY)DriverObject->DriverSection;
    PVOID driver_base = module_entry->DllBase;
    PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)driver_base;
    PIMAGE_NT_HEADERS nt_headers = (PIMAGE_NT_HEADERS)((ULONG_PTR)driver_base + dos_header->e_lfanew);
    // 遍历节表
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(nt_headers);
    for (USHORT i = 0; i < nt_headers->FileHeader.NumberOfSections; i++, section++) {
        if (strcmp((CHAR*)section->Name, ".text") == 0) {
            ULONG_PTR code_start = (ULONG_PTR)driver_base + section->VirtualAddress;
            ULONG_PTR code_end = (ULONG_PTR)code_start + section->Misc.VirtualSize;
            // return DriverRegion{code_start , code_end };
            LogInfo("DriverRegion: 0x%p - 0x%p\n", code_start, code_end);
            region->start = (PVOID)code_start;
            region->end = (PVOID)code_end;
            return STATUS_SUCCESS;
        }
    }
    return STATUS_UNSUCCESSFUL;
}


NTSTATUS GetUserCodeRange(HANDLE ProcessId, PAddressRegion region) {
    PEPROCESS target_process;
    NTSTATUS status = PsLookupProcessByProcessId(ProcessId, &target_process);
    if (!NT_SUCCESS(status)) return status;

    KAPC_STATE apc_state;
    KeStackAttachProcess(target_process, &apc_state);

    UNICODE_STRING routine_name;
    RtlInitUnicodeString(&routine_name, L"PsGetProcessPeb");
    PVOID PsGetProcessPebAddr = MmGetSystemRoutineAddress(&routine_name);
    typedef PVOID(*_PsGetProcessPebType)(_In_ PEPROCESS Process);

    _PsGetProcessPebType _PsGetProcessPeb = (_PsGetProcessPebType)PsGetProcessPebAddr;

    PPEB64 peb = (PPEB64)_PsGetProcessPeb(target_process);
    PLDR_DATA_TABLE_ENTRY main_module = CONTAINING_RECORD(peb->Ldr->InLoadOrderModuleList.Flink, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
    PVOID exe_base = main_module->DllBase;

    __try {
        PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)exe_base;
        PIMAGE_NT_HEADERS nt_headers = (PIMAGE_NT_HEADERS)((ULONG_PTR)exe_base + dos_header->e_lfanew);

        PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(nt_headers);
        for (USHORT i = 0; i < nt_headers->FileHeader.NumberOfSections; i++, section++) {
            if (strcmp((CHAR*)section->Name, ".text") == 0) {
                ULONG_PTR code_start = (ULONG_PTR)exe_base + section->VirtualAddress;
                ULONG_PTR code_end = (ULONG_PTR)code_start + section->Misc.VirtualSize;
                LogInfo("UserCodeRange: 0x%p - 0x%p\n", code_start, code_end);
                region->start = (PVOID)code_start;
                region->end = (PVOID)code_end;
                KeUnstackDetachProcess(&apc_state);
                ObDereferenceObject(target_process);
                return STATUS_SUCCESS;
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        LogError("UserCodeRange Find Error");
    }
    KeUnstackDetachProcess(&apc_state);
    ObDereferenceObject(target_process);
    return STATUS_UNSUCCESSFUL;
}


ULONG_PTR GetModuleBase(ULONG pid, PCWSTR name) {
   
    PEPROCESS process;
    if (!NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)pid, &process))){
        LogError("PsLookupProcessByProcessId Fail %d", pid);
        return 0;
    }
   
    KAPC_STATE apcState;
    KeStackAttachProcess(process, &apcState);

    UNICODE_STRING moduleName;
    RtlInitUnicodeString(&moduleName, name);
    LogInfo("Finding Module %d, %wZ", pid, &moduleName);
    UNICODE_STRING PsGetProcessPebFunCName;
    RtlInitUnicodeString(&PsGetProcessPebFunCName, L"PsGetProcessPeb");
    PVOID PsGetProcessPebAddr = MmGetSystemRoutineAddress(&PsGetProcessPebFunCName);
    if (!PsGetProcessPebAddr) {
        LogError("PsGetProcessPeb Get Fail %d", pid);
        KeUnstackDetachProcess(&apcState);
        if (process) ObDereferenceObject(process);
        return 0;
    }
    typedef PVOID(*_PsGetProcessPebType)(_In_ PEPROCESS Process);
    _PsGetProcessPebType _PsGetProcessPeb = (_PsGetProcessPebType)PsGetProcessPebAddr;
   
    __try {
        if (_PsGetProcessPeb(process)){
            PPEB64 peb = (PPEB64)_PsGetProcessPeb(process);
            PLIST_ENTRY head = &peb->Ldr->InLoadOrderModuleList;

            for (PLIST_ENTRY entry = head->Flink; entry != head; entry = entry->Flink) {
                PLDR_DATA_TABLE_ENTRY module = CONTAINING_RECORD(entry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
                
                if (RtlCompareUnicodeString(&module->BaseDllName, &moduleName, TRUE) == 0) {
                    LogInfo("Find Module Base %p %wZ", (ULONG_PTR)module->DllBase, &module->BaseDllName);
                    KeUnstackDetachProcess(&apcState);
                    if (process) ObDereferenceObject(process);
                    return (ULONG_PTR)module->DllBase;
                }
                
                LogInfo("ModuleList Name %wZ", &module->BaseDllName);
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        LogInfo("Module Not Find  [UNKNOWN] %wZ", &moduleName);
    }
    KeUnstackDetachProcess(&apcState);
    if (process) ObDereferenceObject(process);
    LogError("Module Not Find  [UNKNOWN] %wZ", &moduleName);
    return 0;

}


NTSTATUS RtlForceDeleteFile(PUNICODE_STRING pFilePath) {
    NTSTATUS Status = STATUS_SUCCESS;
    HANDLE hFile = NULL;
    LPBYTE pFileObject = NULL;
    IO_STATUS_BLOCK IoStatusBlock;
    OBJECT_ATTRIBUTES ObjectAttributes;

    InitializeObjectAttributes(&ObjectAttributes, pFilePath, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, 0, 0);
    Status = IoCreateFileEx(&hFile, SYNCHRONIZE | DELETE, &ObjectAttributes, &IoStatusBlock, NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_DELETE, FILE_OPEN, FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0, CreateFileTypeNone, NULL, IO_NO_PARAMETER_CHECKING, NULL);
    if (!NT_SUCCESS(Status)) {
        return STATUS_UNSUCCESSFUL;
    }

    Status = ObReferenceObjectByHandleWithTag(hFile, SYNCHRONIZE | DELETE, *IoFileObjectType, KernelMode, 'ELIF', (LPVOID*)&pFileObject, NULL);
    if (NT_SUCCESS(Status)) {
        ((PFILE_OBJECT)pFileObject)->SectionObjectPointer->ImageSectionObject = NULL;
        if (MmFlushImageSection(((PFILE_OBJECT)pFileObject)->SectionObjectPointer, MmFlushForDelete)) {
            Status = ZwDeleteFile(&ObjectAttributes);
        }
        ObfDereferenceObject(pFileObject);
    }
    ObCloseHandle(hFile, KernelMode);
    return Status;
}


BOOL Compare(LPBYTE pAddress, PCHAR Pattern, PCHAR Mask, DWORD MaskLen) {

    for (SIZE_T i = 0; i < MaskLen; i++) {

        if (Mask[i] == 'x' && pAddress[i] != (BYTE)(Pattern[i])) {

            return FALSE;
        }
    }

    return TRUE;
}

LPBYTE SearchSignForMemory(LPBYTE MemoryBase, DWORD Length, PCHAR Pattern, PCHAR Mask, DWORD MaskLen) {

    for (DWORD Index = NULL; Index < (DWORD)(Length - MaskLen); Index++) {

        LPBYTE pTempAddress = &MemoryBase[Index];

        if (Compare(pTempAddress, Pattern, Mask, MaskLen)) {

            return pTempAddress;
        }
    }

    return NULL;
}


PVOID SearchSignForImage(PVOID ImageBase, CHAR* Pattern, CHAR* Mask, unsigned long MaskLen){

    LPBYTE Result = NULL;

    if (ImageBase != NULL) {

        PIMAGE_NT_HEADERS Headers = (PIMAGE_NT_HEADERS)((LPBYTE)ImageBase + ((PIMAGE_DOS_HEADER)ImageBase)->e_lfanew);;

        PIMAGE_SECTION_HEADER Sections = IMAGE_FIRST_SECTION(Headers);

        for (DWORD Index = NULL; Index < Headers->FileHeader.NumberOfSections; ++Index) {

            PIMAGE_SECTION_HEADER pSection = &Sections[Index];

            if (RtlEqualMemory(pSection->Name, ".text", 5)) {

                Result = SearchSignForMemory((LPBYTE)ImageBase + pSection->VirtualAddress, pSection->Misc.VirtualSize, Pattern, Mask, MaskLen);

                if (Result != NULL) {

                    break;
                }
            }
        }
    }

    return Result;
}

auto ZwQuerySystemInformation(ULONG SystemInformationClass, LPVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength)->NTSTATUS {

    typedef NTSTATUS(NTAPI* fn_ZwQuerySystemInformation)(ULONG, LPVOID, ULONG, PULONG);

    static fn_ZwQuerySystemInformation _ZwQuerySystemInformation = NULL;

    NTSTATUS Status = STATUS_UNSUCCESSFUL;

    if (_ZwQuerySystemInformation == NULL) {

        _ZwQuerySystemInformation = (fn_ZwQuerySystemInformation)(GetKernelExportAddr(L"ZwQuerySystemInformation"));
    }

    if (_ZwQuerySystemInformation != NULL) {

        Status = _ZwQuerySystemInformation(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);
    }

    return Status;
}

auto RtlAllocateMemory(SIZE_T Size)->LPBYTE {
    /*
        
    系统标签：'MmSt'（内存管理器）、'NtFs'（NTFS 驱动）、'CMgb'（配置管理器）。
    第三方驱动标签：'NDIS'（网络驱动）、'dxg'（DirectX 相关）。

    */
    LPBYTE Result = (LPBYTE)(ExAllocatePoolWithTag(NonPagedPool, Size, 'Gt'));

    if (Result != NULL) {

        //RtlFillMemory(Result,0, Size);
        RtlZeroMemory(Result, Size);
    }

    return Result;
}

auto RtlFreeMemoryEx(LPVOID pDst)->VOID {

    if (pDst != NULL) {

        ExFreePoolWithTag(pDst, 'Gt');

        pDst = NULL;
    }
}

typedef struct _SYSTEM_MODULE_INFORMATION_ENTRY {
    PBYTE Section;
    PBYTE MappedBase;
    PBYTE ImageBase;
    ULONG ImageSize;
    ULONG Flags;
    SHORT LoadOrderIndex;
    SHORT InitOrderIndex;
    SHORT LoadCount;
    SHORT PathLength;
    CHAR ImageName[256];
} SYSTEM_MODULE_INFORMATION_ENTRY, * PSYSTEM_MODULE_INFORMATION_ENTRY;

typedef struct _SYSTEM_MODULE_INFORMATION {
    ULONG NumberOfModules;
    SYSTEM_MODULE_INFORMATION_ENTRY Modules[1];
} SYSTEM_MODULE_INFORMATION, * PSYSTEM_MODULE_INFORMATION;

typedef enum _SYSTEM_INFORMATION_CLASS {
    SystemBasicInformation = 0x0,
    SystemProcessorInformation = 0x1,
    SystemPerformanceInformation = 0x2,
    SystemTimeOfDayInformation = 0x3,
    SystemPathInformation = 0x4,
    SystemProcessInformation = 0x5,
    SystemCallCountInformation = 0x6,
    SystemDeviceInformation = 0x7,
    SystemProcessorPerformanceInformation = 0x8,
    SystemFlagsInformation = 0x9,
    SystemCallTimeInformation = 0xa,
    SystemModuleInformation = 0xb,
    SystemLocksInformation = 0xc,
    SystemStackTraceInformation = 0xd,
    SystemNonPagedPoolInformation = 0xe,
    SystemNonNonPagedPoolInformation = 0xf,
    SystemHandleInformation = 0x10,
    SystemObjectInformation = 0x11,
    SystemPageFileInformation = 0x12,
    SystemVdmInstemulInformation = 0x13,
    SystemVdmBopInformation = 0x14,
    SystemFileCacheInformation = 0x15,
    SystemPoolTagInformation = 0x16,
    SystemInterruptInformation = 0x17,
    SystemDpcBehaviorInformation = 0x18,
    SystemFullMemoryInformation = 0x19,
    SystemLoadGdiDriverInformation = 0x1a,
    SystemUnloadGdiDriverInformation = 0x1b,
    SystemTimeAdjustmentInformation = 0x1c,
    SystemSummaryMemoryInformation = 0x1d,
    SystemMirrorMemoryInformation = 0x1e,
    SystemPerformanceTraceInformation = 0x1f,
    SystemObsolete0 = 0x20,
    SystemExceptionInformation = 0x21,
    SystemCrashDumpStateInformation = 0x22,
    SystemKernelDebuggerInformation = 0x23,
    SystemContextSwitchInformation = 0x24,
    SystemRegistryQuotaInformation = 0x25,
    SystemExtendServiceTableInformation = 0x26,
    SystemPrioritySeperation = 0x27,
    SystemVerifierAddDriverInformation = 0x28,
    SystemVerifierRemoveDriverInformation = 0x29,
    SystemProcessorIdleInformation = 0x2a,
    SystemLegacyDriverInformation = 0x2b,
    SystemCurrentTimeZoneInformation = 0x2c,
    SystemLookasideInformation = 0x2d,
    SystemTimeSlipNotification = 0x2e,
    SystemSessionCreate = 0x2f,
    SystemSessionDetach = 0x30,
    SystemSessionInformation = 0x31,
    SystemRangeStartInformation = 0x32,
    SystemVerifierInformation = 0x33,
    SystemVerifierThunkExtend = 0x34,
    SystemSessionProcessInformation = 0x35,
    SystemLoadGdiDriverInSystemSpace = 0x36,
    SystemNumaProcessorMap = 0x37,
    SystemPrefetcherInformation = 0x38,
    SystemExtendedProcessInformation = 0x39,
    SystemRecommendedSharedDataAlignment = 0x3a,
    SystemComPlusPackage = 0x3b,
    SystemNumaAvailableMemory = 0x3c,
    SystemProcessorPowerInformation = 0x3d,
    SystemEmulationBasicInformation = 0x3e,
    SystemEmulationProcessorInformation = 0x3f,
    SystemExtendedHandleInformation = 0x40,
    SystemLostDelayedWriteInformation = 0x41,
    SystemBigPoolInformation = 0x42,
    SystemSessionPoolTagInformation = 0x43,
    SystemSessionMappedViewInformation = 0x44,
    SystemHotpatchInformation = 0x45,
    SystemObjectSecurityMode = 0x46,
    SystemWatchdogTimerHandler = 0x47,
    SystemWatchdogTimerInformation = 0x48,
    SystemLogicalProcessorInformation = 0x49,
    SystemWow64SharedInformationObsolete = 0x4a,
    SystemRegisterFirmwareTableInformationHandler = 0x4b,
    SystemFirmwareTableInformation = 0x4c,
    SystemModuleInformationEx = 0x4d,
    SystemVerifierTriageInformation = 0x4e,
    SystemSuperfetchInformation = 0x4f,
    SystemMemoryListInformation = 0x50,
    SystemFileCacheInformationEx = 0x51,
    SystemThreadPriorityClientIdInformation = 0x52,
    SystemProcessorIdleCycleTimeInformation = 0x53,
    SystemVerifierCancellationInformation = 0x54,
    SystemProcessorPowerInformationEx = 0x55,
    SystemRefTraceInformation = 0x56,
    SystemSpecialPoolInformation = 0x57,
    SystemProcessIdInformation = 0x58,
    SystemErrorPortInformation = 0x59,
    SystemBootEnvironmentInformation = 0x5a,
    SystemHypervisorInformation = 0x5b,
    SystemVerifierInformationEx = 0x5c,
    SystemTimeZoneInformation = 0x5d,
    SystemImageFileExecutionOptionsInformation = 0x5e,
    SystemCoverageInformation = 0x5f,
    SystemPrefetchPatchInformation = 0x60,
    SystemVerifierFaultsInformation = 0x61,
    SystemSystemPartitionInformation = 0x62,
    SystemSystemDiskInformation = 0x63,
    SystemProcessorPerformanceDistribution = 0x64,
    SystemNumaProximityNodeInformation = 0x65,
    SystemDynamicTimeZoneInformation = 0x66,
    SystemCodeIntegrityInformation = 0x67,
    SystemProcessorMicrocodeUpdateInformation = 0x68,
    SystemProcessorBrandString = 0x69,
    SystemVirtualAddressInformation = 0x6a,
    SystemLogicalProcessorAndGroupInformation = 0x6b,
    SystemProcessorCycleTimeInformation = 0x6c,
    SystemStoreInformation = 0x6d,
    SystemRegistryAppendString = 0x6e,
    SystemAitSamplingValue = 0x6f,
    SystemVhdBootInformation = 0x70,
    SystemCpuQuotaInformation = 0x71,
    SystemNativeBasicInformation = 0x72,
    SystemErrorPortTimeouts = 0x73,
    SystemLowPriorityIoInformation = 0x74,
    SystemBootEntropyInformation = 0x75,
    SystemVerifierCountersInformation = 0x76,
    SystemNonPagedPoolInformationEx = 0x77,
    SystemSystemPtesInformationEx = 0x78,
    SystemNodeDistanceInformation = 0x79,
    SystemAcpiAuditInformation = 0x7a,
    SystemBasicPerformanceInformation = 0x7b,
    SystemQueryPerformanceCounterInformation = 0x7c,
    SystemSessionBigPoolInformation = 0x7d,
    SystemBootGraphicsInformation = 0x7e,
    SystemScrubPhysicalMemoryInformation = 0x7f,
    SystemBadPageInformation = 0x80,
    SystemProcessorProfileControlArea = 0x81,
    SystemCombinePhysicalMemoryInformation = 0x82,
    SystemEntropyInterruptTimingInformation = 0x83,
    SystemConsoleInformation = 0x84,
    SystemPlatformBinaryInformation = 0x85,
    SystemThrottleNotificationInformation = 0x86,
    SystemHypervisorProcessorCountInformation = 0x87,
    SystemDeviceDataInformation = 0x88,
    SystemDeviceDataEnumerationInformation = 0x89,
    SystemMemoryTopologyInformation = 0x8a,
    SystemMemoryChannelInformation = 0x8b,
    SystemBootLogoInformation = 0x8c,
    SystemProcessorPerformanceInformationEx = 0x8d,
    SystemSpare0 = 0x8e,
    SystemSecureBootPolicyInformation = 0x8f,
    SystemPageFileInformationEx = 0x90,
    SystemSecureBootInformation = 0x91,
    SystemEntropyInterruptTimingRawInformation = 0x92,
    SystemPortableWorkspaceEfiLauncherInformation = 0x93,
    SystemFullProcessInformation = 0x94,
    SystemKernelDebuggerInformationEx = 0x95,
    SystemBootMetadataInformation = 0x96,
    SystemSoftRebootInformation = 0x97,
    SystemElamCertificateInformation = 0x98,
    SystemOfflineDumpConfigInformation = 0x99,
    SystemProcessorFeaturesInformation = 0x9a,
    SystemRegistryReconciliationInformation = 0x9b,
    SystemSupportedProcessArchitectures = 0xb5,
} SYSTEM_INFORMATION_CLASS;

DYNDATA DynamicData;

NTSTATUS KernelStart(PVOID pThisModule) {

    NTSTATUS Status = STATUS_UNSUCCESSFUL;
    auto _pThisModule = (PKLDR_DATA_TABLE_ENTRY)pThisModule;

    LPBYTE NtOpenFile = (LPBYTE)GetKernelExportAddr(L"NtOpenFile");

    if (NtOpenFile != NULL) {

        ULONG Size = NULL;

        Status = ZwQuerySystemInformation(SystemModuleInformation, NULL, Size, &Size);
       
        if (!NT_SUCCESS(Status) && Size != NULL) {

            PSYSTEM_MODULE_INFORMATION pMods = (PSYSTEM_MODULE_INFORMATION)(RtlAllocateMemory(Size));

            if (pMods != NULL) {

                Status = ZwQuerySystemInformation(SystemModuleInformation, pMods, Size, &Size);
                if (!NT_SUCCESS(Status)) {
                    RtlFreeMemoryEx(pMods);
                    return Status;
                }
                LogInfo("ZwQuerySystemInformation2 Success");
                // return Status;

                PSYSTEM_MODULE_INFORMATION_ENTRY pMod = pMods->Modules;

                for (ULONG Index = NULL; Index < pMods->NumberOfModules; Index++) {
                    if (NtOpenFile >= pMod[Index].ImageBase && NtOpenFile < (LPBYTE)(pMod[Index].ImageBase + pMod[Index].ImageSize)) {
                        for (PLIST_ENTRY pListEntry = _pThisModule->InLoadOrderLinks.Flink; pListEntry != &_pThisModule->InLoadOrderLinks; pListEntry = pListEntry->Flink) {

                            PKLDR_DATA_TABLE_ENTRY pEntry = CONTAINING_RECORD(pListEntry, KLDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

                            if (pMod[Index].ImageBase == pEntry->DllBase && (LPBYTE)pListEntry->Blink >= pEntry->DllBase && (LPBYTE)pListEntry->Blink < (LPBYTE)pEntry->DllBase + pEntry->SizeOfImage) {

                                //DynamicData->KernelBase = (PVOID)(pMod[Index].ImageBase);

                                // DynamicData->ModuleList = (PVOID)(pListEntry->Blink);
                                LogInfo("KernelBase Find Success");
                                break;
                            }
                        }
                    }
                    
                }

                RtlFreeMemoryEx(pMods);
            }
        }
    }

    return Status;
}

