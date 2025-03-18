#pragma warning( disable : 4201 4805)
#include <ntifs.h>
#include <ntddk.h>


#include <intrin.h>
#include "utils.h"
#include "log.h"
#include "NtStruct.h"
#include <minwindef.h>

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


ULONG_PTR GetModuleBase(ULONG pid, WCHAR* name) {
    PEPROCESS process;
    PsLookupProcessByProcessId((HANDLE)pid, &process);
    UNICODE_STRING routine_name;
    RtlInitUnicodeString(&routine_name, L"PsGetProcessPeb");
    PVOID PsGetProcessPebAddr = MmGetSystemRoutineAddress(&routine_name);
    typedef PVOID(*_PsGetProcessPebType)(_In_ PEPROCESS Process);

    _PsGetProcessPebType _PsGetProcessPeb = (_PsGetProcessPebType)PsGetProcessPebAddr;
    UNICODE_STRING moduleName;
    RtlInitUnicodeString(&moduleName,name);
    __try {
        if (_PsGetProcessPeb(process))
        {
            PPEB64 peb = (PPEB64)_PsGetProcessPeb(process);
            PLIST_ENTRY head = &peb->Ldr->InLoadOrderModuleList;

            for (PLIST_ENTRY entry = head->Flink; entry != head; entry = entry->Flink) {
                PLDR_DATA_TABLE_ENTRY module = CONTAINING_RECORD(entry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
                if (RtlEqualUnicodeString(&module->BaseDllName, &moduleName, FALSE)) {
                    LogInfo("Find Module Base %p", (ULONG_PTR)module->DllBase);
                    return (ULONG_PTR)module->DllBase;
                }
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        LogInfo("Module Not Find  [UNKNOWN] %wZ", moduleName);
    }
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


auto GetTextHashA(PCSTR Str)->UINT32 {

	UINT32 Hash = NULL;

	while (Str != NULL && *Str) {

		Hash = (UINT32)(65599 * (Hash + (*Str++) + (*Str > 64 && *Str < 91 ? 32 : 0)));
	}

	return Hash;
}

auto GetTextHashW(PCWSTR Str)->UINT {

	UINT32 Hash = NULL;

	while (Str != NULL && *Str) {

		Hash = (UINT32)(65599 * (Hash + (*Str++) + (*Str > 64 && *Str < 91 ? 32 : 0)));
	}

	return Hash;
}

