#include "utils.h"
#include "tools.h"


ULONG_PTR GetModuleBaseByHashW(ULONG pid, UINT32 moduleHash) {
    PEPROCESS process;
    if (!NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)pid, &process))) {
        DbgPrint("PsLookupProcessByProcessId Fail %d", pid);
        return 0;
    }
    KAPC_STATE apcState;
    KeStackAttachProcess(process, &apcState);

    PVOID PsGetProcessPebAddr = GetKernelFunction(L"PsGetProcessPeb");
    if (!PsGetProcessPebAddr) {
        DbgPrint("PsGetProcessPeb Get Fail %d", pid);
        KeUnstackDetachProcess(&apcState);
        if (process) ObDereferenceObject(process);
        return 0;
    }
    typedef PVOID(*_PsGetProcessPebType)(_In_ PEPROCESS Process);
    _PsGetProcessPebType _PsGetProcessPeb = (_PsGetProcessPebType)PsGetProcessPebAddr;

    __try {
        if (_PsGetProcessPeb(process)) {
            PPEB64 peb = (PPEB64)_PsGetProcessPeb(process);
            PLIST_ENTRY head = &peb->Ldr->InLoadOrderModuleList;

            for (PLIST_ENTRY entry = head->Flink; entry != head; entry = entry->Flink) {
                PLDR_DATA_TABLE_ENTRY module = CONTAINING_RECORD(entry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
                if (GetTextHashW(module->BaseDllName.Buffer) == moduleHash) {
                    DbgPrint("Find Module Base %p %wZ", module->DllBase, &module->BaseDllName);
                    KeUnstackDetachProcess(&apcState);
                    if (process) ObDereferenceObject(process);
                    return (ULONG_PTR)module->DllBase;
                }
                DbgPrint("ModuleList Name %wZ", &module->BaseDllName);
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        DbgPrint("Module Not Find  [UNKNOWN] %ul", moduleHash);
    }
    KeUnstackDetachProcess(&apcState);
    if (process) ObDereferenceObject(process);
    DbgPrint("Module Not Find  [UNKNOWN] %ul", moduleHash);
    return 0;
}

ULONG_PTR GetModuleBase(ULONG pid, PCWSTR moduleName)
{
    PEPROCESS process;
    if (!NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)pid, &process))) {
        DbgPrint("PsLookupProcessByProcessId Fail %d", pid);
        return 0;
    }
    // moduleName 用户传入，复制到内核中
    ULONG len = (wcslen(moduleName) + 1) * sizeof(WCHAR);
    PVOID nhModuleName = ExAllocatePoolWithTag(NonPagedPool, (SIZE_T)len, 'NetF');
    if (!nhModuleName) {
        DbgPrint("ExAllocatePoolWithTag Fail %d", pid);
        return 0;
    }
    RtlCopyMemory(nhModuleName, (PVOID)moduleName, (SIZE_T)len);

    ULONG_PTR moduleBase = 0;

    UNICODE_STRING moduleNameUStr;
    RtlInitUnicodeString(&moduleNameUStr, (PCWSTR)nhModuleName);

    PVOID PsGetProcessPebAddr = GetKernelFunction(L"PsGetProcessPeb");
    if (!PsGetProcessPebAddr) {
        DbgPrint("PsGetProcessPeb Get Fail %d", pid);
        if (process) ObDereferenceObject(process);
        return 0;
    }

    typedef PVOID(*_PsGetProcessPebType)(_In_ PEPROCESS Process);
    _PsGetProcessPebType _PsGetProcessPeb = (_PsGetProcessPebType)PsGetProcessPebAddr;

    KAPC_STATE apcState;
    KeStackAttachProcess(process, &apcState);



    __try {
        PPEB64 peb = (PPEB64)_PsGetProcessPeb(process);
        if (peb && peb->Ldr) {
            PLIST_ENTRY head = &peb->Ldr->InLoadOrderModuleList;

            for (PLIST_ENTRY entry = head->Flink; entry != head; entry = entry->Flink) {
                PLDR_DATA_TABLE_ENTRY module = CONTAINING_RECORD(entry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
                if (!module->BaseDllName.Buffer) {
                    continue;
                }
                UNICODE_STRING cModuleNameUStr;
                RtlInitUnicodeString(&cModuleNameUStr, module->BaseDllName.Buffer);
                // DbgPrint("Loop ModuleList Name %wZ  | len=%d", &cModuleNameUStr, cModuleNameUStr.Length);
                // DbgPrint("Querying ModuleList Name %wZ | len=%d", &moduleNameUStr,  moduleNameUStr.Length);
                if (RtlEqualUnicodeString(&moduleNameUStr, &cModuleNameUStr, TRUE)) {
                    //DbgPrint("Find Module Base %wZ", &module->BaseDllName);
                    moduleBase = (ULONG_PTR)module->DllBase;
                    /* KeUnstackDetachProcess(&apcState);
                     if (process) ObDereferenceObject(process);*/
                     //return  (ULONG_PTR)module->DllBase;
                    break;
                }
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        DbgPrint("Module Not Find 4 except [UNKNOWN] %wZ", moduleNameUStr);
    }
    KeUnstackDetachProcess(&apcState);
    if (process) ObDereferenceObject(process);
    ExFreePoolWithTag(nhModuleName, 'NetF');
    /* if (moduleBase == 0) {
         DbgPrint("Module Not Find  [UNKNOWN] %wZ", moduleNameUStr);
     }*/

    return moduleBase;
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


PVOID SearchSignForImage(PVOID ImageBase, CHAR* Pattern, CHAR* Mask, unsigned long MaskLen) {

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

PVOID GetKernelBase(PDRIVER_OBJECT driver_object) {
    PLDR_DATA_TABLE_ENTRY pDriverList;
    PLIST_ENTRY pCurrentList;

    pDriverList = (PLDR_DATA_TABLE_ENTRY)(driver_object->DriverSection);
    pCurrentList = (PLIST_ENTRY)pDriverList;

    UNICODE_STRING moduleName;
    RtlInitUnicodeString(&moduleName, L"ntoskrnl.exe");

    PVOID kernelBase = NULL;
    while (((PLIST_ENTRY)pDriverList)->Blink != pCurrentList)
    {
        UNICODE_STRING cmoduleName;
        RtlInitUnicodeString(&cmoduleName, (pDriverList->BaseDllName).Buffer);

        if (RtlEqualUnicodeString(&moduleName, &cmoduleName, FALSE)) {
            kernelBase = (PVOID)pDriverList->DllBase;
            DbgPrint("Find ntoskrnl.exe success, base is 0x%p", kernelBase);
        }
        pDriverList = (PLDR_DATA_TABLE_ENTRY)((PLIST_ENTRY)pDriverList)->Blink;
    }
    return kernelBase;
}


NTSTATUS GetDriverTextRegion(PDRIVER_OBJECT DriverObject, AR region) {
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
            region->start = (PVOID)code_start;
            region->end = (PVOID)code_end;
            return STATUS_SUCCESS;
        }
    }
    return STATUS_UNSUCCESSFUL;
}


/*
    判断虚拟地址是否可写
*/
BOOLEAN IsWritableEx(PEPROCESS TargetProcess, PVOID addr) {
    MEMORY_BASIC_INFORMATION MemInfo;
    NTSTATUS status;
    SIZE_T ReturnLength;
    KAPC_STATE ApcState;

    // 3.查询内存页信息
    typedef NTSTATUS(*fn_NtQueryVirtualMemory)(
        HANDLE ProcessHandle,
        PVOID BaseAddress,
        MEMORY_INFORMATION_CLASS MemoryInformationClass,
        PVOID MemoryInformation,
        SIZE_T MemoryInformationLength,
        PSIZE_T ReturnLength
        );
    fn_NtQueryVirtualMemory _NtQueryVirtualMemory = (fn_NtQueryVirtualMemory)GetKernelFunction(L"ZwQueryVirtualMemory");
    if (!_NtQueryVirtualMemory) {
        return false;
    }
    // 2. 附加到目标进程的地址空间
    KeStackAttachProcess(TargetProcess, &ApcState);
    status = _NtQueryVirtualMemory(
        NtCurrentProcess(),  // 使用当前进程句柄（已附加到目标进程）
        addr,
        MemoryBasicInformation,
        &MemInfo,
        sizeof(MemInfo),
        &ReturnLength
    );

    // 4. 恢复原始地址空间
    KeUnstackDetachProcess(&ApcState);

    if (!NT_SUCCESS(status)) return FALSE;

    // 检查保护标志是否包含可写权限
    return (MemInfo.Protect & (PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;
}