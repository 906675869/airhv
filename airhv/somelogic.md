1.CreateFileHook <黑名单模式,只管新增>

2.RtlFramWalkChain
  内核&用户 代码段

3.MemIsAddressVaild
  内核 代码段

4.ProperForRead
  用户 代码段

5.注册进程退出回调
  杀掉守护进程

6.句柄伪装思路，r3 返回请求打开句柄的进程 r0 直接拦截


代码片段：

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
          ULONG_PTR code_end = code_start + section->Misc.VirtualSize;
          DbgPrint("驱动代码段: 0x%p - 0x%p\n", code_start, code_end);
          break;
      }
  }


NTSTATUS GetUserCodeRange(HANDLE ProcessId) {
    PEPROCESS target_process;
    NTSTATUS status = PsLookupProcessByProcessId(ProcessId, &target_process);
    if (!NT_SUCCESS(status)) return status;

    KAPC_STATE apc_state;
    KeStackAttachProcess(target_process, &apc_state);

    PPEB peb = PsGetProcessPeb(target_process);
    PLDR_DATA_TABLE_ENTRY main_module = CONTAINING_RECORD(peb->Ldr->InLoadOrderModuleList.Flink, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
    PVOID exe_base = main_module->DllBase;

    __try {
        PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)exe_base;
        PIMAGE_NT_HEADERS nt_headers = (PIMAGE_NT_HEADERS)((ULONG_PTR)exe_base + dos_header->e_lfanew);
        
        PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(nt_headers);
        for (USHORT i = 0; i < nt_headers->FileHeader.NumberOfSections; i++, section++) {
            if (strcmp((CHAR*)section->Name, ".text") == 0) {
                ULONG_PTR code_start = (ULONG_PTR)exe_base + section->VirtualAddress;
                ULONG_PTR code_end = code_start + section->Misc.VirtualSize;
                DbgPrint("用户代码段: 0x%p - 0x%p\n", code_start, code_end);
                break;
            }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        DbgPrint("访问用户内存失败\n");
    }

    KeUnstackDetachProcess(&apc_state);
    ObDereferenceObject(target_process);
    return STATUS_SUCCESS;
}



    
  
