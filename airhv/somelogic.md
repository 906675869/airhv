1.CreateFile Hook <黑名单模式,只管新增> 通信首选
  ReadFile HooK <黑名单模式> 返回 000（优选，防止CreateFile失败 其增加异常分值）

2.RtlFramWalkChain
  内核&用户 代码段 &&受保护的代码段部分（如shellcode注入的区域）
  清理或替换堆栈空间地址
  用户态可用 用户进程中 可信模块部分（如ntdll.dll）
  内核态可用 可信驱动部分（如 ace-base.sys）

3.MemIsAddressVaild
  内核 代码段

4.ProperForRead
  用户 代码段 

  注意：已上内存保护均无法避免指针读取，和memcpy等方式，（内核中官方写法应保证健壮性，一般会增加内存判断）
  而用户态则可以直接读取（可HOOK VirtualQuery 返回 rwx 为 readonly 降低扫描）

  VirtualQuery : 
  黑名单模式，指定进程id的指定页（一般由内核直接分配），查询其读写属性时为只读

5.注册进程退出回调
  杀掉守护进程，卸载驱动

6.句柄伪装思路，r3 返回请求打开句柄的进程 r0 直接拦截

7.驱动通信加密思路

    maskKey: 0x7758258
    sonkey : GetRandomRgn(0x100, 0x200) 
    tl: GetTicket() >> 3
    
    using key : sonkey < 3 XOR maskKey
    
    pid xor key
    address xor key
    
    用户态：
    // 秒级
    auto now = std::chrono::system_clock::now();
    auto sec_since_epoch = std::chrono::duration_cast<std::chrono::seconds>(now.time_since_epoch()).count();
    
    
    内核态
    LARGE_INTEGER SystemTime;
    KeQuerySystemTime(&SystemTime); // 获取 1601 基准的 100ns 单位时间
    UnixTime.QuadPart = SystemTime.QuadPart - EPOCH_OFFSET; // 转换为 1970 基准
    return UnixTime.QuadPart / 10000 / 1000; // 转换为秒
    
    校验：
    
    math.abs(tl-tl2) > 30 ? banbanban ： pass
    
 8. 源代码防破解思路
    vmprotect <字符串加密>



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

    // 获取用户的代码段地址  
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

    // 在文件中读取文件的中的偏移和大小
    NTSTATUS ParsePeHeader(HANDLE FileHandle, ULONG_PTR* codeStart, ULONG* codeSize) {
      // 读取PE头
      IO_STATUS_BLOCK ioStatus;
      LARGE_INTEGER offset = {0};
      UCHAR peHeader[0x1000];
      NTSTATUS status = ZwReadFile(FileHandle, NULL, NULL, NULL, &ioStatus, peHeader, 0x1000, &offset, NULL);
      if (!NT_SUCCESS(status)) return status;
  
      // 解析.text段
      PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)peHeader;
      PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((ULONG_PTR)dos + dos->e_lfanew);
      PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(nt);
      for (USHORT i = 0; i < nt->FileHeader.NumberOfSections; i++, section++) {
          if (strncmp((CHAR*)section->Name, ".text", 5) == 0) {
              *codeStart = section->PointerToRawData;
              *codeSize = section->SizeOfRawData;
              return STATUS_SUCCESS;
          }
      }
      return STATUS_NOT_FOUND;
    }

    // 定义原始函数指针
    typedef NTSTATUS (*NtReadFile_t)(
        HANDLE, HANDLE, PIO_APC_ROUTINE, PVOID,
        PIO_STATUS_BLOCK, PVOID, ULONG, PLARGE_INTEGER, PULONG
    );
    NtReadFile_t OriginalNtReadFile;

    // Hook 函数
    NTSTATUS HookedNtReadFile(
        HANDLE FileHandle,
        HANDLE Event,
        PIO_APC_ROUTINE ApcRoutine,
        PVOID ApcContext,
        PIO_STATUS_BLOCK IoStatusBlock,
        PVOID Buffer,
        ULONG Length,
        PLARGE_INTEGER ByteOffset,
        PULONG Key
    ) {
        NTSTATUS status;
        BOOLEAN isTargetFile = FALSE;
        
        // 1. 获取文件路径
        PFILE_OBJECT fileObject;
        status = ObReferenceObjectByHandle(FileHandle, FILE_READ_DATA, *IoFileObjectType, KernelMode, (PVOID*)&fileObject, NULL);
        if (NT_SUCCESS(status)) {
            POBJECT_NAME_INFORMATION nameInfo;
            UNICODE_STRING targetPath = RTL_CONSTANT_STRING(L"\\??\\C:\\Target.exe");
            status = IoQueryFileDosDeviceName(fileObject, &nameInfo);
            if (NT_SUCCESS(status) && RtlCompareUnicodeString(&nameInfo->Name, &targetPath, TRUE) == 0) {
                isTargetFile = TRUE;
            }
            ExFreePool(nameInfo);
            ObDereferenceObject(fileObject);
        }
    
        // 2. 检查是否为代码段读取
        if (isTargetFile) {
            // 解析PE头获取.text段文件偏移和大小
            LARGE_INTEGER offset = {0};
            ULONG readSize = 0;
            if (ByteOffset) offset = *ByteOffset;
            else {
                // 若未指定偏移，需从文件当前位置获取（需同步处理）
                KPROCESSOR_MODE prevMode = ExGetPreviousMode();
                KeStackAttachProcess(PsGetCurrentProcess(), &apcState);
                status = ZwQueryInformationFile(FileHandle, IoStatusBlock, &offset, sizeof(offset), FilePositionInformation);
                KeUnstackDetachProcess(&apcState);
            }
    
            // 假设.text段文件偏移为0x400，大小0x1000
            if (offset.QuadPart >= 0x400 && offset.QuadPart < (0x400 + 0x1000)) {
                // 3. 伪造数据
                PVOID fakeData = ExAllocatePoolWithTag(NonPagedPool, Length, 'Fake');
                RtlFillMemory(fakeData, Length, 0x90); // 填充NOP指令
                __try {
                    ProbeForWrite(Buffer, Length, 1);
                    RtlCopyMemory(Buffer, fakeData, Length);
                    IoStatusBlock->Information = Length; // 伪造实际读取字节数
                } __except (EXCEPTION_EXECUTE_HANDLER) {
                    status = GetExceptionCode();
                }
                ExFreePool(fakeData);
                return status; // 直接返回，不调用原始函数
            }
        }
    
          // 4. 调用原始函数
          return OriginalNtReadFile(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, Buffer, Length, ByteOffset, Key);
    }

    


  9. hook Ewtwrite 函数，清理/伪造系统日志痕迹 （具体思路需要按调试后调整）
    
  
