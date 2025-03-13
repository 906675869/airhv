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


  9. hook Ewtwrite 函数，清理/伪造系统日志痕迹 （具体思路需要按调试后调整）
    
  
