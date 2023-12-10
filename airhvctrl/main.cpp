#include <ntifs.h>
#include "hypervisor_gateway.h"
#include "log.h"
#include "nt.h"
#include "NtStruct.h"
#include "Utils.h"


extern void* kernel_code_caves[200];

PVOID base;
ULONG maxLen = 0x2000;

void* nt_create_file_address;
void* nt_query_system_information;
void* nt_open_process;
void* mm_is_address_vaild;
void* prop_for_read;
void* rtl_copy_memory;

PVOID pAllocFromPool;

NTSTATUS(NTAPI* OriginalNtQuerySystemInformation)(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength);


NTSTATUS(*original_nt_create_file)(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes,
	PIO_STATUS_BLOCK IoStatusBlock, PLARGE_INTEGER AllocationSize, ULONG FileAttributes,
	ULONG ShareAccess, ULONG CreateDisposition, ULONG CreateOptions, PVOID EaBuffer, ULONG EaLength
	);

NTSTATUS
(*OriginalNtOpenProcess)(
	_Out_ PHANDLE ProcessHandle,
	_In_ ACCESS_MASK DesiredAccess,
	_In_ POBJECT_ATTRIBUTES ObjectAttributes,
	_In_opt_ PCLIENT_ID ClientId
);

BOOLEAN (*OriginalMmIsAddressValid)(
	_In_ PVOID VirtualAddress
);


VOID (*OriginalProbeForRead)(
	__in_data_source(USER_MODE) _In_reads_bytes_(Length) volatile VOID* Address,
	_In_ SIZE_T Length,
	_In_ ULONG Alignment
);

void (*OriginalRtlCopyMemory)(PVOID Destination, PVOID Source, size_t Length);

void HookedRtlCopyMemory(PVOID Destination, PVOID Source, size_t Length) {
	LogInfo("HookedRtlCopyMemory Start cheat...Source=%xll", Source);
	if ((ULONG64)Source >= (ULONG64)base && (ULONG64)Source <= (ULONG64)base + maxLen) {
		LogInfo("HookedRtlCopyMemory Start cheat...base=%xll", base);
		PVOID pAllocFromPool = ExAllocatePoolWithTag(NonPagedPoolNx, Length +0x10, 'AA');
		if (pAllocFromPool) {
			RtlZeroMemory(pAllocFromPool, Length + 0x10);
			OriginalRtlCopyMemory(Destination, pAllocFromPool, Length);
			ExFreePoolWithTag(pAllocFromPool, 'AA');
		}
	}
	else {
		OriginalRtlCopyMemory(Destination, pAllocFromPool, Length);
	}

}


BOOLEAN HookedMmIsAddressValid(_In_ PVOID VirtualAddress) {
	if (VirtualAddress == base) {
		LogError("HookedMmIsAddressValid Execute %llx, %llx", VirtualAddress, base);
		// LogError("nt_open_process addr is %X", nt_open_process);
		return false;
	}
	return OriginalMmIsAddressValid(VirtualAddress);
}

VOID HookedProbeForRead(volatile VOID* Address,_In_ SIZE_T Length,_In_ ULONG Alignment) {
	if (Address == base) {
		LogError("HookedProbeForRead Execute %llx, %llx Ready To Except", Address, base);
		ASSERT(Address > 0);
	}
	OriginalProbeForRead(Address, Length, Alignment);
}


NTSTATUS NTAPI HookedNtQuerySystemInformation(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength)
{
	NTSTATUS Status = OriginalNtQuerySystemInformation(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);
	if (!NT_SUCCESS(Status)) {
		return Status;
	}
	// PEPROCESS CurrentProcess = IoGetCurrentProcess();
	if (SystemInformationClass == SystemProcessInformation ||
		SystemInformationClass == SystemExtendedProcessInformation ||
		SystemInformationClass == SystemFullProcessInformation )
	{
		LogError("HookedNtQuerySystemInformation execute...");
		PSYSTEM_PROCESS_INFO ProcessInfo = (PSYSTEM_PROCESS_INFO)SystemInformation;

		for (PSYSTEM_PROCESS_INFO Entry = ProcessInfo; Entry->NextEntryOffset != NULL; Entry = (PSYSTEM_PROCESS_INFO)((UCHAR*)Entry + Entry->NextEntryOffset))
		{
			UNICODE_STRING ProcessImageName;
			RtlCreateUnicodeString(&ProcessImageName, L"notepad.exe");
			PSYSTEM_PROCESS_INFO pre = nullptr;
			if ((int)(Entry->ProcessId) == 2104)
			{
				 LogError("ProcessName:%s ½ø³Ìid:2104", Entry->ImageName.Buffer);
				if (pre != nullptr) {
					if (Entry->NextEntryOffset == 0) {
						pre->NextEntryOffset = 0;
					}
					else {
						pre->NextEntryOffset = pre->NextEntryOffset + Entry->NextEntryOffset;
					}
				}
				else {
					ProcessInfo = (PSYSTEM_PROCESS_INFO)((UCHAR*)Entry + Entry->NextEntryOffset);
				}
			}
			else {
				pre = Entry;
			}
			
		}
	}
	return Status;
}




NTSTATUS NTAPI hooked_nt_create_file(
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
)
{
	__try
	{
		ProbeForRead(FileHandle, sizeof(HANDLE), 1);
		ProbeForRead(ObjectAttributes, sizeof(OBJECT_ATTRIBUTES), 1);
		ProbeForRead(ObjectAttributes->ObjectName, sizeof(UNICODE_STRING), 1);
		ProbeForRead(ObjectAttributes->ObjectName->Buffer, ObjectAttributes->ObjectName->Length, 1);
		if (wcsstr(ObjectAttributes->ObjectName->Buffer, L"test.txt") != NULL)
		{
			return STATUS_INVALID_BUFFER_SIZE;
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{

	}
	return original_nt_create_file(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, AllocationSize, FileAttributes, ShareAccess, CreateDisposition, CreateOptions, EaBuffer, EaLength);
}


NTSTATUS HookedNtOpenProcess(OUT PHANDLE ProcessHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	IN PCLIENT_ID ClientId) {
	LogError("HookedNtOpenProcess, execute...");
	auto PreMode = ExGetPreviousMode();
	if (PreMode != KernelMode)
	{
		__try
		{
			ProbeForRead(ClientId, sizeof(CLIENT_ID), sizeof(ULONG));
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			return GetExceptionCode();
		}
	}

	if (ClientId != NULL)
	{
		auto PID = (ULONG)ClientId->UniqueProcess;

		// LogError("HookedNtOpenProcess, execute...%d", PID);
		if (PID > 1000)
		{
			LogError("HookedNtOpenProcess, DENIED...%d", PID);
			return STATUS_ACCESS_DENIED;
		}
		/*if (PID == 1684) {
			LogError("HookedNtOpenProcess, DENIED...%d", PID);
			return STATUS_ACCESS_DENIED;
		}*/

	}

	return OriginalNtOpenProcess(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);
}



VOID driver_unload(PDRIVER_OBJECT driver_object)
{
	UNICODE_STRING dos_device_name;

	//hvgt::unhook_function(nt_create_file_address);
	//// hvgt::unhook_function(nt_open_process);
	//hvgt::unhook_function(mm_is_address_vaild);
	//hvgt::unhook_function(prop_for_read);
	hvgt::unhook_function(rtl_copy_memory);

	RtlInitUnicodeString(&dos_device_name, L"\\DosDevices\\airhvctrl");
	IoDeleteSymbolicLink(&dos_device_name);
	IoDeleteDevice(driver_object->DeviceObject);
}

NTSTATUS driver_create_close(_In_ PDEVICE_OBJECT device_object, _In_ PIRP irp)
{
	UNREFERENCED_PARAMETER(device_object);

	irp->IoStatus.Status = STATUS_SUCCESS;
	irp->IoStatus.Information = 0;

	IoCompleteRequest(irp, IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}

NTSTATUS driver_ioctl_dispatcher(_In_ PDEVICE_OBJECT device_object, _In_ PIRP irp)
{
	UNREFERENCED_PARAMETER(device_object);
	unsigned __int32 bytes_io = 0;

	NTSTATUS status = STATUS_SUCCESS;

	irp->IoStatus.Status = status;
	irp->IoStatus.Information = bytes_io;

	IoCompleteRequest(irp, IO_NO_INCREMENT);
	return status;
}

extern "C"
NTSTATUS DriverEntry(PDRIVER_OBJECT driver_object, PCUNICODE_STRING reg)
{
	UNREFERENCED_PARAMETER(reg);

	NTSTATUS status = STATUS_SUCCESS;
	PDEVICE_OBJECT device_oject = 0;
	UNICODE_STRING driver_name, dos_device_name;

	RtlInitUnicodeString(&driver_name, L"\\Device\\airhvctrl");
	RtlInitUnicodeString(&dos_device_name, L"\\DosDevices\\airhvctrl");

	status = IoCreateDevice(driver_object, 0, &driver_name, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &device_oject);

	if (status == STATUS_SUCCESS)
	{
		driver_object->MajorFunction[IRP_MJ_CLOSE] = driver_create_close;
		driver_object->MajorFunction[IRP_MJ_CREATE] = driver_create_close;
		driver_object->MajorFunction[IRP_MJ_DEVICE_CONTROL] = driver_ioctl_dispatcher;

		driver_object->DriverUnload = driver_unload;
		driver_object->Flags |= DO_BUFFERED_IO;
		IoCreateSymbolicLink(&dos_device_name, &driver_name);


		
		// ULONG size = pEntry->SizeOfImage;
	}
	ULONG BufferSize = 0;
	typedef struct
	{
		PVOID section;
		PVOID MappedBase;
		PVOID ImageBase;
		ULONG ImageSize;
		ULONG Flags;
		USHORT LoadOrderIndex;
		USHORT InitOrderIndex;
		USHORT LoadCount;
		USHORT PathLength;
		char ImageName[MAXIMUM_FILENAME_LENGTH];

	}SYSTEM_MODULE, * PSYSTEM_MODULE;

	typedef struct
	{
		ULONG ModuleCount;
		SYSTEM_MODULE Module[0];
	}SYSTEM_MODULE_INFORMATION, * PSYSTEM_MODULE_INFORMATION;
	ZwQuerySystemInformation(SystemModuleInformation, NULL, 0, &BufferSize);
	PSYSTEM_MODULE_INFORMATION pSystemModuleInformation = NULL;
	pSystemModuleInformation = (PSYSTEM_MODULE_INFORMATION)ExAllocatePool(PagedPool, BufferSize);
	if (pSystemModuleInformation == NULL)
	{
		LogError("ExAllocatePool failed!\n");
		return STATUS_UNSUCCESSFUL;
	}
	NTSTATUS ntStatus = ZwQuerySystemInformation(SystemModuleInformation, pSystemModuleInformation, BufferSize, NULL);
	if (!NT_SUCCESS(ntStatus))
	{
		LogError("ZwQuerySystemInformation failed!\n");
		ExFreePool(pSystemModuleInformation);
		return ntStatus;
	} 
	PSYSTEM_MODULE pSystemModule = NULL;
	pSystemModule = pSystemModuleInformation->Module;
	
	for (int i = 0; i < pSystemModuleInformation->ModuleCount; i++)
	{
		/*LogError("LoadIndex=%d  \tImageBase=0x%016xll \tImageSize=0x%08X\tImageName=%s\n",
			pSystemModule[i].LoadOrderIndex,
			pSystemModule[i].ImageBase,
			pSystemModule[i].ImageSize,
			pSystemModule[i].ImageName);*/
		if (strcmp(pSystemModule[i].ImageName, "\\??\\C:\\Users\\WY\\Desktop\\airhvctrl.sys") == 0) {
			base = (PVOID)pSystemModule[i].ImageBase;
			maxLen = pSystemModule[i].ImageSize;
			LogError("LoadIndex=%d  \tImageBase=%xll \tImageSize=0x%08X\tImageName=%s\n",
				pSystemModule[i].LoadOrderIndex,
				pSystemModule[i].ImageBase,
				pSystemModule[i].ImageSize,
				pSystemModule[i].ImageName);
		}

	}
	if (base == 0) {
		PLDR_DATA_TABLE_ENTRY pEntry = (PLDR_DATA_TABLE_ENTRY)driver_object->DriverSection;
		base = (PVOID)(&pEntry->DllBase);
		LogError("base is 0");
	}
	


	//UNICODE_STRING routine_name;
	//RtlInitUnicodeString(&routine_name,L"NtCreateFile");

	//// Get address of NtCreateFile syscall
	//nt_create_file_address = MmGetSystemRoutineAddress(&routine_name);
	//if (!nt_create_file_address)
	//{
	//	LogError("Couldn't find NtCreateFile address");
	//	return STATUS_UNSUCCESSFUL;
	//}

	//UNICODE_STRING routine_name2;
	//RtlInitUnicodeString(&routine_name2, L"NtQuerySystemInformation");
	//nt_query_system_information = MmGetSystemRoutineAddress(&routine_name2);
	//if (!nt_query_system_information)
	//{
	//	LogError("Couldn't find NtQuerySystemInformation address");
	//	return STATUS_UNSUCCESSFUL;
	//}

	//UNICODE_STRING routine_name3;
	//RtlInitUnicodeString(&routine_name3, L"NtOpenProcess");
	//nt_open_process = MmGetSystemRoutineAddress(&routine_name3);
	//if (!nt_open_process)
	//{
	//	LogError("Couldn't find NtOpenProcess address");
	//	return STATUS_UNSUCCESSFUL;
	//}

	//// 1 byte hook by using icebp instruction
	//if (!hvgt::hook_function(nt_create_file_address, hooked_nt_create_file, (void**)&original_nt_create_file))
	//{
	//	LogError("Couldn't hook NtCreateFile");
	//	return STATUS_UNSUCCESSFUL;
	//}

	//if (!hvgt::hook_function(nt_query_system_information, HookedNtQuerySystemInformation, (void**)&OriginalNtQuerySystemInformation))
	//{
	//	LogError("Couldn't HookedNtQuerySystemInformation");
	//	return STATUS_UNSUCCESSFUL;
	//}

	/*if (!hvgt::hook_function(nt_open_process, HookedNtOpenProcess, (void**)&OriginalNtOpenProcess))
	{
		LogError("Couldn't HookedNtQuerySystemInformation");
		return STATUS_UNSUCCESSFUL;
	}*/

	/*pAllocFromPool = ExAllocatePoolWithTag(NonPagedPoolNx, 1024, 0371);
	if (pAllocFromPool) {
		RtlZeroMemory(pAllocFromPool, 1024);*/

		
		/*auto misAddrValid = MmIsAddressValid(base);
		if (!misAddrValid) {
			LogError("Hook Before: MmIsAddressValid Get Result is False");
		}
		else {
			LogError("Hook Before:MmIsAddressValid Get Result is False");
		}
		mm_is_address_vaild = (void*)&MmIsAddressValid;
		if (!hvgt::hook_function(mm_is_address_vaild, HookedMmIsAddressValid, (void**)&OriginalMmIsAddressValid))
		{
			LogError("Couldn't HookedNtQuerySystemInformation");
			return STATUS_UNSUCCESSFUL;
		}
		misAddrValid = MmIsAddressValid(base);
		if (!misAddrValid) {
			LogError("MmIsAddressValid Get Result is False");
		}
		__try
		{
			ProbeForRead(base,0x29, 1);
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			LogError("Hook Before: ProbeForRead pAllocFromPool Get Result is False");
		}

		prop_for_read = (PVOID)&ProbeForRead;

		if (!hvgt::hook_function(prop_for_read, HookedProbeForRead, (void**)&OriginalProbeForRead))
		{
			LogError("Couldn't HookedProbeForRead");
			return STATUS_UNSUCCESSFUL;
		}
		__try
		{
			ProbeForRead(base, 0x29, 1);
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			LogError("Hook After:ProbeForRead pAllocFromPool Get Result is False");
		}*/

	//}
	//else {
	//	LogError("ExAllocatePoolWithTag Fail");
	//}
	
	PVOID pAllocFromPool = ExAllocatePoolWithTag(NonPagedPoolNx, 0x100, 'AB');
	if (pAllocFromPool) {
		RtlZeroMemory(pAllocFromPool, 0x100);
		RtlCopyMemory(pAllocFromPool, base, 0x20);
		LogInfo("Before HOOK RtlCopyMemory the first %d", *(char*)pAllocFromPool);
	}
	rtl_copy_memory = (void*)&memccpy;
	//rtl_copy_memory = (void*)&memcpy;

	if (!hvgt::hook_function(rtl_copy_memory, HookedRtlCopyMemory, (void**)&OriginalRtlCopyMemory))
	{
		LogError("Couldn't HookedRtlCopyMemory");
		if (pAllocFromPool) {
			ExFreePoolWithTag(pAllocFromPool, 'AB');
		}
		return STATUS_UNSUCCESSFUL;
	}

	if (pAllocFromPool) {
		RtlZeroMemory(pAllocFromPool, 0x100);
		LogInfo("Base Addr is %xll", base);
		RtlCopyMemory(pAllocFromPool, base, 0x20);
		LogInfo("After HOOK RtlCopyMemory the first %d", *(char*)pAllocFromPool);
		ExFreePoolWithTag(pAllocFromPool, 'AB');
	}
	

	hvgt::send_irp_perform_allocation();

	return status;
}