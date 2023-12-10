#pragma warning( disable : 4201 4805)
#include "utils.h"
#include <ntddk.h>
#include <intrin.h>
#include "log.h"
#include "ntapi.h"
#include "hypervisor_routines.h"
#include "hypervisor_gateway.h"
#include "vmm.h"


#include "kmclass.h"
#include "cm.h"
#include "bypass.h"

#define IOCTL_POOL_MANAGER_ALLOCATE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x900, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)

__vmm_context* g_vmm_context = 0;

 VOID driver_unload(PDRIVER_OBJECT driver_object)
 {
	 RegisterNotifyInit(false);
	 ProtectKernelAddrInit(false);
	 ProtectProcessInit(false);
	 ProtectFileInit(false);

	 hvgt::hypervisor_visible(true);

	 UNICODE_STRING dos_device_name;
	 if(g_vmm_context != NULL)
	 {
		 if (g_vmm_context->vcpu_table[0]->vcpu_status.vmm_launched == true)
		 {
			 hvgt::unhook_all_functions();
			 hvgt::vmoff();
		 }
	 }

	 hv::disable_vmx_operation();
	 free_vmm_context();

	/* RtlInitUnicodeString(&dos_device_name, L"\\DosDevices\\airhv");
	 IoDeleteSymbolicLink(&dos_device_name);
	 IoDeleteDevice(driver_object->DeviceObject);*/
 }


extern "C"
NTSTATUS DriverEntry(PDRIVER_OBJECT driver_object, PCUNICODE_STRING reg) 
{
	UNREFERENCED_PARAMETER(reg);

	NTSTATUS status = STATUS_SUCCESS;

	driver_object->DriverUnload = driver_unload;

	//PDEVICE_OBJECT device_object = NULL;
	//UNICODE_STRING driver_name, dos_device_name;

	//RtlInitUnicodeString(&driver_name, L"\\Device\\airhv");
	//RtlInitUnicodeString(&dos_device_name, L"\\DosDevices\\airhvctrl");

	//status = IoCreateDevice(driver_object, 0, &driver_name, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &device_object);
	//if (status == STATUS_SUCCESS)
	//{
	//	driver_object->DriverUnload = driver_unload;
	//	driver_object->Flags |= DO_BUFFERED_IO;
	//	IoCreateSymbolicLink(&dos_device_name, &driver_name);
	//}
	////
	// Check if our cpu support virtualization
	//
	if (!hv::virtualization_support()) {
		LogError("VMX operation is not supported on this processor.\n");
		return STATUS_FAILED_DRIVER_ENTRY;
	}

	//
	// Initialize and start virtual machine
	// If it fails turn off vmx and deallocate all structures
	//
	if(vmm_init() == false)
	{
		hv::disable_vmx_operation();
		free_vmm_context();
		LogError("Vmm initialization failed");
		return STATUS_FAILED_DRIVER_ENTRY;
	}

	// 搜索键盘
	status = SearchKdbServiceCallBack(driver_object);
	if (!NT_SUCCESS(status))
	{
		DbgPrint("KEYBOARD_DEVICE ERROR, error = 0x%08lx\n", status);
		return status;
	}
	//// 搜索鼠标
	status = SearchMouServiceCallBack(driver_object);
	if (!NT_SUCCESS(status))
	{
		DbgPrint("MOUSE_DEVICE ERROR, error = 0x%08lx\n", status);
		return status;
	}
	driverData.kernelBase = GetKernelBase(driver_object);
	if (!driverData.kernelBase) {
		return status;
	}
	// 通讯初始化
	RegisterNotifyInit(true);

	hvgt::hypervisor_visible(false);
	// 内核保护初始化
	ProtectKernelAddrInit(true);
	//// 把当前驱动的文本段加入
	AddressRegion ar;
	GetDriverTextRegion(driver_object, &ar);
	PPROTECT_KERNEL_ADDR addr = (PPROTECT_KERNEL_ADDR)&ar;
	AddProtectKernelAddr(addr);
	// 保护用户进程不被打开
	ProtectProcessInit(true); 
	// 保护文件不被打开
	ProtectFileInit(true);
	if (driver_object)
		RtlForceDeleteFile(&((PKLDR_DATA_TABLE_ENTRY)driver_object->DriverSection)->FullDllName);

	return status;
}