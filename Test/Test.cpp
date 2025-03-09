// Test.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include<Windows.h>
#include <winternl.h>
#include <iostream>
#define IOCTL_TEST CTL_CODE(FILE_DEVICE_UNKNOWN, 0x901, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#include "Share.h"
#pragma comment(lib, "Ntdll.lib") 

#define MASK_KEY 0x7758258

enum ConnectType{
	TEST,
	PROTECT_FILE, // 保护文件
	HIDE_R3_MEM,// 隐藏R3内存
	HIDE_R0_MEM,// 隐藏R0内存
	READ, // 读取
	WRITE,// 写入
	READ_PHY,// 读取物理内存
	WRITE_PHY,// 写入物理内存
	ALLOC, // 申请内存
	KEY,
	MOUSE
};

struct ConnectData{
	ULONG MaskKey;
	ULONG ConnectType; //ConnectType
	PVOID Data; // MemData KeyData MouseData
};

struct MemData {
	ULONG pid;// 目标进程id
	PVOID address;
	ULONG size;
	PVOID bytes; // 读取的内存|写入的内存
};


struct KeyData {



};

struct MouseData {


};

typedef NTSTATUS(NTAPI* PNtCreateFile)(
	PHANDLE FileHandle,
	ACCESS_MASK DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	PIO_STATUS_BLOCK IoStatusBlock,
	PLARGE_INTEGER AllocationSize,
	ULONG FileAttributes,
	ULONG ShareAccess,
	ULONG CreateDisposition,
	ULONG CreateOptions,
	PVOID EaBuffer,
	ULONG EaLength
	);


bool ConnectDevice(PVOID EaBuffer, ULONG EaLength);




bool ConnectDevice(PVOID EaBuffer, ULONG EaLength) {
	HMODULE ntdll = LoadLibrary(L"ntdll.dll");
	if (ntdll == NULL) {
		// Handle error: failed to load ntdll.dll
		return 1;
	}
	PNtCreateFile NtCreateFileFunc = (PNtCreateFile)GetProcAddress(ntdll, "NtCreateFile");
	if (NtCreateFileFunc == NULL) {
		// Handle error: failed to get NtCreateFile address
		FreeLibrary(ntdll);
		return 1;
	}
	HANDLE hFile;
	IO_STATUS_BLOCK ioStatusBlock;
	OBJECT_ATTRIBUTES objectAttributes;
	UNICODE_STRING name;
	RtlInitUnicodeString(&name, L"\\??\\C:\\log.txt"); // Example path in NT namespace format.
	InitializeObjectAttributes(&objectAttributes, &name, OBJ_CASE_INSENSITIVE, NULL, NULL); // Adjust attributes as needed.
	NTSTATUS status = NtCreateFileFunc(&hFile, GENERIC_READ | GENERIC_WRITE, &objectAttributes, &ioStatusBlock, NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ | FILE_SHARE_WRITE,
		NULL, FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT | FILE_OPEN_FOR_BACKUP_INTENT, EaBuffer, EaLength);

	if (!NT_SUCCESS(status)) {
		// Handle error: failed to create/open file
		FreeLibrary(ntdll);
		return 1;
	}
	CloseHandle(hFile); // Don't forget to close the handle!
	FreeLibrary(ntdll); // Unload the library when done.
}

void TestConnect() {
	PVOID r = malloc(20);
	MemData data = {
		13,
		(PVOID)0x271,
		10,
		r
	};
	ConnectData cdata = {
		MASK_KEY,
		ConnectType::READ,
		&data
	};
	ConnectDevice(&cdata, sizeof(ConnectData));
	auto result = *(ULONG64*)r;
	std::cout << std::hex <<result << std::endl;
}










int main()
{
	HANDLE handle = CreateFileA("\\\\.\\airhv", GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (handle == INVALID_HANDLE_VALUE) {
		MessageBoxA(0, "打开设备失败", "错误", 0);
		return 0;
	}
	unsigned char buffer[50] = { 0 };
	unsigned char buffer2[50] = { 0 };
	DWORD len;
	// sprintf((char*)buffer, "hello, driver\r\n");
	if (DeviceIoControl(handle, IOCTL_TEST, buffer, strlen((char*)buffer), buffer2, 49, &len, NULL)) {
		printf("len: %d\n", len);
		for (int i = 0; i < len; i++) {
			printf("0x%02X ", buffer2[i]);
		}
	}
	TestConnect();
	getchar();
	CloseHandle(handle);

	

	return 0;
}

