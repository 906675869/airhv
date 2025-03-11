// Test.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include<Windows.h>
#include <winternl.h>
#include <iostream>
#define IOCTL_TEST CTL_CODE(FILE_DEVICE_UNKNOWN, 0x901, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#include "Share.h"
#pragma comment(lib, "Ntdll.lib") 

#define MASK_KEY 0x7758258

#ifndef METHOD_BUFFERED
#define METHOD_BUFFERED                 0
#endif

#ifndef CTL_CODE
#define CTL_CODE( DeviceType, Function, Method, Access ) (                 \
    ((DeviceType) << 16) | ((Access) << 14) | ((Function) << 2) | (Method) \
)
#endif

#ifndef FILE_ANY_ACCESS
#define FILE_ANY_ACCESS                 0
#endif

#ifndef KEYBOARD_DEVICE
#define KEYBOARD_DEVICE      0
#endif

#ifndef MOUSE_DEVICE
#define MOUSE_DEVICE         1
#endif
//
// Define the various device type values.  Note that values used by Microsoft
// Corporation are in the range 0-0x7FFF(32767), and 0x8000(32768)-0xFFFF(65535)
// are reserved for use by customers.
//
#define FILE_DEVICE_KEYMOUSE	0x8000

//
// Macro definition for defining IOCTL and FSCTL function control codes. Note
// that function codes 0-0x7FF(2047) are reserved for Microsoft Corporation,
// and 0x800(2048)-0xFFF(4095) are reserved for customers.
//
#define KEYMOUSE_IOCTL_BASE 0x800

//
// The device driver IOCTLs

//
#define CTL_CODE_KEYMOUSE(i)	(ULONG)(CTL_CODE(FILE_DEVICE_KEYMOUSE, KEYMOUSE_IOCTL_BASE + i, METHOD_BUFFERED, FILE_ANY_ACCESS))
#define IOCTL_KEYBOARD       	CTL_CODE_KEYMOUSE(0)
#define IOCTL_MOUSE	            CTL_CODE_KEYMOUSE(1)

//
// Name that Win32 front end will use to open the KeyMouse device
//


#define KEYMOUSE_DEVICE_NAME		    L"\\Device\\kmclass"
#define KEYMOUSE_DOS_DEVICE_NAME	    L"\\DosDevices\\kmclass"

#ifdef  UNICODE
#define KEYMOUSE_WIN32_DEVICE_NAME	    L"\\\\.\\kmclass"
#define KEYMOUSE_DRIVER_NAME            L"kmclass"
#else
#define KEYMOUSE_WIN32_DEVICE_NAME	    "\\\\.\\kmclass"
#define KEYMOUSE_DRIVER_NAME            "kmclass"
#endif


typedef struct _KEYBOARD_INPUT_DATA {

	USHORT UnitId;

	USHORT MakeCode;

	USHORT Flags;

	USHORT Reserved;

	ULONG ExtraInformation;

} KEYBOARD_INPUT_DATA, * PKEYBOARD_INPUT_DATA;

//
// Define the keyboard input data Flags.
//

#define KEY_MAKE  0
#define KEY_BREAK 1
#define KEY_E0    2
#define KEY_E1    4
#define KEY_TERMSRV_SET_LED 8
#define KEY_TERMSRV_SHADOW  0x10
#define KEY_TERMSRV_VKPACKET 0x20

#define KEY_DOWN                KEY_MAKE
#define KEY_UP                  KEY_BREAK
#define KEY_BLANK                -1


typedef struct _MOUSE_INPUT_DATA {

	USHORT UnitId;

	USHORT Flags;

	union {
		ULONG Buttons;
		struct {
			USHORT  ButtonFlags;
			USHORT  ButtonData;
		};
	};

	ULONG RawButtons;

	LONG LastX;

	LONG LastY;

	ULONG ExtraInformation;

} MOUSE_INPUT_DATA, * PMOUSE_INPUT_DATA;

//
// Define the mouse button state indicators.
//

#define MOUSE_LEFT_BUTTON        0x0001
#define MOUSE_RIGHT_BUTTON       0x0002
#define MOUSE_LEFT_BUTTON_DOWN   0x0001  // Left Button changed to down.
#define MOUSE_LEFT_BUTTON_UP     0x0002  // Left Button changed to up.
#define MOUSE_RIGHT_BUTTON_DOWN  0x0004  // Right Button changed to down.
#define MOUSE_RIGHT_BUTTON_UP    0x0008  // Right Button changed to up.
#define MOUSE_MIDDLE_BUTTON_DOWN 0x0010  // Middle Button changed to down.
#define MOUSE_MIDDLE_BUTTON_UP   0x0020  // Middle Button changed to up.

#define MOUSE_BUTTON_1_DOWN     MOUSE_LEFT_BUTTON_DOWN
#define MOUSE_BUTTON_1_UP       MOUSE_LEFT_BUTTON_UP
#define MOUSE_BUTTON_2_DOWN     MOUSE_RIGHT_BUTTON_DOWN
#define MOUSE_BUTTON_2_UP       MOUSE_RIGHT_BUTTON_UP
#define MOUSE_BUTTON_3_DOWN     MOUSE_MIDDLE_BUTTON_DOWN
#define MOUSE_BUTTON_3_UP       MOUSE_MIDDLE_BUTTON_UP

#define MOUSE_BUTTON_4_DOWN     0x0040
#define MOUSE_BUTTON_4_UP       0x0080
#define MOUSE_BUTTON_5_DOWN     0x0100
#define MOUSE_BUTTON_5_UP       0x0200

#define MOUSE_WHEEL             0x0400

//
// Define the mouse indicator flags.
//

#define MOUSE_MOVE_RELATIVE         0
#define MOUSE_MOVE_ABSOLUTE         1
#define MOUSE_VIRTUAL_DESKTOP    0x02  // the coordinates are mapped to the virtual desktop
#define MOUSE_ATTRIBUTES_CHANGED 0x04  // requery for mouse attributes

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
	/*MemData data = {
		13,
		(PVOID)0x271,
		10,
		r
	};*/

	KEYBOARD_INPUT_DATA  kid;
	DWORD dwOutput;
	memset(&kid, 0, sizeof(KEYBOARD_INPUT_DATA));
	kid.Flags = KEY_DOWN;

	kid.MakeCode = (USHORT)MapVirtualKey(VK_NUMPAD5, 0);


	ConnectData cdata = {
		MASK_KEY,
		ConnectType::KEY,
		& kid
	};
	ConnectDevice(&cdata, sizeof(ConnectData));
	auto result = *(ULONG64*)r;


	 
	memset(&kid, 0, sizeof(KEYBOARD_INPUT_DATA));
	kid.Flags = KEY_UP;

		kid.MakeCode = (USHORT)MapVirtualKey(VK_NUMPAD5, 0);


	 cdata = {
		MASK_KEY,
		ConnectType::KEY,
		&kid
	};
	ConnectDevice(&cdata, sizeof(ConnectData));

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
	Sleep(3000);
	TestConnect();
	getchar();
	CloseHandle(handle);

	

	return 0;
}

