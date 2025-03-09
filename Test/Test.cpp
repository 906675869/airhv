// Test.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//
#include<Windows.h>
#include <iostream>
#define IOCTL_TEST CTL_CODE(FILE_DEVICE_UNKNOWN, 0x901, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#include "Share.h"


int main()
{
	//HANDLE handle = CreateFileA("\\\\.\\airhv", GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	//if (handle == INVALID_HANDLE_VALUE) {
	//	MessageBoxA(0, "打开设备失败", "错误", 0);
	//	return 0;
	//}
	//unsigned char buffer[50] = { 0 };
	//unsigned char buffer2[50] = { 0 };
	//DWORD len;
	//// sprintf((char*)buffer, "hello, driver\r\n");
	//if (DeviceIoControl(handle, IOCTL_TEST, buffer, strlen((char*)buffer), buffer2, 49, &len, NULL)) {
	//	printf("len: %d\n", len);
	//	for (int i = 0; i < len; i++) {
	//		printf("0x%02X ", buffer2[i]);
	//	}
	//}
	//getchar();
	//CloseHandle(handle);
	std::cout << std::hex << IOCTL_AFD_SEND << std::endl;
	std::cout << std::hex << IOCTL_AFD_SEND_DATAGRAM << std::endl;
	

	return 0;
}

