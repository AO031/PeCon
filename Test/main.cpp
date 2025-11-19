#include<iostream>
#include<Windows.h>
// 首先加上编译选项 
_declspec(thread) int g_tlsNum = 100;
#ifdef _WIN64
#pragma comment(linker, "/INCLUDE:_tls_used")
#else
#pragma comment(linker, "/INCLUDE:__tls_used")
#endif


DWORD WINAPI threadProc(LPVOID lparam) {
	g_tlsNum = 300;
	printf("g_tlsNum=%d\n", g_tlsNum);
	return 0;
}

void NTAPI t_TlsCallBack_A(PVOID DllHandle, DWORD Reason, PVOID Reserved);

/*
	注册TLS函数，.CRT$XLX的作用
	CRT表示使用C Runtime库
	X表示标识名随机
	L表示 TLS Callback section
	X也可以换成B~Y任意一个字符

*/
// 注册 TLS 回调
#ifdef _WIN64
#pragma const_seg(".CRT$XLX") // x64 下用 const_seg（只读段）
EXTERN_C const // 禁用 C++ 的名称修饰 
#else
#pragma data_seg(".CRT$XLX") // x86 下用 data_seg（可读写段）
#endif

//存储回调函数地址 PIMAGE_TLS_CALLBACK pTLS_CALLBACKs，写了几个回调函就要往里面添加几个,最后必须要有一个0
PIMAGE_TLS_CALLBACK pTLS_CALLBACKs[] = { t_TlsCallBack_A,0 };

#ifdef _WIN64
#pragma const_seg()
#else
#pragma data_seg()
#endif


// 编写Tls回调函数 参数1：模块加载基址 参数2：调用的原因 参数3：保留
void NTAPI t_TlsCallBack_A(PVOID DllHandle, DWORD Reason, PVOID Reserved) {
	switch (Reason) {
	case DLL_PROCESS_ATTACH:
		printf("Hello Tls\n");
		break;
	case DLL_THREAD_ATTACH:
		break;
	case DLL_THREAD_DETACH:
		break;
	case DLL_PROCESS_DETACH:
		break;
	}
}

int main() {

	// 创建线程
	HANDLE hThread = CreateThread(NULL, NULL, threadProc, NULL, NULL, NULL);
	if (hThread) {
		WaitForSingleObject(hThread, INFINITE);
	}
	return 0;
}