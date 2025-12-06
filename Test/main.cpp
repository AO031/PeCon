#include <windows.h>  
#include <stdio.h>


#ifdef _WIN64  
#pragma comment (linker, "/INCLUDE:_tls_used")  
#else  
#pragma comment (linker, "/INCLUDE:__tls_used")  
#endif  

//#pragma comment (linker, "/INCLUDE:pTLS_CALLBACKs")  

DWORD g_TlsIndex;
DWORD WINAPI ThreadProc(LPVOID lpParameter) {
    // 为当前线程分配 TLS 数据  
    int* tlsData = (int*)malloc(sizeof(int));
    if (!tlsData) {
        return 1;
    }
    *tlsData = (int)(size_t)lpParameter; // 将线程传递的参数放入 TLS 数据  
    TlsSetValue(g_TlsIndex, tlsData);

    // 使用 TLS 数据  
    printf("Thread %d: TLS Data = %d\n", GetCurrentThreadId(), *tlsData);

    // 模拟工作  
    Sleep(1000);

    // 释放 TLS 数据  
    free(tlsData);
    return 0;
}

void NTAPI TLS_CALLBACK(PVOID DllHandle, DWORD Reason, PVOID Reserved) //TLS callback function  
{
	if (DLL_THREAD_ATTACH == Reason|| DLL_PROCESS_ATTACH == Reason)
	{
		MessageBoxA(NULL, "TLS CALLBACK", "TLS", 0);
		return;
	}
    // 1. 分配 TLS 索引  
    g_TlsIndex = TlsAlloc();
    if (g_TlsIndex == TLS_OUT_OF_INDEXES) {
        printf("Failed to allocate TLS Index\n");
    }

    // 2. 创建线程  
    HANDLE threads = CreateThread(NULL, 0, ThreadProc, (LPVOID)(size_t)0, 0, NULL);
    if (!threads) {
        return;
    }
    // 等待线程完成  
    WaitForSingleObject(threads, INFINITE);

    CloseHandle(threads);
    // 释放 TLS 索引  
    TlsFree(g_TlsIndex);

}


#ifdef _WIN64  
#pragma const_seg(".CRT$XLB")  
EXTERN_C const
#else  
#pragma data_seg(".CRT$XLX")  
#endif  

PIMAGE_TLS_CALLBACK pTLS_CALLBACKs[] = { TLS_CALLBACK,0 };

#ifdef _WIN64  
#pragma const_seg()  
#else  
#pragma data_seg()  
#endif  

int main(void)
{
    MessageBoxA(0, "Main", "gg", 0);

    return 0;
}