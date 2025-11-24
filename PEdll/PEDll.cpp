#include "PEDll.h"


#ifdef _WIN64  
#pragma comment (linker, "/INCLUDE:_tls_used")  
#else  
#pragma comment (linker, "/INCLUDE:__tls_used")  
#endif 


__declspec(thread) int tlsData = 0;
thread_local int tlstest = 0;

DWORD WINAPI ThreadProc(LPVOID lpParamTer) {
	printf("aaa\n");
	return 0;
}


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


#ifdef _WIN64  
#pragma const_seg(".CRT$XLB")  
EXTERN_C const
#else  
#pragma data_seg(".CRT$XLX")  
#endif  

PIMAGE_TLS_CALLBACK pTLS_CALLBACKs[] = { t_TlsCallBack_A,0 };

#ifdef _WIN64  
#pragma const_seg()  
#else  
#pragma data_seg()  
#endif



//int __cdecl Myadd(int a, int b)
//{
//	printf("a+b");
//	return 0;
//}
int Myadd(int a, int b)
{
	printf("a+b\n");
	return a+b;
}
int Mysub(int a, int b)
{
	return a-b;
}

int Mymul(int a, int b)
{
	return a*b;
}

int Mydiv(int a, int b)
{
	return a/b;
}

int Mytls(int a, int b) {
	CreateThread(0, 0, ThreadProc, 0, 0, 0);
	return 0;
}
