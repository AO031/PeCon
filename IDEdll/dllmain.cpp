// dllmain.cpp : 定义 DLL 应用程序的入口点。
#include "pch.h"


DWORD dw = 1;

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        MessageBox(0, 0, L"Load", 0);
        dw = 2;
        break;
    case DLL_THREAD_ATTACH:
        break;
    case DLL_THREAD_DETACH:
        break;
    case DLL_PROCESS_DETACH:
        MessageBox(0, 0, L"UnLoad", 0);
        dw = 3;
        break;
    }
    return TRUE;
}

