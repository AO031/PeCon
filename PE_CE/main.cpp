#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <Windows.h>
#include <TlHelp32.h>
#include <ctype.h>
#include <Psapi.h>
#include <conio.h>


/******************
* 常量定义
******************/
#define MAX_RESULTS 10000
#define RESULT_PEE_PAGE 20
#define MAX_STRING_LENGTH 256
#define MAX_MODULES 256

#define COLOR_DEFAULT 7
#define COLOR_TITLE 11
#define COLOR_WARNING 12
#define COLOR_SUCCESSS 10
#define COLOR_INFO 14

#define COL_PID 8
#define COL_PROCESS_NAME 30
#define COL_MODULE_NAME 30
#define COL_BASE_ADDR 16
#define COL_SIZE 10
#define COL_ADDR 48
#define COL_VALUE 20
#define COL_MEM_ADDR 18
#define COL_MEM_ALLOC 14
#define COL_MEM_STATE 8   
#define COL_MEM_PROT 14
#define COL_MEM_TYPE 8 
#define COL_MEM_SIZE 12

/******************
* 结构定义
******************/
typedef struct {
	DWORD pid;
	CHAR name[MAX_PATH];
}ProcessInfo;

typedef struct {
	CHAR name[MAX_PATH];
	VOID* BaseAddress;
	SIZE_T size;
}SimpleModuleInfo;

typedef enum {
	TYPE_BYTE = 1,
	TYPE_WORD,
	TYPE_DWORD,
	TYPE_ULONGLONG,
	TYPE_STRING,
	TYPE_ARRAY,
}ScanType;

typedef struct {
	VOID* address;
	union {
		BYTE ByteValue;
		WORD WordValue;
		DWORD DwordValue;
		ULONGLONG UlonglongValue;
		CHAR StringValue[MAX_STRING_LENGTH];
		CHAR ArrayValue[MAX_STRING_LENGTH];
	}Value;
	SIZE_T size;
}ScanResult;

/******************
* 全局变量定义
******************/
HANDLE g_hProcess = NULL;
ScanType g_ScanType = (ScanType)NULL;
ScanResult g_ScanResults[MAX_RESULTS] = { NULL };
INT g_ReaultCount = 0;
INT g_ModuleCount = 0;
SimpleModuleInfo g_sModuleInfo[MAX_RESULTS] = { NULL };

/******************
* 函数声明
******************/
VOID SetColor(int color);
VOID ResetColer();
VOID ListProcess();
BOOL AttachProcess(DWORD pid);
VOID LoadProcessModule();
VOID ListProcessModule();
VOID FirstScan();
VOID ClearInput();

/******************
* 入口
******************/
int main() {
	int choice = 0;
	DWORD pid = 0;

	while (TRUE) {
		system("cls");
		SetColor(COLOR_TITLE);
		printf("C===================E\n");
		ResetColer();
		printf("1. 进程列表\n");
		printf("2. 附加进程\n");
		printf("3. 模块信息\n");
		printf("4. 内存信息\n");
		printf("5. 首次扫描\n");
		printf("6. 再次扫描\n");
		printf("7. 扫描结果\n");
		printf("8. 修改内存\n");
		printf("0. 退出程序\n");
		printf("input:");
		if (scanf("%d", &choice) != 1) {
			printf("What? input right choice\n");
			continue;
		}
		switch (choice) {
		case 0:
			if (g_hProcess) {
				CloseHandle(g_hProcess);
			}
			return 0;
		case 1:
			system("cls");
			ListProcess();
			break;
		case 2:
			SetColor(COLOR_INFO);
			printf("Please input pid:");
			ResetColer();

			scanf("%d", &pid);

			if (AttachProcess(pid)) {
				SetColor(COLOR_SUCCESSS);
				printf("Attach Process Success\n");
				ResetColer();
				LoadProcessModule();
				break;
			}
			break;
		case 3:
			if (!g_hProcess) {
				SetColor(COLOR_WARNING);
				printf("Please attach process first");
				ResetColer();
				break;
			}
			else {
				ListProcessModule();
			}
			break;
		case 4:
			printf("想啥呢，这苦力活我就不做了!(API:VirtualQueryEx)!@@!\n");
			break;
		case 5:
			if (!g_hProcess) {
				SetColor(COLOR_WARNING);
				printf("Please attach process first");
				ResetColer();
				break;
			}
			else {
				FirstScan();
			}
			break;
		default:
			printf("What? input right choice\n");
		}

		printf("continue? ...\n");
		_getch();
	}

	return 0;
}

VOID SetColor(int color)
{
	HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
	if (h) {
		SetConsoleTextAttribute(h, color);
	}
	return VOID();
}

VOID ResetColer()
{
	SetColor(COLOR_DEFAULT);
	return VOID();
}

VOID ListProcess()
{
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	if (hSnapshot == INVALID_HANDLE_VALUE) {
		printf("Bad luck,Wrong Handle\n");
		return;
	}
	PROCESSENTRY32 pe32 = { 0 };
	pe32.dwSize = sizeof(PROCESSENTRY32);

	if (!Process32First(hSnapshot, &pe32)) {
		printf("Can't Process32First\n");
		CloseHandle(hSnapshot);
		return;
	}

	do {
		if (pe32.th32ProcessID == 0) continue;
		printf("%-*s%-*u\n", COL_PROCESS_NAME, pe32.szExeFile, COL_PID, pe32.th32ProcessID);
	} while (Process32Next(hSnapshot, &pe32));

	CloseHandle(hSnapshot);
	return;
}

BOOL AttachProcess(DWORD pid)
{
	if (g_hProcess) {
		CloseHandle(g_hProcess);
		g_hProcess = NULL;
	}

	g_hProcess = OpenProcess(PROCESS_ALL_ACCESS, TRUE, pid);
	if (!g_hProcess) {
		SetColor(COLOR_WARNING);
		printf("Open Process Wrong\n");
		ResetColer();
		return FALSE;
	}

	g_ReaultCount = 0;
	g_ModuleCount = 0;

	return TRUE;
}

VOID LoadProcessModule()
{
	if (!g_hProcess) {
		SetColor(COLOR_WARNING);
		printf("Please Attach Process First\n");
		ResetColer();
		return;
	}
	HMODULE hMods[MAX_MODULES] = { 0 };
	DWORD cbNeeded = 0;
	g_ModuleCount = 0;

	if (EnumProcessModules(g_hProcess, hMods, sizeof(hMods), &cbNeeded)) {
		DWORD count = cbNeeded / sizeof(HMODULE);
		count = count < MAX_MODULES ? count : MAX_MODULES;
		for (int i = 0; i < count; i++) {
			CHAR szModName[MAX_PATH] = {0};
			MODULEINFO modinfo = { 0 };
			if (hMods[i]
				&& GetModuleFileNameEx(g_hProcess, hMods[i], szModName, sizeof(szModName))
				&& GetModuleInformation(g_hProcess, hMods[i], &modinfo, sizeof(modinfo))) {
				char* ModuleName = strrchr(szModName, '\\');
				if (ModuleName) {
					ModuleName++;
				}
				else {
					ModuleName = szModName;
				}

				strncpy(g_sModuleInfo[i].name, ModuleName, strlen(ModuleName));
				g_sModuleInfo[i].BaseAddress = modinfo.lpBaseOfDll;
				g_sModuleInfo[i].size = modinfo.SizeOfImage;
				g_ModuleCount++;
			}

		}
	}

	return VOID();
}

VOID ListProcessModule()
{
	if (g_ModuleCount == 0) {
		LoadProcessModule();
	}

	system("cls");
	printf("%-*s%-*s%-*s\n",
		COL_MODULE_NAME, "Module Name",
		COL_ADDR, "Module Base",
		COL_ADDR, "Module Size");
	SetColor(COLOR_INFO);
	for (int i = 0; i < g_ModuleCount; i++) {
		
		printf("%-*s0x%-*p0x%-*p\n",
			COL_MODULE_NAME, g_sModuleInfo[i].name,
			COL_ADDR-2, g_sModuleInfo[i].BaseAddress,
			COL_ADDR, g_sModuleInfo[i].size);
	}
	ResetColer();
	return VOID();
}

VOID FirstScan()
{
	int ScanType = 0;
	int UseRange = 0;

#ifdef _WIN64
	size_t StartRange = 0x000140000000;
	size_t EndRange =   0x7FFFFFFFFFFF;
#else
	size_t StartRange = 0x400000;
	size_t EndRange = 0x7FFFFFFF;
#endif
	SetColor(COLOR_INFO);
	printf("1. BYTE\n");
	printf("2. WORD\n");
	printf("3. DWORD\n");
	printf("4. ULONGLONG\n");
	printf("5. STRING\n");
	printf("6. ARRAY\n");

	printf("What type you want to scan:");
	scanf("%d", &ScanType);
	ClearInput();

	printf("Use Range?:");
	scanf("%d", &UseRange);
	ClearInput();

	if (UseRange) {
		printf("Start Address?:");
		scanf("0x%x", &StartRange);
		ClearInput();
		printf("End Address?:");
		scanf("0x%x", &EndRange);
		ClearInput();
	}

	ResetColer();

}

VOID ClearInput()
{
	char c = 0;
	while ((c = getchar()) != '\n' && c != EOF) {}
}
