#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <Windows.h>
#include <TlHelp32.h>
#include <stdlib.h>
#include "PEparser.h"
#include "PETools.h"


WORD FindPIDByName(const char* TargeName){
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	if (hSnapshot == INVALID_HANDLE_VALUE) {
		return -1;
	}
	PROCESSENTRY32 pe32 = {0};
	pe32.dwSize = sizeof(PROCESSENTRY32);

	if (!Process32First(hSnapshot, &pe32)) {
		printf("Can't Process32First\n");
		CloseHandle(hSnapshot);
		return -1;
	}

	do {
		if (!_stricmp(pe32.szExeFile, TargeName)) {
			CloseHandle(hSnapshot);
			return pe32.th32ProcessID;
		}
	} while (Process32Next(hSnapshot, &pe32));

	return -1;
}


int main() {
	// D:\code\CTF\re\PeCon\Debug\PEdll.dll
	// D:\code\CTF\re\PeCon\x64\Debug\PEdll.dll

	char libpath[MAX_PATH] = { 0 };
	char TargetName[MAX_PATH] = { 0 };
	WORD TargetPID = 65535;
	char Input[127] = { 0 };


	printf("===============LIB INJECK===============\n");
	printf("Choose Target(1:Name 2:PID)\n");
	printf("Choose:");
	if (!fgets(Input, 127, stdin)) {
		printf("Shit,What are you input?\n");
		return 1;
	}

	int choose = atoi(Input);
	if (choose == 1) {
		printf("Input Target Name:");
		if (!fgets(Input, 127, stdin)) {
			printf("Shit,What are you input?\n");
			return 1;
		}
		size_t slen = strlen(Input);
		if (slen > 0 && Input[slen - 1] == '\n') {
			Input[slen - 1] = '\0';
		}
		if (!strcpy(TargetName, Input)) {
			printf("Shit,What are you input?\n");
			return 1;
		}

		TargetPID = FindPIDByName(TargetName);
		if (TargetPID == 65535) {
			printf("Can't find PID\n");
			return 1;
		}

	}
	else if (choose == 2){
		printf("Input Target PID:");

		if (!fgets(Input, 127, stdin)) {
			printf("Shit,What are you input?\n");
			return 1;
		}
		TargetPID = atoi(Input);
	}
	else {
		printf("What?\n");
		return 1;
	}

	printf("Please Input CREAKLIB Path:");
	if (!fgets(Input, 127, stdin)) {
		printf("Shit,What are you input?\n");
		return 1;
	}
	size_t slen = strlen(Input);
	if (slen > 0 && Input[slen - 1] == '\n') {
		Input[slen - 1] = '\0';
	}

	if (!strcpy(libpath, Input) || libpath[0] == '\0') {
		printf("Shit,What are you input?\n");
		return 1;
	}

	system("cls");
	printf("Injecking......\n");
	if (TargetName) {
		printf("Victim Name:%s\n", TargetName);
	}
	printf("Victim PID:%d\n", TargetPID);
	printf("CREAK LIB:%s\n", libpath);

	PE_CONTEXT PEContext = { 0 };
	PEContext.hFile = INVALID_HANDLE_VALUE;
	PEContext.RemoteHandle = INVALID_HANDLE_VALUE;
	if (!LoadFile(libpath, &PEContext)) {
		printf("ERROR:Can't Load File\n");
		return 1;
	}

	if (!MapDllToProcess(TargetPID, &PEContext)) {
		printf("ERROR:MapDllToProcess Failed\n");
		return 1;
	}
	
	return 0;
}