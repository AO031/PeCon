#define _CRT_SECURE_NO_WARNINGS

#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <Windows.h>
#include <WinTrust.h>

   
#pragma warning(disable:4477)
#pragma warning(disable:4313)

BOOL IsPeFile(CONST CHAR* filePath){
	FILE* pFile = fopen(filePath, "rb");

	if (!pFile) return FALSE;

	WORD dosSignature = NULL;
	if (fread(&dosSignature, sizeof(WORD), 1, pFile) != 1)
	{
		fclose(pFile);
		return FALSE;
	}

	if (dosSignature != IMAGE_DOS_SIGNATURE/*0x5A4D*/)
	{
		fclose(pFile);
		return FALSE;
	}

	fclose(pFile);
	return TRUE;
}

VOID CompareFileByBin(CONST CHAR* file1path, CONST CHAR* file2path)
{
	PUCHAR szBuffer1 = NULL;
	PUCHAR szBuffer2 = NULL;
	size_t dwOffset = 0;
	DWORD dwDifferences = 0;
	FILE* pFile1 = NULL;
	FILE* pFile2 = NULL;

	// 文件打开和检查代码...
	if (!IsPeFile(file1path) || !IsPeFile(file2path)) {
		printf("given file type is not PE\n");
		return;
	}

	szBuffer1 = (PUCHAR)malloc(USN_PAGE_SIZE);
	szBuffer2 = (PUCHAR)malloc(USN_PAGE_SIZE);

	if (!szBuffer1 || !szBuffer2) {
		printf("Can't malloc\n");
		return;
	}

	pFile1 = fopen(file1path, "rb");
	pFile2 = fopen(file2path, "rb");
	if (!pFile1 || !pFile2) {
		printf("Can't open File\n");
		return;
	}

	// 循环读取并比较文件内容
	while (1)
	{
		SIZE_T byteRead1 = fread(szBuffer1, 1, USN_PAGE_SIZE, pFile1);
		SIZE_T byteRead2 = fread(szBuffer2, 1, USN_PAGE_SIZE, pFile2);

		if (byteRead1 == 0 && byteRead2 == 0) break;

		if (byteRead1 != byteRead2)
		{

			printf("警告: 文件长度不相等 OFFSET -> 0x%08llx\n",
				dwOffset + (byteRead1 < byteRead2 ? byteRead1 : byteRead2));
			break;
		}

        for (size_t i = 0; i < byteRead1 && i < byteRead2; i++)
        {
            if (szBuffer1[i] != szBuffer2[i])
            {
                printf("0x%08llX | 0x%02X  | 0x%02X  | %c - %c \n",
                    dwOffset + i,
                    szBuffer1[i],
                    szBuffer2[i],
                    (szBuffer1[i] >= 32 && szBuffer1[i] <= 126) ? (char)szBuffer1[i] : '.',
                    (szBuffer2[i] >= 32 && szBuffer2[i] <= 126) ? (char)szBuffer2[i] : '.');
                dwDifferences++;
				return;
            }
        }
		dwOffset += byteRead1;
	}

	fclose(pFile1);
	fclose(pFile2);
	free(szBuffer1);
	free(szBuffer2);
	return;
}

VOID HexAscii(const byte* data, size_t offset, size_t length) {
	char ascii[17] = { 0 };
	ascii[16] = '\x00';
	printf("%08x | ", (int)offset);

	for (size_t i = 0; i < 16; i++) {
		if (i < length) {
			printf("%02X ", data[i]);
			ascii[i] = isprint(data[i]) ? data[i] : '.';
		}
		else {
			printf("  ");
			ascii[i] = ' ';
		}
	}

	printf("|%s|", ascii);

	printf("\n");

}

VOID HexDump(const CHAR* filename) {
	FILE* pFile = fopen(filename, "rb");

	if (!pFile) {
		printf("Failed to open file: %s\n", filename);
		return;
	}
	BYTE buffer[16];
	SIZE_T bufferread = 0;
	SIZE_T offset = 0;
	while (bufferread = fread(buffer, 1, sizeof(buffer), pFile)){
		HexAscii(buffer, offset, bufferread);
		offset += bufferread;
	}
	return;
}

HANDLE g_hFile = INVALID_HANDLE_VALUE;
DWORD g_dwFileSize = 0;
PBYTE g_lpFileBuffer = NULL;
PBYTE g_lpImageBuffer = NULL;
PIMAGE_DOS_HEADER g_DosHeader = NULL;
PIMAGE_NT_HEADERS g_NtHeaders = NULL;
PIMAGE_SECTION_HEADER g_SectionHeader = NULL;
BOOL g_RUNNING = TRUE;
#define MAX_LOAD 16

VOID FreeLoadedFile();
VOID CmdLoad(CONST CHAR* param);
VOID CmdInfo(CONST CHAR* param);
VOID CmdDos(CONST CHAR* param);
VOID CmdNt(CONST CHAR* param);
VOID CmdSection(CONST CHAR* param);
VOID CmdImport(CONST CHAR* param);
VOID CmdExport(CONST CHAR* param);
VOID CmdShowExportFunByName(CONST CHAR* param);
VOID CmdShowExportFunByIndex(CONST CHAR* param);
VOID CmdRelocation(CONST CHAR* param);
VOID CmdResource(CONST CHAR* param);
VOID CmdDebug(CONST CHAR* param);
VOID CmdException(CONST CHAR* param);
VOID CmdFileToImage(CONST CHAR* param);
VOID CmdImageToFile(CONST CHAR* param);
VOID CmdMyLoadLibraryA(CONST CHAR* param);
VOID CmdMyGetProcAddress(CONST CHAR* param);
VOID CmdRva(CONST CHAR* param);
VOID CmdSecurity(CONST CHAR* param);
VOID CmdFoa(CONST CHAR* param);
VOID CmdExit(CONST CHAR* param);


DWORD Rva2Foa(DWORD rva);
DWORD Foa2Rva(DWORD foa);
PBYTE GetFunAddrByName(CONST CHAR* Funname);
DWORD GetFunAddrByIndex(WORD idx);
PBYTE Filebuffer2Imagebuffer(PBYTE lpFileBuffer);
PBYTE Imagebuffer2Filebuffer(PBYTE lpImageBuffer,PDWORD pFileSize);
BOOL SaveBufferToFile(CONST CHAR* filepath, PBYTE lpBuffer, DWORD dwBufferSize);
PBYTE MyLoadLibraryA(CONST CHAR* dllpath, DWORD* ImageSize);
BOOL FixImport(PBYTE lpImageBuffer);
BOOL FixRelocation(PBYTE lpImageBuffer, uintptr_t dwDelta);
FARPROC MyGetProcAddressByName(HMODULE dllbase, CONST CHAR* funcname);
FARPROC MyGetProcAddressByOrd(HMODULE dllbase, DWORD Ord);
VOID ParseResourceDir(PIMAGE_RESOURCE_DIRECTORY pResource, WORD level, size_t ResBaserva);

typedef VOID (*CmdHandler)(CONST CHAR* param);
CmdHandler Findhandler(CONST CHAR* param);

typedef struct {
	CHAR szpath[MAX_PATH];
	PBYTE dllbase;
	DWORD ImageSize;
}LOAD_LIB,*PLOAD_LIB;
LOAD_LIB g_LoadModules[MAX_LOAD] = { 0 };
DWORD g_dwLoadedModulecnt = 0;

typedef struct{
	CONST CHAR* cmd;
	CmdHandler handler;
}CmdEntry;
static CmdEntry CmdTable[] = {
	{"load",CmdLoad},
	{"info",CmdInfo},
	{"dos",CmdDos},
	{"nt",CmdNt},
	{"section",CmdSection},
	{"import",CmdImport},
	{"export",CmdExport},
	{"ShowExportFunByName",CmdShowExportFunByName},
	{"ShowExportFunByIndex",CmdShowExportFunByIndex},
	{"filetoimage",CmdFileToImage},
	{"imagetofile",CmdImageToFile},
	{"MyLoadLibraryA",CmdMyLoadLibraryA},
	{"MyGetProcAddress",CmdMyGetProcAddress},
	{"rva",CmdRva},
	{"foa",CmdFoa},
	{"relocation",CmdRelocation},
	{"security",CmdSecurity},
	{"exception",CmdException},
	{"debug",CmdDebug},
	{"resource",CmdResource},
	{"exit",CmdExit},
	{"q",CmdExit},
	{NULL,NULL}
};


typedef union _UNWIND_CODE {
	struct {
		BYTE CodeOffset;     // 在函数中相对于 Prolog 起始处的偏移量，指定该操作的开始位置  
		BYTE UnwindOp : 4;   // 展开操作类型，属于 UNWIND_OP_CODES 之一  
		BYTE OpInfo : 4;   // 补充信息，根据不同的 UnwindOp 含义不同  
	};
	USHORT FrameOffset;       // 某些操作直接用来描述栈帧内偏移的值  
} UNWIND_CODE, * PUNWIND_CODE;
typedef struct _UNWIND_INFO {
	UCHAR Version : 3;           // 版本号（通常为1）  
	UCHAR Flags : 5;             // 标志（如是否包含异常处理程序）
	UCHAR SizeOfProlog;          // 函数序言（Prolog）的字节数  
	UCHAR CountOfCodes;          // 展开代码条目数量（数组中 UNWIND_CODE 个数）  
	UCHAR FrameRegister : 4;     // 帧指针寄存器（如 RBP、RDI 等）  
	UCHAR FrameOffset : 4;     // 帧指针偏移，用 16 字节单位（FP = RSP + FrameOffset * 16）  
	// UNWIND_CODE UnwindCode[1];   // 不定长度数组，描述具体的栈展开操作  
	// 后续紧跟可选字段：  
	// 1. 如果设置了 UNW_FLAG_EHANDLER 或 UNW_FLAG_UHANDLER，则紧跟有 ExceptionHandler 和 ExceptionData。  
	// 2. 如果设置了 UNW_FLAG_CHAININFO，则后续为一个 RUNTIME_FUNCTION 结构。  
} UNWIND_INFO, * PUNWIND_INFO;

struct CV_INFO_PDB70 {
	DWORD Signature; // "RSDS"  
	GUID Guid;       // 唯一 ID  
	DWORD Age;       // PDB 文件版本  
	char PdbName[1];  // PDB 文件路径  
};

VOID ShowMenu() {
	printf("%s\n", "P======================================E");
	printf("%s\n", "- load");
	printf("%s\n", "- info");
	printf("%s\n", "- dos");
	printf("%s\n", "- nt");
	printf("%s\n", "- section");
	printf("%s\n", "- import");
	printf("%s\n", "- export");
	printf("%s\n", "- ShowExportFunByName");
	printf("%s\n", "- ShowExportFunByIndex");
	printf("%s\n", "- relocation");
	printf("%s\n", "- resource");
	printf("%s\n", "- filetoimage");
	printf("%s\n", "- exception");
	printf("%s\n", "- security");
	printf("%s\n", "- debug");
	printf("%s\n", "- imagetofile");
	printf("%s\n", "- MyLoadLibraryA");
	printf("%s\n", "- MyGetProcAddress");
	printf("%s\n", "- rva");
	printf("%s\n", "- foa");
	printf("%s\n", "- clear");
	printf("%s\n", "- help");
	printf("%s\n", "- exit");
	printf("\n");
	printf("%s", "input >");
}

VOID ProcessCommend() {
	char cmdline[0xFFF] = { 0 };
	char param[MAX_PATH] = { 0 };
	char cmd[32] = { 0 };

	if (fgets(cmdline, MAX_PATH, stdin)) {
		size_t len = strlen(cmdline);
		if (len > 0 && cmdline[len - 1] == '\n') {
			cmdline[len - 1] = '\0';
		}
		int parsed = sscanf(cmdline, "%31s %255s[^\n]", cmd, param);
	}

	CmdHandler handler = Findhandler(cmd);
	if (handler) {
		handler(param);
	}
	else if (cmd[0] != '\0') {
		printf("\ncan't find this cmd!!!\n");
	}
}

// typedef int(__cdecl* pFun)(int, int);
// using pFun = int(*)(int, int);

int main() {

	{
		// D:\code\CTF\re\PeCon\x64\Debug\111.exe
		// D:\code\CTF\re\PeCon\Debug\PEdll.dll
		// C:\Windows\System32\kernel32.dll
		// D:\code\CTF\re\PeCon\x64\Debug\InstDrv.exe
		// D:\x96dbg\snapshot_2025-08-19_19-40\release\x64\x64dbg.exe
	}

	/*
	CHAR file1path[MAX_PATH] = { 0 };
	CHAR file2path[MAX_PATH] = { 0 };
	printf("one: ");
	if (fgets(file1path, MAX_PATH, stdin) != NULL) {
		file1path[strcspn(file1path, "\n")] = NULL;
	}
	printf("two: ");
	if (fgets(file2path, MAX_PATH, stdin) != NULL) {
		file2path[strcspn(file2path, "\n")] = NULL;
	}
	CompareFileByBin(file1path, file2path);
	*/

	/*
	HMODULE h_module = LoadLibraryA("D:\\code\\CTF\\re\\PeCon\\x64\\Debug\\PEdll.dll");
	if (!h_module) return 0;
	pFun pfun = (pFun)GetProcAddress(h_module, "Myadd");
	pfun(1, 12);
	*/

	while (1) {
		system("cls");
		ShowMenu();
		ProcessCommend();
		if (g_RUNNING) {
			system("pause");
		}
		else {
			printf("PE CREAKER!\n");
			return 0;
		}
	}
	
	return 0;
}

VOID FreeLoadedFile()
{
	if (g_lpFileBuffer) {
		free(g_lpFileBuffer);
		g_lpFileBuffer = 0;
	}

	if (g_hFile != INVALID_HANDLE_VALUE) {
		CloseHandle(g_hFile);
		g_hFile = INVALID_HANDLE_VALUE;
	}

	g_dwFileSize = 0;
	g_DosHeader = NULL;
	g_NtHeaders = NULL;
	g_SectionHeader = NULL;

	return VOID();
}

VOID CmdLoad(const CHAR* param)
{
	// 参数检验
	if (param == NULL || *param == '\0'){
		printf("ERROR: missing load path!\n");
		return;
	}
	// 释放之前数据
	FreeLoadedFile();
	// 打开文件
	g_hFile = CreateFileA(
		param,
		GENERIC_READ,
		FILE_SHARE_READ,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL
	);
	if (g_hFile == INVALID_HANDLE_VALUE) {
		printf("ERROR:Can't open file %s,ERROR CODE:%d", param, GetLastError());
		return;
	}

	// 获取文件大小
	
	DWORD dwFileSize = 0;
	dwFileSize = GetFileSize(g_hFile, NULL);
	if (dwFileSize == INVALID_FILE_SIZE) {
		printf("ERROR: GetFileSize failed, ERROR CODE: %d\n", GetLastError());
		FreeLoadedFile();
		return;
	}
	g_dwFileSize = dwFileSize;

	// 申请、写入缓冲区
	g_lpFileBuffer = (PBYTE)malloc(dwFileSize);
	if (!g_lpFileBuffer) {
		printf("malloc failed,bad luck");
		FreeLoadedFile();
		return;
	}

	// 获取数据
	DWORD dwByteRead = 0;
	if (!ReadFile(g_hFile, g_lpFileBuffer, g_dwFileSize, &dwByteRead, NULL) || dwByteRead != g_dwFileSize) {
		printf("ERROR:WRONG READ");
		FreeLoadedFile();
		return;
	}
	
	// DOS
	g_DosHeader = (PIMAGE_DOS_HEADER)g_lpFileBuffer;
	if (g_DosHeader->e_magic != IMAGE_DOS_SIGNATURE/*0x5A4D*/) {
		printf("ERROR:WRONG DOS SIGNATURE->0x%04X\n", g_DosHeader->e_magic);
		FreeLoadedFile();
		return;
	}

	// NT
	DWORD dwNtHeaderoffset = g_DosHeader->e_lfanew;
	if (dwNtHeaderoffset < sizeof(IMAGE_DOS_HEADER) || dwNtHeaderoffset + sizeof(IMAGE_DOS_HEADER)>dwFileSize) {
		printf("ERROR:WRONG NT OFFSET->0x%04X\n", dwNtHeaderoffset);
		FreeLoadedFile();
		return;
	}
	g_NtHeaders = (PIMAGE_NT_HEADERS)(g_lpFileBuffer+dwNtHeaderoffset);
	if (g_NtHeaders->Signature != IMAGE_NT_SIGNATURE/*0x00004550*/) {
		printf("ERROR:WRONG NT Signature->0x%04X\n", g_NtHeaders->Signature);
		FreeLoadedFile();
		return;
	}

	// SECTION
	DWORD dwSectionOffset = dwNtHeaderoffset +
		sizeof(DWORD) +
		IMAGE_SIZEOF_FILE_HEADER +
		g_NtHeaders->FileHeader.SizeOfOptionalHeader;
	g_SectionHeader = (PIMAGE_SECTION_HEADER)(g_lpFileBuffer + dwSectionOffset);

	CloseHandle(g_hFile);
	g_hFile = INVALID_HANDLE_VALUE;

	printf("\nload file success!\n");
	printf("size of file is 0x%08X\n", dwFileSize);
#ifdef _WIN64
	if (g_NtHeaders->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
		printf("ERROR:Can't use x64 program parse x86\n");
		FreeLoadedFile();
	}
#else
	if (g_NtHeaders->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
		printf("ERROR:Can't use x86 program parse x64\n");
		FreeLoadedFile();
	}
#endif // _WIN64
}

VOID CmdInfo(const CHAR* param)
{
	return VOID();
}

VOID CmdDos(const CHAR* param)
{
	if (!g_DosHeader) {
		printf("ERROR:Can't find loaded file.\n");
		return;
	}

	printf("\n");
	printf("e_magic is 0x%04X    // Magic number\n", g_DosHeader->e_magic);
	printf("e_lfanew is 0x%04X   // File address of new exe header\n",g_DosHeader->e_lfanew);
}

VOID CmdNt(const CHAR* param)
{
	if (!g_NtHeaders) {
		printf("ERROR:Can't find loaded file.\n");
		return;
	}

	printf("\n");
	printf("Signature is 0x%08X    \n", g_NtHeaders->Signature);

	IMAGE_FILE_HEADER FileHeader = g_NtHeaders->FileHeader;
	printf("FileHeader.Machine is 0x%04X    \n", FileHeader.Machine);
	printf("FileHeader.NumberOfSections is 0x%04X    \n", FileHeader.NumberOfSections);
	
	// 先判断PE类型再处理可选头
	switch (FileHeader.Machine) {
	case IMAGE_FILE_MACHINE_I386: {
		// 32位PE - 需要强制转换
		IMAGE_OPTIONAL_HEADER32* optHeader32 =
			(IMAGE_OPTIONAL_HEADER32*)&g_NtHeaders->OptionalHeader;
		printf("ImageBase: 0x%08X\n", optHeader32->ImageBase);
		printf("SizeOfImage: 0x%08X\n", optHeader32->SizeOfImage);
		break;
	}
	case IMAGE_FILE_MACHINE_AMD64: {
		// 64位PE
		IMAGE_OPTIONAL_HEADER64* optHeader64 =
			(IMAGE_OPTIONAL_HEADER64*)&g_NtHeaders->OptionalHeader;
		printf("ImageBase: 0x%016llX\n", optHeader64->ImageBase);
		printf("SizeOfImage: 0x%08X\n", optHeader64->SizeOfImage);
		break;
	}
	}
}
               
VOID CmdSection(const CHAR* param)
{
	if (!g_SectionHeader) {
		printf("ERROR:Can't find loaded file\n");
		return;
	}

	for (int i = 0;i < g_NtHeaders->FileHeader.NumberOfSections;i++) {
		printf("Section Name: %s\n", g_SectionHeader[i].Name);
		char szCharacteristics[16] = "Section is ---";

		// 清空权限位
		szCharacteristics[11] = '-';
		szCharacteristics[12] = '-';
		szCharacteristics[13] = '-';

		// 使用位运算检查多个标志
		if (g_SectionHeader[i].Characteristics & IMAGE_SCN_MEM_READ) {
			szCharacteristics[11] = 'R';
		}
		if (g_SectionHeader[i].Characteristics & IMAGE_SCN_MEM_WRITE) {
			szCharacteristics[12] = 'W';
		}
		if (g_SectionHeader[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) {
			szCharacteristics[13] = 'E';
		}
		printf("%s\n", szCharacteristics);
	}
	return VOID();
}

VOID CmdImport(const CHAR* param)
{
	if (!g_NtHeaders) {
		printf("ERROR:Can't find loaded file.!@!\n");
		return;
	}
	
	PIMAGE_OPTIONAL_HEADER pOptionalHeader = (PIMAGE_OPTIONAL_HEADER)&g_NtHeaders->OptionalHeader;
	PIMAGE_DATA_DIRECTORY pDataDirectorys = (PIMAGE_DATA_DIRECTORY)&pOptionalHeader->DataDirectory;
	
	if (!pDataDirectorys) {
		printf("ERROR: DataDirectory is NULL!\n");
		return;
	}

	if (pDataDirectorys[IMAGE_DIRECTORY_ENTRY_IMPORT].Size == 0 || pDataDirectorys[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress == 0) {
		printf("ERROR: This file don't have impect table!@!\n");
		return;
	}

	PIMAGE_IMPORT_DESCRIPTOR ImportDirection = (PIMAGE_IMPORT_DESCRIPTOR)(g_lpFileBuffer +
		Rva2Foa(pDataDirectorys[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress));

	while (ImportDirection->OriginalFirstThunk) {

		printf("Name is %s\n", g_lpFileBuffer + Rva2Foa(ImportDirection->Name));
		printf("INT ADDR(RVA) is 0x%08X\n",ImportDirection->OriginalFirstThunk );
		printf("IAT ADDR(RVA) is 0x%08X\n", ImportDirection->FirstThunk);
		printf("\n");

		if (g_NtHeaders->FileHeader.Machine == IMAGE_FILE_MACHINE_I386) {
			PIMAGE_THUNK_DATA32 pINT = 
				(PIMAGE_THUNK_DATA32)(g_lpFileBuffer + Rva2Foa(ImportDirection->OriginalFirstThunk));
			while (pINT->u1.Ordinal) {
				if (pINT->u1.Ordinal & IMAGE_ORDINAL_FLAG32) {
					printf("\tThis Function Import By Ord:%hu\n", (USHORT)IMAGE_ORDINAL32(pINT->u1.Ordinal));
				}
				else {
					printf("\tThis Function Import By Name:%s\n", g_lpFileBuffer + pINT->u1.Ordinal+sizeof(WORD));
				}
				pINT++;
			}
		}
		else {
			PIMAGE_THUNK_DATA64 pINT =
				(PIMAGE_THUNK_DATA64)(g_lpFileBuffer + Rva2Foa(ImportDirection->OriginalFirstThunk));
			while (pINT) {
				if (pINT->u1.Ordinal & IMAGE_ORDINAL_FLAG64) {
					printf("\tThis Function Import By Ord:%hu\n", (USHORT)IMAGE_ORDINAL64(pINT->u1.Ordinal));
				}
				else {
					printf("\tThis Function Import By Name:%s\n", g_lpFileBuffer + pINT->u1.Ordinal);
				}
				pINT++;
			}
		}
		ImportDirection++;
	}
	return VOID();
}

VOID CmdExport(const CHAR* param)
{
	if (!g_NtHeaders) {
		printf("ERROR:Can't find loaded file.!@!\n");
		return;
	}

	PIMAGE_OPTIONAL_HEADER pOptionalHeader = &g_NtHeaders->OptionalHeader;
	PIMAGE_DATA_DIRECTORY pDataDirectorys = (PIMAGE_DATA_DIRECTORY)&pOptionalHeader->DataDirectory;

	if (pDataDirectorys[IMAGE_DIRECTORY_ENTRY_EXPORT].Size == 0 || pDataDirectorys[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress == 0) {
		printf("ERROR: This file don't have expect table!@!\n");
		return;
	}

	PIMAGE_EXPORT_DIRECTORY ExportDirectory =
		(PIMAGE_EXPORT_DIRECTORY)(g_lpFileBuffer + Rva2Foa(pDataDirectorys[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress));
	printf("Name is %s\n", g_lpFileBuffer + Rva2Foa(ExportDirectory->Name));
	printf("Base is 0x%08X\n", ExportDirectory->Base);
	printf("NumberOfFunctions is 0x%08X\n", ExportDirectory->NumberOfFunctions);
	printf("NumberOfNames is 0x%08X\n", ExportDirectory->NumberOfNames);
	printf("AddressOfFunctions is 0x%08X\n", ExportDirectory->AddressOfFunctions);
	printf("AddressOfNameOrdinals is 0x%08X\n", ExportDirectory->AddressOfNameOrdinals);
	printf("AddressOfNames is 0x%08X\n", ExportDirectory->AddressOfNames);

	printf("\n");
	DWORD* NameRvaArray =
		(DWORD*)(g_lpFileBuffer +
			Rva2Foa(ExportDirectory->AddressOfNames));

	DWORD* AddrRvaArray =
		(DWORD*)(g_lpFileBuffer +
			Rva2Foa(ExportDirectory->AddressOfFunctions));

	WORD* OrdArray =
		(WORD*)(g_lpFileBuffer +
			Rva2Foa(ExportDirectory->AddressOfNameOrdinals));
	
	for (size_t i = 0;i < ExportDirectory->NumberOfNames;i++) {		
		// function name
		printf("Fun Name is %s\n",
			g_lpFileBuffer + Rva2Foa(NameRvaArray[i]));
		
		// function ord
		printf("Fun Ord is %d\n",OrdArray[i]+ExportDirectory->Base);
		
		// function addr
		printf("Fun addr(rva) is 0x%08X\n\n", AddrRvaArray[OrdArray[i]]);
	}

	return VOID();
	
}

VOID CmdShowExportFunByName(const CHAR* param)
{
	if (!g_NtHeaders) {
		printf("ERROR: Can't find loaded file!@!\n");
		return;
	}

	PIMAGE_OPTIONAL_HEADER pOptionalHeader = &g_NtHeaders->OptionalHeader;
	PIMAGE_DATA_DIRECTORY pDataDirectorys = (PIMAGE_DATA_DIRECTORY)&pOptionalHeader->DataDirectory;
	if (pDataDirectorys[IMAGE_DIRECTORY_ENTRY_EXPORT].Size == 0 || pDataDirectorys[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress == 0) {
		printf("ERROR: This file don't have expect table!@!\n");
		return;
	}
	PIMAGE_EXPORT_DIRECTORY ExportDirectory =
		(PIMAGE_EXPORT_DIRECTORY)(g_lpFileBuffer + Rva2Foa(pDataDirectorys[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress));

	DWORD* NameRvaArray =
		(DWORD*)(g_lpFileBuffer +
			Rva2Foa(ExportDirectory->AddressOfNames));

	DWORD* AddrRvaArray =
		(DWORD*)(g_lpFileBuffer +
			Rva2Foa(ExportDirectory->AddressOfFunctions));

	WORD* OrdArray =
		(WORD*)(g_lpFileBuffer +
			Rva2Foa(ExportDirectory->AddressOfNameOrdinals));

	for (size_t i = 0;i < ExportDirectory->NumberOfNames;i++) {

		if (!strcmp((CONST CHAR*)(g_lpFileBuffer + Rva2Foa(NameRvaArray[i])), param)) {
			printf("Fun Name is %s\n",
				g_lpFileBuffer + Rva2Foa(NameRvaArray[i]));

			// function ord
			printf("Fun Ord is %d\n", 
				OrdArray[i] + ExportDirectory->Base);

			// function addr
			printf("Fun addr(rva) is 0x%08X\n\n", 
				AddrRvaArray[OrdArray[i]]);
			return;
		}
		// function name
	}
	printf("ERROR:Can't find this function\n");

	return VOID();
}

VOID CmdShowExportFunByIndex(const CHAR* param)
{
	if (!g_NtHeaders) {
		printf("ERROR: Can't find loaded file!@!\n");
		return;
	}

	PIMAGE_OPTIONAL_HEADER pOptionalHeader = &g_NtHeaders->OptionalHeader;
	PIMAGE_DATA_DIRECTORY pDataDirectorys = (PIMAGE_DATA_DIRECTORY)&pOptionalHeader->DataDirectory;

	if (pDataDirectorys[IMAGE_DIRECTORY_ENTRY_EXPORT].Size == 0 || pDataDirectorys[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress == 0) {
		printf("ERROR: This file don't have expect table!@!\n");
		return;
	}

	PIMAGE_EXPORT_DIRECTORY ExportDirectory =
		(PIMAGE_EXPORT_DIRECTORY)(g_lpFileBuffer + Rva2Foa(pDataDirectorys[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress));

	WORD FunIndex = 0;
	if (sscanf(param, "%hu", &FunIndex) != 1) {
		printf("ERROR:WRONG PARAM!@!\n");
		return;
	}
	if (FunIndex >= ExportDirectory->NumberOfFunctions) {
		printf("ERROR:What? Given Array Index Out of Bounds,No ctf\n");
		return;
	}

	DWORD* NameRvaArray =
		(DWORD*)(g_lpFileBuffer +
			Rva2Foa(ExportDirectory->AddressOfNames));

	DWORD* AddrRvaArray =
		(DWORD*)(g_lpFileBuffer +
			Rva2Foa(ExportDirectory->AddressOfFunctions));

	WORD* OrdArray =
		(WORD*)(g_lpFileBuffer +
			Rva2Foa(ExportDirectory->AddressOfNameOrdinals));

	DWORD FunAddr = AddrRvaArray[FunIndex-ExportDirectory->Base];
	if (!FunAddr) {
		printf("ERROR:INVALID ORD!@!\n");
		return;
	}
	for (size_t i = 0;i < ExportDirectory->NumberOfFunctions;i++) {

		if ((OrdArray[i]+ExportDirectory->Base)==FunIndex) {
			printf("Fun Name is %s\n",
				g_lpFileBuffer + Rva2Foa(NameRvaArray[i]));

			// function ord
			printf("Fun Ord is %d\n",
				OrdArray[i] + ExportDirectory->Base);

			// function addr
			printf("Fun addr(rva) is 0x%08X\n\n",
				FunAddr);
			return;
		}
		// function name
	}

	printf("Fun addr(rva) is 0x%08X\n",FunAddr);
	printf("HINT:this function don't export name\n");

	return VOID();
}

VOID CmdRelocation(const CHAR* param)
{
	if (!g_NtHeaders) {
		printf("ERROR:Can't find loaded file.!@!\n");
		return;
	}

	PIMAGE_OPTIONAL_HEADER pOptionalHeader = &g_NtHeaders->OptionalHeader;
	PIMAGE_DATA_DIRECTORY pDataDirectorys = (PIMAGE_DATA_DIRECTORY)&pOptionalHeader->DataDirectory;

	if (pDataDirectorys[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size == 0 || pDataDirectorys[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress == 0) {
		printf("ERROR: This file don't have relocation!@!\n");
		return;
	}

	PIMAGE_BASE_RELOCATION Relocation =
		(PIMAGE_BASE_RELOCATION)(g_lpFileBuffer + Rva2Foa(pDataDirectorys[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress));
	while (Relocation->VirtualAddress && Relocation->SizeOfBlock) {
		printf("This black base addr: 0x%08X\n", Relocation->VirtualAddress);
		printf("This black size: 0x%08X\n", Relocation->SizeOfBlock);
		PWORD RelOffsetArray = (PWORD)(((PCHAR)Relocation) + 2 * sizeof(IMAGE_BASE_RELOCATION));
		for (size_t i = 0;i < (Relocation->SizeOfBlock - 2 * sizeof(DWORD)) / 2;i++) {
			switch (*RelOffsetArray >> 12) {
			case IMAGE_REL_BASED_ABSOLUTE: 
				printf("\tThis offset do nothing:0x%04X\n", (*RelOffsetArray) & 0xFFF);
				break;
			case IMAGE_REL_BASED_HIGHLOW:
				printf("\tThis offset will rel 32bit val:0x%04X\n", (*RelOffsetArray) & 0xFFF);
				break;
			case IMAGE_REL_BASED_MACHINE_SPECIFIC_9:
				printf("\tThis offset will rel 64bit val:0x%04X\n", (*RelOffsetArray) & 0xFFF);
				break;
			default:
				printf("\t!@! type:%1X,val:0x%04X\n", *RelOffsetArray >> 12, (*RelOffsetArray) & 0xFFF);
			}
			RelOffsetArray++;
		}
		Relocation = (PIMAGE_BASE_RELOCATION)(((PCHAR)Relocation) + Relocation->SizeOfBlock);
	}
}

VOID CmdResource(const CHAR* param)
{
	if (!g_NtHeaders) {
		printf("ERROR:Can't find loaded file.!@!\n");
		return;
	}

	PIMAGE_OPTIONAL_HEADER pOptionalHeader = &g_NtHeaders->OptionalHeader;
	PIMAGE_DATA_DIRECTORY pDataDirectorys = (PIMAGE_DATA_DIRECTORY)&pOptionalHeader->DataDirectory;

	if (pDataDirectorys[IMAGE_DIRECTORY_ENTRY_RESOURCE].Size == 0 || 
		pDataDirectorys[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress == 0) {
		printf("ERROR: This file don't have resource!@!\n");
		return;
	}

	PIMAGE_RESOURCE_DIRECTORY pResourceDir =
		(PIMAGE_RESOURCE_DIRECTORY)(g_lpFileBuffer + Rva2Foa(pDataDirectorys[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress));
	
	puts("- Type");
	puts("- Name");
	puts("- Language");
	ParseResourceDir(pResourceDir, 0, Rva2Foa(pDataDirectorys[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress));

	return VOID();
}

VOID CmdDebug(const CHAR* param)
{
	if (!g_NtHeaders) {
		printf("ERROR:Can't find loaded file.!@!\n");
		return;
	}

	PIMAGE_OPTIONAL_HEADER pOptionalHeader = &g_NtHeaders->OptionalHeader;
	PIMAGE_DATA_DIRECTORY pDataDirectorys = (PIMAGE_DATA_DIRECTORY)&pOptionalHeader->DataDirectory;

	if (pDataDirectorys[IMAGE_DIRECTORY_ENTRY_DEBUG].Size == 0 ||
		pDataDirectorys[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress == 0) {
		printf("ERROR: This file don't have resource!@!\n");
		return;
	}

	PIMAGE_DEBUG_DIRECTORY pDebugDir = (PIMAGE_DEBUG_DIRECTORY)(g_lpFileBuffer +
		Rva2Foa(pDataDirectorys[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress));
	DWORD DirCount = pDataDirectorys[IMAGE_DIRECTORY_ENTRY_DEBUG].Size / sizeof(IMAGE_DEBUG_DIRECTORY);

	for (size_t i = 0; i < DirCount; i++) {
		printf("The %dth Debug Dir\n", i);
		printf("\tthis debug dir type is 0x%04X\n", pDebugDir[i].Type);
		if (pDebugDir[i].Type == IMAGE_DEBUG_TYPE_CODEVIEW) {
			CV_INFO_PDB70* pCVINFO = (CV_INFO_PDB70*)(g_lpFileBuffer + Rva2Foa(pDebugDir[i].AddressOfRawData));
			printf("\t\tthis CV_INFO Signature is 0x%08X\n", pCVINFO->Signature);
			printf("\t\tthis debug pdb path is %s\n", pCVINFO->PdbName);
		}
		printf("\tthis debug dir AddressOfRawData is 0x%08X\n", pDebugDir[i].AddressOfRawData);
		printf("\n");
	}



	return VOID();
}

VOID CmdException(const CHAR* param)
{
#ifndef _WIN64
	printf("x86 don't exist exception dir!@!\n");
	return ;

#else
	if (!g_NtHeaders) {
		printf("ERROR:Can't find loaded file.!@!\n");
		return;
	}
	PIMAGE_OPTIONAL_HEADER pOptionalHeader = &g_NtHeaders->OptionalHeader;
	PIMAGE_DATA_DIRECTORY pDataDirectorys = (PIMAGE_DATA_DIRECTORY)&pOptionalHeader->DataDirectory;

	if (pDataDirectorys[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size == 0 || 
		pDataDirectorys[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress == 0) {
		printf("ERROR: This file don't have Exception!@!\n");
		return;
	}

	PIMAGE_RUNTIME_FUNCTION_ENTRY pRuntime = (PIMAGE_RUNTIME_FUNCTION_ENTRY)(g_lpFileBuffer + Rva2Foa(pDataDirectorys[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress));
	size_t Runtimecount = pDataDirectorys[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size / sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY);
	printf("Runtime Funcition Entry Count is %d\n", Runtimecount);
	for (size_t i = 0; i < Runtimecount; i++) {
		printf("Runtime Funcition Entry:%d\n", i);
		printf("Begin Address rva is 0x%p\n", pRuntime[i].BeginAddress);
		printf("End Address rva is 0x%p\n", pRuntime[i].EndAddress);

		PUNWIND_INFO pUnwindinfo = (PUNWIND_INFO)(g_lpFileBuffer + Rva2Foa(pRuntime[i].UnwindData));
		printf("\tFlags is %p\n", pUnwindinfo->Flags);
		printf("\tCountOfCodes is %d\n", pUnwindinfo->CountOfCodes);

		if (pUnwindinfo->Flags & UNW_FLAG_EHANDLER) {
			DWORD AlignCount = (pUnwindinfo->CountOfCodes + 1) & ~0x1;
			PDWORD pC_SPEC_HANDLE = (PDWORD)((PBYTE)(pUnwindinfo+1) + AlignCount * sizeof(UNWIND_CODE));
			printf("\tException Handle(__except_handler3) rva is %p\n", *pC_SPEC_HANDLE);

			PSCOPE_TABLE pScopetable = (PSCOPE_TABLE)((PBYTE)(pC_SPEC_HANDLE + 1));

			for (size_t j = 0; j < pScopetable->Count; j++) {
				printf("\t\tTry begin address is %p\n", pScopetable->ScopeRecord[j].BeginAddress);
				printf("\t\tTry end address is %p\n", pScopetable->ScopeRecord[j].EndAddress);
				printf("\t\tTry filter address is %p\n", pScopetable->ScopeRecord[j].HandlerAddress);
				printf("\t\tTry-except address is %p\n", pScopetable->ScopeRecord[j].JumpTarget);
				printf("\n");
			}
		}
		printf("\n\n");
	}

	return VOID();
#endif // !_WIN64
}

VOID CmdSecurity(const CHAR* param)
{
	if (!g_NtHeaders) {
		printf("ERROR:Can't find loaded file.!@!\n");
		return;
	}
	PIMAGE_OPTIONAL_HEADER pOptionalHeader = &g_NtHeaders->OptionalHeader;
	PIMAGE_DATA_DIRECTORY pDataDirectorys = (PIMAGE_DATA_DIRECTORY)&pOptionalHeader->DataDirectory;

	if (pDataDirectorys[IMAGE_DIRECTORY_ENTRY_SECURITY].Size == 0 ||
		pDataDirectorys[IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress == 0) {
		printf("ERROR: This file don't have Exception!@!\n");
		return;
	}

	DWORD dwSecurityOffset = pDataDirectorys[IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress;
	DWORD dwCurrentOffset = pDataDirectorys[IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress;
	printf("Security Dir offset is 0x%08X\n", pDataDirectorys[IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress);
	printf("Security Dir size is 0x%08X\n", pDataDirectorys[IMAGE_DIRECTORY_ENTRY_SECURITY].Size);

	while (dwCurrentOffset < dwSecurityOffset + pDataDirectorys[IMAGE_DIRECTORY_ENTRY_SECURITY].Size) {
		LPWIN_CERTIFICATE lpSecurity = (LPWIN_CERTIFICATE)(g_lpFileBuffer + dwCurrentOffset);
		printf("\tThis Certificate version is 0x%04X\n", lpSecurity->wRevision);
		printf("\tThis Certificate type is 0x%04X\n", lpSecurity->wCertificateType);
		dwCurrentOffset += lpSecurity->dwLength;
	}

	return VOID();
}

VOID CmdFileToImage(const CHAR* param)
{
	if (!g_lpFileBuffer) {
		printf("ERROR:Don't load file\n");
		return;
	}
	g_lpImageBuffer = Filebuffer2Imagebuffer(g_lpFileBuffer);
	if(!g_lpImageBuffer){
		printf("ERROR:File to Image failed\n");
		return;
	}
	printf("File to Image success!\n");
	printf("Image buffer addr is 0x%p\n", g_lpImageBuffer);
	printf("Image size is 0x%08X\n", g_NtHeaders->OptionalHeader.SizeOfImage);

	return VOID();
}

VOID CmdImageToFile(const CHAR* param)
{
	if (!g_lpImageBuffer) {
		printf("ERROR:Don't have image buffer\n");
		return;
	}
	DWORD FileSize = 0;
	PBYTE FileBuffer = Imagebuffer2Filebuffer(g_lpImageBuffer, &FileSize);
	if (!FileBuffer) {
		printf("ERROR:Image to File failed\n");
		return;
	}
	if (!SaveBufferToFile(param, FileBuffer, FileSize)) {
		printf("ERROR:Save file failed\n");
		return;
	}
	printf("Image to File success!\n");
	return VOID();
}

VOID CmdMyLoadLibraryA(const CHAR* param)
{
	if (*param == '\0') {
		printf("ERROR:THIS CMD NEEDED A PARAM!\n");
		return;
	}

	for (DWORD i = 0;i < g_dwLoadedModulecnt;i++) {
		if (!strcmp(param, g_LoadModules[i].szpath)) {
			printf("ERROR:This Library Is Loaded\n");
			printf("LIB BASE:0x%p\n", g_LoadModules[i].dllbase);
			printf("LIB SIZE:%04X\n", g_LoadModules[i].ImageSize);
			return;
		}
	}

	DWORD dwImageSize = 0;
	PBYTE lpImageBuffer = MyLoadLibraryA(param, &dwImageSize);

	if (!lpImageBuffer) {
		printf("ERROR:Can't Loaded This LIB:%s\n", param);
		return;
	}

	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)lpImageBuffer;
	PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)(lpImageBuffer + pDosHeader->e_lfanew);


	PIMAGE_OPTIONAL_HEADER pOptionalHeader = &pNtHeader->OptionalHeader;
	PIMAGE_DATA_DIRECTORY pDataDirectorys = pOptionalHeader->DataDirectory;

	if (pDataDirectorys[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress == 0 || pDataDirectorys[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size == 0) {
		printf("THIS FILE DON'T EXIST RELOCATION\n");
	}

	PIMAGE_BASE_RELOCATION pRelocation = (PIMAGE_BASE_RELOCATION)(lpImageBuffer + pDataDirectorys[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);

	printf("LIB BASE:0x%p\n", lpImageBuffer);
	printf("LIB SIZE:%04X\n", dwImageSize);
	printf("LIB RELOCATION:0x%p\n", pRelocation);

	strncpy(g_LoadModules[g_dwLoadedModulecnt].szpath, param, MAX_PATH - 1);
	g_LoadModules[g_dwLoadedModulecnt].szpath[MAX_PATH - 1] = '\0';
	g_LoadModules[g_dwLoadedModulecnt].dllbase = lpImageBuffer;
	g_LoadModules[g_dwLoadedModulecnt].ImageSize = dwImageSize;
	g_dwLoadedModulecnt++;

	return VOID();
}

VOID CmdMyGetProcAddress(const CHAR* param)
{
	uintptr_t LibBase = NULL;
	void* tempBase = NULL;
	CHAR FunName[0xFF] = {0};
	WORD FunOrd = 0;

	if (sscanf(param, "%p:%hu", &tempBase, &FunOrd) == 2) {
		// 成功解析为函数名格式
		LibBase = (uintptr_t)tempBase;
		printf("Using function Ord: %d\n", FunOrd);
		// 这里处理函数名的情况
	}
	// 再尝试解析为 基址 + 序号
	else if (sscanf(param, "%p:%255s", &tempBase, FunName) == 2) {
		// 成功解析为序号格式
		LibBase = (uintptr_t)tempBase;
		printf("Using Name: %s\n", FunName);
		// 这里处理序号的情况
	}
	else {
		printf("ERROR: WRONG PARAM\n");
		printf("Expected: <BaseAddress>:<FunctionName> OR <BaseAddress>:<Ordinal>\n");
		return;
	}

	for (int i = 0; i < MAX_LOAD; i++) {
		if (LibBase == (uintptr_t)g_LoadModules[i].dllbase) {
			FARPROC Funaddr = NULL;
			if (*FunName) {
				Funaddr = MyGetProcAddressByName((HMODULE)(g_LoadModules[i].dllbase), FunName);
			}
			else {
				Funaddr = MyGetProcAddressByOrd((HMODULE)(g_LoadModules[i].dllbase), FunOrd);
			}

			if (!Funaddr) {
				printf("ERROR:Can't Find This Funcation:%s", param);
				return;
			}
			uintptr_t Funoffset = (uintptr_t)Funaddr - (uintptr_t)g_LoadModules[i].dllbase;
			printf("FUNCATION ADDRESS:0x%p\n", Funaddr);
			printf("FUNCATION OFFSET:0x%p\n", (void*)Funoffset);
			
			if (Funoffset) {
				using pFun = int(*)(int, int);
				pFun iic = (pFun)Funaddr;
				int k = iic(2, 1);
				printf("result k is %d\n", k);
			}
			break;
		}
	}

	return VOID();
}

DWORD Rva2Foa(DWORD rva) {
	if (!g_SectionHeader) {
		printf("ERROR:Don't load file\n");
		return 0;
	}
	for (int i = 0;i < g_NtHeaders->FileHeader.NumberOfSections;i++) {
		DWORD startrva = g_SectionHeader[i].VirtualAddress;
		DWORD endrva = g_SectionHeader[i].VirtualAddress + g_SectionHeader[i].Misc.VirtualSize;
		if (rva >= startrva && rva < endrva) {
			DWORD foa = (rva - startrva) + g_SectionHeader[i].PointerToRawData;
			return foa;
		}
	}
	printf("ERROR:WRONG ADDRESS\n");
	return 0;
}

DWORD Foa2Rva(DWORD foa) {
	if (!g_SectionHeader) {
		printf("ERROR:Don't load file\n");
		return 0;
	}

	for (int i = 0;i < g_NtHeaders->FileHeader.NumberOfSections;i++) {
		DWORD startfoa = g_SectionHeader[i].PointerToRawData;
		DWORD endfoa = g_SectionHeader[i].PointerToRawData + g_SectionHeader[i].SizeOfRawData;
		if (foa >= startfoa && foa < endfoa) {
			DWORD rva = (foa - startfoa) + g_SectionHeader[i].VirtualAddress;
			return rva;
		}
	}
	printf("ERROR:WRONG ADDRESS\n");
	return 0;
}

PBYTE GetFunAddrByName(const CHAR* Funname)
{
	if (!g_NtHeaders) {
		printf("ERROR: Can't find loaded file!@!\n");
		return 0;
	}

	PIMAGE_OPTIONAL_HEADER pOptionalHeader = &g_NtHeaders->OptionalHeader;
	PIMAGE_DATA_DIRECTORY pDataDirectorys = (PIMAGE_DATA_DIRECTORY)&pOptionalHeader->DataDirectory;

	if (pDataDirectorys[IMAGE_DIRECTORY_ENTRY_EXPORT].Size == 0 || pDataDirectorys[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress == 0) {
		printf("ERROR: This file don't have expect table!@!\n");
		return 0;
	}
	PIMAGE_EXPORT_DIRECTORY ExportDirectory =
		(PIMAGE_EXPORT_DIRECTORY)(g_lpFileBuffer + Rva2Foa(pDataDirectorys[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress));
	
	DWORD* NameRvaArray =
		(DWORD*)(g_lpFileBuffer +
			Rva2Foa(ExportDirectory->AddressOfNames));

	DWORD* AddrRvaArray =
		(DWORD*)(g_lpFileBuffer +
			Rva2Foa(ExportDirectory->AddressOfFunctions));

	WORD* OrdArray =
		(WORD*)(g_lpFileBuffer +
			Rva2Foa(ExportDirectory->AddressOfNameOrdinals));

	for (size_t i = 0;i < ExportDirectory->NumberOfNames;i++) {
		PCHAR pFunName = (PCHAR)g_lpFileBuffer + Rva2Foa(NameRvaArray[i]);
		if (!strcmp(pFunName,Funname)){
			return (g_lpFileBuffer + Rva2Foa(AddrRvaArray[i]));
		}
	}
	printf("ERROR:Can't find this function\n");

	return 0;
}

DWORD GetFunAddrByIndex(WORD idx)
{
	if (!g_NtHeaders) {
		printf("ERROR: Can't find loaded file!@!\n");
		return 0;
	}

	
	PIMAGE_OPTIONAL_HEADER pOptionalHeader = &g_NtHeaders->OptionalHeader;
	PIMAGE_DATA_DIRECTORY pDataDirectorys = (PIMAGE_DATA_DIRECTORY)&pOptionalHeader->DataDirectory;

	if (pDataDirectorys[IMAGE_DIRECTORY_ENTRY_EXPORT].Size == 0 || pDataDirectorys[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress == 0) {
		printf("ERROR: This file don't have expect table!@!\n");
		return 0;
	}

	PIMAGE_EXPORT_DIRECTORY ExportDirectory =
		(PIMAGE_EXPORT_DIRECTORY)(g_lpFileBuffer + Rva2Foa(pDataDirectorys[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress));

	if (idx >= ExportDirectory->NumberOfFunctions) {
		printf("ERROR:What? Given Array Index Out of Bounds,No ctf\n");
		return 0;
	}

	DWORD* NameRvaArray =
		(DWORD*)(g_lpFileBuffer +
			Rva2Foa(ExportDirectory->AddressOfNames));

	DWORD* AddrRvaArray =
		(DWORD*)(g_lpFileBuffer +
			Rva2Foa(ExportDirectory->AddressOfFunctions));

	WORD* OrdArray =
		(WORD*)(g_lpFileBuffer +
			Rva2Foa(ExportDirectory->AddressOfNameOrdinals));

	DWORD FunAddr = AddrRvaArray[idx - ExportDirectory->Base];
	if (!FunAddr) {
		printf("ERROR:INVALID ORD!@!\n");
		return 0;
	}

	return FunAddr;
}

PBYTE Filebuffer2Imagebuffer(PBYTE lpFileBuffer)
{
	if (!lpFileBuffer) return NULL;
	
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)lpFileBuffer;
	if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) return 0;

	PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)(lpFileBuffer + pDosHeader->e_lfanew);
	if (pNtHeader->Signature != IMAGE_NT_SIGNATURE) return 0;

	PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pNtHeader);

	DWORD dwSizeOfImage = 0;
	if (g_NtHeaders->FileHeader.Machine == IMAGE_FILE_MACHINE_I386) {
		PIMAGE_OPTIONAL_HEADER32 pOptionalHeader = (PIMAGE_OPTIONAL_HEADER32)&pNtHeader->OptionalHeader;
		dwSizeOfImage = pOptionalHeader->SizeOfImage;
	}
	else {
		PIMAGE_OPTIONAL_HEADER64 pOptionalHeader = (PIMAGE_OPTIONAL_HEADER64)&pNtHeader->OptionalHeader;
		dwSizeOfImage = pOptionalHeader->SizeOfImage;
	}

	PCHAR lpImageBuffer = (PCHAR)malloc(dwSizeOfImage);
	if (!lpImageBuffer) {
		printf("malloc failed\n");
		return 0;
	}
	
	memset(lpImageBuffer, 0, dwSizeOfImage);
	DWORD HeaderSize = pNtHeader->OptionalHeader.SizeOfHeaders;
	memcpy(lpImageBuffer, lpFileBuffer, HeaderSize);

	for (size_t i = 0;i < pNtHeader->FileHeader.NumberOfSections;i++) {
		memcpy(
			lpImageBuffer + pSectionHeader[i].VirtualAddress,
			lpFileBuffer + pSectionHeader[i].PointerToRawData,
			min(pSectionHeader[i].SizeOfRawData, pSectionHeader[i].Misc.VirtualSize)
		);
	}

	return (PBYTE)lpImageBuffer;
}

PBYTE Imagebuffer2Filebuffer(PBYTE lpImageBuffer, PDWORD pFileSize)
{
	if (!lpImageBuffer) return NULL;

	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)lpImageBuffer;
	if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) return NULL;

	PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)(lpImageBuffer + pDosHeader->e_lfanew);
	if (pNtHeader->Signature != IMAGE_NT_SIGNATURE) return NULL;

	PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pNtHeader);


	if (g_NtHeaders->FileHeader.Machine == IMAGE_FILE_MACHINE_I386) {
		PIMAGE_OPTIONAL_HEADER32 pOptionalHeader = (PIMAGE_OPTIONAL_HEADER32)&pNtHeader->OptionalHeader;
	}
	else {
		PIMAGE_OPTIONAL_HEADER64 pOptionalHeader = (PIMAGE_OPTIONAL_HEADER64)&pNtHeader->OptionalHeader;
	}

	DWORD dwSizeOfFile = 0x1000;

	for (DWORD i = 0; i < pNtHeader->FileHeader.NumberOfSections; i++) {
		DWORD dwSectionEnd = pSectionHeader[i].PointerToRawData + pSectionHeader[i].SizeOfRawData;
		if (dwSectionEnd > dwSizeOfFile) {
			dwSizeOfFile = dwSectionEnd;
		}
	}

	// 确保文件大小至少包含PE头
	DWORD HeaderSize = pNtHeader->OptionalHeader.SizeOfHeaders;
	dwSizeOfFile = max(dwSizeOfFile, HeaderSize);

	PCHAR lpFileBuffer = (PCHAR)malloc(dwSizeOfFile);
	if (!lpFileBuffer) {
		printf("malloc failed\n");
		return 0;
	}

	memset(lpFileBuffer, 0, dwSizeOfFile);
	memcpy(lpFileBuffer, lpImageBuffer, HeaderSize);

	for (size_t i = 0;i < pNtHeader->FileHeader.NumberOfSections;i++) {
		if (pSectionHeader[i].SizeOfRawData) {
			memcpy(
				lpFileBuffer + pSectionHeader[i].PointerToRawData,
				lpImageBuffer + pSectionHeader[i].VirtualAddress,
				min(pSectionHeader[i].SizeOfRawData, pSectionHeader[i].Misc.VirtualSize)
			);
		}
	}
	*pFileSize = dwSizeOfFile;
	return (PBYTE)lpFileBuffer;
}

BOOL SaveBufferToFile(const CHAR* filepath, PBYTE lpBuffer, DWORD dwBufferSize)
{
	if (*filepath == 0 || !lpBuffer || dwBufferSize == 0) return FALSE;
	HANDLE hFile = CreateFileA(
		filepath,
		GENERIC_WRITE,
		FILE_SHARE_WRITE,
		NULL,
		CREATE_ALWAYS,
		FILE_ATTRIBUTE_NORMAL,
		NULL
	);

	if (hFile == INVALID_HANDLE_VALUE) {
		printf("ERROR: CreateFileA failed, ERROR CODE: %d\n", GetLastError());
		return FALSE;
	}

	DWORD dwBytesWritten = 0;
	if (!WriteFile(hFile, lpBuffer, dwBufferSize, &dwBytesWritten, NULL) || dwBytesWritten != dwBufferSize) {
		printf("ERROR: WriteFile failed, ERROR CODE: %d\n", GetLastError());
		CloseHandle(hFile);
		return FALSE;
	}

	return TRUE;
}

PBYTE MyLoadLibraryA(const CHAR* dllpath,DWORD* ImageSize)
{
	// check
	if (!dllpath || *dllpath == 0) {
		printf("ERROR: Invalid DLL path.\n");
		return 0;
	}
	// 打开文件
	HANDLE hFile = CreateFileA(
		dllpath,
		GENERIC_READ,
		FILE_SHARE_READ,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL
	);
	if (hFile == INVALID_HANDLE_VALUE) {
		printf("ERROR:Can't open file %s,ERROR CODE:%d\n", dllpath, GetLastError());
		return 0;
	}

	// 获取文件大小

	DWORD dwFileSize = 0;
	dwFileSize = GetFileSize(hFile, NULL);
	if (dwFileSize == INVALID_FILE_SIZE) {
		printf("ERROR: GetFileSize failed, ERROR CODE: %d\n", GetLastError());
		return 0;
	}

	// 申请、写入缓冲区
	PBYTE lpFileBuffer = (PBYTE)malloc(dwFileSize);
	if (!lpFileBuffer) {
		printf("malloc failed,bad luck\n");
		return 0;
	}

	// 获取数据
	DWORD dwByteRead = 0;
	if (!ReadFile(hFile, lpFileBuffer, dwFileSize, &dwByteRead, NULL) || dwByteRead != dwFileSize) {
		printf("ERROR:WRONG READ\n");
		return 0;
	}

	CloseHandle(hFile);

	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)lpFileBuffer;
	if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE/*0x5A4D*/) {
		printf("ERROR:WRONG DOS SIGNATURE->0x%04X\n", pDosHeader->e_magic);
		return 0;
	}

	// NT
	DWORD dwNtHeaderoffset = pDosHeader->e_lfanew;
	if (dwNtHeaderoffset < sizeof(IMAGE_DOS_HEADER) || dwNtHeaderoffset + sizeof(IMAGE_DOS_HEADER)>dwFileSize) {
		printf("ERROR:WRONG NT OFFSET->0x%04X\n", dwNtHeaderoffset);
		return 0;
	}
	PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)(lpFileBuffer + dwNtHeaderoffset);
	if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE/*0x00004550*/) {
		printf("ERROR:WRONG NT Signature->0x%04X\n", pNtHeaders->Signature);
		return 0;
	}

	PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pNtHeaders);

	PIMAGE_OPTIONAL_HEADER pOptionalHeader = (PIMAGE_OPTIONAL_HEADER)&pNtHeaders->OptionalHeader;
	DWORD dwSizeOfImage = pOptionalHeader->SizeOfImage;
	*ImageSize = dwSizeOfImage;
	PBYTE lpImageBuffer = (PBYTE)VirtualAlloc(NULL, dwSizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	uintptr_t ImageBaseDelta = (uintptr_t)(lpImageBuffer - pOptionalHeader->ImageBase);
	
	if (!lpImageBuffer) {
		printf("malloc failed\n");
		return 0;
	}
	// copy

	memset(lpImageBuffer, 0, dwSizeOfImage);
	DWORD HeaderSize = pNtHeaders->OptionalHeader.SizeOfHeaders;
	memcpy(lpImageBuffer, lpFileBuffer, HeaderSize);

	for (size_t i = 0;i < pNtHeaders->FileHeader.NumberOfSections;i++) {
		if (pSectionHeader[i].SizeOfRawData > 0) {
			memcpy(
				lpImageBuffer + pSectionHeader[i].VirtualAddress,
				lpFileBuffer + pSectionHeader[i].PointerToRawData,
				min(pSectionHeader[i].SizeOfRawData, pSectionHeader[i].Misc.VirtualSize)
			);
		}
	}
	// import
	if (!FixImport(lpImageBuffer)) {
		printf("ERROR: Fix Import Failed\n");
		return 0;
	}

	// relocation
	if (ImageBaseDelta != 0) {
		if (!FixRelocation(lpImageBuffer, ImageBaseDelta)) {
			printf("WARNING: Fix Relocation Failed Or Not Exit Relocation\n");
			return 0;
		}
	}
	// exec
	 
	// clean
	free(lpFileBuffer);
	lpFileBuffer = NULL;

	return lpImageBuffer;
}

BOOL FixImport(PBYTE lpImageBuffer)
{
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)lpImageBuffer;
	PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)(lpImageBuffer + pDosHeader->e_lfanew);

	PIMAGE_OPTIONAL_HEADER pOptionalHeader = &pNtHeader->OptionalHeader;
	PIMAGE_DATA_DIRECTORY pDataDirectorys = pOptionalHeader->DataDirectory;

	if (pDataDirectorys[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress == 0 ||
		pDataDirectorys[IMAGE_DIRECTORY_ENTRY_IMPORT].Size == 0) {
		printf("THIS FILE DON'T EXIST IMPORT\n");
		return TRUE;
	}

	PIMAGE_IMPORT_DESCRIPTOR pImportDir = (PIMAGE_IMPORT_DESCRIPTOR)(lpImageBuffer + pDataDirectorys[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

	while (pImportDir->Name) {
		PCHAR dllname = (PCHAR)(lpImageBuffer + pImportDir->Name);

		HMODULE h_libmodule = LoadLibraryA(dllname);
		if (!h_libmodule) {
			printf("WARNING: Can't load DLL: %s\n", dllname);
			pImportDir++;
			continue;
		}

		// 正确处理OriginalFirstThunk为0的情况
		PIMAGE_THUNK_DATA pThunkINT = NULL;
		if (pImportDir->OriginalFirstThunk != 0) {
			pThunkINT = (PIMAGE_THUNK_DATA)(lpImageBuffer + pImportDir->OriginalFirstThunk);
		}
		else {
			pThunkINT = (PIMAGE_THUNK_DATA)(lpImageBuffer + pImportDir->FirstThunk);
		}

		PIMAGE_THUNK_DATA pThunkIAT = (PIMAGE_THUNK_DATA)(lpImageBuffer + pImportDir->FirstThunk);

		while (pThunkINT->u1.AddressOfData) {
			FARPROC FunAddr = NULL;
			PCHAR FunName = NULL;
			WORD FunOrd = 0;

			if (IMAGE_SNAP_BY_ORDINAL(pThunkINT->u1.AddressOfData)) {
				FunOrd = IMAGE_ORDINAL(pThunkINT->u1.AddressOfData);
				FunAddr = GetProcAddress(h_libmodule, (LPCSTR)FunOrd);
			}
			else {
				PIMAGE_IMPORT_BY_NAME pImportByName = (PIMAGE_IMPORT_BY_NAME)(lpImageBuffer + pThunkINT->u1.AddressOfData);
				FunName = (PCHAR)pImportByName->Name;
				FunAddr = GetProcAddress(h_libmodule, FunName);
			}

			if (!FunAddr) {
				printf("ERROR: Failed to resolve function! DLL: %s, ", dllname);
				if (FunName) {
					printf("Name: %s\n", FunName);
				}
				else {
					printf("Ordinal: %d\n", FunOrd);
				}
				// 继续处理其他函数，不返回
			}
			else {
				pThunkIAT->u1.Function = (uintptr_t)FunAddr;
			}

			pThunkINT++;
			pThunkIAT++;
		}

		pImportDir++;
	}

	return TRUE;
}

BOOL FixRelocation(PBYTE lpImageBuffer, uintptr_t Delta)
{
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)lpImageBuffer;
	PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)(lpImageBuffer + pDosHeader->e_lfanew);


	PIMAGE_OPTIONAL_HEADER pOptionalHeader = &pNtHeader->OptionalHeader;
	PIMAGE_DATA_DIRECTORY pDataDirectorys = pOptionalHeader->DataDirectory;

	if (pDataDirectorys[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress == 0 || pDataDirectorys[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size == 0) {
		printf("THIS FILE DON'T EXIST RELOCATION\n");
		return TRUE;
	}

	PIMAGE_BASE_RELOCATION pRelocation = (PIMAGE_BASE_RELOCATION)(lpImageBuffer + pDataDirectorys[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
	
	while (pRelocation->SizeOfBlock) {
		uintptr_t lpbase = (uintptr_t)(lpImageBuffer + pRelocation->VirtualAddress);
		PWORD pRelocationOffset = (PWORD)((PBYTE)pRelocation + sizeof(IMAGE_BASE_RELOCATION));
		while (*pRelocationOffset) {
			BYTE RelType = *pRelocationOffset >> 12;
			WORD RelEntry = *pRelocationOffset & 0xFFF;
			if (RelType == IMAGE_REL_BASED_HIGHLOW) {
				PDWORD pTarget = (PDWORD)(lpbase + RelEntry);
				//printf("Relocation:%p\n", pTarget);
				*pTarget += (DWORD)Delta;
			}
			else if (RelType == IMAGE_REL_BASED_DIR64) {
				PULONGLONG pTarget = (PULONGLONG)(lpbase + RelEntry);
				//printf("Relocation:%p\n", pTarget);
				*pTarget += (ULONGLONG)Delta;
			}
			pRelocationOffset++;
		}
		pRelocation = (PIMAGE_BASE_RELOCATION)((PBYTE)pRelocation + pRelocation->SizeOfBlock);
	}
	
	return TRUE;
}

FARPROC MyGetProcAddressByName(HMODULE dllbase, const CHAR* funname)
{
	PBYTE lpImageBuffer = (PBYTE)dllbase;
	if (!lpImageBuffer || !funname || *funname == '\0') return NULL;

	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)lpImageBuffer;
	PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)(lpImageBuffer + pDosHeader->e_lfanew);


	PIMAGE_OPTIONAL_HEADER pOptionalHeader = &pNtHeader->OptionalHeader;
	PIMAGE_DATA_DIRECTORY pDataDirectorys = pOptionalHeader->DataDirectory;

	if (pDataDirectorys[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress == 0 || pDataDirectorys[IMAGE_DIRECTORY_ENTRY_EXPORT].Size == 0) {
		printf("THIS FILE DON'T EXIST EXPORT\n");
		return NULL;
	}

	PIMAGE_EXPORT_DIRECTORY pExportDir = (PIMAGE_EXPORT_DIRECTORY)(lpImageBuffer + pDataDirectorys[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

	
	PDWORD pAddressOfFunctions = (PDWORD)(lpImageBuffer + pExportDir->AddressOfFunctions);
	PDWORD pAddressOfNames = (PDWORD)(lpImageBuffer + pExportDir->AddressOfNames);
	PWORD pAddressOfNameOrdinals = (PWORD)(lpImageBuffer + pExportDir->AddressOfNameOrdinals);

	for (size_t i = 0;i < pExportDir->NumberOfNames;i++) {
		PCHAR FunName = (PCHAR)(lpImageBuffer + pAddressOfNames[i]);
		if (!strcmp(FunName, funname)) {
			return (FARPROC)(lpImageBuffer + pAddressOfFunctions[pAddressOfNameOrdinals[i]]);
		}
	}
	printf("ERROR:Can't Find This Function:%s\n", funname);
	return FARPROC();
}

FARPROC MyGetProcAddressByOrd(HMODULE dllbase, DWORD Ord)
{
	PBYTE lpImageBuffer = (PBYTE)dllbase;
	if (!lpImageBuffer) return NULL;

	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)lpImageBuffer;
	PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)(lpImageBuffer + pDosHeader->e_lfanew);


	PIMAGE_OPTIONAL_HEADER pOptionalHeader = &pNtHeader->OptionalHeader;
	PIMAGE_DATA_DIRECTORY pDataDirectorys = pOptionalHeader->DataDirectory;

	if (pDataDirectorys[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress == 0 || pDataDirectorys[IMAGE_DIRECTORY_ENTRY_EXPORT].Size == 0) {
		printf("THIS FILE DON'T EXIST EXPORT\n");
		return NULL;
	}

	PIMAGE_EXPORT_DIRECTORY pExportDir = (PIMAGE_EXPORT_DIRECTORY)(lpImageBuffer + pDataDirectorys[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

	DWORD Index = Ord - pExportDir->Base;
	if (Index >= pExportDir->NumberOfFunctions) {
		printf("ERROR:UPPER TO THE MAX ORD,NO CTF");
		return NULL;
	}

	PDWORD pAddressOfFunctions = (PDWORD)(lpImageBuffer + pExportDir->AddressOfFunctions);
	PDWORD pAddressOfNames = (PDWORD)(lpImageBuffer + pExportDir->AddressOfNames);
	PWORD pAddressOfNameOrdinals = (PWORD)(lpImageBuffer + pExportDir->AddressOfNameOrdinals);

	return (FARPROC)(lpImageBuffer+ pAddressOfFunctions[Index]);
}

VOID ParseResourceDir(PIMAGE_RESOURCE_DIRECTORY pResource, WORD level, size_t ResBasefoa)
{
	if (!pResource) {
		return;
	}

	char indent[0x10] = "";
	for (size_t i = 0; i < level; i++) {
		strcat(indent, "\t");
	}

	DWORD NumberOfNamed = pResource->NumberOfNamedEntries;
	DWORD NumberOfId = pResource->NumberOfIdEntries;

	PIMAGE_RESOURCE_DIRECTORY_ENTRY pResourceDirEntry =
		(PIMAGE_RESOURCE_DIRECTORY_ENTRY)((PBYTE)pResource+sizeof(IMAGE_RESOURCE_DIRECTORY));
	
	for (size_t i = 0;i < NumberOfNamed;i++) {
		if (pResourceDirEntry[i].Name & IMAGE_RESOURCE_NAME_IS_STRING) {
			printf("%sName offset is 0x%p\n", indent, pResourceDirEntry[i].Name);
			PIMAGE_RESOURCE_DIR_STRING_U pResourceDirString = 
				(PIMAGE_RESOURCE_DIR_STRING_U)(g_lpFileBuffer +
					ResBasefoa +
					(pResourceDirEntry[i].Name & ~IMAGE_RESOURCE_NAME_IS_STRING)
					);

			printf("%sName is ", indent);
			fflush(stdout);  
			wprintf(L"%ls\n", pResourceDirString->NameString);

			printf("%soffset is 0x%p\n", indent, pResourceDirEntry[i].OffsetToData);
			if (pResourceDirEntry[i].OffsetToData & IMAGE_RESOURCE_DATA_IS_DIRECTORY && level < 2) {
				PIMAGE_RESOURCE_DIRECTORY pNewResource =
					(PIMAGE_RESOURCE_DIRECTORY)(g_lpFileBuffer +
						ResBasefoa +
						(pResourceDirEntry[i].OffsetToData & ~IMAGE_RESOURCE_DATA_IS_DIRECTORY)
						);
				ParseResourceDir(
					pNewResource,
					level + 1,
					ResBasefoa
				);
			}
		}


		if (level == 2) {
			PIMAGE_RESOURCE_DATA_ENTRY pResourceData =
				(PIMAGE_RESOURCE_DATA_ENTRY)(g_lpFileBuffer +
					ResBasefoa +
					pResourceDirEntry[i].OffsetToData
					);
			printf("\t\t\tSource offset is 0x%04X\n", pResourceData->OffsetToData);
			printf("\t\t\tSource size is 0x%04X\n", pResourceData->Size);
		}
	}

	for (size_t i = NumberOfNamed;i < NumberOfNamed + NumberOfId;i++) {
		printf("%sid is 0x%p\n",indent,pResourceDirEntry[i].Id);
		printf("%soffset is 0x%p\n", indent, pResourceDirEntry[i].OffsetToData);
		if (pResourceDirEntry[i].OffsetToData & IMAGE_RESOURCE_DATA_IS_DIRECTORY && level < 2) {
			PIMAGE_RESOURCE_DIRECTORY pNewResource = 
				(PIMAGE_RESOURCE_DIRECTORY)(g_lpFileBuffer +
					ResBasefoa +
					(pResourceDirEntry[i].OffsetToData & ~IMAGE_RESOURCE_DATA_IS_DIRECTORY)
			);
			ParseResourceDir(
				pNewResource,
				level + 1,
				ResBasefoa
			);
		}
		if (level == 2) {
			PIMAGE_RESOURCE_DATA_ENTRY pResourceData =
				(PIMAGE_RESOURCE_DATA_ENTRY)(g_lpFileBuffer +
					ResBasefoa +
					pResourceDirEntry[i].OffsetToData
			);
			printf("\t\t\tSource offset is 0x%04X\n", pResourceData->OffsetToData);
			printf("\t\t\tSource size is 0x%04X\n", pResourceData->Size);
		}
	}
}

VOID CmdRva(const CHAR* param)
{
	if (!g_SectionHeader) {
		printf("ERROR:Don't load file\n");
		return;
	}
	DWORD rva = 0;
	if (sscanf(param, "0x%x", &rva) != 1) {
		printf("ERROR: WRONG FMT!\n");
		return;
	}
	for (int i = 0;i < g_NtHeaders->FileHeader.NumberOfSections;i++) {
		DWORD startrva = g_SectionHeader[i].VirtualAddress;
		DWORD endrva = g_SectionHeader[i].VirtualAddress + g_SectionHeader[i].Misc.VirtualSize;
		if (rva >= startrva && rva < endrva) {
			DWORD foa = (rva - startrva) + g_SectionHeader[i].PointerToRawData;
			printf("RVA:0x%08X -> FOA:0x%08X\n", rva, foa);
			printf("Section Name: %s\n", g_SectionHeader[i].Name);
			char szCharacteristics[16] = "Section is ---";

			// 清空权限位
			szCharacteristics[11] = '-';
			szCharacteristics[12] = '-';
			szCharacteristics[13] = '-';

			// 使用位运算检查多个标志
			if (g_SectionHeader[i].Characteristics & IMAGE_SCN_MEM_READ) {
				szCharacteristics[11] = 'R';
			}
			if (g_SectionHeader[i].Characteristics & IMAGE_SCN_MEM_WRITE) {
				szCharacteristics[12] = 'W';
			}
			if (g_SectionHeader[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) {
				szCharacteristics[13] = 'E';
			}
			printf("%s\n", szCharacteristics);
			return;
		}
	}
	printf("ERROR:WRONG ADDRESS\n");
	return;
}

VOID CmdFoa(const CHAR* param)
{
	if (!g_SectionHeader) {
		printf("ERROR:Don't load file\n");
		return;
	}
	DWORD foa = 0;
	if (sscanf(param, "0x%x", &foa) != 1) {
		printf("ERROR: WRONG FMT!\n");
		return;
	}
	for (int i = 0;i < g_NtHeaders->FileHeader.NumberOfSections;i++) {
		DWORD startfoa = g_SectionHeader[i].PointerToRawData;
		DWORD endfoa = g_SectionHeader[i].PointerToRawData + g_SectionHeader[i].SizeOfRawData;
		if (foa >= startfoa && foa < endfoa) {
			DWORD rva = (foa - startfoa) + g_SectionHeader[i].VirtualAddress;
			printf("FOA:0x%08X -> ROA:0x%08X\n", foa, rva);
			printf("Section Name: %s\n", g_SectionHeader[i].Name);
			char szCharacteristics[16] = "Section is ---";

			// 清空权限位
			szCharacteristics[11] = '-';
			szCharacteristics[12] = '-';
			szCharacteristics[13] = '-';

			// 使用位运算检查多个标志
			if (g_SectionHeader[i].Characteristics & IMAGE_SCN_MEM_READ) {
				szCharacteristics[11] = 'R';
			}
			if (g_SectionHeader[i].Characteristics & IMAGE_SCN_MEM_WRITE) {
				szCharacteristics[12] = 'W';
			}
			if (g_SectionHeader[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) {
				szCharacteristics[13] = 'E';
			}
			printf("%s\n", szCharacteristics);
			return;
		}
	}
	printf("ERROR:WRONG ADDRESS\n");
	return;
}

VOID CmdExit(const CHAR* param)
{
	g_RUNNING = FALSE;
	return VOID();
}

CmdHandler Findhandler(const CHAR* cmd)
{
	for (CONST CmdEntry* entry = CmdTable;entry->cmd != 0;entry++) {
		if (strcmp(cmd,entry->cmd) == 0) {
			return entry->handler;
		}
	}
	return NULL;
}
