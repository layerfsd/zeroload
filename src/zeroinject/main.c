#include "../zeroload/zeroload.h"


#include <stdio.h>
#include <stdlib.h>

void test_get_proc_addr(const char *szModule, const char *szProc)
{
	LPBYTE pModule = zeroload_get_module_hash(ZEROLOAD_HASH_KERNEL32);
	printf("%s::%s = 0x%08x\n", szModule, szProc, zeroload_compute_hash(szProc, 0));
	printf("%llx::%llx\n", (DWORD64)pModule, (DWORD64)zeroload_get_proc_addr(pModule, szProc));
	printf("%llx::%llx\n", (DWORD64)GetModuleHandleA(szModule), (DWORD64)GetProcAddress(GetModuleHandleA(szModule), szProc));
	printf("\n");
}

void test_reflective_load(const char *szDll, const char *szProc)
{
	LPBYTE addr = zeroload_read_library_file(szDll);
	DWORD dwOffset = zeroload_get_export_offset(addr, szProc);

	printf("Calculated offset = %d\n", dwOffset);
	(*(void(*)(void*))(addr + dwOffset))(addr);
}

int main()
{
	//LoadLibraryA("user32.dll");
	//test_reflective_load("zeroload", "zeroload");

	//system("PAUSE");
	
	// call the export.
	
	LPBYTE addr = zeroload_read_library_file("zeroload");
	zeroload_load_image(addr);

	//LoadLibraryA("zeroload.dll");

	//printf("%llx\n", addr);


	printf("%08x\n", zeroload_compute_hash("ntdll.dll", 0));

	test_get_proc_addr("kernel32.dll", "LoadLibraryA");
	test_get_proc_addr("kernel32.dll", "VirtualAlloc");

	system("PAUSE");
	return 0;
}