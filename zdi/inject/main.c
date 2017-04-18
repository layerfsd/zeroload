#include "../dll/zeroload/zeroload.h"

#include <stdlib.h>
#include <stdio.h>

void print_hash(const char *str)
{
	printf("zl_compute_hash(\"%s\", 0) = %08x\n", str, zl_compute_hash(str, 0));
}

void print_hashes()
{
	print_hash("ntdll.dll");
	print_hash("kernel32.dll");

	print_hash("VirtualAlloc");
	print_hash("VirtualFree");
	print_hash("VirtualLock");
	print_hash("VirtualUnlock");

	print_hash("LoadLibraryA");
	print_hash("SearchPathA");

	print_hash("CreateFileA");
	print_hash("ReadFile");
	print_hash("GetFileSize");
	print_hash("CloseHandle");

	print_hash("NtFlushInstructionCache");
}

int main(int argc, char *argv[])
{
	print_hashes();

	//PZEROLOAD_STATE pState = zl_state_init();

	system("PAUSE");
	return 0;
}