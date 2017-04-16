#include "zeroload.h"

__declspec(noinline) LPVOID zeroload_start_address(VOID) 
{ 
	return _ReturnAddress(); 
}

LPBYTE __forceinline zeroload_get_base()
{
	LPBYTE lpStartAddr = zeroload_start_address();

	while (--lpStartAddr)
	{
		PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)lpStartAddr;

		if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
			continue;

		if (pDosHeader->e_lfanew <= sizeof(IMAGE_DOS_HEADER))
			continue;

		if (pDosHeader->e_lfanew > 1024)
			continue;

		if (((PIMAGE_NT_HEADERS)(lpStartAddr + pDosHeader->e_lfanew))->Signature == IMAGE_NT_SIGNATURE)
			return lpStartAddr;
	}

	return NULL;
}

VOID WINAPI zeroload_reflective_load(LPVOID lpBaseAddress)
{

}

VOID __declspec(dllexport) WINAPI zeroload(LPVOID lpParam)
{
	LPBYTE lpBaseAddr = NULL;
	
	FnLoadLibraryA_t pLoadLibraryA = NULL;
	FnGetProcAddress_t pGetProcAddress = NULL;
	FnVirtualAlloc_t pVirtualAlloc = NULL;
	FnNtFlushInstructionCache_t pNtFlushInstructionCache = NULL;

	lpBaseAddr = zeroload_get_base();
	//lpPEBLdr = zeroload_get_peb_ldr();
}