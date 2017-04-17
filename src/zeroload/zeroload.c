#include "zeroload.h"

__declspec(noinline) LPVOID zeroload_start_address(VOID) 
{ 
	return _ReturnAddress(); 
}

VOID __declspec(dllexport) WINAPI zeroload(LPVOID lpParam)
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

		// found MZ and 00PE
		if (((PIMAGE_NT_HEADERS)(lpStartAddr + pDosHeader->e_lfanew))->Signature == IMAGE_NT_SIGNATURE)
			break;
	}

	zeroload_load_image(lpStartAddr);
}