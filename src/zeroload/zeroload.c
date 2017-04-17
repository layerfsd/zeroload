#include "zeroload.h"

__declspec(noinline) LPVOID zeroload_start_address(VOID) 
{ 
	return _ReturnAddress(); 
}

VOID __declspec(dllexport) __cdecl zeroload(LPVOID lpParam)
{
	// prevent name mangling for the export, aka _zeroload@4
	// #pragma comment(linker, "/EXPORT:" __FUNCTION__ "=" __FUNCDNAME__)
	// eh, that just did a forward... make it cdecl

	LPBYTE lpStartAddr = zeroload_start_address();

	while (lpStartAddr-- && !zeroload_valid_pe(lpStartAddr))
		continue;

	zeroload_load_image(lpStartAddr);
}