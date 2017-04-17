#include "zeroload.h"

__declspec(noinline) LPVOID zeroload_start_address(VOID) 
{ 
	return _ReturnAddress(); 
}

#ifdef REFLECTIVEDLLINJECTION_VIA_LOADREMOTELIBRARYR
__declspec(dllexport) ULONG_PTR WINAPI ReflectiveLoader(LPVOID lpParameter)
#else
__declspec(dllexport) ULONG_PTR WINAPI zeroload(LPVOID lpParam)
#endif
{
	// prevent name mangling for the export, aka _zeroload@4
	// #pragma comment(linker, "/EXPORT:" __FUNCTION__ "=" __FUNCDNAME__)
	// eh, that just did a forward... make it cdecl

	BOOL bReflectAll = TRUE;

#ifdef REFLECTIVEDLLINJECTION_VIA_LOADREMOTELIBRARYR
	// do NOT reflectively load all imports
	bReflectAll = FALSE;
#endif

	LPBYTE lpStartAddr = zeroload_start_address();

	while (lpStartAddr-- && !zeroload_valid_pe(lpStartAddr))
		continue;

	// returns &DllMain
	return zeroload_load_image(lpStartAddr, bReflectAll);
}