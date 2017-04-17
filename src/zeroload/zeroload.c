#include "zeroload.h"

__declspec(noinline) LPVOID zeroload_start_address(VOID) 
{ 
	return _ReturnAddress(); 
}

// if this is defined, support the old name
#ifdef REFLECTIVEDLLINJECTION_VIA_LOADREMOTELIBRARYR
__declspec(dllexport) ULONG_PTR WINAPI ReflectiveLoader(LPVOID lpParameter)
#else
__declspec(dllexport) ULONG_PTR WINAPI ZEROLOAD_EXPORT_NAME(LPVOID lpParam)
#endif
{
	// prevent name mangling for the export, aka _zeroload@4
	// #pragma comment(linker, "/EXPORT:" __FUNCTION__ "=" __FUNCDNAME__)
	// eh, that just did a forward...

	BOOL bReflectAll = TRUE;

	// do NOT reflectively load all imports in traditional method
#ifdef REFLECTIVEDLLINJECTION_VIA_LOADREMOTELIBRARYR
	bReflectAll = FALSE;
#endif

	LPBYTE lpStartAddr = zeroload_start_address();

	while (lpStartAddr-- && !zeroload_valid_pe(lpStartAddr))
		continue;

	// returns &DllMain
	return (ULONG_PTR)zeroload_load_image(lpStartAddr, bReflectAll);
}