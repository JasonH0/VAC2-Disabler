BOOL hkDwStatus()
{
	return 9;
}
 
BOOL WINAPI hkReadProcessMemory(HANDLE hProcess, LPCVOID lpBaseAddress, LPVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesRead)
{
	DWORD dwRet = ( DWORD ) _ReturnAddress();
 
	if( sVAC.bLoaded == true && dwRet >= sVAC.dwBase && dwRet <= (sVAC.dwBase + sVAC.dwSize) )
	{
		memset( lpBuffer, 0, nSize );
		*lpNumberOfBytesRead = 0;
		nSize = NULL;
	}
 
	return pReadProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesRead);
}
 
HANDLE WINAPI hkCreateThread(LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId)
{
	DWORD dwRet = ( DWORD ) _ReturnAddress();
 
	int iThreads = 0;
 
	if( sVAC.bLoaded == true && dwRet >= sVAC.dwBase && dwRet <= (sVAC.dwBase + sVAC.dwSize) )
	{
		iThreads++;
 
		if( iThreads > 1 )
		{
			lpStartAddress = NULL;
			return INVALID_HANDLE_VALUE;
		}
	}
 
	return pCreateThread(lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, lpThreadId);
}
 
BOOL WINAPI hkPeekNamedPipe(HANDLE hNamedPipe, LPVOID lpBuffer, DWORD nBufferSize, LPDWORD lpBytesRead, LPDWORD lpTotalBytesAvail, LPDWORD lpBytesLeftThisMessage)
{
	DWORD dwRet = (DWORD)_ReturnAddress();
 
	if( sVAC.bLoaded == true && dwRet >= sVAC.dwBase && dwRet <= (sVAC.dwBase + sVAC.dwSize) )
	{
		memset( lpBuffer, 0, nBufferSize);
 
		*lpBytesLeftThisMessage  = NULL;
		*lpTotalBytesAvail = 0;
	}
 
	return pPeekNamedPipe( hNamedPipe, lpBuffer, nBufferSize, lpBytesRead, lpTotalBytesAvail, lpBytesLeftThisMessage );;
}
 
HMODULE WINAPI hkLoadLibrary(LPCSTR lpLibFileName)
{
	if( strstr(lpLibFileName, /*~*/XorStr<0xAA,2,0x0B53F738>("\xD4"+0x0B53F738).s) && strstr(lpLibFileName, /*.tmp*/XorStr<0x36,5,0xFD2B78BF>("\x18\x43\x55\x49"+0xFD2B78BF).s) )
	{
		HMODULE hReturn = pLoadLibrary(lpLibFileName);
 
		MODULEENTRY32 mod32;
		HANDLE hModuleSteam = CreateToolhelp32Snapshot( TH32CS_SNAPMODULE, GetCurrentProcessId() );
 
		mod32.dwSize = sizeof ( MODULEENTRY32 ); 
 
		if ( Module32First ( hModuleSteam, &mod32 ) )
		{
			while ( ( Module32Next( hModuleSteam, &mod32 ) ) )
			{
				if ( strstr ( mod32.szModule, /*~*/XorStr<0x92,2,0xE0F5A9B3>("\xEC"+0xE0F5A9B3).s ) && strstr ( mod32.szModule, /*.tmp*/XorStr<0x37,5,0x3674A789>("\x19\x4C\x54\x4A"+0x3674A789).s ) )
				{
					sVAC.dwBase = ( DWORD ) mod32.modBaseAddr;
					sVAC.dwSize = mod32.modBaseSize;
					sVAC.hHandle = mod32.hModule;
					sVAC.szModuleName = mod32.szModule;
					sVAC.szPath = mod32.szExePath;
 
					if( sVAC.dwBase > 0x0 && sVAC.dwSize > 0x0 && sVAC.hHandle )
					{
						BYTE bMD5[16];
						if(HashModule(sVAC.szModuleName, bMD5))
						{
							char szMD5[32];
							sprintf(szMD5, %X%X%X%X%X%X%X%X%X%X%X%X%X%X%X%X, bMD5[0], bMD5[1], bMD5[2], bMD5[3], bMD5[4], bMD5[5], bMD5[6], bMD5[7], bMD5[8], bMD5[9], bMD5[10], bMD5[11], bMD5[12], bMD5[13], bMD5[14], bMD5[15] );
							
							add_log(/*VAC2_Log.txt*/XorStr<0x02,13,0x840B21C6>("\x54\x42\x47\x37\x59\x4B\x67\x6E\x24\x7F\x74\x79"+0x840B21C6).s, Current Vac2 Hash: [%s], szMD5);
 
							if( strcmpi(szMD5, 7B6E884112C57A5B9E9F95E7D772E55 != 0 )
							{
								char szWarning[512];
								sprintf( szWarning, "Warning:\nSince this program has been released, the Vac2 module hash has changed.  This means, that since the release of this program, Vac2 has updated.  This program may or may not be detected, so use at your own risk!\nCurrent VAC2 Hash: [%s]", szMD5 );
								MessageBox(NULL, szWarning, /*Warning*/XorStr<0x34,8,0xDFC05B61>("\x63\x54\x44\x59\x51\x57\x5D"+0xDFC05B61).s, NULL);
							}
						} 
 
						sVAC.bLoaded = true;
 
						VAC Module Sucessfully Found
						 # Path: %s, mod32.szExePath);
						 # Module Name: %s, mod32.szModule);
 
						sVAC.dwStatus = ( DWORD ) GetProcAddress(GetModuleHandle(sVAC.szModuleName), /*DwStatus*/XorStr<0xE5,9,0x0E4A0B1F>("\xA1\x91\xB4\x9C\x88\x9E\x9E\x9F"+0x0E4A0B1F).s);
						
						if( sVAC.dwStatus && Hook( (char*)sVAC.dwStatus, (char*)hkDwStatus, detDwStatus) )
							VAC Hook Sucessfull
						else
							VAC Hook Failed
					}
					else
					{
						sVAC.bLoaded = false;
 
						VAC Module Corrupted
					}
 
					CloseHandle ( hModuleSteam );
				}
			}
		}
 
		return hReturn;
	}
 
	return pLoadLibrary(lpLibFileName);
}
 
HANDLE WINAPI hkCreateToolhelp32Snapshot(DWORD dwFlags, DWORD th32ProcessID)
{
	DWORD dwRet = ( DWORD ) _ReturnAddress();
 
	if( sVAC.bLoaded == true && dwRet >= sVAC.dwBase && dwRet <= (sVAC.dwBase + sVAC.dwSize) )
	{
		dwFlags = NULL;
		th32ProcessID = NULL;
 
		The loading of the VAC2 module has been blocked sucessfully.
 
		return INVALID_HANDLE_VALUE;
	}
 
	return pCreateToolhelp32Snapshot(dwFlags, th32ProcessID);
}