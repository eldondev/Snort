//#include "snort.h"
#include <winsock2.h>
#include "packet_types.h"
#include <time.h>
#define LIBNET_LIL_ENDIAN 1
#include <windows.h>
#include <Winbase.h>
#include <assert.h>
#include <iphlpapi.h>
#include <iptypes.h>
#include <stdlib.h>
#include <malloc.h>
#include <stdio.h>
#include <string.h>
#include <limits.h>

#define        DOSNAMEPREFIX   TEXT("Packet_")
#define        MAX_LINK_NAME_LENGTH   64
#define        NMAX_PACKET 65535  

typedef struct _ADAPTER  { 
						   HANDLE hFile;
                           TCHAR  SymbolicLink[MAX_LINK_NAME_LENGTH];
						   int NumWrites;
						 }  ADAPTER, *LPADAPTER;

typedef struct GlobalInfo
{
	LPADAPTER  lpAdapter;
	BYTE MAC[6];
	char Aname[512];
	DWORD LocalIp,DefaultGateway;
}GINFO, *LPGINFO;

#ifdef __cplusplus
   extern "C"{
#endif

BOOL libnet_win32_shutdown();
BOOL libnet_win32_init(int AdapterNum);
BOOL libnet_win32_open_adapter(int Open);
void libnet_win32_get_hw_addr();
void libnet_win32_get_local_ip();
BYTE * libnet_win32_FindMAC(DWORD IP);
BOOL libnet_win32_send_arp(DWORD IP);
BYTE * libnet_win32_get_remote_mac(DWORD IP);
