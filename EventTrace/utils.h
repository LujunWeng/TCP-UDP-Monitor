#pragma once
#include <Windows.h>
#include <iostream>
#include <cstdlib>
#include <cstdio>
#include <cwchar>
#include <objbase.h>
#include <guiddef.h>
#include <WbemCli.h>
#include <comutil.h>
#include <in6addr.h>

#define INITGUID
#include <evntrace.h>
#include <evntcons.h>

typedef struct _propertyList
{
	BSTR Name;     // Property name
	LONG CimType;  // Property data type
	IWbemQualifierSet* pQualifiers;
} PROPERTY_LIST;

typedef LPTSTR(NTAPI *PIPV6ADDRTOSTRING)(
	const IN6_ADDR *Addr,
	LPTSTR S
	);
typedef PTSTR (NTAPI *PIPV4ADDRTOSTRING)(
	_In_  const IN_ADDR *Addr,
	_Out_       PTSTR   S
	);

// Points to WMI namespace that contains the ETW MOF classes.
extern IWbemServices* g_pServices;

HRESULT ConnectToETWNamespace(BSTR bstrNamespace);
IWbemClassObject* GetEventCategoryClass(BSTR bstrClassGuid, ULONG Version);
IWbemClassObject* GetEventClass(IWbemClassObject* pEventTraceClass, ULONG EventType);
BOOL GetPropertyList(IWbemClassObject* pClass, PROPERTY_LIST** ppProperties, DWORD* pPropertyCount, LONG** ppPropertyIndex);
void FreePropertyList(PROPERTY_LIST* pProperties, DWORD Count, LONG* pIndex);
PBYTE GetConnEventPropertyValue(PROPERTY_LIST* pProperty, PBYTE pEventData, USHORT RemainingBytes, size_t buflen, wchar_t *outbuf);