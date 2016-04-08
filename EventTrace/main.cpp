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

using namespace std;

typedef struct _propertyList
{
	BSTR Name;     // Property name
	LONG CimType;  // Property data type
	IWbemQualifierSet* pQualifiers;
} PROPERTY_LIST;

typedef struct _classType {
	wchar_t *guid;
	wchar_t *name;
	int version;
	int id;
} EVENT_CLASS_TYPE;

typedef struct _connEventData {
	uint32_t PID;
	uint32_t size;
	uint32_t daddr;
	uint32_t saddr;
	uint16_t dport;
	uint16_t sport;
	uint32_t connid;
	int proto;
	int type;
} CONN_EVENT_DATA;

struct OutputFormat {
	static const wchar_t *titles[];
	static wchar_t buffers[][50];
	static const size_t titlesCount;
	static const size_t bufferLen;
};

const wchar_t *OutputFormat::titles[] = { L"proto", L"type", L"PID", L"size", L"saddr", L"sport", L"daddr", L"dport" };
wchar_t OutputFormat::buffers[][50] = { L"proto", L"type", L"PID", L"size", L"saddr", L"sport", L"daddr", L"dport" };
const size_t OutputFormat::titlesCount = sizeof(OutputFormat::titles) / sizeof(OutputFormat::titles[0]);
const size_t OutputFormat::bufferLen = 50;

// Points to WMI namespace that contains the ETW MOF classes.
IWbemServices* g_pServices = NULL;

//TcpIp and UdpIp class guid and version. 
const EVENT_CLASS_TYPE eventClassList[] = {
	{ L"{9a280ac0-c8e0-11d1-84e2-00c04fb998a2}", L"TCP", 2, 0 },
	{ L"{bf3a50c5-a9c9-4988-a005-2df0b7c80f80}", L"UDP", 2, 1 }
};

HRESULT ConnectToETWNamespace(BSTR bstrNamespace);
IWbemClassObject* GetEventCategoryClass(BSTR bstrClassGuid, ULONG Version);
IWbemClassObject* GetEventClass(IWbemClassObject* pEventTraceClass, ULONG EventType);
PBYTE GetConnEventPropertyValue(PROPERTY_LIST* pProperty, PBYTE pEventData, USHORT RemainingBytes, size_t buflen, wchar_t *outbuf);
BOOL GetPropertyList(IWbemClassObject* pClass, PROPERTY_LIST** ppProperties, DWORD* pPropertyCount, LONG** ppPropertyIndex);
void FreePropertyList(PROPERTY_LIST* pProperties, DWORD Count, LONG* pIndex);
void PrintPropertyName(PROPERTY_LIST* pProperty);
void guidToString(GUID guid, wchar_t *buffer, size_t count);

typedef LPTSTR(NTAPI *PIPV6ADDRTOSTRING)(
	const IN6_ADDR *Addr,
	LPTSTR S
	);

void FreePropertyList(PROPERTY_LIST* pProperties, DWORD Count, LONG* pIndex)
{
	if (pProperties)
	{
		for (DWORD i = 0; i < Count; i++)
		{
			SysFreeString((pProperties + i)->Name);

			if ((pProperties + i)->pQualifiers)
			{
				(pProperties + i)->pQualifiers->Release();
				(pProperties + i)->pQualifiers = NULL;
			}
		}

		free(pProperties);
	}

	if (pIndex)
		free(pIndex);
}

BOOL GetPropertyList(IWbemClassObject* pClass, PROPERTY_LIST** ppProperties, DWORD* pPropertyCount, LONG** ppPropertyIndex)
{
	HRESULT hr = S_OK;
	SAFEARRAY* pNames = NULL;
	LONG j = 0;
	VARIANT var;

	// Retrieve the property names.

	hr = pClass->GetNames(NULL, WBEM_FLAG_LOCAL_ONLY, NULL, &pNames);
	if (pNames)
	{
		*pPropertyCount = pNames->rgsabound->cElements;

		// Allocate a block of memory to hold an array of PROPERTY_LIST structures.

		*ppProperties = (PROPERTY_LIST*)malloc(sizeof(PROPERTY_LIST) * (*pPropertyCount));
		if (NULL == *ppProperties)
		{
			hr = E_OUTOFMEMORY;
			goto cleanup;
		}

		// WMI may not return the properties in the order as defined in the MOF. Allocate
		// an array of indexes that map into the property list array, so you can retrieve
		// the event data in the correct order.

		*ppPropertyIndex = (LONG*)malloc(sizeof(LONG) * (*pPropertyCount));
		if (NULL == *ppPropertyIndex)
		{
			hr = E_OUTOFMEMORY;
			goto cleanup;
		}

		for (LONG i = 0; (ULONG)i < *pPropertyCount; i++)
		{
			//Save the name of the property.

			hr = SafeArrayGetElement(pNames, &i, &((*ppProperties + i)->Name));
			if (FAILED(hr))
			{
				goto cleanup;
			}

			//Save the qualifiers. Used latter to help determine how to read the event data.

			hr = pClass->GetPropertyQualifierSet((*ppProperties + i)->Name, &((*ppProperties + i)->pQualifiers));
			if (FAILED(hr))
			{
				goto cleanup;
			}

			// Use the WmiDataId qualifier to determine the correct property order.
			// Index[0] points to the property list element that contains WmiDataId("1"),
			// Index[1] points to the property list element that contains WmiDataId("2"),
			// and so on. 

			hr = (*ppProperties + i)->pQualifiers->Get(L"WmiDataId", 0, &var, NULL);
			if (SUCCEEDED(hr))
			{
				j = var.intVal - 1;
				VariantClear(&var);
				*(*ppPropertyIndex + j) = i;
			}
			else
			{
				goto cleanup;
			}

			// Save the data type of the property.

			hr = pClass->Get((*ppProperties + i)->Name, 0, NULL, &((*ppProperties + i)->CimType), NULL);
			if (FAILED(hr))
			{
				goto cleanup;
			}
		}
	}

cleanup:

	if (pNames)
	{
		SafeArrayDestroy(pNames);
	}

	if (FAILED(hr))
	{
		if (*ppProperties)
		{
			FreePropertyList(*ppProperties, *pPropertyCount, *ppPropertyIndex);
		}

		return FALSE;
	}

	return TRUE;
}

void guidToString(GUID guid, wchar_t *buffer, size_t count) {
	swprintf(buffer, count, L"{%08lx-%04hx-%04hx-%02hhx%02hhx-%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx}",
		guid.Data1, guid.Data2, guid.Data3,
		guid.Data4[0], guid.Data4[1], guid.Data4[2], guid.Data4[3],
		guid.Data4[4], guid.Data4[5], guid.Data4[6], guid.Data4[7]);
}

HRESULT ConnectToETWNamespace(BSTR bstrNamespace)
{
	HRESULT hr = S_OK;
	IWbemLocator* pLocator = NULL;

	hr = CoInitialize(0);

	hr = CoCreateInstance(__uuidof(WbemLocator),
		0,
		CLSCTX_INPROC_SERVER,
		__uuidof(IWbemLocator),
		(LPVOID*)&pLocator);

	if (FAILED(hr))
	{
		wprintf(L"CoCreateInstance failed with 0x%x\n", hr);
		goto cleanup;
	}

	hr = pLocator->ConnectServer(bstrNamespace,
		NULL, NULL, NULL,
		0L, NULL, NULL,
		&g_pServices);

	if (FAILED(hr))
	{
		wprintf(L"pLocator->ConnectServer failed with 0x%x\n", hr);
		goto cleanup;
	}

	hr = CoSetProxyBlanket(g_pServices,
		RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE,
		NULL,
		RPC_C_AUTHN_LEVEL_PKT, RPC_C_IMP_LEVEL_IMPERSONATE,
		NULL, EOAC_NONE);

	if (FAILED(hr))
	{
		wprintf(L"CoSetProxyBlanket failed with 0x%x\n", hr);
		g_pServices->Release();
		g_pServices = NULL;
	}

cleanup:

	if (pLocator)
		pLocator->Release();

	return hr;
}

IWbemClassObject* GetEventCategoryClass(BSTR bstrClassGuid, ULONG Version)
{
	HRESULT hr = S_OK;
	HRESULT hrQualifier = S_OK;
	IEnumWbemClassObject* pClasses = NULL;
	IWbemClassObject* pClass = NULL;
	IWbemQualifierSet* pQualifiers = NULL;
	ULONG cnt = 0;
	VARIANT varGuid;
	VARIANT varVersion;


	// All ETW MOF classes derive from the EventTrace class, so you need to 
	// enumerate all the EventTrace descendants to find the correct event category class. 

	hr = g_pServices->CreateClassEnum(_bstr_t(L"EventTrace"),
		WBEM_FLAG_DEEP | WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_USE_AMENDED_QUALIFIERS,
		NULL, &pClasses);

	if (FAILED(hr))
	{
		wprintf(L"g_pServices->CreateClassEnum failed with 0x%x\n", hr);
		goto cleanup;
	}

	while (S_OK == hr)
	{
		hr = pClasses->Next(WBEM_INFINITE, 1, &pClass, &cnt);

		if (FAILED(hr))
		{
			wprintf(L"pClasses->Next failed with 0x%x\n", hr);
			goto cleanup;
		}

		// Get all the qualifiers for the class and search for the Guid qualifier. 

		hrQualifier = pClass->GetQualifierSet(&pQualifiers);

		if (pQualifiers)
		{
			hrQualifier = pQualifiers->Get(L"Guid", 0, &varGuid, NULL);

			if (SUCCEEDED(hrQualifier))
			{
				// Compare this class' GUID to the one from the event.

				if (_wcsicmp(varGuid.bstrVal, bstrClassGuid) == 0)
				{
					// If the GUIDs are equal, check for the correct version.
					// The version is correct if the class does not contain the EventVersion
					// qualifier or the class version matches the version from the event.

					hrQualifier = pQualifiers->Get(L"EventVersion", 0, &varVersion, NULL);

					if (SUCCEEDED(hrQualifier))
					{
						if (Version == varVersion.intVal)
						{
							break; //found class
						}

						VariantClear(&varVersion);
					}
					else if (WBEM_E_NOT_FOUND == hrQualifier)
					{
						break; //found class
					}
				}

				VariantClear(&varGuid);
			}

			pQualifiers->Release();
			pQualifiers = NULL;
		}

		pClass->Release();
		pClass = NULL;
	}

cleanup:

	if (pClasses)
	{
		pClasses->Release();
		pClasses = NULL;
	}

	if (pQualifiers)
	{
		pQualifiers->Release();
		pQualifiers = NULL;
	}

	VariantClear(&varVersion);
	VariantClear(&varGuid);

	return pClass;
}

IWbemClassObject* GetEventClass(IWbemClassObject* pEventCategoryClass, ULONG EventType)
{
	HRESULT hr = S_OK;
	HRESULT hrQualifier = S_OK;
	IEnumWbemClassObject* pClasses = NULL;
	IWbemClassObject* pClass = NULL;
	IWbemQualifierSet* pQualifiers = NULL;
	ULONG cnt = 0;
	VARIANT varClassName;
	VARIANT varEventType;
	BOOL FoundEventClass = FALSE;

	// Get the name of the event category class so you can enumerate its children classes.

	hr = pEventCategoryClass->Get(L"__RELPATH", 0, &varClassName, NULL, NULL);

	if (FAILED(hr))
	{
		wprintf(L"pEventCategoryClass->Get failed with 0x%x\n", hr);
		goto cleanup;
	}

	hr = g_pServices->CreateClassEnum(varClassName.bstrVal,
		WBEM_FLAG_SHALLOW | WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_USE_AMENDED_QUALIFIERS,
		NULL, &pClasses);

	if (FAILED(hr))
	{
		wprintf(L"g_pServices->CreateClassEnum failed with 0x%x\n", hr);
		goto cleanup;
	}

	// Loop through the enumerated classes and find the event class that 
	// matches the event. The class is a match if the event type from the 
	// event matches the value from the EventType class qualifier. 

	while (S_OK == hr)
	{
		hr = pClasses->Next(WBEM_INFINITE, 1, &pClass, &cnt);

		if (FAILED(hr))
		{
			wprintf(L"pClasses->Next failed with 0x%x\n", hr);
			goto cleanup;
		}

		// Get all the qualifiers for the class and search for the EventType qualifier. 

		hrQualifier = pClass->GetQualifierSet(&pQualifiers);

		if (FAILED(hrQualifier))
		{
			wprintf(L"pClass->GetQualifierSet failed with 0x%x\n", hrQualifier);
			pClass->Release();
			pClass = NULL;
			goto cleanup;
		}

		hrQualifier = pQualifiers->Get(L"EventType", 0, &varEventType, NULL);

		if (FAILED(hrQualifier))
		{
			wprintf(L"pQualifiers->Get(eventtype) failed with 0x%x\n", hrQualifier);
			pClass->Release();
			pClass = NULL;
			goto cleanup;
		}

		// If multiple events provide the same data, the EventType qualifier
		// will contain an array of types. Loop through the array and find a match.

		if (varEventType.vt & VT_ARRAY)
		{
			HRESULT hrSafe = S_OK;
			int ClassEventType;
			SAFEARRAY* pEventTypes = varEventType.parray;

			for (LONG i = 0; (ULONG)i < pEventTypes->rgsabound->cElements; i++)
			{
				hrSafe = SafeArrayGetElement(pEventTypes, &i, &ClassEventType);

				if (ClassEventType == EventType)
				{
					FoundEventClass = TRUE;
					break;  //for loop
				}
			}
		}
		else
		{
			if (varEventType.intVal == EventType)
			{
				FoundEventClass = TRUE;
			}
		}

		VariantClear(&varEventType);

		if (TRUE == FoundEventClass)
		{
			break;  //while loop
		}

		pClass->Release();
		pClass = NULL;
	}

cleanup:

	if (pClasses)
	{
		pClasses->Release();
		pClasses = NULL;
	}

	if (pQualifiers)
	{
		pQualifiers->Release();
		pQualifiers = NULL;
	}

	VariantClear(&varClassName);
	VariantClear(&varEventType);

	return pClass;
}

PBYTE GetConnEventPropertyValue(PROPERTY_LIST* pProperty, PBYTE pEventData, USHORT RemainingBytes, size_t buflen, wchar_t *outbuf)
{
	HRESULT hr;
	VARIANT varQualifier;
	ULONG ArraySize = 1;
	BOOL PrintAsChar = FALSE;
	BOOL PrintAsHex = FALSE;
	BOOL PrintAsIPAddress = FALSE;
	BOOL PrintAsPort = FALSE;
	BOOL IsWideString = FALSE;
	BOOL IsNullTerminated = FALSE;
	USHORT StringLength = 0;

	//// If the property is an array, retrieve its size. The ArraySize variable
	//// is initialized to 1 to force the loops below to print the value
	//// of the property.

	// The CimType is the data type of the property.

	switch (pProperty->CimType & (~CIM_FLAG_ARRAY))
	{
	case CIM_SINT32:
	{
		LONG temp = 0;

		for (ULONG i = 0; i < ArraySize; i++)
		{
			CopyMemory(&temp, pEventData, sizeof(LONG));
			swprintf(outbuf, buflen, L"%d", temp);
			pEventData += sizeof(LONG);
		}

		return pEventData;
	}

	case CIM_UINT32:
	{
		UINT32 temp = 0;

		for (UINT32 i = 0; i < ArraySize; i++)
		{
			CopyMemory(&temp, pEventData, sizeof(UINT32));
			swprintf(outbuf, buflen, L"%I32u (uint32)", temp);
			pEventData += sizeof(UINT32);
		}

		return pEventData;
	}

	case CIM_SINT64:
	{
		LONGLONG temp = 0;

		for (ULONG i = 0; i < ArraySize; i++)
		{
			CopyMemory(&temp, pEventData, sizeof(LONGLONG));
			swprintf(outbuf, buflen, L"%I64d", temp);
			pEventData += sizeof(LONGLONG);
		}

		return pEventData;
	}

	case CIM_UINT64:
	{
		ULONGLONG temp = 0;

		for (ULONG i = 0; i < ArraySize; i++)
		{
			CopyMemory(&temp, pEventData, sizeof(ULONGLONG));
			swprintf(outbuf, buflen, L"%I64u", temp);
			pEventData += sizeof(ULONGLONG);
		}

		return pEventData;
	}

	case CIM_STRING:
	{
		USHORT temp = 0;

		// The format qualifier is included only if the string is a wide string.

		hr = pProperty->pQualifiers->Get(L"Format", 0, NULL, NULL);
		if (SUCCEEDED(hr))
		{
			IsWideString = TRUE;
		}

		hr = pProperty->pQualifiers->Get(L"StringTermination", 0, &varQualifier, NULL);
		if (FAILED(hr) || (_wcsicmp(varQualifier.bstrVal, L"NullTerminated") == 0))
		{
			IsNullTerminated = TRUE;
		}
		else if (_wcsicmp(varQualifier.bstrVal, L"Counted") == 0)
		{
			// First two bytes of the string contain its length.

			CopyMemory(&StringLength, pEventData, sizeof(USHORT));
			pEventData += sizeof(USHORT);
		}
		else if (_wcsicmp(varQualifier.bstrVal, L"ReverseCounted") == 0)
		{
			// First two bytes of the string contain its length.
			// Count is in big-endian; convert to little-endian.

			CopyMemory(&temp, pEventData, sizeof(USHORT));
			StringLength = MAKEWORD(HIBYTE(temp), LOBYTE(temp));
			pEventData += sizeof(USHORT);
		}
		else if (_wcsicmp(varQualifier.bstrVal, L"NotCounted") == 0)
		{
			// The string is not null-terminated and does not contain
			// its own length, so its length is the remaining bytes of
			// the event data. 

			StringLength = RemainingBytes;
		}

		VariantClear(&varQualifier);

		for (ULONG i = 0; i < ArraySize; i++)
		{
			if (IsWideString)
			{
				if (IsNullTerminated)
				{
					StringLength = (USHORT)wcslen((WCHAR*)pEventData) + 1;
					swprintf(outbuf, buflen, L"%s", (WCHAR*)pEventData);
				}
				else
				{
					LONG StringSize = (StringLength)* sizeof(WCHAR);
					WCHAR* pwsz = (WCHAR*)malloc(StringSize + 2); // +2 for NULL

					if (pwsz)
					{
						CopyMemory(pwsz, (WCHAR*)pEventData, StringSize);
						*(pwsz + StringSize) = '\0';
						swprintf(outbuf, buflen, L"%s", pwsz);
						free(pwsz);
					}
					else
					{
						// Handle allocation error.
					}
				}

				StringLength *= sizeof(WCHAR);
			}
			else  // It is an ANSI string
			{
				if (IsNullTerminated)
				{
					StringLength = (USHORT)strlen((char*)pEventData) + 1;
					printf("%s\n", (char*)pEventData);
				}
				else
				{
					char* psz = (char*)malloc(StringLength + 1);  // +1 for NULL

					if (psz)
					{
						CopyMemory(psz, (char*)pEventData, StringLength);
						*(psz + StringLength) = '\0';
						printf("%s\n", psz);
						free(psz);
					}
					else
					{
						// Handle allocation error.
					}
				}
			}

			pEventData += StringLength;
			StringLength = 0;
		}

		return pEventData;
	}

	case CIM_BOOLEAN:
	{
		BOOL temp = FALSE;

		for (ULONG i = 0; i < ArraySize; i++)
		{
			CopyMemory(&temp, pEventData, sizeof(BOOL));
			swprintf(outbuf, buflen, L"%s", (temp) ? L"TRUE" : L"FALSE");
			pEventData += sizeof(BOOL);
		}

		return pEventData;
	}

	case CIM_SINT8:
	case CIM_UINT8:
	{
		hr = pProperty->pQualifiers->Get(L"Extension", 0, &varQualifier, NULL);
		if (SUCCEEDED(hr))
		{
			// This is here to support legacy event classes; the Guid extension 
			// should only be used on properties whose CIM type is object.

			if (_wcsicmp(L"Guid", varQualifier.bstrVal) == 0)
			{
				WCHAR szGuid[50];
				GUID Guid;

				CopyMemory(&Guid, (GUID*)pEventData, sizeof(GUID));
				StringFromGUID2(Guid, szGuid, sizeof(szGuid) - 1);
				swprintf(outbuf, buflen, L"%s", szGuid);
			}

			VariantClear(&varQualifier);
			pEventData += sizeof(GUID);
		}
		else
		{
			hr = pProperty->pQualifiers->Get(L"Format", 0, NULL, NULL);
			if (SUCCEEDED(hr))
			{
				PrintAsChar = TRUE;  // ANSI character
			}

			for (ULONG i = 0; i < ArraySize; i++)
			{
				if (PrintAsChar)
					swprintf(outbuf, buflen, L"%c", *((char*)pEventData));
				else
					swprintf(outbuf, buflen, L"%hd", *((BYTE*)pEventData));

				pEventData += sizeof(UINT8);
			}
		}

		return pEventData;
	}

	case CIM_CHAR16:
	{
		WCHAR temp;

		for (ULONG i = 0; i < ArraySize; i++)
		{
			CopyMemory(&temp, pEventData, sizeof(WCHAR));
			swprintf(outbuf, buflen, L"%c", temp);
			pEventData += sizeof(WCHAR);
		}

		return pEventData;
	}

	case CIM_SINT16:
	{
		SHORT temp = 0;

		for (ULONG i = 0; i < ArraySize; i++)
		{
			CopyMemory(&temp, pEventData, sizeof(SHORT));
			swprintf(outbuf, buflen, L"%hd", temp);
			pEventData += sizeof(SHORT);
		}

		return pEventData;
	}

	case CIM_UINT16:
	{
		USHORT temp = 0;

		// If the data is a port number, call the ntohs Windows Socket 2 function
		// to convert the data from TCP/IP network byte order to host byte order.
		// This is here to support legacy event classes; the Port extension 
		// should only be used on properties whose CIM type is object.

		hr = pProperty->pQualifiers->Get(L"Extension", 0, &varQualifier, NULL);
		if (SUCCEEDED(hr))
		{
			if (_wcsicmp(L"Port", varQualifier.bstrVal) == 0)
			{
				PrintAsPort = TRUE;
			}

			VariantClear(&varQualifier);
		}

		for (ULONG i = 0; i < ArraySize; i++)
		{
			CopyMemory(&temp, pEventData, sizeof(USHORT));

			if (PrintAsPort)
			{
				swprintf(outbuf, buflen, L"%hu", ntohs(temp));
			}
			else
			{
				swprintf(outbuf, buflen, L"%hu", temp);
			}

			pEventData += sizeof(USHORT);
		}

		return pEventData;
	}

	case CIM_OBJECT:
	{
		// An object data type has to include the Extension qualifier.

		hr = pProperty->pQualifiers->Get(L"Extension", 0, &varQualifier, NULL);
		if (SUCCEEDED(hr))
		{
			if (_wcsicmp(L"Port", varQualifier.bstrVal) == 0)
			{
				USHORT temp = 0;

				VariantClear(&varQualifier);

				for (ULONG i = 0; i < ArraySize; i++)
				{
					CopyMemory(&temp, pEventData, sizeof(USHORT));
					swprintf(outbuf, buflen, L"%hu", ntohs(temp));
					pEventData += sizeof(USHORT);
				}

				return pEventData;
			}
			else if (_wcsicmp(L"IPAddr", varQualifier.bstrVal) == 0 ||
				_wcsicmp(L"IPAddrV4", varQualifier.bstrVal) == 0)
			{
				ULONG temp = 0;

				VariantClear(&varQualifier);

				for (ULONG i = 0; i < ArraySize; i++)
				{
					CopyMemory(&temp, pEventData, sizeof(ULONG));
					temp = ntohl(temp);
					swprintf(outbuf, buflen, L"%lu (ipv4) %d.%d.%d.%d", temp, (temp >> 24) & 0xff,
						(temp >> 16) & 0xff,
						(temp >> 8) & 0xff,
						(temp >> 0) & 0xff);

					pEventData += sizeof(ULONG);
				}

				return pEventData;
			}
			else if (_wcsicmp(L"IPAddrV6", varQualifier.bstrVal) == 0)
			{
				WCHAR IPv6AddressAsString[46];
				IN6_ADDR IPv6Address;
				PIPV6ADDRTOSTRING fnRtlIpv6AddressToString;

				VariantClear(&varQualifier);

				fnRtlIpv6AddressToString = (PIPV6ADDRTOSTRING)GetProcAddress(
					GetModuleHandle(L"ntdll"), "RtlIpv6AddressToStringW");

				if (NULL == fnRtlIpv6AddressToString)
				{
					wprintf(L"GetProcAddress failed with %lu.\n", GetLastError());
					return NULL;
				}

				for (ULONG i = 0; i < ArraySize; i++)
				{
					CopyMemory(&IPv6Address, pEventData, sizeof(IN6_ADDR));

					fnRtlIpv6AddressToString(&IPv6Address, IPv6AddressAsString);

					swprintf(outbuf, buflen, L"%s", IPv6AddressAsString);

					pEventData += sizeof(IN6_ADDR);
				}

				return pEventData;
			}
			else if (_wcsicmp(L"Guid", varQualifier.bstrVal) == 0)
			{
				WCHAR szGuid[50];
				GUID Guid;

				VariantClear(&varQualifier);

				for (ULONG i = 0; i < ArraySize; i++)
				{
					CopyMemory(&Guid, (GUID*)pEventData, sizeof(GUID));

					StringFromGUID2(Guid, szGuid, sizeof(szGuid) - 1);
					swprintf(outbuf, buflen, L"%s", szGuid);

					pEventData += sizeof(GUID);
				}

				return pEventData;
			}
			else
			{
				wprintf(L"Extension, %s, not supported.\n", varQualifier.bstrVal);
				VariantClear(&varQualifier);
				return NULL;
			}
		}
		else
		{
			wprintf(L"Object data type is missing Extension qualifier.\n");
			return NULL;
		}
	}

	default:
	{
		wprintf(L"Unknown CIM type\n");
		return NULL;
	}

	} // switch
}

void PrintPropertyName(PROPERTY_LIST* pProperty)
{
	wprintf(L"%s: ", pProperty->Name);
}

VOID WINAPI eventCallback(
	_In_ PEVENT_TRACE pEvent
	)
{
	OLECHAR ClassGuid[50];
	wchar_t guidStr[50];
	IWbemClassObject* pEventCategoryClass = NULL;
	IWbemClassObject* pEventClass = NULL;
	PBYTE pEventData = NULL;
	PBYTE pEndOfEventData = NULL;
	PROPERTY_LIST* pProperties = NULL;
	DWORD PropertyCount = 0;
	LONG* pPropertyIndex = NULL;
	HRESULT hr = S_OK;
	SAFEARRAY* pNames = NULL;
	LONG j = 0;
	ULONG propCount = 0;

	if (IsEqualGUID(pEvent->Header.Guid, EventTraceGuid) &&
		pEvent->Header.Class.Type == EVENT_TRACE_TYPE_INFO)
	{
		; // Skip this event.
	}
	else
	{
		int classIndex = -1;
		int alen = 0;
		CONN_EVENT_DATA connEventData;

		guidToString(pEvent->Header.Guid, guidStr, sizeof(guidStr)/sizeof(guidStr[0]));
		alen = sizeof(eventClassList) / sizeof(eventClassList[0]);
		for (int i = 0; i < alen; ++i) {
			if (wcscmp(guidStr, eventClassList[i].guid) == 0 
				&& pEvent->Header.Class.Version == eventClassList[i].version) {
				classIndex = i;
				break;
			}
		}
		
		// We only need events related to TCP AND UDP connections. 
		if (classIndex == -1) {
			cerr << "Event Class Guid or Version does not match!" << endl;
			goto cleanup;
		}

		memset(&connEventData, 0, sizeof(connEventData));
		connEventData.proto = eventClassList[classIndex].id;
		connEventData.type = pEvent->Header.Class.Type;
		wprintf(L"%s\n", eventClassList[classIndex].guid);
		wprintf(L"EventVersion(%d)\n", eventClassList[classIndex].version);
		wprintf(L"EventType(%d)\n", connEventData.type);

		StringFromGUID2(pEvent->Header.Guid, ClassGuid, sizeof(ClassGuid));
		if (pEvent->MofLength > 0) {
			pEventCategoryClass = GetEventCategoryClass(_bstr_t(ClassGuid), pEvent->Header.Class.Version);
			if (!pEventCategoryClass) {
				cerr << "Getting Category Class failed!" << endl;
				goto cleanup;
			}

			pEventClass = GetEventClass(pEventCategoryClass, pEvent->Header.Class.Type);
			if (!pEventClass) {
				cerr << "Getting Event Class failed!" << endl;
				goto cleanup;
			}

			if (TRUE == GetPropertyList(pEventClass, &pProperties, &PropertyCount, &pPropertyIndex))
			{
				wchar_t trashBuf[OutputFormat::bufferLen];

				pEventData = (PBYTE)(pEvent->MofData);
				pEndOfEventData = ((PBYTE)(pEvent->MofData) + pEvent->MofLength);

				for (LONG i = 0; (DWORD)i < PropertyCount; i++)
				{
					PROPERTY_LIST* prop = pProperties + pPropertyIndex[i];
					for (size_t j = 0; j < OutputFormat::titlesCount; ++j) {
						if (_wcsicmp(prop->Name, OutputFormat::titles[j]) == 0) {
							pEventData = GetConnEventPropertyValue(pProperties + pPropertyIndex[i],
													  pEventData,
													  (USHORT)(pEndOfEventData - pEventData),
													  OutputFormat::bufferLen,
													  OutputFormat::buffers[j]
													  );
							break;
						}
						if (j + 1 == OutputFormat::titlesCount) {
							pEventData = GetConnEventPropertyValue(pProperties + pPropertyIndex[i],
								pEventData,
								(USHORT)(pEndOfEventData - pEventData),
								OutputFormat::bufferLen,
								trashBuf
								);
						}
					}
					//PrintPropertyName(pProperties + pPropertyIndex[i]);
					//pEventData = GetConnEventPropertyValue(pProperties + pPropertyIndex[i],
					//	pEventData,
					//	(USHORT)(pEndOfEventData - pEventData));
					if (NULL == pEventData)
					{
						//Error reading the data. Handle as appropriate for your application.
						break;
					}
				}
				for (size_t j = 0; j < OutputFormat::titlesCount; ++j) {
					wprintf(L"%s ", OutputFormat::titles[j]);
				}
				wprintf(L"\n");
				swprintf(OutputFormat::buffers[0], OutputFormat::bufferLen, L"%d", eventClassList[classIndex].id);
				swprintf(OutputFormat::buffers[1], OutputFormat::bufferLen, L"%d", pEvent->Header.Class.Type);
				for (size_t j = 0; j < OutputFormat::titlesCount; ++j) {
					wprintf(L"%s ", OutputFormat::buffers[j]);
				}
				wprintf(L"\n");

				FreePropertyList(pProperties, PropertyCount, pPropertyIndex);
			}
		}
	}

cleanup:
	if (pEventCategoryClass != NULL) {
		pEventCategoryClass->Release();
		pEventCategoryClass = NULL;
	}
	if (pEventClass != NULL) {
		pEventClass->Release();
		pEventClass = NULL;
	}
	SafeArrayUnaccessData(pNames);
	if (pNames != NULL) {
		SafeArrayDestroy(pNames);
	}
}

int main() {
	EVENT_TRACE_LOGFILE *traceLogfile;
	TRACEHANDLE thandle = INVALID_PROCESSTRACE_HANDLE;
	ULONG retCode;
	HRESULT hr = S_OK;

	traceLogfile = (EVENT_TRACE_LOGFILE *)malloc(sizeof(EVENT_TRACE_LOGFILE));
	memset(traceLogfile, 0, sizeof(EVENT_TRACE_LOGFILE));

	traceLogfile->LogFileName = NULL;
	traceLogfile->LoggerName = KERNEL_LOGGER_NAME;
	traceLogfile->ProcessTraceMode |= PROCESS_TRACE_MODE_REAL_TIME;
	traceLogfile->EventCallback = eventCallback;

	thandle = OpenTrace(traceLogfile);
	if (INVALID_PROCESSTRACE_HANDLE == thandle) {
		cerr << "OpenTrace returned an invalid handle! ErrCode: " << GetLastError() << endl;
		goto cleanup;
	}

	cout << "Trace opened successfully" << endl;

	hr = ConnectToETWNamespace(_bstr_t(L"root\\wmi"));
	if (FAILED(hr))
	{
		cerr << "ConnectToETWNamespace failed with " << hr << endl;
		goto cleanup;
	}

	retCode = ProcessTrace(&thandle, 1, NULL, NULL);
	if (retCode != ERROR_SUCCESS && retCode != ERROR_CANCELLED)
	{
		cerr << "ProcessTrace failed with " << retCode << endl;
		goto cleanup;
	}

	cout << "Trace closed successfully" << endl;

	return 0;

cleanup:

	if (INVALID_PROCESSTRACE_HANDLE != thandle)
	{
		cerr << "Close Trace!" << endl;
		retCode = CloseTrace(thandle);
	}

	if (g_pServices)
	{
		g_pServices->Release();
		g_pServices = NULL;
	}

	CoUninitialize();
}