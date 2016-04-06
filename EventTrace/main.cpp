#include <Windows.h>
#include <iostream>
#include <cstdlib>
#include <cstdio>
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

IWbemClassObject* GetEventCategoryClass(BSTR bstrClassGuid, ULONG Version);
IWbemClassObject* GetEventClass(IWbemClassObject* pEventTraceClass, ULONG EventType);
PBYTE PrintEventPropertyValue(PROPERTY_LIST* pProperty, PBYTE pEventData, USHORT RemainingBytes);
void PrintPropertyName(PROPERTY_LIST* pProperty);
// Points to WMI namespace that contains the ETW MOF classes.
IWbemServices* g_pServices = NULL;
USHORT g_PointerSize = 0;

typedef LPTSTR (NTAPI *PIPV6ADDRTOSTRING)(
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

// This function retrieves the list of properties, data type, and qualifiers for
// each property in the class. If you know the name of the property you want to 
// retrieve, you can call the IWbemClassObject::Get method to retrieve the data
// type and IWbemClassObject::GetPropertyQualifierSet to retrieve its qualifiers.

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

void printf_guid(GUID guid) {
	printf("{%08lX-%04hX-%04hX-%02hhX%02hhX-%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX}",
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

PBYTE PrintEventPropertyValue(PROPERTY_LIST* pProperty, PBYTE pEventData, USHORT RemainingBytes)
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

	// If the property contains the Pointer or PointerType qualifier,
	// you do not need to know the data type of the property. You just
	// retrieve either four bytes or eight bytes depending on the 
	// pointer's size.

	if (SUCCEEDED(hr = pProperty->pQualifiers->Get(L"Pointer", 0, NULL, NULL)) ||
		SUCCEEDED(hr = pProperty->pQualifiers->Get(L"PointerType", 0, NULL, NULL)))
	{
		if (g_PointerSize == 4) 
		{
			ULONG temp = 0;

			CopyMemory(&temp, pEventData, sizeof(ULONG));
			wprintf(L"0x%x\n", temp);
		}
		else
		{
			ULONGLONG temp = 0;

			CopyMemory(&temp, pEventData, sizeof(ULONGLONG));
			wprintf(L"0x%x\n", temp);
		}

		pEventData += g_PointerSize;

		return pEventData;
	}
	else
	{
		// If the property is an array, retrieve its size. The ArraySize variable
		// is initialized to 1 to force the loops below to print the value
		// of the property.

		if (pProperty->CimType & CIM_FLAG_ARRAY)
		{
			hr = pProperty->pQualifiers->Get(L"MAX", 0, &varQualifier, NULL);
			if (SUCCEEDED(hr))
			{
				ArraySize = varQualifier.intVal;
				VariantClear(&varQualifier);
			}
			else
			{
				wprintf(L"Failed to retrieve the MAX qualifier. Terminating.\n");
				return NULL;
			}
		}

		// The CimType is the data type of the property.

		switch(pProperty->CimType & (~CIM_FLAG_ARRAY))
		{
		case CIM_SINT32:
		{
			LONG temp = 0;

			for (ULONG i=0; i < ArraySize; i++)
			{
				CopyMemory(&temp, pEventData, sizeof(LONG));
				wprintf(L"%d\n", temp);
				pEventData += sizeof(LONG);
			}

			return pEventData;
		}

		case CIM_UINT32:
		{
			ULONG temp = 0;

			hr = pProperty->pQualifiers->Get(L"Extension", 0, &varQualifier, NULL);
			if (SUCCEEDED(hr))
			{
				// Some kernel events pack an IP address into a UINT32.
				// Check for an Extension qualifier whose value is IPAddr.
				// This is here to support legacy event classes; the IPAddr extension 
				// should only be used on properties whose CIM type is object.

				if (_wcsicmp(L"IPAddr", varQualifier.bstrVal) == 0)
				{
					PrintAsIPAddress = TRUE;
				}

				VariantClear(&varQualifier);
			}
			else
			{
				hr = pProperty->pQualifiers->Get(L"Format", 0, NULL, NULL);
				if (SUCCEEDED(hr))
				{
					PrintAsHex = TRUE;
				}
			}

			for (ULONG i = 0; i < ArraySize; i++)
			{
				CopyMemory(&temp, pEventData, sizeof(ULONG));

				if (PrintAsIPAddress)
				{
					wprintf(L"%03d.%03d.%03d.%03d\n", (temp >>  0) & 0xff,
						(temp >>  8) & 0xff,
						(temp >>  16) & 0xff,
						(temp >>  24) & 0xff);
				}
				else if (PrintAsHex)
				{
					wprintf(L"0x%x\n", temp);
				}
				else
				{
					wprintf(L"%lu\n", temp);
				}

				pEventData += sizeof(ULONG);
			}

			return pEventData;
		}

		case CIM_SINT64:
		{
			LONGLONG temp = 0;

			for (ULONG i=0; i < ArraySize; i++)
			{
				CopyMemory(&temp, pEventData, sizeof(LONGLONG));
				wprintf(L"%I64d\n", temp);
				pEventData += sizeof(LONGLONG);
			}

			return pEventData;
		}

		case CIM_UINT64:
		{
			ULONGLONG temp = 0;

			for (ULONG i=0; i < ArraySize; i++)
			{
				CopyMemory(&temp, pEventData, sizeof(ULONGLONG));
				wprintf(L"%I64u\n", temp);
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
						wprintf(L"%s\n", (WCHAR*)pEventData);
					}
					else
					{
						LONG StringSize = (StringLength) * sizeof(WCHAR); 
						WCHAR* pwsz = (WCHAR*)malloc(StringSize+2); // +2 for NULL

						if (pwsz)
						{
							CopyMemory(pwsz, (WCHAR*)pEventData, StringSize); 
							*(pwsz+StringSize) = '\0';
							wprintf(L"%s\n", pwsz);
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
						char* psz = (char*)malloc(StringLength+1);  // +1 for NULL

						if (psz)
						{
							CopyMemory(psz, (char*)pEventData, StringLength);
							*(psz+StringLength) = '\0';
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

			for (ULONG i=0; i < ArraySize; i++)
			{
				CopyMemory(&temp, pEventData, sizeof(BOOL));
				wprintf(L"%s\n", (temp) ? L"TRUE" : L"FALSE");
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
					StringFromGUID2(Guid, szGuid, sizeof(szGuid)-1);
					wprintf(L"%s\n", szGuid);
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
						wprintf(L"%c", *((char*)pEventData)); 
					else
						wprintf(L"%hd", *((BYTE*)pEventData));

					pEventData += sizeof(UINT8);
				}
			}

			wprintf(L"\n");

			return pEventData;
		}

		case CIM_CHAR16:
		{
			WCHAR temp;

			for (ULONG i = 0; i < ArraySize; i++)
			{
				CopyMemory(&temp, pEventData, sizeof(WCHAR));
				wprintf(L"%c", temp);
				pEventData += sizeof(WCHAR);
			}

			wprintf(L"\n");

			return pEventData;
		}

		case CIM_SINT16:
		{
			SHORT temp = 0;

			for (ULONG i = 0; i < ArraySize; i++)
			{
				CopyMemory(&temp, pEventData, sizeof(SHORT));
				wprintf(L"%hd\n", temp);
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
					wprintf(L"%hu\n", ntohs(temp));
				}
				else
				{
					wprintf(L"%hu\n", temp);
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
				if (_wcsicmp(L"SizeT", varQualifier.bstrVal) == 0)
				{
					VariantClear(&varQualifier);

					// You do not need to know the data type of the property, you just 
					// retrieve either 4 bytes or 8 bytes depending on the pointer's size.

					for (ULONG i = 0; i < ArraySize; i++)
					{
						if (g_PointerSize == 4) 
						{
							ULONG temp = 0;

							CopyMemory(&temp, pEventData, sizeof(ULONG));
							wprintf(L"0x%x\n", temp);
						}
						else
						{
							ULONGLONG temp = 0;

							CopyMemory(&temp, pEventData, sizeof(ULONGLONG));
							wprintf(L"0x%x\n", temp);
						}

						pEventData += g_PointerSize;
					}

					return pEventData;
				}
				if (_wcsicmp(L"Port", varQualifier.bstrVal) == 0)
				{
					USHORT temp = 0;

					VariantClear(&varQualifier);

					for (ULONG i = 0; i < ArraySize; i++)
					{
						CopyMemory(&temp, pEventData, sizeof(USHORT));
						wprintf(L"%hu\n", ntohs(temp));
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

						wprintf(L"%d.%d.%d.%d\n", (temp >>  0) & 0xff,
							(temp >>  8) & 0xff,
							(temp >>  16) & 0xff,
							(temp >>  24) & 0xff);

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

						wprintf(L"%s\n", IPv6AddressAsString);

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

						StringFromGUID2(Guid, szGuid, sizeof(szGuid)-1);
						wprintf(L"%s\n", szGuid);

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
}

void PrintPropertyName(PROPERTY_LIST* pProperty)
{
	HRESULT hr;
	VARIANT varDisplayName;

	// Retrieve the Description qualifier for the property. The description qualifier
	// should contain a printable display name for the property. If the qualifier is
	// not found, print the property name.

	hr = pProperty->pQualifiers->Get(L"Description", 0, &varDisplayName, NULL);
	wprintf(L"%s: ", (SUCCEEDED(hr)) ? varDisplayName.bstrVal : pProperty->Name);
	VariantClear(&varDisplayName);
}

VOID WINAPI eventCallback(
	_In_ PEVENT_TRACE pEvent
	)
{
	OLECHAR ClassGuid[50];
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
	BSTR *pNameStrs;
	ULONG propCount = 0;

	//cout << pEvent->Header.Size << ", ";
	//printf_guid(pEvent->Header.Guid);
	//cout << " Ver: " << pEvent->Header.Version;
	//cout << endl;

	if (IsEqualGUID(pEvent->Header.Guid, EventTraceGuid) &&
		pEvent->Header.Class.Type == EVENT_TRACE_TYPE_INFO)
	{
		; // Skip this event.
	}
	else
	{
		printf_guid(pEvent->Header.Guid);
		wprintf(L"EventVersion(%d)\n", pEvent->Header.Class.Version);
		wprintf(L"EventType(%d)\n", pEvent->Header.Class.Type);

		StringFromGUID2(pEvent->Header.Guid, ClassGuid, sizeof(ClassGuid));
		if (pEvent->MofLength > 0) {
			pEventCategoryClass = GetEventCategoryClass(_bstr_t(ClassGuid), pEvent->Header.Class.Version);
			if (!pEventCategoryClass) {
				cerr << "Getting Category Class failed!" << endl;
				goto cleanup;
			}
			cout << "Category Class: " << pEventCategoryClass << endl;
			pEventClass = GetEventClass(pEventCategoryClass, pEvent->Header.Class.Type);
			pEventCategoryClass->Release();
			pEventCategoryClass = NULL;
			if (!pEventClass) {
				cerr << "Getting Event Class failed!" << endl;
				goto cleanup;
			}
			cout << "Class: " << pEventClass << endl;

			if (TRUE == GetPropertyList(pEventClass, &pProperties, &PropertyCount, &pPropertyIndex))
			{
				// Print the property name and value.

				// Get a pointer to the beginning and end of the event data.
				// These pointers are used to calculate the number of bytes of event
				// data left to read. This is only useful if the last data 
				// element is a string that contains the StringTermination("NotCounted") qualifier.

				pEventData = (PBYTE)(pEvent->MofData);
				pEndOfEventData = ((PBYTE)(pEvent->MofData) + pEvent->MofLength);

				for (LONG i = 0; (DWORD)i < PropertyCount; i++)
				{
					PrintPropertyName(pProperties+pPropertyIndex[i]);

					pEventData = PrintEventPropertyValue(pProperties+pPropertyIndex[i], 
						pEventData, 
						(USHORT)(pEndOfEventData - pEventData));

					if (NULL == pEventData)
					{
						//Error reading the data. Handle as appropriate for your application.
						break;
					}
				}

				FreePropertyList(pProperties, PropertyCount, pPropertyIndex);
			}
/*
			// Retrieve the property names.
			hr = pEventClass->GetNames(NULL, WBEM_FLAG_LOCAL_ONLY, NULL, &pNames);
			if (hr != WBEM_S_NO_ERROR) {
				cerr << "Getting Names failed!" << endl;
				goto cleanup;
			}

			// Print the property names
			propCount = pNames->rgsabound->cElements;
			hr = SafeArrayAccessData(pNames, (void **)&pNameStrs);
			if (FAILED(hr)) {
				cerr << "SafeArrayAcessData failed!" << endl;
				goto cleanup;
			}

			for (LONG i = 0; (ULONG)i < propCount; ++i) {
				wprintf(L"%s\n", pNameStrs[i]);
			}
*/
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

	g_PointerSize = (USHORT)traceLogfile->LogfileHeader.PointerSize;
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