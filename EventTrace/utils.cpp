#include "utils.h"

IWbemServices* g_pServices = NULL;

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
			swprintf(outbuf, buflen, L"%I32u", temp);
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
				WCHAR IPv4AddressAsString[20];
				IN_ADDR IPv4Address;
				PIPV4ADDRTOSTRING fnRtlIpv4AddressToString;

				VariantClear(&varQualifier);

				fnRtlIpv4AddressToString = (PIPV4ADDRTOSTRING)GetProcAddress(
					GetModuleHandle(L"ntdll"), "RtlIpv4AddressToStringW");

				if (NULL == fnRtlIpv4AddressToString)
				{
					wprintf(L"GetProcAddress failed with %lu.\n", GetLastError());
					return NULL;
				}

				for (ULONG i = 0; i < ArraySize; i++)
				{
					CopyMemory(&IPv4Address, pEventData, sizeof(IN_ADDR));

					fnRtlIpv4AddressToString(&IPv4Address, IPv4AddressAsString);

					swprintf(outbuf, buflen, L"%s", IPv4AddressAsString);

					pEventData += sizeof(IN_ADDR);
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
