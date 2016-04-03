#include <Windows.h>
#include <iostream>
#include <cstdlib>
#include <cstdio>
#include <objbase.h>
#include <guiddef.h>
#include <WbemCli.h>
#include <comutil.h>

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

// Points to WMI namespace that contains the ETW MOF classes.
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


VOID WINAPI eventCallback(
	_In_ PEVENT_TRACE pEvent
	)
{
	OLECHAR ClassGuid[50];
	IWbemClassObject* pEventCategoryClass = NULL;
	IWbemClassObject* pEventClass = NULL;
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
			//SafeArrayDestroy(pNames);
			//pNames = NULL;
			//pEventClass->Release();
			//pEventClass = NULL;
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
		retCode = CloseTrace(thandle);
	}

	if (g_pServices)
	{
		g_pServices->Release();
		g_pServices = NULL;
	}

	CoUninitialize();
}