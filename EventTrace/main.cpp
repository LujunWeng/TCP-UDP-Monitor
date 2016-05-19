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

#include "utils.h"

using namespace std;

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
	static void jsonFormatOutput();
};

const wchar_t *OutputFormat::titles[] = { L"proto", L"type", L"PID", L"size", L"saddr", L"sport", L"daddr", L"dport" };
wchar_t OutputFormat::buffers[][50] = { L"proto", L"type", L"PID", L"size", L"saddr", L"sport", L"daddr", L"dport" };
const size_t OutputFormat::titlesCount = sizeof(OutputFormat::titles) / sizeof(OutputFormat::titles[0]);
const size_t OutputFormat::bufferLen = 50;
void OutputFormat::jsonFormatOutput() {
	wprintf(L"{ ");
	for (size_t i = 0; i < titlesCount; ++i) {
		wprintf(L"\"%s\":\"%s\"%s", titles[i], buffers[i], i+1==titlesCount ? L"" : L", ");
	}
	wprintf(L" }\n");
	fflush(stdout);
}

//TcpIp and UdpIp class guid and version. 
const EVENT_CLASS_TYPE eventClassList[] = {
	{ L"{9a280ac0-c8e0-11d1-84e2-00c04fb998a2}", L"TCP", 2, 0 },
	{ L"{bf3a50c5-a9c9-4988-a005-2df0b7c80f80}", L"UDP", 2, 1 }
};

void PrintPropertyName(PROPERTY_LIST* pProperty);
void guidToString(GUID guid, wchar_t *buffer, size_t count);
VOID WINAPI eventCallback(_In_ PEVENT_TRACE pEvent);

void guidToString(GUID guid, wchar_t *buffer, size_t count) {
	swprintf(buffer, count, L"{%08lx-%04hx-%04hx-%02hhx%02hhx-%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx}",
		guid.Data1, guid.Data2, guid.Data3,
		guid.Data4[0], guid.Data4[1], guid.Data4[2], guid.Data4[3],
		guid.Data4[4], guid.Data4[5], guid.Data4[6], guid.Data4[7]);
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

					if (NULL == pEventData)
					{
						//Error reading the data. Handle as appropriate for your application.
						break;
					}
				}

				swprintf(OutputFormat::buffers[0], OutputFormat::bufferLen, L"%s", eventClassList[classIndex].name);
				swprintf(OutputFormat::buffers[1], OutputFormat::bufferLen, L"%d", pEvent->Header.Class.Type);
				OutputFormat::jsonFormatOutput();
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