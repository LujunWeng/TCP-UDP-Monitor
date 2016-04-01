#include <Windows.h>
#include <iostream>
#include <cstdlib>
#include <cstdio>
#include <objbase.h>

#define INITGUID
#include <evntrace.h>
#include <evntcons.h>

using namespace std;

void printf_guid(GUID guid) {
	printf("{%08lX-%04hX-%04hX-%02hhX%02hhX-%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX}", 
		guid.Data1, guid.Data2, guid.Data3, 
		guid.Data4[0], guid.Data4[1], guid.Data4[2], guid.Data4[3],
		guid.Data4[4], guid.Data4[5], guid.Data4[6], guid.Data4[7]);
}

VOID WINAPI eventCallback(
	_In_ PEVENT_TRACE pEvent
	)
{
	cout << pEvent->Header.Size << ", ";
	printf_guid(pEvent->Header.Guid);
	cout << endl;
}

int main() {
	EVENT_TRACE_LOGFILE *traceLogfile;
	TRACEHANDLE thandle;
	ULONG retCode;

	traceLogfile = (EVENT_TRACE_LOGFILE *)malloc(sizeof(EVENT_TRACE_LOGFILE));
	memset(traceLogfile, 0, sizeof(EVENT_TRACE_LOGFILE));

	traceLogfile->LogFileName = NULL;
	traceLogfile->LoggerName = KERNEL_LOGGER_NAME;
	traceLogfile->ProcessTraceMode |= PROCESS_TRACE_MODE_REAL_TIME;
	traceLogfile->EventCallback = eventCallback;

	thandle = OpenTrace(traceLogfile);
	if (INVALID_PROCESSTRACE_HANDLE == thandle) {
		cerr << "OpenTrace returned an invalid handle! ErrCode: " << GetLastError() << endl;
		return -1;
	}
	
	cout << "Trace opened successfully" << endl;

	retCode = ProcessTrace(&thandle, 1, NULL, NULL);
	if (ERROR_SUCCESS != retCode) {
		cerr << "Calling ProcessTrace failed! ErrCode: " << GetLastError() << endl;
	}

	retCode = CloseTrace(thandle);
	if (ERROR_SUCCESS != retCode) {
		cerr << "CloseTrace failed! ErrCode: " << GetLastError() << endl;
		return -1;
	}

	cout << "Trace closed successfully" << endl;

	return 0;

}