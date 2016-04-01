#include <Windows.h>
#include <iostream>
#include <cstdlib>
#include <cstdio>

#define INITGUID
#include <evntrace.h>
#include <evntcons.h>

using namespace std;

VOID WINAPI eventCallback(
	_In_ PEVENT_TRACE pEvent
	)
{

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

	retCode = CloseTrace(thandle);
	if (ERROR_SUCCESS != retCode) {
		cerr << "CloseTrace failed! ErrCode: " << GetLastError() << endl;
		return -1;
	}

	cout << "Trace closed successfully" << endl;

	return 0;

}