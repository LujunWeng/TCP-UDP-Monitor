#include <Windows.h>
#include <iostream>
#include <cstdlib>
#include <cstdio>

#define INITGUID
#include <evntrace.h>

using namespace std;

int main() {
	EVENT_TRACE_PROPERTIES *eventTraceProp;
	TCHAR loggerName[] = KERNEL_LOGGER_NAME;
	TRACEHANDLE traceHandler = 0;
	size_t bufferSize = sizeof(EVENT_TRACE_PROPERTIES) + sizeof(loggerName);
	ULONG retCode;

	eventTraceProp = (EVENT_TRACE_PROPERTIES *) malloc(bufferSize);
	memset(eventTraceProp, 0, bufferSize);
	eventTraceProp->Wnode.BufferSize = bufferSize;
	eventTraceProp->Wnode.Guid = SystemTraceControlGuid;
	eventTraceProp->Wnode.ClientContext = 2;
	eventTraceProp->Wnode.Flags |= WNODE_FLAG_TRACED_GUID;
	eventTraceProp->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
	eventTraceProp->EnableFlags = EVENT_TRACE_FLAG_NETWORK_TCPIP;
	eventTraceProp->LogFileNameOffset = 0;	// don't log onto file
	eventTraceProp->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);


	cout << traceHandler << endl;
	retCode = StartTrace(&traceHandler, loggerName, eventTraceProp);
	if (ERROR_SUCCESS != retCode) {
		if (ERROR_ALREADY_EXISTS == retCode) {
			cout << "Trace session already start!" << endl;
			cout << "Ready to stop it!" << endl;
			goto CLEANUP_ON_ERROR;
		}
		cout << "Start trace session failed: " << retCode << endl;
		goto CLEANUP_ON_ERROR;
	}
	cout << traceHandler << endl;


	return 0;

CLEANUP_ON_ERROR:
	retCode = ControlTrace(traceHandler, loggerName, eventTraceProp, EVENT_TRACE_CONTROL_STOP);
	if (ERROR_SUCCESS != retCode) {
		cout << "Stop trace session failed: " << retCode << endl;
		return -1;
	}
}