#include <Windows.h>
#include <iostream>
#include <cstdlib>
#include <cstdio>

#define INITGUID
#include <evntrace.h>

using namespace std;

int main(int argc, char **argv) {
	EVENT_TRACE_PROPERTIES *eventTraceProp = NULL;
	TCHAR loggerName[] = KERNEL_LOGGER_NAME;
	TRACEHANDLE traceHandler = 0;
	size_t bufferSize = sizeof(EVENT_TRACE_PROPERTIES) + sizeof(loggerName);
	ULONG retCode;


	eventTraceProp = (EVENT_TRACE_PROPERTIES *)malloc(bufferSize);
	memset(eventTraceProp, 0, bufferSize);
	eventTraceProp->Wnode.BufferSize = bufferSize;
	eventTraceProp->Wnode.Guid = SystemTraceControlGuid;
	eventTraceProp->Wnode.ClientContext = 2;
	eventTraceProp->Wnode.Flags |= WNODE_FLAG_TRACED_GUID;
	eventTraceProp->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
	eventTraceProp->EnableFlags = EVENT_TRACE_FLAG_NETWORK_TCPIP;
	eventTraceProp->LogFileNameOffset = 0;	// don't log onto file
	eventTraceProp->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);

	retCode = StartTrace(&traceHandler, loggerName, eventTraceProp);
	if (argc <= 1) {
		if (ERROR_SUCCESS != retCode) {
			if (ERROR_ALREADY_EXISTS == retCode) {
				cout << "Trace session already started!" << endl;
				goto cleanup;
			}
			cerr << "Start trace session failed: " << retCode << endl;
			goto cleanup;
		}
		cout << "Trace session started successfully!" << endl;
	} else {
		if (strcmp(argv[1], "close") == 0) {
			cout << "Ready to close trace session!" << endl;

			retCode = ControlTrace(traceHandler, loggerName, eventTraceProp, EVENT_TRACE_CONTROL_STOP);
			if (ERROR_SUCCESS != retCode) {
				cerr << "Stopping trace session failed: " << retCode << endl;
				goto cleanup;
			}
			cout << "Trace session stopped successfully!" << endl;
		}
	}

cleanup:
	free(eventTraceProp);
	return 0;
}