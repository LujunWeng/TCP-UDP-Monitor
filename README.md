# TCP-UDP-Monitor
Monitor TCP and UDP connections in Windows

# Usage

1. Build StartTraceSession project and EventTrace project.
2. Start StartTraceSession.exe first and then start EventTrace.exe 

 run StartTraceSession.exe once to start trace session and run it again to stop it. After starting trace session, you can run EventTrace.exe to get TCP&UDP connections data.

3. Output format:
 
 | proto | type | size | PID | saddr | sport |daddr | dport |
 
 proto (int): 0 stands for TCP; 1 stands for UDP.
 
 type (int): refer to [MSDN](https://msdn.microsoft.com/en-us/library/windows/desktop/aa364128.aspx)
 
 size (uint32_t): byte
 
 PID (uint32_t): process id
 
 saddr : source address
 
 sport (uint32_t host byte order): source port
 
 daddr : destination address
 
 dport (uint16_t host byte order): destination port

# License
[MIT](./LICENSE)
