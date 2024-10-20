import os
import sys
from ptrace.debugger import PtraceDebugger
import time
from ptrace.syscall import SYSCALL_NAMES

def trace_process(pid):
    debugger = PtraceDebugger()
    process = debugger.addProcess(pid, False)
    
    try:
        print(f"Tracing Process: {pid}")
        while True:
            # Wait for the next syscall
            process.syscall()
            process.waitSyscall()
            
            syscall = process.getSyscall()
            if syscall:
                syscall_name = SYSCALL_NAMES.get(syscall.name, "UNKNOWN")
                print(f"[{time.time()}] System call: {syscall_name}({', '.join(map(str, syscall.arguments))})")
                
            process.syscall()
            process.waitSyscall()
    
    except KeyboardInterrupt:
        print("\nStopping the tracer...")
    except Exception as e:
        print(f"Error: {e}")
    finally:
        debugger.quit()
        
def start_and_trace(command):
    debugger = PtraceDebugger()
    process = debugger.createProcess(command[0], command, os.environ)
    
    try:
        print(f"Tracing new process: {command}")
        while True:
            # wait for the next syscall
            process.syscall()
            process.waitSyscall()
            
            syscall = process.getSyscall()
            if syscall:
                syscall_name = SYSCALL_NAMES.get(syscall.name, "UNKNOWN")
                print(f"[{time.time()}] System call: {syscall_name}({', '.join(map(str, syscall.arguments))})")
                
            process.syscall()
            process.waitSyscall()
            
    except KeyboardInterrupt:
        print("\nStopping the tracer...")
    except Exception as e:
        print(f"Error: {e}")
    finally:
        debugger.quit()
        
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: {sys.argv[0]} <pid> or <command>")
        sys.exit(1)
        
    if sys.argv[1].isdigit():
        pid = int(sys.argv[1])
        trace_process(pid)
        
    else:
        command = sys.argv[1:]
        start_and_trace(command)