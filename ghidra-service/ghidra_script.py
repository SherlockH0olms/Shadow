#!/usr/bin/env python
# Ghidra headless analysis script
# Extracts functions, strings, syscalls from binary

try:
    from ghidra.app.decompiler import DecompInterface
    from ghidra.program.model.symbol import SymbolType
    from ghidra.util.task import ConsoleTaskMonitor
    GHIDRA_RUNTIME = True
except ImportError:
    GHIDRA_RUNTIME = False
    print("Not in Ghidra runtime - imports skipped")

import json
import sys


def analyze_binary():
    """Main analysis function - runs in Ghidra headless mode."""
    if not GHIDRA_RUNTIME:
        return {"error": "Must run inside Ghidra"}
    
    results = {
        "functions": [],
        "strings": [],
        "imports": [],
        "syscalls": [],
        "suspicious_patterns": [],
        "decompiled_code": []
    }
    
    try:
        print("Initializing decompiler...")
        decompiler = DecompInterface()
        decompiler.openProgram(currentProgram)
        
        print("Getting functions...")
        function_manager = currentProgram.getFunctionManager()
        functions = function_manager.getFunctions(True)
        
        func_count = 0
        for func in functions:
            if func_count >= 100:  # Limit to first 100 functions
                break
            
            func_name = func.getName()
            func_address = func.getEntryPoint().toString()
            
            # Decompile function
            decompiled = decompiler.decompileFunction(func, 30, ConsoleTaskMonitor())
            
            if decompiled and decompiled.decompileCompleted():
                pseudocode = decompiled.getDecompiledFunction().getC()
                
                results["functions"].append({
                    "name": func_name,
                    "address": func_address,
                    "size": func.getBody().getNumAddresses()
                })
                
                # Check for suspicious patterns
                suspicious = check_suspicious_function(func_name, pseudocode)
                if suspicious:
                    results["suspicious_patterns"].extend(suspicious)
                
                # Store decompiled code for important functions
                if is_important_function(func_name):
                    results["decompiled_code"].append({
                        "function": func_name,
                        "code": pseudocode[:2000]  # Limit size
                    })
            
            func_count += 1
        
        print(f"Analyzed {func_count} functions")
        
        # Extract strings
        print("Extracting strings...")
        memory = currentProgram.getMemory()
        string_count = 0
        
        for block in memory.getBlocks():
            if block.isInitialized() and string_count < 200:
                addr = block.getStart()
                while addr and addr < block.getEnd() and string_count < 200:
                    try:
                        data = getDataAt(addr)
                        if data and data.hasStringValue():
                            string_value = str(data.getValue())
                            if len(string_value) >= 4:
                                results["strings"].append({
                                    "value": string_value[:100],
                                    "address": addr.toString()
                                })
                                string_count += 1
                    except:
                        pass
                    addr = addr.next()
        
        print(f"Extracted {string_count} strings")
        
        # Extract imports
        print("Extracting imports...")
        symbol_table = currentProgram.getSymbolTable()
        for symbol in symbol_table.getExternalSymbols():
            if symbol.getSymbolType() == SymbolType.FUNCTION:
                results["imports"].append({
                    "name": symbol.getName(),
                    "library": symbol.getParentNamespace().getName()
                })
        
        # Detect syscalls
        results["syscalls"] = detect_syscalls(results["imports"])
        
        # Save results
        output_file = "/tmp/ghidra_analysis.json"
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2)
        
        print(f"Analysis complete! Results: {output_file}")
        return results
    
    except Exception as e:
        error_result = {
            "error": f"Analysis failed: {str(e)}",
            "functions": [],
            "strings": [],
            "imports": []
        }
        
        with open("/tmp/ghidra_analysis.json", 'w') as f:
            json.dump(error_result, f, indent=2)
        
        return error_result


def check_suspicious_function(func_name, pseudocode):
    """Check for suspicious patterns in function."""
    suspicious = []
    
    # Suspicious function names
    suspicious_names = ["inject", "hook", "bypass", "evade", "decrypt", 
                       "keylog", "steal", "dump", "crack", "exploit"]
    
    if any(name in func_name.lower() for name in suspicious_names):
        suspicious.append(f"Suspicious function name: {func_name}")
    
    # Dangerous APIs
    dangerous_apis = [
        "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread",
        "NtAllocateVirtualMemory", "NtWriteVirtualMemory",
        "SetWindowsHookEx", "GetAsyncKeyState", "RegSetValueEx"
    ]
    
    for api in dangerous_apis:
        if api in pseudocode:
            suspicious.append(f"Dangerous API call: {api} in {func_name}")
    
    return suspicious


def is_important_function(func_name):
    """Determine if function is important enough to store full decompilation."""
    important_keywords = ["main", "start", "entry", "init", "execute", 
                         "inject", "decrypt", "payload", "shell"]
    return any(keyword in func_name.lower() for keyword in important_keywords)


def detect_syscalls(imports):
    """Detect direct syscall usage."""
    syscalls = []
    syscall_patterns = ["Nt", "Zw", "syscall", "int 0x80", "sysenter"]
    
    for imp in imports:
        if any(pattern in imp["name"] for pattern in syscall_patterns):
            syscalls.append(imp["name"])
    
    return syscalls


if __name__ == "__main__" and GHIDRA_RUNTIME:
    print("Starting Ghidra analysis...")
    analyze_binary()
    print("Done!")
