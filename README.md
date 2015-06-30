# mitigationview

Tool to display a Windows 8+ process mitigation policy. Basically its just
a command-line tool to display output from [GetProcessMitigationPolicy](https://msdn.microsoft.com/en-us/library/windows/desktop/hh769085(v=vs.85).aspx).

## Usage

```
C:\>mitigationview.exe
usage: mitigationview.exe <pid>
```

## Calc example

```
C:\>calc

C:\>tasklist | findstr calc
calc.exe                      5760 Console                    2     14,520 K

C:\>mitigationview.exe 5760
ProcessDEPPolicy
 Enable                                     1
 DisableAtlThunkEmulation                   1
ProcessASLRPolicy
 EnableBottomUpRandomization                1
 EnableForceRelocateImages                  0
 EnableHighEntropy                          0
 DisallowStrippedImages                     0
ProcessStrictHandleCheckPolicy
 RaiseExceptionOnInvalidHandleReference     0
 HandleExceptionsPermanentlyEnabled         0
ProcessSystemCallDisablePolicy
 DisallowWin32kSystemCalls                  0
ProcessExtensionPointDisablePolicy
 DisableExtensionPoints                     0
```

## Chrome example

```
C:\>tasklist | findstr chrome
chrome.exe                    2780 Console                    2     63,864 K
chrome.exe                    2224 Console                    2    126,856 K
chrome.exe                    8036 Console                    2    102,616 K

C:\>mitigationview.exe 2224
ProcessASLRPolicy
 EnableBottomUpRandomization                1
 EnableForceRelocateImages                  0
 EnableHighEntropy                          1
 DisallowStrippedImages                     0
ProcessStrictHandleCheckPolicy
 RaiseExceptionOnInvalidHandleReference     1
 HandleExceptionsPermanentlyEnabled         1
ProcessSystemCallDisablePolicy
 DisallowWin32kSystemCalls                  1
ProcessExtensionPointDisablePolicy
 DisableExtensionPoints                     0

```

