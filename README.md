# RunPE

C# reflective loader for unmanaged binaries.

## Usage

```
Usage: RunPE.exe <file-to-run> <args-to-file-to-run>
        e.g. RunPE.exe C:\Windows\System32\net.exe localgroup administrators

Alternative usage: RunPE.exe ---f <file-to-pretend-to-be> ---b <base64 blob of file bytes> ---a <base64 blob of args>
        e.g: RunPE.exe ---f C:\Windows\System32\svchost.exe ---b <net.exe, base64 encoded> ---a <localgroup administrators, base64 encoded>
```


## Build configuration options

Edit the compilation symbols to quickly adjust the program flow:
(Right click the project in Visual Studio -> Properties -> Build -> Conditional Compilation Symbols)

* DEBUG (automatically added in Debug release mode) -> Very verbose logging
* BREAK_TO_ATTACH -> Print "Press Enter to continue..." and await input so can attach debugger