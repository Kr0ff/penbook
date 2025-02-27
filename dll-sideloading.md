# DLL Sideloading

DLL Sideloading is a method of a program which automatically attempts to load a non-existing DLL from a specific location. In Windows, the operating system can also attempt to load DLL files into processes which it cannot find.&#x20;

This can be abused by placing a custom DLL (malware)  either in the location of where the DLL is being loaded from, or by abusing the DLL search order on Windows. In some cases, its possible to load a DLL from the current working directory.

The following is the search order that Windows uses for DLLs:

* The directory from which the application loaded
* The system directory
* The 16-bit system directory
* The Windows directory
* The current working directory (CWD)
* The directories that are listed in the PATH environment variable

[@itm4n](https://github.com/itm4n) wrote a great blog about abusing `wlanhlp.dll` or `wlanapi.dll` to sideload a malicious DLL from the `%PATH%` environment variable.&#x20;

Reference to the blog post: [https://itm4n.github.io/windows-server-netman-dll-hijacking/](https://itm4n.github.io/windows-server-netman-dll-hijacking/)



