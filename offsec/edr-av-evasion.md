# EDR / AV Evasion

Evading security solutions can be tricky and difficult task to achieve. Windows Defender is typically one of the more easily bypassable security solutions, unless Defender MDE/MDI are deployed via InTune or alternative methods.

Some simple ways to disarm Defender include:

* Removing all virus definitions of Microsoft Defender (_Administrator required_)

<pre class="language-powershell"><code class="lang-powershell"># Run in CMD or powershell
<strong>PS:> cmd /c "%PROGRAMFILES%\Windows Defender\MPCMDRUN.exe" -RemoveDefinitions -All
</strong>PS:> C:\Program Files\Windows Defender\MPCMDRUN.EXE -RemoveDefinitions -All
</code></pre>

* Adding a process, folder, file or extension to the exclusion list (_Administrator required_)

```powershell
# Exclude a process
PS:> Set-MpPreference -ExclusionProcess untrusted.exe

# Exclude a folder
PS:> Set-MpPreference -ExclusionPath C:\Excluded\Path

# Exclude a file
PS:> Set-MpPreference -ExclusionPath C:\location\of\evil\binary\evil.exe

# Exclude an extension
PS:> Set-MpPreference -ExclusionExtension .ps1
```

* Disabling Microsoft Defender's real-time protection (_Administrator required_)

<pre class="language-powershell"><code class="lang-powershell"><strong># Disable real-time protection, behavioural monitoring and intrusion prevention
</strong><strong>PS:> Set-MpPreference -DisableRealtimeMonitoring $true -DisableIntrusionPreventionSystem $true -DisableBehaviorMonitoring $true
</strong></code></pre>

