# WatsonPE
WatsonPE is a small Local Privilege Escalation scan tool, to automate the LPE search on Windows workstations, servers or dc's.
The tool is based on:
- https://book.hacktricks.xyz/
- winPEAS script
- [https://swisskyrepo.github.io/InternalAllTheThings/redteam/escalation/windows-privilege-escalation/](https://swisskyrepo.github.io/InternalAllTheThings/redteam/escalation/windows-privilege-escalation/)
- PowerUp script

<img src="WatsonPE.png" alt="WatsonPE"/>

## Usage

```PowerShell
# calling help function (colors explanation)
.\WatsonPE.ps1 -h

# calls quick win scan
.\WatsonPE.ps1 -light

# calls heavy scan
.\WatsonPE.ps1 -all

# calls enumeration module
.\WatsonPE.ps1 -enum
```
