/*
    HIDS_Rules.yar
    

    Sources:
    - Neo23x0/signature-base
    - MITRE ATT&CK behaviours
    - Custom HIDS test rules
*/


rule HIDS_Test_String
{
    meta:
        description = "Test rule for checking that YARA works"
        author = "Custom HIDS"

    strings:
        $test = "HIDS_YARA_TEST" ascii wide

    condition:
        $test
}


rule HIDS_Suspicious_PowerShell_Code
{
    meta:
        description = "Detects suspicious PowerShell code"
        source = "Adapted from Neo23x0 signature-base gen_powershell_susp.yar"
        original_author = "Florian Roth, Nextron Systems"
        license = "Detection Rule License 1.1"
        modified_by = "Custom HIDS"

    strings:
        $s1 = "new-object net.webclient" ascii wide nocase
        $s2 = "downloadstring" ascii wide nocase
        $s3 = "downloadfile" ascii wide nocase
        $s4 = "invoke-expression" ascii wide nocase
        $s5 = "iex" ascii wide nocase
        $s6 = "powershell.exe -w hidden" ascii wide nocase
        $s7 = "-ep bypass" ascii wide nocase
        $s8 = "-encodedcommand" ascii wide nocase
        $s9 = "-enc" ascii wide nocase
        $s10 = "frombase64string" ascii wide nocase

    condition:
        3 of them
}


rule HIDS_PowerShell_Web_Download
{
    meta:
        description = "Detects PowerShell download behaviour"
        source = "Adapted from Neo23x0 Suspicious_PowerShell_WebDownload_1"
        original_author = "Florian Roth, Nextron Systems"
        license = "Detection Rule License 1.1"
        modified_by = "Custom HIDS"

    strings:
        $s1 = "System.Net.WebClient).DownloadString(\"http" ascii wide nocase
        $s2 = "System.Net.WebClient).DownloadString('http" ascii wide nocase
        $s3 = "System.Net.WebClient).DownloadFile(\"http" ascii wide nocase
        $s4 = "System.Net.WebClient).DownloadFile('http" ascii wide nocase
        $s5 = "Invoke-WebRequest" ascii wide nocase
        $s6 = "iwr " ascii wide nocase
        $s7 = "curl " ascii wide nocase
        $s8 = "http://" ascii wide nocase
        $s9 = "https://" ascii wide nocase

        $fp1 = "chocolatey.org" ascii wide nocase
        $fp2 = "nuget.exe" ascii wide nocase
        $fp3 = "installazurecliwindows" ascii wide nocase

    condition:
        1 of ($s1,$s2,$s3,$s4,$s5,$s6,$s7) and
        1 of ($s8,$s9) and
        not 1 of ($fp*)
}


rule HIDS_PowerShell_In_Word_Document
{
    meta:
        description = "Detects PowerShell and bypass keyword in a Word document"
        source = "Adapted from Neo23x0 PowerShell_in_Word_Doc"
        original_author = "Florian Roth, Nextron Systems"
        license = "Detection Rule License 1.1"
        modified_by = "Custom HIDS"

    strings:
        $s1 = "powershell.exe" ascii wide nocase
        $s2 = "bypass" ascii wide nocase

    condition:
        uint16(0) == 0xcfd0 and filesize < 1000KB and all of them
}


rule HIDS_WScript_PowerShell_Combo
{
    meta:
        description = "Detects WScript launching PowerShell with suspicious options"
        source = "Adapted from Neo23x0 WScript_Shell_PowerShell_Combo"
        original_author = "Florian Roth, Nextron Systems"
        license = "Detection Rule License 1.1"
        modified_by = "Custom HIDS"

    strings:
        $s1 = "CreateObject(\"WScript.Shell\")" ascii wide nocase
        $p1 = "powershell.exe" ascii wide nocase
        $p2 = "-ExecutionPolicy Bypass" ascii wide nocase
        $p3 = "[System.Convert]::FromBase64String(" ascii wide nocase
        $p4 = "-nop" ascii wide nocase
        $p5 = "-w hidden" ascii wide nocase

        $fp1 = "Copyright: Microsoft Corp." ascii wide nocase

    condition:
        filesize < 400KB and $s1 and 1 of ($p*) and not $fp1
}


rule HIDS_Batch_Download_Tools
{
    meta:
        description = "Detects batch/script files using common Windows download tools"
        source = "Adapted from Neo23x0 recon/download indicators and common LOLBin behaviour"
        original_author = "Florian Roth, Nextron Systems"
        license = "Detection Rule License 1.1"
        modified_by = "Custom HIDS"

    strings:
        $tool1 = "certutil" ascii wide nocase
        $tool2 = "bitsadmin" ascii wide nocase
        $tool3 = "curl" ascii wide nocase
        $tool4 = "wget" ascii wide nocase
        $tool5 = "powershell" ascii wide nocase

        $arg1 = "-urlcache" ascii wide nocase
        $arg2 = "-split" ascii wide nocase
        $arg3 = "/transfer" ascii wide nocase
        $arg4 = "downloadfile" ascii wide nocase
        $arg5 = "downloadstring" ascii wide nocase

        $url1 = "http://" ascii wide nocase
        $url2 = "https://" ascii wide nocase

    condition:
        1 of ($tool*) and 1 of ($url*) and 1 of ($arg*)
}


rule HIDS_Recon_Command_Collection
{
    meta:
        description = "Detects multiple reconnaissance commands in one script or output file"
        source = "Adapted from Neo23x0 gen_recon_indicators.yar"
        original_author = "Florian Roth, Nextron Systems"
        license = "Detection Rule License 1.1"
        modified_by = "Custom HIDS"

    strings:
        $s1 = "netstat -an" ascii wide nocase
        $s2 = "net view" ascii wide nocase
        $s3 = "net user" ascii wide nocase
        $s4 = "whoami" ascii wide nocase
        $s5 = "tasklist /v" ascii wide nocase
        $s6 = "systeminfo" ascii wide nocase
        $s7 = "net localgroup administrators" ascii wide nocase
        $s8 = "net user administrator" ascii wide nocase
        $s9 = "tasklist /svc" ascii wide nocase
        $s10 = "wmic qfe list" ascii wide nocase
        $s11 = "arp -a" ascii wide nocase
        $s12 = "ipconfig /all" ascii wide nocase

        $fp1 = ".sublime-settings" ascii wide nocase
        $fp2 = "keyword.command.batchfile" ascii wide nocase

    condition:
        filesize < 1000KB and 4 of ($s*) and not 1 of ($fp*)
}


rule HIDS_Scheduled_Task_Persistence
{
    meta:
        description = "Detects scheduled task creation from scripts"
        source = "Custom HIDS rule based on Windows scheduled task abuse"

    strings:
        $s1 = "schtasks" ascii wide nocase
        $s2 = "/create" ascii wide nocase
        $s3 = "/sc" ascii wide nocase
        $s4 = "/tn" ascii wide nocase
        $s5 = "/tr" ascii wide nocase
        $s6 = "onlogon" ascii wide nocase
        $s7 = "onstart" ascii wide nocase
        $s8 = "runlevel highest" ascii wide nocase
        $s9 = "powershell" ascii wide nocase
        $s10 = "cmd.exe" ascii wide nocase

    condition:
        $s1 and $s2 and 2 of ($s3,$s4,$s5,$s6,$s7,$s8,$s9,$s10)
}


rule HIDS_RunKey_Startup_Persistence
{
    meta:
        description = "Detects common Windows Run key or Startup folder persistence"
        source = "Custom HIDS rule based on Windows startup persistence"

    strings:
        $r1 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii wide nocase
        $r2 = "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce" ascii wide nocase
        $r3 = "Start Menu\\Programs\\Startup" ascii wide nocase
        $r4 = "\\Startup" ascii wide nocase

        $a1 = "reg add" ascii wide nocase
        $a2 = "HKCU" ascii wide nocase
        $a3 = "HKLM" ascii wide nocase
        $a4 = "powershell" ascii wide nocase
        $a5 = "cmd.exe" ascii wide nocase
        $a6 = "wscript" ascii wide nocase

    condition:
        1 of ($r*) and 1 of ($a*)
}


rule HIDS_Suspicious_LNK_Command_Execution
{
    meta:
        description = "Detects shortcut files containing suspicious command execution strings"
        source = "Custom HIDS rule for suspicious LNK behaviour"

    strings:
        $lnk_magic = { 4C 00 00 00 }

        $c1 = "cmd.exe" ascii wide nocase
        $c2 = "powershell" ascii wide nocase
        $c3 = "mshta" ascii wide nocase
        $c4 = "wscript" ascii wide nocase
        $c5 = "rundll32" ascii wide nocase

        $s1 = "http://" ascii wide nocase
        $s2 = "https://" ascii wide nocase
        $s3 = "-enc" ascii wide nocase
        $s4 = "hidden" ascii wide nocase
        $s5 = "bypass" ascii wide nocase

    condition:
        $lnk_magic at 0 and 1 of ($c*) and 1 of ($s*)
}


rule HIDS_Credential_Dumping_Keywords
{
    meta:
        description = "Detects credential dumping or password extraction keywords"
        source = "Custom HIDS rule based on common credential dumping indicators"

    strings:
        $s1 = "mimikatz" ascii wide nocase
        $s2 = "sekurlsa" ascii wide nocase
        $s3 = "logonpasswords" ascii wide nocase
        $s4 = "lsass" ascii wide nocase
        $s5 = "procdump" ascii wide nocase
        $s6 = "reg save hklm\\sam" ascii wide nocase
        $s7 = "reg save hklm\\system" ascii wide nocase
        $s8 = "ntds.dit" ascii wide nocase
        $s9 = "lsass.dmp" ascii wide nocase

    condition:
        any of them
}