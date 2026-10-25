# ReadyHai Windows host probe. Read-only. Run via: powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command -   (script on stdin)
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [Text.Encoding]::UTF8
$partial = New-Object System.Collections.ArrayList
$o = [ordered]@{ probe = 'windows' }
function Sec($name, [scriptblock]$b) {
  try { & $b } catch { [void]$partial.Add("${name}: " + (($_.Exception.Message -split "`n")[0])) }
}
Sec 'os' {
  $os = Get-CimInstance Win32_OperatingSystem
  $o.os = [ordered]@{ caption = $os.Caption; version = $os.Version; build = $os.BuildNumber }
  $o.uptime_secs = [int]((Get-Date) - $os.LastBootUpTime).TotalSeconds
}
$o.language_mode = "$($ExecutionContext.SessionState.LanguageMode)"
if ($o.language_mode -ne 'FullLanguage') { [void]$partial.Add("LanguageMode is $($o.language_mode): checks limited") }
Sec 'elevation' {
  $id = [Security.Principal.WindowsIdentity]::GetCurrent()
  $o.elevated = ([Security.Principal.WindowsPrincipal]$id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
  if (-not $o.elevated) { [void]$partial.Add('not elevated: Defender/SMB/update data may be missing') }
}
Sec 'defender' {
  $d = Get-MpComputerStatus
  $age = $null
  if ($d.AntivirusSignatureLastUpdated) { $age = [math]::Round(((Get-Date) - $d.AntivirusSignatureLastUpdated).TotalDays, 1) }
  $o.defender = [ordered]@{ realtime = [bool]$d.RealTimeProtectionEnabled; signature_age_days = $age; antivirus_enabled = [bool]$d.AntivirusEnabled }
}
Sec 'firewall' {
  $o.firewall = @(Get-NetFirewallProfile | ForEach-Object { [ordered]@{ name = "$($_.Name)"; enabled = ("$($_.Enabled)" -eq 'True') } })
}
Sec 'updates' {
  $job = Start-Job { $s = New-Object -ComObject Microsoft.Update.Session; $r = $s.CreateUpdateSearcher().Search('IsInstalled=0 and IsHidden=0'); $n = 0; $sec = 0
    foreach ($u in $r.Updates) { $n++; foreach ($c in $u.Categories) { if ($c.Name -eq 'Security Updates') { $sec++; break } } }
    @{ count = $n; security = $sec } }
  if (Wait-Job $job -Timeout 60) { $r = Receive-Job $job; $o.pending_updates = [ordered]@{ count = $r.count; security = $r.security } }
  else { Stop-Job $job; [void]$partial.Add('updates: Windows Update search timed out') }
  Remove-Job $job -Force
}
Sec 'smb1' { $o.smb1_enabled = [bool](Get-SmbServerConfiguration).EnableSMB1Protocol }
Sec 'rdp' {
  $ts = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'
  $deny = (Get-ItemProperty $ts -Name fDenyTSConnections).fDenyTSConnections
  $nla = (Get-ItemProperty "$ts\WinStations\RDP-Tcp" -Name UserAuthentication).UserAuthentication
  $o.rdp = [ordered]@{ enabled = ($deny -eq 0); nla = ($nla -eq 1) }
}
Sec 'admins' { $o.local_admins = @(Get-LocalGroupMember -SID 'S-1-5-32-544' | ForEach-Object { "$($_.Name)" }) }
Sec 'ports' {
  $o.listening = @(Get-NetTCPConnection -State Listen | Select-Object -First 300 | ForEach-Object { "$($_.LocalAddress):$($_.LocalPort)" } | Sort-Object -Unique)
}
Sec 'events' {
  $ev = Get-WinEvent -FilterHashtable @{ LogName = 'System', 'Application'; Level = 2 } -MaxEvents 200
  $o.error_lines = @($ev | ForEach-Object { $m = "$($_.Message)"; $first = ($m -split "`r?`n")[0]; "$($_.ProviderName): $first" })
}
Sec 'software' {
  $keys = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
  $o.packages = @(Get-ItemProperty $keys -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName } |
    Select-Object -First 3000 | ForEach-Object { [ordered]@{ name = "$($_.DisplayName)"; version = "$($_.DisplayVersion)" } })
}
$o.partial = @($partial)
$o | ConvertTo-Json -Depth 8 -Compress
