# -------------------------
# UTF-8 FIX
# -------------------------
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8
chcp 65001 | Out-Null

Clear-Host
$host.UI.RawUI.WindowTitle = "Fiori's PC Checker Tool"

# -------------------------
# BANNER
# -------------------------
$bannerLines = @(
    "╔══════════════════════════════════════════════════════════════════════════════════╗",
    "║                                                                                  ║",
    "║  ███████╗██████╗  ██████╗     ██████╗██╗  ██╗███████╗ ██████╗██╗  ██╗        ║",
    "║  ██╔════╝██╔══██╗██╔════╝    ██╔════╝██║  ██║██╔════╝██╔════╝██║ ██╔╝        ║",
    "║  █████╗  ██████╔╝██║         ██║     ███████║█████╗  ██║     █████╔╝         ║",
    "║  ██╔══╝  ██╔═══╝ ██║         ██║     ██╔══██║██╔══╝  ██║     ██╔═██╗         ║",
    "║  ██║     ██║     ╚██████╗    ╚██████╗██║  ██║███████╗╚██████╗██║  ██╗        ║",
    "║  ╚═╝     ╚═╝      ╚═════╝     ╚═════╝╚═╝  ╚═╝╚══════╝ ╚═════╝╚═╝  ╚═╝        ║",
    "║                                                                                  ║",
    "║                      PC Diagnostic Tool v1.0                                     ║",
    "║               Made by @suprsor/Fiori on Discord                                  ║",
    "║                    Full code on GitHub                                          ║",
    "║                                                                                  ║",
    "╚══════════════════════════════════════════════════════════════════════════════════╝"
)
foreach ($line in $bannerLines) { Write-Host $line -ForegroundColor Magenta; Start-Sleep -Milliseconds 10 }
Write-Host ""

# -------------------------
# PROGRESS BAR
# -------------------------
$global:currentPercent = 0
function Update-Progress {
    param([string]$Message, [int]$TargetPercent)
    $barWidth = 40
    for ($p = $global:currentPercent; $p -le $TargetPercent; $p++) {
        $filled = [math]::Floor(($p / 100) * $barWidth)
        $bar = "█" * $filled + "░" * ($barWidth - $filled)
        if ($p -lt 33) { $color = "Red" }
        elseif ($p -lt 66) { $color = "Yellow" }
        else { $color = "Green" }
        Write-Host "`r  [$bar] $p%  $Message" -NoNewline -ForegroundColor $color
        Start-Sleep -Milliseconds 8
    }
    Write-Host "`r  ✔ $Message" -ForegroundColor Green
    $global:currentPercent = $TargetPercent
    Start-Sleep -Milliseconds 100
}

# -------------------------
# OUTPUT SETUP
# -------------------------
$desktopPath = [System.Environment]::GetFolderPath('Desktop')
$outputFile = Join-Path $desktopPath "PcCheckLogs.txt"
if (Test-Path $outputFile) { Clear-Content $outputFile }

$global:Logged = @{}
$global:Findings = @()

function Write-Log { param($text) Add-Content $outputFile $text }
function Add-Finding { 
    param($path,$reason) 
    $key="$path|$reason"
    if (-not $global:Findings.Contains($key)) { 
        $global:Findings += "$path -> $reason" 
    }
}

function Get-OneDrivePath {
    try {
        $path = (Get-ItemProperty "HKCU:\Software\Microsoft\OneDrive" -Name "UserFolder" -ErrorAction SilentlyContinue).UserFolder
        if (-not $path) { $alt = Join-Path $env:UserProfile "OneDrive"; if (Test-Path $alt) { $path = $alt } }
        return $path
    } catch { return $null }
}

# ==================== SCAN 1: REGISTRY ====================
Update-Progress -Message "Reading BAM, AppCompat, MuiCache..." -TargetPercent 11
$paths = @(
    "HKLM:\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings",
    "HKCU:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Store",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage\AppSwitched",
    "HKCR:\Local Settings\Software\Microsoft\Windows\Shell\MuiCache"
)
Write-Log "`n====================`nREGISTRY EXECUTION TRACES`n===================="
foreach ($path in $paths) {
    if (Test-Path $path) {
        Get-ItemProperty $path -ErrorAction SilentlyContinue | ForEach-Object {
            $_.PSObject.Properties | ForEach-Object {
                if ($_.Name -match "\.(exe|rar|dll|cfg)") {
                    if (-not $global:Logged.ContainsKey($_.Name)) {
                        Write-Log $_.Name
                        $global:Logged[$_.Name] = $true
                        if ($_.Name -match "loader|inject|hack|cheat|bypass|spoof|aimbot|triggerbot|easyanticheat") { 
                            Add-Finding $_.Name "Suspicious Registry Trace" 
                        }
                    }
                }
            }
        }
    }
}

# ==================== SCAN 2: WINDOWS INFO ====================
Update-Progress -Message "Querying OS version & security status..." -TargetPercent 22
$regPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion"
$installDateEpoch = (Get-ItemProperty $regPath -ErrorAction SilentlyContinue).InstallDate
if ($installDateEpoch) { $installDate = Get-Date ([System.DateTimeOffset]::FromUnixTimeSeconds($installDateEpoch).DateTime) } else { $installDate = "Unknown" }
$os = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue
$caption = $os.Caption
$build = [int]$os.BuildNumber
$versionNumber = $os.Version
$release = ""
if ($caption -match "Windows 10") {
    switch ($build) {
        {$_ -ge 19044} { $release = "22H2"; break }
        {$_ -ge 19043} { $release = "21H2"; break }
        {$_ -ge 19042} { $release = "20H2"; break }
        {$_ -ge 19041} { $release = "2004/20H1"; break }
        default { $release = "Older" }
    }
} elseif ($caption -match "Windows 11") {
    switch ($build) {
        {$_ -ge 22621} { $release = "24H2"; break }
        {$_ -ge 22000} { $release = "21H2"; break }
        default { $release = "Older" }
    }
}
$fullVersion = "$caption $release (Build $build, Version $versionNumber)"
try { $secureBoot = if (Confirm-SecureBootUEFI -ErrorAction SilentlyContinue) { "Enabled" } else { "Disabled" } } catch { $secureBoot = "Unknown" }
try { $av = Get-MpComputerStatus -ErrorAction SilentlyContinue; $firewall = if ($av.FirewallEnabled) { "Enabled" } else { "Disabled" }; $realTime = if ($av.RealTimeProtectionEnabled) { "Enabled" } else { "Disabled" } } catch { $firewall = "Unknown"; $realTime = "Unknown" }
Write-Log "`n====================`nWINDOWS SYSTEM INFO`n===================="
Write-Log "Install Date: $installDate"
Write-Log "Windows Version: $fullVersion"
Write-Log "Secure Boot: $secureBoot"
Write-Log "Firewall: $firewall"
Write-Log "Real-Time Protection: $realTime"

Write-Host ""
Write-Host "    ╭─────────────────────────────────────────────────────────╮" -ForegroundColor DarkGray
Write-Host "    │ Install Date          : $installDate" -ForegroundColor Cyan
Write-Host "    │ Windows Version       : $fullVersion" -ForegroundColor Cyan
$sbColor = if ($secureBoot -eq "Disabled") { "Red" } elseif ($secureBoot -eq "Enabled") { "Green" } else { "Yellow" }
Write-Host "    │ Secure Boot           : $secureBoot" -ForegroundColor $sbColor
$fwColor = if ($firewall -eq "Disabled") { "Red" } elseif ($firewall -eq "Enabled") { "Green" } else { "Yellow" }
Write-Host "    │ Firewall              : $firewall" -ForegroundColor $fwColor
$rtColor = if ($realTime -eq "Disabled") { "Red" } elseif ($realTime -eq "Enabled") { "Green" } else { "Yellow" }
Write-Host "    │ Real-Time Protection  : $realTime" -ForegroundColor $rtColor
Write-Host "    ╰─────────────────────────────────────────────────────────╯" -ForegroundColor DarkGray
Write-Host ""

# ==================== SCAN 3: BROWSERS ====================
Update-Progress -Message "Checking registry browser keys..." -TargetPercent 33
$path = "HKLM:\SOFTWARE\Clients\StartMenuInternet"
Write-Log "`n====================`nINSTALLED BROWSERS`n===================="
if (Test-Path $path) { Get-ChildItem $path -ErrorAction SilentlyContinue | ForEach-Object { Write-Log $_.Name } }

# ==================== SCAN 4: R6 PROFILES ====================
Update-Progress -Message "Scanning Siege profile folders..." -TargetPercent 44
$user = $env:UserName
$oneDrive = Get-OneDrivePath
$r6Paths = @(
    "C:\Users\$user\Documents\My Games\Rainbow Six - Siege",
    "$oneDrive\Documents\My Games\Rainbow Six - Siege"
)
Write-Log "`n====================`nR6 SIEGE USERNAMES`n===================="
foreach ($p in $r6Paths) {
    if (Test-Path $p) {
        Get-ChildItem $p -Directory -ErrorAction SilentlyContinue | ForEach-Object {
            Write-Log $_.Name
        }
    }
}

# ==================== SCAN 5: PREFETCH ====================
Update-Progress -Message "Parsing .pf execution timestamps..." -TargetPercent 55
$prefetchPath = "C:\Windows\Prefetch"
Write-Log "`n====================`nPREFETCH DATA`n===================="
if (Test-Path $prefetchPath) {
    Get-ChildItem $prefetchPath -Filter "*.pf" -ErrorAction SilentlyContinue | ForEach-Object {
        $name = $_.Name -replace "-.*", ""
        $lastRun = $_.LastWriteTime
        Write-Log "$name : $lastRun"
        if ($name -match "loader|inject|hack|cheat|bypass|spoof|aimbot|triggerbot|easyanticheat") { 
            Add-Finding $name "Suspicious Prefetch entry" 
        }
    }
}

# ==================== SCAN 6: FILE SCAN ====================
Update-Progress -Message "Crawling Downloads, AppData, Desktop, OneDrive..." -TargetPercent 66
$extensions = @(".exe", ".rar", ".dll", ".cfg")
$searchPaths = @("$env:USERPROFILE\Downloads", "$env:USERPROFILE\Desktop", "$env:APPDATA", "$env:LOCALAPPDATA")
if ($oneDrive) { $searchPaths += $oneDrive }
Write-Log "`n====================`nDETECTED FILES`n===================="
foreach ($searchPath in $searchPaths) {
    if (Test-Path $searchPath) {
        Get-ChildItem -Path $searchPath -Recurse -File -ErrorAction SilentlyContinue | ForEach-Object {
            if ($extensions -contains $_.Extension.ToLower()) {
                if (-not $global:Logged.ContainsKey($_.FullName)) {
                    Write-Log $_.FullName
                    $global:Logged[$_.FullName] = $true
                    if ($_.Name -match "loader|inject|hack|cheat|bypass|spoof|aimbot|triggerbot") { 
                        Add-Finding $_.FullName "Suspicious Name" 
                    }
                }
            }
        }
    }
}

# ==================== SCAN 7: PCIE & USB ====================
Update-Progress -Message "Querying PnP device tree..." -TargetPercent 77
Write-Log "`n====================`nPCIE & USB DEVICES`n===================="
$devices = Get-CimInstance Win32_PnPEntity -ErrorAction SilentlyContinue | Where-Object { $_.PNPDeviceID -match "PCI|USB" }
foreach ($dev in $devices) {
    $devName = $dev.Name
    $status = if ($dev.Status -eq "OK") { "Plugged In" } else { "Unplugged/Inactive" }
    if ($dev.PNPDeviceID -match "VEN_([0-9A-F]{4}).*DEV_([0-9A-F]{4})") { $devVid = $matches[1]; $devPid = $matches[2] } else { $devVid = "Unknown"; $devPid = "Unknown" }
    Write-Log "$devName | $status | VID:$devVid PID:$devPid"
}

# ==================== SCAN 8: DEVICE MANAGER ====================
Update-Progress -Message "Querying HID, Net, Display, Mouse..." -TargetPercent 88
$categories = @("Display", "Ports", "HIDClass", "Net", "USB", "Mouse")
Write-Log "`n====================`nDEVICE MANAGER INFO`n===================="
foreach ($cat in $categories) {
    Write-Log "`n$cat Devices:"
    $devs = Get-PnpDevice -Class $cat -ErrorAction SilentlyContinue
    foreach ($dev in $devs) {
        $deviceVID = "Unknown"; $devicePID = "Unknown"
        $status = if ($dev.Status -eq "OK") { "Plugged In" } else { "Unplugged/Inactive" }
        if ($dev.InstanceId -match "VEN_([0-9A-F]{4}).*DEV_([0-9A-F]{4})") { $deviceVID = $matches[1]; $devicePID = $matches[2] }
        if ($deviceVID -ne "Unknown" -or $devicePID -ne "Unknown") { Write-Log "$($dev.Name) | $status | VID:$deviceVID PID:$devicePID" }
    }
}

# ==================== SCAN 9: GHUB SCRIPTS ====================
Update-Progress -Message "Checking LGHUB script directory..." -TargetPercent 100
$ghubPath = "C:\Users\$env:UserName\AppData\Local\LGHUB\scripts"
Write-Log "`n====================`nLOGITECH GHUB SCRIPTS`n===================="
if (Test-Path $ghubPath) {
    Get-ChildItem $ghubPath -Directory -ErrorAction SilentlyContinue | ForEach-Object { Write-Log $_.Name }
}

# ==================== SUMMARY ====================
Write-Host ""
Write-Host "  ╔══════════════════════════════════════════════════════════════════════════════════╗" -ForegroundColor Magenta
Write-Host "  ║                                    FINDINGS SUMMARY                               ║" -ForegroundColor Magenta
Write-Host "  ╚══════════════════════════════════════════════════════════════════════════════════╝" -ForegroundColor Magenta
Write-Host ""
if ($global:Findings.Count -eq 0) {
    Write-Host "  ✔ No suspicious findings detected." -ForegroundColor Green
} else {
    $suspCount = ($global:Findings | Where-Object { $_ -match "Suspicious" }).Count
    Write-Host "  ⚠ Found $($global:Findings.Count) potential issues ($suspCount critical)" -ForegroundColor Yellow
    Write-Host ""
    foreach ($f in $global:Findings) {
        if ($f -match "Suspicious") { Write-Host "  ✖ $f" -ForegroundColor Red }
        else { Write-Host "  ⚠ $f" -ForegroundColor Yellow }
    }
}
Write-Host ""
Write-Host "  ───────────────────────────────────────────────────────────────────────────────────" -ForegroundColor DarkGray
Write-Host "  Made by @suprsor/Fiori on Discord  |  Full code on GitHub" -ForegroundColor Cyan
Write-Host ""
if (Test-Path $outputFile) { Get-Content $outputFile | Set-Clipboard }
Write-Host "  📋 Log saved to: $outputFile" -ForegroundColor Gray
Write-Host "  📋 Log copied to clipboard" -ForegroundColor Gray
Write-Host ""
Write-Host "  ✅ SCAN COMPLETE" -ForegroundColor Green
Write-Host ""
