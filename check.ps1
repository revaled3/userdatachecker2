# =====================================================================
#  Steam userdata - analizator dziennika USN (NTFS Change Journal)
#
#  Wykrywa i wypisuje, co faktycznie stało się z folderami w Steam\userdata:
#  usunięcie (do Kosza / trwale), przeniesienie, zmiana nazwy - wraz z datą i godziną.
#
#  Automatyczna praca Steama jest pomijana: pliki tymczasowe (*.tmp, *.vdf~ itp.)
#  oraz podkatalogi zarządzane przez Steam (gamerecordings\, *cache\, logs\, *.log).
#
#  Uruchomienie (wklej do PowerShella):
#     irm https://raw.githubusercontent.com/revaled3/userdatachecker2/main/check.ps1 | iex
#
#  Skrypt sam poprosi o uprawnienia administratora (okno UAC).
#  Wynik: plik steam_userdata_log.txt na Pulpicie + kopia w schowku.
#  Skrypt NICZEGO nie usuwa ani nie zmienia - tylko czyta dziennik USN.
# =====================================================================

& {

# Adres tego pliku na GitHubie (link "Raw") - potrzebny, żeby okno
# z uprawnieniami administratora mogło pobrać skrypt ponownie.
$ScriptUrl = 'https://raw.githubusercontent.com/revaled3/userdatachecker2/main/check.ps1'

# ---------- 0. Uprawnienia administratora ----------
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
               [Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    if ($ScriptUrl -match 'TWOJ_NICK') {
        Write-Host 'Ten skrypt wymaga uprawnień administratora.' -ForegroundColor Yellow
        Write-Host 'Uruchom PowerShell jako Administrator (Win+X -> Terminal (Administrator)) i wklej komendę ponownie.' -ForegroundColor Yellow
        return
    }
    Write-Host 'Proszę potwierdzić uruchomienie jako Administrator - okno UAC...' -ForegroundColor Cyan
    $cmd = "[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; irm '$ScriptUrl' | iex"
    try {
        Start-Process -FilePath 'powershell.exe' -Verb RunAs -ArgumentList @(
            '-NoProfile', '-NoExit', '-ExecutionPolicy', 'Bypass', '-Command', $cmd) -ErrorAction Stop
        Write-Host 'Analiza działa w nowym oknie (Administrator).' -ForegroundColor Green
    } catch {
        Write-Host 'Nie uzyskano uprawnień administratora (odrzucono okno UAC?).' -ForegroundColor Red
    }
    return
}

$ErrorActionPreference = 'Stop'
try { $OutputEncoding = [Console]::OutputEncoding = New-Object System.Text.UTF8Encoding $false } catch {}
try { $Host.UI.RawUI.WindowTitle = 'Steam userdata - analizator dziennika USN' } catch {}

Write-Host ''
Write-Host 'Steam userdata - analizator dziennika USN (NTFS Change Journal)' -ForegroundColor White
Write-Host '==============================================================' -ForegroundColor White
Write-Host 'Skrypt tylko ODCZYTUJE dane - niczego nie usuwa ani nie zmienia.' -ForegroundColor DarkGray

$logLines   = New-Object System.Collections.Generic.List[string]
$LogPath    = $null
$LogWritten = $false

function Write-Log {
    param([string]$Text)
    $line = ('[{0}] {1}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Text)
    $logLines.Add($line)
    Write-Host $line
}

function Normalize-Id {
    param($Value)
    if ($null -eq $Value) { return $null }
    $s = ([string]$Value).Trim().ToLowerInvariant() -replace '^0x','' -replace '[^0-9a-f]',''
    if (-not $s) { return $null }
    if ($s.Length -lt 32) { $s = $s.PadLeft(32,'0') }
    return $s
}

function Get-FileId {
    param([string]$Path)
    $text = (& fsutil file queryfileid "$Path" 2>&1 | Out-String)
    $m = [regex]::Match($text, '0x([0-9A-Fa-f]+)')
    if (-not $m.Success) { throw "Nie udało się pobrać File ID dla: $Path`r`n$text" }
    return (Normalize-Id $m.Groups[1].Value)
}

function Format-When {
    param([string]$Text)
    foreach ($ci in @([System.Globalization.CultureInfo]::CurrentCulture,
                      [System.Globalization.CultureInfo]::InvariantCulture,
                      (New-Object System.Globalization.CultureInfo 'pl-PL'))) {
        try {
            $dt = [datetime]::Parse($Text, $ci, [System.Globalization.DateTimeStyles]::None)
            return $dt.ToString('yyyy-MM-dd HH:mm:ss')
        } catch {}
    }
    return $Text
}

function Get-TrueCasePath {
    param([string]$Path)
    try {
        $full = [System.IO.Path]::GetFullPath($Path)
        $root = [System.IO.Path]::GetPathRoot($full)
        $rest = $full.Substring($root.Length).TrimEnd('\')
        if (-not $rest) { return $root.ToUpperInvariant() }
        $cur = $root.ToUpperInvariant()
        foreach ($seg in $rest.Split('\')) {
            $hit = [System.IO.Directory]::GetFileSystemEntries($cur, $seg)
            if (-not $hit -or $hit.Count -eq 0) { return $full }
            $cur = $hit[0]
        }
        return $cur
    } catch { return $Path }
}

function Test-UserdataFolder {
    param([string]$Path)
    if (-not $Path) { return $null }
    $p = $Path.Trim().Trim('"').TrimEnd('\')
    if (-not $p) { return $null }
    # zaakceptuj zarówno ...\userdata, jak i folder Steam zawierający userdata
    foreach ($cand in @($p, (Join-Path $p 'userdata'))) {
        try {
            if (Test-Path -LiteralPath $cand -PathType Container) {
                $leaf = Split-Path -Leaf $cand
                if ($leaf -ieq 'userdata') {
                    return (Get-TrueCasePath ((Resolve-Path -LiteralPath $cand).Path.TrimEnd('\')))
                }
            }
        } catch {}
    }
    return $null
}

function Get-AccountCount {
    # Ile folderów kont Steam (nazwa = same cyfry) jest bezpośrednio w userdata.
    param([string]$Path)
    try {
        return @(Get-ChildItem -LiteralPath $Path -Directory -Force -ErrorAction SilentlyContinue |
                 Where-Object { $_.Name -match '^\d+$' }).Count
    } catch { return 0 }
}

function Get-FixedDrives {
    try   { return @((Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' -ErrorAction Stop).DeviceID) }
    catch { return @('C:') }
}

function Search-UserdataDirs {
    # Ograniczone przeszukiwanie drzewa katalogów w poszukiwaniu folderów "userdata".
    param([string[]]$Roots, [int]$MaxDepth = 5, [int]$TimeoutSec = 60)

    $hits = New-Object System.Collections.Generic.List[string]
    $sw   = [System.Diagnostics.Stopwatch]::StartNew()
    $skip = @('windows','winsxs','appdata','node_modules','msocache','perflogs',
              'recovery','windows.old','$recycle.bin','system volume information')

    $stack = New-Object System.Collections.Generic.Stack[object]
    foreach ($r in ($Roots | Select-Object -Unique)) {
        if ($r -and (Test-Path -LiteralPath $r -PathType Container)) {
            $stack.Push([pscustomobject]@{ Path = $r; Depth = 0 })
        }
    }

    while ($stack.Count -gt 0) {
        if ($sw.Elapsed.TotalSeconds -gt $TimeoutSec) { break }
        $cur  = $stack.Pop()
        $kids = $null
        try { $kids = [System.IO.Directory]::GetDirectories($cur.Path) } catch { continue }
        foreach ($k in $kids) {
            $leaf = [System.IO.Path]::GetFileName($k)
            if ($leaf -ieq 'userdata') { $hits.Add($k); continue }
            if (($cur.Depth + 1) -ge $MaxDepth) { continue }
            $ll = $leaf.ToLowerInvariant()
            if ($ll.StartsWith('$') -or ($skip -contains $ll)) { continue }
            try {
                $attr = [System.IO.File]::GetAttributes($k)
                if (($attr -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) { continue }
            } catch { continue }
            $stack.Push([pscustomobject]@{ Path = $k; Depth = $cur.Depth + 1 })
        }
    }
    return $hits
}

function Find-UserdataCandidates {
    # Zwraca posortowaną listę: [pscustomobject]@{ Path; Accounts } (najwięcej kont pierwszy).
    $paths = New-Object System.Collections.Generic.List[string]

    # 1) rejestr Steam
    $regs = @(
        @{ Path = 'HKCU:\Software\Valve\Steam';             Name = 'SteamPath'   },
        @{ Path = 'HKLM:\SOFTWARE\WOW6432Node\Valve\Steam'; Name = 'InstallPath' },
        @{ Path = 'HKLM:\SOFTWARE\Valve\Steam';             Name = 'InstallPath' }
    )
    foreach ($r in $regs) {
        try {
            $val = (Get-ItemProperty -LiteralPath $r.Path -Name $r.Name -ErrorAction Stop).($r.Name)
            if ($val) { $paths.Add((Join-Path ($val -replace '/','\') 'userdata')) }
        } catch {}
    }

    # 2) typowe podkatalogi Steam na wszystkich dyskach stałych
    $drives = Get-FixedDrives
    $subs = @(
        'Program Files (x86)\Steam', 'Program Files\Steam',
        'Steam', 'SteamLibrary', 'Games\Steam', 'Gry\Steam', 'Gry\SteamLibrary'
    )
    foreach ($d in $drives) {
        $paths.Add((Join-Path "$d\" 'userdata'))
        foreach ($s in $subs) { $paths.Add((Join-Path "$d\" (Join-Path $s 'userdata'))) }
    }

    # 3) foldery użytkownika (userdata przeniesiony ręcznie)
    $userBases = @(
        $env:USERPROFILE,
        [Environment]::GetFolderPath('MyDocuments'),
        [Environment]::GetFolderPath('Desktop'),
        (Join-Path $env:USERPROFILE 'Downloads'),
        (Join-Path $env:USERPROFILE 'Saved Games'),
        $env:OneDrive,
        (Join-Path $env:USERPROFILE 'OneDrive\Dokumenty'),
        (Join-Path $env:USERPROFILE 'OneDrive\Documents')
    ) | Where-Object { $_ }
    foreach ($b in $userBases) {
        $paths.Add((Join-Path $b 'userdata'))
        $paths.Add((Join-Path $b 'Steam\userdata'))
    }

    # --- walidacja szybkich kandydatów ---
    $result = New-Object System.Collections.Generic.List[object]
    $seen   = New-Object 'System.Collections.Generic.HashSet[string]'
    foreach ($p in $paths) {
        $ok = Test-UserdataFolder $p
        if (-not $ok) { continue }
        if (-not $seen.Add($ok.ToLowerInvariant())) { continue }
        $result.Add([pscustomobject]@{ Path = $ok; Accounts = (Get-AccountCount $ok); Order = $result.Count })
    }

    # Jeśli żaden szybki kandydat nie ma folderów kont - przeszukaj dyski.
    if (@($result | Where-Object { $_.Accounts -ge 1 }).Count -eq 0) {
        Write-Host 'Szukam folderu "userdata" na dyskach (to może potrwać do ~1 min)...' -ForegroundColor Cyan
        $roots = New-Object System.Collections.Generic.List[string]
        foreach ($b in $userBases) { $roots.Add($b) }
        foreach ($d in $drives) {
            $roots.Add("$d\")
            foreach ($s in @('Program Files','Program Files (x86)','Games','Gry','Apps','SteamLibrary')) {
                $roots.Add((Join-Path "$d\" $s))
            }
        }
        foreach ($h in (Search-UserdataDirs -Roots $roots)) {
            $ok = Test-UserdataFolder $h
            if (-not $ok) { continue }
            if (-not $seen.Add($ok.ToLowerInvariant())) { continue }
            $result.Add([pscustomobject]@{ Path = $ok; Accounts = (Get-AccountCount $ok); Order = $result.Count })
        }
    }

    # Najwięcej folderów kont pierwszy; przy remisie - kolejność wykrycia (rejestr ma priorytet).
    return @($result | Sort-Object -Property @{ Expression = 'Accounts'; Descending = $true },
                                             @{ Expression = 'Order';    Descending = $false })
}

try {
    # ---------- 1. Ustalenie folderu userdata ----------
    $Target = $null

    Write-Host ''
    Write-Host 'Ustalam lokalizację folderu userdata...' -ForegroundColor Cyan
    $udCands = @(Find-UserdataCandidates)

    if ($udCands.Count -gt 0) {
        $withAcc = @($udCands | Where-Object { $_.Accounts -ge 1 })

        if ($withAcc.Count -ge 1) {
            $best   = $withAcc[0]
            $Target = $best.Path
            Write-Host ("Wybrany folder userdata: {0}   (folderów kont: {1})" -f $best.Path, $best.Accounts) -ForegroundColor Green
            $others = @($udCands | Where-Object { $_.Path -ne $best.Path })
            if ($others.Count -gt 0) {
                Write-Host 'Pozostałe znalezione (pominięte):' -ForegroundColor DarkGray
                foreach ($o in $others) {
                    Write-Host ("   {0}   (folderów kont: {1})" -f $o.Path, $o.Accounts) -ForegroundColor DarkGray
                }
            }
        }
        elseif ($udCands.Count -eq 1) {
            Write-Host 'Znaleziono jeden folder userdata, ale jest pusty (brak folderów kont Steam):' -ForegroundColor Yellow
            Write-Host ("   {0}" -f $udCands[0].Path) -ForegroundColor Yellow
            Write-Host 'Jeśli userdata jest gdzie indziej - wklej pełną ścieżkę. Enter = użyj znalezionego.' -ForegroundColor Yellow
            $entered = (Read-Host 'Ścieżka (lub Enter)')
            if ([string]::IsNullOrWhiteSpace($entered)) {
                $Target = $udCands[0].Path
            } else {
                $Target = Test-UserdataFolder $entered
                if (-not $Target) { throw "Podana ścieżka nie wskazuje folderu 'userdata': $entered" }
            }
        }
        else {
            Write-Host 'Znaleziono kilka folderów "userdata", ale żaden nie ma folderów kont Steam:' -ForegroundColor Yellow
            for ($k = 0; $k -lt $udCands.Count; $k++) {
                Write-Host ("   [{0}] {1}" -f ($k + 1), $udCands[$k].Path) -ForegroundColor Yellow
            }
            $sel = (Read-Host 'Wpisz numer właściwego folderu albo wklej pełną ścieżkę')
            if ($sel -match '^\d+$' -and [int]$sel -ge 1 -and [int]$sel -le $udCands.Count) {
                $Target = $udCands[[int]$sel - 1].Path
            } else {
                $Target = Test-UserdataFolder $sel
            }
            if (-not $Target) { throw "Nie rozpoznano wyboru: $sel" }
        }
    }

    if (-not $Target) {
        Write-Host ''
        Write-Host 'Nie udało się odnaleźć folderu "userdata" - ani automatycznie, ani przez przeszukanie dysków.' -ForegroundColor Yellow
        Write-Host 'Podaj pełną ścieżkę do folderu userdata (np. D:\Gry\Steam\userdata):' -ForegroundColor Yellow
        $entered = (Read-Host 'Ścieżka')
        $Target = Test-UserdataFolder $entered
        if (-not $Target) {
            throw "Podana ścieżka nie wskazuje istniejącego folderu 'userdata': $entered"
        }
    }

    $AnchorPath = $Target
    $Volume = ([System.IO.Path]::GetPathRoot($Target)).TrimEnd('\')
    if ($Volume -notmatch '^[A-Za-z]:$') {
        throw "Nie potrafię ustalić litery dysku dla folderu: $Target"
    }

    # Wynik zapisujemy na Pulpicie; jeśli się nie da - w folderze TEMP.
    $OutDir = [Environment]::GetFolderPath('Desktop')
    try {
        if (-not $OutDir -or -not (Test-Path -LiteralPath $OutDir -PathType Container)) { throw 'brak Pulpitu' }
        $probe = Join-Path $OutDir ('.usn_write_test_{0}.tmp' -f ([guid]::NewGuid().ToString('N')))
        Set-Content -LiteralPath $probe -Value 'x' -ErrorAction Stop
        Remove-Item -LiteralPath $probe -Force -ErrorAction SilentlyContinue
    } catch {
        $OutDir = $env:TEMP
    }
    $LogPath = Join-Path $OutDir 'steam_userdata_log.txt'

    Write-Log "Start analizy."
    Write-Log "Komputer        : $env:COMPUTERNAME"
    Write-Log "Folder userdata : $Target"
    Write-Log "Dysk (wolumin)  : $Volume"

    # ---------- 2. Sprawdzenie dziennika USN ----------
    # Dziennik USN jest PER DYSK - analizujemy dziennik tego dysku, na którym
    # faktycznie leży folder userdata (może być inny niż C:).
    $jq = (& fsutil usn queryjournal $Volume 2>&1 | Out-String)
    if ($LASTEXITCODE -ne 0) {
        throw ("Na dysku $Volume nie ma aktywnego dziennika USN (NTFS Change Journal).`r`n" +
               "Bez niego nie da się odtworzyć historii zmian folderu:`r`n  $Target`r`n`r`n" +
               "Możliwe przyczyny:`r`n" +
               "  - to dysk niesystemowy, na którym dziennik nigdy nie był włączony,`r`n" +
               "  - dysk nie jest sformatowany w NTFS (np. exFAT/FAT32 - brak dziennika USN),`r`n" +
               "  - dziennik został celowo usunięty (fsutil usn deletejournal).`r`n$jq")
    }

    $AnchorId = Get-FileId $Target
    Write-Log "File ID folderu userdata: $AnchorId"

    # ---------- 3. Mapa istniejących katalogów + Kosz ----------
    Write-Host ''
    Write-Host '[1/4] Buduję mapę istniejących katalogów userdata...' -ForegroundColor Cyan
    $Fallback = @{}
    $Fallback[$AnchorId] = $AnchorPath
    Get-ChildItem -LiteralPath $AnchorPath -Directory -Recurse -Force -ErrorAction SilentlyContinue | ForEach-Object {
        try { $id = Get-FileId $_.FullName; if ($id) { $Fallback[$id] = $_.FullName } } catch {}
    }

    $RecycleIds = New-Object 'System.Collections.Generic.HashSet[string]'
    try {
        Get-ChildItem -LiteralPath ($Volume + '\$Recycle.Bin') -Directory -Force -ErrorAction Stop | ForEach-Object {
            try {
                $id = Get-FileId $_.FullName
                if ($id) { [void]$RecycleIds.Add($id); $Fallback[$id] = 'KOSZ' }
            } catch {}
        }
    } catch {}
    Write-Log ("Katalogów w mapie pomocniczej: {0} (w tym foldery Kosza: {1})" -f $Fallback.Count, $RecycleIds.Count)

    # ---------- 4. Odczyt dziennika USN (strumieniowo) ----------
    Write-Host '[2/4] Odczytuję dziennik USN (to może potrwać do ~1 min)...' -ForegroundColor Cyan
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName               = 'fsutil'
    $psi.Arguments              = "usn readjournal $Volume csv"
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError  = $true
    $psi.UseShellExecute        = $false
    $psi.CreateNoWindow         = $true
    try { $psi.StandardOutputEncoding = [System.Text.Encoding]::Default } catch {}

    $proc   = [System.Diagnostics.Process]::Start($psi)
    $rx     = New-Object System.Text.RegularExpressions.Regex('(?:^|,)(?:"((?:[^"]|"")*)"|([^,]*))', [System.Text.RegularExpressions.RegexOptions]::Compiled)

    $State = @{}                                                   # fileId -> "nazwa`tparentId" (ostatni znany stan)
    $cands = New-Object System.Collections.Generic.List[object]    # rekordy DELETE / RENAME
    $lineCount = 0

    while ($null -ne ($line = $proc.StandardOutput.ReadLine())) {
        $lineCount++
        if ($line.Length -eq 0) { continue }
        $c0 = $line[0]
        if ($c0 -lt '0' -or $c0 -gt '9') { continue }              # pomiń preambułę i nagłówek
        $mm = $rx.Matches($line)
        if ($mm.Count -lt 10) { continue }

        $g1 = $mm[1].Groups
        $name = if ($g1[1].Success) { $g1[1].Value } else { $g1[2].Value }

        $fileId = $mm[8].Groups[2].Value
        if ($fileId.Length -ne 32) { $fileId = Normalize-Id $fileId }
        if (-not $fileId) { continue }
        $parentId = $mm[9].Groups[2].Value
        if ($parentId.Length -ne 32) { $parentId = Normalize-Id $parentId }

        $reason = [Convert]::ToInt64(($mm[3].Groups[2].Value -replace '^0x',''), 16)

        $State[$fileId] = ($name + "`t" + $parentId)

        if (($reason -band 0x3200) -ne 0) {                        # 0x200 DELETE | 0x1000 RENAME_OLD | 0x2000 RENAME_NEW
            $g5 = $mm[5].Groups
            $time = if ($g5[1].Success) { $g5[1].Value } else { $g5[2].Value }
            $attrs = [Convert]::ToInt64(($mm[6].Groups[2].Value -replace '^0x',''), 16)
            $cands.Add([pscustomobject]@{
                USN       = [int64]$mm[0].Groups[2].Value
                Name      = $name
                TimeText  = $time
                FileId    = $fileId
                ParentId  = $parentId
                IsDelete  = (($reason -band 0x200)  -ne 0)
                IsRenOld  = (($reason -band 0x1000) -ne 0)
                IsRenNew  = (($reason -band 0x2000) -ne 0)
                IsDir     = (($attrs  -band 0x10)   -ne 0)
                ParentPath = $null
                FullPath   = $null
            })
        }
    }
    $errText = $proc.StandardError.ReadToEnd()
    $proc.WaitForExit()

    if ($proc.ExitCode -ne 0) {
        throw "fsutil usn readjournal zakończył się kodem $($proc.ExitCode).`r`n$errText"
    }
    Write-Log ("Przetworzono wierszy dziennika USN: {0}" -f $lineCount)
    Write-Log ("Rekordów DELETE/RENAME (wszystkie ścieżki): {0}" -f $cands.Count)

    # ---------- 5. Odtworzenie ścieżek ----------
    Write-Host '[3/4] Odtwarzam ścieżki katalogów...' -ForegroundColor Cyan
    $memo = @{}
    function Resolve-Dir {
        param([string]$Id)
        if (-not $Id) { return $null }
        if ($Id -eq $AnchorId) { return $AnchorPath }
        if ($memo.ContainsKey($Id)) { return $memo[$Id] }
        if ($Fallback.ContainsKey($Id)) { $memo[$Id] = $Fallback[$Id]; return $memo[$Id] }
        $memo[$Id] = $null                                          # zabezpieczenie przed cyklem
        $node = $State[$Id]
        if ($node) {
            $t = $node.Split("`t", 2)
            $pp = Resolve-Dir $t[1]
            if ($pp -and $pp -ne 'KOSZ' -and $t[0]) {
                $memo[$Id] = (Join-Path $pp $t[0])
                return $memo[$Id]
            }
        }
        return $null
    }

    function Is-UnderUserdata {
        param([string]$Path)
        if (-not $Path) { return $false }
        return $Path.Equals($AnchorPath, [System.StringComparison]::OrdinalIgnoreCase) -or
               $Path.StartsWith($AnchorPath + '\', [System.StringComparison]::OrdinalIgnoreCase)
    }

    foreach ($c in $cands) {
        $pp = Resolve-Dir $c.ParentId
        $c.ParentPath = $pp
        if ($pp -and $pp -ne 'KOSZ') { $c.FullPath = Join-Path $pp $c.Name }
    }

    $udIds = New-Object 'System.Collections.Generic.HashSet[string]'
    foreach ($c in $cands) {
        if ((Is-UnderUserdata $c.ParentPath) -or (Is-UnderUserdata $c.FullPath)) { [void]$udIds.Add($c.FileId) }
    }

    # ---------- 6. Rekonstrukcja operacji ----------
    Write-Host '[4/4] Rekonstruuję operacje (usunięcia / przeniesienia / zmiany nazw)...' -ForegroundColor Cyan

    function New-Event {
        param($Time, $USN, $IsDir, $Action, $From, $To, $Detail)
        [pscustomobject]@{
            Czas      = (Format-When $Time)
            CzasSurowy = $Time
            USN       = [int64]$USN
            Typ       = $(if ($IsDir) { 'FOLDER' } else { 'plik' })
            Operacja  = $Action
            Skad      = $From
            Dokad     = $To
            Szczegoly = $Detail
        }
    }

    $byId = @{}
    foreach ($c in $cands) {
        if (-not $udIds.Contains($c.FileId)) { continue }
        if (-not $byId.ContainsKey($c.FileId)) { $byId[$c.FileId] = New-Object System.Collections.Generic.List[object] }
        $byId[$c.FileId].Add($c)
    }

    $events = New-Object System.Collections.Generic.List[object]

    foreach ($fid in $byId.Keys) {
        $recs = @($byId[$fid] | Sort-Object USN)
        $pendingOld = $null
        $deleteEmitted = $false

        foreach ($r in $recs) {
            if ($r.IsRenOld) { $pendingOld = $r; continue }

            if ($r.IsRenNew) {
                if ($pendingOld) {
                    $oldPath       = $pendingOld.FullPath
                    $newParentPath = Resolve-Dir $r.ParentId
                    $newPath       = if ($newParentPath -and $newParentPath -ne 'KOSZ') { Join-Path $newParentPath $r.Name } else { $null }
                    $toRecycle     = $RecycleIds.Contains($r.ParentId)
                    $fromRecycle   = $RecycleIds.Contains($pendingOld.ParentId)
                    $oldUnder      = Is-UnderUserdata $oldPath
                    $newUnder      = Is-UnderUserdata $newPath

                    if ($toRecycle -and $oldUnder) {
                        $events.Add((New-Event $pendingOld.TimeText $pendingOld.USN $pendingOld.IsDir 'USUNIĘTO (do Kosza)' $oldPath 'Kosz' ''))
                    }
                    elseif ($fromRecycle -and $newUnder) {
                        $events.Add((New-Event $r.TimeText $r.USN $r.IsDir 'PRZYWRÓCONO z Kosza' 'Kosz' $newPath ''))
                    }
                    elseif ($oldUnder -and $newUnder) {
                        if ($pendingOld.ParentId -eq $r.ParentId) {
                            $events.Add((New-Event $pendingOld.TimeText $pendingOld.USN $pendingOld.IsDir 'ZMIENIONO NAZWĘ' $oldPath $newPath ('nowa nazwa: ' + $r.Name)))
                        } else {
                            $events.Add((New-Event $pendingOld.TimeText $pendingOld.USN $pendingOld.IsDir 'PRZENIESIONO (w obrębie userdata)' $oldPath $newPath ''))
                        }
                    }
                    elseif ($oldUnder -and -not $newUnder) {
                        $dst = if ($newPath) { $newPath } else { ('inna lokalizacja / nowa nazwa: ' + $r.Name) }
                        $events.Add((New-Event $pendingOld.TimeText $pendingOld.USN $pendingOld.IsDir 'PRZENIESIONO POZA userdata' $oldPath $dst ''))
                    }
                    elseif (-not $oldUnder -and $newUnder) {
                        $events.Add((New-Event $r.TimeText $r.USN $r.IsDir 'PRZENIESIONO DO userdata' ('poprzednia nazwa: ' + $pendingOld.Name) $newPath ''))
                    }
                    $pendingOld = $null
                }
                continue
            }

            if ($r.IsDelete) {
                if ($deleteEmitted) { continue }
                if (Is-UnderUserdata $r.FullPath) {
                    $deleteEmitted = $true
                    $events.Add((New-Event $r.TimeText $r.USN $r.IsDir 'USUNIĘTO TRWALE' $r.FullPath $null 'usunięcie z pominięciem Kosza (np. Shift+Del) lub opróżnienie Kosza'))
                }
            }
        }

        if ($pendingOld -and (Is-UnderUserdata $pendingOld.FullPath)) {
            $events.Add((New-Event $pendingOld.TimeText $pendingOld.USN $pendingOld.IsDir 'ZMIENIONO NAZWĘ / PRZENIESIONO' $pendingOld.FullPath '(nieznane)' 'druga część operacji poza zakresem dziennika USN'))
        }
    }

    # zwiń zagnieżdżone trwałe usunięcia (folder + jego zawartość) do samego folderu nadrzędnego
    $permDel = @($events | Where-Object { $_.Operacja -eq 'USUNIĘTO TRWALE' })
    $keep = New-Object System.Collections.Generic.List[object]
    foreach ($e in $events) {
        if ($e.Operacja -ne 'USUNIĘTO TRWALE') { $keep.Add($e); continue }
        $covered = $false
        foreach ($p in $permDel) {
            if ($p -eq $e) { continue }
            if ($p.Typ -eq 'FOLDER' -and $e.Skad -and $p.Skad -and
                $e.Skad.StartsWith($p.Skad + '\', [System.StringComparison]::OrdinalIgnoreCase)) {
                $covered = $true; break
            }
        }
        if (-not $covered) { $keep.Add($e) }
    }
    $events = $keep

    # ---------- Filtr szumu (wspólny dla folderów i plików) ----------
    # Zdarzenia, które nie są działaniem użytkownika, tylko normalną pracą Steama:
    #   (a) pliki tymczasowe / pośrednie
    $tempRx  = New-Object System.Text.RegularExpressions.Regex('(?i)(\.tmp$|\.stmp$|~[0-9a-f]{3,}\.tmp$|\.async\d+\.tmp$|\.partial$|\.crdownload$|\.opdownload$|\.vdf~|\.crc$|\.ncf$|\.tmp\.|\.new$|\.bak$)')
    #   (b) podkatalogi userdata zarządzane automatycznie przez Steam:
    #       gamerecordings\ (nagrywanie gry), *cache\ (avatarcache, librarycache, shadercache...),
    #       logs\ oraz pliki *.log
    $noiseRx = New-Object System.Text.RegularExpressions.Regex('(?i)(\\gamerecordings(\\|$)|\\[^\\]*cache(\\|$)|\\logs?(\\|$)|\.log$|\.log\.\d+$)')

    function Test-Noise {
        param($Event)
        foreach ($p in @([string]$Event.Skad, [string]$Event.Dokad)) {
            if ($p -and ($tempRx.IsMatch($p) -or $noiseRx.IsMatch($p))) { return $true }
        }
        return $false
    }

    $allEvents = @($events | Sort-Object USN -Descending)

    $folderEventsAll   = @($allEvents | Where-Object { $_.Typ -eq 'FOLDER' })
    $folderEvents      = @($folderEventsAll | Where-Object { -not (Test-Noise $_) })
    $skippedFolderAuto = $folderEventsAll.Count - $folderEvents.Count

    # ---------- 7. Zapis wyniku (jeden plik tekstowy) ----------
    $today = (Get-Date).ToString('yyyy-MM-dd')

    $allFileEvents = @($allEvents | Where-Object { $_.Typ -eq 'plik' })
    $fileEvents    = @($allFileEvents | Where-Object { -not (Test-Noise $_) })
    $skippedTemp   = $allFileEvents.Count - $fileEvents.Count

    # zakres czasu pokryty przez dziennik USN
    $times = @($allEvents | ForEach-Object { try { [datetime]::Parse($_.Czas, [System.Globalization.CultureInfo]::InvariantCulture) } catch {} })
    $zakres = if ($times.Count -gt 0) {
        '{0}  ...  {1}' -f ($times | Measure-Object -Minimum).Minimum.ToString('yyyy-MM-dd HH:mm:ss'),
                            ($times | Measure-Object -Maximum).Maximum.ToString('yyyy-MM-dd HH:mm:ss')
    } else { '(brak zdarzeń w userdata)' }

    $logLines.Add('')
    $logLines.Add('==================================================================')
    $logLines.Add('  RAPORT: zmiany folderów w Steam\userdata (dziennik USN NTFS)')
    $logLines.Add('==================================================================')
    $logLines.Add(('  Wygenerowano : {0}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')))
    $logLines.Add(('  Komputer     : {0}' -f $env:COMPUTERNAME))
    $logLines.Add(('  Folder       : {0}' -f $AnchorPath))
    $logLines.Add(('  Zakres zmian userdata w dzienniku: {0}' -f $zakres))
    $logLines.Add('')
    $logLines.Add('  Znaczenie operacji:')
    $logLines.Add('    USUNIĘTO (do Kosza)  - folder przeniesiony do Kosza (zwykłe Delete)')
    $logLines.Add('    USUNIĘTO TRWALE      - usunięty z pominięciem Kosza (Shift+Del) lub opróżniono Kosz')
    $logLines.Add('    ZMIENIONO NAZWĘ      - zmiana nazwy w tym samym miejscu')
    $logLines.Add('    PRZENIESIONO ...     - zmiana lokalizacji folderu')
    $logLines.Add('    PRZYWRÓCONO z Kosza  - folder odzyskany z Kosza')
    $logLines.Add('')
    $logLines.Add('==================================================================')
    $logLines.Add('  OPERACJE NA FOLDERACH W userdata  (od najnowszej)')
    $logLines.Add('==================================================================')
    if ($skippedFolderAuto -gt 0) {
        $logLines.Add(('  (pominięto {0} operacji na automatycznych podkatalogach Steama:' -f $skippedFolderAuto))
        $logLines.Add('   gamerecordings\, *cache\, logs\ - nie są to działania użytkownika)')
        $logLines.Add('')
    }
    if ($folderEvents.Count -eq 0) {
        $logLines.Add('  (brak)  -  w dostępnym oknie dziennika USN nie wykryto żadnych')
        $logLines.Add('           usunięć, przeniesień ani zmian nazw folderów w userdata.')
        $logLines.Add('           Uwaga: starsze zdarzenia mogły zostać nadpisane w dzienniku.')
    } else {
        foreach ($e in $folderEvents) {
            $mark = if ($e.Czas.StartsWith($today)) { '   <-- DZIŚ' } else { '' }
            $logLines.Add(('  {0}   {1}{2}' -f $e.Czas, $e.Operacja, $mark))
            $logLines.Add(('      co     : FOLDER'))
            $logLines.Add(('      skąd   : {0}' -f $e.Skad))
            if ($e.Dokad)     { $logLines.Add(('      dokąd  : {0}' -f $e.Dokad)) }
            if ($e.Szczegoly) { $logLines.Add(('      uwagi  : {0}' -f $e.Szczegoly)) }
            $logLines.Add('')
        }
    }

    $logLines.Add('==================================================================')
    $logLines.Add(('  OPERACJE NA POJEDYNCZYCH PLIKACH W userdata: {0}' -f $fileEvents.Count))
    if ($skippedTemp -gt 0) {
        $logLines.Add(('  (pominięto {0} zdarzeń - to normalna praca Steama, nie działania użytkownika:' -f $skippedTemp))
        $logLines.Add('     - pliki tymczasowe/pośrednie: *.tmp, *.vdf~, *.async*.tmp, *.crdownload itp.')
        $logLines.Add('     - automatyczne podkatalogi Steama: gamerecordings\, *cache\, logs\, *.log)')
    }
    $logLines.Add('==================================================================')
    if ($fileEvents.Count -gt 0) {
        foreach ($e in $fileEvents) {
            $line = '  {0}   {1,-32}   {2}' -f $e.Czas, $e.Operacja, $e.Skad
            if ($e.Dokad) { $line += '  ->  ' + $e.Dokad }
            $logLines.Add($line)
        }
    } else {
        $logLines.Add('  (brak istotnych zdarzeń plikowych)')
    }

    Write-Log ("Wykryto operacji na folderach: {0} (pominięto automatycznych podkatalogów Steama: {1})" -f $folderEvents.Count, $skippedFolderAuto)
    Write-Log ("Wykryto istotnych operacji na plikach: {0} (pominięto zdarzeń automatycznych Steama: {1})" -f $fileEvents.Count, $skippedTemp)
    Write-Log ("Plik wyniku: {0}" -f $LogPath)
    Write-Log "Koniec analizy."

    Set-Content -LiteralPath $LogPath -Value $logLines -Encoding UTF8
    $LogWritten = $true

    function HtmlEnc { param($Text) [System.Net.WebUtility]::HtmlEncode([string]$Text) }

    function Get-OpClass {
        param([string]$Op)
        if ($Op.StartsWith('USUNIĘTO TRWALE')) { return 'del' }
        if ($Op.StartsWith('USUNIĘTO'))        { return 'bin' }
        if ($Op.StartsWith('PRZYWRÓCONO'))     { return 'restore' }
        if ($Op.StartsWith('ZMIENIONO'))       { return 'rename' }
        return 'move'
    }

    function New-HtmlReport {
        $css = @'
:root{--bg:#f6f7f9;--card:#fff;--text:#1b1f24;--muted:#5f6b7a;--line:#e3e6ea;--mono:#f0f2f5;
--ok:#1a7f37;--ok-bg:#e6f4ea;--bad:#c62828;--bad-bg:#fdecea;--warn:#b35c00;--warn-bg:#fff2e0;
--blue:#1f5fbf;--blue-bg:#e7effb;--violet:#6b3fb5;--violet-bg:#f1eafb}
@media (prefers-color-scheme:dark){:root{--bg:#111418;--card:#1a1e24;--text:#e6e9ed;--muted:#98a2ae;--line:#2b313a;--mono:#232830;
--ok:#56d364;--ok-bg:#15301d;--bad:#ff7b72;--bad-bg:#3a1a1a;--warn:#ffa657;--warn-bg:#3a2712;
--blue:#79b8ff;--blue-bg:#16263d;--violet:#c4a5ff;--violet-bg:#2a1f3f}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);font:15px/1.5 "Segoe UI",system-ui,sans-serif}
main{max-width:1000px;margin:0 auto;padding:28px 16px 48px}
h1{font-size:24px;margin:0 0 4px}
h2{font-size:17px;margin:32px 0 12px}
.sub{color:var(--muted);margin:0 0 20px}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:16px 18px}
.meta{display:grid;grid-template-columns:auto 1fr;gap:6px 16px}
.meta dt{color:var(--muted)} .meta dd{margin:0;word-break:break-all}
.verdict{margin:20px 0;padding:16px 18px;border-radius:10px;font-weight:600;font-size:16px}
.verdict small{display:block;font-weight:400;font-size:14px;margin-top:4px;opacity:.9}
.verdict.ok{background:var(--ok-bg);color:var(--ok)} .verdict.bad{background:var(--bad-bg);color:var(--bad)}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px}
.stat .n{font-size:28px;font-weight:700;line-height:1.1} .stat .l{color:var(--muted);font-size:13px}
.ev{margin-bottom:10px}
.ev-head{display:flex;flex-wrap:wrap;align-items:center;gap:8px 10px;margin-bottom:8px}
.time{font-variant-numeric:tabular-nums;font-weight:600}
.badge{display:inline-block;padding:2px 9px;border-radius:999px;font-size:12px;font-weight:700;letter-spacing:.02em;white-space:nowrap}
.b-del{background:var(--bad-bg);color:var(--bad)} .b-bin{background:var(--warn-bg);color:var(--warn)}
.b-move{background:var(--blue-bg);color:var(--blue)} .b-rename{background:var(--violet-bg);color:var(--violet)}
.b-restore{background:var(--ok-bg);color:var(--ok)}
.today{background:var(--bad);color:#fff}
.path{font-family:Consolas,"Cascadia Mono",monospace;font-size:13px;background:var(--mono);padding:2px 6px;border-radius:4px;word-break:break-all}
.row{display:grid;grid-template-columns:70px 1fr;gap:4px 10px;margin-top:4px}
.row .k{color:var(--muted);font-size:13px;padding-top:2px}
table{width:100%;border-collapse:collapse}
th,td{text-align:left;padding:8px 10px;border-bottom:1px solid var(--line);vertical-align:top}
th{color:var(--muted);font-weight:600;font-size:13px}
td.t{white-space:nowrap;font-variant-numeric:tabular-nums}
.empty{color:var(--muted)}
.note{color:var(--muted);font-size:13px;margin-top:8px}
.legend{display:grid;grid-template-columns:auto 1fr;gap:8px 12px;align-items:center}
details{margin-top:24px} summary{cursor:pointer;color:var(--muted)}
pre{background:var(--mono);padding:12px;border-radius:8px;overflow-x:auto;font-size:12px}
@media (max-width:600px){.row{grid-template-columns:1fr}.row .k{padding:0}td.t{white-space:normal}}
'@
        $sb = New-Object System.Text.StringBuilder
        $gen = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
        [void]$sb.Append('<!DOCTYPE html><html lang="pl"><head><meta charset="utf-8">')
        [void]$sb.Append('<meta name="viewport" content="width=device-width,initial-scale=1">')
        [void]$sb.Append(('<title>Raport userdata - {0}</title><style>{1}</style></head><body><main>' -f (HtmlEnc $env:COMPUTERNAME), $css))

        [void]$sb.Append('<h1>Raport: Steam userdata</h1>')
        [void]$sb.Append('<p class="sub">Usunięcia, przeniesienia i zmiany nazw odczytane z dziennika zmian NTFS (USN Journal)</p>')
        [void]$sb.Append('<div class="card"><dl class="meta">')
        [void]$sb.Append(('<dt>Komputer</dt><dd>{0}</dd>' -f (HtmlEnc $env:COMPUTERNAME)))
        [void]$sb.Append(('<dt>Folder</dt><dd><span class="path">{0}</span></dd>' -f (HtmlEnc $AnchorPath)))
        [void]$sb.Append(('<dt>Zakres dziennika</dt><dd>{0}</dd>' -f (HtmlEnc $zakres)))
        [void]$sb.Append(('<dt>Wygenerowano</dt><dd>{0}</dd>' -f (HtmlEnc $gen)))
        [void]$sb.Append('</dl></div>')

        $fileDeletes = @($fileEvents | Where-Object { $_.Operacja.StartsWith('USUNIĘTO') }).Count
        if ($folderEvents.Count -gt 0) {
            [void]$sb.Append(('<div class="verdict bad">Wykryto operacje na folderach w userdata: {0}<small>Szczegóły poniżej - sprawdź daty i ścieżki.</small></div>' -f $folderEvents.Count))
        } elseif ($fileEvents.Count -gt 0) {
            [void]$sb.Append(('<div class="verdict ok">Brak operacji na folderach w userdata<small>Wykryto tylko operacje na pojedynczych plikach: {0} (w tym usunięć: {1}).</small></div>' -f $fileEvents.Count, $fileDeletes))
        } else {
            [void]$sb.Append('<div class="verdict ok">Nie wykryto żadnych usunięć, przeniesień ani zmian nazw<small>W okresie objętym dziennikiem USN.</small></div>')
        }

        [void]$sb.Append('<div class="stats">')
        [void]$sb.Append(('<div class="card stat"><div class="n">{0}</div><div class="l">operacji na folderach</div></div>' -f $folderEvents.Count))
        [void]$sb.Append(('<div class="card stat"><div class="n">{0}</div><div class="l">operacji na plikach</div></div>' -f $fileEvents.Count))
        [void]$sb.Append(('<div class="card stat"><div class="n">{0}</div><div class="l">pominiętych zdarzeń automatycznych Steama</div></div>' -f ($skippedTemp + $skippedFolderAuto)))
        [void]$sb.Append('</div>')

        [void]$sb.Append('<h2>Operacje na folderach (od najnowszej)</h2>')
        if ($folderEvents.Count -eq 0) {
            [void]$sb.Append('<div class="card empty">Brak - w dostępnym oknie dziennika USN nie wykryto usunięć, przeniesień ani zmian nazw folderów.</div>')
        } else {
            foreach ($e in $folderEvents) {
                [void]$sb.Append('<div class="card ev"><div class="ev-head">')
                [void]$sb.Append(('<span class="time">{0}</span><span class="badge b-{1}">{2}</span>' -f (HtmlEnc $e.Czas), (Get-OpClass $e.Operacja), (HtmlEnc $e.Operacja)))
                if ($e.Czas.StartsWith($today)) { [void]$sb.Append('<span class="badge today">DZIŚ</span>') }
                [void]$sb.Append('</div>')
                [void]$sb.Append(('<div class="row"><span class="k">skąd</span><span><span class="path">{0}</span></span></div>' -f (HtmlEnc $e.Skad)))
                if ($e.Dokad)     { [void]$sb.Append(('<div class="row"><span class="k">dokąd</span><span><span class="path">{0}</span></span></div>' -f (HtmlEnc $e.Dokad))) }
                if ($e.Szczegoly) { [void]$sb.Append(('<div class="row"><span class="k">uwagi</span><span>{0}</span></div>' -f (HtmlEnc $e.Szczegoly))) }
                [void]$sb.Append('</div>')
            }
        }
        if ($skippedFolderAuto -gt 0) {
            [void]$sb.Append(('<p class="note">Pominięto {0} operacji na automatycznych podkatalogach Steama (gamerecordings\, *cache\, logs\).</p>' -f $skippedFolderAuto))
        }

        [void]$sb.Append('<h2>Operacje na pojedynczych plikach</h2>')
        if ($fileEvents.Count -eq 0) {
            [void]$sb.Append('<div class="card empty">Brak istotnych zdarzeń plikowych.</div>')
        } else {
            [void]$sb.Append('<div class="card" style="padding:4px 8px;overflow-x:auto"><table><thead><tr><th>Czas</th><th>Operacja</th><th>Ścieżka</th></tr></thead><tbody>')
            foreach ($e in $fileEvents) {
                $mark = if ($e.Czas.StartsWith($today)) { ' <span class="badge today">DZIŚ</span>' } else { '' }
                $pathHtml = '<span class="path">{0}</span>' -f (HtmlEnc $e.Skad)
                if ($e.Dokad) { $pathHtml += ' &rarr; <span class="path">{0}</span>' -f (HtmlEnc $e.Dokad) }
                [void]$sb.Append(('<tr><td class="t">{0}{1}</td><td><span class="badge b-{2}">{3}</span></td><td>{4}</td></tr>' -f
                    (HtmlEnc $e.Czas), $mark, (Get-OpClass $e.Operacja), (HtmlEnc $e.Operacja), $pathHtml))
            }
            [void]$sb.Append('</tbody></table></div>')
        }
        if ($skippedTemp -gt 0) {
            [void]$sb.Append(('<p class="note">Pominięto {0} zdarzeń - normalna praca Steama (pliki *.tmp, *.vdf~, *.crdownload, podkatalogi *cache\, logs\, gamerecordings\).</p>' -f $skippedTemp))
        }

        [void]$sb.Append('<h2>Znaczenie operacji</h2><div class="card legend">')
        [void]$sb.Append('<span class="badge b-bin">USUNIĘTO (do Kosza)</span><span>przeniesione do Kosza (zwykłe Delete)</span>')
        [void]$sb.Append('<span class="badge b-del">USUNIĘTO TRWALE</span><span>usunięte z pominięciem Kosza (Shift+Del) lub opróżniono Kosz</span>')
        [void]$sb.Append('<span class="badge b-rename">ZMIENIONO NAZWĘ</span><span>zmiana nazwy w tym samym miejscu</span>')
        [void]$sb.Append('<span class="badge b-move">PRZENIESIONO</span><span>zmiana lokalizacji (w obrębie, poza lub do userdata)</span>')
        [void]$sb.Append('<span class="badge b-restore">PRZYWRÓCONO z Kosza</span><span>odzyskane z Kosza</span>')
        [void]$sb.Append('</div>')
        [void]$sb.Append('<p class="note">Dziennik USN ma ograniczony rozmiar - zdarzenia starsze niż podany zakres mogły zostać już nadpisane.</p>')

        $tech = @($logLines | Where-Object { $_.StartsWith('[') }) -join "`n"
        [void]$sb.Append(('<details><summary>Log techniczny</summary><pre>{0}</pre></details>' -f (HtmlEnc $tech)))
        [void]$sb.Append('</main></body></html>')
        return $sb.ToString()
    }

    $copied = $false
    try { Set-Clipboard -Value ($logLines -join "`r`n"); $copied = $true } catch {}

    # ---------- 8. Raport HTML (otwierany w przeglądarce) ----------
    $HtmlPath = [System.IO.Path]::ChangeExtension($LogPath, '.html')
    try {
        $html = New-HtmlReport
        [System.IO.File]::WriteAllText($HtmlPath, $html, (New-Object System.Text.UTF8Encoding $true))
    } catch {
        Write-Host ("Nie udało się zapisać raportu HTML: {0}" -f $_.Exception.Message) -ForegroundColor Yellow
        $HtmlPath = $null
    }

    Write-Host ''
    Write-Host '=====================================================' -ForegroundColor Green
    Write-Host ' GOTOWE' -ForegroundColor Green
    Write-Host '=====================================================' -ForegroundColor Green
    Write-Host ''

    if ($folderEvents.Count -eq 0) {
        Write-Host 'Nie znaleziono operacji na folderach userdata w oknie dziennika USN.' -ForegroundColor Yellow
    } else {
        Write-Host ("Znaleziono {0} operacji na folderach userdata:" -f $folderEvents.Count) -ForegroundColor Green
        Write-Host ''
        foreach ($e in $folderEvents) {
            Write-Host ('  {0}   {1}' -f $e.Czas, $e.Operacja) -ForegroundColor White
            Write-Host ('      {0}' -f $e.Skad) -ForegroundColor Gray
            if ($e.Dokad) { Write-Host ('      -> {0}' -f $e.Dokad) -ForegroundColor Gray }
        }
    }
    Write-Host ''
    Write-Host ("Wynik zapisany w: {0}" -f $LogPath)
    if ($HtmlPath) { Write-Host ("Raport HTML     : {0}" -f $HtmlPath) }
    if ($copied) {
        Write-Host 'Raport skopiowano do schowka - wystarczy go wkleić (Ctrl+V) osobie, która o niego prosi.' -ForegroundColor Cyan
    }
    Write-Host ''

    # explorer.exe otwiera plik w domyślnej przeglądarce jako zwykły użytkownik (nie jako Administrator)
    if ($HtmlPath) {
        try { Start-Process explorer.exe -ArgumentList ('"{0}"' -f $HtmlPath) } catch {}
    } else {
        try { Start-Process notepad.exe -ArgumentList ('"{0}"' -f $LogPath) } catch {}
    }
}
catch {
    $logLines.Add('')
    $logLines.Add('[BŁĄD] Analiza przerwana:')
    $logLines.Add(('  {0}' -f $_.Exception.Message))
    if ($_.ScriptStackTrace) { $logLines.Add(('  {0}' -f ($_.ScriptStackTrace -replace "`r?`n", ' | '))) }
    Write-Host ''
    Write-Host '[BŁĄD] Analiza przerwana:' -ForegroundColor Red
    Write-Host $_.Exception.Message -ForegroundColor Red
}
finally {
    if ($LogPath -and -not $LogWritten) {
        try { Set-Content -LiteralPath $LogPath -Value $logLines -Encoding UTF8 } catch {}
    }
}

}
