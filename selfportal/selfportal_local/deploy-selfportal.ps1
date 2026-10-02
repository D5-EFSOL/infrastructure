# ============================================================
# SelfPortal — развёртывание на IIS
# ============================================================
# Создаёт каталог C:\inetpub\wwwroot\SelfPortal, копирует туда
# password.aspx и web.config (лежат рядом со скриптом), создаёт
# пул приложений SelfPortal (учётка NetworkService) и приложение
# IIS, указывающее на этот каталог.
#
# Запуск: от имени администратора (скрипт сам перезапустит себя
# с повышением прав, если запущен без них).
# ============================================================

# --- Параметры (при необходимости поменяйте здесь) ------------
$SiteName      = "Default Web Site"   # сайт IIS, к которому привязываем приложение
$AppName       = "SelfPortal"         # имя приложения (путь в URL)
$AppPoolName   = "SelfPortal"         # имя пула приложений
$AppPoolUser   = "NetworkService"     # учётная запись пула
$TargetDir     = "C:\inetpub\wwwroot\SelfPortal"
$ClientName    = "client_name"        # имя клиента для итогового URL
$Port          = "port"              # порт (замените на реальный)
# --------------------------------------------------------------

$ErrorActionPreference = "Stop"

# --- Самоповышение прав до администратора ---------------------
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "Требуются права администратора. Перезапуск с повышением..." -ForegroundColor Yellow
    Start-Process -FilePath 'powershell.exe' `
        -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" `
        -Verb RunAs
    exit
}

function Step($msg) {
    Write-Host ("[{0}] {1}" -f (Get-Date -Format "HH:mm:ss"), $msg) -ForegroundColor Cyan
}

Step "Начало развёртывания SelfPortal"

# --- 1. Импорт модуля IIS -------------------------------------
Step "Импорт модуля WebAdministration..."
Import-Module WebAdministration -ErrorAction Stop

# --- 1.1 Регистрация источника Event Log ----------------------
# Источник "RDWebPassChange" должен существовать, иначе
# EventLog.WriteEntry() в приложении не сможет писать события
# (пул работает под NetworkService без прав на создание источника).
Step "Регистрация источника Event Log 'RDWebPassChange'..."
if (-not [System.Diagnostics.EventLog]::SourceExists("RDWebPassChange")) {
    [System.Diagnostics.EventLog]::CreateEventSource("RDWebPassChange", "Application")
    Step "Источник 'RDWebPassChange' создан в журнале 'Application'."
} else {
    Step "Источник 'RDWebPassChange' уже существует."
}

# --- 2. Создание каталога и копирование файлов ---------------
Step "Создание каталога $TargetDir ..."
if (-not (Test-Path $TargetDir)) {
    New-Item -ItemType Directory -Path $TargetDir -Force | Out-Null
}

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

foreach ($f in @("password.aspx", "web.config")) {
    $src = Join-Path $scriptDir $f
    if (-not (Test-Path $src)) {
        Write-Host "ОШИБКА: не найден файл $src" -ForegroundColor Red
        Read-Host "Нажмите любую клавишу для выхода"
        exit 1
    }
    Step "Копирование $f ..."
    Copy-Item -Path $src -Destination (Join-Path $TargetDir $f) -Force
}

# --- 3. Создание пула приложений -----------------------------
Step "Создание пула приложений $AppPoolName ..."
# ВАЖНО: НЕ используем Test-Path "IIS:\AppPools\..." — у IIS-провайдера
# Test-Path возвращает $true даже для несуществующего пула, из-за чего
# скрипт ошибочно считал пул существующим и падал на Set-ItemProperty.
$existingPool = Get-Item "IIS:\AppPools\$AppPoolName" -ErrorAction SilentlyContinue
if ($null -ne $existingPool) {
    Write-Host "Пул $AppPoolName уже существует — пропускаем создание." -ForegroundColor Yellow
} else {
    New-WebAppPool -Name $AppPoolName -Force | Out-Null
}

# Учётная запись пула — NetworkService
Set-ItemProperty -Path "IIS:\AppPools\$AppPoolName" -Name processModel.identityType -Value 2  # 2 = NetworkService
Set-ItemProperty -Path "IIS:\AppPools\$AppPoolName" -Name managedRuntimeVersion -Value "v4.0"
Set-ItemProperty -Path "IIS:\AppPools\$AppPoolName" -Name managedPipelineMode -Value "Integrated"

Step "Пул $AppPoolName настроен (NetworkService, .NET 4.0, Integrated)."

# --- 4. Создание приложения IIS ------------------------------
Step "Создание приложения /$AppName на сайте $SiteName ..."
# ВАЖНО: НЕ используем Test-Path "IIS:\Sites\..." — та же особенность
# IIS-провайдера: Test-Path возвращает $true для несуществующего пути.
$existingApp = Get-WebApplication -Name $AppName -Site $SiteName -ErrorAction SilentlyContinue
if ($null -ne $existingApp) {
    Write-Host "Приложение /$AppName уже существует — удаляем и пересоздаём." -ForegroundColor Yellow
    Remove-WebApplication -Name $AppName -Site $SiteName
}

New-WebApplication -Name $AppName -Site $SiteName -PhysicalPath $TargetDir -ApplicationPool $AppPoolName -Force | Out-Null

# --- 5. Перезапуск пула --------------------------------------
Step "Перезапуск пула $AppPoolName ..."
Restart-WebAppPool -Name $AppPoolName

# --- 6. Проверка ---------------------------------------------
Step "Проверка результата..."
$pool = Get-Item "IIS:\AppPools\$AppPoolName"
$app  = Get-WebApplication -Name $AppName -Site $SiteName

Write-Host ""
Write-Host "Пул приложений : $($pool.Name)  (state: $($pool.state))" -ForegroundColor Green
Write-Host "Приложение     : /$AppName -> $($app.physicalPath)" -ForegroundColor Green
Write-Host "Файлы в каталоге:" -ForegroundColor Green
Get-ChildItem $TargetDir | ForEach-Object { Write-Host ("  - {0} ({1} байт)" -f $_.Name, $_.Length) }

Write-Host ""
Write-Host "============================================================" -ForegroundColor Green
Write-Host "Портал создан по адресу:" -ForegroundColor Green
Write-Host "  https://$ClientName.esit.info:$Port/SelfPortal" -ForegroundColor White
Write-Host "============================================================" -ForegroundColor Green
Write-Host ""

Read-Host "Нажмите любую клавишу для выхода"
