Import-Module ActiveDirectory

# Список портов для проверки
$ports = @(53, 88, 135, 389, 445, 464, 3268)

Write-Host "=== Шаг 1: Определение структуры леса и поиск контроллеров ===" -ForegroundColor Cyan
try {
    $forest = Get-ADForest
    $forestRoot = $forest.RootDomain
    $forestMode = $forest.ForestMode
    $domains = $forest.Domains
    
    Write-Host "Имя леса Active Directory : " -NoNewline -ForegroundColor White
    Write-Host $forest.Name -ForegroundColor Green
    Write-Host "Корневой домен леса       : " -NoNewline -ForegroundColor White
    Write-Host $forestRoot -ForegroundColor Green
    Write-Host "Режим работы (ForestMode) : " -NoNewline -ForegroundColor White
    Write-Host $forestMode -ForegroundColor Yellow
    Write-Host "Всего доменов в структуре : " -NoNewline -ForegroundColor White
    Write-Host $domains.Count -ForegroundColor Green
    
    Write-Host "`nЛогическая топология доменов и их контроллеры:" -ForegroundColor Cyan
    Write-Host "==================================================" -ForegroundColor Cyan
    
    # Сначала выводим корневой домен
    Write-Host "[*] КОРНЕВОЙ ДОМЕН: $forestRoot" -ForegroundColor Green
    $rootDCs = Get-ADDomainController -Filter * -Server $forestRoot
    foreach ($dc in $rootDCs) {
        $displayIP = $dc.IPAddress
        if ([string]::IsNullOrEmpty($displayIP) -or $displayIP -match ":") {
            try { $dnsLookup = Resolve-DnsName -Name $dc.Hostname -Type A -ErrorAction Stop; $displayIP = $dnsLookup.IPAddress | Select-Object -First 1 } catch { $displayIP = "Не определен" }
        }
        $fqdnString = "{0,-35}" -f $dc.Hostname
        Write-Host "    └── DC (FQDN): " -NoNewline -ForegroundColor Gray
        Write-Host $fqdnString -NoNewline -ForegroundColor Yellow
        Write-Host " IP: " -NoNewline -ForegroundColor Gray
        Write-Host $displayIP -ForegroundColor Green
    }
    
    # Теперь выводим остальные домены (дочерние или другие деревья леса)
    foreach ($domain in $domains) {
        if ($domain -eq $forestRoot) { continue } # Корень уже вывели
        
        # Определяем тип домена (дочерний или дерево)
        if ($domain.EndsWith($forestRoot)) {
            Write-Host "`n[*] ДОЧЕРНИЙ ДОМЕН: $domain" -ForegroundColor Cyan
        } else {
            Write-Host "`n[*] ВЫДЕЛЕННОЕ ДЕРЕВО ДОМЕНОВ (Tree): $domain" -ForegroundColor Magenta
        }
        
        $otherDCs = Get-ADDomainController -Filter * -Server $domain
        foreach ($dc in $otherDCs) {
            $displayIP = $dc.IPAddress
            if ([string]::IsNullOrEmpty($displayIP) -or $displayIP -match ":") {
                try { $dnsLookup = Resolve-DnsName -Name $dc.Hostname -Type A -ErrorAction Stop; $displayIP = $dnsLookup.IPAddress | Select-Object -First 1 } catch { $displayIP = "Не определен" }
            }
            $fqdnString = "{0,-35}" -f $dc.Hostname
            Write-Host "    └── DC (FQDN): " -NoNewline -ForegroundColor Gray
            Write-Host $fqdnString -NoNewline -ForegroundColor Yellow
            Write-Host " IP: " -NoNewline -ForegroundColor Gray
            Write-Host $displayIP -ForegroundColor Green
        }
    }
    Write-Host "==================================================" -ForegroundColor Cyan
    
    # Собираем общий массив всех DC для Шага 2
    $allDCs = foreach ($domain in $domains) { Get-ADDomainController -Filter * -Server $domain }
    
} catch {
    Write-Host "Ошибка при определении структуры леса AD: $_" -ForegroundColor Red
    return
}

Write-Host "`n=== Шаг 2: Запуск комплексной диагностики (DNS, PTR, Порты) ===" -ForegroundColor Cyan

foreach ($dc in $allDCs) {
    $dcFqdn = $dc.Hostname
    $dcDomain = $dc.Domain
    
    Write-Host "`nПроверяется: $dcFqdn (Домен: $dcDomain)" -ForegroundColor Yellow
    
    # Определение IPv4 для сокетов
    $ipAddress = $dc.IPAddress
    if ($ipAddress -match ":" -or [string]::IsNullOrEmpty($ipAddress)) {
        try {
            $dnsQuery = Resolve-DnsName -Name $dcFqdn -Type A -ErrorAction Stop
            $ipAddress = $dnsQuery.IPAddress | Select-Object -First 1
        } catch {
            $ipAddress = "Не определен"
        }
    }

    if ($ipAddress -and $ipAddress -ne "Не определен" -and $ipAddress -notmatch ":") {
        Write-Host "  [+] DNS (Прямая зона): Успешно -> $ipAddress" -ForegroundColor Green
    } else {
        Write-Host "  [-] DNS (Прямая зона): ОШИБКА! Система возвращает IPv6 или адрес не найден." -ForegroundColor Red
        $ipAddress = "Не определен"
    }

    # 2. Проверка обратной зоны DNS (PTR-запись)
    if ($ipAddress -ne "Не определен") {
        try {
            $dnsQueryPtr = Resolve-DnsName -Name $ipAddress -Type PTR -ErrorAction Stop
            if ($dnsQueryPtr) {
                Write-Host "  [+] DNS (Обратная зона/PTR): Успешно -> $($dnsQueryPtr.NameHost)" -ForegroundColor Green
            }
        } catch {
            Write-Host "  [-] DNS (Обратная зона/PTR): ОШИБКА (Запись PTR отсутствует)!" -ForegroundColor Red
        }
    }

    # 3. Сканирование портов
    foreach ($port in $ports) {
        if ($port -eq 3268 -and $dc.IsGlobalCatalog -eq $false) {
            continue
        }

        if ($ipAddress -ne "Не определен") {
            try {
                $tcpClient = New-Object System.Net.Sockets.TcpClient
                $tcpClient.Client = New-Object System.Net.Sockets.Socket([System.Net.Sockets.AddressFamily]::InterNetwork, [System.Net.Sockets.SocketType]::Stream, [System.Net.Sockets.ProtocolType]::Tcp)
                
                $connect = $tcpClient.BeginConnect($ipAddress, $port, $null, $null)
                $wait = $connect.AsyncWaitHandle.WaitOne(1000, $false)
                
                if ($wait -and $tcpClient.Connected) {
                    Write-Host "    • Порт $port : ОТКРЫТ" -ForegroundColor Green
                } else {
                    Write-Host "    • Порт $port : ЗАКРЫТ или ТАЙМАУТ" -ForegroundColor Red
                }
                $tcpClient.Close()
            } catch {
                Write-Host "    • Порт $port : ОШИБКА подключения" -ForegroundColor DarkRed
            }
        }
    }
}

Write-Host "`n=== Диагностика завершена! ===" -ForegroundColor Cyan
