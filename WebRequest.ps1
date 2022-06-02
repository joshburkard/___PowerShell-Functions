#region set Certificate Policy
    Add-Type @"
    using System.Net;
    using System.Security.Cryptography.X509Certificates;
    public class TrustAllCertsPolicy : ICertificatePolicy {
        public bool CheckValidationResult( ServicePoint srvPoint, X509Certificate certificate, WebRequest request, int certificateProblem ) {
            return true;
        }
    }
"@
    [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
#endregion set Certificate Policy

#region set proxy
    $proxy = new-object System.Net.WebProxy
    [system.net.webrequest]::defaultwebproxy = $proxy
#endregion set proxy

#region test TLS connection protocol
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
#endregion test TLS connection protocol

#region set proxy for Internet Explorer
    $proxy = 'http://fqdn.domain.net:8080'
    $bypassList = '*.domain.net;localhost;*.domain-b.net;<local>'
    $reg = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
    $proxyString = ""
    for ($i = 0;$i -lt (([System.Text.Encoding]::Unicode.GetBytes($proxy)).length); $i++) {
        if ($i % 2 -eq 0) {
            $byte = (([System.Text.Encoding]::Unicode.GetBytes($proxy))[$i])
            $convertedByte=%{[System.Convert]::ToString($byte,16)}
            $proxyString = $proxystring + $convertedByte  + ","
        }
    }
    $bypassString = ""
    for ($i = 0;$i -lt (([System.Text.Encoding]::Unicode.GetBytes($bypassList)).length); $i++) {
        if ($i % 2 -eq 0) {
            $byte = (([System.Text.Encoding]::Unicode.GetBytes($bypassList))[$i])
            $convertedByte=%{[System.Convert]::ToString($byte,16)}
            $bypassString = $bypassString + $convertedByte  + ","
        }
    }
    $regString="46,00,00,00,00,00,00,00,0b,00,00,00,"+(%{[System.Convert]::ToString($proxy.length,16)})+",00,00,00," + $proxystring + (%{[System.Convert]::ToString($bypassList.length,16)}) + ",00,00,00," + $bypassString +  "00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00"
    $regstringAsArray = ("0x"+$regString.replace(",",",0x")).Split(",")
    $reg = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
    Set-ItemProperty -Path $reg -Name ProxyServer -Value $proxy
    Set-ItemProperty -Path $reg -Name ProxyEnable -Value 1
    Set-ItemProperty -Path $reg -Name ProxyOverride -Value $bypassList
    $reg = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Connections"
    Set-ItemProperty -Path $reg -Name DefaultConnectionSettings -Type Binary -Value $regstringAsArray
    Set-ItemProperty -Path $reg -Name SavedLegacySettings -Type Binary -Value $regstringAsArray
#endregion set proxy for Internet Explorer
