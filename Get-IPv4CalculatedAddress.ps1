Function Get-IPv4CalculatedAddress {
    Param (
        [string]$IPAddress = '192.168.1.0'
        ,
        [int]$Add = -1
    )
    $StrNetworkAddress = ($IPAddress.split("/"))[0]
    $NetworkIP = ([System.Net.IPAddress]$StrNetworkAddress).GetAddressBytes()
    [Array]::Reverse($NetworkIP)
    $NetworkIP = ([System.Net.IPAddress]($NetworkIP -join ".")).Address
    $StartIP = $NetworkIP + $Add
    #Convert To Double
    If (($StartIP.Gettype()).Name -ine "double")
    {
    $StartIP = [Convert]::ToDouble($StartIP)
    }
    $StartIP = [System.Net.IPAddress]$StartIP
    Return $StartIP
}