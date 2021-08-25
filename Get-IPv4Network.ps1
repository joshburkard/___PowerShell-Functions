Function Get-IPv4Network {
    Param (
        $ip = '192.168.1.1/24'
        ,
        $mask
        ,
        $cidr
    )
    if ( $ip -match '/' ) {
        $ipParts = $ip -split '/'
        $ip = $ipParts[0]
        $cidr = $ipParts[1]
    }
    if ( ( [string]::IsNullOrEmpty( $mask ) ) -and  ( [string]::IsNullOrEmpty( $cidr ) ) ) {
        $cidr = 24
    }
    $ipAddr = [Net.IPAddress]::Parse($ip)
    if ( $cidr ) {
        $maskaddr = [Net.IPAddress]::Parse( (Convert-INT64-toIP -int ([convert]::ToInt64(("1"*$cidr+"0"*(32-$cidr)),2))))
        $mask = $maskaddr.IPAddressToString
    }
    else {
        $maskaddr = [Net.IPAddress]::Parse($mask)
        $cidr = get-IPv4CIDR -subnetmask $mask

    }
    $NetworkAddr   = new-object net.ipaddress ($maskaddr.address -band $ipaddr.address)
    $BroadcastAddr = new-object net.ipaddress (([system.net.ipaddress]::parse("255.255.255.255").address -bxor $maskaddr.address -bor $networkaddr.address ) )
    $StartAddr     = get-IPV4CalculatedAddress -IPAddress $networkaddr.IPAddressToString -Add 1
    $EndAddr       = get-IPV4CalculatedAddress -IPAddress $broadcastaddr.IPAddressToString -Add -1

    New-Object -TypeName PSObject -Property @{
        Network = $networkaddr
        BroadCast = $broadcastaddr
        Start     = $startaddr
        End       = $EndAddr
        Mask      = $mask
        CIDR      = $cidr
    } | Select-Object Network, Start, End, BroadCast, Mask, CIDR
}