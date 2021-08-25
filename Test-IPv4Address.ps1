function Test-IPv4Address {
    <#
        .SYNOPSIS

        .EXAMPLE

            Test-IPv4Address '192.168.0.1'
            Test-IPv4Address 'aaaa'
    #>
    param
    (
        [Parameter(Mandatory=$true)]
        [ValidateScript({$_ -match [IPAddress]$_ })]
        [String]$ip

    )

    $ip
}


