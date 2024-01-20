function Test-RegistryKey {
    [OutputType('bool')]
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Key
    )

    $ErrorActionPreference = 'Stop'

    if (Get-Item -Path $Key -ErrorAction Ignore) {
        $true
    }
}

function Test-RegistryValue {
    [OutputType('bool')]
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Key,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Value
    )

    $ErrorActionPreference = 'Stop'

    if (Get-ItemProperty -Path $Key -Name $Value -ErrorAction Ignore) {
        $true
    }
}

function Test-RegistryValueNotNull {
    [OutputType('bool')]
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Key,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Value
    )

    $ErrorActionPreference = 'Stop'

    if (($regVal = Get-ItemProperty -Path $Key -Name $Value -ErrorAction Ignore) -and $regVal.($Value)) {
        $true
    }
}