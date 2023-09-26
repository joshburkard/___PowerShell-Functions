function New-SoftwareTag {
    Param (
        [string]$Company = 'SDWorx'
        ,
        [string]$Software = 'SQL CommVault FullAgent'
        ,
        [string]$Version = '11.0.80 - 1'
        ,
        [string]$Action = 'install'
        ,
        [string]$Status
        ,
        [string]$LogFile
    )
    $RegPath = "HKLM:\SOFTWARE\${Company}\${Software}\$Version"
    try {
        Get-ItemProperty -Path $RegPath -ErrorAction Stop
    }
    catch [System.Management.Automation.ItemNotFoundException] {
        New-Item -Path $RegPath -Force
    }
    Set-ItemProperty -Path $RegPath -Name $Action -Value ( Get-Date -Format "dd/MM/yyyy HH:mm:ss" )
    if ( [boolean]$Status ) {
        Set-ItemProperty -Path $RegPath -Name 'Status' -Value $Status
    }
    if ( [boolean]$Status ) {
        Set-ItemProperty -Path $RegPath -Name 'LogFile' -Value $LogFile
    }
}