Function Test-ADPassword {
    [CmdletBinding()]
    [OutputType([String])]

    Param (
        [Parameter(
            Mandatory = $false,
            ValueFromPipeLine = $true,
            ValueFromPipelineByPropertyName = $true
        )]
        [Alias(
            'PSCredential'
        )]
        [ValidateNotNull()]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential
    )
    $Domain = $null
    $Root = $null
    $Username = $null
    $Password = $null

    If( -not [boolean]$Credential ) {
        Try {
            $Credential = Get-Credential "domain\$env:username" -ErrorAction Stop
        }
        Catch {
            $ErrorMsg = $_.Exception.Message
            Write-Warning "Failed to validate credentials: $ErrorMsg "
            Pause
            Break
        }
    }

    if ( $Credential.UserName -match '\\' -or $Credential.UserName -match '@' ) {
        # Checking module
        Try {
            # Split username and password
            $Username = $Credential.username
            $Password = $Credential.GetNetworkCredential().password

            # Get Domain
            $Root = "LDAP://" + ([ADSI]'').distinguishedName
            $Domain = New-Object System.DirectoryServices.DirectoryEntry($Root,$UserName,$Password)
        }
        Catch {
            $_.Exception.Message
            Continue
        }

        If( !$domain ) {
            Write-Warning "Something went wrong"
        }
        Else
        {
            [boolean]$domain.name
        }
    }
    else {
        $computer = $env:COMPUTERNAME

        Add-Type -AssemblyName System.DirectoryServices.AccountManagement
        $obj = New-Object System.DirectoryServices.AccountManagement.PrincipalContext('machine', $computer)
        $obj.ValidateCredentials($Credential.UserName, $Credential.GetNetworkCredential().Password )
    }
}

$Credential = Get-Credential
$Credential.UserName
$Credential.GetNetworkCredential().Password
$Credential.GetType().FullName

Test-ADPassword -Credential $Credential

Function get-RandomPassword {
    Param (
        [Parameter(Mandatory = $false)]
        [ValidateRange(4, [int]::MaxValue)]
        [int]$length = 8
        ,
        $SpecialChars = '' # = '!@#%&()*+-./\:;<=>?[]_{}|'
    )
    #$punc = 46..46
    $digits = 48..57
    $letters = 65..90 + 97..122
    $arr = $SpecialChars.ToCharArray() | ForEach-Object { [byte][char]$_ }

    do {
        $password = get-random -count $length `
            -input ($digits + $letters + $arr ) |
                ForEach-Object -begin { $aa = $null } `
                -process {$aa += [char]$_} `
                -end {$aa}
        if ( [string]::IsNullOrEmpty( $SpecialChars ) ) {
            $passwordmatch = ( ($password -match "[0-9]") -and ($password -cmatch "[a-z]") -and ($password -cmatch "[A-Z]") )
        }
        else {
            $passwordmatch = ( ($password -match "[0-9]") -and ($password -cmatch "[a-z]") -and ($password -cmatch "[A-Z]") -and ( $password -cmatch "[$SpecialChars]" ) )
        }
    } while ( $passwordmatch -eq $false )

    return $password
}

get-RandomPassword -length 20