function Get-UserPwdInfo {
    Param (
        $UserDN
    )

    Function Convert-HexSIDToDec($HexSID) {
        # Convert into normal array of bytes.
        $strSID = "S-" + $HexSID[0]
        $arrSID = $strSID.Split(" ")
        $Max = $arrSID.Count
        $DecSID = $arrSID[0] + "-" + $arrSID[1] + "-" + $arrSID[8]
        If ($Max -eq 11) {
            Return $DecSID
        }
        $Temp1 = [Int64]$arrSID[12] + (256 * ([Int64]$arrSID[13] + (256 * ([Int64]$arrSID[14] + (256 * ([Int64]$arrSID[15]))))))
        $DecSID = $DecSID + "-" + $($Temp1)
        If ($Max -eq 15) {
            Return $DecSID
        }
        $Temp2 = [Int64]$arrSID[16] + (256 * ([Int64]$arrSID[17] + (256 * ([Int64]$arrSID[18] + (256 * ([Int64]$arrSID[19]))))))
        $DecSID = $DecSID + "-" + $($Temp2)
        $Temp3 = [Int64]$arrSID[20] + (256 * ([Int64]$arrSID[21] + (256 * ([Int64]$arrSID[22] + (256 * ([Int64]$arrSID[23]))))))
        $DecSID = $DecSID + "-" + $($Temp3)
        If ($Max -lt 24) {
            Return $DecSID
        }
        $Temp4 = [Int64]$arrSID[24] + (256 * ([Int64]$arrSID[25] + (256 * ([Int64]$arrSID[26] + (256 * ([Int64]$arrSID[27]))))))
        $DecSID = $DecSID + "-" + $($Temp4)
        Return $DecSID
    }

    $ACCOUNTDISABLE       = 0x000002
    $DONT_EXPIRE_PASSWORD = 0x010000
    $PASSWORD_EXPIRED     = 0x800000

    if ( [string]::IsNullOrEmpty( $UserDN ) ) {
        $SysInfo = New-Object -ComObject "ADSystemInfo"
        $UserDN = $SysInfo.GetType().InvokeMember("UserName", "GetProperty", $Null, $SysInfo, $Null)
    }

    $User = [ADSI]"LDAP://$UserDN"

    $searcher=New-Object DirectoryServices.DirectorySearcher
    $searcher.Filter="(&(distinguishedName=$($User.distinguishedName)))"
    $results=$searcher.findone()
    $PwdLastSet = [datetime]::fromfiletime($results.properties.pwdlastset[0])

    $DomainName = ( $UserDN -split ',' | Where-Object { $_ -match 'DC' } | ForEach-Object { $_ -replace 'DC=', '' } ) -join '.'
    [ADSI]$domain = "WinNT://$( $DomainName )"
    $MaxPasswordAge = $domain.MaxPasswordAge.Value

    try {
        $ADSystemInfo = New-Object -ComObject "ADSystemInfo"
        $DomainShortName = $ADSystemInfo.GetType().InvokeMember("DomainShortName", "GetProperty", $null, $ADSystemInfo, $null)
    }
    catch {
        $DomainShortName = ''
    }

    $objectSID = Convert-HexSIDToDec -HexSID $user.objectSid

    # $ret = New-Object -TypeName PSObject -Property @{
    $ret = [ordered]@{}
    $ret.Add( 'userPrincipalName', $User.userPrincipalName.ToString() )
    $ret.Add( 'sAMAccountName', $user.sAMAccountName.ToString() )
    $ret.Add( 'objectSID', $objectSID )
    $ret.Add( 'UserDisplayName', $results.Properties.displayname[0].ToString() )
    $ret.Add( 'UserDistinguishedName', $results.Properties.distinguishedname[0].ToString() )
    $ret.Add( 'Domain', $domain.Name.ToString() )
    $ret.Add( 'DomainPreWindows2000', $DomainShortName )
    $ret.Add( 'Enabled', ( -not [bool]($results.Properties.useraccountcontrol[0] -band $ACCOUNTDISABLE ) ) )
    $ret.Add( 'PasswordNeverExpires', ( [bool]($results.Properties.useraccountcontrol[0] -band $DONT_EXPIRE_PASSWORD ) ) )
    $ret.Add( 'PasswordExpired', ( [bool]($results.Properties.useraccountcontrol[0] -band $PASSWORD_EXPIRED ) ) )
    $ret.Add( 'MaxPasswordAge', $domain.MaxPasswordAge.Value / 3600 / 24 )
    $ret.Add( 'MinPasswordAge', $domain.MinPasswordAge.Value / 3600 / 24 )
    $ret.Add( 'LastPasswordSet', $PwdLastSet )
    $ret.Add( 'CurrentPasswordAge', ( New-TimeSpan -Start $PwdLastSet -End ( Get-Date ) ) )
    $ret.Add( 'PasswordExpiresOn', $PwdLastSet.AddSeconds( $MaxPasswordAge ) )
    $ret.Add( 'PasswordExpiresIn', ( New-TimeSpan -Start ( Get-Date ) -End $PwdLastSet.AddSeconds( $MaxPasswordAge ) ) )
    $ret
}
$UserPwdInfo = Get-UserPwdInfo
$UserPwdInfo

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


$Credential = New-Object System.Management.Automation.PSCredential ( $UserName, ( ConvertTo-SecureString $Password -AsPlainText -Force ) )


Function get-RandomPassword {
    Param (
        [Parameter(Mandatory = $false)]
        [ValidateRange(4, [int]::MaxValue)]
        [int]$length = 8
        ,
        $SpecialChars = '' # = '!@#%&()*+-./\:;<=>?[]_{}|'
    )
    #$punc = 46..46
    # $digits = 48..57
    $digits = 49..57 # exclude 0
    # $letters = 65..90 + 97..122
    $letters = 65..72 + 74..78 + 80..90 + 97..107 + 109..122 # exclude i,l,I,O
    # $digits | ForEach-Object { "$( $_ ) - $( [char]$_ )" }
    # $letters | ForEach-Object { "$( $_ ) - $( [char]$_ )" }    $digits = 48..57
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




