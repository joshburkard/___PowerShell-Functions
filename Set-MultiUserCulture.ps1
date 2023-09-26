function Set-MultiUserCulture {
    <#
        .SYNOPSIS
            this function defines the culture for multiple users

            the setting will be set to the defined users

            you can choose to deploy the setting to the Welcome Screen, System Account, the Default Account (for new users) and to all already existing user profiles.

        .PARAMETER CultureName
            defines the name of the Culture

            The format for the culture name based on RFC 4646 is languagecode2-country/regioncode2, where languagecode2 is the two-letter language code and country/regioncode2
            is the two-letter subculture code. Examples include ja-JP for Japanese (Japan) and en-US for English (United States). In cases where a two-letter language code is
            not available, a three-letter code as defined in ISO 639-3 is used.

            this string parameter is mandatory

        .EXAMPLE
            Set-MultiUserCulture -CultureName de-DE -WelcomeScreen -SystemAccount -DefaultAccount -ExistingProfiles
    #>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$true)]
        [string]$CultureName # = 'de-DE'
        ,
        [Parameter(Mandatory=$false)]
        [switch]$WelcomeScreen
        ,
        [Parameter(Mandatory=$false)]
        [switch]$SystemAccount
        ,
        [Parameter(Mandatory=$false)]
        [switch]$DefaultAccount
        ,
        [Parameter(Mandatory=$false)]
        [switch]$ExistingProfiles
        ,
        [Parameter(Mandatory=$false)]
        [string]$ProfileName
    )

    Write-Verbose "selected culture ${CultureName}"
    $NewCulture = [System.Globalization.CultureInfo]::GetCultureInfo($CultureName)
    Write-Verbose $NewCulture.DisplayName

    $RegSettings = @{
        iCalendarType = $NewCulture.Calendar.CalendarType.value__
        # iCountry =
        iCurrDigits = $NewCulture.NumberFormat.CurrencyDecimalDigits
        iCurrency = $NewCulture.NumberFormat.CurrencyPositivePattern
        # iDate = 1
        iDigits = $NewCulture.NumberFormat.CurrencyDecimalDigits
        iFirstDayOfWeek = $NewCulture.DateTimeFormat.FirstDayOfWeek.value__
        iFirstWeekOfYear = $NewCulture.DateTimeFormat.CalendarWeekRule.value__
        # iLZero = 1
        # iMeasure = 0 # 0 = metric | 1 = imperial
        iNegCurr = $NewCulture.NumberFormat.CurrencyNegativePattern
        iNegNumber = $NewCulture.NumberFormat.NumberNegativePattern
        iPaperSize = 9 # 1 = US letter | 5 = US legal | 8 = A3 | 9 = A4
        iTime = [int]( $NewCulture.DateTimeFormat.ShortTimePattern -cmatch 'H' ) # 0 = AM/PM | 1 = 24h
        # iTimePrefix = 0
        # iTLZero = 1
        Locale = "$( '{0:x}' -f $NewCulture.LCID )".PadLeft(8,'0')
        LocaleName = $NewCulture.Name
        # NumShape = 1 # 1 = Never
        s1159 = $NewCulture.DateTimeFormat.AMDesignator
        s2359 = $NewCulture.DateTimeFormat.PMDesignator
        # sCountry = $WinHomeLocation.HomeLocation
        sCurrency = $NewCulture.NumberFormat.CurrencySymbol
        sDate = $NewCulture.DateTimeFormat.DateSeparator
        sDecimal = $NewCulture.NumberFormat.NumberDecimalSeparator
        sGrouping = '3;0' #
        sLanguage = $NewCulture.ThreeLetterWindowsLanguageName
        sList = $NewCulture.TextInfo.ListSeparator
        sLongDate = $NewCulture.DateTimeFormat.LongDatePattern
        sMonDecimalSep = $NewCulture.NumberFormat.CurrencyDecimalSeparator
        # sMonGrouping = '3;0'
        sMonThousandSep = $NewCulture.NumberFormat.CurrencyGroupSeparator
        sNativeDigits = ( $NewCulture.NumberFormat.NativeDigits -join '' )
        sNegativeSign = $NewCulture.NumberFormat.NegativeSign
        sPositiveSign = $NewCulture.NumberFormat.PositiveSign
        sShortDate = $NewCulture.DateTimeFormat.ShortDatePattern
        sShortTime = $NewCulture.DateTimeFormat.ShortTimePattern
        sThousand = $NewCulture.NumberFormat.NumberGroupSeparator
        sTime = $NewCulture.DateTimeFormat.TimeSeparator
        sTimeFormat = $NewCulture.DateTimeFormat.LongTimePattern
        sYearMonth = $NewCulture.DateTimeFormat.YearMonthPattern
    }

    $ProfileList = @()
    if ( $WelcomeScreen ) {
        Write-Verbose "Welcome Screen"
        $ProfileList += [PSCUstomObject]@{
            PreLoaded = $false
            ProfilePath = $null
            LoadKey = $null
            RegKey = 'HKU:\S-1-5-19'
        }
    }
    if ( $SystemAccount ) {
        Write-Verbose "System Account"
        $ProfileList += [PSCUstomObject]@{
            PreLoaded = $false
            ProfilePath = $null
            LoadKey = $null
            RegKey = 'HKU:\S-1-5-19'
        }
    }
    if ( $DefaultAccount ) {
        Write-Verbose "Default Account"
        $ProfileList += [PSCUstomObject]@{
            PreLoaded = $true
            ProfilePath = "C:\Users\Default\NTUSER.DAT"
            LoadKey = "HKU\TEMP"
            RegKey = "HKU:\TEMP"
        }
    }
    if ( $ExistingProfiles -or $ProfileName ) {
        $RegPath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList'
        $UserProfiles = Get-ChildItem -Path $RegPath | ForEach-Object {Get-ItemProperty $_.pspath }
        $UserProfiles = $UserProfiles | Select-Object @{n='path'; e={ @( $_.PSPath -split '\\' )[ -1 ] }}, profileImagePath, sid
    }
    if ( $ProfileName ) {
        Write-Verbose "specific profilename $( $ProfileName )"
        $UserProfile = $UserProfiles | Where-Object { $_.ProfileImagePath.SubString( ( $_.ProfileImagePath.Length - $ProfileName.Length ), $ProfileName.Length ) -eq $ProfileName }
        if ( Test-Path -Path "HKU:\\$( $UserProfile.path )" ) {
            $Preloaded = $false
        }
        else {
            $Preloaded = $true
        }
        $ProfileList += [PSCUstomObject]@{
            PreLoaded = $Preloaded
            ProfilePath = "$( $UserProfile.ProfileImagePath )\NTUSER.DAT"
            LoadKey = "HKU\$( $UserProfile.path )"
            RegKey = "HKU:\$( $UserProfile.path )"
        }
    }
    if ( $ExistingProfiles ) {
        Write-Verbose "all other users"

        foreach ( $UserProfile in $UserProfiles ) {
            write-verbose "  $( $UserProfile.ProfileImagePath )"

            if ( Test-Path -Path "HKU:\\$( $UserProfile.path )" ) {
                $Preloaded = $false
            }
            else {
                $Preloaded = $true
            }
            $ProfileList += [PSCUstomObject]@{
                PreLoaded = $Preloaded
                ProfilePath = "$( $UserProfile.ProfileImagePath )\NTUSER.DAT"
                LoadKey = "HKU\$( $UserProfile.path )"
                RegKey = "HKU:\$( $UserProfile.path )"
            }
        }
    }

    if ( ( Get-PSProvider -PSProvider Registry ).Drives.Name -notcontains 'HKU' ) {
        Write-Verbose "load psprovider for registry"
        New-PSDrive -PSProvider Registry -Name HKU -Root HKEY_USERS
    }

    Write-Verbose "loop through profiles"
    foreach ( $ProfileItem in $ProfileList ) {
        Write-Verbose $ProfileItem.RegKey
        if ( $ProfileItem.PreLoaded ) {
            Start-Process -FilePath 'C:\windows\System32\reg.exe' -ArgumentList "load $( $ProfileItem.LoadKey ) $( $ProfileItem.ProfilePath )" -Wait
            Write-Verbose "loaded regkey from $( $ProfileItem.ProfilePath )"
        }

        $ProfileRegPath = "$( $ProfileItem.RegKey )\Control Panel\International"

        Write-Verbose "set new settings ..."
        foreach ( $Key in $RegSettings.Keys ) {
            Set-ItemProperty -Path $ProfileRegPath -Name $Key -Value $RegSettings."${Key}" -Force -Confirm:$false
        }

        if ( $ProfileItem.PreLoaded ) {
            Start-Process -FilePath 'C:\windows\System32\reg.exe' -ArgumentList "unload $( $ProfileItem.LoadKey )" -Wait
            Write-Verbose "unloaded regkey"
        }


    }
}

