function Write-Log {
    <#
        .SYNOPSIS
            Write to a Log File

        .DESCRIPTION
            Write to a Log File

        .NOTES
            File-Name:  write-Log.ps1
            Author:     Josh Burkard - josh@burkard.it
            Version:    1.0.0

            Changelog:
                    1.0.0,  2020-04-23, Josh Burkard, initial creation

        .PARAMETER Status
            the status of the message.

            this string parameter is mandatory and allows one off this values:
                'INFO', 'WARN', 'ERROR', 'VERBOSE', 'OK', 'END', 'START'

        .PARAMETER Message
            the message to display

            this string parameter is mandatory

        .PARAMETER LogName
            the file of the log

            this string parameter is mandatory, it can be submitted through $PSDefaultParameterValues

        .PARAMETER SubStepLevel
            the level of the indentation

            default is 0

            this integer parameter is not mandatory

        .PARAMETER NoOutput
            if this switch parameter is set, there will be no console output. the logged message will only be writen to the logfile

        .LINK

            https://github.com/joshburkard/___PowerShell-Functions


        .EXAMPLE

            $PSDefaultParameterValues = @{}
            $PSDefaultParameterValues.Add( "Write-Log:LogName", "c:\Admin\Logs\$Package-$Program-$( Get-Date -Format "yyyyMMdd-HHmmss" ).log" )
            Write-Log -Message "Test Message" -Status INFO
            Write-Log -Message "Test Message 1" -Status OK -SubStepLevel 1

    #>
    [CmdletBinding()]
    param (
        [parameter(Mandatory=$true)]
        [ValidateSet('INFO', 'WARN', 'ERROR', 'VERBOSE', 'OK', 'END', 'START')]
        [Alias('Severity')]
        [string]
        $Status,
        [parameter(Mandatory=$true)]
        [string]
        $Message,
        [string]
        $LogName = "c:\Admin\Logs\OSDeployment.log"
        ,
        [switch]$NoOutput
        ,
        [Parameter(Mandatory=$false)]
        [int]$SubStepLevel = 0

    )

    <# $objSMSTS = New-Object -ComObject Microsoft.SMS.TSEnvironment
    $SMSTSLogPath = $objSMSTS.Value("_SMSTSLogPath")

    if (Test-Path $SMSTSLogPath) {
        $LogFile = $(Join-Path $SMSTSLogPath $LogName)
    } #>
    $LogFile = $LogName

    $Path = Split-Path -Path $LogFile
    if (!(Test-Path -Path "$Path")) {
        [void]( New-Item -Type directory -Path "$Path" -Force )
    }

    if( -not ( Test-Path -Path  $LogFile ) ) {
        [void]( New-Item -Path $LogFile -ItemType File )
    }

    $WriteSuccess = $false
    $retry = 0
    do {
        try {
            $retry++
            $stream = [System.IO.StreamWriter]::new($LogFile, $true, ([System.Text.Utf8Encoding]::new()))
            $stream.WriteLine( "$( ( [System.DateTime]::Now ).ToString() ) $( $Status.PadRight(8, ' ').ToUpper() ) - $( ''.PadRight( ($SubStepLevel * 2) , ' ')  )$Message" )
            $stream.close()
            $WriteSuccess = $true
        }
        catch {
            # Write-Host "." -ForegroundColor Yellow -NoNewline
            Start-Sleep -Milliseconds 10
        }
    } until ( ( $WriteSuccess -eq $true ) -or ( $retry -ge 5 ) )

    if ( $WriteSuccess -eq $false ) {
        try {
            "$( ( [System.DateTime]::Now ).ToString() ) $( $Status.PadRight(8, ' ').ToUpper() ) - $( ''.PadRight( ($SubStepLevel * 2) , ' ')  )$Message" | Out-File -FilePath $LogFile -Encoding utf8 -Append
            $WriteSuccess = $true
        }
        catch {
            Write-Host "couldn't write to log" -ForegroundColor Red
        }
    }

    Switch ($Status) {
        'Info'      {$FColor='gray'}
        'Warning'   {$FColor='yellow'}
        'WARN'      {$FColor='yellow'}
        'Error'     {$FColor='red'}
        'Verbose'   {$FColor='yellow'}
        'Ok'        {$FColor='green'}
        Default     {$FColor='gray'}
    }

    if ( $NoOutput -eq $false ) {
        Write-Host "$(([System.DateTime]::Now).ToString()) [$($Status.PadRight(8, ' ').ToUpper())] - $( ''.PadRight( ($SubStepLevel * 2) , ' ')  )$($Message)"  -ForegroundColor $FColor
    }
}