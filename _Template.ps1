﻿<#
    .SYNOPSIS
        This script does magic things

    .DESCRIPTION
        This script does magic things using powershell

    .NOTES
        File-Name:  _template.ps1
        Author:     Josh Burkard - josh@burkard.it
        Version:    1.0.0

        Changelog:
                1.0.0,  2020-04-23, Josh Burkard, initial creation

    .PARAMETER xyz

    .LINK
        https://github.com/joshburkard/___PowerShell-Functions


    .EXAMPLE
#>
[CmdletBinding()]
param (
    [Parameter(Mandatory=$false)]
    [String]$xyz
)
try {
    #region declarations
        #region get current path of the started script file
            switch ( $ExecutionContext.Host.Name ) {
                "ConsoleHost" { Write-Verbose "Runbook is executed from PowerShell Console"; if ( [boolean]$MyInvocation.ScriptName ) { if ( ( $MyInvocation.ScriptName ).EndsWith( ".psm1" ) ) { $CurrentFile = [System.IO.FileInfo]$Script:MyInvocation.ScriptName } else { $CurrentFile = [System.IO.FileInfo]$MyInvocation.ScriptName } } elseif ( [boolean]$MyInvocation.MyCommand ) { if ( [boolean]$MyInvocation.MyCommand.Source ) { if ( ( $MyInvocation.MyCommand.Source ).EndsWith( ".psm1" ) ) { $CurrentFile = [System.IO.FileInfo]$Script:MyInvocation.MyCommand.Source } else { $CurrentFile = [System.IO.FileInfo]$MyInvocation.MyCommand.Source } } else { $CurrentFile = [System.IO.FileInfo]$MyInvocation.MyCommand.Path } } }
                "Visual Studio Code Host" { Write-Verbose 'Runbook is executed from Visual Studio Code'; If ( [boolean]( $psEditor.GetEditorContext().CurrentFile.Path ) ) { Write-Verbose "c"; $CurrentFile = [System.IO.FileInfo]$psEditor.GetEditorContext().CurrentFile.Path } else { if ( ( [System.IO.FileInfo]$MyInvocation.ScriptName ).Extension -eq '.psm1' ) { Write-Verbose "d1"; $PSCallStack = Get-PSCallStack; $CurrentFile =[System.IO.FileInfo] @( $PSCallStack | Where-Object { $_.ScriptName -match '.ps1'} )[0].ScriptName } else { Write-Verbose "d2";  $CurrentFile = [System.IO.FileInfo]$MyInvocation.scriptname } } }
                "Windows PowerShell ISE Host" { Write-Verbose 'Runbook is executed from ISE'; Write-Verbose "  CurrentFile"; $CurrentFile = [System.IO.FileInfo]( $psISE.CurrentFile.FullPath ) }
            }

            $CurrentPath = $CurrentFile.Directory.FullName
        #endregion get current path of the started script file
    #endregion declarations

    #region functions
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
                    $stream.WriteLine( "$( $LogDate ) $( $Status.PadRight(8, ' ').ToUpper() ) - $( ''.PadRight( ($SubStepLevel * 2) , ' ')  )$Message" )
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
                    "$( $LogDate ) $( $Status.PadRight(8, ' ').ToUpper() ) - $( ''.PadRight( ($SubStepLevel * 2) , ' ')  )$Message" | Out-File -FilePath $LogFile -Encoding utf8 -Append
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

    #endregion functions

    #region execution
        #region start logging
            $PSDefaultParameterValues = @{}
            $PSDefaultParameterValues.Add( "Write-Log:LogName", "$( $CurrentPath )\Logs\$( $CurrentFile.BaseName )-$( Get-Date -Format "yyyyMMdd-HHmmss" ).log" )
            Write-Log -Message "started script $( $CurrentFile.Name )" -Status INFO
            Write-Log -Message "write log to file $( $PSDefaultParameterValues.'Write-Log:LogName' )" -Status INFO -SubStepLevel 1

            if ( [boolean]$PSBoundParameters.GetEnumerator() ) {
                Write-Log "started with parameters:" -Status INFO -SubStepLevel 1
                foreach ( $bp in $PSBoundParameters.GetEnumerator() ) {
                    Write-Log -Message "$( $bp.Key ) : $( $bp.Value )" -Status INFO -SubStepLevel 2
                }
            }
        #endregion start logging

        Write-Verbose "This is only a verbose test"

        #region create a handled error
            try {
                1/0
            }
            catch {
                Write-Log -Message "invalid division by zero" -Status ERROR
                Exit 500
            }
        #endregion create a handled error

        #region end script
            Write-Log -Message "script ended without failures" -Status OK
            Exit 0
        #endregion end script
    #endregion execution
}
catch {
    $err = $_
    $Error.Clear()

    Write-Output $err

    $ScriptName = $err.InvocationInfo.ScriptName
    $Content = $err.InvocationInfo.Line
    if ( [boolean]$Content ) {
        $Content = $Content.Trim()
    }
    $LineNumber = $err.InvocationInfo.ScriptLineNumber
    $Col = $err.InvocationInfo.OffsetInLine

    Write-Output "Error Occured at:"
    if ( [boolean]$ScriptName ) {
        Write-Output "  ScriptName:  $($ScriptName)"
    }
    Write-Output "  LineNumber:  $($LineNumber)"
    Write-Output "  Col:         $($Col)"
    Write-Output "  Content:     $($Content)"

    Exit 1
}