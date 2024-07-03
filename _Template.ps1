<#
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

        function Clear-LogFolder {
            <#
                .SYNOPSIS
                    Clears the Log Folder
                .DESCRIPTION
                    Clears the Log Folder, remove the oldest files

                    if nothing else is defined, all files older than 14 days and all files older than the newest 1000 will be removed
                .NOTES
                    File-Name:  Clear-LogFolder.ps1
                    Author:     Josh Burkard - josh@burkard.it
                    Version:    1.0.0
                    Changelog:
                            1.0.0,  2020-04-23, Josh Burkard, initial creation

                .PARAMETER Path
                    the path to be cleaned

                    this path parameter is mandatory and allows only a path to a directory

                .PARAMETER MaxDays
                    the max age of the files

                    this integer parameter is not mandatory, the default value is 14 days

                .PARAMETER MaxCount
                    the max count of file to beleft after removing by MaxAge

                    the newest files will stay

                    this integer parameter is not mandatory, the default value is 1000

                .LINK
                    https://github.com/joshburkard/___PowerShell-Functions

                .EXAMPLE
                    Clear-LogFolder -Path "c:\Admin\Logs\"

                .EXAMPLE
                    Clear-LogFolder -Path "c:\Admin\Logs\" -MaxDays 30

                .EXAMPLE
                    Clear-LogFolder -Path "c:\Admin\Logs\" -MaxCount 500

                .EXAMPLE
                    Clear-LogFolder -Path "c:\Admin\Logs\" -MaxDays 30 - MaxCount 250

            #>
            [CmdletBinding()]
            Param (
                [Parameter(Mandatory=$true)]
                [ValidateScript({
                    if ( -Not ($_ | Test-Path) ) {
                        throw "File or folder does not exist"
                    }
                    if ( ( Get-Item -Path $_.FullName ) -isnot [System.IO.DirectoryInfo] ) {
                        throw "Path must be a Directory"
                    }
                    return $true
                })]
                [System.IO.FileInfo]$Path # = 'c:\Admin\Logs\Get-EWSMail'
                ,
                [int]$MaxDays = 14
                ,
                [int]$MaxCount = 1000
            )
            $AllChildItems = Get-ChildItem -Path $Path
            $NewerThen = ( Get-Date ).AddDays( 0 - $MaxDays )
            $ChildItems = $AllChildItems | Where-Object { ( Get-Date $_.LastWriteTime ) -ge $NewerThen }
            $ChildItems = $ChildItems | Sort-Object LastWriteTime -Descending | Select-Object -First $MaxCount

            $RemoveItems = $AllChildItems | Where-Object { $_.Name -notin $ChildItems.Name }
            $RemoveItems | ForEach-Object { Remove-Item -Path $_.FullName -Confirm:$false -Force }
        }
    #endregion functions

    #region execution
        #region start logging
            $PSDefaultParameterValues = @{}
            # $PSDefaultParameterValues.Add( "Write-Log:LogName", "$( $CurrentPath )\Logs\$( $CurrentFile.BaseName )-$( Get-Date -Format "yyyyMMdd-HHmmss" ).log" )
            $PSDefaultParameterValues.Add( "Write-Log:LogName", "C:\Admin\Logs\OSD\$( Get-Date -Format "yyyyMMdd-HHmmss" )-$( $CurrentFile.BaseName ).log" )
            Write-Log -Message "started script $( $CurrentFile.Name )" -Status INFO
            Write-Log -Message "write log to file $( $PSDefaultParameterValues.'Write-Log:LogName' )" -Status INFO -SubStepLevel 1

            if ( [boolean]$PSBoundParameters.GetEnumerator() ) {
                Write-Log "started with parameters:" -Status INFO -SubStepLevel 1
                foreach ( $bp in $PSBoundParameters.GetEnumerator() ) {
                    Write-Log -Message "$( $bp.Key ) : $( $bp.Value )" -Status INFO -SubStepLevel 2
                }
            }
            Clear-LogFolder -Path "$( $CurrentPath )\Logs" -MaxDays 30 -MaxCount 1000
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

    if ( Get-Command -Name Write-Log -ErrorAction SilentlyContinue ) {
        Write-Log -Message "Error Occured at:" -Status ERROR
        if ( [boolean]$ScriptName ) {
            Write-Log -Message "ScriptName:  $($ScriptName)" -Status ERROR -SubStepLevel 1
        }
        Write-Log -Message "LineNumber:  $($LineNumber)" -Status ERROR -SubStepLevel 1
        Write-Log -Message "Col:         $($Col)" -Status ERROR -SubStepLevel 1
        Write-log -Message "Content:     $($Content)" -Status ERROR -SubStepLevel 1
    }
    else {
        Write-Output "Error Occured at:"
        if ( [boolean]$ScriptName ) {
            Write-Output "  ScriptName:  $($ScriptName)"
        }
        Write-Output "  LineNumber:  $($LineNumber)"
        Write-Output "  Col:         $($Col)"
        Write-Output "  Content:     $($Content)"
    }
    Exit 1
}