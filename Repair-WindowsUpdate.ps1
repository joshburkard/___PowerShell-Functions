<#
    .SYNOPSIS
        This script tries to repair Windows Update

    .DESCRIPTION
        This script tries to repair Windows Update

    .NOTES
        File-Name:  Repair-WindowsUpdate.ps1
        Author:     Josh Burkard - josh@burkard.it
        Version:    1.0.0

        Changelog:
                1.0.0,  2020-04-23, Josh Burkard, initial creation

    .PARAMETER xyz

    .LINK
        https://github.com/joshburkard/___PowerShell-Functions


    .EXAMPLE
        . Repair-WindowsUpdate
#>
[CmdletBinding()]
param (
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
                [System.IO.FileInfo]$Path # = 'c:\Admin\Logs\Get-EWSMail'
                ,
                [int]$MaxDays = 14
                ,
                [int]$MaxCount = 1000
            )

            if ( -Not ( Test-Path -Path $Path ) ) {
                Write-Warning -Message "File or folder does not exist"
            }
            elseif ( ( Get-Item -Path $Path.FullName ) -isnot [System.IO.DirectoryInfo] ) {
                Write-Warning -Message "Path must be a Directory"
            }
            else {
                $AllChildItems = Get-ChildItem -Path $Path
                $NewerThen = ( Get-Date ).AddDays( 0 - $MaxDays )
                $ChildItems = $AllChildItems | Where-Object { ( Get-Date $_.LastWriteTime ) -ge $NewerThen }
                $ChildItems = $ChildItems | Sort-Object LastWriteTime -Descending | Select-Object -First $MaxCount

                $RemoveItems = $AllChildItems | Where-Object { $_.Name -notin $ChildItems.Name }
                $RemoveItems | ForEach-Object { Remove-Item -Path $_.FullName -Confirm:$false -Force }
            }
        }

        function Start-ProcessAdv {
            <#
                .SYNOPSIS
                    This function executes an executable file with parameters and and captures its exit code, stdout and stderr.

                .DESCRIPTION
                    This function executes an executable file with parameters and and captures its exit code, stdout and stderr.

                .PARAMETER FilePath
                    the full path to the executable file

                    only for compatibility with old versions of this function, the parameter has an alias to FileName. do not use this alias in new scripts.

                .PARAMETER ArgumentList
                    the arguments which should be transmitted to the executable process

                    only for compatibility with old versions of this function, the parameter has an alias to Arguments. do not use this alias in new scripts.

                .PARAMETER VERB
                    should the process run as Administrator

                .PARAMETER TimeOut
                    TimeOut in seconds

                .PARAMETER WorkingDirectory
                    the directory in which the procss should work

                .PARAMETER WaitChildProcess
                    if this switch parameter is set, the function will wait till all child processes are finished

                .PARAMETER WaitChildProcessTimeOut
                    this parameter defines the timeout in seconds for the waiting to child processes. the timeout starts after the main process finished.

                    if  not all childprocesses are finished, it will returnd as a warn message

                    this integer parameter is not mandatory. the default value is 1800 (30 minutes)

                .LINK
                    https://github.com/joshburkard/___PowerShell-Functions

                .EXAMPLE
                    Start-ProcessAdv -FilePath 'git' -ArgumentList 'status' -TimeOut 60
            #>
            [OutputType('PSCustomObject')]
            [CmdletBinding()]
            param(
                [Parameter(Mandatory=$true)]
                [ValidateNotNullOrEmpty()]
                [Alias('FileName')]
                [String]$FilePath
                ,
                [Parameter(Mandatory=$false)]
                [Alias('Arguments')]
                [String[]]$ArgumentList
                ,
                [Parameter(Mandatory=$false)]
                [ValidateSet('','runas')]
                [String]$Verb = ''
                ,
                [Parameter( Mandatory = $false)]
                [int]$TimeOut
                ,
                [Parameter( Mandatory = $false)]
                [string]$WorkingDirectory = $null
                ,
                [Parameter( Mandatory = $false)]
                [System.Management.Automation.PSCredential]$Credential
                ,
                [switch]$WaitChildProcess
                ,
                [Parameter( Mandatory = $false)]
                [int]$WaitChildProcessTimeOut = 1800
            )

            # Setting process invocation parameters.
            $ProcessStartInfo = New-Object -TypeName System.Diagnostics.ProcessStartInfo
            $ProcessStartInfo.CreateNoWindow = $true
            $ProcessStartInfo.UseShellExecute = $false
            $ProcessStartInfo.RedirectStandardOutput = $true
            $ProcessStartInfo.RedirectStandardError = $true
            $ProcessStartInfo.FileName = $FilePath
            if ( [boolean]$WorkingDirectory ) {
                $ProcessStartInfo.WorkingDirectory = $WorkingDirectory
            }

            if (! [String]::IsNullOrEmpty($ArgumentList)) {
                $ProcessStartInfo.Arguments = $ArgumentList
            }
            if ( -not [String]::IsNullOrEmpty( $Verb ) ) {
                $ProcessStartInfo.Verb = $Verb
            }
            if ( [boolean]$Credential ) {
                $ProcessStartInfo.UserName = $Credential.GetNetworkCredential().UserName
                $ProcessStartInfo.Domain   = $Credential.GetNetworkCredential().Domain
                $ProcessStartInfo.Password = $Credential.Password
            }

            # Creating process object.
            $Process = New-Object -TypeName System.Diagnostics.Process
            $Process.StartInfo = $ProcessStartInfo

            if ( [boolean]$WaitChildProcess ) {
                $global:ChildProcessesPIDs = @()
                # $global:ChildProcessesPIDs += $Process.Id

                Register-WMIEvent -query "SELECT * FROM Win32_ProcessStartTrace" -SourceIdentifier "ChildProcessEvent" -action {
                    $e = $Event.SourceEventArgs.NewEvent
                    # Write-Host $e.ProcessName, $e.ID, $e.ParentID, "started"

                    # $global:a = $e
                    Write-Verbose "$( $e.ParentProcessID ) $( $e.ProcessID ) $( $e.ProcessName ) started"
                    if ( $e.ParentProcessID -in $global:ChildProcessesPIDs -and $e.ProcessName -notin @( 'WmiPrvSE.exe' ) ) {
                        $global:ChildProcessesPIDs += $e.ProcessID
                        Write-Verbose "it's a child process of the started process"

                    }
                }
            }

            # Creating string builders to store stdout and stderr.
            $StdOutBuilder = New-Object -TypeName System.Text.StringBuilder
            $StdErrBuilder = New-Object -TypeName System.Text.StringBuilder

            # Adding event handers for stdout and stderr.
            $ScripBlock = {
                if ( -not [String]::IsNullOrEmpty( $EventArgs.Data ) ) {
                    $Event.MessageData.AppendLine( $EventArgs.Data )
                }
            }
            $StdOutEvent = Register-ObjectEvent -InputObject $Process `
                -Action $ScripBlock -EventName 'OutputDataReceived' `
                -MessageData $StdOutBuilder
            $StdErrEvent = Register-ObjectEvent -InputObject $Process `
                -Action $ScripBlock -EventName 'ErrorDataReceived' `
                -MessageData $StdErrBuilder

            # Starting process.
            [Void]$Process.Start()
            $global:ChildProcessesPIDs += $Process.Id
            $Process.BeginOutputReadLine()
            $Process.BeginErrorReadLine()
            if ( [boolean]$TimeOut ) {
                [Void]$Process.WaitForExit( $TimeOut * 1000 )
            }
            else {
                [Void]$Process.WaitForExit()
            }


            # Unregistering events to retrieve process output.
            Unregister-Event -SourceIdentifier $StdOutEvent.Name
            Unregister-Event -SourceIdentifier $StdErrEvent.Name

            # get errors and output from the Builder object
            $StdOut     = $StdOutBuilder.ToString().Trim()
            $StdErr     = $StdErrBuilder.ToString().Trim()

            # remove empty chars from the error and output variables
            $StdOut = ( $StdOut.ToCharArray() | Where-Object { [boolean]$_ } ) -join ''
            $StdErr = ( $StdErr.ToCharArray() | Where-Object { [boolean]$_ } ) -join ''

            # create the return object
            $Result = New-Object -TypeName PSObject -Property ( [Ordered]@{
                "ExeFile"    = $FilePath;
                "Parameters" = $ArgumentList -join " ";
                "ExitCode"   = $Process.ExitCode;
                "StdOut"     = $StdOut
                "StdErr"     = $StdErr
                ID           = $Process.Id
            } )

            if ( [boolean]$WaitChildProcess ) {
                Start-Sleep -Seconds 1
                $StartTime = Get-Date
                do {
                    Start-Sleep -Seconds 1
                    $AllProcesses = Get-WmiObject Win32_Process
                    $ChildProcesses = $AllProcesses | Where-Object { $_.ProcessID -in $global:ChildProcessesPIDs -and $_.Name -notin @('WmiPrvSE.exe')}
                } while ( ( [boolean]$ChildProcesses ) -and ( $StartTime -gt ( Get-Date ).AddSeconds( 0 - $WaitChildProcessTimeOut ) ) )
                if ( [boolean]$ChildProcesses ) {
                    Write-Warning -Message "not all processes are finished:"
                    $ChildProcesses | ForEach-Object {
                        Write-Warning -Message "$( $_.ProcessID.ToString().PadLeft(8, ' ') ): $( $_.Name )"
                    }
                }
                Unregister-Event -SourceIdentifier ChildProcessEvent
                Remove-Variable -Name ChildProcessesPIDs -Scope Global -ErrorAction SilentlyContinue
            }

            return $Result
        }
    #endregion functions

    #region execution
        #region start logging
            $PSDefaultParameterValues = @{}
            # $PSDefaultParameterValues.Add( "Write-Log:LogName", "$( $CurrentPath )\Logs\$( $CurrentFile.BaseName )-$( Get-Date -Format "yyyyMMdd-HHmmss" ).log" )
            $PSDefaultParameterValues.Add( "Write-Log:LogName", "C:\Admin\Logs\$( Get-Date -Format "yyyyMMdd-HHmmss" )-$( $CurrentFile.BaseName ).log" )
            Write-Log -Message "started script $( $CurrentFile.Name )" -Status INFO
			Write-Log -Message "started script as $( $env:USERDOMAIN )\$( $env:USERNAME )" -Status INFO
            Write-Log -Message "write log to file $( $PSDefaultParameterValues.'Write-Log:LogName' )" -Status INFO -SubStepLevel 1

            if ( [boolean]$PSBoundParameters.GetEnumerator() ) {
                Write-Log "started with parameters:" -Status INFO -SubStepLevel 1
                foreach ( $bp in $PSBoundParameters.GetEnumerator() ) {
                    Write-Log -Message "$( $bp.Key ) : $( $bp.Value )" -Status INFO -SubStepLevel 2
                }
            }
            # Clear-LogFolder -Path "C:\Admin\Logs" -MaxDays 30 -MaxCount 1000
        #endregion start logging

        #region stopping services
            Write-Log -Message 'stopping services ...' -Status INFO

            $Services = @('bits', 'wuauserv', 'appidsvc', 'cryptsvc')

            foreach ( $Service in $Services ) {
                Write-Log -Message $Service -Status INFO -SubStepLevel 1
                if ( Get-Service -Name $Service -ErrorAction SilentlyContinue ) {
                    try {
                        Stop-Service -Name $Service -Force -Confirm:$false
                        Write-Log -Message 'service stopped' -Status OK -SubStepLevel 2
                    }
                    catch {
                        Write-Log -Message 'couldn''t stop service' -Status ERROR -SubStepLevel 2
                    }
                }
                else {
                    Write-Log -Message 'service doesn''t exist' -Status INFO -SubStepLevel 2
                }
            }
        #endregion stopping services

        #region remove files
            Write-Log -Message 'remove files ...' -Status INFO

            Write-Log -Message '%ALLUSERSPROFILE%\Application Data\Microsoft\Network\Downloader\qmgr*.dat ...' -Status INFO -SubStepLevel 1
            $Files = Get-ChildItem -Path ( Join-Path -Path $env:ALLUSERSPROFILE -ChildPath "\Application Data\Microsoft\Network\Downloader\" ) -Filter "qmgr*.dat"
            $Files | Remove-Item -Force -Confirm:$false

            Write-Log -Message '%systemroot%\SoftwareDistribution ...' -Status INFO -SubStepLevel

            Remove-Item -Path ( Join-Path -Path $env:SystemRoot -ChildPath 'SoftwareDistribution' ) -Force -Recurse -Confirm:$false
        #endregion remove files

        #region reset BITS service
            Write-Log -Message 'reset BITS service' -Status INFO

            $res = Start-ProcessAdv -FilePath 'C:\Windows\System32\sc.exe' -ArgumentList 'sdset bits D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;AU)(A;;CCLCSWRPWPDTLOCRRC;;;PU)'
            if ( $res.ExitCode -eq 0 ) {
                Write-Log -Message 'OK' -Status OK -SubStepLevel 1
            }
            else {
                Write-Log -Message 'error:' -Status ERROR -SubStepLevel 1
                Write-Log -Message "Exit Code: $( $res.ExitCode )" -Status ERROR -SubStepLevel 1
                if ( [boolean]$res.StdOut ) {
                    Write-Log -Message "StdOut: $( $res.StdOut )" -Status ERROR -SubStepLevel 1
                }
                if ( [boolean]$res.StdErr ) {
                    Write-Log -Message "StdErr: $( $res.StdErr )" -Status ERROR -SubStepLevel 1
                }
            }
        #endregion reset BITS service

        #region reset WUAUSERV service
            Write-Log -Message 'reset WUAUSERV service' -Status INFO

            $res = Start-ProcessAdv -FilePath 'C:\Windows\System32\sc.exe' -ArgumentList 'sdset wuauserv D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;AU)(A;;CCLCSWRPWPDTLOCRRC;;;PU)'
            if ( $res.ExitCode -eq 0 ) {
                Write-Log -Message 'OK' -Status OK -SubStepLevel 1
            }
            else {
                Write-Log -Message 'error:' -Status ERROR -SubStepLevel 1
                Write-Log -Message "Exit Code: $( $res.ExitCode )" -Status ERROR -SubStepLevel 1
                if ( [boolean]$res.StdOut ) {
                    Write-Log -Message "StdOut: $( $res.StdOut )" -Status ERROR -SubStepLevel 1
                }
                if ( [boolean]$res.StdErr ) {
                    Write-Log -Message "StdErr: $( $res.StdErr )" -Status ERROR -SubStepLevel 1
                }
            }
        #endregion reset WUAUSERV service

        #region reregister dll's
            Write-Log -Message 'reregister dll''s ...' -Status INFO

            $dlls = @(
                'atl.dll',
                'urlmon.dll',
                'mshtml.dll',
                'shdocvw.dll',
                'browseui.dll',
                'jscript.dll',
                'vbscript.dll',
                'scrrun.dll',
                'msxml.dll',
                'msxml3.dll',
                'msxml6.dll',
                'actxprxy.dll',
                'softpub.dll',
                'wintrust.dll',
                'dssenh.dll',
                'rsaenh.dll',
                'gpkcsp.dll',
                'sccbase.dll',
                'slbcsp.dll',
                'cryptdlg.dll',
                'oleaut32.dll',
                'ole32.dll',
                'shell32.dll',
                'initpki.dll',
                'wuapi.dll',
                'wuaueng.dll',
                'wuaueng1.dll',
                'wucltui.dll',
                'wups.dll',
                'wups2.dll',
                'wuweb.dll',
                'qmgr.dll',
                'qmgrprxy.dll',
                'wucltux.dll',
                'muweb.dll',
                'wuwebv.dll'
            )
            foreach ( $dll in $dlls ) {
                $dllPath = ( Join-Path -Path $env:SystemRoot -ChildPath "system32\$dll" )
                if ( Test-Path -Path $dllPath ) {
                    Write-Log -Message $dllPath -Status INFO -SubStepLevel 1
                    $res = Start-ProcessAdv -FilePath "C:\Windows\System32\regsvr32.exe" -ArgumentList "/s $dllPath"

                    if ( $res.ExitCode -eq 0 ) {
                        Write-Log -Message 'OK' -Status OK -SubStepLevel 2
                    }
                    else {
                        Write-Log -Message 'error:' -Status ERROR -SubStepLevel 1
                        Write-Log -Message "Exit Code: $( $res.ExitCode )" -Status ERROR -SubStepLevel 2
                        if ( [boolean]$res.StdOut ) {
                            Write-Log -Message "StdOut: $( $res.StdOut )" -Status ERROR -SubStepLevel 2
                        }
                        if ( [boolean]$res.StdErr ) {
                            Write-Log -Message "StdErr: $( $res.StdErr )" -Status ERROR -SubStepLevel 2
                        }
                    }
                }
            }
        #endregion reregister dll's

        #region remove faulty registry values
            Write-Log -Message 'remove faulty registry values ...' -Status INFO

            Get-ItemProperty -Path 'HKLM:\'
        #endregion remove faulty registry values

        #region reset proxy
            Write-Log -Message 'reset proxy ...' -Status INFO

            Start-ProcessAdv -FilePath 'C:\Windows\System32\netsh.exe' -ArgumentList 'winhttp reset proxy'
        #endregion reset proxy

        #region start services
            Write-Log -Message 'start services ...' -Status INFO

            $Services = @('bits', 'wuauserv', 'appidsvc', 'cryptsvc')

            foreach ( $Service in $Services ) {
                Write-Log -Message $Service -Status INFO -SubStepLevel 1
                if ( Get-Service -Name $Service -ErrorAction SilentlyContinue ) {
                    try {
                        Start-Service -Name $Service -Confirm:$false
                        Write-Log -Message 'service started' -Status OK -SubStepLevel 2
                    }
                    catch {
                        Write-Log -Message 'couldn''t start service' -Status ERROR -SubStepLevel 2
                    }
                }
                else {
                    Write-Log -Message 'service doesn''t exist' -Status INFO -SubStepLevel 2
                }
            }
        #endregion start services


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
        Write-Log -Message "Content:     $($Content)" -Status ERROR -SubStepLevel 1
        if ( [boolean]$err.Exception.Message ) {
            Write-Log -Message $err.Exception.Message -Status ERROR -SubStepLevel 1
        }
    }
    else {
        Write-Output "Error Occured at:"
        if ( [boolean]$ScriptName ) {
            Write-Output "  ScriptName:  $($ScriptName)"
        }
        Write-Output "  LineNumber:  $($LineNumber)"
        Write-Output "  Col:         $($Col)"
        Write-Output "  Content:     $($Content)"
        if ( [boolean]$err.Exception.Message ) {
            Write-Output "  $( $err.Exception.Message )"
        }
    }
    Exit 1
}