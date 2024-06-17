<#
    .SYNOPSIS
        this script moves the recovery partition to the end of the disk

    .DESCRIPTION
        this script moves the recovery partition to the end of the disk

    .NOTES
        File-Name:  Move-OSDRecoveryPartition.ps1
        Author:     Josua Burkard - josua.burkard@sdworx.com
        Version:    1.0.00000
        Changelog:
            1.0.00000,  2024-03-06, Josua Burkard, initial creation

        Dependencies:
            this script is dependent from this modules.
                - PowerShell 5.1

            this script needs connection to:
                -

        Notes:
            this script is tested with GPT style disks on Windows 2022

            use this script with care on other Disk types or other Operating Systems

            a good backup or snapshot is recommended

    .LINK
        https://thedxt.ca/2023/06/moving-windows-recovery-partition-correctly/

    .EXAMPLE
        .\Move-OSDRecoveryPartition.ps1

#>
[CmdLetBinding()]
Param(
)
try {
    #region declaration
        $ErrorActionPreference = 'Stop'

        #region get current path of the started script file
            switch ( $ExecutionContext.Host.Name ) {
                "ConsoleHost" { Write-Verbose "Runbook is executed from PowerShell Console"; if ( [boolean]$MyInvocation.ScriptName ) { if ( ( $MyInvocation.ScriptName ).EndsWith( ".psm1" ) ) { $CurrentFile = [System.IO.FileInfo]$Script:MyInvocation.ScriptName } else { $CurrentFile = [System.IO.FileInfo]$MyInvocation.ScriptName } } elseif ( [boolean]$MyInvocation.MyCommand ) { if ( [boolean]$MyInvocation.MyCommand.Source ) { if ( ( $MyInvocation.MyCommand.Source ).EndsWith( ".psm1" ) ) { $CurrentFile = [System.IO.FileInfo]$Script:MyInvocation.MyCommand.Source } else { $CurrentFile = [System.IO.FileInfo]$MyInvocation.MyCommand.Source } } else { $CurrentFile = [System.IO.FileInfo]$MyInvocation.MyCommand.Path } } }
                "Visual Studio Code Host" { Write-Verbose 'Runbook is executed from Visual Studio Code'; If ( [boolean]( $psEditor.GetEditorContext().CurrentFile.Path ) ) { Write-Verbose "c"; $CurrentFile = [System.IO.FileInfo]$psEditor.GetEditorContext().CurrentFile.Path } else { if ( ( [System.IO.FileInfo]$MyInvocation.ScriptName ).Extension -eq '.psm1' ) { Write-Verbose "d1"; $PSCallStack = Get-PSCallStack; $CurrentFile =[System.IO.FileInfo] @( $PSCallStack | Where-Object { $_.ScriptName -match '.ps1'} )[0].ScriptName } else { Write-Verbose "d2";  $CurrentFile = [System.IO.FileInfo]$MyInvocation.scriptname } } }
                "Windows PowerShell ISE Host" { Write-Verbose 'Runbook is executed from ISE'; Write-Verbose "  CurrentFile"; $CurrentFile = [System.IO.FileInfo]( $psISE.CurrentFile.FullPath ) }
            }

            $CurrentPath = $CurrentFile.Directory.FullName
        #endregion get current path of the started script file
    #endregion declaration

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
                        'INFO', 'WARN', 'Warning', 'ERROR', 'VERBOSE', 'OK', 'END', 'START'
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
                    Add-Content -Path "$($LogFile)" -Value "$(([System.DateTime]::Now).ToString()) $( $Status.PadRight(8, ' ').ToUpper() ) - $( ''.PadRight( ($SubStepLevel * 2) , ' ')  )$Message" -ErrorAction Stop
                    $WriteSuccess = $true
                }
                catch {
                    # Write-Host "." -ForegroundColor Yellow -NoNewline
                    Start-Sleep -Milliseconds 10
                }
            } until ( ( $WriteSuccess -eq $true ) -or ( $retry -ge 5 ) )
            if ( $WriteSuccess -eq $false ) {
                Write-Host "couldn't write to log" -ForegroundColor Red
            }
            Switch ($Status) {
                'INFO'      {$FColor='gray'}
                'WARN'      {$FColor='yellow'}
                'ERROR'     {$FColor='red'}
                'VERBOSE'   {$FColor='yellow'}
                'OK'        {$FColor='green'}
                Default     {$FColor='gray'}
            }
            if ( $NoOutput -eq $false ) {
                Write-Host "$(([System.DateTime]::Now).ToString()) [$($Status.PadRight(8, ' ').ToUpper())] - $( ''.PadRight( ($SubStepLevel * 2) , ' ')  )$($Message)"  -ForegroundColor $FColor
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
            # define the path, where the log file of this script should be writen
            $PSDefaultParameterValues.Add( "Write-Log:LogName", "C:\Admin\Logs\OSD\$( Get-Date -Format "yyyyMMdd-HHmmss" )-$( $CurrentFile.BaseName ).log" )
            Write-Log -Message "started script $( $CurrentFile.Name )" -Status INFO
            Write-Log -Message "write log to file $( $PSDefaultParameterValues.'Write-Log:LogName' )" -Status INFO
        #endregion start logging

        #region get current recovery partition
            Write-Log -Message 'get current recovery partition ...' -Status INFO

            $RecoveryPartition = Get-Partition | Where-Object { $_.Type -eq 'Recovery' }

            if ( [boolean]$RecoveryPartition ) {
                Write-Log -Message "found  recovery partition:" -Status OK -SubStepLevel 1
                Write-Log -Message "Disk Number:      $( $RecoveryPartition.DiskNumber )" -Status OK -SubStepLevel 2
                Write-Log -Message "Partition Number: $( $RecoveryPartition.PartitionNumber )" -Status OK -SubStepLevel 2
            }
            else {
                if ( [System.IO.File]::Exists( 'C:\Windows\System32\Recovery\Winre.wim' ) ) {
                    Write-Log -Message "recovery partition was already disabled" -Status WARN -SubStepLevel 1
                }
                else {
                    Write-Log -Message "recovery partition was wrongly removed, can't recover it" -Status ERROR -SubStepLevel 1
                    Exit 2
                }
            }
        #endregion get current recovery partition

        #region disable Windows Recovery Environment
            if ( [boolean]$RecoveryPartition ) {
                Write-Log -Message 'disable Windows Recovery Environment ...' -Status INFO

                $res = Start-ProcessAdv -FilePath 'C:\Windows\System32\ReAgentc.exe' -ArgumentList '/disable'
                if ( $res.ExitCode -eq 0 ) {
                    Write-Log -Message 'OK' -Status OK -SubStepLevel 1
                }
                else {
                    Write-Log -Message 'failed:' -Status ERROR -SubStepLevel 1
                    if ( [boolean]$res.StdOut ) {
                        Write-Log -Message $res.StdOut -Status ERROR -SubStepLevel 2
                    }
                    if ( [boolean]$res.StdErr ) {
                        Write-Log -Message $res.StdErr -Status ERROR -SubStepLevel 2
                    }
                }
            }

            if ( [System.IO.File]::Exists( 'C:\Windows\System32\Recovery\Winre.wim' ) ) {
                Write-Log -Message "Recovery Partition was moved to C:\Windows\System32\Recovery\Winre.wim " -Status OK -SubStepLevel 1
            }
            else {
                Write-Log -Message "can't find file C:\Windows\System32\Recovery\Winre.wim, recovery not possible" -Status ERROR -SubStepLevel 1
            }
        #endregion disable Windows Recovery Environment

        #region remove existing recovery partition
            Write-Log -Message 'remove existing recovery partition ...' -Status INFO
            $RecoveryPartition | Remove-Partition -Confirm:$false
        #endregion remove existing recovery partition

        #region create new partition at the end of the disk
            Write-Log -Message 'create new partition at the end of the disk ...' -Status INFO

            $Disk = Get-Disk -Number $RecoveryPartition.DiskNumber
            Write-Log -Message "Disk Number: $( $RecoveryPartition.DiskNumber )" -Status INFO -SubStepLevel 1
            Write-Log -Message "Disk Size:   $( $Disk.Size )" -Status INFO -SubStepLevel 1
            Write-Log -Message "Partition Size: $( $RecoveryPartition.Size )" -Status INFO -SubStepLevel 1
            $PartitionOffset = ( $Disk.Size - $RecoveryPartition.Size - ( 1024*1024 ) )
            Write-Log -Message "Partition Offset: $( $PartitionOffset )" -Status INFO -SubStepLevel 1

            if ( $Disk.PartitionStyle -eq 'GPT' ) {
                $NewPartition = New-Partition -DiskNumber $RecoveryPartition.DiskNumber -Size $RecoveryPartition.Size -Offset $PartitionOffset -GptType '{de94bba4-06d1-4d40-a16a-bfd50179d6ac}'
            }
            else {
                $NewPartition = New-Partition -DiskNumber $RecoveryPartition.DiskNumber -Size $RecoveryPartition.Size -Offset $PartitionOffset
            }

            Write-Log -Message 'format as NTFS and label as Recovery ...' -Status INFO
            $NewPartition | Format-Volume -FileSystem NTFS -NewFileSystemLabel 'Recovery'
        #endregion create new partition at the end of the disk

        #region change attributes to new partition
            Write-Log -Message 'change attributes to new partition ...' -Status INFO

            switch ( $Disk.PartitionStyle ) {
                'GPT' {
                    Write-Log -Message 'partition style is GPT ...' -Status INFO -SubStepLevel 1
                    # $NewPartition | Set-Partition -GptType '{de94bba4-06d1-4d40-a16a-bfd50179d6ac}'
                    $Partition = Get-Partition -DiskNumber $RecoveryPartition.DiskNumber -PartitionNumber $RecoveryPartition.PartitionNumber

                    $InputString = @"
select disk $( $Disk.DiskNumber )
select partition $( $NewPartition.PartitionNumber )
set id=de94bba4-06d1-4d40-a16a-bfd50179d6ac
gpt attributes=0x8000000000000001
exit
"@
                    $res = $InputString | diskpart.exe

                }
                'MBR' {
                    Write-Log -Message 'partition style is MBR ...' -Status INFO -SubStepLevel 1
                    $InputString = @"
select disk $( $Disk.DiskNumber )
select partition $( $NewPartition.PartitionNumber )
set id=27
exit
"@
                    $res = $InputString | diskpart.exe

                }
            }
        #endregion change attributes to new partition

        #region re-enable Windows Recovery Environment
            Write-Log -Message 're-enable Windows Recovery Environment ...' -Status INFO
            $res = Start-ProcessAdv -FilePath 'C:\Windows\System32\ReAgentc.exe' -ArgumentList '/enable'

            if ( -not [System.IO.File]::Exists( 'C:\Windows\System32\Recovery\Winre.wim' ) ) {
                Write-Log -Message 'Recover Environment is enabled again' -Status OK -SubStepLevel 1
            }
            else {
                Write-Log -Message 'couldn''t enable Recover Environment' -Status ERROR -SubStepLevel 1
            }
        #endregion re-enable Windows Recovery Environment

        #region end script
            Write-Log -Message "script ended without failures" -Status OK
            Exit 0
        #endregion end script
    #endregion execution
}
catch {
    $err = $_
    $Error.Clear()
    $Content = $err.InvocationInfo.Line
    if ( [boolean]$Content ) {
        $Content = $Content.Trim()
    }
    $LineNumber = $err.InvocationInfo.ScriptLineNumber
    $Col = $err.InvocationInfo.OffsetInLine
    Write-Output "Error Occured at:"
    if ( ( Get-Command -Name Write-Log -ErrorAction SilentlyContinue ) -and ( $PSDefaultParameterValues.Keys -contains 'Write-Log:LogName' ) ) {
        Write-Log -Message $err -Status ERROR
        Write-Log -Message "  Script:      $( $CurrentFile.FullName )" -Status ERROR
        Write-Log -Message "  LineNumber:  $( $LineNumber )" -Status ERROR
        Write-Log -Message "  Col:         $( $Col )" -Status ERROR
        Write-Log -Message "  Content:     $( $Content )" -Status ERROR
        if ( [boolean]$err.Exception ) {
            Write-Log -Message "  Error:       $( $err.Exception.Message )" -Status ERROR
        }
    }
    else {
        Write-Output $err
        Write-Output "  Script:      $( $CurrentFile.FullName )"
        Write-Output "  LineNumber:  $( $LineNumber )"
        Write-Output "  Col:         $( $Col )"
        Write-Output "  Content:     $( $Content )"
        if ( [boolean]$err.Exception ) {
            Write-Output "  Error:       $( $err.Exception.Message )"
        }
    }
    Set-Location $CurrentPath
    Exit 1
}