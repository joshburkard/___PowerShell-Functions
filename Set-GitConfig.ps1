#region declaration
    $ProxyServer = "aproxy.corproot.net"
    $ProxyPort = 8080
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
            [ValidateSet('INFO', 'WARN', 'Warning', 'ERROR', 'VERBOSE', 'OK', 'END', 'START')]
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
                Add-Content -Path "$($LogFile)" -Value "$(([System.DateTime]::Now).ToString()) $( $Status.PadRight(8, ' ').ToUpper() ) - $Message" -ErrorAction Stop
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
            'Info'      {$FColor='gray'}
            'Warning'   {$FColor='yellow'}
            'Error'     {$FColor='red'}
            'Verbose'   {$FColor='yellow'}
            'Ok'        {$FColor='green'}
            Default     {$FColor='gray'}
        }

        if ( $NoOutput -eq $false ) {
            Write-Host "$(([System.DateTime]::Now).ToString()) [$($Status.PadRight(8, ' ').ToUpper())] - $($Message)"  -ForegroundColor $FColor
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

        $Result = New-Object -TypeName PSObject -Property ( [Ordered]@{
            "ExeFile"    = $FilePath;
            "Parameters" = $ArgumentList -join " ";
            "ExitCode"   = $Process.ExitCode;
            "StdOut"     = $StdOutBuilder.ToString().Trim();
            "StdErr"     = $StdErrBuilder.ToString().Trim()
        } )

        return $Result
    }

    function Invoke-GITCommand {
        Param (
            [Parameter(Mandatory=$true)]
            [string]$Command
            ,
            [Parameter(Mandatory=$false)]
            [string]$Message
            ,
            [Parameter(Mandatory=$false)]
            [int]$SubStepLevel = 0
            ,
            [Parameter(Mandatory=$false)]
            [string]$WorkingDirectory
            ,
            [Parameter(Mandatory=$false)]
            [switch]$Passthru
            ,
            [Parameter(Mandatory=$false)]
            [switch]$NoLog
        )
        $ParamsGeneral = @{}
        $ParamsLevel = @{}
        if ( [boolean]$Message ) {
            $ParamsGeneral.Add( 'Message', $Message )
        }
        else {
            $ParamsGeneral.Add( 'Message', $Command )
        }
        if ( [boolean]$SubStepLevel ) {
            $ParamsGeneral.Add( 'SubStepLevel', $SubStepLevel )
            $ParamsLevel.Add( 'SubStepLevel', $SubStepLevel )
        }
        $ProcessParams = @{
            FilePath     = 'git'
            ArgumentList = $Command
        }
        if ( [boolean]$WorkingDirectory ) {
            $ProcessParams.Add( 'WorkingDirectory', $WorkingDirectory )
        }
        $res = Start-ProcessAdv @ProcessParams

        if ( -not $NoLog ) {
            if ( $res.ExitCode -eq 0 ) {
                Write-Log -Status OK @ParamsGeneral
            }
            else {
                $CommandPart = @( $Command -split ' ' )[0]
                switch ( $CommandPart ) {
                    'config' {
                        switch ( $res.ExitCode ) {
                            1 {
                                Write-Log -Status ERROR @ParamsGeneral
                                Write-Log -Message "The section or key is invalid" -Status ERROR @ParamsLevel
                            }
                            2 {
                                Write-Log -Status ERROR @ParamsGeneral
                                Write-Log -Message "no section or name was provided" -Status ERROR @ParamsLevel
                            }
                            3 {
                                Write-Log -Status ERROR @ParamsGeneral
                                Write-Log -Message "the config file is invalid" -Status ERROR @ParamsLevel
                            }
                            4 {
                                Write-Log -Status ERROR @ParamsGeneral
                                Write-Log -Message "the config file cannot be written" -Status ERROR @ParamsLevel
                            }
                            5 {
                                Write-Log -Status WARN @ParamsGeneral
                                Write-Log -Message "you try to unset an option which does not exist" -Status WARN @ParamsLevel
                            }
                            6 {
                                Write-Log -Status ERROR @ParamsGeneral
                                Write-Log -Message "you try to use an invalid regexp" -Status ERROR @ParamsLevel
                            }
                        }
                    }
                }
                if ( [boolean]( $res.StdErr ) ) {
                    Write-Log -Message $res.StdErr -Status ERROR @ParamsLevel
                }
                elseif ( [boolean]( $res.StdOut ) ) {
                    Write-Log -Message $res.StdOut -Status ERROR @ParamsLevel
                }
            }
        }
        if ( $Passthru ) {
            return $res
        }
    }
#endregion functions

#region execution

    #region test connectivity to Proxy
        $ProxyConnection = [boolean]( Test-NetConnection -ComputerName $ProxyServer -Port $ProxyPort -WarningAction SilentlyContinue ).TcpTestSucceeded
    #endregion test connectivity to Proxy

    #region get git config
    $ConfiguredProxyHTTP = ( Invoke-GITCommand -Command 'config http.proxy' -Passthru -NoLog -WorkingDirectory $CurrentLocation ).StdOut
    $ConfiguredProxyHTTPS = ( Invoke-GITCommand -Command 'config https.proxy' -Passthru -NoLog -WorkingDirectory $CurrentLocation ).StdOut
    #endregion get git config

    #region configure git proxy
        if ( $ProxyConnection ) {
            $NeededProxy = "http://$( $ProxyServer ):$( $ProxyPort )"

            Invoke-GITCommand -Command "config --global --unset http.proxy" -SubStepLevel 1
            Invoke-GITCommand -Command "config --global --unset https.proxy" -SubStepLevel 1
            Invoke-GITCommand -Command "config --global --add http.proxy ${NeededProxy}" -SubStepLevel 1
            Invoke-GITCommand -Command "config --global --add https.proxy ${NeededProxy}" -SubStepLevel 1
        }
        else {
            Invoke-GITCommand -Command "config --global --unset http.proxy" -SubStepLevel 1
            Invoke-GITCommand -Command "config --global --unset https.proxy" -SubStepLevel 1
        }
    #endregion configure git proxy
#endregion execution