function Start-ProcessAdv {
    <#
        .SYNOPSIS
            This function executes an executable file with parameters and and captures its exit code, stdout and stderr.

        .DESCRIPTION
            This function executes an executable file with parameters and and captures its exit code, stdout and stderr.

        .PARAMETER FileName
            the full path to the executable file

        .PARAMETER Arguments
            the arguments which should be transmitted to the executable process

        .PARAMETER VERB
            should the process run as Administrator

        .PARAMETER TimeOut
            TimeOut in seconds

        .PARAMETER WorkingDirectory
            the directory in which the procss should work
    #>
    [OutputType('PSCustomObject')]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [String]$FileName
        ,
        [Parameter(Mandatory=$false)]
        [String[]]$Arguments
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
    )

    # Setting process invocation parameters.
    $ProcessStartInfo = New-Object -TypeName System.Diagnostics.ProcessStartInfo
    $ProcessStartInfo.CreateNoWindow = $true
    $ProcessStartInfo.UseShellExecute = $false
    $ProcessStartInfo.RedirectStandardOutput = $true
    $ProcessStartInfo.RedirectStandardError = $true
    $ProcessStartInfo.FileName = $FileName
    if ( [boolean]$WorkingDirectory ) {
        $ProcessStartInfo.WorkingDirectory = $WorkingDirectory
    }

    if (! [String]::IsNullOrEmpty($Arguments)) {
        $ProcessStartInfo.Arguments = $Arguments
    }
    if (! [String]::IsNullOrEmpty($Verb)) {
        $ProcessStartInfo.Verb = $Verb
    }

    # Creating process object.
    $Process = New-Object -TypeName System.Diagnostics.Process
    $Process.StartInfo = $ProcessStartInfo

    # Creating string builders to store stdout and stderr.
    $oStdOutBuilder = New-Object -TypeName System.Text.StringBuilder
    $oStdErrBuilder = New-Object -TypeName System.Text.StringBuilder

    # Adding event handers for stdout and stderr.
    $ScripBlock = {
        if (! [String]::IsNullOrEmpty($EventArgs.Data)) {
            $Event.MessageData.AppendLine($EventArgs.Data)
        }
    }
    $StdOutEvent = Register-ObjectEvent -InputObject $Process `
        -Action $ScripBlock -EventName 'OutputDataReceived' `
        -MessageData $oStdOutBuilder
    $StdErrEvent = Register-ObjectEvent -InputObject $Process `
        -Action $ScripBlock -EventName 'ErrorDataReceived' `
        -MessageData $oStdErrBuilder

    # Starting process.
    [Void]$Process.Start()
    $Process.BeginOutputReadLine()
    $Process.BeginErrorReadLine()
    [Void]$Process.WaitForExit()

    # Unregistering events to retrieve process output.
    Unregister-Event -SourceIdentifier $StdOutEvent.Name
    Unregister-Event -SourceIdentifier $StdErrEvent.Name

    $oResult = New-Object -TypeName PSObject -Property ([Ordered]@{
        "ExeFile"   = $FileName;
        "Arguments" = $Arguments -join " ";
        "ExitCode"  = $Process.ExitCode;
        "StdOut"    = $oStdOutBuilder.ToString().Trim();
        "StdErr"    = $oStdErrBuilder.ToString().Trim()
    })

    return $oResult
}
