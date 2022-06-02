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
    } )

    return $Result
}
