function Get-ScriptInformartion {
    [CmdletBinding()]
    Param()
    switch ( $ExecutionContext.Host.Name ) {
        "ConsoleHost" {
            Write-Verbose "Runbook is executed from PowerShell Console"
            if ( [boolean]$MyInvocation.ScriptName ) {
                if ( ( $MyInvocation.ScriptName ).EndsWith( ".psm1" ) ) {
                    $MyScriptPath = $Script:MyInvocation.ScriptName
                }
                else {
                    $MyScriptPath = $MyInvocation.ScriptName
                }
            }
            elseif ( [boolean]$MyInvocation.MyCommand ) {
                if ( ( $MyInvocation.MyCommand.Source ).EndsWith( ".psm1" ) ) {
                    $MyScriptPath = [System.IO.FileInfo]$Script:MyInvocation.MyCommand.Source
                }
                else {
                    $MyScriptPath = [System.IO.FileInfo]$MyInvocation.MyCommand.Source
                }
            }
        }
        "Visual Studio Code Host" {
            Write-Verbose 'Runbook is executed from Visual Studio Code'
            If ( [boolean]( $psEditor.GetEditorContext().CurrentFile.Path ) ) {
                Write-Verbose "c"
                $MyScriptPath = [System.IO.FileInfo]$psEditor.GetEditorContext().CurrentFile.Path
                # $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath(".\")
            }
            else {
                if ( ( [System.IO.FileInfo]$MyInvocation.ScriptName ).Extension -eq '.psm1' ) {
                    Write-Verbose "d1"

                    $PSCallStack = Get-PSCallStack
                    $MyScriptPath =[System.IO.FileInfo] @( $PSCallStack | Where-Object { $_.ScriptName -match '.ps1'} )[0].ScriptName
                }
                else {
                    Write-Verbose "d2"
                    $MyScriptPath = [System.IO.FileInfo]$MyInvocation.scriptname
                }
            }
        }
        "Windows PowerShell ISE Host" {
            Write-Verbose 'Runbook is executed from ISE'
            <#
            if ( [boolean]$MyInvocation.ScriptName ) {
                Write-Verbose "  ScriptName"
            }
            elseif ( $MyInvocation.MyCommand ) {
                Write-Verbose "  MyCommand"
                if ( ( $MyInvocation.MyCommand.CommandType -eq 'Function' ) -or ( $MyInvocation.MyCommand.Source ).EndsWith( ".psm1" ) ) {
                    Write-Verbose "    Function"
                    $MyScriptPath = $Script:MyInvocation.MyCommand
                }
                else {
                    Write-Verbose "    direct"
                    $MyScriptPath = [System.IO.FileInfo]( $MyInvocation.MyCommand.Source )
                }
            }
            else {
            #>
                Write-Verbose "  CurrentFile"
                $MyScriptPath = [System.IO.FileInfo]( $psISE.CurrentFile.FullPath )
            # }
        }
    }

    $MyScriptPath
}

Remove-Variable -Name a
$a = Get-ScriptInformartion -Verbose
$a
<#
$a.
$a.CommandType
[System.IO.FileInfo]( $a.GetType()

$a
#>