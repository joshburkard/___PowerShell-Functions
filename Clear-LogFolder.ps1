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
    $ChildItems = $AllChildItems | Where-Object { ( Get-Date $_.LastWriteTime ) -ge ( Get-Date ).AddDays( 0 - $MaxDays ) }
    $ChildItems = $ChildItems | Sort-Object LastWriteTime -Descending | Select-Object -First $MaxCount

    $RemoveItems = $AllChildItems | Where-Object { $_.Name -notin $ChildItems.Name }
    $RemoveItems | ForEach-Object { Remove-Item -Path $_.FullName -Confirm:$false -Force }
}