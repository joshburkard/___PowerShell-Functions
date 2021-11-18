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