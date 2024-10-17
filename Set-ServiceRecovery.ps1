function Set-ServiceRecovery {
    <#
        .SYNOPSIS
            Set the Service Recovery options

        .DESCRIPTION
            Set the Service Recovery options

        .NOTES
            File-Name:  Set-ServiceRecovery.ps1
            Author:     Josh Burkard - josh@burkard.it
            Version:    1.0.0

            Changelog:
                    1.0.0,  2024-10-17, Josh Burkard, initial creation

        .PARAMETER ComputerName
            the name of a remote computer

            this string parameter is not mandatory, and use the local computer if not defined

        .PARAMETER ServiceName
            the name of service to set (not the Display Name)

            this string parameter is mandatory

        .PARAMETER action1
            the action which is executed when the service stops the first time

            this parameter allows this values:

            - none
            - reboot   --> restart the computer
            - restart  --> restart the service
            - run      --> runs a command

            this string parameter is not mandatory, if not defined 'restart' will be used.

        .PARAMETER action2
            the action which is executed when the service stops the second time

            this parameter allows this values:

            - none
            - reboot   --> restart the computer
            - restart  --> restart the service
            - run      --> runs a command

            this string parameter is not mandatory, if not defined 'restart' will be used.

        .PARAMETER actionLast
            the action which is executed when the service stops the third or more time

            this parameter allows this values:

            - none
            - reboot   --> restart the computer
            - restart  --> restart the service
            - run      --> runs a command

            this string parameter is not mandatory, if not defined 'restart' will be used.

        .PARAMETER time1
            the timeout in milliseconds to start the service the first time

            this string parameter is not mandatory, if not defined '30000' will be used.

        .PARAMETER time2
            the timeout in milliseconds to start the service the second time

            this string parameter is not mandatory, if not defined '30000' will be used.

        .PARAMETER timeLast
            the timeout in milliseconds to start the service the third or more time

            this string parameter is not mandatory, if not defined '30000' will be used.

        .PARAMETER resetcounter
            this parameter defines the Length of period of no failures (in seconds)
            after which to reset the failure count to 0

            this string parameter is not mandatory, if not defined '4000' will be used.

        .PARAMETER command
            this parameter defines the command to execute

            this string parameter is mandatory if one of the 3 actions has a 'run' definied. this parameter is only in this case visible

        .PARAMETER RebootMessage
            this parameter defines the message to display before a reboot

            this string parameter is mandatory if one of the 3 actions has a 'reboot' definied. this parameter is only in this case visible

        .LINK

            https://github.com/joshburkard/___PowerShell-Functions


        .EXAMPLE

            Set-ServiceRecovery -ServiceName sshd -action1 restart -action2 none -actionLast none

    #>
    [CmdletBinding()]
    param
    (
        [string] [Parameter(Mandatory=$true)] $ServiceName,
        [string] [Parameter(Mandatory=$false)] $ComputerName = $env:COMPUTERNAME,
        [ValidateSet('run','restart','reboot','none')]
        [string] $action1 = "restart",
        [int] $time1 =  30000, # in miliseconds
        [ValidateSet('run','restart','reboot','none')]
        [string] $action2 = "restart",
        [int] $time2 =  30000, # in miliseconds
        [ValidateSet('run','restart','reboot','none')]
        [string] $actionLast = "restart",
        [int] $timeLast = 30000, # in miliseconds
        [int] $resetCounter = 4000 # in seconds
        #,
        #[string]$command
        # ,
        # [string]$RebootMessage
    )
    DynamicParam {
        $paramDictionary = New-Object System.Management.Automation.RuntimeDefinedParameterDictionary
        # $attributeCollection = New-Object System.Collections.ObjectModel.Collection[System.Attribute]
        if ( 'run' -in @( $action1, $action2, $actionLast ) ) {
            $commandAttribute = New-Object System.Management.Automation.ParameterAttribute
            # $commandAttribute.Position = 3
            $commandAttribute.Mandatory = $true
            $commandAttribute.HelpMessage = "Please enter the command to execute:"
            $attributeCollection = New-Object System.Collections.ObjectModel.Collection[System.Attribute]
            $attributeCollection.Add($commandAttribute)
            $commandParam = New-Object System.Management.Automation.RuntimeDefinedParameter('command', [string], $attributeCollection)
            $paramDictionary.Add('command', $commandParam)
        }
        if ( 'reboot' -in @( $action1, $action2, $actionLast ) ) {
            $rebootMessageAttribute = New-Object System.Management.Automation.ParameterAttribute
            # $commandAttribute.Position = 3
            $rebootMessageAttribute.Mandatory = $true
            $rebootMessageAttribute.HelpMessage = "Please enter the RebootMessage:"
            $attributeCollection = New-Object System.Collections.ObjectModel.Collection[System.Attribute]
            $attributeCollection.Add($rebootMessageAttribute)
            $commandParam = New-Object System.Management.Automation.RuntimeDefinedParameter('RebootMessage', [string], $attributeCollection)
            $paramDictionary.Add('RebootMessage', $commandParam)
        }
        return $paramDictionary
    }
    Process {
        if ( ( 'reboot' -in @( $action1, $action2, $actionLast ) ) -and ( -not [boolean]$PSBoundParameters.RebootMessage ) ) {
            throw "a reboot message must be defined when reboot action is used"
        }
        if ( ( 'run' -in @( $action1, $action2, $actionLast ) ) -and ( -not [boolean]$PSBoundParameters.command ) ) {
            throw "a command must be defined when run action is used"
        }
        $serverPath = "\\" + $ComputerName
        $services = Get-CimInstance -ClassName 'Win32_Service' | Where-Object { $_.Name -imatch $ServiceName }

        foreach ( $service in $services ) {
            $ArgumentList = "$serverPath failure $($service.Name) actions= "
            <#
            if ( $action1 -eq 'none' ) { $action1_c = '""' } else { $action1_c = $action1 }
            if ( $action2 -eq 'none' ) { $action2_c = '""' } else { $action2_c = $action2 }
            if ( $actionLast -eq 'none' ) { $actionLast_c = '""' } else { $actionLast_c = $actionLast }
            #>
            $ArgumentList += $action1+"/"+$time1
            $ArgumentList += "/"+$action2+"/"+$time2
            $ArgumentList += "/"+$actionLast+"/"+$timeLast
            # $action = $action1+"/"+$time1+"/"+$action2+"/"+$time2+"/"+$actionLast+"/"+$timeLast

            if ( [boolean]$PSBoundParameters.command ) {
                $ArgumentList += " command= ""$( $PSBoundParameters.command )"""
            }
            if ( [boolean]$PSBoundParameters.RebootMessage ) {
                $ArgumentList += " reboot= ""$( $PSBoundParameters.RebootMessage )"""
            }

            $ArgumentList += " reset= $resetCounter"
            # https://technet.microsoft.com/en-us/library/cc742019.aspx
            # $output = sc.exe $serverPath failure $($service.Name) actions= $action reset= $resetCounter
            Start-ProcessAdv -FilePath 'C:\Windows\System32\sc.exe' -ArgumentList $ArgumentList
        }
    }
}