function Test-Port {
    <#
    .SYNOPSIS
        Tests port on computer.

    .DESCRIPTION
        Tests port on computer.

    .PARAMETER Computer
        Name of server to test the port connection on.

    .PARAMETER Port
        Port to test

    .PARAMETER Protocol
        TCP or UDP

    .PARAMETER TimeOut
        Sets a timeout for the port query. (In milliseconds, Default is 1000)

    .NOTES
        Name: Test-Port.ps1
        Author: Josua Burkard
        DateCreated: 16.05.2019
        List of Ports: http://www.iana.org/assignments/port-numbers

        To Do:
            Add capability to run background jobs for each host to shorten the time to scan.
    .LINK
        http://www.burkard.it

    .EXAMPLE
        Test-Port -Computer 'server' -Port 80
        Checks port 80 on server 'server' to see if it is listening

    .EXAMPLE
        Test-Port -Computer dc1 -port 17 -Protocol UDP -timeout 10000

        Server   : dc1
        Port     : 17
        TypePort : UDP
        Open     : True

    #>
    [cmdletbinding(
        ConfirmImpact = 'low'
    )]
    Param(
        [Parameter(Mandatory = $True)]
        [string]$Computer
        ,
        [Parameter(Mandatory = $True)]
        [string]$Port
        ,
        [Parameter(Mandatory = $False)]
        [int]$timeout=1000
        ,
        [Parameter(Mandatory = $False)]
        [Validateset('TCP','UDP')]
        [string]$Protocol = 'TCP'
    )
    Begin {
        #Typically you never do this, but in this case I felt it was for the benefit of the function
        #as any errors will be noted in the output of the report
        $ErrorActionPreference = "SilentlyContinue"
        $report = @()
    }
    Process {
        If ($Protocol -eq 'TCP' ) {
            #Create temporary holder
            $temp = "" | Select-Object Server, Port, TypePort, Open, Notes
            #Create object for connecting to port on computer
            $tcpobject = new-Object system.Net.Sockets.TcpClient
            #Connect to remote machine's port
            $connect = $tcpobject.BeginConnect($Computer,$Port,$null,$null)
            #Configure a timeout before quitting
            $wait = $connect.AsyncWaitHandle.WaitOne($timeout,$false)
            #If timeout
            If(!$wait) {
                #Close connection
                $tcpobject.Close()
                Write-Verbose "Connection Timeout"
                #Build report
                $temp.Server = $Computer
                $temp.Port = $Port
                $temp.TypePort = "TCP"
                $temp.Open = "False"
                $temp.Notes = "Connection to Port Timed Out"
            } Else {
                $error.Clear()
                try {
                    $tcpobject.EndConnect($connect) | out-Null
                }
                catch {
                }
                #If error
                If($error[0]){
                    #Begin making error more readable in report
                    [string]$string = ($error[0].exception).message
                    $message = (($string.split(":")[1]).replace('"',"")).TrimStart()
                    $failed = $true
                }
                #Close connection
                $tcpobject.Close()
                #If unable to query port to due failure
                If($failed){
                    #Build report
                    $temp.Server = $Computer
                    $temp.Port = $Port
                    $temp.TypePort = "TCP"
                    $temp.Open = "False"
                    $temp.Notes = "$message"
                } Else{
                    #Build report
                    $temp.Server = $Computer
                    $temp.Port = $Port
                    $temp.TypePort = "TCP"
                    $temp.Open = "True"
                    $temp.Notes = ""
                }
            }
            #Reset failed value
            $failed = $Null
            #Merge temp array with report
            $report += $temp
        }
        If ($Protocol -eq 'UDP' ) {
            #Create temporary holder
            $temp = "" | Select-Object Server, Port, TypePort, Open, Notes
            #Create object for connecting to port on computer
            $udpobject = new-Object system.Net.Sockets.Udpclient
            #Set a timeout on receiving message
            $udpobject.client.ReceiveTimeout = $Timeout
            #Connect to remote machine's port
            Write-Verbose "Making UDP connection to remote server"
            $udpobject.Connect("$Computer",$Port)
            #Sends a message to the host to which you have connected.
            Write-Verbose "Sending message to remote host"
            $a = new-object system.text.asciiencoding
            $byte = $a.GetBytes("$(Get-Date)")
            [void]$udpobject.Send($byte,$byte.length)
            #IPEndPoint object will allow us to read datagrams sent from any source.
            Write-Verbose "Creating remote endpoint"
            $remoteendpoint = New-Object system.net.ipendpoint([system.net.ipaddress]::Any,0)
            Try {
                #Blocks until a message returns on this socket from a remote host.
                Write-Verbose "Waiting for message return"
                $receivebytes = $udpobject.Receive([ref]$remoteendpoint)
                [string]$returndata = $a.GetString($receivebytes)
                If ($returndata) {
                    Write-Verbose "Connection Successful"
                    #Build report
                    $temp.Server = $Computer
                    $temp.Port = $Port
                    $temp.TypePort = "UDP"
                    $temp.Open = "True"
                    $temp.Notes = $returndata
                    $udpobject.close()
                }
            } Catch {
                If ($Error[0].ToString() -match "\bRespond after a period of time\b") {
                    #Close connection
                    $udpobject.Close()
                    #Make sure that the host is online and not a false positive that it is open
                    If (Test-Connection -comp $Computer -count 1 -quiet) {
                        Write-Verbose "Connection Open"
                        #Build report
                        $temp.Server = $Computer
                        $temp.Port = $Port
                        $temp.TypePort = "UDP"
                        $temp.Open = "True"
                        $temp.Notes = ""
                    } Else {
                        <#
                        It is possible that the host is not online or that the host is online,
                        but ICMP is blocked by a firewall and this port is actually open.
                        #>
                        Write-Verbose "Host maybe unavailable"
                        #Build report
                        $temp.Server = $Computer
                        $temp.Port = $Port
                        $temp.TypePort = "UDP"
                        $temp.Open = "False"
                        $temp.Notes = "Unable to verify if port is open or if host is unavailable."
                    }
                } ElseIf ($Error[0].ToString() -match "forcibly closed by the remote host" ) {
                    #Close connection
                    $udpobject.Close()
                    Write-Verbose "Connection Timeout"
                    #Build report
                    $temp.Server = $Computer
                    $temp.Port = $Port
                    $temp.TypePort = "UDP"
                    $temp.Open = "False"
                    $temp.Notes = "Connection to Port Timed Out"
                } Else {
                    $udpobject.close()
                }
            }
            #Merge temp array with report
            $report += $temp
        }
    }
    End {
        #Generate Report
        $report
    }
}