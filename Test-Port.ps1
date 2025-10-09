function Test-Port {
    <#
    .SYNOPSIS
        Tests network connection to a specific port on a remote computer.

    .DESCRIPTION
        Tests network connection to a specific port on a remote computer.

    .PARAMETER ComputerName
        Name of ComputerName to test the port connection on.

    .PARAMETER Port
        Port to test

        This parameter is mandatory when using protocols TCP or UDP

    .PARAMETER Protocol
        TCP, UDP, RPC or ICMP

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
        Test-Port -Computer 'ComputerName' -Port 80
        Checks port 80 on ComputerName 'ComputerName' to see if it is listening

    .EXAMPLE
        Test-Port -Computer dc1 -port 17 -Protocol UDP -timeout 10000

    .EXAMPLE
        Test-Port -Computer dc1 -port 17 -Protocol RPC

    .EXAMPLE
        Test-Port -Computer dc1 -port 17 -Protocol ICMP

    .OUTPUTS
        ComputerName   : dc1
        RemoteAddress  : 192.168.1.100
        RemotePort     : 17
        SourceAddress  : 192.168.20.20
        Protocol       : UDP
        TestSucceeded  : True
        Notes          :

    #>
    [cmdletbinding(
        ConfirmImpact = 'low'
    )]
    Param(
        [Parameter(Mandatory = $True)]
        [string]$ComputerName
        ,
        [Parameter(Mandatory = $False)]
        [string]$Port
        ,
        [Parameter(Mandatory = $False)]
        [int]$timeout=1000
        ,
        [Parameter(Mandatory = $False)]
        [Validateset('TCP','UDP', 'RPC', 'ICMP')]
        [string]$Protocol = 'TCP'
    )
    Begin {
        #Typically you never do this, but in this case I felt it was for the benefit of the function
        #as any errors will be noted in the output of the report
        $ErrorActionPreference = "SilentlyContinue"
        $report = @()

    }
    Process {
        function ConvertTo-IPv4Address {
            param (
                $ip
            )
            $ipObj = [System.Net.IPAddress]::Parse($ip)

            if ($ipObj.IsIPv4MappedToIPv6) {
                $ipv4 = $ipObj.MapToIPv4().ToString()
                Write-Verbose "Converted to IPv4: $ipv4"
                return $ipv4
            } else {
                Write-Verbose "Address is not IPv4-mapped IPv6: $($ipObj.ToString())"
                return $ipObj.ToString()
            }
        }

        function Test-ValidIPAddress {
            param (
                [string]$ip
            )
            return [System.Net.IPAddress]::TryParse($ip, [ref]$null)
        }

        function Resolve-Address {
            param (
                [string]$address
            )

            if (Test-ValidIPAddress -ip $address) {
                Write-Verbose "'$address' is a valid IP address."
                return $address
            } else {
                Write-Verbose "'$address' is not a valid IP address. Checking if it's a DNS name..."
                try {
                    $hostEntry = [System.Net.Dns]::GetHostEntry($address)
                    Write-Verbose "Resolved IP addresses:"
                    $hostEntry.AddressList | ForEach-Object { Write-Verbose $_.ToString() }
                    return $hostEntry.AddressList
                } catch {
                    throw "Could not resolve DNS name to an IP address."
                }
            }
        }

        $RemoteAddress = Resolve-Address -address $ComputerName

        #Create temporary holder
        $temp = "" | Select-Object ComputerName, RemoteAddress, RemotePort, SourceAddress, Protocol, TestSucceeded, Notes
        $temp.ComputerName = $ComputerName
        $temp.RemoteAddress = ConvertTo-IPv4Address($RemoteAddress)
        $temp.RemotePort = $Port
        $temp.Protocol = $Protocol

        switch ( $Protocol ) {
            'TCP' {
                $failed = $false
                #Create object for connecting to port on computer
                $tcpClient = new-Object System.Net.Sockets.TcpClient
                #Connect to remote machine's port
                $connect = $tcpClient.BeginConnect($ComputerName,$Port,$null,$null)
                #Configure a timeout before quitting
                $wait = $connect.AsyncWaitHandle.WaitOne($timeout,$false)
                #If timeout
                If(!$wait) {
                    #Close connection
                    $tcpClient.Close()
                    Write-Verbose "Connection Timeout"

                    $temp.TestSucceeded = $false
                    $temp.Notes = "Connection to Port Timed Out"
                } Else {
                    $error.Clear()
                    try {
                        $tcpClient.EndConnect($connect) | out-Null
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


                    try {
                        if ($tcpClient.Client -and $tcpClient.Client.LocalEndPoint) {
                            $temp.SourceAddress = ConvertTo-IPv4Address($tcpClient.Client.LocalEndPoint.Address.ToString())
                        }
                    } catch {
                        Write-Verbose "Could not retrieve source address: $_"
                    }
                    try {
                        $tcpClient.Close()
                        Write-Verbose "Closed TCP connection"
                    }
                    catch {
                        Write-Verbose "couldn't close TCP connection"
                    }

                    #If unable to query port to due failure
                    If ( [boolean]$failed ) {
                        Write-Verbose "tcp test failed"
                        $temp.TestSucceeded = $false
                        $temp.Notes = "$message"
                    }
                    else {
                        Write-Verbose "tcp test succeeded"
                        $temp.TestSucceeded = $true
                        $temp.Notes = ""
                    }
                }
                #Reset failed value
                $failed = $Null
            }
            'UDP' {
                #Create object for connecting to port on computer
                $udpClient = New-Object System.Net.Sockets.Udpclient
                #Set a timeout on receiving message
                $udpClient.client.ReceiveTimeout = $Timeout
                #Connect to remote machine's port
                Write-Verbose "Making UDP connection to remote ComputerName"
                $udpClient.Connect("$ComputerName",$Port)
                $temp.SourceAddress = ConvertTo-IPv4Address($udpClient.Client.LocalEndPoint.Address)
                #Sends a message to the host to which you have connected.
                Write-Verbose "Sending message to remote host"
                $a = new-object system.text.asciiencoding
                $byte = $a.GetBytes("$(Get-Date)")
                [void]$udpClient.Send($byte,$byte.length)
                #IPEndPoint object will allow us to read datagrams sent from any source.
                Write-Verbose "Creating remote endpoint"
                $remoteendpoint = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Any,0)
                Try {
                    #Blocks until a message returns on this socket from a remote host.
                    Write-Verbose "Waiting for message return"
                    $receivebytes = $udpClient.Receive([ref]$remoteendpoint)
                    [string]$returndata = $a.GetString($receivebytes)
                    If ($returndata) {
                        Write-Verbose "Connection Successful"
                        #Build report
                        $temp.TestSucceeded = $true
                        $temp.Notes = $returndata
                        $udpClient.close()
                    }
                } Catch {
                    If ($Error[0].ToString() -match "\bRespond after a period of time\b") {
                        #Close connection
                        $udpClient.Close()
                        #Make sure that the host is online and not a false positive that it is TestSucceeded
                        If (Test-Connection -comp $ComputerName -count 1 -quiet) {
                            Write-Verbose "Connection TestSucceeded"
                            #Build report
                            $temp.TestSucceeded = $true
                            $temp.Notes = ""
                        } Else {
                            <#
                            It is possible that the host is not online or that the host is online,
                            but ICMP is blocked by a firewall and this port is actually TestSucceeded.
                            #>
                            Write-Verbose "Host maybe unavailable"
                            #Build report
                            $temp.ComputerName = $ComputerName
                            $temp.RemoteAddress = $RemoteAddress
                            $temp.RemotePort = $Port
                            $temp.Protocol = "UDP"
                            $temp.TestSucceeded = $false
                            $temp.Notes = "Unable to verify if port is TestSucceeded or if host is unavailable."
                        }
                    } ElseIf ($Error[0].ToString() -match "forcibly closed by the remote host" ) {
                        #Close connection
                        $udpClient.Close()
                        Write-Verbose "Connection Timeout"
                        #Build report
                        $temp.ComputerName = $ComputerName
                        $temp.RemoteAddress = $RemoteAddress
                        $temp.RemotePort = $Port
                        $temp.Protocol = 'UDP'
                        $temp.TestSucceeded = $false
                        $temp.Notes = "Connection to Port Timed Out"
                    } Else {
                        $udpClient.close()
                    }
                }
            }
            'RPC' {
                $temp.RemotePort = 135
                Set-StrictMode -Version Latest
                $PInvokeCode = @'
                    using System;
                    using System.Collections.Generic;
                    using System.Runtime.InteropServices;

                    public class Rpc
                    {
                        // I found this crud in RpcDce.h

                        [DllImport("Rpcrt4.dll", CharSet = CharSet.Auto)]
                        public static extern int RpcBindingFromStringBinding(string StringBinding, out IntPtr Binding);

                        [DllImport("Rpcrt4.dll")]
                        public static extern int RpcBindingFree(ref IntPtr Binding);

                        [DllImport("Rpcrt4.dll", CharSet = CharSet.Auto)]
                        public static extern int RpcMgmtEpEltInqBegin(IntPtr EpBinding,
                                                                int InquiryType, // 0x00000000 = RPC_C_EP_ALL_ELTS
                                                                int IfId,
                                                                int VersOption,
                                                                string ObjectUuid,
                                                                out IntPtr InquiryContext);

                        [DllImport("Rpcrt4.dll", CharSet = CharSet.Auto)]
                        public static extern int RpcMgmtEpEltInqNext(IntPtr InquiryContext,
                                                                out RPC_IF_ID IfId,
                                                                out IntPtr Binding,
                                                                out Guid ObjectUuid,
                                                                out IntPtr Annotation);

                        [DllImport("Rpcrt4.dll", CharSet = CharSet.Auto)]
                        public static extern int RpcBindingToStringBinding(IntPtr Binding, out IntPtr StringBinding);

                        public struct RPC_IF_ID
                        {
                            public Guid Uuid;
                            public ushort VersMajor;
                            public ushort VersMinor;
                        }


                        // Returns a dictionary of <Uuid, port>
                        public static Dictionary<int, string> QueryEPM(string host)
                        {
                            Dictionary<int, string> ports_and_uuids = new Dictionary<int, string>();
                            int retCode = 0; // RPC_S_OK

                            IntPtr bindingHandle = IntPtr.Zero;
                            IntPtr inquiryContext = IntPtr.Zero;
                            IntPtr elementBindingHandle = IntPtr.Zero;
                            RPC_IF_ID elementIfId;
                            Guid elementUuid;
                            IntPtr elementAnnotation;

                            try
                            {
                                retCode = RpcBindingFromStringBinding("ncacn_ip_tcp:" + host, out bindingHandle);
                                if (retCode != 0)
                                    throw new Exception("RpcBindingFromStringBinding: " + retCode);

                                retCode = RpcMgmtEpEltInqBegin(bindingHandle, 0, 0, 0, string.Empty, out inquiryContext);
                                if (retCode != 0)
                                    throw new Exception("RpcMgmtEpEltInqBegin: " + retCode);

                                do
                                {
                                    IntPtr bindString = IntPtr.Zero;
                                    retCode = RpcMgmtEpEltInqNext (inquiryContext, out elementIfId, out elementBindingHandle, out elementUuid, out elementAnnotation);
                                    if (retCode != 0)
                                        if (retCode == 1772)
                                            break;

                                    retCode = RpcBindingToStringBinding(elementBindingHandle, out bindString);
                                    if (retCode != 0)
                                        throw new Exception("RpcBindingToStringBinding: " + retCode);

                                    string s = Marshal.PtrToStringAuto(bindString).Trim().ToLower();
                                    if(s.StartsWith("ncacn_ip_tcp:"))
                                        if (ports_and_uuids.ContainsKey(int.Parse(s.Split('[')[1].Split(']')[0])) == false) ports_and_uuids.Add(int.Parse(s.Split('[')[1].Split(']')[0]), elementIfId.Uuid.ToString());

                                    RpcBindingFree(ref elementBindingHandle);

                                }
                                while (retCode != 1772); // RPC_X_NO_MORE_ENTRIES

                            }
                            catch(Exception ex)
                            {
                                Console.WriteLine(ex);
                                return ports_and_uuids;
                            }
                            finally
                            {
                                RpcBindingFree(ref bindingHandle);
                            }

                            return ports_and_uuids;
                        }
                    }
'@

                [Bool]$EPMTestSucceeded = $False
                [Bool]$bolResult = $False
                $tcpClient = New-Object System.Net.Sockets.TcpClient

                Try {
                    $tcpClient.Connect($ComputerName, 135)
                    If ($tcpClient.Connected) {
                        $EPMTestSucceeded = $True
                    }
                    $temp.SourceAddress = ConvertTo-IPv4Address($tcpClient.Client.LocalEndPoint.Address)
                    $tcpClient.Close()
                    Write-Verbose "TCP Port 135 TestSucceeded"
                }
                Catch {
                    $tcpClient.Dispose()
                    Write-Verbose "TCP Port 135 closed"
                }

                If ($EPMTestSucceeded) {
                    try {
                        Add-Type $PInvokeCode

                        # Dictionary <Uuid, Port>
                        $RPC_ports_and_uuids = [Rpc]::QueryEPM($ComputerName)
                    }
                    catch {
                        $temp.TestSucceeded = $false
                        $temp.Notes = 'couldn''t receive RPC ports'
                    }
                    if ( [boolean]$RPC_ports_and_uuids ) {
                        try {
                            $temp.TestSucceeded = $true
                            $ClosedPorts = @()

                            $PortDeDup = ($RPC_ports_and_uuids.Keys) | Sort-Object -Unique
                            Foreach ($Port In $PortDeDup)
                            {
                                $tcpClient = New-Object System.Net.Sockets.TcpClient
                                Try
                                {
                                    $tcpClient.Connect($ComputerName, $Port)
                                    If ($tcpClient.Connected)
                                    {
                                        Write-Verbose "$Port Reachable"
                                    }
                                    $tcpClient.Close()
                                }
                                Catch
                                {
                                    $temp.TestSucceeded = $false
                                    $ClosedPorts += $Port

                                    Write-Verbose "$Port Unreachable"
                                    $tcpClient.Dispose()
                                }
                            }
                            if ( ! $temp.TestSucceeded ) {
                                $temp.Notes = "Ports $( $ClosedPorts -join ', ' ) are closed"
                            }
                        }
                        catch {
                            $temp.TestSucceeded = $false
                            $temp.Notes = 'couldn''t receive RPC ports'
                        }
                    }
                }
                else {
                    $temp.TestSucceeded = $false
                    $temp.Notes = "TCP Port 135 closed"
                }
            }
            'ICMP' {
                $temp.SourceAddress = (Test-Connection -ComputerName ($env:ComputerName) -IPv4 -Count 1).Address.IPAddressToString
                $t = Test-Connection -ComputerName $ComputerName -ErrorAction SilentlyContinue

                if ( [boolean]$t ) {
                    if ( ! [boolean]( $t | Where-Object { $_.Status -ne 'Success' } ) ) {
                        $temp.TestSucceeded = $true
                    }
                    else {
                        $temp.TestSucceeded = $false
                        $failedCount = @( $t | Where-Object { $_.Status -ne 'Success' } ).Count
                        $totalCount =@($t).Count
                        $temp.Notes = "${failedCount} of ${totalCount} ICMP pings failed"
                    }
                }
                else {
                    $temp.TestSucceeded = $false
                    $temp.Notes = $error[0]
                }
            }
        }
        #Merge temp array with report
        $report += $temp    }
    End {
        #Generate Report
        $report
    }
}