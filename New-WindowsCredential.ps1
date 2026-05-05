function New-WindowsCredential {
    <#
        .SYNOPSIS
            Saves a credential to the Windows Credential Manager as a Generic credential.

        .PARAMETER TargetName
            The target name (label) used to identify the credential.

        .PARAMETER Credential
            The PSCredential object containing the username and password to store.

        .PARAMETER Persist
            How the credential is persisted. Defaults to LocalMachine.
            Session       - Credential is lost when the logon session ends.
            LocalMachine  - Credential persists for this machine and this user.
            Enterprise    - Credential is roamed to all machines in the domain.

        .EXAMPLE
            $cred = New-Object System.Management.Automation.PSCredential("myuser", (ConvertTo-SecureString "mypassword" -AsPlainText -Force))
            New-WindowsCredential -TargetName "MyAppCredential" -Credential $cred

    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$TargetName,
        [Parameter(Mandatory=$true)]
        [System.Management.Automation.PSCredential]$Credential,
        [Parameter(Mandatory=$false)]
        [ValidateSet('Session', 'LocalMachine', 'Enterprise')]
        [string]$Persist = 'LocalMachine'
    )

    $persistMap = @{ Session = 1; LocalMachine = 2; Enterprise = 3 }

    $code = @'
using System;
using System.Runtime.InteropServices;
public class WinCredManager {
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct CREDENTIAL {
        public uint Flags;
        public uint Type;
        public string TargetName;
        public string Comment;
        public System.Runtime.InteropServices.ComTypes.FILETIME LastWritten;
        public uint CredentialBlobSize;
        public IntPtr CredentialBlob;
        public uint Persist;
        public uint AttributeCount;
        public IntPtr Attributes;
        public string TargetAlias;
        public string UserName;
    }
    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool CredRead(string target, uint type, uint reservedFlag, out IntPtr credentialPtr);
    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool CredWrite([In] ref CREDENTIAL userCredential, [In] uint flags);
    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern void CredFree(IntPtr cred);
    public static System.Net.NetworkCredential GetCredential(string target) {
        IntPtr credPtr;
        if (!CredRead(target, 1, 0, out credPtr))
            throw new Exception("Credential not found in Windows Credential Manager: " + target);
        try {
            var cred = Marshal.PtrToStructure<CREDENTIAL>(credPtr);
            string password = Marshal.PtrToStringUni(cred.CredentialBlob, (int)(cred.CredentialBlobSize / 2));
            return new System.Net.NetworkCredential(cred.UserName, password);
        } finally {
            CredFree(credPtr);
        }
    }
    public static void WriteCredential(string target, string username, string password, uint persist) {
        byte[] passwordBytes = System.Text.Encoding.Unicode.GetBytes(password);
        IntPtr passwordPtr = Marshal.AllocHGlobal(passwordBytes.Length);
        try {
            Marshal.Copy(passwordBytes, 0, passwordPtr, passwordBytes.Length);
            CREDENTIAL cred = new CREDENTIAL {
                TargetName = target,
                UserName = username,
                CredentialBlob = passwordPtr,
                CredentialBlobSize = (uint)passwordBytes.Length,
                Type = 1,
                Persist = persist
            };
            if (!CredWrite(ref cred, 0))
                throw new Exception("Failed to write credential to Windows Credential Manager. Win32 error: " + Marshal.GetLastWin32Error());
        } finally {
            Marshal.FreeHGlobal(passwordPtr);
        }
    }
}
'@
    if (-not ([System.Management.Automation.PSTypeName]'WinCredManager').Type) {
        Add-Type -TypeDefinition $code
    }
    [WinCredManager]::WriteCredential(
        $TargetName,
        $Credential.UserName,
        $Credential.GetNetworkCredential().Password,
        [uint32]$persistMap[$Persist]
    )
}