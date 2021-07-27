#region set Certificate Policy
    Add-Type @"
    using System.Net;
    using System.Security.Cryptography.X509Certificates;
    public class TrustAllCertsPolicy : ICertificatePolicy {
        public bool CheckValidationResult( ServicePoint srvPoint, X509Certificate certificate, WebRequest request, int certificateProblem ) {
            return true;
        }
    }
"@
    [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
#endregion set Certificate Policy

#region set proxy
    $proxy = new-object System.Net.WebProxy
    [system.net.webrequest]::defaultwebproxy = $proxy
#endregion set proxy

#region test TLS connection protocol
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
#endregion test TLS connection protocol
