function Get-TrustAllCertsPolicy () {
    # Trust all certs as we don't use an internal CA
    # Remove this if you do use an internal CA or are using an external CA
    add-type @"
using System.Net;
using System.Security.Cryptography.X509Certificates;
public class TrustAllCertsPolicy : ICertificatePolicy {
    public bool CheckValidationResult(
        ServicePoint srvPoint, X509Certificate certificate,
        WebRequest request, int certificateProblem) {
        return true;
    }
}
"@
    
    return $(New-Object TrustAllCertsPolicy)
}

function Set-CertificatePolicy ($Func) {
    [System.Net.ServicePointManager]::CertificatePolicy = $Func
}

function Get-CertificatePolicy () {
    return [System.Net.ServicePointManager]::CertificatePolicy
}