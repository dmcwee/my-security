param(
    [switch]$force
)

$json = Get-ChildItem -Path .\my-security.json -ErrorAction SilentlyContinue
if(($null -eq $json) -or ($force)) {
    Copy-Item .\my-security.template.json -Destination .\my-security.json
}

$psm = Get-ChildItem -Path .\my-security.psm1 -ErrorAction SilentlyContinue
if(($null -eq $psm) -or ($force)) {
    Copy-Item .\my-security.unsigned.psm1 -Destination .\my-security.psm1

    $cert = Get-ChildItem -Path Cert:\CurrentUser\My -DnsName my-security@davidmcwee.com -ErrorAction SilentlyContinue
    if(($null -eq $tCert) -or ($force)) {
        $cert = New-SelfSignedCertificate -DnsName my-security@davidmcwee.com -Type CodeSigning -CertStoreLocation Cert:\CurrentUser\My
        Export-Certificate -Cert $cert -FilePath my-security.crt
        Import-Certificate -FilePath .\my-security.crt -CertStoreLocation Cert:\CurrentUser\Root
    }

    Set-AuthenticodeSignature .\my-security.psm1 -Certificate $cert
}
