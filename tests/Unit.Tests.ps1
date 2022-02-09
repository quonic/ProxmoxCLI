$projectRoot = Resolve-Path "$PSScriptRoot\.."
$script:ModuleName = 'ProxmoxCLI'
$UnitTestSettingsFile = Resolve-Path "$projectRoot\tests\UTSettings.ps1"
. $UnitTestSettingsFile
$SecurePassword = $Password | ConvertTo-SecureString -AsPlainText -Force
$Credentials = New-Object System.Management.Automation.PSCredential -ArgumentList $UserName, $SecurePassword

Describe "Connect-PveServer" {
    Context "With BypassSSLCheck switch" {
        # arrange
        Mock Invoke-RestMethod -MockWith {
            return [PSCustomObject]@{
                data = @{
                    ticket              = 'asdfghjklqwertyuiop';
                    CSRFPreventionToken = 'zxcvbnmasdhjfkquieotwqwqyutibnxmczv';
                }
            }
        }

        # act
        Connect-PveServer -Server $Server -Credentials $Credentials -BypassSSLCheck

        # assert
        It "Should call 'Invoke-RestMethod' with the expected result" {
            Assert-MockCalled Invoke-RestMethod -Times 1 -Exactly
        }
        It "Should call 'GetCertificatePolicy' once" {
            Assert-MockCalled GetCertificatePolicy -Times 1 -Exactly
        }
        It "Should call 'GetTrustAllCertsPolicy' once" {
            Assert-MockCalled GetTrustAllCertsPolicy -Times 1 -Exactly
        }
        It "Should call 'SetCertificatePolicy' twice" {
            Assert-MockCalled SetCertificatePolicy -Times 2 -Exactly
        }

    }
    Context "With out BypassSSLCheck switch" {
        # arrange
        Mock Invoke-RestMethod -MockWith {
            return [PSCustomObject]@{
                data = @{
                    ticket              = 'asdfghjklqwertyuiop';
                    CSRFPreventionToken = 'zxcvbnmasdhjfkquieotwqwqyutibnxmczv';
                }
            }
        }

        # act
        Connect-PveServer -Server $Server -Credentials $Credentials

        # assert
        It "Should call 'Invoke-RestMethod' with the expected result" {
            Assert-MockCalled Invoke-RestMethod -Times 1 -Exactly
        }
        It "Should call 'GetCertificatePolicy' once" {
            Assert-MockCalled GetCertificatePolicy -Times 0 -Exactly
        }
        It "Should call 'GetTrustAllCertsPolicy' once" {
            Assert-MockCalled GetTrustAllCertsPolicy -Times 0 -Exactly
        }
        It "Should call 'SetCertificatePolicy' twice" {
            Assert-MockCalled SetCertificatePolicy -Times 0 -Exactly
        }
    }
} -Skip