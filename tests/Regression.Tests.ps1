$projectRoot = Resolve-Path "$PSScriptRoot\.."
$script:ModuleName = 'ProxmoxCLI'

Describe "Regression tests" -Tag Build {

    Context "Github Issues" {
        # $issues = Get-GitHubIssue -Uri 'https://github.com/quonic/ProxmoxCLI'
    }
}
