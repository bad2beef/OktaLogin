# OktaLogin
## About OktaLogin
See this module’s sister at https://github.com/bad2beef/AWSLogin . In order to facilitate pure PowerShell login for AWS CLI (which itself is Python-based, but no matter…) via Okta SSO one of course needs to handle that pesky Okta login to SAML assertion workflow. This is broken off here as a separate module so that it can be easily installed and used for any other application where you may wish to complete a login via Okta but maintain some programmatic control over behavior. ( *cough* scrapers *cough* fuzzers *cough* )

## Installation
This is a simple pure PowerShell module. Simply copy the contents of the repository into `Modules\OktaLogin` and you should be ready to go.
```powershell
PS> Set-Location $env:PSModulePath.Split( ';' )[0]
PS> git clone git@github.com:bad2beef/OktaLogin.git
Cloning into 'OktaLogin'...
remote: Counting objects: 4, done.
remote: Compressing objects: 100% (4/4), done.
remote: Total 4 (delta 0), reused 4 (delta 0), pack-reused 0
Receiving objects: 100% (4/4), done.
PS>
```
