
Function Get-OktaSessionToken
{
    <#
        .SYNOPSIS
            Gets an Okta Session Token.

        .DESCRIPTION
            Gets and Okta Session Token. Okta Session Tokens are valid initial
            logons to Okta and cannot be used to directly access integrated
            applications.
        
        .PARAMETER OktaDomain
            The full Okta account domain. Example: mycompany.okta.com

        .PARAMETER Credential
            PSCredential to use for logon. If unspecified a GUI prompt will be
            issued.

        .EXAMPLE
            Get-OktaSessionToken -OktaDomain 'mycompany.okta.com' -Credential ( Get-Credential )
    #>

    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory=$true)]
        [String]$OktaDomain,

        [Parameter(Mandatory=$true)]
        [System.Management.Automation.PSCredential]$Credential = ( Get-Credential )
    )

    $OktaURI_Authn = ( 'https://{0}/api/v1/authn' -f $OktaDomain )
    $Parameters = @{
        'username'   = $Credential.UserName ;
        'password'   = $Credential.GetNetworkCredential().Password ;
    }

    Write-Verbose ( 'Attempting login to {0}.' -f $OktaURI_Authn )
    Try
    {
        $Response = Invoke-RestMethod `
            -URI $OktaURI_Authn `
            -Method Post `
            -Headers @{
                'Accept'       = 'application/json' ;
                'Content-Type' = 'application/json' ;
            } `
            -Body ( $Parameters | ConvertTo-Json )
    }
    Catch
    {
        Write-Error ( 'Could not log in. {0}' -f $_.Exception.Message )
        return
    }

    Write-Verbose ( 'Login result ''{0}''.' -f $Response.status )
    If ( $Response.status -like 'SUCCESS' ) # Login os OK, we're done.
    {
        $Response.sessionToken
    }
    ElseIf ( $Response.status -like 'MFA_REQUIRED' ) # Login requires MFA, find and use a factor.
    {
        Write-Verbose 'MFA required. Trying factors.'
        ForEach ( $Factor in $Response._embedded.factors )
        {
            Write-Verbose ( 'Attempting MFA {0}.' -f $Factor.factorType )
            If ( $Factor.factorType -like 'push' )
            {
                $OktaURI_Authn_Verify = ( 'https://{0}/api/v1/authn/factors/{1}/verify' -f @( $OktaDomain, $Factor.id ) )
                $Parameters = @{
                    'factorId'   = $Factor.id ;
                    'stateToken' = $Response.stateToken ;
                }
                
                While ( $true )
                {
                    Write-Verbose ( 'Attempting MFA via {0}.' -f $OktaURI_Authn_Verify )

                    Try
                    {
                        $VerifyResponse = Invoke-RestMethod `
                            -Uri $OktaURI_Authn_Verify `
                            -Method Post `
                            -Headers @{
                                'Accept'       = 'application/json' ;
                                'Content-Type' = 'application/json' ;
                            } `
                            -Body ( $Parameters | ConvertTo-Json )
                    }
                    Catch
                    {
                        Write-Error ( 'Could not complete MFA attempt. {0}' -f $_.Exception.Message )
                        continue
                    }
                    
                    If ( $VerifyResponse.status -like 'SUCCESS' )
                    {
                        $VerifyResponse.sessionToken
                        return
                    }
                    ElseIf ( $VerifyResponse.factorResult -like 'REJECTED' )
                    {
                        Write-Error ( 'MFA factor rejected. {0}.' -f $VerifyResponse.status )
                        continue
                    }
                    ElseIf ( $VerifyResponse.factorResult -like 'WAITING' )
                    {
                        Write-Verbose 'Waiting for factor.'
                        Start-Sleep -Seconds 5
                    }
                    Else
                    {
                        Write-Error ( 'Could not complete MFA attempt. {0}' -f $VerifyResponse.status )
                        continue
                    }
                }
            }
            Else
            {
                Write-Warning 'Skipping unsupported factor.'
            }

            Write-Error 'No suitable factors could be completed. (Currently only push is supported.)'
        }
    }
    Else
    {
        Write-Error ( 'Login failed. ''{0}''.' -f $Response.status )
    }
}

Function Get-OktaSAMLAssertion
{
    <#
        .SYNOPSIS
            Gets a SAML assertion for an Okta-integrated application.

        .DESCRIPTION
            Gets a SAML assertion for an Okta-integrated application.
        
        .PARAMETER OktaAppURI
            The full URI to the Okta app instance. This is the URI one would navigate to if clicking on the application instance in the Okta porta.

        .PARAMETER OktaSessionToken
            A valid Okta session token. See Get-OktaSessionToken .

        .EXAMPLE
            $Token = Get-OktaSessionToken -OktaDomain 'mycompany.okta.com' -Credential ( Get-Credential )
            Get-OktaSAMLAssertion -OktaAppUri 'https://mycompany.okta.com/home/SomeApp/AppID/Instance' -OktaSessionToken $Token
    #>

    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory=$true)]
        [String]$OktaAppURI,

        [Parameter(Mandatory=$true)]
        [String]$OktaSessionToken
    )

    Try
    {
        $Response = Invoke-WebRequest `
            -Uri ( '{0}?sessionToken={1}' -f @( $OktaAppURI, $OktaSessionToken ) ) `
            -UseBasicParsing # Deprecated in PS 6.0, required prior to avoid launching browser processes and to work on Core.
    }
    Catch
    {
        Write-Error ( 'Could not complete request for SAML assertion. {0}' -f $_.Exception.Message )
        return
    }
    
    If ( $Response.StatusCode -eq 200 )
    {
        [System.Web.HttpUtility]::HtmlDecode( $Response.InputFields[0].value ) # With -UseBasicParsing HTML entities are not automatically decoded
    }
    Else
    {
        Write-Error ( 'Web request failed. {0}.' -f $Response.StatusDescription )
    }
}
