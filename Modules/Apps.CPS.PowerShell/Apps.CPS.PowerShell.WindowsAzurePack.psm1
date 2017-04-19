##################################################################
# Module Manifest Name: Apps.CPS.PowerShell.WindowsAzurePack.psm1
# Module Manifest Description: Holds Windows Azure Pack related functions
# Author: Srinath Sadda
#################################################################

<#
    .SYNOPSIS
        CPS Windows Azure Pack Module.
    .DESCRIPTION
        Holds Windows Azure Pack related functions.
    .EXAMPLE
        Import-Module -Name .\Apps.CPS.PowerShell.psd1
    .NOTES
        Module Name: Apps.CPS.PowerShell.WindowsAzurePack.psm1
        Module Description: Holds Windows Azure Pack related functions.
        Author: Srinath Sadda
    .LINK
#>

Function Test-CPSWAPEndpoint {
    [CmdletBinding()]
    Param (
        [String] $Name,
        [System.Uri] $Address
    )
	
    Begin {
		If ($PSBoundParameters['Verbose']) {
			$VerbosePreference = "Continue"
		}
		If ($PSBoundParameters['Debug']) {
			$DebugPreference = "Continue"
			$ConfirmPreference = "None"
		}
        Write-Verbose -Message "[$((Get-Date).ToString())] [Test-CPSWAPEndpoint] [Wap Endpoint Name: $Name] [Uri: $Address]"
Add-Type -TypeDefinition @"
    using System.Collections.Generic;
    using System.Net;
    using System.Net.Security;
    using System.Security.Cryptography.X509Certificates;

    public static class SSLValidator
    {
        private static Stack<System.Net.Security.RemoteCertificateValidationCallback> funcs = new Stack<System.Net.Security.RemoteCertificateValidationCallback>();

        private static bool OnValidateCertificate(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors)
        {
            return true;
        }

        public static void OverrideValidation()
        {
            funcs.Push(ServicePointManager.ServerCertificateValidationCallback);
            // ServicePointManager.ServerCertificateValidationCallback = OnValidateCertificate;
            ServicePointManager.ServerCertificateValidationCallback += new System.Net.Security.RemoteCertificateValidationCallback(OnValidateCertificate);
        }

        public static void RestoreValidation()
        {
            if (funcs.Count > 0) {
                ServicePointManager.ServerCertificateValidationCallback = funcs.Pop();
            }
        }
    }
"@
        Write-Verbose -Message "[$((Get-Date).ToString())] [Test-CPSWAPEndpoint] [[SSLValidator]::OverrideValidation()] Overriding default certificate validation..."
        [SSLValidator]::OverrideValidation()
	}

	Process {
        $Stopwatch = New-Object System.Diagnostics.Stopwatch
        $TestResult = [PSCustomObject] @{
            Name = $Name
            Address = $Address
            Result = $False
            StatusCode = 0 # [enum]::GetValues([System.Net.HttpStatusCode])
            StatusDescription = $Null
        }

        Try {
            Write-Verbose -Message "[$((Get-Date).ToString())] [Test-CPSWAPEndpoint] $($MyInvocation.InvocationName) $Name"
            
            [System.Net.ServicePointManager]::DefaultConnectionLimit = 8
            [System.Net.ServicePointManager]::MaxServicePointIdleTime = 10000
            
            $WebRequest = [System.Net.WebRequest]::Create($Address)
            $WebRequest.Accept = "application/xml"
            $WebRequest.KeepAlive = $False
            
            Write-Verbose -Message "[$((Get-Date).ToString())] [Test-CPSWAPEndpoint] [HTTP/1.1] Request Method:  $($WebRequest.Method)"
            Write-Verbose -Message "[$((Get-Date).ToString())] [Test-CPSWAPEndpoint] [HTTP/1.1] Request Uri:  $($WebRequest.RequestUri)"
            Write-Verbose -Message "[$((Get-Date).ToString())] [Test-CPSWAPEndpoint] [HTTP/1.1] Request Headers:  $($WebRequest.Headers)"
            
            $WebResponse = $WebRequest.GetResponse()
            If ($WebResponse.StatusCode -ne [System.Net.HttpStatusCode]::OK) {
                Write-Error -Exception $(System.Exception("Response: {0} {1}" -f [Int]($WebResponse.StatusCode), $WebResponse.StatusDescription)) -ErrorAction Stop
            }

            Write-Verbose -Message "[$((Get-Date).ToString())] [Test-CPSWAPEndpoint] Response Status Code: $([Int]($WebResponse.StatusCode))"
            Write-Verbose -Message "[$((Get-Date).ToString())] [Test-CPSWAPEndpoint] Response Status Description: $($WebResponse.StatusDescription)"
            Write-Verbose -Message "[$((Get-Date).ToString())] [Test-CPSWAPEndpoint] Response Headers: $($WebResponse.Headers)"

            $WebResponseStream = (New-Object -TypeName System.IO.StreamReader -ArgumentList $WebResponse.GetResponseStream()).ReadToEnd()
            Write-Debug -Message "[$((Get-Date).ToString())] [Test-CPSWAPEndpoint] Debug Info (Response Stream): $WebResponseStream"
            
            $TestResult.Result = $True
            $TestResult.StatusCode = [Int] $WebResponse.StatusCode
            $TestResult.StatusDescription = $WebResponse.StatusDescription
        }
        Catch [System.Net.WebException] {
            $TestResult.Result = $False
            If (!$TestResult.StatusDescription) {
                If ($_.Exception.Response) {
                    $TestResult.StatusCode = [Int] $_.Exception.Response.StatusCode
                    $TestResult.StatusDescription = $_.Exception.Response.StatusDescription
                }
                Else {
                    $TestResult.StatusDescription = $_.Exception.Message
                }
            }
        }
        Catch [Exception] {
            Write-Error -Exception $_.Exception -Message $_.Exception.Message
            $TestResult.Result = $False
            If (!$TestResult.StatusDescription) {
                $TestResult.StatusDescription = $_.Exception.Message
            }
        }
        Finally {
            Write-Verbose -Message "[$((Get-Date).ToString())] [Test-CPSWAPEndpoint] $($MyInvocation.InvocationName) $Name"
            Write-Verbose -Message "[$((Get-Date).ToString())] [Test-CPSWAPEndpoint] Elapsed Time: $($Stopwatch.Elapsed)"
        }

        Write-Output -InputObject $TestResult
	}

	End {
        [SSLValidator]::RestoreValidation()
        [System.GC]::Collect()
	}
}

Function Test-CPSWAPServiceEndpoint {
    [CmdletBinding()]
    Param ()
	
    Begin {
		If ($PSBoundParameters['Verbose']) {
			$VerbosePreference = "Continue"
		}
		If ($PSBoundParameters['Debug']) {
			$DebugPreference = "Continue"
			$ConfirmPreference = "None"
		}

        $RootActivityId = $(Get-Date -Format "yyyymmss")
        $ActiveStepId = 0
        $TotalSteps = 12
        
        Try {
            $ActiveStepId++
            Write-Progress -Activity "Validating Windows Azure Pack (WAP) Service EndPoints.." -Status "Processing: Step ($ActiveStepId of $TotalSteps)" -Id $RootActivityId -PercentComplete (($ActiveStepId / $TotalSteps)*100) -CurrentOperation "Performing Initial Configuration Tasks.."
            $Prefix = $env:COMPUTERNAME.Split('-')[0]
            $SmaComputer = (Get-Random -InputObject @("$Prefix-SMA-01","$Prefix-SMA-02","$Prefix-SMA-03") -Count 1)
            Write-Verbose -Message "[$((Get-Date).ToString())] [Test-CPSWAPServiceEndpoint] SMA Computer Name: $SmaComputer"
        }
        Catch {
            Write-Error -Exception $_.Exception -Message $_.Exception.Message -ErrorAction Stop
        }

        $ExcludeProperties = @("PSComputerName","RunspaceId","PSShowComputerName","CimClass","CimInstanceProperties","CimSystemProperties")
	}

	Process {        
        Try {
            # Get WAP variables from SMA
            $ActiveStepId++
            Write-Progress -Activity "Validating Windows Azure Pack (WAP) Service EndPoints.." -Status "Processing: Step ($ActiveStepId of $TotalSteps)" -Id $RootActivityId -PercentComplete (($ActiveStepId / $TotalSteps)*100) -CurrentOperation "Getting WAP Variables From SMA.."
            $WAPInternalEndpointMap = Get-CPSSMAVariableValue -SmaComputer $SmaComputer -Name "WAPInternalEndpointMap"
            $WAPAdminSiteUri = Get-CPSSMAVariableValue -SmaComputer $SmaComputer -Name "WAPAdminSiteURI"
            $WAPAdfsUri = Get-CPSSMAVariableValue -SmaComputer $SmaComputer -Name "WAPAdfsURI"
            $WAPPublicEndpointMap = Get-CPSSMAVariableValue -SmaComputer $SmaComputer -Name "WAPPublicEndpointMap"
            $WAPAuthSiteUri = Get-CPSSMAVariableValue -SmaComputer $SmaComputer -Name "WapAuthSiteURI"
            $WAPTenantSiteUri = Get-CPSSMAVariableValue -SmaComputer $SmaComputer -Name "WapTenantSiteURI"
            $WAPTenantPublicAPIUri = Get-CPSSMAVariableValue -SmaComputer $SmaComputer -Name "WAPTenantPublicAPIURI"

            # Construct list of WAP endpoints to verify.
            # Note: For MgmtSvc-TenantSite (VIP & FQDN), we need to test the connectvity from a NAT VM.
            
            $WAPEndpoints = @()
            $WAPEndpoints += New-Object -TypeName PSObject -Property @{
                Name = "MgmtSvc-AdminSite (VIP)"
                Address = (New-Uri -BaseUri $WAPInternalEndpointMap."MgmtSvc-AdminSite")
                RemoteComputer = $Null
            }
            $WAPEndpoints += New-Object -TypeName PSObject -Property @{
                Name = "MgmtSvc-AdminSite (FQDN)"
                Address = (New-Uri -BaseUri $WAPAdminSiteUri)
                RemoteComputer = $Null
            }
            $WAPEndpoints += New-Object -TypeName PSObject -Property @{
                Name = "ADFS (VIP)"
                Address = (New-Uri -BaseUri $WAPInternalEndpointMap."ADFS" -Path "/FederationMetadata/2007-06/FederationMetadata.xml")
                RemoteComputer = $Null
            }
            $WAPEndpoints += New-Object -TypeName PSObject -Property @{
                Name = "ADFS (FQDN)"
                Address = (New-Uri -BaseUri $WAPAdfsUri -Path "/FederationMetadata/2007-06/FederationMetadata.xml")
                RemoteComputer = $Null
            }
            $WAPEndpoints += New-Object -TypeName PSObject -Property @{
                Name = "MgmtSvc-AuthSite (VIP)"
                Address = (New-Uri -BaseUri $WAPPublicEndpointMap."MgmtSvc-AuthSite" -Path "/wsfederation/issue")
                RemoteComputer = $Null
            }
            $WAPEndpoints += New-Object -TypeName PSObject -Property @{
                Name = "MgmtSvc-AuthSite (FQDN)"
                Address = (New-Uri -BaseUri $WAPAuthSiteUri -Path "/wsfederation/issue")
                RemoteComputer = $Null
            }

            #region MgmtSvc-TenantSite
            If ($WAPPublicEndpointMap."MgmtSvc-TenantSite".Split(':')[2].TrimEnd('/') -ne 443) {
                $TenantSiteVIPIUri = $WAPPublicEndpointMap."MgmtSvc-TenantSite".Substring(0,$WAPPublicEndpointMap."MgmtSvc-TenantSite".LastIndexOf(':'))
                $WAPEndpoints += New-Object -TypeName PSObject -Property @{
                    Name = "MgmtSvc-TenantSite (VIP)"
                    Address = (New-Uri -BaseUri "$($TenantSiteVIPIUri):443" -Path "/ping")
                    RemoteComputer = $Null
                }
            }
            Else {
                $WAPEndpoints += New-Object -TypeName PSObject -Property @{
                    Name = "MgmtSvc-TenantSite (VIP)"
                    Address = (New-Uri -BaseUri $WAPPublicEndpointMap."MgmtSvc-TenantSite" -Path "/ping")
                    RemoteComputer = $Null
                }
            }
            #endregion

            #region MgmtSvc-TenantSite (FQDN)
            $WAPEndpoints += New-Object -TypeName PSObject -Property @{
                Name = "MgmtSvc-TenantSite (FQDN)"
                Address = (New-Uri -BaseUri $WAPTenantSiteUri)
                RemoteComputer = "$Prefix-$((Get-Random -InputObject @("1N0201", "1N0202") -Count 1)).$env:USERDNSDOMAIN"
            }
            #endregion

            #region MgmtSvc-TenantPublicAPI (VIP)
            If ($WAPPublicEndpointMap."MgmtSvc-TenantPublicAPI".Split(':')[2].TrimEnd('/') -ne 443) {
                $TenantPublicAPIUri = $WAPPublicEndpointMap."MgmtSvc-TenantPublicAPI".Substring(0,$WAPPublicEndpointMap."MgmtSvc-TenantPublicAPI".LastIndexOf(':'))
                $WAPEndpoints += New-Object -TypeName PSObject -Property @{
                    Name = "MgmtSvc-TenantPublicAPI (VIP)"
                    Address = (New-Uri -BaseUri "$($TenantPublicAPIUri):443" -Path "/ping")
                    RemoteComputer = $Null
                }
            }
            Else {
                $WAPEndpoints += New-Object -TypeName PSObject -Property @{
                    Name = "MgmtSvc-TenantPublicAPI (VIP)"
                    Address = (New-Uri -BaseUri $WAPPublicEndpointMap."MgmtSvc-TenantPublicAPI" -Path "/ping")
                    RemoteComputer = $Null
                }
            }
            #endregion

            #region MgmtSvc-TenantPublicAPI (FQDN)
            If ($WAPTenantPublicAPIUri.Split(':')[2].TrimEnd('/') -ne 443) {
                $TenantPublicAPIFQDNUri = $WAPTenantPublicAPIUri.Substring(0,$WAPTenantPublicAPIUri.LastIndexOf(':'))
                $WAPEndpoints += New-Object -TypeName PSObject -Property @{
                    Name = "MgmtSvc-TenantPublicAPI (FQDN)"
                    Address = (New-Uri -BaseUri "$($TenantPublicAPIFQDNUri):443" -Path "/ping")
                    RemoteComputer = $Null
                }
            }
            Else {
                $WAPEndpoints += New-Object -TypeName PSObject -Property @{
                    Name = "MgmtSvc-TenantPublicAPI (FQDN)"
                    Address = (New-Uri -BaseUri $WAPTenantPublicAPIUri -Path "/ping")
                    RemoteComputer = $Null
                }
            }
            #endregion

            # Test WAP endpoints
            ForEach ($WAPEndpoint in $WAPEndpoints) {
                $ActiveStepId++
                Write-Progress -Activity "Validating Windows Azure Pack (WAP) Service EndPoints.." -Status "Processing: Step ($ActiveStepId of $TotalSteps)" -Id $RootActivityId -PercentComplete (($ActiveStepId / $TotalSteps)*100) -CurrentOperation "Validating Service EndPoint: $($WAPEndpoint.Name) - $($WAPEndpoint.Address).."
                If ($Null -ne $WAPEndpoint.RemoteComputer) {
                    If (($PSBoundParameters['Verbose']) -and ($PSBoundParameters['Debug'])) {
                        $WapEndpointStatus = Invoke-CommandV2 -ComputerName $WAPEndpoint.RemoteComputer -ScriptBlock {
                            Test-CPSWAPEndpoint -Name $args[0] -Address $args[1] -Verbose -Debug
                        } -ArgumentList @($WAPEndpoint.Name, $WAPEndpoint.Address) | Select-Object * -ExcludeProperty $ExcludeProperties
                    }
                    ElseIf ($PSBoundParameters['Verbose']) {
                        $WapEndpointStatus = Invoke-CommandV2 -ComputerName $WAPEndpoint.RemoteComputer -ScriptBlock {
                            Test-CPSWAPEndpoint -Name $args[0] -Address $args[1] -Verbose
                        } -ArgumentList @($WAPEndpoint.Name, $WAPEndpoint.Address) | Select-Object * -ExcludeProperty $ExcludeProperties
                    }
                    ElseIf ($PSBoundParameters['Debug']) {
                        $WapEndpointStatus = Invoke-CommandV2 -ComputerName $WAPEndpoint.RemoteComputer -ScriptBlock {
                            Test-CPSWAPEndpoint -Name $args[0] -Address $args[1] -Debug
                        } -ArgumentList @($WAPEndpoint.Name, $WAPEndpoint.Address) | Select-Object * -ExcludeProperty $ExcludeProperties
                    }
                    Else {
                        $WapEndpointStatus = Invoke-CommandV2 -ComputerName $WAPEndpoint.RemoteComputer -ScriptBlock {
                            Test-CPSWAPEndpoint -Name $args[0] -Address $args[1]
                        } -ArgumentList @($WAPEndpoint.Name, $WAPEndpoint.Address) | Select-Object * -ExcludeProperty $ExcludeProperties
                    }
                }
                Else {
                    $WapEndpointStatus = Test-CPSWAPEndpoint -Name $WAPEndpoint.Name -Address $WAPEndpoint.Address
                }
                Write-Debug -Message "[$((Get-Date).ToString())] [Test-CPSWAPServiceEndpoint] Debug Info (Wap Service Endpoints Status): $($WapEndpointStatus | ConvertTo-Json -Compress)"
                Write-Output -InputObject $WapEndpointStatus
            }
        }
        Catch {
            Write-Error -Exception $_.Exception -Message $_.Exception.Message
        }
	}

	End {
		[System.GC]::Collect()
	}
}

Function Test-CPSWAPSTSTrust {
    <#
        .SYNOPSIS
            Validates Tenant and Admin portals against their STS token-signing certificates.
        .DESCRIPTION
            Validates Tenant and Admin portals against their STS token-signing certificates.
        .EXAMPLE
            Test-CPSWAPSTSTrust -Verbose
    #>
    
    [CmdletBinding()]
    [OutputType([System.Object])]
    Param (
    )
	
    Begin {
		If ($PSBoundParameters['Verbose']) {
			$VerbosePreference = "Continue"
		}
		If ($PSBoundParameters['Debug']) {
			$DebugPreference = "Continue"
			$ConfirmPreference = "None"
		}

        $RootActivityId = $(Get-Date -Format "yyyymmss")
        $ActiveStepId = 0
        $TotalSteps = 5

        Try {
            $ActiveStepId++
            Write-Progress -Activity "Validating Windows Azure Pack (WAP) STS Token-Signing Certificates.." -Status "Processing: Step ($ActiveStepId of $TotalSteps)" -Id $RootActivityId -PercentComplete (($ActiveStepId / $TotalSteps)*100) -CurrentOperation "Performing Initial Configuration Tasks.."
            $SaveVerbosePreference = $VerbosePreference
            $VerbosePreference = "SilentlyContinue"
            Import-Module -Name Microsoft.SystemCenter.ServiceManagementAutomation -Verbose:$False
            Import-Module -Name MgmtSvcConfig -Verbose:$False
            $VerbosePreference = $SaveVerbosePreference
        }
        Catch {
            Write-Error -Exception $_.Exception -Message $_.Exception.Message -ErrorAction Stop
        }

        Try {
            # SMA Information
            $ActiveStepId++
            Write-Progress -Activity "Validating Windows Azure Pack (WAP) STS Token-Signing Certificates.." -Status "Processing: Step ($ActiveStepId of $TotalSteps)" -Id $RootActivityId -PercentComplete (($ActiveStepId / $TotalSteps)*100) -CurrentOperation "Getting SMA Information.."
            $Portals = @("Admin", "Tenant")
            $SmaServer = ((Get-SCService -Name SMA).ComputerTiers.VMs | Where-Object {($_.Enabled -eq $True) -and ($_.Status -eq "Running")}).Name | Get-Random
            $SmaWebServiceEndPoint = "https://$SmaServer"
            Write-Verbose -Message "[$((Get-Date).ToString())] [Test-CPSWAPSTSTrust] [SMA Server: $SmaServer]"
            Write-Debug -Message "[$((Get-Date).ToString())] [Test-CPSWAPSTSTrust] [SMA Web Service EndPoint = $SmaWebServiceEndPoint]"

            # WAP SQL Connection Information
            $ActiveStepId++
            Write-Progress -Activity "Validating Windows Azure Pack (WAP) STS Token-Signing Certificates.." -Status "Processing: Step ($ActiveStepId of $TotalSteps)" -Id $RootActivityId -PercentComplete (($ActiveStepId / $TotalSteps)*100) -CurrentOperation "Getting WAP SQL Connection Information.."
            $SqlServer = (Get-SmaVariable -WebServiceEndPoint $SmaWebServiceEndPoint -Name CpsServiceSettingsMap -ErrorAction Stop).Value.Katal.'CPS-Katal-SQLNetworkName'
            $SqlInstance = (Get-SmaVariable -WebServiceEndPoint $SmaWebServiceEndPoint -Name CpsServiceSettingsMap -ErrorAction Stop).Value.Katal.'CPS-Katal-SQLInstanceName'
            $StoreConnectionString = ('Data Source={0};Initial Catalog=Microsoft.MgmtSvc.Store;Integrated Security=True' -f $(($SqlServer + '\' + $SqlInstance).TrimEnd('\')))
            $PortalConfigStoreConnectionString = ('Data Source={0};Initial Catalog=Microsoft.MgmtSvc.PortalConfigStore;Integrated Security=True' -f $(($SqlServer + '\' + $SqlInstance).TrimEnd('\')))
            Write-Verbose -Message "[$((Get-Date).ToString())] [Test-CPSWAPSTSTrust] [SQL Server: $SqlServer]"
            Write-Verbose -Message "[$((Get-Date).ToString())] [Test-CPSWAPSTSTrust] [SQL Instance: $SqlInstance]"
            Write-Debug -Message "[$((Get-Date).ToString())] [Test-CPSWAPSTSTrust] [Store Connection String = $StoreConnectionString]"
            Write-Debug -Message "[$((Get-Date).ToString())] [Test-CPSWAPSTSTrust] [Portal ConfigStore Connection String = $PortalConfigStoreConnectionString]"
        }
        Catch {
            Write-Error -Exception $_.Exception -Message $_.Exception.Message -ErrorAction Stop
        }
	}

	Process {
        ForEach ($Portal in $Portals) {
            $ActiveStepId++
            $ProgressPreference = "Continue"
            Write-Progress -Activity "Validating Windows Azure Pack (WAP) STS Token-Signing Certificates.." -Status "Processing: Step ($ActiveStepId of $TotalSteps)" -Id $RootActivityId -PercentComplete (($ActiveStepId / $TotalSteps)*100) -CurrentOperation "Validating $Portal Portal.."
            Write-Verbose -Message "[$((Get-Date).ToString())] [Test-CPSWAPSTSTrust] [Portal: $Portal]"
            $ProgressPreference = "SilentlyContinue"
            
            # WAP Relying Party Settings (Certificates)
            $RelyingPartySettings = Get-MgmtSvcRelyingPartySettings -Target $Portal -ConnectionString $PortalConfigStoreConnectionString
            $RelyingPartyCertificates = $RelyingPartySettings.Certificates
            Write-Debug -Message "[$((Get-Date).ToString())] [Test-CPSWAPSTSTrust] Debug Info ($Portal Portal Relying Party Certificates): $($RelyingPartyCertificates | ConvertTo-Json)"

            # Decode each certificate stored in WAP's Relying Party Settings
            $DecodedWapCertificates = @()
            ForEach ($RelyingPartyCertificate in $RelyingPartyCertificates) {
                [System.Security.Cryptography.X509Certificates.X509Certificate2] $DecodedWapCertificate = [System.Convert]::FromBase64String($RelyingPartyCertificate)
                $DecodedWapCertificates += $DecodedWapCertificate
                Write-Verbose -Message "[$((Get-Date).ToString())] [Test-CPSWAPSTSTrust] [WAP Certificate Subject: $($DecodedWapCertificate.Subject)]"
                Write-Verbose -Message "[$((Get-Date).ToString())] [Test-CPSWAPSTSTrust] [WAP Certificate Thumbprint: $($DecodedWapCertificate.Thumbprint)]"
                Write-Verbose -Message "[$((Get-Date).ToString())] [Test-CPSWAPSTSTrust] [WAP Certificate Not Valid Before: $($DecodedWapCertificate.NotBefore)]"
                Write-Verbose -Message "[$((Get-Date).ToString())] [Test-CPSWAPSTSTrust] [WAP Certificate Not Valid After: $($DecodedWapCertificate.NotAfter)]"
            }
            Write-Debug -Message "[$((Get-Date).ToString())] [Test-CPSWAPSTSTrust] Debug Info (Decoded WAP Certificates): $($DecodedWapCertificates | ConvertTo-Json)"

            # Construct STS Metadata EndPoint Uri
            $STSMetaEndPoint = "$($RelyingPartySettings.EndPoint.GetLeftPart(1))/FederationMetadata/2007-06/FederationMetadata.xml"

            # Get Certificate Content from STS Metadata EndPoint
            [Xml] $STSMetaContent = (Invoke-WebRequest -UseBasicParsing -Uri $STSMetaEndPoint).Content
            $STSCertificates = ($STSMetaContent.EntityDescriptor.RoleDescriptor | Where-Object {$_.Type -eq "fed:SecurityTokenServiceType"}).KeyDescriptor | 
                    Where-Object {$_.Use -eq "signing"} | ForEach-Object {$_.KeyInfo.x509data.X509Certificate}
            Write-Debug -Message "[$((Get-Date).ToString())] [Test-CPSWAPSTSTrust] Debug Info ($Portal Portal STS Certificates): $($STSCertificates | ConvertTo-Json)"

            # Decode each cert stored in WAP's Relying Party Settings
            $DecodedSTSCertificates = @()
            ForEach ($STSCertificate in $STSCertificates) {
                [System.Security.Cryptography.X509Certificates.X509Certificate2] $DecodedSTSCertificate = [System.Convert]::FromBase64String($STSCertificate)
                $DecodedSTSCertificates += $DecodedSTSCertificate
                Write-Verbose -Message "[$((Get-Date).ToString())] [Test-CPSWAPSTSTrust] [STS Certificate Subject: $($DecodedSTSCertificate.Subject)]"
                Write-Verbose -Message "[$((Get-Date).ToString())] [Test-CPSWAPSTSTrust] [STS Certificate Thumbprint: $($DecodedSTSCertificate.Thumbprint)]"
                Write-Verbose -Message "[$((Get-Date).ToString())] [Test-CPSWAPSTSTrust] [STS Certificate Not Valid Before: $($DecodedSTSCertificate.NotBefore)]"
                Write-Verbose -Message "[$((Get-Date).ToString())] [Test-CPSWAPSTSTrust] [STS Certificate Not Valid After: $($DecodedSTSCertificate.NotAfter)]"
            }
            Write-Debug -Message "[$((Get-Date).ToString())] [Test-CPSWAPSTSTrust] Debug Info (($Portal Portal Decoded STS Certificates): $($DecodedSTSCertificates | ConvertTo-Json)"

            ForEach ($DecodedSTSCertificate in $DecodedSTSCertificates) {
                If ($DecodedSTSCertificate -notin $DecodedWapCertificates) {
                    Write-Warning -Message "[$((Get-Date).ToString())] [Test-CPSWAPSTSTrust] Certificate Thumbprint '$($DecodedSTSCertificate.Thumbprint)' is not trusted by WAP '$($Portal)' portal. Run Set-MgmtSvcRelyingParty to re-trust."
                    New-Object -TypeName PSObject -Property @{
                        Portal = $Portal
                        IsTrusted = $False
                        IsReTrustRequired = $True
                        Subject = $DecodedSTSCertificate.Subject
                        ThumbPrint = $DecodedSTSCertificate.Thumbprint
                        NotBefore = $DecodedSTSCertificate.NotBefore
                        NotAfter = $DecodedSTSCertificate.NotAfter
                    } | Select-Object Portal,IsTrusted,IsReTrustRequired,Subject,ThumbPrint,NotBefore,NotAfter
                }
                Else {
                    Write-Verbose -Message "[$((Get-Date).ToString())] [Test-CPSWAPSTSTrust] Certificate Thumbprint '$($DecodedSTSCertificate.Thumbprint)' is trusted by WAP '$($Portal)' portal. No further action required."
                    New-Object -TypeName PSObject -Property @{
                        Portal = $Portal
                        IsTrusted = $True
                        IsReTrustRequired = $False
                        Subject = $DecodedSTSCertificate.Subject
                        ThumbPrint = $DecodedSTSCertificate.Thumbprint
                        NotBefore = $DecodedSTSCertificate.NotBefore
                        NotAfter = $DecodedSTSCertificate.NotAfter
                    } | Select-Object Portal,IsTrusted,IsReTrustRequired,Subject,ThumbPrint,NotBefore,NotAfter
                }
            }
        }
	}

	End {
		[System.GC]::Collect()
	}
}