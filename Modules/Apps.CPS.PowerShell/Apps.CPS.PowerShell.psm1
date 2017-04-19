#########################################################
# Module Manifest Name: Apps.CPS.PowerShell.psm1
# Module Manifest Description: Holds CPS generic functions
# Author: Srinath Sadda
#########################################################

<#
    .SYNOPSIS
        CPS Module.
    .DESCRIPTION
        Holds CPS generic functions.
    .EXAMPLE
        Import-Module -Name .\Apps.CPS.PowerShell.psd1
    .NOTES
        Module Name: Apps.CPS.PowerShell.psm1
        Module Description: Holds CPS generic functions.
        Author: Srinath Sadda
    .LINK
#>

Function New-CPSPSSession {
    [CmdletBinding(SupportsShouldProcess = $True, ConfirmImpact = "Low")]
    Param (
        [Parameter(
            Position = 0,
            Mandatory = $True
        )]
        [ValidateNotNullOrEmpty()]
        [Alias("Computer")]
        [String] $ComputerName,

        [Parameter(
            Position = 1,
            Mandatory = $True
        )]
        [ValidateNotNullOrEmpty()]
        [Alias("Authentication")]
        [System.Management.Automation.Runspaces.AuthenticationMechanism] $AuthenticationMechanism,

        [Parameter(
            Position = 2,
            Mandatory = $True
        )]
        [ValidateNotNullOrEmpty()]
        [Alias("Credential")]
        [System.Management.Automation.PSCredential] $PSCredential
    )

    Begin {
        If ($PSBoundParameters['Verbose']) {
            $VerbosePreference = "Continue"
        }
        If ($PSBoundParameters['Debug']) {
            $DebugPreference = "Continue"
            $ConfirmPreference = "None"
        }
    }

    Process {
        Try {
            If ($PSCmdlet.ShouldProcess($ComputerName)) {
                Write-Verbose -Message "[New-CPSPSSession] [New-PSSession] Creating a PSSession..."
                Write-Debug -Message "[New-CPSPSSession] [New-PSSession] [ComputerName: $ComputerName] [AuthenticationMechanism: $AuthenticationMechanism] [PSCredential (UserName): $($PSCredential.UserName)]"
                $PSSession = New-PSSession -ComputerName $ComputerName -Authentication $AuthenticationMechanism -Credential $PSCredential -ErrorAction Stop
                If ($PSSession.State -eq 'Opened') {
                    Write-Verbose -Message "[New-CPSPSSession] Successfully created a PSSession [Name: $($PSSession.Name)] [Id: $($PSSession.Id)] [State: $($PSSession.State)]"
                    Write-Output -InputObject $PSSession
                }
            }
        }
        Catch {
            Write-Error -Exception $_.Exception
        }
    }

    End {
        [System.GC]::Collect()
    }
}

Function Remove-CPSPSSession {
    [CmdletBinding(SupportsShouldProcess = $True, ConfirmImpact = "Low")]
    Param (
        [Parameter(
            Position = 0,
            Mandatory = $True
        )]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({
            If ($_.State -ne 'Opened') {
                Throw "THE GIVEN PSSession OBJECT IS CURRENTLY IN '$($_.State)' STATE!".ToUpper()
            }
            $True
        })]
        [System.Management.Automation.Runspaces.PSSession] $PSSession
    )

    Begin {
        If ($PSBoundParameters['Verbose']) {
            $VerbosePreference = "Continue"
        }
        If ($PSBoundParameters['Debug']) {
            $DebugPreference = "Continue"
            $ConfirmPreference = "None"
        }
    }

    Process {
        Try {
            If ($PSSession.State -eq 'Opened') {
                If ($PSCmdlet.ShouldProcess($($PSSession.Name))) {
                    Write-Verbose -Message "[Remove-CPSPSSession] Removing a PSSession [Name: $($PSSession.Name)] [Id: $($PSSession.Id)] [State: $($PSSession.State)]..."
                    Remove-PSSession -Session $PSSession -ErrorAction Stop
                }
            }
        }
        Catch {
            Write-Error -Exception $_.Exception
        }
    }

    End {
        [System.GC]::Collect()
    }
}

Function Get-CPSSSLCertificateStatus {
    [CmdletBinding()]
    Param (       
        [Parameter(
            Position = 0,
            Mandatory = $True,
            ParameterSetName = "ClusterType"
        )]
        [ValidateNotNullOrEmpty()]
        [ValidateSet("CC","MC")]
        [String] $ClusterType,

        [Parameter(
            Position = 0,
            Mandatory = $True,
            ParameterSetName = "Services"
        )]
        [ValidateNotNullOrEmpty()]
        [Array] $Services,

        [Parameter(
            Position = 1,
            Mandatory = $False,
            HelpMessage = "Specify maximum no. of threads. Default is 4 threads. Maximum is 8 threads:"
        )]
        [ValidateNotNullOrEmpty()]
        [ValidateRange(1,8)]
        [Int16] $MaxThreads = 4
    )

    Begin {
        If ($PSBoundParameters['Verbose']) {
            $VerbosePreference = "Continue"
        }
        If ($PSBoundParameters['Debug']) {
            $DebugPreference = "Continue"
            $ConfirmPreference = "None"
        }

        #region Import VMM Module
        Try {
            $SaveVerbosePreference = $VerbosePreference
            $VerbosePreference = "SilentlyContinue"
            Import-Module -Name BitsTransfer -Verbose:$False
            Import-Module -Name PSWorkflow -Verbose:$False
            Import-Module -Name VirtualMachineManager -Verbose:$False
            $VerbosePreference = $SaveVerbosePreference
        }
        Catch {
            Write-Error -Exception $_.Exception -Message $_.Exception.Message -ErrorAction Stop
        }
        #endregion

        #region Identify Computers
        $Computers = @()
        $VMMServer = Get-CPSVMMOwnerNode
        
        If ($PSBoundParameters['ClusterType']) {
            Switch ($ClusterType) {
                "CC" {
                    Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSSSLCertificateStatus] [Get-SCService] Getting services..."
                    $SCServices = Get-SCService -VMMServer $VMMServer | Where-Object {(@("Katal-Public","MgmtSvc-MySQL","MgmtSvc-SQLServer") -icontains $_.Name) -and ($_.VMHostGroup.Name -eq "Compute Clusters")}
                }
                "MC" {
                    Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSSSLCertificateStatus] [Get-SCService] Getting services..."
                    $SCServices = Get-SCService -VMMServer $VMMServer | Where-Object {(@("Katal","SMA","SPF") -icontains $_.Name) -and ($_.VMHostGroup.Name -eq "Management Cluster")}
                }
                default {
                    Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSSSLCertificateStatus] [Get-SCService] Getting services..."
                    $SCServices = Get-SCService -VMMServer $VMMServer
                }
            }
            Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSSSLCertificateStatus] Identified $($SCServices.Count) services."
        }
        ElseIf ($PSBoundParameters['Services']) {
            ForEach ($Service in $Services) {
                [Array] $SCServices += Get-SCService -VMMServer $VMMServer -Name $Service
            }
        }
        
        $Computers = $SCServices.ComputerTiers.VMs.ComputerName
        Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSSSLCertificateStatus] Identified $($Computers.Count) computers."

        $SCServices | ForEach-Object {
            [PSObject[]] $InputObjects += New-Object -TypeName PSObject -Property @{
                Cluster = $_.VMHostGroup.Name
                Service = $_.Name
                Computer = $_.ComputerTiers.VMs.ComputerName
            }
        }
        #endregion

        #region Script Block
        $ScriptBlock = {
            [CmdletBinding()]
            Param (       
                [Parameter(
                    Position = 0,
                    Mandatory = $True
                )]
                [ValidateNotNullOrEmpty()]
                [PSObject] $InputObject
            )

            $ExcludeProperties = @("PSComputerName","RunspaceId","PSShowComputerName","CimClass","CimInstanceProperties","CimSystemProperties")

            If ($PSBoundParameters['Verbose']) {
                $VerbosePreference = "Continue"
            }
            If ($PSBoundParameters['Debug']) {
                $DebugPreference = "Continue"
                $ConfirmPreference = "None"
            }

            #region Script Block 2
            $ScriptBlock2 = {
                [CmdletBinding()]
                Param (       
                    [Parameter(
                        Position = 0,
                        Mandatory = $True
                    )]
                    [ValidateNotNullOrEmpty()]
                    [PSObject] $InputObject
                )

                If ($PSBoundParameters['Verbose']) {
                    $VerbosePreference = "Continue"
                }
                If ($PSBoundParameters['Debug']) {
                    $DebugPreference = "Continue"
                    $ConfirmPreference = "None"
                }

                Try {
                    Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSSSLCertificateStatus] Importing module 'WebAdministration'..."
                    $SaveVerbosePreference = $VerbosePreference
                    $VerbosePreference = "SilentlyContinue"
                    Import-Module -Name WebAdministration -ErrorAction Stop
                    $VerbosePreference = $SaveVerbosePreference
                }
                Catch {
                    Write-Warning -Message "[$((Get-Date).ToString())] [Get-CPSSSLCertificateStatus] [$env:COMPUTERNAME] 'WebAdministration' module was not found! Skipped."
                    Continue
                }

                Try {
                    $WebSites = Get-ChildItem -Path "IIS:\Sites"
                    ForEach ($WebSite in $WebSites) {
                        ForEach ($Binding in $WebSite.Bindings.Collection) {
                            If ($Binding.Protocol -ieq "https") {
                                $Uri = (New-Object -TypeName System.UriBuilder($Binding.Protocol, $env:COMPUTERNAME, ($Binding.BindingInformation -split ':')[1])).Uri
                                $ThumbPrint = $Binding.CertificateHash
                                If ($ThumbPrint -eq "") {
                                    Write-Warning -Message "[$((Get-Date).ToString())] [Get-CPSSSLCertificateStatus] Certificate Hash (ThumbPrint) is empty for website '$($WebSite.Name)'! Skipped."
                                    Continue
                                }
                                $Certificate = Get-Item -Path "Cert:\LocalMachine\My\$ThumbPrint"
                                $IsExpired = $False
                                If (($Null -ne $Certificate.NotAfter) -and ($Certificate.NotAfter -ne "")) {
                                    $Days = ([DateTime] $Certificate.NotAfter - (Get-Date)).Days
                                    If ($Days -le 0) {
                                        $IsExpired = $True
                                    }
                                }
                                $CertificateInfo = New-Object -TypeName PSObject -Property @{
                                    Cluster = $InputObject.Cluster
                                    Service = $InputObject.Service
                                    Computer = $env:COMPUTERNAME
                                    WebSite = $WebSite.Name
                                    Uri = $Uri
                                    IsExpired = $IsExpired
                                    ThumbPrint = $ThumbPrint
                                    Subject = $Certificate.Subject
                                    NotBefore = $Certificate.NotBefore
                                    NotAfter = $Certificate.NotAfter
                                }
                                Write-Debug -Message "[$((Get-Date).ToString())] [Get-CPSSSLCertificateStatus] Debug Info (SSL Certificate Info): $($CertificateInfo | ConvertTo-Json)"
                                Write-Output -InputObject $CertificateInfo
                            }
                        }
                    }
                }
                Catch {
                    Write-Error -Exception $_.Exception -Message $_.Exception.Message
                }
            }
            #endregion

            $Computers = $InputObject.Computer
            [Array]::Sort($Computers)
            ForEach ($Computer in $Computers) {
                Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSSSLCertificateStatus] Getting SSL certificates status from computer [$Computer]..."
                Try {
                    If (Test-Connection -ComputerName $Computer -Count 1 -Quiet) {
                        $CertificateInfo = Invoke-Command -ComputerName $Computer -ScriptBlock $ScriptBlock2 -ArgumentList $InputObject -ErrorAction Stop
                        If ($Null -ne $CertificateInfo) {
                            Write-Output -InputObject $CertificateInfo | Select-Object * -ExcludeProperty $ExcludeProperties
                        }
                    }
                    Else {
                        Write-Warning -Message "[$((Get-Date).ToString())] [Get-CPSSSLCertificateStatus] Computer [$Computer] is not responding! Skipped."
                    }
                }
                Catch {
                    Write-Error -Exception $_.Exception -Message $_.Exception.Message
                }
            }
        }
        #endregion
    }

    Process {
        #region  Invoke-PSRunSpace
        If ($PSBoundParameters['Verbose'] -and $PSBoundParameters['Debug']) {
            Invoke-PSRunSpace -InputObject $InputObjects -ScriptBlock $ScriptBlock -MaxThreads $MaxThreads -SendInputObjectInstance -Verbose -Debug | 
                Where-Object { ($Null -ne ($_.PSObject.Properties | ForEach-Object { $_.Value })) }
        }
        ElseIf ($PSBoundParameters['Verbose']) {
            Invoke-PSRunSpace -InputObject $InputObjects -ScriptBlock $ScriptBlock -MaxThreads $MaxThreads -SendInputObjectInstance -Verbose | 
                Where-Object { ($Null -ne ($_.PSObject.Properties | ForEach-Object { $_.Value })) }
        }
        ElseIf ($PSBoundParameters['Debug']) {
            Invoke-PSRunSpace -InputObject $InputObjects -ScriptBlock $ScriptBlock -MaxThreads $MaxThreads -SendInputObjectInstance -Debug | 
                Where-Object { ($Null -ne ($_.PSObject.Properties | ForEach-Object { $_.Value })) }
        }
        Else {
            Invoke-PSRunSpace -InputObject $InputObjects -ScriptBlock $ScriptBlock -MaxThreads $MaxThreads -SendInputObjectInstance | 
                Where-Object { ($Null -ne ($_.PSObject.Properties | ForEach-Object { $_.Value })) }
        }
        #endregion
    }

    End {
        [System.GC]::Collect()
    }
}

Function Test-CPSCompliance {
    [CmdletBinding()]
    [OutputType([System.Object])]
    Param (
        [Parameter(
            Position = 0,
            Mandatory = $True
        )]
        [ValidateNotNullOrEmpty()]
        [ValidateSet("OSDReplacement")]
        [Alias("Scenario")]
        [String] $ComplianceScenario
    )
    DynamicParam {
        # Create a dictionary
        $RuntimeParameterDictionary = New-Object -TypeName System.Management.Automation.RuntimeDefinedParameterDictionary

        If ($PSBoundParameters['ComplianceScenario'] -eq "OSDReplacement") {
            # Set dynamic parameter name
            $ParameterNameVmHosts = 'VmHosts'

            # Create a collection attribute
            $AttributeCollectionVmHosts = New-Object -TypeName System.Collections.ObjectModel.Collection[System.Attribute]

            # Create and set parameter attributes
            $ParameterAttributeVmHosts = New-Object -TypeName System.Management.Automation.ParameterAttribute
            $ParameterAliasVmHosts = New-Object -TypeName System.Management.Automation.AliasAttribute -ArgumentList "Hosts"
            $ParameterAttributeVmHosts.Position = 1
            $ParameterAttributeVmHosts.Mandatory = $True

            # Add attributes to attributes collection
            $AttributeCollectionVmHosts.Add($ParameterAttributeVmHosts)
            $AttributeCollectionVmHosts.Add($ParameterAliasVmHosts)

            # Create and return dynamic parameter dictionary
            $RuntimeParameterVmHosts = New-Object -TypeName System.Management.Automation.RuntimeDefinedParameter($ParameterNameVmHosts, [String[]], $AttributeCollectionVmHosts)
            $RuntimeParameterDictionary.Add($ParameterNameVmHosts, $RuntimeParameterVmHosts)
        }
        Return $RuntimeParameterDictionary
    }
	
    Begin {
		If ($PSBoundParameters['Verbose']) {
			$VerbosePreference = "Continue"
		}
		If ($PSBoundParameters['Debug']) {
			$DebugPreference = "Continue"
			$ConfirmPreference = "None"
		}

        Try {
            $SaveVerbosePreference = $VerbosePreference
            $VerbosePreference = "SilentlyContinue"
            Import-Module -Name VirtualMachineManager -Verbose:$False
            Import-Module -Name OperationsManager -Verbose:$False
            Import-Module -Name NetworkTransition -Verbose:$False
            Import-Module -Name NetAdapter -Verbose:$False
            $VerbosePreference = $SaveVerbosePreference
        }
        Catch {
            Write-Error -Exception $_.Exception -Message $_.Exception.Message -ErrorAction Stop
        }

        $Prefix = $env:COMPUTERNAME.Split('-')[0]

        Try {
            # Bind parameters to friendly variables
            $VmHosts = $PsBoundParameters[$ParameterNameVmHosts]
        }
        Catch {
            Write-Error -Exception $_.Exception -Message $_.Exception.Message
        }
	}

	Process {
        #region OSDReplacement
        If ($PSBoundParameters['ComplianceScenario'] -eq "OSDReplacement") {
            Write-Verbose -Message "[$((Get-Date).ToString())] [Test-CPSCompliance] [Compliance Scenario: Operating System Drive (OSD) Replacement]"
            ForEach ($VmHost in $VmHosts) {
                Write-Verbose -Message "[$((Get-Date).ToString())] [Test-CPSCompliance] [Test-NetConnection] Verifying WinRM connectivity to host [$VmHost]..."
                $IsStorageNode = $False
                [HashTable] $HashTable = @{}
                $HashTable.Add("VmHost", $VmHost)
                
                If (!(Test-NetConnection -ComputerName $VmHost -CommonTCPPort WINRM -InformationLevel Quiet)) {
                    Write-Warning -Message "[$((Get-Date).ToString())] [Test-CPSCompliance] Can't establish connection!"
                    Continue
                }
                Write-Verbose -Message "[$((Get-Date).ToString())] [Test-CPSCompliance] WinRM connectivity is verified."

                # Identify whether the given VMHost is a storage node or not
                Switch -Regex ($VmHost) {
                    "(.[R-Rr-r][1-9][S-Ss-s][S-Ss-s].)" {
                        Write-Verbose -Message "[$((Get-Date).ToString())] [Test-CPSCompliance] The given VMHost [$VmHost] is a storage node and is not associated with a VMM management server."
                        $IsStorageNode = $True
                    }
                    default {
                        Write-Verbose -Message "[$((Get-Date).ToString())] [Test-CPSCompliance] The given VMHost [$VmHost] is a not storage node and is associated with a VMM management server."
                        $IsStorageNode = $False
                    }
                }

                # Host Group
                If (!$IsStorageNode) {
                    $HostGroup = (Get-SCVMHost -ComputerName $VmHost).HostCluster.HostGroup
                    $HashTable.Add("VmHostGroup", $HostGroup.Name)
                    Write-Verbose -Message "[$((Get-Date).ToString())] [Test-CPSCompliance] The given VMHost [$VmHost] is belongs to host group '$($HostGroup.Name)'"
                }

                #region Verify local administrator account state
                Write-Verbose -Message "[$((Get-Date).ToString())] [Test-CPSCompliance] [Get-CimInstance -ClassName Win32_UserAccount] Verifying local administrator account status..."
                If ((Get-CimInstance -Computername $VmHost -ClassName Win32_UserAccount -Filter "LocalAccount='True' AND SID LIKE 'S-1-5-21-%-500'").Disabled -eq $True) {
                    Write-Verbose -Message "[$((Get-Date).ToString())] [Test-CPSCompliance] Local administrator account is in disabled state."
                    $HashTable.Add("IsLocalAdministartorAccountDisabled", $True)
                }
                Else {
                    Write-Warning -Message "[$((Get-Date).ToString())] [Test-CPSCompliance] Local administrator account is in enabled state!"
                    Write-Verbose -Message "[$((Get-Date).ToString())] [Test-CPSCompliance] It is advised to execute Disable-LocalAdminOnNode runbook as per the OSDReplacement Guide."
                    $HashTable.Add("IsLocalAdministartorAccountDisabled", $False)
                }
                #endregion

                #region Verify ISATAP state (it is expected to be enabled on storage nodes though)
                Write-Verbose -Message "[$((Get-Date).ToString())] [Test-CPSCompliance] [Get-NetIsatapConfiguration] Verifying ISATAP state..."
                If ((Get-NetIsatapConfiguration -CimSession $VmHost).State -eq "Disabled") {
                    If (!$IsStorageNode) {
                        Write-Verbose -Message "[$((Get-Date).ToString())] [Test-CPSCompliance] ISATAP is in disabled state."
                        $HashTable.Add("IsIsatapDisabled", $True)
                    }
                    Else {
                        Write-Warning -Message "[$((Get-Date).ToString())] [Test-CPSCompliance] ISATAP is in disabled state!"
                        Write-Verbose -Message "[$((Get-Date).ToString())] [Test-CPSCompliance] It is advised to execute Disable-ISATAPOnNode runbook as per the OSDReplacement Guide."
                        $HashTable.Add("IsIsatapDisabled", $False)
                    }
                }
                Else {
                    If ($IsStorageNode) {
                        Write-Verbose -Message "[$((Get-Date).ToString())] [Test-CPSCompliance] ISATAP is in enabled state."
                        $HashTable.Add("IsIsatapDisabled", $True)
                    }
                    Else {
                        Write-Warning -Message "[$((Get-Date).ToString())] [Test-CPSCompliance] ISATAP is in enabled state!"
                        Write-Verbose -Message "[$((Get-Date).ToString())] [Test-CPSCompliance] It is advised to execute Disable-ISATAPOnNode runbook as per the OSDReplacement Guide."
                        $HashTable.Add("IsIsatapDisabled", $False)
                    }
                }
                #endregion

                #region Verify Flow Control state
                Write-Verbose -Message "[$((Get-Date).ToString())] [Test-CPSCompliance] [Get-NetAdapterAdvancedProperty] Verifying Flow Control state..."
                If ((Get-NetAdapterAdvancedProperty -CimSession $VmHost -DisplayName '*Flow Control*').RegistryValue -eq '0') {
                    Write-Verbose -Message "[$((Get-Date).ToString())] [Test-CPSCompliance] Flow Control is in disabled state"
                    $HashTable.Add("IsFlowControlDisabled", $True)
                }
                Else {
                    Write-Warning -Message "[$((Get-Date).ToString())] [Test-CPSCompliance] Flow Control is in enabled state!"
                    Write-Verbose -Message "[$((Get-Date).ToString())] [Test-CPSCompliance] It is advised to execute Disable-FlowControlOnNode runbook as per the OSDReplacement Guide."
                    $HashTable.Add("IsFlowControlDisabled", $False)
                }
                #endregion

                #region Verify OMSA agent presense
                Write-Verbose -Message "[$((Get-Date).ToString())] [Test-CPSCompliance] [Get-CimInstance -ClassName Win32_Product] Verifying OMSA agent presense..."
                If (Get-CimInstance -ComputerName $VmHost -ClassName Win32_Product | Where-Object {($_.Name -match "Dell") -and ($_.InstallLocation -eq "C:\Program Files\Dell\SysMgt\")}) {
                    Write-Verbose -Message "[$((Get-Date).ToString())] [Test-CPSCompliance] OMSA agent is installed."
                    $HashTable.Add("IsOMSAAgentInstalled", $True)
                }
                Else {
                    Write-Warning -Message "[$((Get-Date).ToString())] [Test-CPSCompliance] OMSA agent is not installed!"
                    $HashTable.Add("IsOMSAAgentInstalled", $False)
                }
                #endregion

                #region Verify SCOM agent presense and state
                Try {
                    Write-Verbose -Message "[$((Get-Date).ToString())] [Test-CPSCompliance] [Get-SCOMAgent] Verifying SCOM agent presense..."
                    New-SCOMManagementGroupConnection -ComputerName "$Prefix-OM-0$(Get-Random -InputObject 1,2,3)" -ErrorAction Stop
                    $SCOMAgent = Get-SCOMAgent -DNSHostName ("{0}.{1}" -f $VmHost,$env:USERDNSDOMAIN)
                    If ($SCOMAgent) {
                        If ($SCOMAgent.Healthstate -ne 'Success') {
                            Write-Verbose -Message "[$((Get-Date).ToString())] [Test-CPSCompliance] SCOM agent is installed. [Install Date: $($SCOMAgent.InstallTime)]"
                            Write-Warning -Message "[$((Get-Date).ToString())] [Test-CPSCompliance] SCOM agent is not healthy! It is advised to review it's status in the OpsMgr Console."
                            $HashTable.Add("IsSCOMAgentInstalled", $True)
                        }
                        Else {
                            Write-Verbose -Message "[$((Get-Date).ToString())] [Test-CPSCompliance] SCOM agent is installed. [Install Date: $($SCOMAgent.InstallTime)]"
                            $HashTable.Add("IsSCOMAgentInstalled", $True)
                        }
                    }
                    Else {
                        Write-Warning -Message "[$((Get-Date).ToString())] [Test-CPSCompliance] SCOM agent is not installed!"
                        Write-Verbose -Message "[$((Get-Date).ToString())] [Test-CPSCompliance] It is advised to execute Install-OMAgentOnNode runbook as per the OSDReplacement Guide."
                        $HashTable.Add("IsSCOMAgentInstalled", $False)
                    }
                }
                Catch {
                    Write-Error -Exception $_.Exception -Message $_.Exception.Message
                }
                Finally {
                    Get-SCOMManagementGroupConnection -ErrorAction SilentlyContinue | Remove-SCOMManagementGroupConnection -ErrorAction SilentlyContinue
                }
                #endregion

                #region Verify DPM agent presense
                Write-Verbose -Message "[$((Get-Date).ToString())] [Test-CPSCompliance] [Get-CimInstance -ClassName Win32_Product] Verifying DPM agent presense..."
                If (Get-CimInstance -ComputerName $VmHost -ClassName Win32_Product | Where-Object {$_.Name -eq 'Microsoft System Center 2012 R2 DPM Protection Agent'}) {
                    Write-Verbose -Message "[$((Get-Date).ToString())] [Test-CPSCompliance] DPM agent is installed."
                    $HashTable.Add("IsDPMAgentInstalled", $True)
                }
                Else {
                    Write-Warning -Message "[$((Get-Date).ToString())] [Test-CPSCompliance] DPM agent is not installed!"
                    Write-Verbose -Message "[$((Get-Date).ToString())] [Test-CPSCompliance] It is advised to execute Install-DPMAgentOnSpecificHosts runbook as per the OSDReplacement Guide."
                    $HashTable.Add("IsDPMAgentInstalled", $False)
                }
                #endregion

                #region Verify Windows Update settings
                Write-Verbose -Message "[$((Get-Date).ToString())] [Test-CPSCompliance] [Invoke-Command] Verifying Windows Update settings..."
                If (Invoke-Command -ComputerName $VmHost -ScriptBlock {Get-ChildItem -Path "HKLM:\software\policies\Microsoft\Windows\WindowsUpdate" -ErrorAction SilentlyContinue}) {
                    Write-Verbose -Message "[$((Get-Date).ToString())] [Test-CPSCompliance] Windows Update settings are in place."
                    $HashTable.Add("IsWindowsUpdateConfigured", $True)
                }
                Else {
                    Write-Warning -Message "[$((Get-Date).ToString())] [Test-CPSCompliance] Windows Update settings are not in place!"
                    Write-Verbose -Message "[$((Get-Date).ToString())] [Test-CPSCompliance] It is advised to update Windows Update settings as per the OSDReplacement Guide."
                    $HashTable.Add("IsWindowsUpdateConfigured", $False)
                }
                #endregion

                #region Verify SCEP agent presense (excluding storage nodes)
                If (!$IsStorageNode) {
                    Write-Verbose -Message "[$((Get-Date).ToString())] [Test-CPSCompliance] [Get-CimInstance -ClassName Win32_Product] Verifying SCEP agent presense..."
                    If (Get-CimInstance -ComputerName $VmHost -ClassName Win32_Product | Where-Object {($_.Name -eq 'Microsoft Endpoint Protection Management Components') -or ($_.Name -eq 'Microsoft Forefront Endpoint Protection 2010 Server Management')}) {
                        Write-Verbose -Message "[$((Get-Date).ToString())] [Test-CPSCompliance] SCEP agent is installed."
                        $HashTable.Add("IsSCEPAgentInstalled", $True)
                    }
                    Else {
                        Write-Warning -Message "[$((Get-Date).ToString())] [Test-CPSCompliance] SCEP agent is not installed!"
                        Write-Verbose -Message "[$((Get-Date).ToString())] [Test-CPSCompliance] It is advised to install the System Center EndPoint Protection antimalware agent as per the OSDReplacement Guide."
                        $HashTable.Add("IsSCEPAgentInstalled", $False)
                    }
                }
                #endregion

                #region Verify Virtual Machine Paths
                If (!$IsStorageNode) {
                    Try {
                        Write-Verbose -Message "[$((Get-Date).ToString())] [Test-CPSCompliance] Verifying default external data root and virtual hard disk paths..."
                        $VmHostClusterSharePaths = ((Get-SCVMHost -ComputerName $VmHost).HostCluster.RegisteredStorageFileShares | Where-Object {$_.StorageClassification.Name -eq "PrimaryStorage"}).SharePath
                        $VirtualSystemManagementServiceSettingData = Get-CimInstance -ComputerName $VmHost -Namespace "root\virtualization\v2" -ClassName Msvm_VirtualSystemManagementServiceSettingData
                        $DefaultExternalDataRoot = $VirtualSystemManagementServiceSettingData.DefaultExternalDataRoot
                        $DefaultVirtualHardDiskPath = $VirtualSystemManagementServiceSettingData.DefaultVirtualHardDiskPath
                        If ($($HostGroup.Name) -match 'Management') {
                            If (($DefaultExternalDataRoot -eq "$VmHostClusterSharePaths\VMs") -or ($DefaultExternalDataRoot -eq "$VmHostClusterSharePaths\VMs" -replace ".$env:USERDNSDOMAIN")) {
                                Write-Verbose -Message "[$((Get-Date).ToString())] [Test-CPSCompliance] Default external data root path '$DefaultExternalDataRoot' is configured correctly."
                                $HashTable.Add("IsDefaultExternalDataRootConfiguredCorrectly", $True)
                            }
                            Else {
                                Write-Warning -Message "[$((Get-Date).ToString())] [Test-CPSCompliance] Default external data root path '$DefaultExternalDataRoot' is configured incorrectly!"
                                Write-Verbose -Message "[$((Get-Date).ToString())] [Test-CPSCompliance] It is advised to execute Configure-HyperVPathsOnNode runbook as per the OSDReplacement Guide."
                                $HashTable.Add("IsDefaultExternalDataRootConfiguredCorrectly", $False)
                            }
                            If (($DefaultVirtualHardDiskPath -eq "$VmHostClusterSharePaths\VHDs") -or ($DefaultVirtualHardDiskPath -eq "$VmHostClusterSharePaths\VHDs" -replace ".$env:USERDNSDOMAIN")) {
                                Write-Verbose -Message "[$((Get-Date).ToString())] [Test-CPSCompliance] Default virtual hard disk path '$DefaultVirtualHardDiskPath' is configured correctly."
                                $HashTable.Add("IsDefaultVirtualHardDiskPathConfiguredCorrectly", $True)
                            }
                            Else {
                                Write-Warning -Message "[$((Get-Date).ToString())] [Test-CPSCompliance] Default virtual hard disk path '$DefaultVirtualHardDiskPath' is configured incorrectly!"
                                Write-Verbose -Message "[$((Get-Date).ToString())] [Test-CPSCompliance] It is advised to execute Configure-HyperVPathsOnNode runbook as per the OSDReplacement Guide."
                                $HashTable.Add("IsDefaultVirtualHardDiskPathConfiguredCorrectly", $False)
                            }
                        }
                        ElseIf($($HostGroup.Name) -match 'Compute') {
                            If (($DefaultExternalDataRoot -in "$VmHostClusterSharePaths") -or ($DefaultExternalDataRoot -in "$VmHostClusterSharePaths" -replace ".$env:USERDNSDOMAIN")) {
                                Write-Verbose -Message "[$((Get-Date).ToString())] [Test-CPSCompliance] Default external data root path '$DefaultExternalDataRoot' is configured correctly."
                                $HashTable.Add("IsDefaultExternalDataRootConfiguredCorrectly", $True)
                            }
                            Else {
                                Write-Warning -Message "[$((Get-Date).ToString())] [Test-CPSCompliance] Default external data root path '$DefaultExternalDataRoot' is configured incorrectly!"
                                Write-Verbose -Message "[$((Get-Date).ToString())] [Test-CPSCompliance] It is advised to execute Configure-HyperVPathsOnNode runbook as per the OSDReplacement Guide."
                                $HashTable.Add("IsDefaultExternalDataRootConfiguredCorrectly", $False)
                            }
                            If (($DefaultVirtualHardDiskPath -in "$VmHostClusterSharePaths") -or ($DefaultVirtualHardDiskPath -in "$VmHostClusterSharePaths" -replace ".$env:USERDNSDOMAIN")) {
                                Write-Verbose -Message "[$((Get-Date).ToString())] [Test-CPSCompliance] Default virtual hard disk path '$DefaultVirtualHardDiskPath' is configured correctly."
                                $HashTable.Add("IsDefaultVirtualHardDiskPathConfiguredCorrectly", $True)
                            }
                            Else {
                                Write-Warning -Message "[$((Get-Date).ToString())] [Test-CPSCompliance] Default virtual hard disk path '$DefaultVirtualHardDiskPath' is configured incorrectly!"
                                Write-Verbose -Message "[$((Get-Date).ToString())] [Test-CPSCompliance] It is advised to execute Configure-HyperVPathsOnNode runbook as per the OSDReplacement Guide."
                                $HashTable.Add("IsDefaultVirtualHardDiskPathConfiguredCorrectly", $False)
                            }
                        }
                    }
                    Catch {
                        Write-Error -Exception $_.Exception -Message $_.Exception.Message
                    }
                }
                #endregion

                New-Object -TypeName PSObject -Property $HashTable
                Write-Debug -Message "[$((Get-Date).ToString())] [Test-CPSCompliance] Debug Info (CPS Compliance Scan Status): $($HashTable | ConvertTo-Json)"
            }
        }
        #endregion
	}

	End {
        Write-Verbose -Message "[$((Get-Date).ToString())] [Test-CPSCompliance] CPS Compliance scan is finished."
		[System.GC]::Collect()
	}
}

Function Get-CPSClusterProcessMemoryDump {
    [CmdletBinding(SupportsShouldProcess = $True, ConfirmImpact = "Low")]
    Param (
        [Parameter(
            Position = 0,
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True)]
        [ValidateNotNullOrEmpty()]
        [String] $Server,

        [Parameter(
            Position = 1,
            Mandatory = $True
        )]
        [ValidateNotNullOrEmpty()]
        [String] $Destination,

        [Parameter(
            Position = 2,
            Mandatory = $False,
            HelpMessage = "Path to Sysinternals ProcDump.exe utility. If not specified, will look in the following location: 'C:\DiagnosticTools\Sysinternals\ProcDump.exe'. You can get the utility from 'https://download.sysinternals.com/files/Procdump.zip'"
        )]
        [String] $ProcDumpPath = "$($env:SystemDrive)\DiagnosticTools\Sysinternals\ProcDump.exe",

        [Parameter(
            Position = 3,
            Mandatory = $False
        )]
        [ValidateNotNullOrEmpty()]
        [Switch] $Compress,

        [Parameter(
            Position = 4,
            Mandatory = $False
        )]
        [ValidateNotNullOrEmpty()]
        [Int] $ParentActivityId
    )

    Begin {
        If ($PSBoundParameters['Verbose']) {
            $VerbosePreference = "Continue"
        }
        If ($PSBoundParameters['Debug']) {
            $DebugPreference = "Continue"
            $ConfirmPreference = "None"
        }

        $ExcludeProperties = @("PSComputerName","RunspaceId","PSShowComputerName","CimClass","CimInstanceProperties","CimSystemProperties")

        #region Script Block
        $ScriptBlock = {
            Param (
                [Parameter(
                    Position = 0,
                    Mandatory = $True)]
                [ValidateNotNullOrEmpty()]
                [String] $Server
            )
            
            $VerbosePreference = $Using:VerbosePreference
            $DebugPreference = $Using:DebugPreference
            $ConfirmPreference = $Using:ConfirmPreference
            
            Try {
                $StagingDirectory = "$($env:SystemDrive)\Temp\$([GUID]::NewGuid().Guid)\"
                New-Item -Path $StagingDirectory -ItemType Directory -Force | Out-Null
                Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSClusterProcessMemoryDump] [Server: $Server]"
                Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSClusterProcessMemoryDump] [Staging Directory: $StagingDirectory]"
                
                $WorkingDirectory = "$($env:SystemDrive)\DiagnosticTools\Sysinternals\" # Sysinternals directory
                $Executable = "ProcDump.exe" # Executable file
                Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSClusterProcessMemoryDump] [Working Directory: $WorkingDirectory]"
                
                Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSClusterProcessMemoryDump] Getting 'Cluster Service (clussvc)' and 'Resource Hosting Subsystem (RHS)' processes details..."
                [Array] $Processes = Get-Process -Name clussvc,rhs | Select-Object ProcessName,Id
                Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSClusterProcessMemoryDump] Identified $($Processes.Count) processes."
                Write-Debug -Message "[$((Get-Date).ToString())] [Get-CPSClusterProcessMemoryDump] Debug Info (Processes): $($Processes | ConvertTo-Json)"
                
                If ($Processes.Count -ge 1) {
                    $I = 0
                    ForEach ($Process in $Processes) {
                        $I++
                        Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSClusterProcessMemoryDump] Taking memory dump of process [Process Name: $($Process.ProcessName)] [Id: $($Process.Id)] ($I of $($Processes.Count))..."
                        
                        $Time = (Get-Date).ToString('MM-dd-yyyy-hh-mm-ss')
                        $FilePath = "$($StagingDirectory)" + "$($Server)" + "_" + $($Process.ProcessName) + "_" + $($Process.Id) + "_" + "$($Time)" + ".dmp"
                        Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSClusterProcessMemoryDump] [Memory Dump File Path: $FilePath]"

                        # Using reflect mode (-r -a) doesn't work on Windows 10
                        $Parameters = " -accepteula -64 -ma -o -r -a " + "$($Process.Id)" + " " + $($FilePath)
                        
                        # Trigger memory dump
                        Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSClusterProcessMemoryDump] [Start-Process] Invoking ProcDump.exe [Parameters: $($Parameters.Trim())] [Maximum TimeOut: 5 minutes]..."
                        Start-Process -FilePath $Executable -ArgumentList $Parameters -WindowStyle Hidden -WorkingDirectory $WorkingDirectory -Wait -ErrorAction Stop -PassThru | Wait-Process -Timeout 300 | Out-Null
                    }
                }
            }
            Catch {
                Write-Error -Exception $_.Exception -Message $_.Exception.Message
            }
            Finally {
                $Status = New-Object -TypeName PSObject -Property @{
                    Server = $Server
                    FilePaths = [Array] $(Get-ChildItem -Path $StagingDirectory)
                }
                Write-Debug -Message "[$((Get-Date).ToString())] [Get-CPSClusterProcessMemoryDump] Debug Info (Memory Dump Status): $($Status | ConvertTo-Json)"
                Write-Output -InputObject $Status
            }
        }
        #endregion

        # Verify the given ProcDump.exe executable presence
        Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSClusterProcessMemoryDump] [ProcDump.exe Location: $ProcDumpPath]"
        Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSClusterProcessMemoryDump] Verifying the given path to ProcDump.exe executable..."
        If (!(Test-Path -Path $ProcDumpPath)) {
            Throw "[$((Get-Date).ToString())] [Get-CPSClusterProcessMemoryDump] The given path to ProcDump.exe executable is invalid!"
        }
        Else {
            Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSClusterProcessMemoryDump] Verification of the given path to ProcDump.exe executable is successful."
        }
    }

    Process {
        Try {
            $RootActivityId = $(Get-Date -Format "yyyymmss")
            $ActiveStepId = 0
            
            # Get system drive letter
            $SystemDrive = Invoke-Command -ComputerName $Server -ScriptBlock {$env:SystemDrive} -ErrorAction Stop

            $SysinternalsDirectory = "\\$Server\$($SystemDrive.TrimEnd(':'))$\DiagnosticTools\Sysinternals\"
            Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSClusterProcessMemoryDump] [Sysinternals Directory: $SysinternalsDirectory]"

            $DestinationDirectory = New-Item -Path $Destination -Name $Server -ItemType Directory -Force -ErrorAction Stop
            Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSClusterProcessMemoryDump] [Destination Directory: $DestinationDirectory]"

            # Verify and create Sysinternals directory
            Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSClusterProcessMemoryDump] Verifying Sysinternals directory presence..."
            If (!(Test-Path -Path $SysinternalsDirectory)) {
                Write-Warning -Message "[$((Get-Date).ToString())] [Get-CPSClusterProcessMemoryDump] Sysinternals directory doesn't exist!"
                Invoke-Command -ComputerName $Server -ScriptBlock {
                    $VerbosePreference = $Using:VerbosePreference
                    $DebugPreference = $Using:DebugPreference
                    $ConfirmPreference = $Using:ConfirmPreference
                    Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSClusterProcessMemoryDump] Creating Sysinternals directory..."
                    New-Item -Path "$($env:SystemDrive)\DiagnosticTools\Sysinternals\" -ItemType Directory -Force -ErrorAction Stop | Out-Null
                } -ErrorAction Stop -Verbose | Out-Null
            }

            Start-Sleep -Seconds 5
            
            If ($PSCmdlet.ShouldProcess("$ProcDumpPath", "Copy-Item")) {
                If (Test-Path -Path $SysinternalsDirectory) {
                    Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSClusterProcessMemoryDump] Verification of Sysinternals directory presence is successful."
                    # Copy ProcDump.exe executable
                    New-PSDrive -Name Z -Root $SysinternalsDirectory -PSProvider FileSystem -ErrorAction Stop | Out-Null
                    Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSClusterProcessMemoryDump] Copying 'ProcDump.exe' executable from '$ProcDumpPath' to '$SysinternalsDirectory'..."
                    Copy-Item -Path $ProcDumpPath -Destination "Z:\" -Force -ErrorAction Stop | Out-Null
                    Remove-PSDrive -Name Z -ErrorAction Stop | Out-Null
                }
                Else {
                    Write-Warning -Message "[$((Get-Date).ToString())] [Get-CPSClusterProcessMemoryDump] Sysinternals directory doesn't exist!"
                    Return
                }
            }

            # Take memory dumps
            If (($PSBoundParameters['Verbose']) -and ($PSBoundParameters['Debug'])) {
                [Array] $MemoryDumpFiles = Invoke-Command -ComputerName $Server -ScriptBlock $ScriptBlock -ArgumentList $Server -ErrorAction Stop -Verbose -Debug | Select-Object FilePaths -ExcludeProperty $ExcludeProperties | ForEach-Object {$_.FilePaths}
            }
            ElseIf ($PSBoundParameters['Verbose']) {
                [Array] $MemoryDumpFiles = Invoke-Command -ComputerName $Server -ScriptBlock $ScriptBlock -ArgumentList $Server -ErrorAction Stop -Verbose | Select-Object FilePaths -ExcludeProperty $ExcludeProperties | ForEach-Object {$_.FilePaths}
            }
            ElseIf ($PSBoundParameters['Debug']) {
                [Array] $MemoryDumpFiles = Invoke-Command -ComputerName $Server -ScriptBlock $ScriptBlock -ArgumentList $Server -ErrorAction Stop -Debug | Select-Object FilePaths -ExcludeProperty $ExcludeProperties | ForEach-Object {$_.FilePaths}
            }
            Else {
                [Array] $MemoryDumpFiles = Invoke-Command -ComputerName $Server -ScriptBlock $ScriptBlock -ArgumentList $Server -ErrorAction Stop | Select-Object FilePaths -ExcludeProperty $ExcludeProperties | ForEach-Object {$_.FilePaths}
            }

            $I = 0
            ForEach ($MemoryDumpFile in $MemoryDumpFiles) {
                $I++
                $ActiveStepId++
                If ($PSBoundParameters['ParentActivityId']) {
                    Write-Progress -Activity "Getting Cluster Process Memory Dumps.." -Status "Processing Server $($Server): Memory Dump File '$($MemoryDumpFile.BaseName)' $ActiveStepId of $($MemoryDumpFiles.Count)" -Id $RootActivityId -ParentId $ParentActivityId -PercentComplete (($ActiveStepId / $($MemoryDumpFiles.Count))*100) -CurrentOperation "Copying Memory Dump File.."
                }
                Else {
                    Write-Progress -Activity "Getting Cluster Process Memory Dumps.." -Status "Processing Server $($Server): Memory Dump File '$($MemoryDumpFile.BaseName)' $ActiveStepId of $($MemoryDumpFiles.Count)" -Id $RootActivityId -PercentComplete (($ActiveStepId / $($MemoryDumpFiles.Count))*100) -CurrentOperation "Copying Memory Dump File.."
                }
                
                Try {
                    If ($PSCmdlet.ShouldProcess("$($MemoryDumpFile.BaseName)", "Copy-Item")) {
                        Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSClusterProcessMemoryDump] [Copy-Item] Copying memory dump file [Server: $Server] [Name: $($MemoryDumpFile.BaseName)] [Path: $($MemoryDumpFile.FullName)] ($I of $($MemoryDumpFiles.Count))..."
                        $RemoteMemoryDumpFilePath = Join-Path -Path "\\$Server\$($SystemDrive.TrimEnd(':'))$" -ChildPath $($MemoryDumpFile.FullName.Split(':')[1])
                        Copy-Item -Path $RemoteMemoryDumpFilePath -Destination $DestinationDirectory -Recurse -Force -ErrorAction Stop
                        Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSClusterProcessMemoryDump] [Remove-Item] Removing the raw memory dump file [$RemoteMemoryDumpFilePath] on server [$Server]..."
                        Remove-Item -Path $RemoteMemoryDumpFilePath -Recurse -Force
                    }
                }
                Catch {
                    Write-Error -Exception $_.Exception -Message $_.Exception.Message
                }
                
                If ($PSBoundParameters['ParentActivityId']) {
                    Write-Progress -Activity "Getting Cluster Process Memory Dumps.." -Status "Processing Server $($Server): Memory Dump File '$($MemoryDumpFile.BaseName)' $ActiveStepId of $($MemoryDumpFiles.Count)" -Id $RootActivityId -ParentId $ParentActivityId -PercentComplete (($ActiveStepId / $($MemoryDumpFiles.Count))*100) -CurrentOperation "Copying Memory Dump File.." -Completed
                }
                Else {
                    Write-Progress -Activity "Getting Cluster Process Memory Dumps.." -Status "Processing Server $($Server): Memory Dump File '$($MemoryDumpFile.BaseName)' $ActiveStepId of $($MemoryDumpFiles.Count)" -Id $RootActivityId -PercentComplete (($ActiveStepId / $($MemoryDumpFiles.Count))*100) -CurrentOperation "Copying Memory Dump File.." -Completed
                }
            }

            Try {
                Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSClusterProcessMemoryDump] [Remove-Item] Removing the staging folder [$(Split-Path -Path $RemoteMemoryDumpFilePath)] on server [$Server]..."
                Remove-Item -Path $(Split-Path -Path $RemoteMemoryDumpFilePath) -Recurse -Force
            }
            Catch {
                Write-Error -Exception $_.Exception -Message $_.Exception.Message
            }

            If ($PSBoundParameters['Compress']) {
                If ($PSBoundParameters['ParentActivityId']) {
                    Write-Progress -Activity "Getting Cluster Process Memory Dumps.." -Status "Processing Server $($Server)" -Id $RootActivityId -ParentId $ParentActivityId -PercentComplete 100 -CurrentOperation "Compressing Memory Dump Files.."
                }
                Else {
                    Write-Progress -Activity "Getting Cluster Process Memory Dumps.." -Status "Processing Server $($Server)" -Id $RootActivityId -PercentComplete 100 -CurrentOperation "Compressing Memory Dump Files.."
                }
                
                $DestinationArchiveFilePath = Join-Path -Path $(Split-Path -Path $DestinationDirectory) -ChildPath "$(Split-Path -Path $DestinationDirectory -Leaf).zip"
                New-Archive -Path $DestinationDirectory -ArchivePath $DestinationArchiveFilePath -CompressionLevel Optimal
                If (Test-Path -Path $DestinationArchiveFilePath) {
                    Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSClusterProcessMemoryDump] [Remove-Item] Removing the previously copied raw memory dump files [$DestinationDirectory]..."
                    Remove-Item -Path $DestinationDirectory -Recurse -Force
                }
                
                If ($PSBoundParameters['ParentActivityId']) {
                    Write-Progress -Activity "Getting Cluster Process Memory Dumps.." -Status "Processing Server $($Server)" -Id $RootActivityId -ParentId $ParentActivityId -PercentComplete 100 -CurrentOperation "Compressing Memory Dump Files.." -Completed
                }
                Else {
                    Write-Progress -Activity "Getting Cluster Process Memory Dumps.." -Status "Processing Server $($Server)" -Id $RootActivityId -PercentComplete 100 -CurrentOperation "Compressing Memory Dump Files.." -Completed
                }
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