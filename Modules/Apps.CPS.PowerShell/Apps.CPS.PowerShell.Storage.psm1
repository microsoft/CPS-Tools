###########################################################
# Module Manifest Name: Apps.CPS.PowerShell.Storage.psm1
# Module Manifest Description: Holds Storage related functions
# Author: Srinath Sadda
###########################################################

<#
    .SYNOPSIS
        CPS Storage Module.
    .DESCRIPTION
        Holds Storage related functions.
    .EXAMPLE
        Import-Module -Name .\Apps.CPS.PowerShell.psd1
    .NOTES
        Module Name: Apps.CPS.PowerShell.Storage.psm1
        Module Description: Holds Storage related functions.
        Author: Srinath Sadda
    .LINK
#>

Function Read-CPSStorageHealth {
    [CmdletBinding()]
    [OutputType([System.Object])]
    Param (
        [Parameter(
            Position = 0,
            Mandatory = $True,
            ValueFromPipeline = $True
        )]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({
            If (!$(Test-Path -Path $_)) {
                Throw "THE GIVEN PATH '$($_)' DOESN'T EXIST!"
            }
            $True
        })]
        [String] $Path,

        [Parameter(
            Position = 1,
            Mandatory = $False
        )]
        [Switch] $GridView,

        [Parameter(
            Position = 2,
            Mandatory = $False
        )]
        [Switch] $Wait
    )

    Begin {
        If ($PSBoundParameters['Verbose']) {
            $VerbosePreference = "Continue"
        }
        If ($PSBoundParameters['Debug']) {
            $DebugPreference = "Continue"
            $ConfirmPreference = "None"
        }

        #region Function: Test-CliXmlFile
        Function Test-CliXmlFile {
            [CmdletBinding()]
            [OutputType([System.Boolean])]
            Param (
                [Parameter(
                    Position = 0,
                    Mandatory = $True,
                    ValueFromPipeline = $True
                )]
                [ValidateNotNullOrEmpty()]
                [String] $Path
            )

            Try {
                $XML = New-Object -TypeName System.Xml.XmlDocument
                $XML.Load($($Item.FullName))
                Return $True
            }
            Catch {
                Write-Error -Exception $_.Exception -Message $_.Exception.Message
                Return $False
            }
        }
        #endregion
    }

    Process {
        Try {
            Write-Verbose -Message "[$((Get-Date).ToString())] [Read-CPSStorageHealth] [Get-Item] Verifying the given path [$Path]..."
            $PathObject = Get-Item -Path $Path
            If ($Null -eq $PathObject) {
                Write-Warning -Message "[$((Get-Date).ToString())] [Read-CPSStorageHealth] Verification of the given path [$Path] is unsuccessful!"
                Break
            }
            $Path = $PathObject.FullName
            If ($Path.ToLower().EndsWith(".zip")) {
                Write-Verbose -Message "[$((Get-Date).ToString())] [Read-CPSStorageHealth] Identified the given path [$Path] as a compressed file."
                [Reflection.Assembly]::LoadWithPartialName("System.IO.Compression.FileSystem") | Out-Null
                $ExtractToPath = $Path.Substring(0, $Path.Length - 4)
                If (Test-Path -Path $ExtractToPath) {
                    Write-Verbose -Message "[$((Get-Date).ToString())] [Read-CPSStorageHealth] The directory [$ExtractToPath] already exists in the given location."
                    Write-Verbose -Message "[$((Get-Date).ToString())] [Read-CPSStorageHealth] [Remove-Item] Removing the directory [$ExtractToPath] that already exists in the given location..."
                    Remove-Item -Path $ExtractToPath -Recurse -Force | Out-Null
                }
                Write-Verbose -Message "[$((Get-Date).ToString())] [Read-CPSStorageHealth] Extracting the given file contents..."
                [System.IO.Compression.ZipFile]::ExtractToDirectory($Path, $ExtractToPath)
                $Path = $ExtractToPath
                Write-Verbose -Message "[$((Get-Date).ToString())] [Read-CPSStorageHealth] Successfully extracted the given file contents."
            }
        }
        Catch {
            Write-Error -Exception $_.Exception -Message $_.Exception.Message -ErrorAction Stop
        }

        Try {
            [HashTable] $HashTable = @{}
            Write-Verbose -Message "[$((Get-Date).ToString())] [Read-CPSStorageHealth] [Get-ChildItem] Identifying files from the given path [$Path]..."
            $Items = Get-ChildItem -Path $Path -Filter *.XML -Force
            Write-Verbose -Message "[$((Get-Date).ToString())] [Read-CPSStorageHealth] Identified $($Items.Count) files."
        }
        Catch {
            Write-Error -Exception $_.Exception -Message $_.Exception.Message -ErrorAction Stop
        }

        $I = 0
        ForEach ($Item in $Items) {
            Try {
                $I++
                Write-Verbose -Message "[$((Get-Date).ToString())] [Read-CPSStorageHealth] [Test-CliXmlFile] Processing file [$($Item.Name)] ($I of $($Items.Count))..."
                If (Test-CliXmlFile -Path $Item.FullName -ErrorAction SilentlyContinue) {
                    Write-Verbose -Message "[$((Get-Date).ToString())] [Read-CPSStorageHealth] [$($Item.Name)] [Size: $([Math]::Truncate(($Item.Length) / 1KB)) KB] is a valid XML file. Reading content..."
                    Clear-Variable -Name Name -ErrorAction SilentlyContinue
                    Clear-Variable -Name InputObject -ErrorAction SilentlyContinue
                    $Name = $($Item.Name -replace('.XML','') -replace('Get',''))
                    $InputObject = Import-Clixml -Path $($Item.FullName)
                    If ($PSBoundParameters['GridView']) {
                        Write-Verbose -Message "[$((Get-Date).ToString())] [Read-CPSStorageHealth] Formatting content to display in grid view..."
                        $ExcludeProperties = @("PSComputerName","RunspaceId","PSShowComputerName","CimClass","CimInstanceProperties","CimSystemProperties")
                        ForEach ($Object in $InputObject) {
                            $Properties = ($Object | Get-Member -MemberType Properties)
                            ForEach ($Property in $Properties) {
                                $PropertyName = $Property.Name
                                $PropertyValue = $Object.$($Property.Name)
                                If (($Null -eq $PropertyName) -or ('' -eq $PropertyName)) {
                                    Continue
                                }
                                If ($Null -ne $PropertyValue) {
                                    Switch ($PropertyValue.GetType().Name) {
                                        'ArrayList' {
                                            If ($ExcludeProperties -notcontains $Property.Name) {
                                                $ExcludeProperties += $Property.Name
                                            }
                                        }
                                        'Object[]' {
                                            Switch ($PropertyValue.GetType().BaseType.Name) {
                                                'Array' {
                                                    If ($ExcludeProperties -notcontains $Property.Name) {
                                                        $ExcludeProperties += $Property.Name
                                                    }
                                                }
                                                Default {
                                                }
                                            }
                                        }
                                        Default {
                                        }
                                    }
                                }
                            }
                        }
                        $ExcludeProperties = $ExcludeProperties | Sort-Object -Unique
                        If ($PSBoundParameters['Wait']) {
                            Write-Verbose -Message "[$((Get-Date).ToString())] [Read-CPSStorageHealth] Waiting for grid view to close..."
                            $InputObject | Select-Object * -ExcludeProperty $ExcludeProperties | Out-GridView -Title $((($Name -creplace '(?<!^)([A-Z][a-z]|(?<=[a-z])[A-Z])', ' $&') -join(' ')).Replace('_', ' - ')) -Wait
                        }
                        Else {
                            $InputObject | Select-Object * -ExcludeProperty $ExcludeProperties | Out-GridView -Title $((($Name -creplace '(?<!^)([A-Z][a-z]|(?<=[a-z])[A-Z])', ' $&') -join(' ')).Replace('_', ' - ')) -OutputMode None
                        }
                    }
                    $HashTable.Add($Name, $InputObject)
                }
                Else {
                    Write-Warning -Message "[$((Get-Date).ToString())] [Read-CPSStorageHealth] [$($Item.Name)] is not a valid XML file!"
                }
            }
            Catch {
                Write-Error -Exception $_.Exception -Message $_.Exception.Message
            }
        }
    }

    End {
        $StorageHealth = New-Object -TypeName PSCustomObject -Property $HashTable
        Write-Debug -Message "[$((Get-Date).ToString())] Storage Health (Debug Info): $($StorageHealth | ConvertTo-Json)"
        Write-Output -InputObject $StorageHealth
        [System.GC]::Collect()
    }
}

Function Get-CPSStorageHealth {
    <#
        .SYNOPSIS
            Retrieves storage health information.
        .DESCRIPTION
            Retrieves storage health information.
        .PARAMETER RackIdentifier
            If specified, storage cluster name will be determined from a specified rack. Default is rack 1.
        .PARAMETER WriteToFolderPath
            Specify path to a directory to save storage health information. Default is current user profile path.
        .PARAMETER MaxThreads
            Specify maximum no. of threads. Default is 4 threads. Maximum is 8 threads.
        .PARAMETER TimeOut
            The maximum number of minutes for the cmdlet can run before the cmdlet can be self terminate.
            Default is 30 minutes. Minimum is 15 and Maximum is 60 minutes.
        .PARAMETER IncludeEventLogs
            Includes event logs from all storage nodes.
        .PARAMETER IncludeStorageEnclosureHealth
            Includes storage enclosure health.
            When you specify this switch, you must also specify path to Storage Enclosure CLI (secli) tool to 'SECliPath' parameter.
        .PARAMETER SECliPath
            Path to Storage Enclosure CLI (secli) tool.
            If not specified, will look in standard local install location: 'C:\Program Files\Dell\ServerHardwareManager\ServerHardwareManagerCLI\Secli.exe'
        .PARAMETER IncludeMemoryDumps
            Includes memory dumps from all storage nodes if exist.
        .PARAMETER IncludeClusterProcessMemoryDumps
            Takes memory dump of 'Cluster Service (clussvc)' and 'Resource Hosting Subsystem (RHS)' processes on all storage nodes.
            When you specify this switch, you must also specify path to ProcDump.exe utility for 'ProcDumpPath' parameter.
        .PARAMETER ProcDumpPath
            Path to Sysinternals ProcDump.exe utility.
            If not specified, will look in the following location: 'C:\DiagnosticTools\Sysinternals\ProcDump.exe'. You can get the utility from 'https://download.sysinternals.com/files/Procdump.zip'
        .PARAMETER IncludeReliabilityCounters
            Includes reliability counters.
        .PARAMETER VerifyMPIO
            Verifies multipath I/O status for physical disks on all storage nodes.
        .PARAMETER Compress
            Creates a zip archive that contains the files and directories from the specified directory.
        .EXAMPLE
            Retrieve storage health information from a specified rack (default is rack 1).
            Get-CPSStorageHealth -Verbose
        .EXAMPLE
            Retrieve storage health information from a specified rack.
            Get-CPSStorageHealth -RackIdentifier 1 -Verbose
        .EXAMPLE
            Retrieve storage health extended information.
            Get-CPSStorageHealth -RackIdentifier 1 -MaxThreads 4 -IncludeEventLogs -IncludeStorageEnclosureHealth -SECliPath "C:\Secli\secli.exe" -IncludeMemoryDumps -IncludeReliabilityCounters -VerifyMPIO -Compress -Verbose
        .EXAMPLE
            Retrieve storage health extended information including cluster process memory dumps.
            Get-CPSStorageHealth -RackIdentifier 1 -MaxThreads 4 -IncludeEventLogs -IncludeStorageEnclosureHealth -SECliPath "C:\Secli\secli.exe" -IncludeMemoryDumps -IncludeClusterProcessMemoryDumps -ProcDumpPath "C:\DiagnosticTools\Sysinternals\ProcDump.exe" -IncludeReliabilityCounters -VerifyMPIO -Compress -Verbose
        .NOTES
        .LINK
    #>

    [CmdletBinding()]
    [OutputType([System.Object])]
    Param (
        [Parameter(
            Position = 0,
            Mandatory = $False,
            HelpMessage = "If specified, storage cluster name will be determined from a specified rack. Default is rack 1."
        )]
        [ValidateNotNullOrEmpty()]
        [ValidateRange(1,4)]
        [Alias("Rack")]
        [Int] $RackIdentifier = 1,

        [Parameter(
            Position = 1,
            Mandatory = $False,
            HelpMessage = "Specify path to a directory to save storage health information. Default is current user profile path."
        )]
        [ValidateNotNullOrEmpty()]
        [String] $WriteToFolderPath = "$env:USERPROFILE\StorageHealth\$(Get-Date -Format 'M-dd-yyyy')\$([GUID]::NewGuid().Guid)\",

        [Parameter(
            Position = 2,
            Mandatory = $False,
            HelpMessage = "Specify maximum no. of threads. Default is 4 threads. Maximum is 8 threads:"
        )]
        [ValidateNotNullOrEmpty()]
        [ValidateRange(1,8)]
        [Int16] $MaxThreads = 4,

        [Parameter(
            Position = 3,
            Mandatory = $False,
            HelpMessage = "The maximum number of minutes for the cmdlet can run before the cmdlet can be self terminate. Default is 30 minutes. Minimum is 15 and Maximum is 60 minutes."
        )]
        [ValidateNotNullOrEmpty()]
        [ValidateRange(15,60)]
        [Int16] $TimeOut = 30,

        [Parameter(
            Position = 4,
            Mandatory = $False,
            HelpMessage = "Includes event logs from all storage nodes."
        )]
        [ValidateNotNullOrEmpty()]
        [Switch] $IncludeEventLogs,

        [Parameter(
            Position = 5,
            Mandatory = $False,
            HelpMessage = "Includes storage enclosure health. When you specify this switch, you must also specify path to Storage Enclosure CLI (secli) tool for 'SECliPath' parameter."
        )]
        [ValidateNotNullOrEmpty()]
        [Switch] $IncludeStorageEnclosureHealth,

        [Parameter(
            Position = 6,
            Mandatory = $False,
            HelpMessage = "Path to Storage Enclosure CLI (secli) tool. If not specified, will look in standard local install location: 'C:\Program Files\Dell\ServerHardwareManager\ServerHardwareManagerCLI\Secli.exe'"
        )]
        [String] $SECliPath = "$($env:SystemDrive)\Program Files\Dell\ServerHardwareManager\ServerHardwareManagerCLI\Secli.exe",

        [Parameter(
            Position = 7,
            Mandatory = $False,
            HelpMessage = "Includes memory dumps from all storage nodes, if exist."
        )]
        [ValidateNotNullOrEmpty()]
        [Switch] $IncludeMemoryDumps,

        [Parameter(
            Position = 8,
            Mandatory = $False,
            HelpMessage = "Takes memory dump of 'Cluster Service (clussvc)' and 'Resource Hosting Subsystem (RHS)' processes on all storage nodes. When you specify this switch, you must also specify path to ProcDump.exe utility for 'ProcDumpPath' parameter."
        )]
        [ValidateNotNullOrEmpty()]
        [Switch] $IncludeClusterProcessMemoryDumps,

        [Parameter(
            Position = 9,
            Mandatory = $False,
            HelpMessage = "Path to Sysinternals ProcDump.exe utility. If not specified, will look in the following location: 'C:\DiagnosticTools\Sysinternals\ProcDump.exe'. You can get the utility from 'https://download.sysinternals.com/files/Procdump.zip'"
        )]
        [String] $ProcDumpPath = "$($env:SystemDrive)\DiagnosticTools\Sysinternals\ProcDump.exe",

        [Parameter(
            Position = 10,
            Mandatory = $False,
            HelpMessage = "Includes reliability counters."
        )]
        [ValidateNotNullOrEmpty()]
        [Switch] $IncludeReliabilityCounters,

        [Parameter(
            Position = 11,
            Mandatory = $False,
            HelpMessage = "Verifies multipath I/O status for physical disks on all storage nodes."
        )]
        [ValidateNotNullOrEmpty()]
        [Switch] $VerifyMPIO,
        
        [Parameter(
            Position = 12,
            Mandatory = $False,
            HelpMessage = "Creates a zip archive that contains the files and directories from the specified directory."
        )]
        [ValidateNotNullOrEmpty()]
        [Switch] $Compress
    )

    Begin {
        If ($PSBoundParameters['Verbose']) {
            $VerbosePreference = "Continue"
        }
        If ($PSBoundParameters['Debug']) {
            $DebugPreference = "Continue"
            $ConfirmPreference = "None"
        }

        $StartTime = Get-Date
        $RootActivityId = $(Get-Date -Format "yyyymmss")
        $ActiveStepId = 0
        $Steps = @(
            "Initial Configuration Tasks",
            "Cluster",
            "Cluster Nodes",
            "Active Cluster Nodes",
            "Access Node",
            "Access Node CimSession",
            "Cluster Logs",
            "Cluster Groups",
            "Cluster Networks",
            "Cluster Resources",
            "Cluster Shared Volumes",
            "Scale-Out File Servers",
            "SMB Shares",
            "SMB Open Files",
            "SMB Witness Clients",
            "Virtual Disks",
            "Physical Disks",
            "Physical Disks",
            "Storage Pools",
            "Volumes",
            "P&P Signed Drivers",
            "Storage Sub-System",
            "Storage Sub-System Storage Pools",
            "Storage Sub System Physical Disks",
            "Storage Sub System Virtual Disks",
            "Storage Sub System Storage Enclosure",
            "Deduplication Status",
            "Cluster Shared Volumes (CSV) to Virtual Disks",
            "Virtual Disks to Storage Pools"
        )
        If ($PSBoundParameters['IncludeEventLogs']) {
            $Steps += "Backup Event Logs"
        }
        If ($PSBoundParameters['IncludeStorageEnclosureHealth']) {
            $Steps += "Retrieve Storage Enclosure Health"
        }
        If ($PSBoundParameters['IncludeMemoryDumps']) {
            $Steps += "Retrieve Memory Dumps"
        }
        If ($PSBoundParameters['IncludeClusterProcessMemoryDumps']) {
            $Steps += "Retrieve Cluster Process Memory Dumps"
        }
        If ($PSBoundParameters['IncludeReliabilityCounters']) {
            $Steps += "Storage Reliability Counters"
        }
        If ($PSBoundParameters['VerifyMPIO']) {
            $Steps += "Verify MPIO"
        }
        If ($PSBoundParameters['Compress']) {
            $Steps += "Compress"
        }
        $TotalSteps = $Steps.Count
        $BackgroundJobs = @()
        [HashTable] $HashTable = @{}

        $ActiveStepId++ #1
        Write-Progress -Activity "Getting CPS Storage Health.." -Status "Processing: Step $ActiveStepId of $TotalSteps" -Id $RootActivityId -PercentComplete (($ActiveStepId / $TotalSteps)*100) -CurrentOperation "Performing Initial Configuration Tasks.."

        #region Initial Configuration Tasks
        Try {
            $SaveVerbosePreference = $VerbosePreference
            $VerbosePreference = "SilentlyContinue"
            Import-Module -Name Storage -Verbose:$False
            Import-Module -Name SmbShare -Verbose:$False
            Import-Module -Name FailoverClusters -Verbose:$False
            Import-Module -Name VirtualMachineManager -Verbose:$False
            $VerbosePreference = $SaveVerbosePreference
        }
        Catch {
            Write-Error -Exception $_.Exception -Message $_.Exception.Message -ErrorAction Stop
        }

        Try {
            If (!$PSBoundParameters['WriteToFolderPath']) {
                Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSStorageHealth] Creating a directory [$WriteToFolderPath] to save storage health information..."
                New-Item -Path $WriteToFolderPath -ItemType Directory -Force -ErrorAction Stop | Out-Null
            }
            Else {
                [String] $WriteToFolderPath = Join-Path -Path $WriteToFolderPath -ChildPath "StorageHealth\$(Get-Date -Format 'M-dd-yyyy')\$([GUID]::NewGuid().Guid)\"
                If (!(Test-Path -Path $WriteToFolderPath)) {
                    Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSStorageHealth] Creating a directory [$WriteToFolderPath] to save storage health information..."
                    New-Item -Path $WriteToFolderPath -ItemType Directory -Force -ErrorAction Stop | Out-Null
                }
            }
            If (Test-Path -Path $WriteToFolderPath) {
                Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSStorageHealth] Verified path [$WriteToFolderPath]"
            }
            Else {
                Write-Warning -Message "[$((Get-Date).ToString())] [Get-CPSStorageHealth] Verification of the given path [$WriteToFolderPath] is failed!"
            }
        }
        Catch {
            Write-Error -Exception $_.Exception -Message $_.Exception.Message -ErrorAction Stop
        }

        If ($Host.Version.Major -ge 5) {
            $TranscriptLogFilePath = $(Join-Path -Path $WriteToFolderPath -ChildPath "Transcript.log")
            Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSStorageHealth] [Start-Transcript] Starting transcript..."
            Start-Transcript -Path $TranscriptLogFilePath -Append -NoClobber -Force | Out-Null
            Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSStorageHealth] Transcript will be available at [$TranscriptLogFilePath]"
        }
        Else {
            If ($Host.Name -eq "ConsoleHost") {
                $TranscriptLogFilePath = $(Join-Path -Path $WriteToFolderPath -ChildPath "Transcript.log")
                Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSStorageHealth] [Start-Transcript] Starting transcript..."
                Start-Transcript -Path $TranscriptLogFilePath -Append -NoClobber -Force | Out-Null
                Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSStorageHealth] Transcript will be available at [$TranscriptLogFilePath]"
            }
            Else {
                Write-Warning -Message "[$((Get-Date).ToString())] [Get-CPSStorageHealth] Skipping transcript as the cmdlet is running from host [Name: $($Host.Name)] [Version: $($Host.Version.Major)]..."
            }
        }
        #endregion

        #region Cluster Information
        $ActiveStepId++ #2
        Write-Progress -Activity "Getting CPS Storage Health.." -Status "Processing: Step $ActiveStepId of $TotalSteps" -Id $RootActivityId -PercentComplete (($ActiveStepId / $TotalSteps)*100) -CurrentOperation "Getting Cluster Information.."
        Try {
            Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSStorageHealth] [Get-Cluster] Getting storage cluster information for [Rack $RackIdentifier]..."
            $((Get-SCStorageArray).StorageProvider.Name) | ForEach-Object {
                Switch -Regex ($_) {
                    "(.[R-Rr-r]$($RackIdentifier)[S-Ss-s][C-Cc-c].)" {
                        $Cluster = Get-Cluster -Name $_ -ErrorAction Stop | Select-Object *
                    }
                    default {
                    }
                }
            }
            $ClusterName = $Cluster.Name
            $HashTable.Add("Cluster", $Cluster)
            $HashTable.Add("ClusterName", $ClusterName)
            $BackgroundJobs += Write-ClixmlAsync -InputObject $Cluster -WriteToFolderPath $WriteToFolderPath -WriteToFileName "Cluster"
            Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSStorageHealth] Identified cluster as [$ClusterName]"
            Try {
                Write-Debug -Message "[$((Get-Date).ToString())] [Get-CPSStorageHealth] Debug Info (Cluster): $($Cluster | ConvertTo-Json)"
            }
            Catch {
                Write-Debug -Message "[$((Get-Date).ToString())] [Get-CPSStorageHealth] Debug Info (Cluster): $($Cluster | ConvertTo-Json -Compress)"
            }
        }
        Catch {
            Write-Error -Exception $_.Exception -Message $_.Exception.Message -ErrorAction Stop
        }
        #endregion
    }

    Process {
        #region Cluster Nodes
        $ActiveStepId++ #3
        Write-Progress -Activity "Getting CPS Storage Health.." -Status "Processing: Step $ActiveStepId of $TotalSteps" -Id $RootActivityId -PercentComplete (($ActiveStepId / $TotalSteps)*100) -CurrentOperation "Getting Cluster Nodes.."
        Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSStorageHealth] [Get-ClusterNode] Getting cluster nodes..."
        $ClusterNodes = Get-ClusterNode -Cluster $(Get-Cluster -Name $ClusterName) # Cluster Nodes
        $HashTable.Add("ClusterNodes", $ClusterNodes)
        $BackgroundJobs += Write-ClixmlAsync -InputObject $ClusterNodes -WriteToFolderPath $WriteToFolderPath -WriteToFileName "ClusterNodes"
        Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSStorageHealth] Identified $($ClusterNodes.Count) cluster nodes."
        Try {
            Write-Debug -Message "[$((Get-Date).ToString())] [Get-CPSStorageHealth] Debug Info (Cluster Nodes): $($ClusterNodes | ConvertTo-Json)"
        }
        Catch {
            Write-Debug -Message "[$((Get-Date).ToString())] [Get-CPSStorageHealth] Debug Info (Cluster Nodes): $($ClusterNodes | ConvertTo-Json -Compress)"
        }
        #endregion
        
        #region Active Cluster Nodes
        $ActiveStepId++ #4
        Write-Progress -Activity "Getting CPS Storage Health.." -Status "Processing: Step $ActiveStepId of $TotalSteps" -Id $RootActivityId -PercentComplete (($ActiveStepId / $TotalSteps)*100) -CurrentOperation "Identifying Active Cluster Nodes.."
        Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSStorageHealth] Identifying active cluster nodes..."
        $ActiveClusterNodes = ($ClusterNodes | Where-Object { $_.State -like "Up" })
        $HashTable.Add("ActiveClusterNodes", $ActiveClusterNodes)
        Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSStorageHealth] Identified $($ActiveClusterNodes.Count) active cluster nodes."
        Try {
            Write-Debug -Message "[$((Get-Date).ToString())] [Get-CPSStorageHealth] Debug Info (Active Cluster Nodes): $($ActiveClusterNodes | ConvertTo-Json)"
        }
        Catch {
            Write-Debug -Message "[$((Get-Date).ToString())] [Get-CPSStorageHealth] Debug Info (Active Cluster Nodes): $($ActiveClusterNodes | ConvertTo-Json -Compress)"
        }
        #endregion

        #region Access Node
        $ActiveStepId++ #5
        Write-Progress -Activity "Getting CPS Storage Health.." -Status "Processing: Step $ActiveStepId of $TotalSteps" -Id $RootActivityId -PercentComplete (($ActiveStepId / $TotalSteps)*100) -CurrentOperation "Selecting Access Node.."
        Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSStorageHealth] Selecting a random active cluster node..."
        $AccessNode = (($ClusterNodes | Where-Object { $_.State -like "Up" }) | Get-Random).Name # Access Node
        $HashTable.Add("AccessNode", $AccessNode)
        If (!(Test-Connection -ComputerName $AccessNode -Count 1)) {
            Throw "Access node can't be reachable!"
        }
        Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSStorageHealth] Selected access node as [$AccessNode]"
        #endregion

        #region Access Node CimSession
        $ActiveStepId++ #6
        Write-Progress -Activity "Getting CPS Storage Health.." -Status "Processing: Step $ActiveStepId of $TotalSteps" -Id $RootActivityId -PercentComplete (($ActiveStepId / $TotalSteps)*100) -CurrentOperation "Establishing CimSession To Access Node.."
        Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSStorageHealth] Establishing a CimSession to active cluster node [$AccessNode]..."
        Try {
            $CimSession = New-CimSession -ComputerName $AccessNode -Name $(Join-Path -Path "CimSession-" -ChildPath "$(Get-Date -Format "yyyy-MM-dd-mm-ss")")
            If ($CimSession.TestConnection()) {
                Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSStorageHealth] Successfully established a CimSession to active cluster node [$AccessNode]"
            }
        }
        Catch {
            Write-Warning -Message "[$((Get-Date).ToString())] [Get-CPSStorageHealth] Unable to establish a CimSession to active cluster node [$AccessNode]!"
            Write-Error -Exception $_.Exception -Message $_.Exception.Message -ErrorAction Stop
        }
        #endregion

        #region Get Cluster Logs
        $ActiveStepId++ #7
        Write-Progress -Activity "Getting CPS Storage Health.." -Status "Processing: Step $ActiveStepId of $TotalSteps" -Id $RootActivityId -PercentComplete (($ActiveStepId / $TotalSteps)*100) -CurrentOperation "Getting Cluster Logs.."

        #region Script Block Cluster Logs
        $ScriptBlockClusterLogs = {
            [CmdletBinding()]
            Param (
                [Parameter(Position = 0, Mandatory = $True)]
                $ClusterName,

                [Parameter(Position = 1, Mandatory = $True)]
                $Destination
            )

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
                    Import-Module -Name FailoverClusters -Verbose:$False
                    $VerbosePreference = $SaveVerbosePreference
                }
                Catch {
                    Write-Error -Exception $_.Exception -Message $_.Exception.Message -ErrorAction Stop
                }
            }

            Process {
                Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSStorageHealth] [Get-ClusterLog] Creating a log file for all nodes in a failover cluster [$ClusterName]..."
                $ClusterLogs = Get-ClusterLog -Cluster $ClusterName -UseLocalTime -Destination $Destination
                Write-Output -InputObject $ClusterLogs
                $DestinationArchiveFilePath = Join-Path -Path $(Split-Path -Path $Destination) -ChildPath "$(Split-Path -Path $Destination -Leaf).zip"
                New-Archive -Path $Destination -ArchivePath $DestinationArchiveFilePath -CompressionLevel Optimal
                If (Test-Path -Path $DestinationArchiveFilePath) {
                    Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSStorageHealth] [Remove-Item] Removing the previously copied raw cluster log files from [$Destination]..."
                    Remove-Item -Path $Destination -Recurse -Force
                }
            }

            End {
                [System.GC]::Collect()
            }
        }
        #endregion

$CPSUtilityModulePath = $(Get-Module -Name "Apps.Utility.PowerShell").Path.Replace('psm1','psd1')
$ClusterLogsInitializationScript = @"
Import-Module -Name $CPSUtilityModulePath -Force -Verbose:$False
"@
        $ClusterLogsInitializationScriptBlock = [ScriptBlock]::Create($ClusterLogsInitializationScript)
        $ClusterLogsDestination = "$($WriteToFolderPath.TrimEnd('\'))\ClusterLogs\$ClusterName\"
        Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSStorageHealth] [Start-Job] Initiating a background job to create a log file for all nodes in a failover cluster [$ClusterName]..."
        If ($PSBoundParameters['Verbose'] -and $PSBoundParameters['Debug']) {
            $ClusterLogJob = Start-Job -Name $([GUID]::NewGuid().Guid) -InitializationScript $ClusterLogsInitializationScriptBlock -ScriptBlock $ScriptBlockClusterLogs -ArgumentList $ClusterName, $ClusterLogsDestination -Verbose -Debug
        }
        ElseIf ($PSBoundParameters['Verbose']) {
            $ClusterLogJob = Start-Job -Name $([GUID]::NewGuid().Guid) -InitializationScript $ClusterLogsInitializationScriptBlock -ScriptBlock $ScriptBlockClusterLogs -ArgumentList $ClusterName, $ClusterLogsDestination -Verbose
        }
        ElseIf ($PSBoundParameters['Debug']) {
            $ClusterLogJob = Start-Job -Name $([GUID]::NewGuid().Guid) -InitializationScript $ClusterLogsInitializationScriptBlock -ScriptBlock $ScriptBlockClusterLogs -ArgumentList $ClusterName, $ClusterLogsDestination -Debug
        }
        Else {
            $ClusterLogJob = Start-Job -Name $([GUID]::NewGuid().Guid) -InitializationScript $ClusterLogsInitializationScriptBlock -ScriptBlock $ScriptBlockClusterLogs -ArgumentList $ClusterName, $ClusterLogsDestination
        }
        Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSStorageHealth] A background job [Name: $($ClusterLogJob.Name)] [Id: $($ClusterLogJob.Id)] has been created successfully."
        $BackgroundJobs += $ClusterLogJob
        $HashTable.Add("ClusterLogs", $True)
        #endregion

        #region Backup Event Logs
        If ($PSBoundParameters['IncludeEventLogs']) {
            $ActiveStepId++ #8
            Write-Progress -Activity "Getting CPS Storage Health.." -Status "Processing: Step $ActiveStepId of $TotalSteps" -Id $RootActivityId -PercentComplete (($ActiveStepId / $TotalSteps)*100) -CurrentOperation "Backup Event Logs.."
            $StorageNodes = $ClusterNodes | Select-Object Name | ForEach-Object {$_.Name}
            $EventLogsDestination = "$($WriteToFolderPath.TrimEnd('\'))\EventLogs\"
            Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSStorageHealth] [BackUp-EventLog] Copying event logs from $($StorageNodes.Count) storage nodes..."
            If ($PSBoundParameters['Verbose'] -and $PSBoundParameters['Debug']) {
                $StorageNodes | BackUp-EventLog -Destination $EventLogsDestination -Compress -ParentActivityId $RootActivityId -Verbose -Debug
            }
            ElseIf ($PSBoundParameters['Verbose']) {
                $StorageNodes | BackUp-EventLog -Destination $EventLogsDestination -Compress -ParentActivityId $RootActivityId -Verbose
            }
            ElseIf ($PSBoundParameters['Debug']) {
                $StorageNodes | BackUp-EventLog -Destination $EventLogsDestination -Compress -ParentActivityId $RootActivityId -Debug
            }
            Else {
                $StorageNodes | BackUp-EventLog -Destination $EventLogsDestination -Compress -ParentActivityId $RootActivityId
            }
            $HashTable.Add("IncludeEventLogs", $True)
        }
        #endregion

        #region Get Memory Dumps
        If ($PSBoundParameters['IncludeMemoryDumps']) {
            $ActiveStepId++ #9
            Write-Progress -Activity "Getting CPS Storage Health.." -Status "Processing: Step $ActiveStepId of $TotalSteps" -Id $RootActivityId -PercentComplete (($ActiveStepId / $TotalSteps)*100) -CurrentOperation "Getting Memory Dumps.."
            $StorageNodes = $ClusterNodes | Select-Object Name | ForEach-Object {$_.Name}
            $MemoryDumpsDestination = "$($WriteToFolderPath.TrimEnd('\'))\MemoryDumps\"
            Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSStorageHealth] [Get-MemoryDump] Copying memory dumps from $($StorageNodes.Count) storage nodes..."
            If ($PSBoundParameters['Verbose'] -and $PSBoundParameters['Debug']) {
                $StorageNodes | Get-MemoryDump -Destination $MemoryDumpsDestination -Compress -ParentActivityId $RootActivityId -Verbose -Debug
            }
            ElseIf ($PSBoundParameters['Verbose']) {
                $StorageNodes | Get-MemoryDump -Destination $MemoryDumpsDestination -Compress -ParentActivityId $RootActivityId -Verbose
            }
            ElseIf ($PSBoundParameters['Debug']) {
                $StorageNodes | Get-MemoryDump -Destination $MemoryDumpsDestination -Compress -ParentActivityId $RootActivityId -Debug
            }
            Else {
                $StorageNodes | Get-MemoryDump -Destination $MemoryDumpsDestination -Compress -ParentActivityId $RootActivityId
            }
            $HashTable.Add("IncludeMemoryDumps", $True)
        }
        #endregion

        #region Cluster Groups
        $ActiveStepId++ #10
        Write-Progress -Activity "Getting CPS Storage Health.." -Status "Processing: Step $ActiveStepId of $TotalSteps" -Id $RootActivityId -PercentComplete (($ActiveStepId / $TotalSteps)*100) -CurrentOperation "Getting Cluster Groups.."
        Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSStorageHealth] [Get-ClusterGroup] Getting cluster groups for the cluster [$ClusterName]..."
        $ClusterGroups = Get-ClusterGroup -Cluster $ClusterName # Cluster Groups
        $HashTable.Add("ClusterGroups", $ClusterGroups)
        $BackgroundJobs += Write-ClixmlAsync -InputObject $ClusterGroups -WriteToFolderPath $WriteToFolderPath -WriteToFileName "ClusterGroups"
        Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSStorageHealth] Identified $($ClusterGroups.Count) cluster groups."
        Try {
            Write-Debug -Message "[$((Get-Date).ToString())] [Get-CPSStorageHealth] Debug Info (Cluster Groups): $($ClusterGroups | ConvertTo-Json)"
        }
        Catch {
            Write-Debug -Message "[$((Get-Date).ToString())] [Get-CPSStorageHealth] Debug Info (Cluster Groups): $($ClusterGroups | ConvertTo-Json -Compress)"
        }
        #endregion

        #region Cluster Networks
        $ActiveStepId++ #11
        Write-Progress -Activity "Getting CPS Storage Health.." -Status "Processing: Step $ActiveStepId of $TotalSteps" -Id $RootActivityId -PercentComplete (($ActiveStepId / $TotalSteps)*100) -CurrentOperation "Getting Cluster Networks.."
        Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSStorageHealth] [Get-ClusterNetwork] Getting cluster networks..."
        $ClusterNetworks = Get-ClusterNetwork -Cluster $ClusterName # Cluster Networks
        $HashTable.Add("ClusterNetworks", $ClusterNetworks)
        $BackgroundJobs += Write-ClixmlAsync -InputObject $ClusterNetworks -WriteToFolderPath $WriteToFolderPath -WriteToFileName "ClusterNetworks"
        Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSStorageHealth] Identified $($ClusterNetworks.Count) cluster networks."
        Try {
            Write-Debug -Message "[$((Get-Date).ToString())] [Get-CPSStorageHealth] Debug Info (Cluster Networks): $($ClusterNetworks | ConvertTo-Json)"
        }
        Catch {
            Write-Debug -Message "[$((Get-Date).ToString())] [Get-CPSStorageHealth] Debug Info (Cluster Networks): $($ClusterNetworks | ConvertTo-Json -Compress)"
        }
        #endregion

        #region Cluster Resources
        $ActiveStepId++ #12
        Write-Progress -Activity "Getting CPS Storage Health.." -Status "Processing: Step $ActiveStepId of $TotalSteps" -Id $RootActivityId -PercentComplete (($ActiveStepId / $TotalSteps)*100) -CurrentOperation "Getting Cluster Resources.."
        Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSStorageHealth] [Get-ClusterResource] Getting cluster resources..."
        $ClusterResources = Get-ClusterResource -Cluster $ClusterName # Cluster Resources
        $HashTable.Add("ClusterResources", $ClusterResources)
        $BackgroundJobs += Write-ClixmlAsync -InputObject $ClusterResources -WriteToFolderPath $WriteToFolderPath -WriteToFileName "ClusterResources"
        Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSStorageHealth] Identified $($ClusterResources.Count) cluster resources."
        Try {
            Write-Debug -Message "[$((Get-Date).ToString())] [Get-CPSStorageHealth] Debug Info (Cluster Resources): $($ClusterResources | ConvertTo-Json)"
        }
        Catch {
            Write-Debug -Message "[$((Get-Date).ToString())] [Get-CPSStorageHealth] Debug Info (Cluster Resources): $($ClusterResources | ConvertTo-Json -Compress)"
        }
        #endregion

        #region Cluster Shared Volumes
        $ActiveStepId++ #13
        Write-Progress -Activity "Getting CPS Storage Health.." -Status "Processing: Step $ActiveStepId of $TotalSteps" -Id $RootActivityId -PercentComplete (($ActiveStepId / $TotalSteps)*100) -CurrentOperation "Getting Cluster Shared Volumes.."
        Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSStorageHealth] Getting cluster shared volumes..."
        $ClusterSharedVolumes = Get-ClusterSharedVolume -Cluster $ClusterName # Cluster Shared Volumes
        $HashTable.Add("ClusterSharedVolumes", $ClusterSharedVolumes)
        $BackgroundJobs += Write-ClixmlAsync -InputObject $ClusterSharedVolumes -WriteToFolderPath $WriteToFolderPath -WriteToFileName "ClusterSharedVolumes"
        Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSStorageHealth] Identified $($ClusterSharedVolumes.Count) cluster shared volumes."
        Try {
            Write-Debug -Message "[$((Get-Date).ToString())] [Get-CPSStorageHealth] Debug Info (Cluster Shared Volumes): $($ClusterSharedVolumes | ConvertTo-Json)"
        }
        Catch {
            Write-Debug -Message "[$((Get-Date).ToString())] [Get-CPSStorageHealth] Debug Info (Cluster Shared Volumes): $($ClusterSharedVolumes | ConvertTo-Json -Compress)"
        }
        #endregion

        #region Scale-Out File Servers
        $ActiveStepId++ #14
        Write-Progress -Activity "Getting CPS Storage Health.." -Status "Processing: Step $ActiveStepId of $TotalSteps" -Id $RootActivityId -PercentComplete (($ActiveStepId / $TotalSteps)*100) -CurrentOperation "Getting Scale-Out File Servers.."
        Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSStorageHealth] Identifying Scale-Out file servers..."
        $ScaleOutFileServers = $ClusterGroups | Where-Object { $_.GroupType -like 'ScaleOut*' } # Scale Out File Servers
        $HashTable.Add("ScaleOutFileServers", $ScaleOutFileServers)
        $BackgroundJobs += Write-ClixmlAsync -InputObject $ScaleOutFileServers -WriteToFolderPath $WriteToFolderPath -WriteToFileName "ScaleOutFileServers"
        Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSStorageHealth] Identified $($ScaleOutFileServers.Count) Scale-Out file servers."
        Try {
            Write-Debug -Message "[$((Get-Date).ToString())] [Get-CPSStorageHealth] Debug Info (Scale-Out File Servers): $($ScaleOutFileServers | ConvertTo-Json)"
        }
        Catch {
            Write-Debug -Message "[$((Get-Date).ToString())] [Get-CPSStorageHealth] Debug Info (Scale-Out File Servers): $($ScaleOutFileServers | ConvertTo-Json -Compress)"
        }
        #endregion

        #region SMB Shares
        $ActiveStepId++ #15
        Write-Progress -Activity "Getting CPS Storage Health.." -Status "Processing: Step $ActiveStepId of $TotalSteps" -Id $RootActivityId -PercentComplete (($ActiveStepId / $TotalSteps)*100) -CurrentOperation "Getting SMB Shares.."
        Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSStorageHealth] [Get-SmbShare] Getting SMB shares..."
        $SmbShares = Get-SmbShare -CimSession $CimSession # SMB Shares
        $HashTable.Add("SmbShares", $SmbShares)
        $BackgroundJobs += Write-ClixmlAsync -InputObject $SmbShares -WriteToFolderPath $WriteToFolderPath -WriteToFileName "SmbShares"
        Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSStorageHealth] Identified $($SmbShares.Count) SMB shares."
        Try {
            Write-Debug -Message "[$((Get-Date).ToString())] [Get-CPSStorageHealth] Debug Info (SMB Shares): $($SmbShares | ConvertTo-Json)"
        }
        Catch {
            Write-Debug -Message "[$((Get-Date).ToString())] [Get-CPSStorageHealth] Debug Info (SMB Shares): $($SmbShares | ConvertTo-Json -Compress)"
        }
        #endregion

        #region SMB Open Files
        $ActiveStepId++ #16
        Write-Progress -Activity "Getting CPS Storage Health.." -Status "Processing: Step $ActiveStepId of $TotalSteps" -Id $RootActivityId -PercentComplete (($ActiveStepId / $TotalSteps)*100) -CurrentOperation "Getting SMB Open Files.."
        Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSStorageHealth] [Get-SmbOpenFile] Getting SMB open files..."
        $SmbOpenFiles = Get-SmbOpenFile -CimSession $CimSession
        $HashTable.Add("SmbOpenFiles", $SmbOpenFiles)
        $BackgroundJobs += Write-ClixmlAsync -InputObject $SmbOpenFiles -WriteToFolderPath $WriteToFolderPath -WriteToFileName "SmbOpenFiles"
        Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSStorageHealth] Identified $($SmbOpenFiles.Count) SMB open files."
        Try {
            Write-Debug -Message "[$((Get-Date).ToString())] [Get-CPSStorageHealth] Debug Info (SMB Open Files): $($SmbOpenFiles | ConvertTo-Json)"
        }
        Catch {
            Write-Debug -Message "[$((Get-Date).ToString())] [Get-CPSStorageHealth] Debug Info (SMB Open Files): $($SmbOpenFiles | ConvertTo-Json -Compress)"
        }
        #endregion

        #region SMB Witness Clients
        $ActiveStepId++ #17
        Write-Progress -Activity "Getting CPS Storage Health.." -Status "Processing: Step $ActiveStepId of $TotalSteps" -Id $RootActivityId -PercentComplete (($ActiveStepId / $TotalSteps)*100) -CurrentOperation "Getting SMB Witness Clients.."
        Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSStorageHealth] [Get-SmbWitnessClient] Getting SMB witness clients..."
        $SmbWitnessClients = Get-SmbWitnessClient -CimSession $CimSession
        $HashTable.Add("SmbWitnessClients", $SmbWitnessClients)
        $BackgroundJobs += Write-ClixmlAsync -InputObject $SmbWitnessClients -WriteToFolderPath $WriteToFolderPath -WriteToFileName "SmbWitnessClients"
        Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSStorageHealth] Identified $($SmbWitnessClients.Count) SMB witness clients."
        Try {
            Write-Debug -Message "[$((Get-Date).ToString())] [Get-CPSStorageHealth] Debug Info (SMB Witness Clients): $($SmbWitnessClients | ConvertTo-Json)"
        }
        Catch {
            Write-Debug -Message "[$((Get-Date).ToString())] [Get-CPSStorageHealth] Debug Info (SMB Witness Clients): $($SmbWitnessClients | ConvertTo-Json -Compress)"
        }
        #endregion

        #region Virtual Disks
        $ActiveStepId++ #18
        Write-Progress -Activity "Getting CPS Storage Health.." -Status "Processing: Step $ActiveStepId of $TotalSteps" -Id $RootActivityId -PercentComplete (($ActiveStepId / $TotalSteps)*100) -CurrentOperation "Getting Virtual Disks.."
        Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSStorageHealth] [Get-VirtualDisk] Getting virtual disks..."
        $VirtualDisks = Get-VirtualDisk -CimSession $CimSession # Virtual Disks
        $HashTable.Add("VirtualDisks", $VirtualDisks)
        $BackgroundJobs += Write-ClixmlAsync -InputObject $VirtualDisks -WriteToFolderPath $WriteToFolderPath -WriteToFileName "VirtualDisks"
        Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSStorageHealth] Identified $($VirtualDisks.Count) virtual disks."
        Try {
            Write-Debug -Message "[$((Get-Date).ToString())] [Get-CPSStorageHealth] Debug Info (Virtual Disks): $($VirtualDisks | ConvertTo-Json)"
        }
        Catch {
            Write-Debug -Message "[$((Get-Date).ToString())] [Get-CPSStorageHealth] Debug Info (Virtual Disks): $($VirtualDisks | ConvertTo-Json -Compress)"
        }
        #endregion

        #region Physical Disks
        $ActiveStepId++ #19
        Write-Progress -Activity "Getting CPS Storage Health.." -Status "Processing: Step $ActiveStepId of $TotalSteps" -Id $RootActivityId -PercentComplete (($ActiveStepId / $TotalSteps)*100) -CurrentOperation "Getting Physical Disks.."
        Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSStorageHealth] [Get-PhysicalDisk] Getting physical disks..."
        $PhysicalDisks = Get-PhysicalDisk -CimSession $CimSession
        $HashTable.Add("PhysicalDisks", $PhysicalDisks)
        $BackgroundJobs += Write-ClixmlAsync -InputObject $PhysicalDisks -WriteToFolderPath $WriteToFolderPath -WriteToFileName "PhysicalDisks"
        Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSStorageHealth] Identified $($PhysicalDisks.Count) physical disks."
        Try {
            Write-Debug -Message "[$((Get-Date).ToString())] [Get-CPSStorageHealth] Debug Info (Physical Disks): $($PhysicalDisks | ConvertTo-Json)"
        }
        Catch {
            Write-Debug -Message "[$((Get-Date).ToString())] [Get-CPSStorageHealth] Debug Info (Physical Disks): $($PhysicalDisks | ConvertTo-Json -Compress)"
        }
        #endregion

        #region Storage Pools
        $ActiveStepId++ #20
        Write-Progress -Activity "Getting CPS Storage Health.." -Status "Processing: Step $ActiveStepId of $TotalSteps" -Id $RootActivityId -PercentComplete (($ActiveStepId / $TotalSteps)*100) -CurrentOperation "Getting Storage Pools.."
        Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSStorageHealth] [Get-StoragePool] Getting storage pools..."
        $StoragePools = Get-StoragePool -CimSession $CimSession # Storage Pools
        $HashTable.Add("StoragePools", $StoragePools)
        $BackgroundJobs += Write-ClixmlAsync -InputObject $StoragePools -WriteToFolderPath $WriteToFolderPath -WriteToFileName "StoragePools"
        Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSStorageHealth] Identified $($StoragePools.Count) storage pools."
        Try {
            Write-Debug -Message "[$((Get-Date).ToString())] [Get-CPSStorageHealth] Debug Info (Storage Pools): $($StoragePools | ConvertTo-Json)"
        }
        Catch {
            Write-Debug -Message "[$((Get-Date).ToString())] [Get-CPSStorageHealth] Debug Info (Storage Pools): $($StoragePools | ConvertTo-Json -Compress)"
        }
        #endregion

        #region Volumes
        $ActiveStepId++ #21
        Write-Progress -Activity "Getting CPS Storage Health.." -Status "Processing: Step $ActiveStepId of $TotalSteps" -Id $RootActivityId -PercentComplete (($ActiveStepId / $TotalSteps)*100) -CurrentOperation "Getting Volumes.."
        Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSStorageHealth] [Get-Volume] Getting volumes..."
        $Volumes = Get-Volume -CimSession $CimSession # Volumes
        $HashTable.Add("Volumes", $Volumes)
        $BackgroundJobs += Write-ClixmlAsync -InputObject $Volumes -WriteToFolderPath $WriteToFolderPath -WriteToFileName "Volumes"
        Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSStorageHealth] Identified $($Volumes.Count) volumes."
        Try {
            Write-Debug -Message "[$((Get-Date).ToString())] [Get-CPSStorageHealth] Debug Info (Volumes): $($Volumes | ConvertTo-Json)"
        }
        Catch {
            Write-Debug -Message "[$((Get-Date).ToString())] [Get-CPSStorageHealth] Debug Info (Volumes): $($Volumes | ConvertTo-Json -Compress)"
        }
        #endregion

        #region Plug and Play (PnP) Signed Drivers
        $ActiveStepId++ #22
        Write-Progress -Activity "Getting CPS Storage Health.." -Status "Processing: Step $ActiveStepId of $TotalSteps" -Id $RootActivityId -PercentComplete (($ActiveStepId / $TotalSteps)*100) -CurrentOperation "Getting Plug and Play (PnP) Signed Drivers.."
        Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSStorageHealth] [Get-CimInstance -ClassName Win32_PnPSignedDriver] Getting Plug and Play (PnP) signed drivers..."
        $StorageNodes = $ClusterNodes | Select-Object Name | ForEach-Object {$_.Name}
        $PnPSignedDrivers = @()
        ForEach ($StorageNode in $StorageNodes) {
            $PnPSignedDrivers_StorageNode = Get-CimInstance -ClassName Win32_PnPSignedDriver -ComputerName $StorageNode
            $PnPSignedDrivers += $PnPSignedDrivers_StorageNode
            $BackgroundJobs += Write-ClixmlAsync -InputObject $PnPSignedDrivers_StorageNode -WriteToFolderPath $WriteToFolderPath -WriteToFileName "P&PSignedDrivers_$StorageNode"
        }
        $HashTable.Add("P&PSignedDrivers", $PnPSignedDrivers)
        Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSStorageHealth] Identified $($PnPSignedDrivers.Count) Plug and Play (PnP) signed drivers from $($StorageNodes.Count) storage nodes."
        Try {
            Write-Debug -Message "[$((Get-Date).ToString())] [Get-CPSStorageHealth] Debug Info (Plug and Play (PnP) Signed Drivers): $($PnPSignedDrivers | ConvertTo-Json)"
        }
        Catch {
            Write-Debug -Message "[$((Get-Date).ToString())] [Get-CPSStorageHealth] Debug Info (Plug and Play (PnP) Signed Drivers): $($PnPSignedDrivers | ConvertTo-Json -Compress)"
        }
        #endregion

        #region Storage Sub-System
        $ActiveStepId++ #23
        Write-Progress -Activity "Getting CPS Storage Health.." -Status "Processing: Step $ActiveStepId of $TotalSteps" -Id $RootActivityId -PercentComplete (($ActiveStepId / $TotalSteps)*100) -CurrentOperation "Getting Storage Sub-System.."
        Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSStorageHealth] Getting storage sub-system information..."
        $StorageSubSystem = Get-StorageSubSystem -FriendlyName Cluster* -CimSession $CimSession # Storage Sub System
        $HashTable.Add("StorageSubSystem", $StorageSubSystem)
        $BackgroundJobs += Write-ClixmlAsync -InputObject $StorageSubSystem -WriteToFolderPath $WriteToFolderPath -WriteToFileName "StorageSubSystem"
        Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSStorageHealth] Identified storage sub-system as [$($StorageSubSystem.Name)]"
        Try {
            Write-Debug -Message "[$((Get-Date).ToString())] [Get-CPSStorageHealth] Debug Info (Storage Sub System): $($StorageSubSystem | ConvertTo-Json)"
        }
        Catch {
            Write-Debug -Message "[$((Get-Date).ToString())] [Get-CPSStorageHealth] Debug Info (Storage Sub System): $($StorageSubSystem | ConvertTo-Json -Compress)"
        }
        #endregion

        #region Storage Sub-System Storage Pools
        $ActiveStepId++ #24
        Write-Progress -Activity "Getting CPS Storage Health.." -Status "Processing: Step $ActiveStepId of $TotalSteps" -Id $RootActivityId -PercentComplete (($ActiveStepId / $TotalSteps)*100) -CurrentOperation "Getting Storage Sub-System Storage Pools.."
        Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSStorageHealth] [Get-StoragePool]  Getting storage pools for storage sub-system [$($StorageSubSystem.FriendlyName)]..."
        $StorageSubSystemStoragePools = Get-StoragePool -IsPrimordial $False -CimSession $CimSession -StorageSubSystem $StorageSubSystem # Storage Pools In Storage Sub System
        $HashTable.Add("StorageSubSystemStoragePools", $StorageSubSystemStoragePools)
        $BackgroundJobs += Write-ClixmlAsync -InputObject $StorageSubSystemStoragePools -WriteToFolderPath $WriteToFolderPath -WriteToFileName "StorageSubSystemStoragePools"
        Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSStorageHealth] Identified $($StoragePools.Count) storage pools."
        Try {
            Write-Debug -Message "[$((Get-Date).ToString())] [Get-CPSStorageHealth] Debug Info (Storage Pools In Storage Sub System): $($StorageSubSystemStoragePools | ConvertTo-Json)"
        }
        Catch {
            Write-Debug -Message "[$((Get-Date).ToString())] [Get-CPSStorageHealth] Debug Info (Storage Pools In Storage Sub System): $($StorageSubSystemStoragePools | ConvertTo-Json -Compress)"
        }
        #endregion

        #region Storage Sub System Physical Disks
        $ActiveStepId++ #25
        Write-Progress -Activity "Getting CPS Storage Health.." -Status "Processing: Step $ActiveStepId of $TotalSteps" -Id $RootActivityId -PercentComplete (($ActiveStepId / $TotalSteps)*100) -CurrentOperation "Getting Storage Sub System Physical Disks.."
        $ScriptBlockStorageSubSystemPhysicalDisks = {
            [CmdletBinding()]
            Param (
                [Parameter(Mandatory=$True)]
                $PhysicalDisk
            )

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
                    Import-Module -Name Storage -Verbose:$False
                    $VerbosePreference = $SaveVerbosePreference
                }
                Catch {
                    Write-Error -Exception $_.Exception -Message $_.Exception.Message -ErrorAction Stop
                }
            }

            Process {
                Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSStorageHealth] [Invoke-PSRunSpace] [Get-StorageSubSystem] Getting storage sub system information associated with the given physical disk [Name: $($PhysicalDisk.FriendlyName)] [UniqueId: $($PhysicalDisk.UniqueId)]..."
                $StorageSubSystem = Get-StorageSubSystem -PhysicalDisk $PhysicalDisk
                Try {
                    Write-Debug -Message "[$((Get-Date).ToString())] [Get-CPSStorageHealth] [Invoke-PSRunSpace] Debug Info (Storage Sub-System Physical Disk): $($StorageSubSystem | ConvertTo-Json)"
                }
                Catch {
                    Write-Debug -Message "[$((Get-Date).ToString())] [Get-CPSStorageHealth] [Invoke-PSRunSpace] Debug Info (Storage Sub-System Physical Disk): $($StorageSubSystem | ConvertTo-Json -Compress)"
                }
                Write-Output -InputObject $StorageSubSystem
            }

            End {
                [System.GC]::Collect()
            }
        }

        $PhysicalDisks_ = $PhysicalDisks | Where-Object { ($_.OperationalStatus -ne "Detached") -and ($_.OperationalStatus -ne "Lost Communication") }
        Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSStorageHealth] [Invoke-PSRunSpace] Getting storage sub system information associated with the given $($PhysicalDisks_.Count) physical disks..."
        # Storage Sub System Physical Disks
        If ($PSBoundParameters['Verbose'] -and $PSBoundParameters['Debug']) {
            $StorageSubSystemPhysicalDisks = Invoke-PSRunSpace -InputObject $PhysicalDisks_ -ScriptBlock $ScriptBlockStorageSubSystemPhysicalDisks -MaxThreads $MaxThreads -SendInputObjectInstance -Verbose -Debug
        }
        ElseIf ($PSBoundParameters['Verbose']) {
            $StorageSubSystemPhysicalDisks = Invoke-PSRunSpace -InputObject $PhysicalDisks_ -ScriptBlock $ScriptBlockStorageSubSystemPhysicalDisks -MaxThreads $MaxThreads -SendInputObjectInstance -Verbose
        }
        ElseIf ($PSBoundParameters['Debug']) {
            $StorageSubSystemPhysicalDisks = Invoke-PSRunSpace -InputObject $PhysicalDisks_ -ScriptBlock $ScriptBlockStorageSubSystemPhysicalDisks -MaxThreads $MaxThreads -SendInputObjectInstance -Debug
        }
        Else {
            $StorageSubSystemPhysicalDisks = Invoke-PSRunSpace -InputObject $PhysicalDisks_ -ScriptBlock $ScriptBlockStorageSubSystemPhysicalDisks -MaxThreads $MaxThreads -SendInputObjectInstance
        }
        $HashTable.Add("StorageSubSystemPhysicalDisks", $StorageSubSystemPhysicalDisks)
        $BackgroundJobs += Write-ClixmlAsync -InputObject $StorageSubSystemPhysicalDisks -WriteToFolderPath $WriteToFolderPath -WriteToFileName "StorageSubSystemPhysicalDisks"
        Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSStorageHealth] Identified $($StorageSubSystemPhysicalDisks.Count) storage sub system objects."
        Try {
            Write-Debug -Message "[$((Get-Date).ToString())] [Get-CPSStorageHealth] Debug Info (Storage Sub-System Physical Disks): $($StorageSubSystemPhysicalDisks | ConvertTo-Json)"
        }
        Catch {
            Write-Debug -Message "[$((Get-Date).ToString())] [Get-CPSStorageHealth] Debug Info (Storage Sub-System Physical Disks): $($StorageSubSystemPhysicalDisks | ConvertTo-Json -Compress)"
        }
        #endregion

        #region Storage Sub System Virtual Disks
        $ActiveStepId++ #26
        Write-Progress -Activity "Getting CPS Storage Health.." -Status "Processing: Step $ActiveStepId of $TotalSteps" -Id $RootActivityId -PercentComplete (($ActiveStepId / $TotalSteps)*100) -CurrentOperation "Getting Storage Sub System Virtual Disks.."
        $ScriptBlockStorageSubSystemVirtualDisks = {
            [CmdletBinding()]
            Param (
                [Parameter(Mandatory=$True)]
                $VirtualDisk
            )

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
                    Import-Module -Name Storage -Verbose:$False
                    $VerbosePreference = $SaveVerbosePreference
                }
                Catch {
                    Write-Error -Exception $_.Exception -Message $_.Exception.Message -ErrorAction Stop
                }
            }

            Process {
                Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSStorageHealth] [Invoke-PSRunSpace] [Get-StorageSubSystem] Getting storage sub system information associated with the given virtual disk [Name: $($VirtualDisk.FriendlyName)] [UniqueId: $($VirtualDisk.UniqueId)]..."
                $StorageSubSystem = Get-StorageSubSystem -VirtualDisk $VirtualDisk
                Try {
                    Write-Debug -Message "[$((Get-Date).ToString())] [Get-CPSStorageHealth] [Invoke-PSRunSpace] Debug Info (Storage Sub-System Virtual Disk): $($StorageSubSystem | ConvertTo-Json)"
                }
                Catch {
                    Write-Debug -Message "[$((Get-Date).ToString())] [Get-CPSStorageHealth] [Invoke-PSRunSpace] Debug Info (Storage Sub-System Virtual Disk): $($StorageSubSystem | ConvertTo-Json -Compress)"
                }
                Write-Output -InputObject $StorageSubSystem
            }

            End {
                [System.GC]::Collect()
            }
        }

        Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSStorageHealth] [Invoke-PSRunSpace] Getting storage sub system information associated with the given $($VirtualDisks.Count) virtual disks..."
        # Storage Sub System Virtual Disks
        If ($PSBoundParameters['Verbose'] -and $PSBoundParameters['Debug']) {
            $StorageSubSystemVirtualDisks = Invoke-PSRunSpace -InputObject $VirtualDisks -ScriptBlock $ScriptBlockStorageSubSystemVirtualDisks -MaxThreads $MaxThreads -SendInputObjectInstance -Verbose -Debug
        }
        ElseIf ($PSBoundParameters['Verbose']) {
            $StorageSubSystemVirtualDisks = Invoke-PSRunSpace -InputObject $VirtualDisks -ScriptBlock $ScriptBlockStorageSubSystemVirtualDisks -MaxThreads $MaxThreads -SendInputObjectInstance -Verbose
        }
        ElseIf ($PSBoundParameters['Debug']) {
            $StorageSubSystemVirtualDisks = Invoke-PSRunSpace -InputObject $VirtualDisks -ScriptBlock $ScriptBlockStorageSubSystemVirtualDisks -MaxThreads $MaxThreads -SendInputObjectInstance -Debug
        }
        Else {
            $StorageSubSystemVirtualDisks = Invoke-PSRunSpace -InputObject $VirtualDisks -ScriptBlock $ScriptBlockStorageSubSystemVirtualDisks -MaxThreads $MaxThreads -SendInputObjectInstance
        }
        $HashTable.Add("StorageSubSystemVirtualDisks", $StorageSubSystemVirtualDisks)
        $BackgroundJobs += Write-ClixmlAsync -InputObject $StorageSubSystemVirtualDisks -WriteToFolderPath $WriteToFolderPath -WriteToFileName "StorageSubSystemVirtualDisks"
        Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSStorageHealth] Identified $($StorageSubSystemVirtualDisks.Count) storage sub system objects."
        Try {
            Write-Debug -Message "[$((Get-Date).ToString())] [Get-CPSStorageHealth] Debug Info (Storage Sub-System Virtual Disks): $($StorageSubSystemVirtualDisks | ConvertTo-Json)"
        }
        Catch {
            Write-Debug -Message "[$((Get-Date).ToString())] [Get-CPSStorageHealth] Debug Info (Storage Sub-System Virtual Disks): $($StorageSubSystemVirtualDisks | ConvertTo-Json -Compress)"
        }
        #endregion

        #region Storage Reliability Counters
        If ($PSBoundParameters['IncludeReliabilityCounters']) {
            $ActiveStepId++ #27
            Write-Progress -Activity "Getting CPS Storage Health.." -Status "Processing: Step $ActiveStepId of $TotalSteps" -Id $RootActivityId -PercentComplete (($ActiveStepId / $TotalSteps)*100) -CurrentOperation "Getting Storage Reliability Counters.."
            $ScriptBlockStorageReliabilityCounters = {
                [CmdletBinding()]
                Param (
                    [Parameter(Mandatory=$True)]
                    $PhysicalDisk,

                    [Parameter(Mandatory=$True)]
                    $AccessNode
                )

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
                        Import-Module -Name Storage -Verbose:$False
                        $VerbosePreference = $SaveVerbosePreference
                    }
                    Catch {
                        Write-Error -Exception $_.Exception -Message $_.Exception.Message -ErrorAction Stop
                    }
                }

                Process {
                    Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSStorageHealth] [Invoke-PSRunSpace] [Get-StorageReliabilityCounter] Getting storage reliability counters for the given physical disk [Name: $($PhysicalDisk.FriendlyName)] [UniqueId: $($PhysicalDisk.UniqueId)]..."
                    $ProgressPreference = "SilentlyContinue"
                    $StorageReliabilityCounter = Get-StorageReliabilityCounter -PhysicalDisk $PhysicalDisk -CimSession $AccessNode # Storage Reliability Counters
                    Try {
                        Write-Debug -Message "[$((Get-Date).ToString())] [Get-CPSStorageHealth] [Invoke-PSRunSpace] Debug Info (Storage Reliability Counters): $($StorageReliabilityCounter | ConvertTo-Json)"
                    }
                    Catch {
                        Write-Debug -Message "[$((Get-Date).ToString())] [Get-CPSStorageHealth] [Invoke-PSRunSpace] Debug Info (Storage Reliability Counters): $($StorageReliabilityCounter | ConvertTo-Json -Compress)"
                    }
                    Write-Output -InputObject $StorageReliabilityCounter
                }

                End {
                    [System.GC]::Collect()
                }
            }

            $PhysicalDisks_ = $PhysicalDisks | Where-Object { ($_.OperationalStatus -ne "Detached") -and ($_.OperationalStatus -ne "Lost Communication") }
            Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSStorageHealth] [Invoke-PSRunSpace] Getting storage reliability counters for $($PhysicalDisks_.Count) physical disks..."
            # Storage Reliability Counters
            If ($PSBoundParameters['Verbose'] -and $PSBoundParameters['Debug']) {
                $StorageReliabilityCounters = Invoke-PSRunSpace -InputObject $PhysicalDisks_ -ScriptBlock $ScriptBlockStorageReliabilityCounters -Arguments $AccessNode -MaxThreads $MaxThreads -SendInputObjectInstance -Verbose -Debug
            }
            ElseIf ($PSBoundParameters['Verbose']) {
                $StorageReliabilityCounters = Invoke-PSRunSpace -InputObject $PhysicalDisks_ -ScriptBlock $ScriptBlockStorageReliabilityCounters -Arguments $AccessNode -MaxThreads $MaxThreads -SendInputObjectInstance -Verbose
            }
            ElseIf ($PSBoundParameters['Debug']) {
                $StorageReliabilityCounters = Invoke-PSRunSpace -InputObject $PhysicalDisks_ -ScriptBlock $ScriptBlockStorageReliabilityCounters -Arguments $AccessNode -MaxThreads $MaxThreads -SendInputObjectInstance -Debug
            }
            Else {
                $StorageReliabilityCounters = Invoke-PSRunSpace -InputObject $PhysicalDisks_ -ScriptBlock $ScriptBlockStorageReliabilityCounters -Arguments $AccessNode -MaxThreads $MaxThreads -SendInputObjectInstance
            }
            $HashTable.Add("StorageReliabilityCounters", $StorageReliabilityCounters)
            $BackgroundJobs += Write-ClixmlAsync -InputObject $StorageReliabilityCounters -WriteToFolderPath $WriteToFolderPath -WriteToFileName "StorageReliabilityCounters"
            Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSStorageHealth] Retrieved storage reliability counters."
            Try {
                Write-Debug -Message "[$((Get-Date).ToString())] [Get-CPSStorageHealth] Debug Info (Storage Reliability Counters): $($StorageReliabilityCounters | ConvertTo-Json)"
            }
            Catch {
                Write-Debug -Message "[$((Get-Date).ToString())] [Get-CPSStorageHealth] Debug Info (Storage Reliability Counters): $($StorageReliabilityCounters | ConvertTo-Json -Compress)"
            }
        }
        #endregion

        #region Storage Sub System Storage Enclosure
        $ActiveStepId++ #28
        Write-Progress -Activity "Getting CPS Storage Health.." -Status "Processing: Step $ActiveStepId of $TotalSteps" -Id $RootActivityId -PercentComplete (($ActiveStepId / $TotalSteps)*100) -CurrentOperation "Getting Storage Sub System Storage Enclosure.."
        If (Get-Command -Name '*StorageEnclosure*') {
            Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSStorageHealth] [Get-StorageEnclosure] Getting storage enclosure information of storage sub-system [$($StorageSubSystem.Name)]..."
            $StorageSubSystemEnclosures = Get-StorageEnclosure -CimSession $CimSession -StorageSubSystem $StorageSubsystem # Storage Enclosures
            $HashTable.Add("StorageSubSystemEnclosures", $StorageSubSystemEnclosures)
            $BackgroundJobs += Write-ClixmlAsync -InputObject $StorageSubSystemEnclosures -WriteToFolderPath $WriteToFolderPath -WriteToFileName "StorageSubSystemEnclosures"
            Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSStorageHealth] [Get-StorageEnclosure] Identified $($StorageSubSystemEnclosures.Count) storage enclosures."
            Try {
                Write-Debug -Message "[$((Get-Date).ToString())] [Get-CPSStorageHealth] Debug Info (Storage Sub-System Storage Enclosure): $($StorageSubSystemEnclosures | ConvertTo-Json)"
            }
            Catch {
                Write-Debug -Message "[$((Get-Date).ToString())] [Get-CPSStorageHealth] Debug Info (Storage Sub-System Storage Enclosure): $($StorageSubSystemEnclosures | ConvertTo-Json -Compress)"
            }
        }
        #endregion

        #region Deduplication Status
        $ActiveStepId++ #29
        Write-Progress -Activity "Getting CPS Storage Health.." -Status "Processing: Step $ActiveStepId of $TotalSteps" -Id $RootActivityId -PercentComplete (($ActiveStepId / $TotalSteps)*100) -CurrentOperation "Getting Deduplication Status.."
        Try {
            Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSStorageHealth] [Get-Command -Module Deduplication] Verifying deduplication Cmdlets availability on access node [$AccessNode]..."
            If ($(Invoke-Command -ComputerName $AccessNode {(Get-Command -Module Deduplication)} )) {
                Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSStorageHealth] Deduplication Cmdlets found on access node [$AccessNode]"
                Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSStorageHealth] Getting deduplication status for volumes that have data deduplication metadata..."
                $ScriptBlockDedupStatus = {
                    $ProgressPreference = "SilentlyContinue"
                    Get-DedupStatus
                }
                $DedupVolumes = Invoke-Command -ComputerName $AccessNode -ScriptBlock $ScriptBlockDedupStatus | Select-Object * -ExcludeProperty PSComputerName,RunspaceId,PSShowComputerName # Deduplication Status
                $HashTable.Add("DedupVolumes", $DedupVolumes)
                $BackgroundJobs += Write-ClixmlAsync -InputObject $DedupVolumes -WriteToFolderPath $WriteToFolderPath -WriteToFileName "DedupVolumes"
                Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSStorageHealth] Retrieved deduplication status for $($DedupVolumes.Count) volumes."
                Try {
                    Write-Debug -Message "[$((Get-Date).ToString())] [Get-CPSStorageHealth] Debug Info (Deduplication Status): $($DedupVolumes | ConvertTo-Json)"
                }
                Catch {
                    Write-Debug -Message "[$((Get-Date).ToString())] [Get-CPSStorageHealth] Debug Info (Deduplication Status): $($DedupVolumes | ConvertTo-Json -Compress)"
                }
            }
        }
        Catch {
            Write-Warning -Message "[Get-CPSStorageHealth] Unable to determine deduplication status!"
            Write-Error -Exception $_.Exception -Message $_.Exception.Message
        }
        #endregion

        #region Cluster Shared Volumes (CSV) to Virtual Disks
        $ActiveStepId++ #30
        Write-Progress -Activity "Getting CPS Storage Health.." -Status "Processing: Step $ActiveStepId of $TotalSteps" -Id $RootActivityId -PercentComplete (($ActiveStepId / $TotalSteps)*100) -CurrentOperation "Mapping Cluster Shared Volumes (CSV) to Virtual Disks.."
        $ScriptBlockClusterSharedVolumesToVirtualDisks = {
            [CmdletBinding()]
            Param (
                [Parameter(Mandatory=$True)]
                $VirtualDisk,

                [Parameter(Mandatory=$True)]
                $SmbShares,
            
                [Parameter(Mandatory=$True)]
                $ClusterName
            )

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
                    If (!(Get-Module -Name FailoverClusters)) {
                        Import-Module -Name FailoverClusters -Verbose:$False
                    }
                    $VerbosePreference = $SaveVerbosePreference
                }
                Catch {
                    Write-Error -Exception $_.Exception -Message $_.Exception.Message -ErrorAction Stop
                }
            }

            Process {
				Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSStorageHealth] [Invoke-PSRunSpace] Processing virtual disk [Name: $($VirtualDisk.FriendlyName)] [UniqueId: $($VirtualDisk.UniqueId)]..."
				Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSStorageHealth] [Invoke-PSRunSpace] [Get-ClusterSharedVolume] Getting information about Cluster Shared Volumes (CSV) in a failover cluster [$ClusterName]..."
				$ClusterSharedVolumes_ = $VirtualDisk | Get-ClusterSharedVolume -Cluster $ClusterName
				Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSStorageHealth] [Invoke-PSRunSpace] Identified $($ClusterSharedVolumes_.Count) cluster shared volumes."
				Try {
					Write-Debug -Message "[$((Get-Date).ToString())] [Get-CPSStorageHealth] [Invoke-PSRunSpace] Debug Info (Cluster Shared Volumes): $($ClusterSharedVolumes_ | ConvertTo-Json)"
				}
				Catch {
					Write-Debug -Message "[$((Get-Date).ToString())] [Get-CPSStorageHealth] [Invoke-PSRunSpace] Debug Info (Cluster Shared Volumes): $($ClusterSharedVolumes_ | ConvertTo-Json -Compress)"
				}
				If (($Null -ne $ClusterSharedVolumes_) -and ($ClusterSharedVolumes_.Count -ge 1)) {
                    ForEach ($ClusterSharedVolume_ in $ClusterSharedVolumes_) {
                        $ClusterSharedVolume = $VirtualDisk | Select-Object FriendlyName,CSVName,CSVNode,CSVPath,CSVVolume,ShareName,SharePath,VolumeID,PoolName,VDResiliency,VDCopies,VDColumns,VDEAware
                        Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSStorageHealth] [Invoke-PSRunSpace] Processing cluster shared volume [$($ClusterSharedVolume_.Name)]..."
					    $ClusterSharedVolume.CSVName = $ClusterSharedVolume_.Name
					    $ClusterSharedVolume.CSVNode = $ClusterSharedVolume_.OwnerNode.Name
					    $ClusterSharedVolume.CSVPath = $ClusterSharedVolume_.SharedVolumeInfo.FriendlyVolumeName
					    If ($ClusterSharedVolume.CSVPath.Length -ne 0) {
                            $ClusterSharedVolume.CSVVolume = $ClusterSharedVolume.CSVPath.Split(“\”)[2]
                        }
					    $Shares = $SmbShares | Where-Object Path –like $($ClusterSharedVolume.CSVPath + ”\*”)
					    $Share = $Shares | Select-Object -First 1
					    If ($Share) {
						    $ClusterSharedVolume.ShareName = $Share.Name
						    $ClusterSharedVolume.SharePath = $Share.Path
						    $ClusterSharedVolume.VolumeID = $Share.Volume
						    If ($Shares.Count -gt 1) { $ClusterSharedVolume.ShareName += "*" }
					    }
                        Write-Output -InputObject $ClusterSharedVolume
                    }
				}
            }

            End {
                [System.GC]::Collect()
            }
        }

        Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSStorageHealth] [Invoke-PSRunSpace] Getting information about Cluster Shared Volumes (CSV) associated with $($VirtualDisks.Count) virtual disks..."
        # Cluster Shared Volumes (CSV) to Virtual Disks
        # Note: If you are not seeing results from all virtual disks, try to increase TimeOut value (in seconds)
        If ($PSBoundParameters['Verbose'] -and $PSBoundParameters['Debug']) {
            $ClusterSharedVolumesToVirtualDisks = Invoke-PSRunSpace -InputObject $($VirtualDisks | Where-Object {$_.FriendlyName -notlike "*Quorum*"}) -ScriptBlock $ScriptBlockClusterSharedVolumesToVirtualDisks -Arguments $SmbShares,$ClusterName -MaxThreads $MaxThreads -TimeOut 500 -SendInputObjectInstance -Verbose -Debug
        }
        ElseIf ($PSBoundParameters['Verbose']) {
            $ClusterSharedVolumesToVirtualDisks = Invoke-PSRunSpace -InputObject $($VirtualDisks | Where-Object {$_.FriendlyName -notlike "*Quorum*"}) -ScriptBlock $ScriptBlockClusterSharedVolumesToVirtualDisks -Arguments $SmbShares,$ClusterName -MaxThreads $MaxThreads -TimeOut 500 -SendInputObjectInstance -Verbose
        }
        ElseIf ($PSBoundParameters['Debug']) {
            $ClusterSharedVolumesToVirtualDisks = Invoke-PSRunSpace -InputObject $($VirtualDisks | Where-Object {$_.FriendlyName -notlike "*Quorum*"}) -ScriptBlock $ScriptBlockClusterSharedVolumesToVirtualDisks -Arguments $SmbShares,$ClusterName -MaxThreads $MaxThreads -TimeOut 500 -SendInputObjectInstance -Debug
        }
        Else {
            $ClusterSharedVolumesToVirtualDisks = Invoke-PSRunSpace -InputObject $($VirtualDisks | Where-Object {$_.FriendlyName -notlike "*Quorum*"}) -ScriptBlock $ScriptBlockClusterSharedVolumesToVirtualDisks -Arguments $SmbShares,$ClusterName -MaxThreads $MaxThreads -TimeOut 500 -SendInputObjectInstance
        }
        $HashTable.Add("ClusterSharedVolumesToVirtualDisks", $ClusterSharedVolumesToVirtualDisks)
        $BackgroundJobs += Write-ClixmlAsync -InputObject $ClusterSharedVolumesToVirtualDisks -WriteToFolderPath $WriteToFolderPath -WriteToFileName "ClusterSharedVolumesToVirtualDisks"
        Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSStorageHealth] Retrieved Cluster Shared Volumes (CSV) information associated with virtual disks."
        Try {
            Write-Debug -Message "[$((Get-Date).ToString())] [Get-CPSStorageHealth] Debug Info (Virtual Disks Overview): $($VirtualDisksOverview | ConvertTo-Json)"
        }
        Catch {
            Write-Debug -Message "[$((Get-Date).ToString())] [Get-CPSStorageHealth] Debug Info (Virtual Disks Overview): $($VirtualDisksOverview | ConvertTo-Json -Compress)"
        }
        #endregion

        #region Virtual Disks to Storage Pools
        $ActiveStepId++ #31
        Write-Progress -Activity "Getting CPS Storage Health.." -Status "Processing: Step $ActiveStepId of $TotalSteps" -Id $RootActivityId -PercentComplete (($ActiveStepId / $TotalSteps)*100) -CurrentOperation "Mapping Virtual Disks to Storage Pools.."
        $ScriptBlockVirtualDisksToStoragePools = {
            [CmdletBinding()]
            Param (
                [Parameter(Mandatory=$True)]
                $StoragePool,

                [Parameter(Mandatory=$True)]
                $AccessNode,
            
                [Parameter(Mandatory=$True)]
                $ClusterSharedVolumesToVirtualDisks
            )

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
                    Import-Module -Name Storage -Verbose:$False
                    $VerbosePreference = $SaveVerbosePreference
                }
                Catch {
                    Write-Error -Exception $_.Exception -Message $_.Exception.Message -ErrorAction Stop
                }
            }

            Process {
                $DebugPreference = "Continue"
                $ConfirmPreference = "None"
                If ($StoragePool | Where-Object { $_.IsReadOnly -ne $True } ) {
                    Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSStorageHealth] [Invoke-PSRunSpace] [Get-VirtualDisk] Getting virtual disks for storage pool [$($StoragePool.FriendlyName)]..."
                    $VirtualDisks = Get-VirtualDisk -CimSession $AccessNode -StoragePool $StoragePool
                    Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSStorageHealth] [Invoke-PSRunSpace] Identified $($VirtualDisks.Count) virtual disks."
                    ForEach ($VirtualDisk in $VirtualDisks) {
		                $ClusterSharedVolumesToVirtualDisks | ForEach-Object {
                            If ($_.FriendlyName –eq $VirtualDisk.FriendlyName) { 
                                $_.PoolName = $StoragePool.FriendlyName
                                $_.VDResiliency = $VirtualDisk.ResiliencySettingName
                                $_.VDCopies = $VirtualDisk.NumberofDataCopies
                                $_.VDColumns = $VirtualDisk.NumberofColumns
                                $_.VDEAware = $VirtualDisk.IsEnclosureAware
                            }
                        }
                    }
                    Write-Output -InputObject $ClusterSharedVolumesToVirtualDisks
                }
            }

            End {
                [System.GC]::Collect()
            }
        }

        Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSStorageHealth] [Invoke-PSRunSpace] Getting information about virtual disks associated with $($StoragePools.Count) storage pools..."
        # Virtual Disks to Storage Pools
        # Note: If you are not seeing results from all storage pools, try to increase TimeOut value (in seconds)
        If ($PSBoundParameters['Verbose'] -and $PSBoundParameters['Debug']) {
            $VirtualDisksToStoragePools = Invoke-PSRunSpace -InputObject $StoragePools -ScriptBlock $ScriptBlockVirtualDisksToStoragePools -Arguments $AccessNode,$ClusterSharedVolumesToVirtualDisks -MaxThreads $MaxThreads -TimeOut 500 -SendInputObjectInstance -Verbose -Debug
        }
        ElseIf ($PSBoundParameters['Verbose']) {
            $VirtualDisksToStoragePools = Invoke-PSRunSpace -InputObject $StoragePools -ScriptBlock $ScriptBlockVirtualDisksToStoragePools -Arguments $AccessNode,$ClusterSharedVolumesToVirtualDisks -MaxThreads $MaxThreads -TimeOut 500 -SendInputObjectInstance -Verbose
        }
        ElseIf ($PSBoundParameters['Debug']) {
            $VirtualDisksToStoragePools = Invoke-PSRunSpace -InputObject $StoragePools -ScriptBlock $ScriptBlockVirtualDisksToStoragePools -Arguments $AccessNode,$ClusterSharedVolumesToVirtualDisks -MaxThreads $MaxThreads -TimeOut 500 -SendInputObjectInstance -Debug
        }
        Else {
            $VirtualDisksToStoragePools = Invoke-PSRunSpace -InputObject $StoragePools -ScriptBlock $ScriptBlockVirtualDisksToStoragePools -Arguments $AccessNode,$ClusterSharedVolumesToVirtualDisks -MaxThreads $MaxThreads -TimeOut 500 -SendInputObjectInstance
        }
        $HashTable.Add("VirtualDisksToStoragePools", $VirtualDisksToStoragePools)
        $BackgroundJobs += Write-ClixmlAsync -InputObject $VirtualDisksToStoragePools -WriteToFolderPath $WriteToFolderPath -WriteToFileName "VirtualDisksToStoragePools"
        Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSStorageHealth] Retrieved virtual disks information associated with storage pools."
        Try {
            Write-Debug -Message "[$((Get-Date).ToString())] [Get-CPSStorageHealth] Debug Info (Virtual Disks to Storage Pools): $($VirtualDisksToStoragePools | ConvertTo-Json)"
        }
        Catch {
            Write-Debug -Message "[$((Get-Date).ToString())] [Get-CPSStorageHealth] Debug Info (Virtual Disks to Storage Pools): $($VirtualDisksToStoragePools | ConvertTo-Json -Compress)"
        }
        #endregion

        #region Verify MPIO
        If ($PSBoundParameters['VerifyMPIO']) {
            $ActiveStepId++ #32
            Write-Progress -Activity "Getting CPS Storage Health.." -Status "Processing: Step $ActiveStepId of $TotalSteps" -Id $RootActivityId -PercentComplete (($ActiveStepId / $TotalSteps)*100) -CurrentOperation "Verifying MPIO Status.."
            If ($PSBoundParameters['Verbose'] -and $PSBoundParameters['Debug']) {
                $MPIOStatus = Test-CPSMPIOAsync -RackIdentifier $RackIdentifier -Verbose -Debug
            }
            ElseIf ($PSBoundParameters['Verbose']) {
                $MPIOStatus = Test-CPSMPIOAsync -RackIdentifier $RackIdentifier -Verbose
            }
            ElseIf ($PSBoundParameters['Debug']) {
                $MPIOStatus = Test-CPSMPIOAsync -RackIdentifier $RackIdentifier -Debug
            }
            Else {
                $MPIOStatus = Test-CPSMPIOAsync -RackIdentifier $RackIdentifier
            }
            $HashTable.Add("MPIOStatus", $MPIOStatus)
            $BackgroundJobs += Write-ClixmlAsync -InputObject $MPIOStatus -WriteToFolderPath $WriteToFolderPath -WriteToFileName "MPIOStatus"
            Try {
                Write-Debug -Message "[$((Get-Date).ToString())] [Get-CPSStorageHealth] Debug Info (MPIO Status): $($MPIOStatus | ConvertTo-Json)"
            }
            Catch {
                Write-Debug -Message "[$((Get-Date).ToString())] [Get-CPSStorageHealth] Debug Info (MPIO Status): $($MPIOStatus | ConvertTo-Json -Compress)"
            }
        }
        #endregion

        #region Retrieve Storage Enclosure Health
        If ($PSBoundParameters['IncludeStorageEnclosureHealth']) {
            $ActiveStepId++ #33
            Write-Progress -Activity "Getting CPS Storage Health.." -Status "Processing: Step $ActiveStepId of $TotalSteps" -Id $RootActivityId -PercentComplete (($ActiveStepId / $TotalSteps)*100) -CurrentOperation "Retrieve Storage Enclosure Health.."
            $StorageNode = ($ClusterNodes | Select-Object Name | ForEach-Object {$_.Name}) | Select-Object -First 1
            $StorageEnclosureHealthLocation = "$($WriteToFolderPath.TrimEnd('\'))"
            Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSStorageHealth] [Get-CPSStorageEnclosureHealth] Getting storage enclosure logs from $($StorageNodes.Count) storage nodes..."
            If ($PSBoundParameters['Verbose'] -and $PSBoundParameters['Debug']) {
                Get-CPSStorageEnclosureHealth -StorageNodes $StorageNode -SASIndex 0 -SECliPath $SECliPath -WriteToFolderPath $StorageEnclosureHealthLocation -ParentActivityId $RootActivityId -Force -Verbose -Debug | Out-Null
                Get-CPSStorageEnclosureHealth -StorageNodes $StorageNode -SASIndex 1 -SECliPath $SECliPath -WriteToFolderPath $StorageEnclosureHealthLocation -ParentActivityId $RootActivityId -Force -Verbose -Debug | Out-Null
            }
            ElseIf ($PSBoundParameters['Verbose']) {
                Get-CPSStorageEnclosureHealth -StorageNodes $StorageNode -SASIndex 0 -SECliPath $SECliPath -WriteToFolderPath $StorageEnclosureHealthLocation -ParentActivityId $RootActivityId -Force -Verbose | Out-Null
                Get-CPSStorageEnclosureHealth -StorageNodes $StorageNode -SASIndex 1 -SECliPath $SECliPath -WriteToFolderPath $StorageEnclosureHealthLocation -ParentActivityId $RootActivityId -Force -Verbose | Out-Null
            }
            ElseIf ($PSBoundParameters['Debug']) {
                Get-CPSStorageEnclosureHealth -StorageNodes $StorageNode -SASIndex 0 -SECliPath $SECliPath -WriteToFolderPath $StorageEnclosureHealthLocation -ParentActivityId $RootActivityId -Force -Debug | Out-Null
                Get-CPSStorageEnclosureHealth -StorageNodes $StorageNode -SASIndex 1 -SECliPath $SECliPath -WriteToFolderPath $StorageEnclosureHealthLocation -ParentActivityId $RootActivityId -Force -Debug | Out-Null
            }
            Else {
                Get-CPSStorageEnclosureHealth -StorageNodes $StorageNode -SASIndex 0 -SECliPath $SECliPath -WriteToFolderPath $StorageEnclosureHealthLocation -ParentActivityId $RootActivityId -Force | Out-Null
                Get-CPSStorageEnclosureHealth -StorageNodes $StorageNode -SASIndex 1 -SECliPath $SECliPath -WriteToFolderPath $StorageEnclosureHealthLocation -ParentActivityId $RootActivityId -Force | Out-Null
            }
            $HashTable.Add("IncludeStorageEnclosureHealth", $True)
        }
        #endregion

        #region Get Cluster Process Memory Dumps
        If ($PSBoundParameters['IncludeClusterProcessMemoryDumps']) {
            $ActiveStepId++ #34
            Write-Progress -Activity "Getting CPS Storage Health.." -Status "Processing: Step $ActiveStepId of $TotalSteps" -Id $RootActivityId -PercentComplete (($ActiveStepId / $TotalSteps)*100) -CurrentOperation "Getting Cluster Process Memory Dumps.."
            $StorageNodes = $ClusterNodes | Select-Object Name | ForEach-Object {$_.Name}
            $ProcessMemoryDumpsDestination = "$($WriteToFolderPath.TrimEnd('\'))\ClusterProcessMemoryDumps\"
            Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSStorageHealth] [Get-CPSClusterProcessMemoryDump] Getting cluster process memory dumps from $($StorageNodes.Count) storage nodes..."
            # Get-CPSClusterProcessMemoryDump throws an exception if the given path to 'ProcDump.exe' is invalid
            Try {
                If ($PSBoundParameters['Verbose'] -and $PSBoundParameters['Debug']) {
                    $StorageNodes | Get-CPSClusterProcessMemoryDump -Destination $ProcessMemoryDumpsDestination -ProcDumpPath $ProcDumpPath -Compress -ParentActivityId $RootActivityId -Verbose -Debug
                }
                ElseIf ($PSBoundParameters['Verbose']) {
                    $StorageNodes | Get-CPSClusterProcessMemoryDump -Destination $ProcessMemoryDumpsDestination -ProcDumpPath $ProcDumpPath -Compress -ParentActivityId $RootActivityId -Verbose
                }
                ElseIf ($PSBoundParameters['Debug']) {
                    $StorageNodes | Get-CPSClusterProcessMemoryDump -Destination $ProcessMemoryDumpsDestination -ProcDumpPath $ProcDumpPath -Compress -ParentActivityId $RootActivityId -Debug
                }
                Else {
                    $StorageNodes | Get-CPSClusterProcessMemoryDump -Destination $ProcessMemoryDumpsDestination -ProcDumpPath $ProcDumpPath -Compress -ParentActivityId $RootActivityId
                }
                $HashTable.Add("IncludeClusterProcessMemoryDumps", $True)
            }
            Catch {
                Write-Error -Exception $_.Exception -Message $_.Exception.Message
                $HashTable.Add("IncludeClusterProcessMemoryDumps", $False)
            }
        }
        #endregion

        Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSStorageHealth] Gathering of storage health is complete."

        $ActiveStepId++ #35
        Write-Progress -Activity "Getting CPS Storage Health.." -Status "Processing: Step $ActiveStepId of $TotalSteps" -Id $RootActivityId -PercentComplete (($ActiveStepId / $TotalSteps)*100) -CurrentOperation "Waiting for $(($BackgroundJobs | Where-Object {$_.State -eq 'Running'}).Count) Background Jobs.."
        While ((($BackgroundJobs | Where-Object {$_.State -eq 'Running'}).Count -ge 1) -and ($(Get-ElapsedTime -StartTime $StartTime).TotalMinutes -lt $TimeOut)) {
            $BackgroundJobs | Where-Object {($_.HasMoreData -eq $True) -and ($_.State -eq 'Running')} | ForEach-Object {$_ | Receive-Job}
            Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSStorageHealth] Waiting for $(($BackgroundJobs | Where-Object {$_.State -eq 'Running'}).Count) background jobs to finish..."
            Start-Sleep -Milliseconds 800
        }

        #region Compress
        If ($PSBoundParameters['Compress']) {
            [System.GC]::Collect()
            $ActiveStepId++ #36
            Write-Progress -Activity "Getting CPS Storage Health.." -Status "Processing: Step $ActiveStepId of $TotalSteps" -Id $RootActivityId -PercentComplete (($ActiveStepId / $TotalSteps)*100) -CurrentOperation "Creating a New Archive File.."
            If ($PSBoundParameters['WriteToFolderPath']) {
                $ArchivePath = Join-Path -Path "$((Get-Item -Path $WriteToFolderPath).Parent.FullName)" -ChildPath "$($ClusterName)_StorageHealth_$(Get-Date -Format 'M-dd-yyyy')_$([GUID]::NewGuid().Guid).ZIP"
            }
            Else {
                $ArchivePath = Join-Path -Path "$((Get-Item -Path $WriteToFolderPath).Parent.FullName)" -ChildPath "$($ClusterName)_StorageHealth_$((Get-Item -Path $WriteToFolderPath).Parent.BaseName)_$((Get-Item -Path $WriteToFolderPath).BaseName).ZIP"
            }
            Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSStorageHealth] [New-Archive] Creating a new archive file..."
            If ($PSBoundParameters['Verbose'] -and $PSBoundParameters['Debug']) {
                New-Archive -Path $WriteToFolderPath -ArchivePath $ArchivePath -CompressionLevel Optimal -Verbose -Debug
            }
            ElseIf ($PSBoundParameters['Verbose']) {
                New-Archive -Path $WriteToFolderPath -ArchivePath $ArchivePath -CompressionLevel Optimal -Verbose
            }
            ElseIf ($PSBoundParameters['Debug']) {
                New-Archive -Path $WriteToFolderPath -ArchivePath $ArchivePath -CompressionLevel Optimal -Debug
            }
            Else {
                New-Archive -Path $WriteToFolderPath -ArchivePath $ArchivePath -CompressionLevel Optimal
            }
            If (Test-Path -Path $ArchivePath) {
                Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSStorageHealth] [Remove-Item] Removing a temporary folder [$WriteToFolderPath]..."
                Remove-Item -Path $WriteToFolderPath -Recurse -Force
            }
            Else {
                Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSStorageHealth] Storage health information is available here: [$WriteToFolderPath]"
            }
            $HashTable.Add("Compress", $True)
        }
        #endregion

        $CPSStorageHealth = New-Object -TypeName PSCustomObject -Property $HashTable
        Write-Output -InputObject $CPSStorageHealth
    }

    End {
        If ($Host.Version.Major -ge 5) {
            Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSStorageHealth] [Stop-Transcript] Stopping transcript..."
            Stop-Transcript | Out-Null
            Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSStorageHealth] Transcript is available at [$TranscriptLogFilePath]"
        }
        Else {
            If ($Host.Name -eq "ConsoleHost") {
                Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSStorageHealth] [Stop-Transcript] Stopping transcript..."
                Stop-Transcript | Out-Null
                Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSStorageHealth] Transcript is available at [$TranscriptLogFilePath]"
            }
        }
        [System.GC]::Collect()
    }
}

Function Get-CPSStorageHealthOverview {
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
    }

    Process {
        Try {
            Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSStorageHealthOverview] [Get-SCStorageArray] Getting storage health..."
            $SCStorageArray = Get-SCStorageArray
            $StorageHealthOverview = New-Object -TypeName PSObject -Property @{
                StorageProviders = $SCStorageArray.StorageProvider | Select-Object Name,Enabled,Status
                StorageFileServers = $SCStorageArray.StorageProvider.StorageFileServers | Select-Object Name,Enabled,State
                StorageNodes = $SCStorageArray.StorageNodes | Select-Object Name,Enabled,OperationalStatus,State
                StoragePools = $SCStorageArray.StoragePools | Select-Object Name,Enabled,OperationalStatus,HealthStatus,Classification
                StorageDisks = $SCStorageArray.StorageDisks | Select-Object Name,DiskStatus,StorageLogicalUnit,Classification
                StoragePhysicalDisks = $SCStorageArray.StoragePhysicalDisks | Select-Object Name,Enabled,OperationalStatus,HealthStatus,StoragePool,MediaType
            }

            Write-Debug -Message "[$((Get-Date).ToString())] [Get-CPSStorageHealthOverview] Debug Info (Storage Health Overview): $($StorageHealthOverview | ConvertTo-Json)"
            Write-Output -InputObject $StorageHealthOverview
        }
        Catch {
            Write-Error -Exception $_.Exception -Message $_.Exception.Message
        }
    }

    End {
        [System.GC]::Collect()
    }
}

Function Get-CPSStorageNode {
    [CmdletBinding()]
    [OutputType([System.Object])]
    Param (
        [Parameter(
            Position = 0,
            Mandatory = $False
        )]
        [ValidateNotNullOrEmpty()]
        [ValidateRange(1,4)]
        [Alias("Rack")]
        [Int] $RackIdentifier = 1
    )
	
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
            $VerbosePreference = $SaveVerbosePreference
        }
        Catch {
            Write-Error -Exception $_.Exception -Message $_.Exception.Message -ErrorAction Stop
        }
	}

	Process {
		Try {
            #region Storage Nodes
            [String[]] $StorageNodes = @()
            If ($PSBoundParameters['RackIdentifier']) {
                Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSStorageNode] [Get-SCStorageArray] Getting storage nodes for [Rack $RackIdentifier]..."
                $(Get-SCStorageArray | Where-Object {($_.StorageNodes.Enabled -eq $True) -and ($_.StorageNodes.State -eq "OK")} | ForEach-Object {$_.StorageNodes.Name}) | ForEach-Object {
                    Switch -Regex ($_) {
                        "(.[R-Rr-r]$($RackIdentifier)[S-Ss-s][S-Ss-s][0-9][0-9].)" {
                            [String[]] $StorageNodes += $_
                        }
                        default {
                        }
                    }
                }
            }
            Else {
                Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSStorageNode] [Get-SCStorageArray] Getting storage nodes..."
                [String[]] $StorageNodes = $(Get-SCStorageArray | ForEach-Object {$_.StorageNodes.Name})
            }
            Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSStorageNode] Identified $($StorageNodes.Count) storage nodes."
            Write-Debug -Message "[$((Get-Date).ToString())] [Get-CPSStorageNode] Debug Info (Storage Nodes): $($StorageNodes | ConvertTo-Json -Compress)"
            Write-Output -InputObject $StorageNodes
            #endregion
		}
		Catch {
			Write-Error -Exception $_.Exception -Message $_.Exception.Message -ErrorAction Stop
		}
	}

	End {
		[System.GC]::Collect()
	}
}

Function Get-CPSStorageAccessNode {
    [CmdletBinding()]
    [OutputType([System.Object])]
    Param (
        [Parameter(
            Position = 0,
            Mandatory = $False
        )]
        [ValidateNotNullOrEmpty()]
        [ValidateRange(1,4)]
        [Alias("Rack")]
        [Int] $RackIdentifier = 1
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
            [String[]] $StorageNodes = @(Get-CPSStorageNode -RackIdentifier $RackIdentifier)
            If ($StorageNodes.Count -ge 1) {
                Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSStorageAccessNode] Selecting a random storage node..."
                $AccessNode = $StorageNodes | Get-Random
                Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSStorageAccessNode] [Access Node: $AccessNode]"
                Write-Output -InputObject $AccessNode
            }
		}
		Catch {
			Write-Error -Exception $_.Exception -Message $_.Exception.Message -ErrorAction Stop
		}
	}

	End {
		[System.GC]::Collect()
	}
}

Function Get-CPSStorageFileShare {
    [CmdletBinding()]
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

        Try {
            $SaveVerbosePreference = $VerbosePreference
            $VerbosePreference = "SilentlyContinue"
            Import-Module -Name VirtualMachineManager -Verbose:$False
            $VerbosePreference = $SaveVerbosePreference
        }
        Catch {
            Write-Error -Exception $_.Exception -Message $_.Exception.Message -ErrorAction Stop
        }

		$ExcludeProperties = @("PSComputerName","RunspaceId","PSShowComputerName","CimClass","CimInstanceProperties","CimSystemProperties")
	}

	Process {
		Try {
            $VMMOwnerNode = Get-CPSVMMOwnerNode
		}
		Catch {
			Write-Error -Exception $_.Exception -Message $_.Exception.Message -ErrorAction Stop
		}
		
		Try {
			Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSStorageFileShare] [Get-SCStorageFileShare] Getting storage file shares..."
			$StorageFileShares = Get-SCStorageFileShare -VMMServer $VMMOwnerNode | Select-Object * -ExcludeProperty $ExcludeProperties
			Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSStorageFileShare] Identified $($StorageFileShares.Count) storage file shares."
			Write-Debug -Message "[$((Get-Date).ToString())] [Get-CPSStorageFileShare] Debug Info (Storage File Shares): $($StorageFileShares | ConvertTo-Json -Compress)"
		}
		Catch {
			Write-Error -Exception $_.Exception -Message $_.Exception.Message -ErrorAction stop
		}
        Write-Output -InputObject $StorageFileShares
	}

	End {
		[System.GC]::Collect()
	}
}

Function Get-CPSDiskSpace {
    [CmdletBinding()]
    Param (       
        [Parameter(
            Position = 0,
            Mandatory = $True
        )]
        [ValidateNotNullOrEmpty()]
        [ValidateSet("CC","EC","MC","SC")]
        [String] $ClusterType,

        [Parameter(
            Position = 1,
            Mandatory = $False,
            HelpMessage = "Specify maximum no. of threads. Default is 4 threads. Maximum is 8 threads:"
        )]
        [ValidateNotNullOrEmpty()]
        [ValidateRange(1,8)]
        [Int16] $MaxThreads,

        [Parameter(
            Position = 2,
            Mandatory = $False
        )]
        [ValidateNotNullOrEmpty()]
        [Switch] $OutputTypeAsJSON
    )

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
            $VerbosePreference = $SaveVerbosePreference
        }
        Catch {
            Write-Error -Exception $_.Exception -Message $_.Exception.Message -ErrorAction Stop
        }

        $RootActivityId = $(Get-Date -Format "yyyymmss")
        $ActiveStepId = 0

        $Servers = @()
        $ExcludeProperties = @("PSComputerName","RunspaceId","PSShowComputerName","CimClass","CimInstanceProperties","CimSystemProperties")

        #region Get-CPSVMMOwnerNode
        $VMMServer = Get-CPSVMMOwnerNode
        #endregion
        
        #region Get-SCVMHost
        Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSDiskSpace] [Get-SCVMHost] Getting virtual machine hosts for cluster type [$ClusterType]..."
        $VMHosts = Get-SCVMHost -VMMServer $VMMServer | Select-Object FullyQualifiedDomainName,HostCluster | Where-Object {$_.HostCluster -like "*$ClusterType*"}
        Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSDiskSpace] Identified $($VMHosts.Count) virtual machine hosts."
        #endregion

        #region Get-SCVirtualMachine
        ForEach ($VMHost in $VMHosts) {
	        $Servers += $($VMHost.FullyQualifiedDomainName)
            Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSDiskSpace] [Get-SCVirtualMachine] Getting virtual machines from host [$($VMHost.FullyQualifiedDomainName)]..."
            $VirtualMachines = Get-SCVirtualMachine -VMHost $($VMHost.FullyQualifiedDomainName) | Select-Object Name | ForEach-Object {$_.Name}
            Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSDiskSpace] Identified $($VirtualMachines.Count) virtual machines."
	        $Servers += $VirtualMachines
        }
        #endregion

        $TotalSteps = $Servers.Count

        #region Script Block
        $ScriptBlock = {
            [CmdletBinding()]
            Param (       
                [Parameter(
                    Position = 0,
                    Mandatory = $True
                )]
                [ValidateNotNullOrEmpty()]
                [String] $Server,

                [Parameter(
                    Position = 1,
                    Mandatory = $False
                )]
                [ValidateNotNullOrEmpty()]
                [Switch] $OutputTypeAsJSON
            )
		    
            Try {
			    Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSDiskSpace] [Get-CimInstance -ClassName Win32_LogicalDisk] Getting disk space information for server [$Server]..."
			    $SystemDrive = Invoke-Command -ComputerName $Server -ScriptBlock {Get-CimInstance -ClassName Win32_LogicalDisk | Where-Object {$_.DeviceID -eq $env:SystemDrive}} -ErrorAction Stop
			    Write-Debug -Message "[$((Get-Date).ToString())] [Get-CPSDiskSpace] Debug Info (Disk Space): $($SystemDrive | ConvertTo-Json -Compress)"
                Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSDiskSpace] Getting P&U profile and log size..."
                $ProfilePath = Get-ChildItem -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList" | ForEach-Object {
                    Get-ItemProperty -Path $_.PSPath | Where-Object {$_.ProfileImagePath -match "CPS-Update-Admin"}
                } | ForEach-Object {$_.ProfileImagePath}
                [System.Double] $PUProfileSize = [Math]::Round(((Get-ChildItem -Path $ProfilePath -Recurse -File -Force -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum).Sum / 1GB),2)
                [System.Double] $PULogSize = [Math]::Round(((Get-ChildItem -Path "C:\CPSPULogs" -Recurse -File -Force -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum).Sum / 1GB),2)
                $SystemDrive = $SystemDrive | Add-Member -MemberType NoteProperty -Name PUProfileSizeGB -Value $PUProfileSize -PassThru
                $SystemDrive = $SystemDrive | Add-Member -MemberType NoteProperty -Name PULogSizeGB -Value $PULogSize -PassThru
                If ($Null -ne $SystemDrive) {
                    If ($PSBoundParameters['OutputTypeAsJSON']) {
                        Write-Output -InputObject $($($SystemDrive | Select-Object *,@{Name="SizeGB";Expression={[Math]::Truncate($_.Size / 1GB)}},@{Name="FreeSpaceGB";Expression={[Math]::Truncate($_.FreeSpace / 1GB)}},@{Name="FreeSpacePercent";Expression={[Math]::Round((($_.FreeSpace/$_.Size) * 100))}} -ExcludeProperty $ExcludeProperties) | ConvertTo-Json -Compress)
                    }
                    Else {
			            Write-Output -InputObject $SystemDrive | Select-Object *,@{Name="SizeGB";Expression={[Math]::Truncate($_.Size / 1GB)}},@{Name="FreeSpaceGB";Expression={[Math]::Truncate($_.FreeSpace / 1GB)}},@{Name="FreeSpacePercent";Expression={[Math]::Round((($_.FreeSpace/$_.Size) * 100))}} -ExcludeProperty $ExcludeProperties
                    }
                }
		    }
		    Catch {
			    Write-Error -Exception $_.Exception -Message $_.Exception.Message
		    }
        }
        #endregion
    }

    Process {
        #region Get-CimInstance -ClassName Win32_LogicalDisk
        If ($PSBoundParameters['MaxThreads']) {
            If ($PSBoundParameters['OutputTypeAsJSON']) {
                If ($PSBoundParameters['Verbose'] -and $PSBoundParameters['Debug']) {
                    Invoke-PSRunSpace -InputObject $Servers -ScriptBlock $ScriptBlock -Arguments $OutputTypeAsJSON -MaxThreads $MaxThreads -SendInputObjectInstance -Verbose -Debug
                }
                ElseIf ($PSBoundParameters['Verbose']) {
                    Invoke-PSRunSpace -InputObject $Servers -ScriptBlock $ScriptBlock -Arguments $OutputTypeAsJSON -MaxThreads $MaxThreads -SendInputObjectInstance -Verbose
                }
                ElseIf ($PSBoundParameters['Debug']) {
                    Invoke-PSRunSpace -InputObject $Servers -ScriptBlock $ScriptBlock -Arguments $OutputTypeAsJSON -MaxThreads $MaxThreads -SendInputObjectInstance -Debug
                }
                Else {
                    Invoke-PSRunSpace -InputObject $Servers -ScriptBlock $ScriptBlock -Arguments $OutputTypeAsJSON -MaxThreads $MaxThreads -SendInputObjectInstance
                }
            }
            Else {
                If ($PSBoundParameters['Verbose'] -and $PSBoundParameters['Debug']) {
                    Invoke-PSRunSpace -InputObject $Servers -ScriptBlock $ScriptBlock -MaxThreads $MaxThreads -SendInputObjectInstance -Verbose -Debug
                }
                ElseIf ($PSBoundParameters['Verbose']) {
                    Invoke-PSRunSpace -InputObject $Servers -ScriptBlock $ScriptBlock -MaxThreads $MaxThreads -SendInputObjectInstance -Verbose
                }
                ElseIf ($PSBoundParameters['Debug']) {
                    Invoke-PSRunSpace -InputObject $Servers -ScriptBlock $ScriptBlock -MaxThreads $MaxThreads -SendInputObjectInstance -Debug
                }
                Else {
                    Invoke-PSRunSpace -InputObject $Servers -ScriptBlock $ScriptBlock -MaxThreads $MaxThreads -SendInputObjectInstance
                }
            }
        }
        Else {
	        $I = 0
            [Array]::Sort($Servers)
	        ForEach ($Server in $Servers) {
		        Try {
			        $I++
                    $ActiveStepId++
                    Write-Progress -Activity "Getting CPS Disk Space.." -Status "Processing Server: $($Server) ($ActiveStepId of $TotalSteps)" -Id $RootActivityId -PercentComplete (($ActiveStepId / $TotalSteps)*100) -CurrentOperation "Getting Disk Space Information.."
			        Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSDiskSpace] [Get-CimInstance -ClassName Win32_LogicalDisk] Getting disk space information for server [$Server] ($I of $($Servers.Count))..."
			        $SystemDrive = Invoke-Command -ComputerName $Server -ScriptBlock {Get-CimInstance -ClassName Win32_LogicalDisk | Where-Object {$_.DeviceID -eq $env:SystemDrive}} -ErrorAction Stop
			        Write-Debug -Message "[$((Get-Date).ToString())] [Get-CPSDiskSpace] Debug Info (Disk Space): $($SystemDrive | ConvertTo-Json -Compress)"
                    If ($Null -ne $SystemDrive) {
                        If ($PSBoundParameters['OutputTypeAsJSON']) {
                            Write-Output -InputObject $($($SystemDrive | Select-Object *,@{Name="SizeGB";Expression={[Math]::Truncate($_.Size / 1GB)}},@{Name="FreeSpaceGB";Expression={[Math]::Truncate($_.FreeSpace / 1GB)}},@{Name="FreeSpacePercent";Expression={[Math]::Round((($_.FreeSpace/$_.Size) * 100))}} -ExcludeProperty $ExcludeProperties) | ConvertTo-Json -Compress)
                        }
                        Else {
			                Write-Output -InputObject $SystemDrive | Select-Object *,@{Name="SizeGB";Expression={[Math]::Truncate($_.Size / 1GB)}},@{Name="FreeSpaceGB";Expression={[Math]::Truncate($_.FreeSpace / 1GB)}},@{Name="FreeSpacePercent";Expression={[Math]::Round((($_.FreeSpace/$_.Size) * 100))}} -ExcludeProperty $ExcludeProperties
                        }
                    }
		        }
		        Catch {
			        Write-Error -Exception $_.Exception -Message $_.Exception.Message
		        }
	        }
            Write-Progress -Activity "Getting CPS Disk Space.." -Status "Processing Complete" -Id $RootActivityId -PercentComplete 100 -CurrentOperation "Getting Disk Space Information.." -Completed
        }
        #endregion
    }

    End {
        [System.GC]::Collect()
    }
}

Function Get-CPSPhysicalDisk {
    [CmdletBinding()]
    Param (
        [Parameter(
            Position = 0,
            Mandatory = $False,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [ValidateNotNullOrEmpty()]
        [ValidateRange(1,4)]
        [Alias("Rack")]
        [Int] $RackIdentifier = 1,

        [Parameter(
            Position = 1,
            Mandatory = $False
        )]
        [ValidateNotNullOrEmpty()]
        [Switch] $OutputTypeAsJSON
    )
	
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
            Import-Module -Name Storage -Verbose:$False
            $VerbosePreference = $SaveVerbosePreference
        }
        Catch {
            Write-Error -Exception $_.Exception -Message $_.Exception.Message -ErrorAction Stop
        }

		$ExcludeProperties = @("PSComputerName","RunspaceId","PSShowComputerName","CimClass","CimInstanceProperties","CimSystemProperties")
	}

	Process {
        #region Access Node
		Try {
            $AccessNode = Get-CPSStorageAccessNode -RackIdentifier $RackIdentifier
		}
		Catch {
			Write-Error -Exception $_.Exception -Message $_.Exception.Message -ErrorAction Stop
		}
        #endregion
		
		Try {
            #region Physical Disks
            Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSPhysicalDisk] [Get-PhysicalDisk] Getting physical disks..."
            $PhysicalDisks = Get-PhysicalDisk -CimSession $AccessNode
            Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSPhysicalDisk] Identified $($PhysicalDisks.Count) physical disks."
            $I = 0
            ForEach ($PhysicalDisk in $PhysicalDisks) {
                $I++
                Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSPhysicalDisk] Processing physical disk $($PhysicalDisk.FriendlyName) ($I of $($PhysicalDisks.Count))..."
                $PhysicalDisk = $PhysicalDisk | Add-Member -MemberType NoteProperty -Name DiskNumber -Value $($PhysicalDisk.FriendlyName -replace('PhysicalDisk','')) -PassThru
                If ($PSBoundParameters['OutputTypeAsJSON']) {
                    Write-Output -InputObject ($PhysicalDisk | Select-Object *,@{Name="SizeGB";Expression={[Math]::Truncate($_.Size / 1GB)}},@{Name="AllocatedSizeGB";Expression={[Math]::Truncate($_.AllocatedSize / 1GB)}} -ExcludeProperty $ExcludeProperties | ConvertTo-Json -Compress)
                }
                Else {
                    Write-Output -InputObject $($PhysicalDisk | Select-Object *,@{Name="SizeGB";Expression={[Math]::Truncate($_.Size / 1GB)}},@{Name="AllocatedSizeGB";Expression={[Math]::Truncate($_.AllocatedSize / 1GB)}} -ExcludeProperty $ExcludeProperties)
                }
                Write-Debug -Message "[$((Get-Date).ToString())] [Get-CPSPhysicalDisk] Debug Info (Physical Disk): $($PhysicalDisk | ConvertTo-Json -Compress)"
            }
            #endregion
		}
		Catch {
			Write-Error -Exception $_.Exception -Message $_.Exception.Message -ErrorAction stop
		}
	}

	End {
		[System.GC]::Collect()
	}
}

Function Get-CPSVirtualDisk {
    [CmdletBinding()]
    Param (
        [Parameter(
            Position = 0,
            Mandatory = $False
        )]
        [ValidateNotNullOrEmpty()]
        [ValidateRange(1,4)]
        [Alias("Rack")]
        [Int] $RackIdentifier = 1,

        [Parameter(
            Position = 1,
            Mandatory = $False
        )]
        [ValidateNotNullOrEmpty()]
        [Switch] $OutputTypeAsJSON
    )
	
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
            Import-Module -Name Storage -Verbose:$False
            $VerbosePreference = $SaveVerbosePreference
        }
        Catch {
            Write-Error -Exception $_.Exception -Message $_.Exception.Message -ErrorAction Stop
        }

		$ExcludeProperties = @("PSComputerName","RunspaceId","PSShowComputerName","CimClass","CimInstanceProperties","CimSystemProperties")
	}

	Process {
        #region Access Node
		Try {
            $AccessNode = Get-CPSStorageAccessNode -RackIdentifier $RackIdentifier
		}
		Catch {
			Write-Error -Exception $_.Exception -Message $_.Exception.Message -ErrorAction Stop
		}
        #endregion
		
		Try {
            #region Virtual Disks
            Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSVirtualDisk] [Get-VirtualDisk] Getting virtual disks..."
            $VirtualDisks = Get-VirtualDisk -CimSession $AccessNode | Select-Object *,@{Name="SizeGB";Expression={[Math]::Truncate($_.Size / 1GB)}},@{Name="AllocatedSizeGB";Expression={[Math]::Truncate($_.AllocatedSize / 1GB)}} -ExcludeProperty $ExcludeProperties
            Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSVirtualDisk] Identified $($VirtualDisks.Count) virtual disks."
            Write-Debug -Message "[$((Get-Date).ToString())] [Get-CPSVirtualDisk] Debug Info (Virtual Disks): $($VirtualDisks | ConvertTo-Json -Compress)"
            #endregion
		}
		Catch {
			Write-Error -Exception $_.Exception -Message $_.Exception.Message -ErrorAction stop
		}

        If ($PSBoundParameters['OutputTypeAsJSON']) {
            Write-Output -InputObject ($VirtualDisks | ConvertTo-Json -Compress)
        }
        Else {
            Write-Output -InputObject $VirtualDisks
        }
	}

	End {
		[System.GC]::Collect()
	}
}

Function Get-CPSStoragePool {
    [CmdletBinding()]
    Param (
        [Parameter(
            Position = 0,
            Mandatory = $False,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [ValidateNotNullOrEmpty()]
        [ValidateRange(1,4)]
        [Alias("Rack")]
        [Int] $RackIdentifier = 1,

        [Parameter(
            Position = 1,
            Mandatory = $False
        )]
        [ValidateNotNullOrEmpty()]
        [Switch] $OutputTypeAsJSON
    )
	
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
            Import-Module -Name Storage -Verbose:$False
            $VerbosePreference = $SaveVerbosePreference
        }
        Catch {
            Write-Error -Exception $_.Exception -Message $_.Exception.Message -ErrorAction Stop
        }

		$ExcludeProperties = @("PSComputerName","RunspaceId","PSShowComputerName","CimClass","CimInstanceProperties","CimSystemProperties")
	}

	Process {
        #region Access Node
		Try {
            $AccessNode = Get-CPSStorageAccessNode -RackIdentifier $RackIdentifier
		}
		Catch {
			Write-Error -Exception $_.Exception -Message $_.Exception.Message -ErrorAction Stop
		}
        #endregion
		
		Try {
            #region Storage Pools
            Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSStoragePool] [Get-StoragePool -IsPrimordial `$False] Getting storage pools..."
            $StoragePools = Get-StoragePool -CimSession $AccessNode -IsPrimordial $False | Sort-Object -Property FriendlyName
            Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSStoragePool] Identified $($StoragePools.Count) storage pools."
            $I = 0
            ForEach ($StoragePool in $StoragePools) {
                $I++
                Write-Verbose -Message "[$((Get-Date).ToString())] Processing storage pool $($StoragePool.FriendlyName) ($I of $($StoragePools.Count))..."
                $HDDs = (Get-PhysicalDisk -CimSession $AccessNode -StoragePool $StoragePool | Where-Object {$_.MediaType -eq "HDD"}).Count
                $SSDs = (Get-PhysicalDisk -CimSession $AccessNode -StoragePool $StoragePool | Where-Object {$_.MediaType -eq "SSD"}).Count
                $StoragePool = $StoragePool | Add-Member -MemberType NoteProperty -Name "TotalHDD" -Value $HDDs -PassThru
                $StoragePool = $StoragePool | Add-Member -MemberType NoteProperty -Name "TotalSSD" -Value $SSDs -PassThru
                If ($PSBoundParameters['OutputTypeAsJSON']) {
                    Write-Output -InputObject $($StoragePool | Select-Object *,@{Name="SizeTB";Expression={[Math]::Truncate($_.Size / 1TB)}},@{Name="AllocatedSizeTB";Expression={[Math]::Truncate($_.AllocatedSize / 1TB)}} -ExcludeProperty $ExcludeProperties | ConvertTo-Json -Compress)
                }
                Else {
                    Write-Output -InputObject $($StoragePool | Select-Object *,@{Name="SizeTB";Expression={[Math]::Truncate($_.Size / 1TB)}},@{Name="AllocatedSizeTB";Expression={[Math]::Truncate($_.AllocatedSize / 1TB)}} -ExcludeProperty $ExcludeProperties)
                }
                Write-Debug -Message "[$((Get-Date).ToString())] [Get-CPSStoragePool] Debug Info (Storage Pools): $($StoragePool | ConvertTo-Json -Compress)"
            }
            #endregion
		}
		Catch {
			Write-Error -Exception $_.Exception -Message $_.Exception.Message -ErrorAction stop
		}
	}

	End {
		[System.GC]::Collect()
	}
}

Function Get-CPSVolume {
    [CmdletBinding()]
    Param (
        [Parameter(
            Position = 0,
            Mandatory = $False,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [ValidateNotNullOrEmpty()]
        [ValidateRange(1,4)]
        [Alias("Rack")]
        [Int] $RackIdentifier = 1,

        [Parameter(
            Position = 1,
            Mandatory = $False
        )]
        [ValidateNotNullOrEmpty()]
        [Switch] $OutputTypeAsJSON
    )
	
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
            Import-Module -Name Storage -Verbose:$False
            $VerbosePreference = $SaveVerbosePreference
        }
        Catch {
            Write-Error -Exception $_.Exception -Message $_.Exception.Message -ErrorAction Stop
        }

		$ExcludeProperties = @("PSComputerName","RunspaceId","PSShowComputerName","CimClass","CimInstanceProperties","CimSystemProperties")
	}

	Process {
        #region Access Node
		Try {
            $AccessNode = Get-CPSStorageAccessNode -RackIdentifier $RackIdentifier
		}
		Catch {
			Write-Error -Exception $_.Exception -Message $_.Exception.Message -ErrorAction Stop
		}
        #endregion
		
		Try {
            #region Volumes
            Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSVolume] [Get-Volume] Getting volumes..."
            $Volumes = Get-Volume -CimSession $AccessNode | Select-Object *,@{Name="SizeGB";Expression={[Math]::Truncate($_.Size / 1GB)}},@{Name="SizeRemainingGB";Expression={[Math]::Truncate($_.SizeRemaining / 1GB)}} -ExcludeProperty $ExcludeProperties
            Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSVolume] Identified $($Volumes.Count) volumes."
            Write-Debug -Message "[$((Get-Date).ToString())] [Get-CPSVolume] Debug Info (Volumes): $($Volumes | ConvertTo-Json -Compress)"
            #endregion
		}
		Catch {
			Write-Error -Exception $_.Exception -Message $_.Exception.Message -ErrorAction stop
		}

        If ($PSBoundParameters['OutputTypeAsJSON']) {
            Write-Output -InputObject $($Volumes | ConvertTo-Json -Compress)
        }
        Else {
            Write-Output -InputObject $Volumes
        }
	}

	End {
		[System.GC]::Collect()
	}
}

Function Test-CPSMPIO {
    [CmdletBinding()]
    Param (
    )
	
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
        Import-Module -Name Storage -Verbose:$False
        $VerbosePreference = $SaveVerbosePreference
    }
    Catch {
        Write-Error -Exception $_.Exception -Message $_.Exception.Message -ErrorAction Stop
    }
	
    $StorageNodeErrorCount = 0
    $StorageNodes = Get-StorageNode | Sort-Object -Property Name -Unique

    ForEach ($StorageNode in $StorageNodes) {
        $ErrorCount = 0
        $PhysicalDiskStorageNodeView = Get-PhysicalDiskStorageNodeView -StorageNode $StorageNode
        $PhysicalDisk = Get-PhysicalDisk
        ForEach ($PhysicalDiskView in $PhysicalDiskStorageNodeView) {
            $PhysicalDiskInfo = $PhysicalDisk | Where-Object {$_.ObjectId -eq $($PhysicalDiskView.PhysicalDiskObjectId)}
            [HashTable] $HashTable = @{}
            $HashTable.Add("StorageNode", $($StorageNode.Name))
            $HashTable.Add("FriendlyName", $($PhysicalDiskInfo.FriendlyName))
            $HashTable.Add("HealthStatus", $($PhysicalDiskInfo.HealthStatus))
            $HashTable.Add("OperationalStatus", $($PhysicalDiskInfo.OperationalStatus))
            $HashTable.Add("ObjectId", [String] $($PhysicalDiskView.PhysicalDiskObjectId))
            $HashTable.Add("PathId", $($PhysicalDiskView.PathId -join(', ')))
            $HashTable.Add("PathState", $($PhysicalDiskView.PathState -join (', ')))
            $HashTable.Add("IsMpioEnabled", $($PhysicalDiskView.IsMpioEnabled))
            If (($PhysicalDiskView.IsMpioEnabled -eq $False) -or ($PhysicalDiskView.PathState[0] -ne "Active/Optimized") -or ($PhysicalDiskView.PathState[1] -ne "Active/Optimized")) {
                If ($PhysicalDiskInfo.BusType -eq "SAS") {
                    $ErrorCount++
                    $HashTable.Add("IsMpioVerified", $False)
                    Write-Warning -Message "[$((Get-Date).ToString())] [Test-CPSMPIO] MPIO query status failed for Disk Number $($PhysicalDiskView.DiskNumber)"
                }
            }
            Else {
                $HashTable.Add("IsMpioVerified", $True)
            }
            New-Object -TypeName PSCustomObject -Property $HashTable
        }
        If ($ErrorCount -eq 0) {
            Write-Verbose -Message "[$((Get-Date).ToString())] [Test-CPSMPIO] Successfully verfied multi paths for $($PhysicalDiskStorageNodeView.Count) disks on storage node $($StorageNode.Name)"
        }
        Else {
            $StorageNodeErrorCount++
            Write-Warning -Message "[$((Get-Date).ToString())] [Test-CPSMPIO] Failed to verify $($ErrorCount) multi paths for storage node $($StorageNode.Name)"
        }
    }

    If ($StorageNodeErrorCount -eq 0) {
        Write-Verbose -Message "[$((Get-Date).ToString())] [Test-CPSMPIO] Successfully verified multi paths for all storage nodes."
    }
    Else {
        $StorageNodeErrorCount++
        Write-Warning -Message "[$((Get-Date).ToString())] [Test-CPSMPIO] Failure in verifying disk(s) on $($StorageNodeErrorCount) / $($StorageNodes.count) storage nodes."
    }
}

Function Test-CPSMPIOAsync {
    [CmdletBinding()]
    [OutputType([System.Object])]
    Param (
        [Parameter(
            Position = 0,
            Mandatory = $False
        )]
        [ValidateNotNullOrEmpty()]
        [ValidateRange(1,4)]
        [Alias("Rack")]
        [Int] $RackIdentifier = 1
    )
	
    Begin {
		If ($PSBoundParameters['Verbose']) {
			$VerbosePreference = "Continue"
		}
		If ($PSBoundParameters['Debug']) {
			$DebugPreference = "Continue"
			$ConfirmPreference = "None"
		}

        #region Script Block 1
        $ScriptBlock1 = {
            [CmdletBinding()]
            [OutputType([System.Object])]
            Param (
                [Parameter(
                    Position = 0,
                    Mandatory = $True
                )]
                [ValidateNotNullOrEmpty()]
                [String] $StorageNode
            )

		    If ($PSBoundParameters['Verbose']) {
			    $VerbosePreference = "Continue"
		    }
		    If ($PSBoundParameters['Debug']) {
			    $DebugPreference = "Continue"
			    $ConfirmPreference = "None"
		    }

            $ExcludeProperties = @("PSComputerName","RunspaceId","PSShowComputerName","CimClass","CimInstanceProperties","CimSystemProperties")
            
            #region Script Block 2
            $ScriptBlock2 = {
                [CmdletBinding()]
                [OutputType([System.Object])]
                Param (
                )

                Try {
                    $SaveVerbosePreference = $VerbosePreference
                    $VerbosePreference = "SilentlyContinue"
                    Import-Module -Name Storage -Verbose:$False
                    $VerbosePreference = $SaveVerbosePreference
                }
                Catch {
                    Write-Error -Exception $_.Exception -Message $_.Exception.Message -ErrorAction Stop
                }

                $VerbosePreference = $Using:VerbosePreference
                $DebugPreference = $Using:DebugPreference
                $ConfirmPreference = "None"
                
                $ErrorCount = 0
                $StorageNodeErrorCount = 0
                
                $StorageNode = $(Get-StorageNode | Where-Object {$_.Name -like "$env:COMPUTERNAME*"} | Sort-Object -Property Name -Unique)
                $PhysicalDiskStorageNodeView = Get-PhysicalDiskStorageNodeView -StorageNode $StorageNode
                $PhysicalDisk = Get-PhysicalDisk
                ForEach ($PhysicalDiskView in $PhysicalDiskStorageNodeView) {
                    $PhysicalDiskInfo = $PhysicalDisk | Where-Object {$_.ObjectId -eq $($PhysicalDiskView.PhysicalDiskObjectId)}
                    [HashTable] $HashTable = @{}
                    $HashTable.Add("StorageNode", $($StorageNode.Name))
                    $HashTable.Add("FriendlyName", $($PhysicalDiskInfo.FriendlyName))
                    $HashTable.Add("HealthStatus", $($PhysicalDiskInfo.HealthStatus))
                    $HashTable.Add("OperationalStatus", $($PhysicalDiskInfo.OperationalStatus))
                    $HashTable.Add("ObjectId", [String] $($PhysicalDiskView.PhysicalDiskObjectId))
                    $HashTable.Add("PathId", $($PhysicalDiskView.PathId -join(', ')))
                    $HashTable.Add("PathState", $($PhysicalDiskView.PathState -join (', ')))
                    $HashTable.Add("IsMpioEnabled", $($PhysicalDiskView.IsMpioEnabled))
                    If (($PhysicalDiskView.IsMpioEnabled -eq $False) -or ($PhysicalDiskView.PathState[0] -ne "Active/Optimized") -or ($PhysicalDiskView.PathState[1] -ne "Active/Optimized")) {
                        If ($PhysicalDiskInfo.BusType -eq "SAS") {
                            $ErrorCount++
                            $HashTable.Add("IsMpioVerified", $False)
                            Write-Warning -Message "[$((Get-Date).ToString())] [Test-CPSMPIOAsync] MPIO query status failed for Disk Number $($PhysicalDiskView.DiskNumber)"
                        }
                    }
                    Else {
                        $HashTable.Add("IsMpioVerified", $True)
                    }
                    New-Object -TypeName PSCustomObject -Property $HashTable
                }
                If ($ErrorCount -eq 0) {
                    Write-Verbose -Message "[$((Get-Date).ToString())] [Test-CPSMPIOAsync] Successfully verfied multi paths for $($PhysicalDiskStorageNodeView.Count) disks on storage node $($StorageNode.Name)"
                }
                Else {
                    $StorageNodeErrorCount++
                    Write-Warning -Message "[$((Get-Date).ToString())] [Test-CPSMPIOAsync] Failed to verify $($ErrorCount) multi paths for storage node $($StorageNode.Name)"
                }
            }
            #endregion
            
            If (($PSBoundParameters['Verbose']) -and ($PSBoundParameters['Debug'])) {
                Invoke-Command -ComputerName $StorageNode -ScriptBlock $ScriptBlock2 | Select-Object * -ExcludeProperty $ExcludeProperties -Verbose -Debug
            }
            ElseIf ($PSBoundParameters['Verbose']) {
                Invoke-Command -ComputerName $StorageNode -ScriptBlock $ScriptBlock2 | Select-Object * -ExcludeProperty $ExcludeProperties -Verbose
            }
            ElseIf ($PSBoundParameters['Debug']) {
                Invoke-Command -ComputerName $StorageNode -ScriptBlock $ScriptBlock2 | Select-Object * -ExcludeProperty $ExcludeProperties -Debug
            }
            Else {
                Invoke-Command -ComputerName $StorageNode -ScriptBlock $ScriptBlock2 | Select-Object * -ExcludeProperty $ExcludeProperties
            }
        }
        #endregion

        #region Storage Nodes
		Try {
            [Array] $StorageNodes = Get-CPSStorageNode -RackIdentifier $RackIdentifier
		}
		Catch {
			Write-Error -Exception $_.Exception -Message $_.Exception.Message -ErrorAction Stop
		}
        #endregion
	}

	Process {
        If (($PSBoundParameters['Verbose']) -and ($PSBoundParameters['Debug'])) {
            Invoke-PSRunSpace -InputObject $StorageNodes -ScriptBlock $ScriptBlock1 -MaxThreads 4 -SendInputObjectInstance -Verbose -Debug
        }
        ElseIf ($PSBoundParameters['Verbose']) {
            Invoke-PSRunSpace -InputObject $StorageNodes -ScriptBlock $ScriptBlock1 -MaxThreads 4 -SendInputObjectInstance -Verbose
        }
        ElseIf ($PSBoundParameters['Debug']) {
            Invoke-PSRunSpace -InputObject $StorageNodes -ScriptBlock $ScriptBlock1 -MaxThreads 4 -SendInputObjectInstance -Debug
        }
        Else {
            Invoke-PSRunSpace -InputObject $StorageNodes -ScriptBlock $ScriptBlock1 -MaxThreads 4 -SendInputObjectInstance
        }
	}

	End {
		[System.GC]::Collect()
	}
}

Function Invoke-CPSMPIO {
    [CmdletBinding()]
    [OutputType([System.Object])]
    Param (
        [Parameter(
            Position = 0,
            Mandatory = $False
        )]
        [ValidateNotNullOrEmpty()]
        [ValidateRange(1,4)]
        [Alias("Rack")]
        [Int] $RackIdentifier = 1
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
	}

	Process {
        #region Access Node
		Try {
            $AccessNode = Get-CPSStorageAccessNode -RackIdentifier $RackIdentifier
		}
		Catch {
			Write-Error -Exception $_.Exception -Message $_.Exception.Message -ErrorAction Stop
		}
        #endregion

        If (($PSBoundParameters['Verbose']) -and ($PSBoundParameters['Debug'])) {
            Invoke-CommandV2 -ComputerName $AccessNode -ScriptBlock {Test-CPSMPIO -Verbose -Debug} | Select-Object * -ExcludeProperty $ExcludeProperties
        }
        ElseIf ($PSBoundParameters['Verbose']) {
            Invoke-CommandV2 -ComputerName $AccessNode -ScriptBlock {Test-CPSMPIO -Verbose} | Select-Object * -ExcludeProperty $ExcludeProperties
        }
        ElseIf ($PSBoundParameters['Debug']) {
            Invoke-CommandV2 -ComputerName $AccessNode -ScriptBlock {Test-CPSMPIO -Debug} | Select-Object * -ExcludeProperty $ExcludeProperties
        }
        Else {
            Invoke-CommandV2 -ComputerName $AccessNode -ScriptBlock {Test-CPSMPIO} | Select-Object * -ExcludeProperty $ExcludeProperties
        }
	}

	End {
		[System.GC]::Collect()
	}
}

Function Get-CPSStorageEnclosureHealth {
    [CmdletBinding(SupportsShouldProcess = $True, ConfirmImpact = "Low")]
    [OutputType([System.Object])]
    Param (
        [Parameter(
            Position = 0,
            Mandatory = $False
        )]
        [String[]] $StorageNodes = $((Get-SCStorageArray).StorageNodes | Where-Object {($_.State -eq "OK") -and ($_.OperationalStatus -eq "OK")} | ForEach-Object {$_.Name} | Get-Random -Count 1),

        [Parameter(
            Position = 1,
            Mandatory = $False
        )]
        [ValidateNotNullOrEmpty()]
        [ValidateSet("0","1")]
        [String] $SASIndex = 0,

        [Parameter(
            Position = 2,
            Mandatory = $False
        )]
        [String] $SECliPath = "$($env:SystemDrive)\Program Files\Dell\ServerHardwareManager\ServerHardwareManagerCLI\Secli.exe",

        [Parameter(
            Position = 3,
            Mandatory = $False
        )]
        [ValidateNotNullOrEmpty()]
        [String] $WriteToFolderPath = "$env:USERPROFILE\StorageEnclosureHealth\$(Get-Date -Format 'M-dd-yyyy')\$([GUID]::NewGuid().Guid)\",

        [Parameter(
            Position = 4,
            Mandatory = $False
        )]
        [ValidateNotNullOrEmpty()]
        [Int] $ParentActivityId,

        [Parameter(
            Position = 5,
            Mandatory = $False
        )]
        [ValidateNotNullOrEmpty()]
        [Switch] $Force
    )

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
            Import-Module -Name Storage -Verbose:$False
            $VerbosePreference = $SaveVerbosePreference
        }
        Catch {
            Write-Error -Exception $_.Exception -Message $_.Exception.Message -ErrorAction Stop
        }

        $WriteToFolderPath = $WriteToFolderPath.TrimEnd('\')
        
        $SECliCommands = @(
            "info enclosure",
            "list power supplies",
            "list emms",
            "list drawers",
            "list fans",
            "list temp sensors",
            "list current sensors",
            "list drive slots",
            "list drives",
            "list failed drives"
        )

        $ScriptBlock = {
            Param (
                [String] $Command
            )
            Set-Location -Path "C:\Secli\"
            .\Secli.exe $Command
        }

        #region Initial Configuration Tasks
        Try {
            Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSStorageEnclosureHealth] Verifying the given path [$WriteToFolderPath]..."
            If ((!$PSBoundParameters['WriteToFolderPath']) -or (!(Test-Path -Path $WriteToFolderPath))) {
                Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSStorageEnclosureHealth] Creating a directory [$WriteToFolderPath] to save storage enclosure health..."
                New-Item -Path $WriteToFolderPath -ItemType Directory -Force -ErrorAction Stop | Out-Null
            }
            If (Test-Path -Path $WriteToFolderPath) {
                Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSStorageEnclosureHealth] Verification of the given path [$WriteToFolderPath] is successful."
            }
        }
        Catch {
            Write-Error -Exception $_.Exception -Message $_.Exception.Message -ErrorAction Stop
        }
        #endregion

        #region Verify Secli.exe Presense
        Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSStorageEnclosureHealth] Verifying the given path [$SECliPath] to 'Secli.exe'..."
        $SecliStatus = Get-Command -Name $SECliPath -ErrorAction SilentlyContinue
        If ($Null -ne $SecliStatus) {
            If ($SecliStatus.Name -eq "Secli.exe") {
                Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSStorageEnclosureHealth] 'Secli.exe' found in the given location [$SECliPath]."
                $SECLIHash = Get-FileHash -Path $SECliPath | Where-Object {$_.Algorithm -eq 'SHA256' -and $_.Hash -eq 'A7E162B7EEDDC518103047E5B6A3F8365DCB5B1339F044E61B44E4A9A11087E4'}
                If ($Null -ne $SECLIHash) {
                    Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSStorageEnclosureHealth] 'Secli.exe' SHA256 hash is verified."
                }
                Else {
                    Write-Warning -Message "[$((Get-Date).ToString())] [Get-CPSStorageEnclosureHealth] 'Secli.exe' SHA256 hash verification is failed! Make sure you have installed DELL Server Hardware Manager v1.5.0.1682"
                    Break
                }
            }
            Else {
                Write-Warning -Message "[$((Get-Date).ToString())] [Get-CPSStorageEnclosureHealth] Can't find 'Secli.exe' in the given location [$SECliPath]!"
                Break
            }
        }
        Else {
            Write-Warning -Message "[$((Get-Date).ToString())] [Get-CPSStorageEnclosureHealth] Can't find 'Secli.exe' in the given location!"
            Break
        }
        #endregion
    }

    Process {
        $RootActivityId = $(Get-Date -Format "yyyymmss")
        $ActiveStepId = 0
        $I = 0
        
        #region ForEach ($StorageNode in $StorageNodes)
        ForEach ($StorageNode in $StorageNodes) {
            $I++
            $ActiveStepId++
            If ($PSBoundParameters['ParentActivityId']) {
                Write-Progress -Activity "Retrieve Storage Enclosure Health.." -Status "Processing Storage Node $($StorageNode): Node $ActiveStepId of $($StorageNodes.Count)" -Id $RootActivityId -ParentId $ParentActivityId -PercentComplete (($ActiveStepId / $($StorageNodes.Count))*100) -CurrentOperation "Getting Storage Enclosure(s) Health..."
            }
            Else {
                Write-Progress -Activity "Retrieve Storage Enclosure Health.." -Status "Processing Storage Node $($StorageNode): Node $ActiveStepId of $($StorageNodes.Count)" -Id $RootActivityId -PercentComplete (($ActiveStepId / $($StorageNodes.Count))*100) -CurrentOperation "Getting Storage Enclosure(s) Health..."
            }

            #region Verify if there is an existing Secli.exe process is running
            $StorageNodeSECliPath = "\\$StorageNode\C$\Secli\"
            Try {
                Invoke-Command -ComputerName $StorageNode -ScriptBlock {
                    If (!(Test-Path -Path "C:\Secli\")) {
                        New-Item -Path "C:\Secli\" -ItemType Directory -Force | Out-Null
                    }
                    #region Stop Existing Secli Processes
                    If ($PSBoundParameters['Force']) {
                        Try {
                            Get-Process -Name secli -ErrorAction SilentlyContinue | Where-Object {($_.Path -eq 'C:\Secli\secli.exe')} | ForEach-Object {
                                Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSStorageEnclosureHealth] Stopping an existing Secli process [Name: $($_.Name)] [Path: $($_.Path)]..."
                                $_ | Stop-Process -Force | Out-Null
                                Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSStorageEnclosureHealth] Successfully stopped Secli process."
                            }
                        }
                        Catch {
                            Write-Error -Exception $_.Exception -Message $_.Exception.Message
                        }
                    }
                    #endregion
                }
                Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSStorageEnclosureHealth] [Copy-Item] Copying 'Secli.exe' from the given path to storage node [$StorageNode]..."
                If ($PSCmdlet.ShouldProcess("$SECliPath", "Copy-Item")) {
                    Copy-Item -Path $SECliPath -Destination $StorageNodeSECliPath -Force | Out-Null
                }
            }
            Catch {
                Write-Error -Exception $_.Exception -Message $_.Exception.Message
                Continue
            }
            #endregion

            Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSStorageEnclosureHealth] [Get-StorageEnclosure] Getting storage enclosures from storage node [$StorageNode]..."
            $StorageEnclosures = Get-StorageEnclosure -CimSession $StorageNode | Sort-Object FriendlyName # Storage Enclosures
            Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSStorageEnclosureHealth] Identified $($StorageEnclosures.Count) storage enclosures."
            $I = 0
            
            #region ForEach ($StorageEnclosure in $StorageEnclosures)
            ForEach ($StorageEnclosure in $StorageEnclosures) {
                $I++
                Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSStorageEnclosureHealth] Processing storage enclosure [$($StorageEnclosure.FriendlyName)] ($I of $($StorageEnclosures.Count))..."
                If ($WriteToFolderPath.Contains('\StorageEnclosureHealth\')) {
                    $LogPath = "$WriteToFolderPath\$StorageNode\SAS-$SASIndex\$($StorageEnclosure.FriendlyName)_$($StorageEnclosure.UniqueId)"
                }
                Else {
                    $LogPath = "$WriteToFolderPath\StorageEnclosureHealth\$StorageNode\SAS-$SASIndex\$($StorageEnclosure.FriendlyName)_$($StorageEnclosure.UniqueId)"
                }
                If (!(Test-Path -Path $LogPath)) {
                    New-Item -Path $LogPath -ItemType Directory -Force | Out-Null
                }
                Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSStorageEnclosureHealth] [LogPath: $($LogPath)]"
                $StorageEnclosure | Export-Clixml -Path "$LogPath\$($StorageEnclosure.FriendlyName)_$($StorageEnclosure.UniqueId).xml" -Force
                
                #region Storage Enclosure Vendor Data
                Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSStorageEnclosureHealth] [Get-StorageEnclosureVendorData] Getting vendor-specific data for an enclosure [Name: $($StorageEnclosure.FriendlyName)] [Unique Id: $($StorageEnclosure.UniqueId)]..."
                $StorageEnclosureVendorData = Get-StorageEnclosureVendorData -UniqueId $StorageEnclosure.UniqueId -PageNumber 0x2 -CimSession $StorageNode
                $StorageEnclosureVendorData | Export-Clixml -Path "$LogPath\$($StorageEnclosure.FriendlyName)_$($StorageEnclosure.UniqueId)_VendorData.xml" -Force
                #endregion

                Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSStorageEnclosureHealth] [Storage Node: $StorageNode]"
                Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSStorageEnclosureHealth] [Storage Enclosure Name: $($StorageEnclosure.FriendlyName)]"
                Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSStorageEnclosureHealth] [Storage Enclosure Unique Id: $($StorageEnclosure.UniqueId)]"
                Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSStorageEnclosureHealth] [Storage Enclosure Health Status: $($StorageEnclosure.HealthStatus)]"
                
                $StorageEnclosureUniqueId = $StorageEnclosure.UniqueId.ToLower()
                $StorageEnclosureCommand = "-enc=$StorageEnclosureUniqueId"
                
                #region ForEach ($SECliCommand in $SECliCommands)
                ForEach ($SECliCommand in $SECliCommands) {
                    $Command = " $SECliCommand -a=$SASIndex $StorageEnclosureCommand -outputformat=xml"
                    Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSStorageEnclosureHealth] [Invoke-Command] Executing command [$($Command.TrimStart())]..."
                    [Xml] $CommandResult = Invoke-Command -ComputerName $StorageNode -ScriptBlock $ScriptBlock -ArgumentList $Command
                    $CommandResult.ChildNodes[0].ChildNodes[0].ChildNodes[0].ChildNodes | Export-Clixml -Path "$LogPath\$($StorageEnclosure.FriendlyName)_$($StorageEnclosure.UniqueId)_$($CommandResult.ChildNodes[0].ChildNodes[0].ChildNodes[0].Name).xml" -Force
                    
                    # In case of EMMS
                    If ($SECliCommand -eq "list emms") {
                        $Command = " $SECliCommand -a=1 $StorageEnclosureCommand -outputformat=xml"
                        Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSStorageEnclosureHealth] [Invoke-Command] Executing command [$($Command.TrimStart())]..."
                        [Xml] $CommandResult = Invoke-Command -ComputerName $StorageNode -ScriptBlock $ScriptBlock -ArgumentList $Command
                        $CommandResult.ChildNodes[0].ChildNodes[0].ChildNodes[0].ChildNodes | Export-Clixml -Path "$LogPath\$($StorageEnclosure.FriendlyName)_$($StorageEnclosure.UniqueId)_$($CommandResult.ChildNodes[0].ChildNodes[0].ChildNodes[0].Name)_SAS-Index-2.xml" -Force
                    }
                }
                #endregion
            }
            #endregion

            If ($PSBoundParameters['ParentActivityId']) {
                Write-Progress -Activity "Retrieve Storage Enclosure Health.." -Status "Processing Storage Node $($StorageNode): Node $ActiveStepId of $($StorageNodes.Count)" -Id $RootActivityId -ParentId $ParentActivityId -PercentComplete (($ActiveStepId / $($StorageNodes.Count))*100) -CurrentOperation "Getting Storage Enclosure(s) Health..." -Completed
            }
            Else {
                Write-Progress -Activity "Retrieve Storage Enclosure Health.." -Status "Processing Storage Node $($StorageNode): Node $ActiveStepId of $($StorageNodes.Count)" -Id $RootActivityId -PercentComplete (($ActiveStepId / $($StorageNodes.Count))*100) -CurrentOperation "Getting Storage Enclosure(s) Health..." -Completed
            }
        }
        #endregion
    }

    End {
        [System.GC]::Collect()
    }
}

Function Get-CPSStorageEnclosureDrive {
    [CmdletBinding(SupportsShouldProcess = $True, ConfirmImpact = "Low")]
    [OutputType([System.Object])]
    Param (
        [Parameter(
            Position = 0,
            Mandatory = $False
        )]
        [String[]] $StorageNodes = $((Get-SCStorageArray).StorageNodes | Where-Object {($_.State -eq "OK") -and ($_.OperationalStatus -eq "OK")} | ForEach-Object {$_.Name} | Get-Random -Count 1),

        [Parameter(
            Position = 1,
            Mandatory = $False
        )]
        [ValidateNotNullOrEmpty()]
        [ValidateSet("0","1")]
        [String] $SASIndex = 0,

        [Parameter(
            Position = 2,
            Mandatory = $False
        )]
        [String] $SECliPath = "$($env:SystemDrive)\Program Files\Dell\ServerHardwareManager\ServerHardwareManagerCLI\Secli.exe",

        [Parameter(
            Position = 3,
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

        Try {
            $SaveVerbosePreference = $VerbosePreference
            $VerbosePreference = "SilentlyContinue"
            Import-Module -Name Storage -Verbose:$False
            $VerbosePreference = $SaveVerbosePreference
        }
        Catch {
            Write-Error -Exception $_.Exception -Message $_.Exception.Message -ErrorAction Stop
        }

        #region Verify Secli.exe Presense
        Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSStorageEnclosureDrive] Verifying the given path [$SECliPath] to 'Secli.exe'..."
        $SecliStatus = Get-Command -Name $SECliPath -ErrorAction SilentlyContinue
        If ($Null -ne $SecliStatus) {
            If ($SecliStatus.Name -eq "Secli.exe") {
                Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSStorageEnclosureDrive] 'Secli.exe' found in the given location [$SECliPath]."
                $SECLIHash = Get-FileHash -Path $SECliPath | Where-Object {$_.Algorithm -eq 'SHA256' -and $_.Hash -eq 'A7E162B7EEDDC518103047E5B6A3F8365DCB5B1339F044E61B44E4A9A11087E4'}
                If ($Null -ne $SECLIHash) {
                    Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSStorageEnclosureDrive] 'Secli.exe' SHA256 hash is verified."
                }
                Else {
                    Write-Warning -Message "[$((Get-Date).ToString())] [Get-CPSStorageEnclosureDrive] 'Secli.exe' SHA256 hash verification is failed! Make sure you have installed DELL Server Hardware Manager v1.5.0.1682"
                    Break
                }
            }
            Else {
                Write-Warning -Message "[$((Get-Date).ToString())] [Get-CPSStorageEnclosureDrive] Can't find 'Secli.exe' in the given location [$SECliPath]!"
                Break
            }
        }
        Else {
            Write-Warning -Message "[$((Get-Date).ToString())] [Get-CPSStorageEnclosureDrive] Can't find 'Secli.exe' in the given location!"
            Break
        }
        #endregion
    }

    Process {
        $RootActivityId = $(Get-Date -Format "yyyymmss")
        $ActiveStepId = 0
        $I = 0
        
        ForEach ($StorageNode in $StorageNodes) {
            $I++
            $ActiveStepId++
            If ($PSBoundParameters['ParentActivityId']) {
                Write-Progress -Activity "Retrieve Storage Enclosure Drives.." -Status "Processing Storage Node $($StorageNode): Node $ActiveStepId of $($StorageNodes.Count)" -Id $RootActivityId -ParentId $ParentActivityId -PercentComplete (($ActiveStepId / $($StorageNodes.Count))*100) -CurrentOperation "Getting Storage Enclosure Drives..."
            }
            Else {
                Write-Progress -Activity "Retrieve Storage Enclosure Drives.." -Status "Processing Storage Node $($StorageNode): Node $ActiveStepId of $($StorageNodes.Count)" -Id $RootActivityId -PercentComplete (($ActiveStepId / $($StorageNodes.Count))*100) -CurrentOperation "Getting Storage Enclosure Drives..."
            }

            #region Copy Secli.exe Executable To Storage Node
            $StorageNodeSECliPath = "\\$StorageNode\C$\Secli\"
            Try {
                Invoke-Command -ComputerName $StorageNode -ScriptBlock {
                    If (!(Test-Path -Path "C:\Secli\")) {
                        New-Item -Path "C:\Secli\" -ItemType Directory -Force | Out-Null
                    }
                }
                Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSStorageEnclosureDrive] [Copy-Item] Copying 'Secli.exe' from the given path to storage node [$StorageNode]..."
                If ($PSCmdlet.ShouldProcess("$SECliPath", "Copy-Item")) {
                    Copy-Item -Path $SECliPath -Destination $StorageNodeSECliPath -Force | Out-Null
                }
            }
            Catch {
                Write-Error -Exception $_.Exception -Message $_.Exception.Message
                Continue
            }
            #endregion

            Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSStorageEnclosureDrive] [Get-StorageEnclosure] Getting storage enclosures from storage node [$StorageNode]..."
            $StorageEnclosures = Get-StorageEnclosure -CimSession $StorageNode | Sort-Object FriendlyName # Storage Enclosures
            Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSStorageEnclosureDrive] Identified $($StorageEnclosures.Count) storage enclosures."
            $PhysicalDisks = Get-PhysicalDisk -CimSession $StorageNode # Physical Disks
            Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSStorageEnclosureDrive] Identified $($PhysicalDisks.Count) physical disks."
            
            #region Script Block 1
            $ScriptBlock1 = {
                Param (
                    $StorageEnclosure,
                    $PhysicalDisks,
                    $StorageNode,
                    $SASIndex
                )

                #region Script Block 2
                $ScriptBlock2 = {
                    Param (
                        [String] $Command
                    )
                    Try {
                        Set-Location -Path "C:\Secli\" -ErrorAction Stop
                        .\Secli.exe $Command
                    }
                    Catch {
                        Write-Error -Exception $_.Exception -Message $_.Exception.Message
                    }
                }
                #endregion

                Try {
                    $SaveVerbosePreference = $VerbosePreference
                    $VerbosePreference = "SilentlyContinue"
                    Import-Module -Name Storage -Verbose:$False
                    $VerbosePreference = $SaveVerbosePreference
                }
                Catch {
                    Write-Error -Exception $_.Exception -Message $_.Exception.Message -ErrorAction Stop
                }

                Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSStorageEnclosureDrive] Processing storage enclosure [$($StorageEnclosure.UniqueId)]..."
                Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSStorageEnclosureDrive] [Storage Node: $StorageNode]"
                Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSStorageEnclosureDrive] [Storage Enclosure Unique Id: $($StorageEnclosure.UniqueId)]"
                Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSStorageEnclosureDrive] [Storage Enclosure Health Status: $($StorageEnclosure.HealthStatus)]"
                If ($StorageEnclosure.HealthStatus -eq 0) {
                    $StorageEnclosureHealthStatus = "Healthy"
                }
                Else {
                    $StorageEnclosureHealthStatus = $StorageEnclosure.HealthStatus
                }
                
                $StorageEnclosureUniqueId = $StorageEnclosure.UniqueId.ToLower()
                $StorageEnclosureCommand = "-enc=$StorageEnclosureUniqueId"
                
                #region Enclosure Info & Drives
                Try {
                    $EnclosureInfoCmd = " info enclosure -a=$SASIndex $StorageEnclosureCommand -outputformat=xml" # Enclosure info
                    Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSStorageEnclosureDrive] [Invoke-Command] Executing command [$($EnclosureInfoCmd.TrimStart())]..."
                    [Xml] $EnclosureInfoCmdResult = Invoke-Command -ComputerName $StorageNode -ScriptBlock $ScriptBlock2 -ArgumentList $EnclosureInfoCmd
                    $StorageEnclosureInfo = $EnclosureInfoCmdResult.ChildNodes[0].ChildNodes[0].ChildNodes[0].ChildNodes
                    Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSStorageEnclosureDrive] [Storage Enclosure Service Tag: $($StorageEnclosureInfo.ServiceTag.Replace('SVC_',''))]"
                    Write-Debug -Message "[$((Get-Date).ToString())] [Get-CPSStorageEnclosureDrive] Debug Info (Storage Enclosure Info): $($StorageEnclosureInfo | ConvertTo-Csv -NoTypeInformation | ConvertFrom-Csv | ConvertTo-Json)"
                    
                    $EnclosureDrivesCmd = " list drives -a=$SASIndex $StorageEnclosureCommand -outputformat=xml" # List drives
                    Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSStorageEnclosureDrive] [Invoke-Command] Executing command [$($EnclosureDrivesCmd.TrimStart())]..."
                    [Xml] $EnclosureDrivesResult = Invoke-Command -ComputerName $StorageNode -ScriptBlock $ScriptBlock2 -ArgumentList $EnclosureDrivesCmd
                    $StorageEnclosureDrives = $EnclosureDrivesResult.ChildNodes[0].ChildNodes[0].ChildNodes[0].ChildNodes
                    
                    $StorageEnclosureDrives = $StorageEnclosureDrives | Add-Member -MemberType NoteProperty -Name StorageEnclosureUniqueId -Value $($StorageEnclosure.UniqueId) -PassThru
                    $StorageEnclosureDrives = $StorageEnclosureDrives | Add-Member -MemberType NoteProperty -Name StorageEnclosureHealthStatus -Value $([String] $StorageEnclosureHealthStatus) -PassThru
                    $StorageEnclosureDrives = $StorageEnclosureDrives | Add-Member -MemberType NoteProperty -Name StorageEnclosureServiceTag -Value $($StorageEnclosureInfo.ServiceTag.Replace('SVC_','')) -PassThru
                    
                    $StorageEnclosureDrives_ = ($StorageEnclosureDrives | Group-Object -Property VendorId -AsHashTable)
                    $StorageEnclosureDrives__ = ($StorageEnclosureDrives_).Keys | ForEach-Object {$StorageEnclosureDrives_["$($_)"] | ConvertTo-Csv -NoTypeInformation | ConvertFrom-Csv}
                    
                    ForEach ($StorageEnclosureDrive__ in $StorageEnclosureDrives__) {
                        $StorageEnclosureDrive__ = $StorageEnclosureDrive__ | Add-Member -MemberType NoteProperty -Name FriendlyName -Value $($PhysicalDisks | Where-Object {$_.SerialNumber -eq $StorageEnclosureDrive__.SerialNumber} | Select-Object FriendlyName | ForEach-Object {$_.FriendlyName}) -PassThru
                        $StorageEnclosureDrive__ = $StorageEnclosureDrive__ | Add-Member -MemberType NoteProperty -Name DiskNumber -Value $($PhysicalDisks | Where-Object {$_.SerialNumber -eq $StorageEnclosureDrive__.SerialNumber} | ForEach-Object {$_.FriendlyName -replace('PhysicalDisk','')}) -PassThru
                        $StorageEnclosureDrive__ = $StorageEnclosureDrive__ | Add-Member -MemberType NoteProperty -Name IsIndicationEnabled -Value $($PhysicalDisks | Where-Object {$_.SerialNumber -eq $StorageEnclosureDrive__.SerialNumber} | Select-Object IsIndicationEnabled | ForEach-Object {$_.IsIndicationEnabled}) -PassThru
                    
                        Write-Debug -Message "[$((Get-Date).ToString())] [Get-CPSStorageEnclosureDrive] Debug Info (Storage Enclosure Drive): $($StorageEnclosureDrive__ | ConvertTo-Json -Compress)"
                        Write-Output -InputObject $StorageEnclosureDrive__
                    }
                }
                Catch {
                    Write-Error -Exception $_.Exception -Message $_.Exception.Message
                    Continue
                }
                #endregion
            }
            #endregion

            If ($PSBoundParameters['Verbose'] -and $PSBoundParameters['Debug']) {
                Invoke-PSRunSpace -InputObject $StorageEnclosures -ScriptBlock $ScriptBlock1 -Arguments $PhysicalDisks,$StorageNode,$SASIndex -MaxThreads 4 -SendInputObjectInstance -Verbose -Debug
            }
            ElseIf ($PSBoundParameters['Verbose']) {
                Invoke-PSRunSpace -InputObject $StorageEnclosures -ScriptBlock $ScriptBlock1 -Arguments $PhysicalDisks,$StorageNode,$SASIndex -MaxThreads 4 -SendInputObjectInstance -Verbose
            }
            ElseIf ($PSBoundParameters['Debug']) {
                Invoke-PSRunSpace -InputObject $StorageEnclosures -ScriptBlock $ScriptBlock1 -Arguments $PhysicalDisks,$StorageNode,$SASIndex -MaxThreads 4 -SendInputObjectInstance -Debug
            }
            Else {
                Invoke-PSRunSpace -InputObject $StorageEnclosures -ScriptBlock $ScriptBlock1 -Arguments $PhysicalDisks,$StorageNode,$SASIndex -MaxThreads 4 -SendInputObjectInstance
            }

            If ($PSBoundParameters['ParentActivityId']) {
                Write-Progress -Activity "Retrieve Storage Enclosure Drives.." -Status "Processing Storage Node $($StorageNode): Node $ActiveStepId of $($StorageNodes.Count)" -Id $RootActivityId -ParentId $ParentActivityId -PercentComplete (($ActiveStepId / $($StorageNodes.Count))*100) -CurrentOperation "Getting Storage Enclosure Drives..." -Completed
            }
            Else {
                Write-Progress -Activity "Retrieve Storage Enclosure Drives.." -Status "Processing Storage Node $($StorageNode): Node $ActiveStepId of $($StorageNodes.Count)" -Id $RootActivityId -PercentComplete (($ActiveStepId / $($StorageNodes.Count))*100) -CurrentOperation "Getting Storage Enclosure Drives..." -Completed
            }
        }
    }

    End {
        [System.GC]::Collect()
    }
}

Function Get-CPSStorageEnclosureFailedDrive {
    [CmdletBinding(SupportsShouldProcess = $True, ConfirmImpact = "Low")]
    [OutputType([System.Object])]
    Param (
        [Parameter(
            Position = 0,
            Mandatory = $False
        )]
        [String[]] $StorageNodes = $((Get-SCStorageArray).StorageNodes | Where-Object {($_.State -eq "OK") -and ($_.OperationalStatus -eq "OK")} | ForEach-Object {$_.Name} | Get-Random -Count 1),

        [Parameter(
            Position = 1,
            Mandatory = $False
        )]
        [ValidateNotNullOrEmpty()]
        [ValidateSet("0","1")]
        [String] $SASIndex = 0,

        [Parameter(
            Position = 2,
            Mandatory = $False
        )]
        [String] $SECliPath = "$($env:SystemDrive)\Program Files\Dell\ServerHardwareManager\ServerHardwareManagerCLI\Secli.exe",

        [Parameter(
            Position = 3,
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

        Try {
            $SaveVerbosePreference = $VerbosePreference
            $VerbosePreference = "SilentlyContinue"
            Import-Module -Name Storage -Verbose:$False
            $VerbosePreference = $SaveVerbosePreference
        }
        Catch {
            Write-Error -Exception $_.Exception -Message $_.Exception.Message -ErrorAction Stop
        }

        #region Verify Secli.exe Presense
        Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSStorageEnclosureFailedDrive] Verifying the given path [$SECliPath] to 'Secli.exe'..."
        $SecliStatus = Get-Command -Name $SECliPath -ErrorAction SilentlyContinue
        If ($Null -ne $SecliStatus) {
            If ($SecliStatus.Name -eq "Secli.exe") {
                Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSStorageEnclosureFailedDrive] 'Secli.exe' found in the given location [$SECliPath]."
                $SECLIHash = Get-FileHash -Path $SECliPath | Where-Object {$_.Algorithm -eq 'SHA256' -and $_.Hash -eq 'A7E162B7EEDDC518103047E5B6A3F8365DCB5B1339F044E61B44E4A9A11087E4'}
                If ($Null -ne $SECLIHash) {
                    Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSStorageEnclosureFailedDrive] 'Secli.exe' SHA256 hash is verified."
                }
                Else {
                    Write-Warning -Message "[$((Get-Date).ToString())] [Get-CPSStorageEnclosureFailedDrive] 'Secli.exe' SHA256 hash verification is failed! Make sure you have installed DELL Server Hardware Manager v1.5.0.1682"
                    Break
                }
            }
            Else {
                Write-Warning -Message "[$((Get-Date).ToString())] [Get-CPSStorageEnclosureFailedDrive] Can't find 'Secli.exe' in the given location [$SECliPath]!"
                Break
            }
        }
        Else {
            Write-Warning -Message "[$((Get-Date).ToString())] [Get-CPSStorageEnclosureFailedDrive] Can't find 'Secli.exe' in the given location!"
            Break
        }
        #endregion
    }

    Process {
        $RootActivityId = $(Get-Date -Format "yyyymmss")
        $ActiveStepId = 0
        $I = 0
        
        ForEach ($StorageNode in $StorageNodes) {
            $I++
            $ActiveStepId++
            If ($PSBoundParameters['ParentActivityId']) {
                Write-Progress -Activity "Retrieve Storage Enclosure Failed Drives.." -Status "Processing Storage Node $($StorageNode): Node $ActiveStepId of $($StorageNodes.Count)" -Id $RootActivityId -ParentId $ParentActivityId -PercentComplete (($ActiveStepId / $($StorageNodes.Count))*100) -CurrentOperation "Getting Storage Enclosure Failed Drives..."
            }
            Else {
                Write-Progress -Activity "Retrieve Storage Enclosure Failed Drives.." -Status "Processing Storage Node $($StorageNode): Node $ActiveStepId of $($StorageNodes.Count)" -Id $RootActivityId -PercentComplete (($ActiveStepId / $($StorageNodes.Count))*100) -CurrentOperation "Getting Storage Enclosure Failed Drives..."
            }

            #region Copy Secli.exe Executable To Storage Node
            $StorageNodeSECliPath = "\\$StorageNode\C$\Secli\"
            Try {
                Invoke-Command -ComputerName $StorageNode -ScriptBlock {
                    If (!(Test-Path -Path "C:\Secli\")) {
                        New-Item -Path "C:\Secli\" -ItemType Directory -Force | Out-Null
                    }
                }
                Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSStorageEnclosureFailedDrive] [Copy-Item] Copying 'Secli.exe' from the given path to storage node [$StorageNode]..."
                If ($PSCmdlet.ShouldProcess("$SECliPath", "Copy-Item")) {
                    Copy-Item -Path $SECliPath -Destination $StorageNodeSECliPath -Force | Out-Null
                }
            }
            Catch {
                Write-Error -Exception $_.Exception -Message $_.Exception.Message
                Continue
            }
            #endregion

            Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSStorageEnclosureFailedDrive] [Get-StorageEnclosure] Getting storage enclosures from storage node [$StorageNode]..."
            $StorageEnclosures = Get-StorageEnclosure -CimSession $StorageNode | Sort-Object FriendlyName # Storage Enclosures
            Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSStorageEnclosureFailedDrive] Identified $($StorageEnclosures.Count) storage enclosures."
            $PhysicalDisks = Get-PhysicalDisk -CimSession $StorageNode # Physical Disks
            Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSStorageEnclosureDrive] Identified $($PhysicalDisks.Count) physical disks."
            
            #region Script Block 1
            $ScriptBlock1 = {
                Param (
                    $StorageEnclosure,
                    $PhysicalDisks,
                    $StorageNode,
                    $SASIndex
                )

                #region Script Block 2
                $ScriptBlock2 = {
                    Param (
                        [String] $Command
                    )
                    Try {
                        Set-Location -Path "C:\Secli\" -ErrorAction Stop
                        .\Secli.exe $Command
                    }
                    Catch {
                        Write-Error -Exception $_.Exception -Message $_.Exception.Message
                    }
                }
                #endregion

                Try {
                    $SaveVerbosePreference = $VerbosePreference
                    $VerbosePreference = "SilentlyContinue"
                    Import-Module -Name Storage -Verbose:$False
                    $VerbosePreference = $SaveVerbosePreference
                }
                Catch {
                    Write-Error -Exception $_.Exception -Message $_.Exception.Message -ErrorAction Stop
                }

                Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSStorageEnclosureFailedDrive] Processing storage enclosure [$($StorageEnclosure.UniqueId)]..."
                Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSStorageEnclosureFailedDrive] [Storage Node: $StorageNode]"
                Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSStorageEnclosureFailedDrive] [Storage Enclosure Unique Id: $($StorageEnclosure.UniqueId)]"
                Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSStorageEnclosureFailedDrive] [Storage Enclosure Health Status: $($StorageEnclosure.HealthStatus)]"
                
                $StorageEnclosureUniqueId = $StorageEnclosure.UniqueId.ToLower()
                $StorageEnclosureCommand = "-enc=$StorageEnclosureUniqueId"
                
                #region Enclosure Info & Failed Drives
                Try {
                    $EnclosureInfoCmd = " info enclosure -a=$SASIndex $StorageEnclosureCommand -outputformat=xml" # Enclosure info
                    Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSStorageEnclosureFailedDrive] [Invoke-Command] Executing command [$($EnclosureInfoCmd.TrimStart())]..."
                    [Xml] $EnclosureInfoCmdResult = Invoke-Command -ComputerName $StorageNode -ScriptBlock $ScriptBlock2 -ArgumentList $EnclosureInfoCmd
                    $StorageEnclosureInfo = $EnclosureInfoCmdResult.ChildNodes[0].ChildNodes[0].ChildNodes[0].ChildNodes
                    Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSStorageEnclosureFailedDrive] [Storage Enclosure Service Tag: $($StorageEnclosureInfo.ServiceTag.Replace('SVC_',''))]"
                    Write-Debug -Message "[$((Get-Date).ToString())] [Get-CPSStorageEnclosureFailedDrive] Debug Info (Storage Enclosure Info): $($StorageEnclosureInfo | ConvertTo-Csv -NoTypeInformation | ConvertFrom-Csv | ConvertTo-Json)"
                    
                    $EnclosureDrivesCmd = " list failed drives -a=$SASIndex $StorageEnclosureCommand -outputformat=xml" # List failed drives
                    Write-Verbose -Message "[$((Get-Date).ToString())] [Get-CPSStorageEnclosureFailedDrive] [Invoke-Command] Executing command [$($EnclosureDrivesCmd.TrimStart())]..."
                    [Xml] $EnclosureDrivesResult = Invoke-Command -ComputerName $StorageNode -ScriptBlock $ScriptBlock2 -ArgumentList $EnclosureDrivesCmd
                    $StorageEnclosureDrives = $EnclosureDrivesResult.ChildNodes[0].ChildNodes[0].ChildNodes[0].ChildNodes
                    
                    $StorageEnclosureDrives = $StorageEnclosureDrives | Add-Member -MemberType NoteProperty -Name StorageEnclosureUniqueId -Value $($StorageEnclosure.UniqueId) -PassThru
                    $StorageEnclosureDrives = $StorageEnclosureDrives | Add-Member -MemberType NoteProperty -Name StorageEnclosureHealthStatus -Value $($StorageEnclosure.HealthStatus) -PassThru
                    $StorageEnclosureDrives = $StorageEnclosureDrives | Add-Member -MemberType NoteProperty -Name StorageEnclosureServiceTag -Value $($StorageEnclosureInfo.ServiceTag.Replace('SVC_','')) -PassThru
                    
                    $StorageEnclosureDrives_ = ($StorageEnclosureDrives | Group-Object -Property VendorId -AsHashTable)
                    $StorageEnclosureDrives__ = ($StorageEnclosureDrives_).Keys | ForEach-Object {$StorageEnclosureDrives_["$($_)"] | ConvertTo-Csv -NoTypeInformation | ConvertFrom-Csv}
                    
                    ForEach ($StorageEnclosureDrive__ in $StorageEnclosureDrives__) {
                        $StorageEnclosureDrive__ = $StorageEnclosureDrive__ | Add-Member -MemberType NoteProperty -Name FriendlyName -Value $($PhysicalDisks | Where-Object {$_.SerialNumber -eq $StorageEnclosureDrive__.SerialNumber} | Select-Object FriendlyName | ForEach-Object {$_.FriendlyName}) -PassThru
                        $StorageEnclosureDrive__ = $StorageEnclosureDrive__ | Add-Member -MemberType NoteProperty -Name DiskNumber -Value $($PhysicalDisks | Where-Object {$_.SerialNumber -eq $StorageEnclosureDrive__.SerialNumber} | ForEach-Object {$_.FriendlyName -replace('PhysicalDisk','')}) -PassThru
                        $StorageEnclosureDrive__ = $StorageEnclosureDrive__ | Add-Member -MemberType NoteProperty -Name IsIndicationEnabled -Value $($PhysicalDisks | Where-Object {$_.SerialNumber -eq $StorageEnclosureDrive__.SerialNumber} | Select-Object IsIndicationEnabled | ForEach-Object {$_.IsIndicationEnabled}) -PassThru
                        
                        Write-Debug -Message "[$((Get-Date).ToString())] [Get-CPSStorageEnclosureFailedDrive] Debug Info (Storage Enclosure Drive): $($StorageEnclosureDrive__ | ConvertTo-Json -Compress)"
                        Write-Output -InputObject $StorageEnclosureDrive__
                    }
                }
                Catch {
                    Write-Error -Exception $_.Exception -Message $_.Exception.Message
                    Continue
                }
                #endregion
            }
            #endregion

            If ($PSBoundParameters['Verbose'] -and $PSBoundParameters['Debug']) {
                Invoke-PSRunSpace -InputObject $StorageEnclosures -ScriptBlock $ScriptBlock1 -Arguments $PhysicalDisks,$StorageNode,$SASIndex -MaxThreads 4 -SendInputObjectInstance -Verbose -Debug
            }
            ElseIf ($PSBoundParameters['Verbose']) {
                Invoke-PSRunSpace -InputObject $StorageEnclosures -ScriptBlock $ScriptBlock1 -Arguments $PhysicalDisks,$StorageNode,$SASIndex -MaxThreads 4 -SendInputObjectInstance -Verbose
            }
            ElseIf ($PSBoundParameters['Debug']) {
                Invoke-PSRunSpace -InputObject $StorageEnclosures -ScriptBlock $ScriptBlock1 -Arguments $PhysicalDisks,$StorageNode,$SASIndex -MaxThreads 4 -SendInputObjectInstance -Debug
            }
            Else {
                Invoke-PSRunSpace -InputObject $StorageEnclosures -ScriptBlock $ScriptBlock1 -Arguments $PhysicalDisks,$StorageNode,$SASIndex -MaxThreads 4 -SendInputObjectInstance
            }

            If ($PSBoundParameters['ParentActivityId']) {
                Write-Progress -Activity "Retrieve Storage Enclosure Failed Drives.." -Status "Processing Storage Node $($StorageNode): Node $ActiveStepId of $($StorageNodes.Count)" -Id $RootActivityId -ParentId $ParentActivityId -PercentComplete (($ActiveStepId / $($StorageNodes.Count))*100) -CurrentOperation "Getting Storage Enclosure Failed Drives..." -Completed
            }
            Else {
                Write-Progress -Activity "Retrieve Storage Enclosure Failed Drives.." -Status "Processing Storage Node $($StorageNode): Node $ActiveStepId of $($StorageNodes.Count)" -Id $RootActivityId -PercentComplete (($ActiveStepId / $($StorageNodes.Count))*100) -CurrentOperation "Getting Storage Enclosure Failed Drives..." -Completed
            }
        }
    }

    End {
        [System.GC]::Collect()
    }
}