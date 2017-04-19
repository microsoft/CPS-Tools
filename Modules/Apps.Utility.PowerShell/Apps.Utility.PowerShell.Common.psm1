#########################################################
# Module Manifest Name: Apps.Utility.PowerShell.Common.psm1
# Module Manifest Description: Utility Module - Holds common functions
# Author: Srinath Sadda
#########################################################

Function Invoke-CommandV2 {
    [CmdletBinding(
        DefaultParameterSetName = 'InProcess',
        HelpUri = 'http://go.microsoft.com/fwlink/?LinkID = 135225',
        RemotingCapability = 'OwnedByCommand'
    )]
    Param(
        [Parameter(
            ParameterSetName = 'FilePathRunspace',
            Position = 0
        )]
        [Parameter(
            ParameterSetName = 'Session',
            Position = 0
        )]
        [ValidateNotNullOrEmpty()]
        [System.Management.Automation.Runspaces.PSSession[]]
        ${Session},
 
        [Parameter(
            ParameterSetName = 'FilePathComputerName',
            Position = 0
        )]
        [Parameter(
            ParameterSetName = 'ComputerName',
            Position = 0
        )]
        [Alias('Cn')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        ${ComputerName},
 
        [Parameter(
            ParameterSetName = 'Uri',
            ValueFromPipelineByPropertyName = $True
        )]
        [Parameter(
            ParameterSetName = 'FilePathUri',
            ValueFromPipelineByPropertyName =  $True
        )]
        [Parameter(
            ParameterSetName = 'ComputerName',
            ValueFromPipelineByPropertyName =  $True
        )]
        [Parameter(
            ParameterSetName = 'FilePathComputerName',
            ValueFromPipelineByPropertyName =  $True
        )]
        [PSCredential]
        [System.Management.Automation.CredentialAttribute()]
        ${Credential},
 
        [Parameter(ParameterSetName = 'ComputerName')]
        [Parameter(ParameterSetName = 'FilePathComputerName')]
        [ValidateRange(1, 65535)]
        [Int]
        ${Port},
 
        [Parameter(ParameterSetName = 'ComputerName')]
        [Parameter(ParameterSetName = 'FilePathComputerName')]
        [Switch]
        ${UseSSL},
 
        [Parameter(
            ParameterSetName = 'FilePathComputerName',
            ValueFromPipelineByPropertyName =  $True
        )]
        [Parameter(
            ParameterSetName = 'ComputerName',
            ValueFromPipelineByPropertyName =  $True
        )]
        [Parameter(
            ParameterSetName = 'FilePathUri',
            ValueFromPipelineByPropertyName =  $True
        )]
        [Parameter(
            ParameterSetName = 'Uri',
            ValueFromPipelineByPropertyName =  $True
        )]
        [String]
        ${ConfigurationName},
 
        [Parameter(
            ParameterSetName = 'ComputerName',
            ValueFromPipelineByPropertyName =  $True
        )]
        [Parameter(
            ParameterSetName = 'FilePathComputerName',
            ValueFromPipelineByPropertyName =  $True
        )]
        [String]
        ${ApplicationName},
 
        [Parameter(ParameterSetName = 'FilePathComputerName')]
        [Parameter(ParameterSetName = 'Session')]
        [Parameter(ParameterSetName = 'ComputerName')]
        [Parameter(ParameterSetName = 'FilePathRunspace')]
        [Parameter(ParameterSetName = 'FilePathUri')]
        [Parameter(ParameterSetName = 'Uri')]
        [Int]
        ${ThrottleLimit},
 
        [Parameter(
            ParameterSetName = 'Uri',
            Position = 0
        )]
        [Parameter(
            ParameterSetName = 'FilePathUri',
            Position = 0
        )]
        [Alias('Uri','Cu')]
        [ValidateNotNullOrEmpty()]
        [Uri[]]
        ${ConnectionUri},
 
        [Parameter(ParameterSetName = 'FilePathComputerName')]
        [Parameter(ParameterSetName = 'Uri')]
        [Parameter(ParameterSetName = 'ComputerName')]
        [Parameter(ParameterSetName = 'FilePathRunspace')]
        [Parameter(ParameterSetName = 'FilePathUri')]
        [Parameter(ParameterSetName = 'Session')]
        [Switch]
        ${AsJob},
 
        [Parameter(ParameterSetName = 'Uri')]
        [Parameter(ParameterSetName = 'FilePathComputerName')]
        [Parameter(ParameterSetName = 'FilePathUri')]
        [Parameter(ParameterSetName = 'ComputerName')]
        [Alias('Disconnected')]
        [Switch]
        ${InDisconnectedSession},
 
        [Parameter(ParameterSetName = 'FilePathComputerName')]
        [Parameter(ParameterSetName = 'ComputerName')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        ${SessionName},
 
        [Parameter(ParameterSetName = 'FilePathComputerName')]
        [Parameter(ParameterSetName = 'Session')]
        [Parameter(ParameterSetName = 'FilePathRunspace')]
        [Parameter(ParameterSetName = 'ComputerName')]
        [Parameter(ParameterSetName = 'FilePathUri')]
        [Parameter(ParameterSetName = 'Uri')]
        [Alias('Hcn')]
        [Switch]
        ${HideComputerName},
 
        [Parameter(ParameterSetName = 'Session')]
        [Parameter(ParameterSetName = 'FilePathRunspace')]
        [Parameter(ParameterSetName = 'FilePathComputerName')]
        [Parameter(ParameterSetName = 'ComputerName')]
        [Parameter(ParameterSetName = 'FilePathUri')]
        [Parameter(ParameterSetName = 'Uri')]
        [String]
        ${JobName},
 
        [Parameter(ParameterSetName = 'Session', Mandatory =  $True, Position = 1)]
        [Parameter(ParameterSetName = 'Uri', Mandatory =  $True, Position = 1)]
        [Parameter(ParameterSetName = 'InProcess', Mandatory =  $True, Position = 0)]
        [Parameter(ParameterSetName = 'ComputerName', Mandatory =  $True, Position = 1)]
        [Alias('Command')]
        [ValidateNotNull()]
        [ScriptBlock]
        ${ScriptBlock},
 
        [Parameter(ParameterSetName = 'InProcess')]
        [Switch]
        ${NoNewScope},
 
        [Parameter(ParameterSetName = 'FilePathUri', Mandatory =  $True, Position = 1)]
        [Parameter(ParameterSetName = 'FilePathComputerName', Mandatory =  $True, Position = 1)]
        [Parameter(ParameterSetName = 'FilePathRunspace', Mandatory =  $True, Position = 1)]
        [Alias('PSPath')]
        [ValidateNotNull()]
        [String]
        ${FilePath},
 
        [Parameter(ParameterSetName = 'Uri')]
        [Parameter(ParameterSetName = 'FilePathUri')]
        [Switch]
        ${AllowRedirection},
 
        [Parameter(ParameterSetName = 'FilePathComputerName')]
        [Parameter(ParameterSetName = 'ComputerName')]
        [Parameter(ParameterSetName = 'Uri')]
        [Parameter(ParameterSetName = 'FilePathUri')]
        [System.Management.Automation.Remoting.PSSessionOption]
        ${SessionOption},
 
        [Parameter(ParameterSetName = 'Uri')]
        [Parameter(ParameterSetName = 'ComputerName')]
        [Parameter(ParameterSetName = 'FilePathComputerName')]
        [Parameter(ParameterSetName = 'FilePathUri')]
        [System.Management.Automation.Runspaces.AuthenticationMechanism]
        ${Authentication},

        [Parameter(ParameterSetName = 'FilePathComputerName')]
        [Parameter(ParameterSetName = 'ComputerName')]
        [Parameter(ParameterSetName = 'Uri')]
        [Parameter(ParameterSetName = 'FilePathUri')]
        [Switch]
        ${EnableNetworkAccess},
 
        [Parameter(ValueFromPipeline =  $True)]
        [PSObject]
        ${InputObject},
 
        [Alias('Args')]
        [System.Object[]]
        ${ArgumentList},
 
        [Parameter(ParameterSetName = 'ComputerName')]
        [Parameter(ParameterSetName = 'Uri')]
        [String]
        ${CertificateThumbprInt}
    )
 
    Begin {
        Function Get-ScriptBlockFunction {
            Param (
                [Parameter(Mandatory = $True)]
                [ValidateNotNull()]
                [ScriptBlock]
                $ScriptBlock
            )

            # Return all user-defined function names contained within the supplied ScriptBlock
            $ScriptBlock.Ast.FindAll({$args[0] -is [Management.Automation.Language.CommandAst]}, $True) |
                ForEach-Object { $_.CommandElements[0] } | Sort-Object Value -Unique | ForEach-Object { $_.Value } |
                    Where-Object { Get-ChildItem Function:\$_ -ErrorAction Ignore }
        }
 
        Function Get-FunctionDefinition {
            Param (
                [Parameter(Mandatory = $True, ValueFromPipeline = $True)]
                [String[]]
                [ValidateScript({Get-Command $_})]
                $FunctionName
            )

            Begin {
                # We want to output a single String versus an array of Strings
                $FunctionCollection  =  ''    
            }
 
            Process {
                ForEach ($Function in $FunctionName) {
                    $FunctionInfo  =  Get-Command $Function
                    $FunctionCollection +=  "function $($FunctionInfo.Name) {`n$($FunctionInfo.Definition)`n}`n"
                }
            }
 
            End {
                $FunctionCollection
            }
        }
 
        Try {
            $OutBuffer  =  $Null
            If ($PSBoundParameters.TryGetValue('OutBuffer', [Ref]$OutBuffer)) {
                $PSBoundParameters['OutBuffer']  =  1
            }
            $WrappedCmd  =  $ExecutionContext.InvokeCommand.GetCommand('Invoke-Command', [System.Management.Automation.CommandTypes]::Cmdlet)
            If ($PSBoundParameters['ScriptBlock']) {
                $FunctionDefinitions  =  Get-ScriptBlockFunction $ScriptBlock | Get-FunctionDefinition
                $PSBoundParameters['ScriptBlock']  =  [ScriptBlock]::Create($FunctionDefinitions + $ScriptBlock.ToString())
            }
            $ScriptCmd  =  {& $WrappedCmd @PSBoundParameters }
            $SteppablePipeline  =  $ScriptCmd.GetSteppablePipeline($MyInvocation.CommandOrigin)
            $SteppablePipeline.Begin($PSCmdlet)
        }
        Catch {
            Throw $_
        }
    }
 
    Process {
        Try {
            $SteppablePipeline.Process($_)
        }
        Catch {
            Throw $_
        }
    }
 
    End
    {
        Try {
            $SteppablePipeline.End()
        }
        Catch {
            Throw $_
        }
    }
}

Function ConvertFrom-CliXml {
    [CmdletBinding()]
    [OutputType([System.Object])]
    Param (       
        [Parameter(
            Position = 0,
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True)]
        [ValidateNotNullOrEmpty()]
        [System.Object] $CliXml
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
        Write-Debug -Message "[ConvertFrom-CliXml] CliXml: $CliXml"
        Write-Verbose -Message "[ConvertFrom-CliXml] Deserializing the given CliXml into object format..."
        [System.Management.Automation.PSSerializer]::Deserialize($CliXml)
    }
    End {
        [System.GC]::Collect()
    }
}

Function ConvertTo-CliXml {
    [CmdletBinding()]
    [OutputType([System.String])]
    Param (
        [Parameter(
            Position = 0,
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True
        )]
        [ValidateNotNullOrEmpty()]
        [System.Object] $InputObject,

        [Parameter(
            Position = 1,
            Mandatory = $False
        )]
        [ValidateNotNullOrEmpty()]
        [Int] $Depth = 1
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
        Write-Debug -Message "[ConvertTo-CliXml] InputObject: $($InputObject | ConvertTo-Json -Compress)"
        Write-Verbose -Message "[ConvertTo-CliXml] Serializing the given input object (with depth of $Depth) into CliXml format..."
        [System.Management.Automation.PSSerializer]::Serialize($InputObject, $Depth)
    }
    End {
        [System.GC]::Collect()
    }
}

Function Format-PascalCase {
    [CmdletBinding()]
    Param (
        [Parameter(
            Position = 0,
            Mandatory = $True,
            ValueFromPipeline = $True
        )]
        [ValidateNotNullOrEmpty()]
        [System.Management.Automation.PSObject[]] $PSObjects
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
        $PSObjects | ForEach-Object {
            If ($_ -is [Array]) {
                $_ | ForEach-Object { Format-PascalCase $_ }
            }
            Else {
                ($_.ToString() -creplace '(?<!^)([A-Z][a-z]|(?<=[a-z])[A-Z])', ' $&') -join(' ')
            }
        }
    }

    End {
        [System.GC]::Collect()
    }
}

Function Format-PSObject {
    [CmdletBinding()]
    Param (
        [Parameter(
            Position = 0,
            Mandatory = $True,
            ValueFromPipeline = $True
        )]
        [ValidateNotNullOrEmpty()]
        [System.Management.Automation.PSObject[]] $PSObjects
    )

    Begin {
        If ($PSBoundParameters['Verbose']) {
            $VerbosePreference = "Continue"
        }
        If ($PSBoundParameters['Debug']) {
            $DebugPreference = "Continue"
            $ConfirmPreference = "None"
        }

        $FormattedObjects = 0
    }

    Process {
        $I = 0
        ForEach ($PSObject in $PSObjects) {
            $I++
            Write-Verbose -Message "[Format-PSObject] Formatting PSObject ($I of $($PSObjects.Count))..."
            Try {
                Write-Debug -Message "[$((Get-Date).ToString())] [Format-PSObject] Debug Info (PSObject): $($PSObject | ConvertTo-Json)"
            }
            Catch {
                Write-Debug -Message "[$((Get-Date).ToString())] [Format-PSObject] Debug Info (PSObject): $($PSObject | ConvertTo-Json -Compress)"
            }

            Try {
                $Properties = $PSObject | Get-Member -MemberType Properties
                [HashTable] $HashTable = @{}

                ForEach ($Property in $Properties) {
                    $Name = Format-PascalCase @($Property.Name)
                    $Value = $PSObject.$($Property.Name)
                                
                    If (($Null -eq $Name) -or ('' -eq $Name)) {
                        Continue
                    }
                    
                    $HashTable.Add($Name, $Value)
                }

                $PSObjectInfo = New-Object -TypeName PSCustomObject -Property $HashTable
                
                Try {
                    Write-Debug -Message "[$((Get-Date).ToString())] [Format-PSObject] Debug Info (Formatted PSObject): $($PSObjectInfo | ConvertTo-Json)"
                }
                Catch {
                    Write-Debug -Message "[$((Get-Date).ToString())] [Format-PSObject] Debug Info (Formatted PSObject): $($PSObjectInfo | ConvertTo-Json -Compress)"
                }
                Write-Output -InputObject $PSObjectInfo
                
                $FormattedObjects++
            }
            Catch {
                Write-Error -Exception $_.Exception
            }
        }
    }

    End {
        Write-Verbose -Message "[Format-PSObject] Successfully formatted PSObjects: $FormattedObjects"
        [System.GC]::Collect()
    }
}

Function Get-InstalledUpdate {
    [CmdletBinding()]
    Param (
        [Parameter(
            Position = 0,
            Mandatory = $False
        )]
        [Switch] $ExchangeServerSpecific
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
        Write-Verbose -Message "[Get-InstalledUpdate] Getting installed updates..."
    
        $UpdateSearcher = New-Object -ComObject Microsoft.Update.Searcher
        $TotalUpdates = $UpdateSearcher.QueryHistory(0,$($UpdateSearcher.GetTotalHistoryCount()))
        
        Write-Verbose -Message "[Get-InstalledUpdate] Identified $($TotalUpdates.Count) updates."

        $I = 0
        ForEach ($Update in $TotalUpdates) {
            $I++
            Write-Verbose -Message "[Get-InstalledUpdate] Processing update [$($Update.Title)] ($I of $($TotalUpdates.Count) updates)..."

            If ($PSBoundParameters['ExchangeServerSpecific']) {
                If ($Title -like '*Exchange Server*') {
                    Write-Verbose -Message "[Get-InstalledUpdate] Identified as Exchange Server specific installed rollup or security update."
                    $InstalledUpdate = Format-InstalledUpdate -Update $Update
                }
            }
            Else {
                $InstalledUpdate = Format-InstalledUpdate -Update $Update
            }
            Write-Debug -Message "[Get-InstalledUpdate] Debug Info: $($InstalledUpdate | ConvertTo-Json)"
            Write-Output -InputObject $InstalledUpdate
        }
    }

    End {
        [System.GC]::Collect()
    }
}

Function Format-InstalledUpdate {
    [CmdletBinding()]
    Param (
        [Parameter(
            Position = 0,
            Mandatory = $True
        )]
        $Update
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
        $ID = $Update.Title | Select-String -Pattern 'KB\d*' | Select-Object { $_.Matches }
        New-Object -TypeName PSObject -Property @{
            ID = $ID.' $_.Matches '.Value
            Title = $Update.Title
            Date = $Update.Date
        } | Select-Object ID,Title,Date
    }

    End {
        [System.GC]::Collect()
    }
}

Function Get-ElapsedTime {
    [CmdletBinding()]
    Param (       
        [Parameter(
            Position = 0,
            Mandatory = $True
        )]
        [ValidateNotNullOrEmpty()]
        [DateTime] $StartTime,

        [Parameter(
            Position = 1,
            Mandatory = $False
        )]
        [ValidateNotNullOrEmpty()]
        [DateTime] $EndTime
    )

    If (!$PSBoundParameters['EndTime']) {
        $EndTime = Get-Date
    }
    Write-Output -InputObject $($EndTime - $StartTime)
}

Function Write-Clixml {
    [CmdletBinding()]
    Param (       
        [Parameter(
            Position = 0,
            Mandatory = $True
        )]
        [ValidateNotNullOrEmpty()]
        [System.Object] $InputObject,

        [Parameter(
            Position = 1,
            Mandatory = $True
        )]
        [ValidateNotNullOrEmpty()]
        [String] $WriteToFolderPath,

        [Parameter(
            Position = 2,
            Mandatory = $True
        )]
        [ValidateNotNullOrEmpty()]
        [String] $WriteToFileName
    )

    Try {
        If (!(Test-Path -Path $WriteToFolderPath)) {
            Write-Verbose -Message "[$((Get-Date).ToString())] [Write-Clixml] Path $WriteToFolderPath doesn't exist! Creating a directory now..."
            New-Item -Path $WriteToFolderPath -ItemType Directory -Force -ErrorAction Stop | Out-Null
        }
        Write-Verbose -Message "[$((Get-Date).ToString())] [Write-Clixml] Verified path [$WriteToFolderPath]"
        Write-Verbose -Message "[$((Get-Date).ToString())] [Write-Clixml] [Export-Clixml] Converting the given input object to CliXml format and saving to file..."
        Export-Clixml -InputObject $InputObject -Path "$WriteToFolderPath\$WriteToFileName.XML" -Force -ErrorAction Stop
    }
    Catch {
        Write-Error -Exception $_.Exception -Message $_.Exception.Message -ErrorAction Stop
    }
}

Function Write-ClixmlAsync {
    [CmdletBinding()]
    [OutputType([System.Object])]
    Param (       
        [Parameter(
            Position = 0,
            Mandatory = $True
        )]
        [ValidateNotNullOrEmpty()]
        [System.Object] $InputObject,

        [Parameter(
            Position = 1,
            Mandatory = $True
        )]
        [ValidateNotNullOrEmpty()]
        [String] $WriteToFolderPath,

        [Parameter(
            Position = 2,
            Mandatory = $True
        )]
        [ValidateNotNullOrEmpty()]
        [String] $WriteToFileName
    )

    If ($PSBoundParameters['Verbose']) {
        $VerbosePreference = "Continue"
    }
    If ($PSBoundParameters['Debug']) {
        $DebugPreference = "Continue"
        $ConfirmPreference = "None"
    }

    #region Script Block
    $ScriptBlock = {
        [CmdletBinding()]
        Param (       
            [Parameter(
                Position = 0,
                Mandatory = $True
            )]
            [ValidateNotNullOrEmpty()]
            [System.Object] $InputObject,

            [Parameter(
                Position = 1,
                Mandatory = $True
            )]
            [ValidateNotNullOrEmpty()]
            [String] $WriteToFolderPath,

            [Parameter(
                Position = 2,
                Mandatory = $True
            )]
            [ValidateNotNullOrEmpty()]
            [String] $WriteToFileName
        )

        If ($PSBoundParameters['Verbose']) {
            $VerbosePreference = "Continue"
        }
        If ($PSBoundParameters['Debug']) {
            $DebugPreference = "Continue"
            $ConfirmPreference = "None"
        }

        Try {
            If (!(Test-Path -Path $WriteToFolderPath)) {
                Write-Verbose -Message "[$((Get-Date).ToString())] [Write-ClixmlAsync] Path $WriteToFolderPath doesn't exist! Creating a directory now..."
                New-Item -Path $WriteToFolderPath -ItemType Directory -Force -ErrorAction Stop | Out-Null
            }
            Write-Verbose -Message "[$((Get-Date).ToString())] [Write-ClixmlAsync] Verified path [$WriteToFolderPath]"
            Write-Verbose -Message "[$((Get-Date).ToString())] [Write-ClixmlAsync] [Export-Clixml] Converting the given input object to CliXml format and saving to file..."
            Export-Clixml -InputObject $InputObject -Path "$WriteToFolderPath\$WriteToFileName.XML" -Force -ErrorAction Stop
        }
        Catch {
            Write-Error -Exception $_.Exception -Message $_.Exception.Message -ErrorAction Stop
        }
    }
    #endregion

    Try {
        Write-Verbose -Message "[$((Get-Date).ToString())] [Write-ClixmlAsync] Invoking a background job..."
        $Job = Start-Job -Name $([GUID]::NewGuid().Guid) -ScriptBlock $ScriptBlock -ArgumentList $InputObject, $WriteToFolderPath, $WriteToFileName
        Write-Verbose -Message "[$((Get-Date).ToString())] [Write-ClixmlAsync] A background job [Name: $($Job.Name)] [Id: $($Job.Id)] has been created successfully."
        Write-Output -InputObject $Job
    }
    Catch {
        Write-Error -Exception $_.Exception -Message $_.Exception.Message -ErrorAction Stop
    }
}

Function Write-Json {
    [CmdletBinding()]
    Param (       
        [Parameter(
            Position = 0,
            Mandatory = $True
        )]
        [ValidateNotNullOrEmpty()]
        [System.Object] $InputObject,

        [Parameter(
            Position = 1,
            Mandatory = $True
        )]
        [ValidateNotNullOrEmpty()]
        [String] $WriteToFolderPath,

        [Parameter(
            Position = 2,
            Mandatory = $True
        )]
        [ValidateNotNullOrEmpty()]
        [String] $WriteToFileName
    )

    Try {
        If (!(Test-Path -Path $WriteToFolderPath)) {
            Write-Verbose -Message "[$((Get-Date).ToString())] [Write-Json] Path $WriteToFolderPath doesn't exist! Creating a directory now..."
            New-Item -Path $WriteToFolderPath -ItemType Directory -Force -ErrorAction Stop | Out-Null
        }
        Write-Verbose -Message "[$((Get-Date).ToString())] [Write-Json] Verified path [$WriteToFolderPath]"
        Write-Verbose -Message "[$((Get-Date).ToString())] [Write-Json] [ConvertTo-Json] Converting the given input object to JSON format..."
        $Json = ConvertTo-Json -InputObject $InputObject -Compress
        Write-Verbose -Message "[$((Get-Date).ToString())] [Write-Json] [Out-File] Writing JSON content to file..."
        Out-File -InputObject $Json -FilePath "$WriteToFolderPath\$WriteToFileName.JSON" -Force -ErrorAction Stop
    }
    Catch {
        Write-Error -Exception $_.Exception -Message $_.Exception.Message -ErrorAction Stop
    }
}

Function Write-JsonAsync {
    [CmdletBinding()]
    [OutputType([System.Object])]
    Param (       
        [Parameter(
            Position = 0,
            Mandatory = $True
        )]
        [ValidateNotNullOrEmpty()]
        [System.Object] $InputObject,

        [Parameter(
            Position = 1,
            Mandatory = $True
        )]
        [ValidateNotNullOrEmpty()]
        [String] $WriteToFolderPath,

        [Parameter(
            Position = 2,
            Mandatory = $True
        )]
        [ValidateNotNullOrEmpty()]
        [String] $WriteToFileName
    )

    If ($PSBoundParameters['Verbose']) {
        $VerbosePreference = "Continue"
    }
    If ($PSBoundParameters['Debug']) {
        $DebugPreference = "Continue"
        $ConfirmPreference = "None"
    }

    #region Script Block
    $ScriptBlock = {
        [CmdletBinding()]
        Param (       
            [Parameter(
                Position = 0,
                Mandatory = $True
            )]
            [ValidateNotNullOrEmpty()]
            [System.Object] $InputObject,

            [Parameter(
                Position = 1,
                Mandatory = $True
            )]
            [ValidateNotNullOrEmpty()]
            [String] $WriteToFolderPath,

            [Parameter(
                Position = 2,
                Mandatory = $True
            )]
            [ValidateNotNullOrEmpty()]
            [String] $WriteToFileName
        )

        If ($PSBoundParameters['Verbose']) {
            $VerbosePreference = "Continue"
        }
        If ($PSBoundParameters['Debug']) {
            $DebugPreference = "Continue"
            $ConfirmPreference = "None"
        }

        Try {
            If (!(Test-Path -Path $WriteToFolderPath)) {
                Write-Verbose -Message "[$((Get-Date).ToString())] [Write-Json] Path $WriteToFolderPath doesn't exist! Creating a directory now..."
                New-Item -Path $WriteToFolderPath -ItemType Directory -Force -ErrorAction Stop | Out-Null
            }
            Write-Verbose -Message "[$((Get-Date).ToString())] [Write-Json] Verified path [$WriteToFolderPath]"
            Write-Verbose -Message "[$((Get-Date).ToString())] [Write-Json] [ConvertTo-Json] Converting the given input object to JSON format..."
            $Json = ConvertTo-Json -InputObject $InputObject -Compress
            Write-Verbose -Message "[$((Get-Date).ToString())] [Write-Json] [Out-File] Writing JSON content to file..."
            Out-File -InputObject $Json -FilePath "$WriteToFolderPath\$WriteToFileName.JSON" -Force -ErrorAction Stop
        }
        Catch {
            Write-Error -Exception $_.Exception -Message $_.Exception.Message -ErrorAction Stop
        }
    }
    #endregion

    Try {
        Write-Verbose -Message "[$((Get-Date).ToString())] [Write-JsonAsync] Invoking a background job..."
        $Job = Start-Job -Name $([GUID]::NewGuid().Guid) -ScriptBlock $ScriptBlock -ArgumentList $InputObject, $WriteToFolderPath, $WriteToFileName
        Write-Verbose -Message "[$((Get-Date).ToString())] [Write-JsonAsync] A background job [Name: $($Job.Name)] [Id: $($Job.Id)] has been created successfully."
        Write-Output -InputObject $Job
    }
    Catch {
        Write-Error -Exception $_.Exception -Message $_.Exception.Message -ErrorAction Stop
    }
}

Function BackUp-EventLog {
    [CmdletBinding(SupportsShouldProcess = $True, ConfirmImpact = "Low")]
    Param (
        [Parameter(
            Position = 0,
            Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True)]
        [ValidateNotNullOrEmpty()]
        [Alias("ComputerName")]
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
            HelpMessage = "Gets only the specified items. Wildcards are permitted."
        )]
        [ValidateNotNullOrEmpty()]
        [String[]] $Include,

        [Parameter(
            Position = 3,
            Mandatory = $False,
            HelpMessage = "Omits the specified items. Wildcards are permitted."
        )]
        [ValidateNotNullOrEmpty()]
        [String[]] $Exclude,

        [Parameter(
            Position = 4,
            Mandatory = $False
        )]
        [ValidateNotNullOrEmpty()]
        [Switch] $Compress,

        [Parameter(
            Position = 5,
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
    }

    Process {
        Try {
            $RootActivityId = $(Get-Date -Format "yyyymmss")
            $ActiveStepId = 0
            $SystemDrive = Invoke-Command -ComputerName $Server -ScriptBlock {$env:SystemDrive.TrimEnd(':')}
            $SourceDirectory = "\\$Server\$SystemDrive$\Windows\System32\Winevt\Logs\"
            $DestinationDirectory = New-Item -Path $Destination -Name $Server -ItemType Directory -Force -ErrorAction Stop
            Write-Verbose -Message "[$((Get-Date).ToString())] [BackUp-EventLog] [Server: $Server]"
            Write-Verbose -Message "[$((Get-Date).ToString())] [BackUp-EventLog] [Source Directory: $SourceDirectory]"
            Write-Verbose -Message "[$((Get-Date).ToString())] [BackUp-EventLog] [Destination: $Destination]"
            Write-Verbose -Message "[$((Get-Date).ToString())] [BackUp-EventLog] [Destination Directory: $DestinationDirectory]"
            Write-Verbose -Message "[$((Get-Date).ToString())] [BackUp-EventLog] [Get-ChildItem] Identifying no. of log files..."
            $LogFiles = Get-ChildItem -Path $SourceDirectory -Filter "*.evtx" -Recurse -Include $Include -Exclude $Exclude -Force -ErrorAction Stop
            Write-Verbose -Message "[$((Get-Date).ToString())] [BackUp-EventLog] Identified $($LogFiles.Count) log files."

            $I = 0
            ForEach ($LogFile in $LogFiles) {
                $I++
                $ActiveStepId++
                If ($PSBoundParameters['ParentActivityId']) {
                    Write-Progress -Activity "Backup Event Logs.." -Status "Processing Server $($Server): Log File $ActiveStepId of $($LogFiles.Count)" -Id $RootActivityId -ParentId $ParentActivityId -PercentComplete (($ActiveStepId / $($LogFiles.Count))*100) -CurrentOperation "Copying Log File.."
                }
                Else {
                    Write-Progress -Activity "Backup Event Logs.." -Status "Processing Server $($Server): Log File $ActiveStepId of $($LogFiles.Count)" -Id $RootActivityId -PercentComplete (($ActiveStepId / $($LogFiles.Count))*100) -CurrentOperation "Copying Log File.."
                }
                
                Try {
                    If ($PSCmdlet.ShouldProcess("$($LogFile.BaseName)", "Copy-Item")) {
                        Write-Verbose -Message "[$((Get-Date).ToString())] [BackUp-EventLog] [Copy-Item] Copying log file [Server: $Server] [Name: $($LogFile.BaseName)] [Path: $($LogFile.FullName)] ($I of $($LogFiles.Count))..."
                        Copy-Item -Path $LogFile.FullName -Destination $DestinationDirectory -Recurse -Force -ErrorAction Stop
                    }
                }
                Catch {
                    Write-Error -Exception $_.Exception -Message $_.Exception.Message
                }

                If ($PSBoundParameters['ParentActivityId']) {
                    Write-Progress -Activity "Backup Event Logs.." -Status "Processing Server $($Server): Log File $ActiveStepId of $($LogFiles.Count)" -Id $RootActivityId -ParentId $ParentActivityId -PercentComplete (($ActiveStepId / $($LogFiles.Count))*100) -CurrentOperation "Copying Log File.." -Completed
                }
                Else {
                    Write-Progress -Activity "Backup Event Logs.." -Status "Processing Server $($Server): Log File $ActiveStepId of $($LogFiles.Count)" -Id $RootActivityId -PercentComplete (($ActiveStepId / $($LogFiles.Count))*100) -CurrentOperation "Copying Log File.." -Completed
                }
            }

            If ($PSBoundParameters['Compress']) {
                If ($PSBoundParameters['ParentActivityId']) {
                    Write-Progress -Activity "Backup Event Logs.." -Status "Processing Server $($Server)" -Id $RootActivityId -ParentId $ParentActivityId -PercentComplete 100 -CurrentOperation "Compressing Log Files.."
                }
                Else {
                    Write-Progress -Activity "Backup Event Logs.." -Status "Processing Server $($Server)" -Id $RootActivityId -PercentComplete 100 -CurrentOperation "Compressing Log Files.."
                }
                
                $DestinationArchiveFilePath = Join-Path -Path $(Split-Path -Path $DestinationDirectory) -ChildPath "$(Split-Path -Path $DestinationDirectory -Leaf).zip"
                New-Archive -Path $DestinationDirectory -ArchivePath $DestinationArchiveFilePath -CompressionLevel Optimal
                If (Test-Path -Path $DestinationArchiveFilePath) {
                    Write-Verbose -Message "[$((Get-Date).ToString())] [BackUp-EventLog] [Remove-Item] Removing the previously copied raw event log files [$DestinationDirectory]..."
                    Remove-Item -Path $DestinationDirectory -Recurse -Force
                }
                
                If ($PSBoundParameters['ParentActivityId']) {
                    Write-Progress -Activity "Backup Event Logs.." -Status "Processing Server $($Server)" -Id $RootActivityId -ParentId $ParentActivityId -PercentComplete 100 -CurrentOperation "Compressing Log Files.." -Completed
                }
                Else {
                    Write-Progress -Activity "Backup Event Logs.." -Status "Processing Server $($Server)" -Id $RootActivityId -PercentComplete 100 -CurrentOperation "Compressing Log Files.." -Completed
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

Function Get-MemoryDump {
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
            Mandatory = $False
        )]
        [ValidateNotNullOrEmpty()]
        [Switch] $Compress,

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
    }

    Process {
        Try {
            $RootActivityId = $(Get-Date -Format "yyyymmss")
            $ActiveStepId = 0
            $SystemDrive = Invoke-Command -ComputerName $Server -ScriptBlock {$env:SystemDrive.TrimEnd(':')}
            $SourceDirectory = "\\$Server\$SystemDrive$\Windows\"
            $DestinationDirectory = New-Item -Path $Destination -Name $Server -ItemType Directory -Force -ErrorAction Stop
            Write-Verbose -Message "[$((Get-Date).ToString())] [Get-MemoryDump] [Server: $Server]"
            Write-Verbose -Message "[$((Get-Date).ToString())] [Get-MemoryDump] [Source Directory: $SourceDirectory]"
            Write-Verbose -Message "[$((Get-Date).ToString())] [Get-MemoryDump] [Destination: $Destination]"
            Write-Verbose -Message "[$((Get-Date).ToString())] [Get-MemoryDump] [Destination Directory: $DestinationDirectory]"
            Write-Verbose -Message "[$((Get-Date).ToString())] [Get-MemoryDump] [Get-ChildItem] Identifying no. of memory dump files..."
            [Array] $MemoryDumpFiles = Get-Item -Path $(Join-Path -Path $SourceDirectory -ChildPath "MEMORY.DMP") -ErrorAction SilentlyContinue
            $Path_ = $(Join-Path -Path $SourceDirectory -ChildPath "Minidump")
            If (Test-Path -Path $Path_) {
                [Array] $MemoryDumpFiles += Get-ChildItem -Path $Path_ -Filter "*.dmp" -Recurse -Force -ErrorAction SilentlyContinue
            }
            $Path_ = $(Join-Path -Path $SourceDirectory -ChildPath "LiveKernelReports")
            If (Test-Path -Path $Path_) {
                [Array] $MemoryDumpFiles += Get-ChildItem -Path $Path_ -Filter "*.dmp" -Recurse -Force -ErrorAction SilentlyContinue
            }
            Write-Verbose -Message "[$((Get-Date).ToString())] [Get-MemoryDump] Identified $($MemoryDumpFiles.Count) memory dump files."

            $I = 0
            ForEach ($MemoryDumpFile in $MemoryDumpFiles) {
                $I++
                $ActiveStepId++
                If ($PSBoundParameters['ParentActivityId']) {
                    Write-Progress -Activity "Backup Memory Dumps.." -Status "Processing Server $($Server): Memory Dump File ($($MemoryDumpFile.Name) - $([Math]::Truncate(($MemoryDumpFile.Length) / 1MB)) MB) $ActiveStepId of $($MemoryDumpFiles.Count)" -Id $RootActivityId -ParentId $ParentActivityId -PercentComplete (($ActiveStepId / $($MemoryDumpFiles.Count))*100) -CurrentOperation "Copying Memory Dump File.."
                }
                Else {
                    Write-Progress -Activity "Backup Memory Dumps.." -Status "Processing Server $($Server): Memory Dump File ($($MemoryDumpFile.Name) - $([Math]::Truncate(($MemoryDumpFile.Length) / 1MB)) MB) $ActiveStepId of $($MemoryDumpFiles.Count)" -Id $RootActivityId -PercentComplete (($ActiveStepId / $($MemoryDumpFiles.Count))*100) -CurrentOperation "Copying Memory Dump File.."
                }
                Try {
                    Clear-Variable -Name MemoryDumpFileSizeGB -Force -ErrorAction SilentlyContinue
                    Clear-Variable -Name LocalFreeDiskSpaceGB -Force -ErrorAction SilentlyContinue
                    Clear-Variable -Name SizeDiff -Force -ErrorAction SilentlyContinue
                    $MemoryDumpFileSizeGB = $([Math]::Truncate(($MemoryDumpFile.Length) / 1GB))
                    $LocalFreeDiskSpaceGB = Get-CimInstance -ClassName Win32_LogicalDisk | Where-Object {$_.DeviceID -eq $env:SystemDrive} | Select-Object @{Name="FreeSpaceGB";Expression={[Math]::Truncate($_.FreeSpace / 1GB)}} | ForEach-Object {$_.FreeSpaceGB}
                    $SizeDiff = $LocalFreeDiskSpaceGB - $MemoryDumpFileSizeGB
                    If (($SizeDiff -le $MemoryDumpFileSizeGB) -or ($SizeDiff -le 2)) {
                        Write-Warning -Message "[$((Get-Date).ToString())] [Get-MemoryDump] There is insufficient disk space ($LocalFreeDiskSpaceGB GB available on local disk) to complete operation!"
                        Write-Warning -Message "[$((Get-Date).ToString())] [Get-MemoryDump] Skipped copying of memory dump file [Server: $Server] [Name: $($MemoryDumpFile.Name)] [Size: $([Math]::Truncate(($MemoryDumpFile.Length) / 1MB)) MB] [Path: $($MemoryDumpFile.FullName)] ($I of $($MemoryDumpFiles.Count))."
                        Continue
                    }
                    Write-Verbose -Message "[$((Get-Date).ToString())] [Get-MemoryDump] [Copy-Item] Copying memory dump file [Server: $Server] [Name: $($MemoryDumpFile.Name)] [Size: $([Math]::Truncate(($MemoryDumpFile.Length) / 1MB)) MB] [Path: $($MemoryDumpFile.FullName)] ($I of $($MemoryDumpFiles.Count))..."
                    If ($PSCmdlet.ShouldProcess("$($MemoryDumpFile.BaseName)", "Copy-Item")){
                        $DestinationFilePath = $(Join-Path -Path $DestinationDirectory -ChildPath $($MemoryDumpFile.Name))
                        $DestinationArchiveFilePath = Join-Path -Path $(Split-Path -Path $DestinationFilePath) -ChildPath "$($MemoryDumpFile.BaseName).zip"
                        Copy-Item -Path $MemoryDumpFile.FullName -Destination $DestinationDirectory -Recurse -Force -ErrorAction Stop
                        If (Test-Path -Path $DestinationFilePath) {
                            Write-Verbose -Message "[$((Get-Date).ToString())] [Get-MemoryDump] Verification of new archive file is successful."
                            If ($PSBoundParameters['Compress']) {
                                If ($PSBoundParameters['ParentActivityId']) {
                                    Write-Progress -Activity "Backup Memory Dumps.." -Status "Processing Server $($Server): Memory Dump File ($($MemoryDumpFile.Name) - $([Math]::Truncate(($MemoryDumpFile.Length) / 1MB)) MB) $ActiveStepId of $($MemoryDumpFiles.Count)" -Id $RootActivityId -ParentId $ParentActivityId -PercentComplete (($ActiveStepId / $($MemoryDumpFiles.Count))*100) -CurrentOperation "Compressing Memory Dump File.."
                                }
                                Else {
                                    Write-Progress -Activity "Backup Memory Dumps.." -Status "Processing Server $($Server): Memory Dump File ($($MemoryDumpFile.Name) - $([Math]::Truncate(($MemoryDumpFile.Length) / 1MB)) MB) $ActiveStepId of $($MemoryDumpFiles.Count)" -Id $RootActivityId -PercentComplete (($ActiveStepId / $($MemoryDumpFiles.Count))*100) -CurrentOperation "Compressing Memory Dump File.."
                                }
                                New-Archive -Path $DestinationFilePath -ArchivePath $DestinationArchiveFilePath -CompressionLevel Optimal
                                If (Test-Path -Path $DestinationArchiveFilePath) {
                                    Write-Verbose -Message "[$((Get-Date).ToString())] [Get-MemoryDump] [Remove-Item] Removing the previously copied raw memory dump file [$DestinationFilePath]..."
                                    Remove-Item -Path $DestinationFilePath -Force
                                }
                            }
                        }
                        Else {
                            Write-Warning -Message "[$((Get-Date).ToString())] [Get-MemoryDump] Verification of new archive file is unsuccessful!"
                        }
                    }
                }
                Catch {
                    Write-Error -Exception $_.Exception -Message $_.Exception.Message
                }
            }
            If ($PSBoundParameters['ParentActivityId']) {
                If ($MemoryDumpFiles.Count -gt 0) {
                    Write-Progress -Activity "Backup Memory Dumps.." -Status "Processing Server $($Server): Memory Dump File $ActiveStepId of $($MemoryDumpFiles.Count)" -Id $RootActivityId -ParentId $ParentActivityId -PercentComplete (($ActiveStepId / $($MemoryDumpFiles.Count))*100) -CurrentOperation "Copying Memory Dump File.." -Completed
                }
                Else {
                    Write-Progress -Activity "Backup Memory Dumps.." -Status "Processing Server $($Server)" -Id $RootActivityId -ParentId $ParentActivityId -PercentComplete 100 -CurrentOperation "Copying Memory Dump File.." -Completed
                }
            }
            Else {
                If ($MemoryDumpFiles.Count -gt 0) {
                    Write-Progress -Activity "Backup Memory Dumps.." -Status "Processing Server $($Server): Memory Dump File $ActiveStepId of $($MemoryDumpFiles.Count)" -Id $RootActivityId -PercentComplete (($ActiveStepId / $($MemoryDumpFiles.Count))*100) -CurrentOperation "Copying Memory Dump File.." -Completed
                }
                Else {
                    Write-Progress -Activity "Backup Memory Dumps.." -Status "Processing Server $($Server)" -Id $RootActivityId -PercentComplete 100 -CurrentOperation "Copying Memory Dump File.." -Completed
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

Function New-Archive {
    [CmdletBinding(SupportsShouldProcess = $True, ConfirmImpact = "Low")]
    Param (
        [Parameter(
            Position = 0,
            Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [String] $Path,

        [Parameter(
            Position = 1,
            Mandatory = $True
        )]
        [ValidateNotNullOrEmpty()]
        [String] $ArchivePath,

        [Parameter(
            Position = 2,
            Mandatory = $False
        )]
        [ValidateNotNullOrEmpty()]
        [System.IO.Compression.CompressionLevel] $CompressionLevel =  [System.IO.Compression.CompressionLevel]::Optimal
    )

    Begin {
        If ($PSBoundParameters['Verbose']) {
            $VerbosePreference = "Continue"
        }
        If ($PSBoundParameters['Debug']) {
            $DebugPreference = "Continue"
            $ConfirmPreference = "None"
        }

        [Reflection.Assembly]::LoadWithPartialName("System.IO.Compression.FileSystem") | Out-Null
    }

    Process {
        Try {
            If (!(Test-Path -Path $ArchivePath)) {
                New-Item -Path $(Split-Path -Path $ArchivePath) -ItemType Directory -Force | Out-Null
            }
            # If the given source is a directory
            If ((Get-Item -Path $Path) -is [System.IO.DirectoryInfo]) {
                Write-Verbose -Message "[$((Get-Date).ToString())] [New-Archive] Identified the given source path as a directory."
                Write-Verbose -Message "[$((Get-Date).ToString())] [New-Archive] Creating a new archive file [Source: $Path] [Destination: $ArchivePath]..."
                If ($PSCmdlet.ShouldProcess("$Path", "[System.IO.Compression.ZipFile]::CreateFromDirectory")){
                    If (Test-Path -Path $ArchivePath) {
                        Write-Verbose -Message "[$((Get-Date).ToString())] [New-Archive] [Remove-Item] Removing an existing archive file..."
                        Remove-Item -Path $ArchivePath -Force
                    }
                    [System.IO.Compression.ZipFile]::CreateFromDirectory($Path, $ArchivePath, $CompressionLevel, $False) | Out-Null
                }
            }
            # If the given source is a file
            Else {
                Write-Verbose -Message "[$((Get-Date).ToString())] [New-Archive] Identified the given source path as a file."
                $ZipEntry = $Path | Split-Path -Leaf
                Write-Verbose -Message "[$((Get-Date).ToString())] [New-Archive] Creating a new archive file [Source: $Path] [Destination: $ArchivePath]..."
                If ($PSCmdlet.ShouldProcess("$Path", "[System.IO.Compression.ZipFileExtensions]::CreateEntryFromFile")){
                    $ZipFile = [System.IO.Compression.ZipFile]::Open($ArchivePath, 'Update')
                    [System.IO.Compression.ZipFileExtensions]::CreateEntryFromFile($ZipFile, $Path, $ZipEntry, $CompressionLevel) | Out-Null
                }
            }
            If (Test-Path -Path $ArchivePath) {
                Write-Verbose -Message "[$((Get-Date).ToString())] [New-Archive] Verification of new archive file is successful."
            }
            Else {
                Write-Warning -Message "[$((Get-Date).ToString())] [New-Archive] Verification of new archive file is unsuccessful!"
            }
        }
        Catch {
            Write-Error -Exception $_.Exception -Message $_.Exception.Message
        }
    }

    End {
        If (!((Get-Item -Path $Path) -is [System.IO.DirectoryInfo])) {
            $ZipFile.Dispose()
        }
        [System.GC]::Collect()
    }
}

Function Get-ItemCountInArray {
    [CmdletBinding()]
    [OutputType([System.Int32])]
    Param (
        [System.Object] $InputObject
    )

    If ($Null -eq $InputObject) {
        Return 0
    }
    Else {
        If ($InputObject.GetType().BaseType.Name -eq "Array") {
            Return ($InputObject).Count
        }
        Else {
            Return 1
        }
    }
}

Function New-Uri {
    [CmdletBinding(SupportsShouldProcess = $True, ConfirmImpact = "Low")]
    Param (
        [String] $BaseUri,
        [String] $Path = $Null
    )
	
    Begin {
		If ($PSBoundParameters['Verbose']) {
			$VerbosePreference = "Continue"
		}
		If ($PSBoundParameters['Debug']) {
			$DebugPreference = "Continue"
			$ConfirmPreference = "None"
		}

        Write-Verbose -Message "[$((Get-Date).ToString())] [New-Uri] [Base Uri: $BaseUri] [Path: $Path]"
	}

	Process {
        Try {
            If ($PSCmdlet.ShouldProcess("$BaseUri", "Initializing a new instance of the UriBuilder class with the specified Uri...")){
                $UriBuilder = New-Object System.UriBuilder($BaseUri)
                $UriBuilder.Path = $Path
                Write-Verbose -Message "[$((Get-Date).ToString())] [New-Uri] Uri: $($UriBuilder.Uri)"
                Write-Output -InputObject $($UriBuilder.Uri)
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