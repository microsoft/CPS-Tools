################################################################
# Module Name: Apps.Utility.PowerShell.RunSpace.psm1
# Module Description: Utility Module - Holds RunSpace supported functions
# Author: Srinath Sadda
################################################################

<#
    .SYNOPSIS
        PowerShell RunSpace module.
    .DESCRIPTION
        PowerShell RunSpace module.
    .EXAMPLE
        Import-Module -Name .\Apps.Utility.PowerShell.RunSpace.psm1
    .NOTES
        Module Name: Apps.Utility.PowerShell.RunSpace.psm1
        Module Description: PowerShell RunSpace module.
        Author: Srinath Sadda
#>

# Adds a Microsoft .NET Framework type (a class) to a Windows PowerShell session
# Initialize a custom powershell class 'AsyncPipeline'
If (!('AsyncPipeline' -as [Type])) {
    Add-Type @'
        public class AsyncPipeline {
            public System.Management.Automation.PowerShell Pipeline;
            public System.IAsyncResult AsyncResult;
        }
'@
}

Function Invoke-Async {
    <#
        .SYNOPSIS
            Create a PowerShell pipeline and executes a script block asynchronously.
        .DESCRIPTION
            Create a PowerShell pipeline and executes a script block asynchronously.
        .PARAMETER RunspacePool
            Specify a pool of one or more runspaces, typically created using 'New-RunspacePool' Cmdlet.
            A runspace pool is a collection of runspaces upon which PowerShell pipelines can be executed.
        .PARAMETER ScriptBlock
            Represents a precompiled block of script text that can be used as a single unit.
            A script block is an instance of a Microsoft .NET Framework type (System.Management.Automation.ScriptBlock)
        .PARAMETER Arguments
            A script block can accept arguments and return values.
            The 'Arguments' parameter supplies the values of the variables, in the order that they are listed.
        .EXAMPLE
            $ScriptBlock = {
                Param (
                    $Computer,
                    $Service
                )
                Get-Service -Name $Service -ComputerName $Computer
            }
            Invoke-Async -RunspacePool $(New-RunSpacePool -MaxThreads 10) -ScriptBlock $ScriptBlock -Arguments $Computer,$Service
        .EXAMPLE
            $ScriptBlock = {
                Param (
                    $Computer,
                    $Service
                )
                Get-Service -Name $Service -ComputerName $Computer
            }
            $SyncObject = [HashTable]::Synchronized(@{})
            Invoke-Async -RunspacePool $(New-RunSpacePool -MaxThreads 10 -SyncObject $SyncObject) -ScriptBlock $ScriptBlock -Arguments $Computer,$Service
    #>

    [CmdletBinding()]
    Param (
        [Parameter(
            Position=0,
            Mandatory=$True,
            HelpMessage="Specify a pool of one or more runspaces, typically created using 'New-RunspacePool' Cmdlet:"
        )]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({
            If ($_ -is [System.Management.Automation.Runspaces.RunspacePool]) {
                $True
            }
            Else {
                Throw "OOPS! YOU SPECIFIED AN INCORRECT OBJECT TYPE! THE EXPECTED TYPE IS: [RunspacePool]"
            }
        })]
        [System.Management.Automation.Runspaces.RunspacePool] $RunspacePool,
        
        [Parameter(
            Position=1,
            Mandatory=$True,
            HelpMessage="Represents a precompiled block of script text that can be used as a single unit:"
        )]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({
            If ($_ -is [System.Management.Automation.ScriptBlock]) {
                $True
            }
            Else {
                Throw "OOPS! YOU SPECIFIED AN INCORRECT OBJECT TYPE! THE EXPECTED TYPE IS: [ScriptBlock]"
            }
        })]
        [System.Management.Automation.ScriptBlock] $ScriptBlock,
        
        [Parameter(
            Position=2,
            Mandatory=$False,
            HelpMessage="A script block can accept arguments and return values. The 'Arguments' parameter supplies the values of the variables, in the order that they are listed:"
        )]
        [ValidateNotNullOrEmpty()]
        [Object[]] $Arguments
    )

    If ($PSBoundParameters['Verbose']) {
        $VerbosePreference = "Continue"
    }
    If ($PSBoundParameters['Debug']) {
        $DebugPreference = "Continue"
        $ConfirmPreference = "None"
    }

    Try {
        # Initializes a new instance of the PowerShell class with an empty pipeline.
        $Pipeline = [System.Management.Automation.PowerShell]::Create()

        # Sets the runspace pool used by the PowerShell object.
        # A runspace from this pool is used whenever the PowerShell object pipeline is invoked.
        $Pipeline.RunspacePool = $RunspacePool

        If ($PSBoundParameters['Verbose'] -or $PSBoundParameters['Debug']) {
            $VerboseScriptBlock = {
                $VerbosePreference = 'Continue'
            }
            $DebugScriptBlock = {
                $DebugPreference = "Continue"
                $ConfirmPreference = "None"
            }
            
            If ($PSBoundParameters['Verbose']) { 
                $Pipeline.AddScript($VerboseScriptBlock) | Out-Null
            }
            If ($PSBoundParameters['Debug']) {
                $Pipeline.AddScript($DebugScriptBlock) | Out-Null
            }

            $Pipeline.Invoke()
            $Pipeline.Commands.Clear()
        }
        
        # NOTE: Out-Null - Deletes output instead of sending it down the pipeline.
        # Adds a script to the end of the pipeline of the PowerShell object.
        $Pipeline.AddScript($ScriptBlock) | Out-Null
        
        Foreach($Arg in $Arguments) {
            # NOTE: Out-Null - Deletes output instead of sending it down the pipeline.
            # Adds an argument for a positional parameter of a command without specifying the parameter name.
            If ($Arg -is [Object[]]) {
                Foreach($Arg_ in $Arg) {
                    $Pipeline.AddArgument($Arg_) | Out-Null
                }
            }
            Else {
                $Pipeline.AddArgument($Arg) | Out-Null
            }
        }

        # Asynchronously runs the commands of the PowerShell object pipeline.
        $AsyncResult = $Pipeline.BeginInvoke()

        # Creates a AsyncPipeline object.
        $Status = New-Object AsyncPipeline -ErrorAction Stop -ErrorVariable AsyncPipeline_

        If (!$AsyncPipeline_) {
            $Status.Pipeline = $Pipeline
            $Status.AsyncResult = $AsyncResult
        
            If ($Status) {
                # Returns the status of AsyncPipeline.
                Write-Output -InputObject $Status
            }
        }
    }
    Catch {
        # Capture an exception.
        Write-Error -Exception $_.Exception -Message $_.Exception.Message
    }
}

Function New-RunSpacePool {
    <#
        .SYNOPSIS
            Creates a runspace pool.
        .DESCRIPTION
            Creates a pool of runspaces that specifies the minimum and maximum number of opened runspaces for the pool.
        .PARAMETER MaxThreads
            Defines the maximum number of pipelines that can be concurrently (asynchronously) executed on the pool.
            The number of available pools determined the maximum number of processes that can be running concurrently.
			Minimum is 1. Maximum is 8.
        .PARAMETER SyncObject
            A synchronized HashTable which will be make available to entire runspace pool.
            $SyncObject = [HashTable]::Synchronized(@{})
        .PARAMETER MTA
            Create runspaces in a multi-threaded apartment. It is not recommended to use this option unless absolutely necessary.
        .EXAMPLE
            Creates a pool of 4 runspaces.
            $RunSpacePool = New-RunSpacePool -MaxThreads 4
        .EXAMPLE
            Creates a pool of 4 runspaces with synchronized object (HashTable)
            $SyncObject = [HashTable]::Synchronized(@{})
            $RunSpacePool = New-RunSpacePool -MaxThreads 4 -SyncObject $SyncObject
    #>

    [CmdletBinding(
        SupportsShouldProcess = $True,
        ConfirmImpact = "Low"
    )]
    Param (
        [Parameter(
            Position=0,
            Mandatory=$True,
            HelpMessage="Specify maximum no. of threads. Maximum is 8 threads:"
        )]
        [ValidateNotNullOrEmpty()]
        [ValidateRange(1,8)]
        [Int16] $MaxThreads,

        [Parameter(
            Position=1,
            Mandatory=$False
        )]
        [HashTable] $SyncObject = [HashTable]::Synchronized(@{}),

        [Parameter(
            Position=2,
            Mandatory=$False,
            HelpMessage="Specify this switch to create runspaces in a multi-threaded apartment:"
        )]
        [Switch] $MTA
    )

    Try {
        If ($PSCmdlet.ShouldProcess($MaxThreads)) {
            If ($PSBoundParameters['Verbose']) {
                $VerbosePreference = "Continue"
            }
            If ($PSBoundParameters['Debug']) {
                $DebugPreference = "Continue"
                $ConfirmPreference = "None"
            }
            
            $SessionState = [System.Management.Automation.RunSpaces.InitialSessionState]::CreateDefault()
            If ($PSBoundParameters['SyncObject']) { 
                $SessionState.Variables.Add((New-Object System.Management.Automation.Runspaces.SessionStateVariableEntry("SyncObject", $SyncObject, $Null)))
            }
            
            # Add Functions from current runspace to the InitialSessionState
            ForEach ($Function in (Get-ChildItem Function: | Where-Object {@("Apps.Utility.PowerShell", "Apps.CPS.PowerShell") -contains $_.ModuleName})) {
                Write-Debug "[$((Get-Date).ToString())] [New-RunSpacePool] Adding function $($Function.Name) to InitialSessionState..."
                $SessionState.Commands.Add((New-Object -TypeName System.Management.Automation.Runspaces.SessionStateFunctionEntry -ArgumentList $Function.Name, $Function.Definition))
            }

            <#
            # Add Modules from current runspace to the InitialSessionState
            # For now we're loading two specific modules only!
            ForEach ($ModulePath in (Get-Module | Where-Object {@("Apps.Utility.PowerShell", "Apps.CPS.PowerShell") -contains $_.Name} | Select-Object -ExpandProperty ModuleBase)) {
                Write-Debug "[$((Get-Date).ToString())] [New-RunSpacePool] Adding module $($ModulePath) to InitialSessionState..."
                $SessionState.ImportPSModulesFromPath($ModulePath)
            }

            # Add Snapins from current runspace to the InitialSessionState
            ForEach($SnapinName in (Get-PSSnapin | Select-Object -ExpandProperty Name)) {
                # Skip Snapin 'Microsoft.PowerShell.Core' (it's loaded by default)
                If (!($SnapinName -eq 'Microsoft.PowerShell.Core')) {
                    $PSSnapInException = $Null
                    Write-Debug "[$((Get-Date).ToString())] [New-RunSpacePool] Adding PSSnapin $($SnapinName) to InitialSessionState..."
                    $SessionState.ImportPSSnapIn($SnapinName, [Ref] $PSSnapInException)
                    If ($PSSnapInException) {
                        Write-Warning -Message "[$((Get-Date).ToString())] [New-RunSpacePool] An exception has occurred while adding PSSnapin $($SnapinName) to InitialSessionState!"
                        Write-Error -Exception $PSSnapInException
                    }
                }
            }
            #>

            # Creates a pool of runspaces that specifies the minimum and maximum number of opened runspaces for the pool.
            $RunSpacePool = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspacePool(1, $MaxThreads, $SessionState, $Host)
        
            # NOTE: Runspace.ApartmentState property must be set before the runspace is opened.
            # Specify the apartment state of the thread used to run commands in the runspace.
        
            If ($MTA) {
                # The thread will create and enter a multi-threaded apartment.
                $RunSpacePool.ApartmentState = 'MTA'
            }
            Else {
                # The thread will create and enter a single-threaded apartment.
                $RunSpacePool.ApartmentState = 'STA'
            }

            # Open runspaces.
            $RunSpacePool.Open()
        
            # Returns a pool of runspaces.
            Write-Output -InputObject $RunSpacePool
        }
    }
    Catch {
        # Capture an exception.
        Write-Error -Exception $_.Exception -Message $_.Exception.Message
    }
}

Function Get-AsyncInfo {
    <#
        .SYNOPSIS
            Receives the results of an asynchronous pipeline.
        .DESCRIPTION
            Receives the results of an asynchronous pipeline running in a separate runspace.
        .PARAMETER Pipeline
            An AsyncPipleine object, typically returned by 'Invoke-Async' Cmdlet.
        .EXAMPLE
            $ScriptBlock = {
                Param (
                    $Computer,
                    $Service
                )
                Get-Service -Name $Service -ComputerName $Computer
            }
            $AsyncPipelines = Invoke-Async -RunspacePool $(New-RunSpacePool 10) -ScriptBlock $ScriptBlock -Arguments $Computer,$Service
            
            ForEach ($AsyncPipeline in $AsyncPipelines) {
                Get-AsyncInfo -Pipeline $AsyncPipeline
            }
        .NOTES
            Since it is unknown what exists in the results stream of the pipeline, this function will not have a standard return type.
    #>

    [CmdletBinding()]
    Param (
        [Parameter(Position=0,Mandatory=$True,HelpMessage="Specify an AsyncPipleine object, typically returned by Invoke-Async cmdlet:")]
        [ValidateNotNullOrEmpty()]
        [AsyncPipeline] $Pipeline
    )

    If ($PSBoundParameters['Verbose']) {
        $VerbosePreference = "Continue"
    }
    If ($PSBoundParameters['Debug']) {
        $DebugPreference = "Continue"
        $ConfirmPreference = "None"
    }

    Try {
        # Pipeline.EndInvoke - Waits for the pending asynchronous BeginInvoke call to be completed and then returns the results of the call.
        # AsyncResult - The IAsyncResult interface returned by the BeginInvoke call. This interface represents the status of the call.

        # If Pipeline is completed:
        If ($Pipeline.AsyncResult.IsCompleted) {
            # Get the results from the IAsyncResult object.
            Write-Output -InputObject $($Pipeline.Pipeline.EndInvoke($Pipeline.AsyncResult))
        }

        # Capture streams.
        ForEach ($ErrorStream in $Pipeline.Pipeline.Streams.Error.ReadAll()) { Write-Error -ErrorRecord $ErrorStream }
        ForEach ($WarningStream in $Pipeline.Pipeline.Streams.Warning.ReadAll()) { Write-Warning -Message $WarningStream }
        ForEach ($VerboseStream in $Pipeline.Pipeline.Streams.Verbose.ReadAll()) { Write-Verbose -Message $VerboseStream }
        ForEach ($DebugStream in $Pipeline.Pipeline.Streams.Debug.ReadAll()) { Write-Debug -Message $DebugStream }
    }
    Catch {
        # Capture an exception.
        Write-Error -Exception $_.Exception -Message $_.Exception.Message
    }
    Finally {
        # Note: We're proceeding with disposing of the Pipeline regardless of it's state...
        # Releases all resources used by the PowerShell object.
        $Pipeline.Pipeline.Dispose()
    }
}

Function Get-AsyncStatus {
    <#
        .SYNOPSIS
            Receives the status of one or more asynchronous pipelines.
        .DESCRIPTION
            Receives the status of one or more asynchronous pipelines.
        .PARAMETER Pipelines
            An array of AsyncPipleine objects, typically returned by 'Invoke-Async' Cmdlet.
        .EXAMPLE
            $ScriptBlock = {
                Param (
                    $Computer,
                    $Service
                )
                Get-Service -Name $Service -ComputerName $Computer
            }
            $AsyncPipelines = Invoke-Async -RunspacePool $(New-RunSpacePool 10) -ScriptBlock $ScriptBlock -Arguments $Computer,$Service

            $Status = Get-AsyncStatus -Pipelines $AsyncPipelines
        .EXAMPLE
            $ScriptBlock = {
                Param (
                    $Computer,
                    $Service
                )
                Get-Servie -Name $Service -ComputerName $Computer
            }
            
            $Status = Get-AsyncStatus -Pipelines $(Invoke-Async -RunspacePool $(New-RunSpacePool 10) -ScriptBlock $ScriptBlock -Arguments $Computer,$Service)
    #>

    [CmdletBinding()]
    Param (
        [Parameter(Position=0,Mandatory=$True,HelpMessage="Specify an array of AsyncPipleine objects, typically returned by Invoke-Async Cmdlet:")]
        [ValidateNotNullOrEmpty()]
        [AsyncPipeline[]] $AsyncPipelines
    )

    If ($PSBoundParameters['Verbose']) {
        $VerbosePreference = "Continue"
    }
    If ($PSBoundParameters['Debug']) {
        $DebugPreference = "Continue"
        $ConfirmPreference = "None"
    }

    Write-Verbose -Message "[$((Get-Date).ToString())] [Get-AsyncStatus] Identified $($AsyncPipelines.Count) async pipelines."
    ForEach ($AsyncPipeline in $AsyncPipelines) {
        Try {
            Write-Verbose -Message "[$((Get-Date).ToString())] [Get-AsyncStatus] Processing pipeline [$($AsyncPipeline.Pipeline.InstanceId.Guid)]..."
            New-Object -TypeName PSObject -Property @{
                'InstanceIdGuid' = $AsyncPipeline.Pipeline.InstanceId.Guid
                'State' = $AsyncPipeline.Pipeline.InvocationStateInfo.State
                'Reason' = $AsyncPipeline.Pipeline.InvocationStateInfo.Reason
                'IsCompleted' = $AsyncPipeline.AsyncResult.IsCompleted
                'AsyncState' = $AsyncPipeline.AsyncResult.AsyncState
                'Error' = $AsyncPipeline.Pipeline.Streams.Error
                'Warning' = $AsyncPipeline.Pipeline.Streams.Warning
                'Info' = $AsyncPipeline.Pipeline.Streams.Information
                'Verbose' = $AsyncPipeline.Pipeline.Streams.Verbose
                'Debug' = $AsyncPipeline.Pipeline.Streams.Debug
            }
        }
        Catch {
            # Capture an exception.
            Write-Verbose -Message "[$((Get-Date).ToString())] [Get-AsyncStatus] An exception has occurred while processing pipeline [$($AsyncPipeline.Pipeline.InstanceId.Guid)]!"
            Write-Error -Exception $_.Exception -Message $_.Exception.Message
        }
    }
}

Function Invoke-PSRunSpace {
    <#
        .SYNOPSIS
            Executes a set of parameterized script blocks asynchronously using runspaces and returns the resulting data.
        .DESCRIPTION
            Encapsulates generic logic for using Powershell background runspaces to execute parameterized script blocks in an efficient multi-threaded fashion.
        .PARAMETER InputObject
            List of PowerShell objects.
        .PARAMETER ScriptBlock
            Represents a precompiled block of script text that can be used as a single unit.
            ScriptBlock should contain one or more parameters.
            A script block is an instance of a Microsoft .NET Framework type (System.Management.Automation.ScriptBlock)
        .PARAMETER Arguments
            A script block can accept arguments and return values.
            The 'Arguments' parameter supplies the values of the variables, in the order that they are listed.
        .PARAMETER SyncObject
        .PARAMETER MaxThreads
            The maximum number of concurrent threads to use. The default value is equal to no. of specified servers. Maximum is 8.
        .PARAMETER TimeOut
        .PARAMETER ShowProgress
            An optional switch to display a progress bar that depicts the status of a running command.
        .PARAMETER SendInputObjectInstance
            An instance of the given input object will be make available to each runspace in runspace pool.
            When you specify this switch, make sure that your script block is written to accept the first parameter as an object instance!
            See examples for additional help.
        .PARAMETER ParentActivityId
            Display a progress bar. The parent Write-Progress activity of the current Write-Progress activity.
        .EXAMPLE
            Opens a separate runspace for each object specified in the $Objects variable and executes the ScriptBlock with the specified no. of Arguments.
            
            $VerbosePreference = "Continue"
            $Service = "Netlogon"
            $Computers = @('localhost','localhost','localhost','localhost')
            $ScriptBlock = {
                Param (
                    $Computer,
                    $Service
                )
                Write-Verbose -Message "Waiting for 5 seconds before execute code in ScriptBlock..."
                Start-Sleep -Seconds 5
                Get-Service -Name $Service -ComputerName $Computer
            }

            Invoke-PSRunSpace -InputObject $Computers -ScriptBlock $ScriptBlock -Arguments $Service -SendInputObjectInstance -Verbose -Debug
        .EXAMPLE
            Opens a separate runspace for each object specified in the $Objects variable and executes the ScriptBlock with the specified no. of Arguments and synchronized Hashtable.
            
            $VerbosePreference = "Continue"
            $SyncObject = [HashTable]::Synchronized(@{})
            $SyncObject.Counter = 0
            $Service = "Netlogon"
            $Computers = @('localhost','localhost','localhost','localhost')
            $ScriptBlock = {
                Param (
                    $Computer,
                    $Service
                )
                Write-Verbose -Message "Waiting for 5 seconds before execute code in ScriptBlock..."
                Start-Sleep -Seconds 5
                $SyncObject.Counter++
                Get-Service -Name $Service -ComputerName $Computer
            }

            Write-Verbose -Message "SyncObject counter before execution: $($SyncObject.Counter)"
            Invoke-PSRunSpace -InputObject $Computers -ScriptBlock $ScriptBlock -Arguments $Service -SyncObject $SyncObject -SendInputObjectInstance -Verbose -Debug
            Write-Verbose -Message "SyncObject counter after execution: $($SyncObject.Counter)"
    #>

    [CmdletBinding()]
    Param (
        [Parameter(
            Position=0,
            Mandatory=$True,
            HelpMessage="Specify a list of PowerShell objects:"
        )]
        [ValidateNotNullOrEmpty()]
        $InputObject,

        [Parameter(
            Position=1,
            Mandatory=$True,
            HelpMessage="A script block is an instance of a Microsoft .NET Framework type (System.Management.Automation.ScriptBlock):"
        )]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({
            If ($_ -is [System.Management.Automation.ScriptBlock]) {
                $True
            }
            Else {
                Throw "YOU SPECIFIED A WRONG OBJECT TYPE! THE EXPECTED TYPE IS: [ScriptBlock]"
            }
        })]
        [System.Management.Automation.ScriptBlock] $ScriptBlock,

        [Parameter(
            Position=2,
            Mandatory=$False,
            HelpMessage="A script block can accept arguments and return values:"
        )]
        [ValidateNotNullOrEmpty()]
        [Alias("Args")]
        [Object[]] $Arguments,

        [Parameter(
            Position=3,
            Mandatory=$False
        )]
        [HashTable] $SyncObject = [HashTable]::Synchronized(@{}),

        [Parameter(
            Position=4,
            Mandatory=$False,
            HelpMessage="Specify maximum no. of threads. Maximum is 8 threads:"
        )]
        [ValidateNotNullOrEmpty()]
        [ValidateRange(1,8)]
        [Int16] $MaxThreads,

        [Parameter(
            Position=5,
            Mandatory=$False,
            HelpMessage="Specify timeout value for all threads:"
        )]
        [ValidateNotNullOrEmpty()]
        [Int32] $TimeOut,

        [Parameter(
            Position=6,
            Mandatory=$False
        )]
        [Switch] $SendInputObjectInstance,

        [Parameter(
            Position = 7,
            Mandatory = $False
        )]
        [ValidateNotNullOrEmpty()]
        [Int] $ParentActivityId
    )

    If ($PSBoundParameters['Verbose']) {
        $VerbosePreference = "Continue"
    }
    If ($PSBoundParameters['Debug']) {
        $DebugPreference = "Continue"
        $ConfirmPreference = "None"
    }

    Try {
        Write-Debug -Message "[$((Get-Date).ToString())] [Invoke-PSRunSpace] Identified the given set of objects (InputObject) as $($InputObject.Count)."

        # Array variable to store a list of pipelines.
        $AsyncPipelines = @()

        # Array variable to store a list of completed pipeline instances.
        $CompletedPipelineInstances = @()

        # Create a pool with specified no. of runspaces.
        If (!$MaxThreads) {
            If ($InputObject.Count -gt 8) {
                $MaxThreads = 8
            }
            Else {
                $MaxThreads = $InputObject.Count
            }
        }

        Write-Debug -Message "[$((Get-Date).ToString())] [Invoke-PSRunSpace] Maximum threads allowed is set to: $MaxThreads"

        If ($TimeOut) {
            Write-Debug -Message "[$((Get-Date).ToString())] [Invoke-PSRunSpace] TimeOut value for an entire runspace pool is set to: $TimeOut"
        }
        
        # Create a pool with sufficient no. of runspaces (based on no. of objects)
        If ($PSBoundParameters['Verbose'] -and $PSBoundParameters['Debug']) {
            If ($PSBoundParameters['SyncObject']) {
                $RunSpacePool = New-RunSpacePool -MaxThreads $MaxThreads -SyncObject $SyncObject -Verbose -Debug -Confirm:$False
            }
            Else {
                $RunSpacePool = New-RunSpacePool -MaxThreads $MaxThreads -Verbose -Debug -Confirm:$False
            }
        }
        ElseIf ($PSBoundParameters['Verbose']) {
            If ($PSBoundParameters['SyncObject']) { 
                $RunSpacePool = New-RunSpacePool -MaxThreads $MaxThreads -SyncObject $SyncObject -Verbose -Confirm:$False
            }
            Else {
                $RunSpacePool = New-RunSpacePool -MaxThreads $MaxThreads -Verbose -Confirm:$False
            }
        }
        ElseIf ($PSBoundParameters['Debug']) {
            If ($PSBoundParameters['SyncObject']) { 
                $RunSpacePool = New-RunSpacePool -MaxThreads $MaxThreads -SyncObject $SyncObject -Debug -Confirm:$False
            }
            Else {
                $RunSpacePool = New-RunSpacePool -MaxThreads $MaxThreads -Debug -Confirm:$False
            }
        }
        Else {
            If ($PSBoundParameters['SyncObject']) { 
                $RunSpacePool = New-RunSpacePool -MaxThreads $MaxThreads -SyncObject $SyncObject -Confirm:$False
            }
            Else {
                $RunSpacePool = New-RunSpacePool -MaxThreads $MaxThreads -Confirm:$False
            }
        }

        Write-Debug -Message "[$((Get-Date).ToString())] [Invoke-PSRunSpace] A new runspace pool has been opened with maximum of $MaxThreads threads."

        # Wait TimeOut Value
        $WaitTimeOut = Get-Date

        Write-Debug -Message "[$((Get-Date).ToString())] [Invoke-PSRunSpace] Begin to process $($InputObject.Count) objects."

        $InputObjectCount = 1
        $RootActivityId = $(Get-Date -Format "yyyymmss")
        
        ForEach ($Object in $InputObject) {
            Write-Debug -Message "[$((Get-Date).ToString())] [Invoke-PSRunSpace] Processing $($InputObjectCount) of $($InputObject.Count) objects..."
            
            While ($($RunSpacePool.GetAvailableRunspaces()) -le 0) {
                Write-Debug -Message "[$((Get-Date).ToString())] [Invoke-PSRunSpace] All of the runspaces in the pool are in use..."
                $AsyncPipelines | Where-Object {($_.AsyncResult.IsCompleted -eq $True) -and ($CompletedPipelineInstances -notcontains $_.Pipeline.InstanceId.Guid)} | ForEach-Object {
                    Try {
                        Write-Debug -Message "[$((Get-Date).ToString())] [Invoke-PSRunSpace] Getting results from completed pipeline [$($_.Pipeline.InstanceId.Guid)]..."
                        
                        Write-Output -InputObject $($_.Pipeline.EndInvoke($_.AsyncResult))
                        $CompletedPipelineInstances += $_.Pipeline.InstanceId.Guid
                        
                        ForEach ($ErrorStream in $_.Pipeline.Streams.Error.ReadAll()) { Write-Error -ErrorRecord $ErrorStream }
                        ForEach ($WarningStream in $_.Pipeline.Streams.Warning.ReadAll()) { Write-Warning -Message $WarningStream }
                        ForEach ($VerboseStream in $_.Pipeline.Streams.Verbose.ReadAll()) { Write-Verbose -Message $VerboseStream }
                        ForEach ($DebugStream in $_.Pipeline.Streams.Debug.ReadAll()) { Write-Debug -Message $DebugStream }
                    }
                    Catch {
                        # Capture an exception.
                        Write-Verbose -Message "[$((Get-Date).ToString())] [Invoke-PSRunSpace] An exception has occurred while trying to get results from completed pipeline [$($_.Pipeline.InstanceId.Guid)]!"
                        Write-Error -Exception $_.Exception -Message $_.Exception.Message
                    }
                    Finally {
                        If ($PSBoundParameters['ParentActivityId']) {
                            Write-Progress -Activity "Processing Async Pipeline Instances.." -Status "Processing: Async Pipeline $($CompletedPipelineInstances.Count) of $($InputObject.Count)" -Id $RootActivityId -ParentId $ParentActivityId -PercentComplete (($($CompletedPipelineInstances.Count) / $($InputObject.Count))*100) -CurrentOperation "Processing Async Pipeline Instances.."
                        }
                        Else {
                            Write-Progress -Activity "Processing Async Pipeline Instances.." -Status "Processing: Async Pipeline $($CompletedPipelineInstances.Count) of $($InputObject.Count)" -Id $RootActivityId -PercentComplete (($($CompletedPipelineInstances.Count) / $($InputObject.Count))*100) -CurrentOperation "Processing Async Pipeline Instances.."
                        }
                        
                        # Note: We're proceeding with disposing of the Pipeline regardless of it's state...
                        # Releases all resources used by the PowerShell object.
                        Write-Debug -Message "[$((Get-Date).ToString())] [Invoke-PSRunSpace] Disposing the pipeline [$($_.Pipeline.InstanceId.Guid)]..."
                        $_.Pipeline.Dispose()
                    }
                }
                Write-Debug -Message "[$((Get-Date).ToString())] [Invoke-PSRunSpace] Sleeping for 200 Milliseconds..."
                Start-Sleep -Milliseconds 200
            }
            
            Write-Debug -Message "[$((Get-Date).ToString())] [Invoke-PSRunSpace] A runspace is available to use. Proceeding with invoking..."
            # Create a PowerShell pipeline and executes a script block asynchronously.
            If (($Arguments) -and ($SendInputObjectInstance)) {
                Write-Debug -Message "[$((Get-Date).ToString())] [Invoke-PSRunSpace] [Invoke-Async] Invoking a new runspace for an object ($InputObjectCount of $($InputObject.Count)) with arguments and an object instance..."
                If ($PSBoundParameters['Verbose'] -and $PSBoundParameters['Debug']) {
                    $AsyncPipelines += Invoke-Async -RunSpacePool $RunSpacePool -ScriptBlock $ScriptBlock -Arguments $Object,@($Arguments) -Verbose -Debug
                }
                ElseIf ($PSBoundParameters['Verbose']) {
                    $AsyncPipelines += Invoke-Async -RunSpacePool $RunSpacePool -ScriptBlock $ScriptBlock -Arguments $Object,@($Arguments) -Verbose
                }
                ElseIf ($PSBoundParameters['Debug']) {
                    $AsyncPipelines += Invoke-Async -RunSpacePool $RunSpacePool -ScriptBlock $ScriptBlock -Arguments $Object,@($Arguments) -Debug
                }
                Else {
                    $AsyncPipelines += Invoke-Async -RunSpacePool $RunSpacePool -ScriptBlock $ScriptBlock -Arguments $Object,@($Arguments)
                }
            }
            ElseIf (($Arguments) -and (!$SendInputObjectInstance)) {
                Write-Debug -Message "[$((Get-Date).ToString())] [Invoke-PSRunSpace] [Invoke-Async] Invoking a new runspace for an object ($InputObjectCount of $($InputObject.Count)) with arguments..."
                If ($PSBoundParameters['Verbose'] -and $PSBoundParameters['Debug']) {
                    $AsyncPipelines += Invoke-Async -RunSpacePool $RunSpacePool -ScriptBlock $ScriptBlock -Arguments @($Arguments) -Verbose -Debug
                }
                ElseIf ($PSBoundParameters['Verbose']) {
                    $AsyncPipelines += Invoke-Async -RunSpacePool $RunSpacePool -ScriptBlock $ScriptBlock -Arguments @($Arguments) -Verbose
                }
                ElseIf ($PSBoundParameters['Debug']) {
                    $AsyncPipelines += Invoke-Async -RunSpacePool $RunSpacePool -ScriptBlock $ScriptBlock -Arguments @($Arguments) -Verbose
                }
                Else {
                    $AsyncPipelines += Invoke-Async -RunSpacePool $RunSpacePool -ScriptBlock $ScriptBlock -Arguments @($Arguments)
                }
            }
            ElseIf ((!$Arguments) -and ($SendInputObjectInstance)) {
                Write-Debug -Message "[$((Get-Date).ToString())] [Invoke-PSRunSpace] [Invoke-Async] Invoking a new runspace for an object ($InputObjectCount of $($InputObject.Count)) with an object instance..."
                If ($PSBoundParameters['Verbose'] -and $PSBoundParameters['Debug']) {
                    $AsyncPipelines += Invoke-Async -RunSpacePool $RunSpacePool -ScriptBlock $ScriptBlock -Arguments $Object -Verbose -Debug
                }
                ElseIf ($PSBoundParameters['Verbose']) {
                    $AsyncPipelines += Invoke-Async -RunSpacePool $RunSpacePool -ScriptBlock $ScriptBlock -Arguments $Object -Verbose
                }
                ElseIf ($PSBoundParameters['Debug']) {
                    $AsyncPipelines += Invoke-Async -RunSpacePool $RunSpacePool -ScriptBlock $ScriptBlock -Arguments $Object -Debug
                }
                Else {
                    $AsyncPipelines += Invoke-Async -RunSpacePool $RunSpacePool -ScriptBlock $ScriptBlock -Arguments $Object
                }
            }
            Else {
                Write-Debug -Message "[$((Get-Date).ToString())] [Invoke-PSRunSpace] [Invoke-Async] Invoking a new runspace for an object ($InputObjectCount of $($InputObject.Count)) without any arguments..."
                If ($PSBoundParameters['Verbose'] -and $PSBoundParameters['Debug']) {
                    $AsyncPipelines += Invoke-Async -RunSpacePool $RunSpacePool -ScriptBlock $ScriptBlock -Verbose -Debug
                }
                ElseIf ($PSBoundParameters['Verbose']) {
                    $AsyncPipelines += Invoke-Async -RunSpacePool $RunSpacePool -ScriptBlock $ScriptBlock -Verbose
                }
                ElseIf ($PSBoundParameters['Debug']) {
                    $AsyncPipelines += Invoke-Async -RunSpacePool $RunSpacePool -ScriptBlock $ScriptBlock -Debug
                }
                Else {
                    $AsyncPipelines += Invoke-Async -RunSpacePool $RunSpacePool -ScriptBlock $ScriptBlock
                }
            }

            $InputObjectCount++
        }

        If ($TimeOut) {
            While ((($AsyncPipelines | Where-Object {$_.Pipeline.InvocationStateInfo.State -eq "Running"}).Count -gt 0) -and ($($($(Get-Date) - $WaitTimeOut).TotalSeconds) -lt $TimeOut)) {
                $AsyncPipelines | Where-Object {($_.AsyncResult.IsCompleted -eq $True) -and ($CompletedPipelineInstances -notcontains $_.Pipeline.InstanceId.Guid)} | ForEach-Object {                    
                    Try {
                        Write-Debug -Message "[$((Get-Date).ToString())] [Invoke-PSRunSpace] Getting results from completed pipeline [$($_.Pipeline.InstanceId.Guid)]..."
                    
                        Write-Output -InputObject $($_.Pipeline.EndInvoke($_.AsyncResult))
                        $CompletedPipelineInstances += $_.Pipeline.InstanceId.Guid
                
                        ForEach ($ErrorStream in $_.Pipeline.Streams.Error.ReadAll()) { Write-Error -ErrorRecord $ErrorStream }
                        ForEach ($WarningStream in $_.Pipeline.Streams.Warning.ReadAll()) { Write-Warning -Message $WarningStream }
                        ForEach ($VerboseStream in $_.Pipeline.Streams.Verbose.ReadAll()) { Write-Verbose -Message $VerboseStream }
                        ForEach ($DebugStream in $_.Pipeline.Streams.Debug.ReadAll()) { Write-Debug -Message $DebugStream }
                    }
                    Catch {
                        # Capture an exception.
                        Write-Verbose -Message "[$((Get-Date).ToString())] [Invoke-PSRunSpace] Disposing the pipeline [$($_.Pipeline.InstanceId.Guid)]..."
                        Write-Error -Exception $_.Exception
                    }
                    Finally {
                        If ($PSBoundParameters['ParentActivityId']) {
                            Write-Progress -Activity "Processing Async Pipeline Instances.." -Status "Processing: Async Pipeline $($CompletedPipelineInstances.Count) of $($AsyncPipelines.Count)" -Id $RootActivityId -ParentId $ParentActivityId -PercentComplete (($($CompletedPipelineInstances.Count) / $($AsyncPipelines.Count))*100) -CurrentOperation "Processing Async Pipeline Instances.."
                        }
                        Else {
                            Write-Progress -Activity "Processing Async Pipeline Instances.." -Status "Processing: Async Pipeline $($CompletedPipelineInstances.Count) of $($AsyncPipelines.Count)" -Id $RootActivityId -PercentComplete (($($CompletedPipelineInstances.Count) / $($AsyncPipelines.Count))*100) -CurrentOperation "Processing Async Pipeline Instances.."
                        }
                        
                        # Note: We're proceeding with disposing of the Pipeline regardless of it's state...
                        # Releases all resources used by the PowerShell object.
                        Write-Debug -Message "[$((Get-Date).ToString())] [Invoke-PSRunSpace] Disposing the pipeline [$($_.Pipeline.InstanceId.Guid)]..."
                        $_.Pipeline.Dispose()
                    }
                }
                Write-Debug -Message "[$((Get-Date).ToString())] [Invoke-PSRunSpace] Sleeping for 200 Milliseconds..."
                Start-Sleep -Milliseconds 200
            }
        }
        Else {
            While (($AsyncPipelines | Where-Object {$_.Pipeline.InvocationStateInfo.State -eq "Running"}).Count -gt 0) {
                $AsyncPipelines | Where-Object {($_.AsyncResult.IsCompleted -eq $True) -and ($CompletedPipelineInstances -notcontains $_.Pipeline.InstanceId.Guid)} | ForEach-Object {                    
                    Try {
                        Write-Debug -Message "[$((Get-Date).ToString())] [Invoke-PSRunSpace] Getting results from completed pipeline [$($_.Pipeline.InstanceId.Guid)]..."
                    
                        Write-Output -InputObject $($_.Pipeline.EndInvoke($_.AsyncResult))
                        $CompletedPipelineInstances += $_.Pipeline.InstanceId.Guid
                
                        ForEach ($ErrorStream in $_.Pipeline.Streams.Error.ReadAll()) { Write-Error -ErrorRecord $ErrorStream }
                        ForEach ($WarningStream in $_.Pipeline.Streams.Warning.ReadAll()) { Write-Warning -Message $WarningStream }
                        ForEach ($VerboseStream in $_.Pipeline.Streams.Verbose.ReadAll()) { Write-Verbose -Message $VerboseStream }
                        ForEach ($DebugStream in $_.Pipeline.Streams.Debug.ReadAll()) { Write-Debug -Message $DebugStream }
                    }
                    Catch {
                        # Capture an exception.
                        Write-Verbose -Message "[$((Get-Date).ToString())] [Invoke-PSRunSpace] Disposing the pipeline [$($_.Pipeline.InstanceId.Guid)]..."
                        Write-Error -Exception $_.Exception -Message $_.Exception.Message
                    }
                    Finally {
                        If ($PSBoundParameters['ParentActivityId']) {
                            Write-Progress -Activity "Processing Async Pipeline Instances.." -Status "Processing: Async Pipeline $($CompletedPipelineInstances.Count) of $($AsyncPipelines.Count)" -Id $RootActivityId -ParentId $ParentActivityId -PercentComplete (($($CompletedPipelineInstances.Count) / $($AsyncPipelines.Count))*100) -CurrentOperation "Processing Async Pipeline Instances.."
                        }
                        Else {
                            Write-Progress -Activity "Processing Async Pipeline Instances.." -Status "Processing: Async Pipeline $($CompletedPipelineInstances.Count) of $($AsyncPipelines.Count)" -Id $RootActivityId -PercentComplete (($($CompletedPipelineInstances.Count) / $($AsyncPipelines.Count))*100) -CurrentOperation "Processing Async Pipeline Instances.."
                        }
                        
                        # Note: We're proceeding with disposing of the Pipeline regardless of it's state...
                        # Releases all resources used by the PowerShell object.
                        Write-Debug -Message "[$((Get-Date).ToString())] [Invoke-PSRunSpace] Disposing the pipeline [$($_.Pipeline.InstanceId.Guid)]..."
                        $_.Pipeline.Dispose()
                    }
                }
                Write-Debug -Message "[$((Get-Date).ToString())] [Invoke-PSRunSpace] Sleeping for 200 Milliseconds..."
                Start-Sleep -Milliseconds 200
            }
        }

        ForEach ($AsyncPipeline in $($AsyncPipelines | Where-Object {$CompletedPipelineInstances -notcontains $_.Pipeline.InstanceId.Guid})) {
            Write-Debug -Message "[$((Get-Date).ToString())] [Invoke-PSRunSpace] [Get-AsyncInfo] Invoking Get-AsyncInfo function to get results from the remaining set of pipelines..."
            Get-AsyncInfo -Pipeline $AsyncPipeline
            
            If ($PSBoundParameters['ParentActivityId']) {
                Write-Progress -Activity "Processing Async Pipeline Instances.." -Status "Processing: Async Pipeline $($($AsyncPipelines | Where-Object {$CompletedPipelineInstances -contains $_.Pipeline.InstanceId.Guid}).Count) of $($AsyncPipelines.Count)" -Id $RootActivityId -ParentId $ParentActivityId -PercentComplete (($($($AsyncPipelines | Where-Object {$CompletedPipelineInstances -contains $_.Pipeline.InstanceId.Guid}).Count) / $($AsyncPipelines.Count))*100) -CurrentOperation "Processing Async Pipeline Instances.."
            }
            Else {
                Write-Progress -Activity "Processing Async Pipeline Instances.." -Status "Processing: Async Pipeline $($($AsyncPipelines | Where-Object {$CompletedPipelineInstances -contains $_.Pipeline.InstanceId.Guid}).Count) of $($AsyncPipelines.Count)" -Id $RootActivityId -PercentComplete (($($($AsyncPipelines | Where-Object {$CompletedPipelineInstances -contains $_.Pipeline.InstanceId.Guid}).Count) / $($AsyncPipelines.Count))*100) -CurrentOperation "Processing Async Pipeline Instances.."
            }
        }
    }
    Catch {
        # Capture an exception.
        Write-Verbose -Message "[$((Get-Date).ToString())] [Invoke-PSRunSpace] An exception has occurred while trying to invoking runspaces!"
        Write-Error -Exception $_.Exception -Message $_.Exception.Message
    }
    Finally {
        If ($PSBoundParameters['ParentActivityId']) {
            Write-Progress -Activity "Processing Async Pipeline Instances.." -Status "Processing: Async Pipeline $($($AsyncPipelines | Where-Object {$CompletedPipelineInstances -contains $_.Pipeline.InstanceId.Guid}).Count) of $($AsyncPipelines.Count)" -Id $RootActivityId -ParentId $ParentActivityId -PercentComplete 100 -CurrentOperation "Processing Async Pipeline Instances.." -Completed
        }
        Else {
            Write-Progress -Activity "Processing Async Pipeline Instances.." -Status "Processing: Async Pipeline Instance $($($AsyncPipelines | Where-Object {$CompletedPipelineInstances -contains $_.Pipeline.InstanceId.Guid}).Count) of $($AsyncPipelines.Count)" -Id $RootActivityId -PercentComplete 100 -CurrentOperation "Processing Async Pipeline Instances.." -Completed
        }
        # Releases all resources used by the PowerShell object.
        Write-Debug -Message "[$((Get-Date).ToString())] [Invoke-PSRunSpace] Disposing runspace pool..."
        $RunSpacePool.Dispose()
    }
}