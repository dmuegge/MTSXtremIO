<# Module Name:     MTSXtremIO.psm1
## 
## Author:          David Muegge
## Purpose:         Provides PowerShell access to the EMC XtremIO REST API
##																					             
##                                                                             
####################################################################################################
## Disclaimer
## ****************************************************************
## * THE (MTSXtremIO PowerShell Module)                           *
## * IS PROVIDED WITHOUT WARRANTY OF ANY KIND.                    *
## *                                                              *
## * This module is licensed under the terms of the MIT license.  *
## * See license.txt in the root of the github project            *
## *                                                              *
## **************************************************************** 
###################################################################################################>
#Requires -Version 4

# TODO - Multi cluster support and testing, In Progress
# TODO - ShouldProcess on write functions
# TODO - Pipline improvements on New, Set, Remove functions
# TODO - Authentication and certificates improvements - Trusted SSL for connection and client cert auth
# TODO - POssibly adjust ID parameters to Index - Need to do more testing of piping gets to new,set, and remove commands
# TODO - Look at Error handiling schemes to supply additional information in failed calls
# TODO - Add informational output objects for success of New, Set, Remove operations 

# ISSUE - Pipeline input by name not working properly when piping output from get functions



# Helper functions not exported
function Test-ClusterID{
[CmdletBinding()]
param ($TestValue)
    $value = 0
    if([int]::TryParse( $TestValue, [ref]$value ) ) {
        $true
    }
    else{
        $false
    }
}



# Base and connection functions
# .ExternalHelp MTSXtremIO.psm1-Help.xml
function New-PasswordFile{
	[CmdletBinding()]
	param ( 
		[Parameter(Mandatory=$True)][Alias('p')][string]$Path,
		[Parameter(Mandatory=$True)][Alias('f')][string]$Filename
	)
        
    If(Test-Path -Path $Path){
	    $passwd = Read-Host -prompt 'Password' -assecurestring
        $FullFilePath = $Path + '\' + $Filename
        New-Item -Path $FullFilePath -ItemType File
	    ConvertFrom-SecureString -securestring $passwd | Out-File -FilePath $FullFilePath.ToString()
    }
    Else
    {
        Write-Error -Message ('[New-PasswordFile] :: Path file not found: ' + $Path)
    }

    
} # New-PasswordFile

# .ExternalHelp MTSXtremIO.psm1-Help.xml
function Get-PasswordFromFile{
[CmdletBinding()]
	param ( 
		[Parameter(Mandatory=$True)][Alias('f')][string]$FullPath
	)

    
    # Test file existence and retrieve file object
    If(Test-Path -Path $FullPath){

        $File = Get-item -Path $FullPath
        $filedata = Get-Content -Path $File.FullName
        $password = ConvertTo-SecureString -String $filedata
        $BSTR = [System.Runtime.InteropServices.marshal]::SecureStringToBSTR($password)
        $password = [System.Runtime.InteropServices.marshal]::PtrToStringAuto($BSTR)
        [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR)
        return $password

    }
    else
    {
        Write-Error -Message ('[Get-PasswordFromFile] :: Password file not found: ' + $FullPath)
    }
    
} # Get-PasswordFromFile

# .ExternalHelp MTSXtremIO.psm1-Help.xml
function Disable-CertificateValidation{
[CmdletBinding()]
param()

add-type @"
using System.Net;
using System.Security.Cryptography.X509Certificates;

    public class IDontCarePolicy : ICertificatePolicy {
    public IDontCarePolicy() {}
    public bool CheckValidationResult(
        ServicePoint sPoint, X509Certificate cert,
        WebRequest wRequest, int certProb) {
        return true;
    }
}
"@
[System.Net.ServicePointManager]::CertificatePolicy = New-Object -TypeName IDontCarePolicy 

} # Disable-CertificateValidation

# .ExternalHelp MTSXtremIO.psm1-Help.xml
function Set-XIOAPIConnectionInfo{
	[CmdletBinding()]
	param ([Parameter(Mandatory=$True)][Alias('u')][string]$username,
           [Parameter(Mandatory=$True)][Alias('p')][string]$passwordfile,
           [Parameter(Mandatory=$True)][Alias('h')][string]$hostname,
           [Parameter(Mandatory=$False)][ValidateNotNullOrEmpty()][Alias('c')][string]$certpath=$null,
           [Parameter(Mandatory=$False)][ValidateNotNullOrEmpty()][Alias('t')][string]$certthumbprint=$null           
           )

    # Encode basic authorization header
    $upassword = Get-PasswordFromFile -FullPath $passwordfile
    $auth = $username + ':' + $upassword
    $Encoded = [System.Text.Encoding]::UTF8.GetBytes($auth)
    $EncodedPassword = [System.Convert]::ToBase64String($Encoded)

    # set base uri
    $baseuri = 'https://' + $hostname + '/api/json/v2/types/'

    # Define global connection variables
    New-Variable -Name XIOAPIBaseUri -Value $baseuri -Scope Global -Force
    New-Variable -Name XIOAPIHeaders -Value @{'Authorization'="Basic $($EncodedPassword)"} -Scope Global -Force

    
    if($certpath){
            
    }

    # TODO - Setup root certificate validation - this requires installation of root certificate in client store


} # Set-XIOAPIConnectionInfo

# .ExternalHelp MTSXtremIO.psm1-Help.xml
function Get-XIOAPITypes{
[CmdletBinding()]
	param ()
        
    $Uri = $Global:XIOAPIBaseUri
    ($Uri.Remove($Uri.LastIndexOf('/'),1))
    (Invoke-RestMethod -Method Get -Uri $Uri -Headers $Global:XIOAPIHeaders).Children
    
} # Get-XIOAPITypes

# .ExternalHelp MTSXtremIO.psm1-Help.xml
function Get-XIOItem{
[CmdletBinding()]
	param ([Parameter(Mandatory=$True)][Alias('u')][string]$UriString)
    
    Invoke-RestMethod -Method Get -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders
    
} # Get-XIOItem


# Get functions
# .ExternalHelp MTSXtremIO.psm1-Help.xml
function Get-XIOPerformance{
[CmdletBinding()]
Param([Parameter( Mandatory=$true)]
        [ValidateSet('Volume','Snapshot','Target','Initiator')]
        [Alias('e')][string]$Entity,
        [Parameter(Mandatory=$false)]
        [Alias('a')][string]$Aggregation,
        [Parameter(Mandatory=$false)]
        [Alias('f')][string]$ExportFile,
        [Parameter(Mandatory=$false)]
        [Alias('ft')][datetime]$FromTime,
        [Parameter(Mandatory=$false)]
        [Alias('tt')][datetime]$ToTime,
        [Parameter(Mandatory=$false)]
        [Alias('g')][string]$Granularity,
        [Parameter(Mandatory=$false)]
        [Alias('l')][string]$RecordLimit,
        [Parameter(Mandatory=$false)]
        [Alias('ol')][int[]]$ObjectList,
        [Parameter(Mandatory=$false)]
        [Alias('t')][string]$TimeFrame,
        [Parameter(Mandatory=$false)]
        [Alias('v')][string]$Vertical

)

    Begin{
        $UriObject = 'performance'
    }
    Process{
        # Return details of XMS names passed by parameter or pipeline
        if($Entity){$UriString = ($UriObject + '?entity=' + $Entity)}
        if($Aggregation){$UriString = $UriString + '&aggregation-type=' + $Aggregation}
        if($ExportFile){$UriString = $UriString + '&export-to-file=' + $ExportFile}
        if($FromTime){$UriString = $UriString + '&from-time=' + $FromTime}
        if($ToTime){$UriString = $UriString + '&to-time=' + $ToTime}
        if($Granularity){$UriString = $UriString + '&granularity=' + $Granularity}
        if($RecordLimit){$UriString = $UriString + '&limit=' + $RecordLimit}
        if($ObjectList){$UriString = $UriString + '&obj-list=' + $ObjectList}
        if($Vertical){$UriString = $UriString + '&vertical=' + $Vertical}
        Invoke-RestMethod -Method Get -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders

    }
    

    # TODO - COmplete this function - questions about objects in documentation need 4.0

} # Get-XIOPerformance

# .ExternalHelp MTSXtremIO.psm1-Help.xml
function Get-XIOXms{
[CmdletBinding(DefaultParameterSetName='AllXmss')]
param ( [Parameter( Mandatory=$true,
                    ValueFromPipeline=$true,
                    Position=0, 
                    ParameterSetName='XMSByName')]
        [Alias('n')][string]$Name=$null,
        [Parameter(Mandatory=$true,ParameterSetName='XMSByID')]
        [Alias('i')][string]$ID=$null
        
)

    Begin{
        $UriObject = 'xms'
    }
    Process{
        # Return details of object names passed by parameter or pipeline
        if($Name){
            $UriString = ($UriObject + '/?name=' + $Name)
            (Invoke-RestMethod -Method Get -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders).Content
        }
    }
    End{
        
        # Return detail of specific object by ID
        if($ID){
            $UriString = ($UriObject + '/' + $ID)
            (Invoke-RestMethod -Method Get -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders).Content
        }

        # No parameters passed return details of all Objects
        if($PSCmdlet.ParameterSetName -eq 'AllXmss'){
            $UriString = ($UriObject + '/')
            (Get-XIOItem -UriString $UriObject).$UriObject | ForEach-Object{(Invoke-RestMethod -Method Get -Uri ($Global:XIOAPIBaseUri + $UriString + '?name=' + ($_.Name)) -Headers $Global:XIOAPIHeaders).Content}
        }
        
    }  
} # Get-XIOXms

# .ExternalHelp MTSXtremIO.psm1-Help.xml
function Get-XIOUserAccount{
[CmdletBinding(DefaultParameterSetName='AllUserAccounts')]
param ( [Parameter(Mandatory=$true, 
                    ValueFromPipeline=$true,
                    Position=0,
                    ParameterSetName='UserAccountByName')]
        [Alias('n')] 
        [string]$Name=$null,
        [Parameter(Mandatory=$true,
                    ParameterSetName='UserAccountByIndex')]
        [Alias('i')] 
        [string]$ID=$null
)
    Begin{
        $UriObject = 'user-accounts'
    }
    Process{
        # Return details of object by name passed by parameter or pipeline
        if($Name){
            $UriString = ($UriObject + '/?name=' + $Name)
            (Invoke-RestMethod -Method Get -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders).content
        }
    }
    End{
        # Return detail of object by ID
        if($ID){
            $UriString = ($UriObject + '/' + $ID)
            (Invoke-RestMethod -Method Get -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders).content
        }
        
        # No parameters passed return details of all objects
        if($PSCmdlet.ParameterSetName -eq 'AllUserAccounts'){
            $UriString = ($UriObject + '/')
            (Get-XIOItem -UriString $UriObject).$UriObject | ForEach-Object{(Invoke-RestMethod -Method Get -Uri ($Global:XIOAPIBaseUri + $UriString + '?name=' + ($_.Name)) -Headers $Global:XIOAPIHeaders).Content}
        }
    }

} # Get-XIOUserAccount

# .ExternalHelp MTSXtremIO.psm1-Help.xml
function Get-XIOCluster{
[CmdletBinding(DefaultParameterSetName='AllClusters')]
param ( [Parameter( Mandatory=$true,
                    ValueFromPipeline=$true,
                    Position=0, 
                    ParameterSetName='ClusterByName')]
        [Alias('n')][string]$Name=$null,
        [Parameter(Mandatory=$true,ParameterSetName='ClusterByID')]
        [Alias('i')][string]$ID=$null
        
)
    Begin{
        $UriObject = 'clusters'
    }
    Process{
        # Return details of object names passed by parameter or pipeline
        if($Name){
            $UriString = ($UriObject + '/?name=' + $Name)
            (Invoke-RestMethod -Method Get -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders).Content
        }
    }
    End{
        
        # Return detail of specific object by ID
        if($ID){
            $UriString = ($UriObject + '/' + $ID)
            (Invoke-RestMethod -Method Get -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders).Content
        }

        # No parameters passed return details of all objects
        if($PSCmdlet.ParameterSetName -eq 'AllClusters'){
            $UriString = ($UriObject + '/')
            (Get-XIOItem -UriString $UriObject).$UriObject | ForEach-Object{(Invoke-RestMethod -Method Get -Uri ($Global:XIOAPIBaseUri + $UriString + '?name=' + ($_.Name)) -Headers $Global:XIOAPIHeaders).Content}
        }
        
    }  
} # Get-XIOCluster

# .ExternalHelp MTSXtremIO.psm1-Help.xml
function Get-XIOBrick{
[CmdletBinding(DefaultParameterSetName='AllBricks')]
param ( [Parameter(Mandatory=$true, 
                    ValueFromPipeline=$true,  
                    Position=0,
                    ParameterSetName='BrickByName')]
        [Alias('n')] 
        [string]$Name=$null,
        [Parameter(Mandatory=$true, 
                    ParameterSetName='BrickByIndex')]
        [Alias('i')] 
        [string]$ID=$null
        
)
    Begin{
        $UriObject = 'bricks'
    }   
    Process{
        # Return details of object names passed by parameter or pipeline
        if($Name){
            $UriString = ($UriObject + '/?name=' + $Name)
            (Invoke-RestMethod -Method Get -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders).content
        }
        
    }
    End{
        
        # Return detail of specific object by ID
        if($ID){
            $UriString = ($UriObject + '/' + $ID)
            (Invoke-RestMethod -Method Get -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders).content
        }

        # No parameters passed return details of all objects
        if($PSCmdlet.ParameterSetName -eq 'AllBricks'){
            $UriString = ($UriObject + '/')
            (Get-XIOItem -UriString $UriObject).$UriObject | ForEach-Object{(Invoke-RestMethod -Method Get -Uri ($Global:XIOAPIBaseUri + $UriString + '?name=' + ($_.Name)) -Headers $Global:XIOAPIHeaders).Content}
        }

    }
} # Get-XIOBrick

# .ExternalHelp MTSXtremIO.psm1-Help.xml
function Get-XIOXenvs{
[CmdletBinding(DefaultParameterSetName='AllXEnvs')]
param ( [Parameter(Mandatory=$true, 
                    ValueFromPipeline=$true, 
                    Position=0,
                    ParameterSetName='XenvsByName')]
        [Alias('n')] 
        [string]$Name=$null,
        [Parameter(Mandatory=$true,
                    ParameterSetName='XenvsByIndex')]
        [Alias('i')] 
        [string]$ID=$null
)
   
    Begin{
        $UriObject = 'xenvs'
    }
    Process 
    {
        
        # Return details of object names passed by parameter or pipeline
        if($Name){
            $UriString = ($UriObject + '/?name=' + $Name)
            (Invoke-RestMethod -Method Get -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders).content
                
        }
        
    }
    End 
    {
        # Return detail of specific object by ID
        if($ID){
            $UriString = ($UriObject + '/' + $ID)
            (Invoke-RestMethod -Method Get -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders).content
        }

        # No parameters passed return details of all objects
        if($PSCmdlet.ParameterSetName -eq 'AllXEnvs'){
            $UriString = ($UriObject + '/')
            (Get-XIOItem -UriString $UriObject).$UriObject | ForEach-Object{(Invoke-RestMethod -Method Get -Uri ($Global:XIOAPIBaseUri + $UriString + '?name=' + ($_.Name)) -Headers $Global:XIOAPIHeaders).Content}
        }

    }
    
} # Get-XIOXenvs

# .ExternalHelp MTSXtremIO.psm1-Help.xml
function Get-XIOStorageController{
[CmdletBinding(DefaultParameterSetName='AllControllers')]
param ( [Parameter(Mandatory=$true,
                   ValueFromPipeline=$true,  
                   Position=0, 
                   ParameterSetName='SCByName')]
        [Alias('n')] 
        [string]$Name=$null,
        [Parameter(Mandatory=$true,ParameterSetName='SCByIndex')]
        [Alias('i')] 
        [string]$ID=$null
)
    Begin{
        $UriObject = 'storage-controllers'
    }
    Process{
        # Return details of object names passed by parameter or pipeline             
        if($Name){
            $UriString = ($UriObject + '/?name=' + $Name)
            (Invoke-RestMethod -Method Get -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders).content
        }
    }
    End{
        # Return detail of specific object by ID  
        if($ID){
            $UriString = ($UriObject + '/' + $ID)
            (Invoke-RestMethod -Method Get -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders).content
        }
        # No parameters passed return details of all objects
        if($PSCmdlet.ParameterSetName -eq 'AllControllers'){
            $UriString = ($UriObject + '/')
            (Get-XIOItem -UriString $UriObject).$UriObject | ForEach-Object{(Invoke-RestMethod -Method Get -Uri ($Global:XIOAPIBaseUri + $UriString + '?name=' + ($_.Name)) -Headers $Global:XIOAPIHeaders).Content}
        }
    }
} # Get-XIOStorageController

# .ExternalHelp MTSXtremIO.psm1-Help.xml
function Get-XIOStorageControllerPSU{
[CmdletBinding(DefaultParameterSetName='AllControllers')]
param ( [Parameter(Mandatory=$true,
                   ValueFromPipeline=$true,  
                   Position=0, 
                   ParameterSetName='SCByName')]
        [Alias('n')] 
        [string]$Name=$null,
        [Parameter(Mandatory=$true,ParameterSetName='SCByIndex')]
        [Alias('i')] 
        [string]$ID=$null
)
    Begin{
        $UriObject = 'storage-controller-psus'
    }
    Process{
        # Return details of object names passed by parameter or pipeline             
        if($Name){
            $UriString = ($UriObject + '/?name=' + $Name)
            (Invoke-RestMethod -Method Get -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders).content
        }
    }
    End{
        # Return detail of specific object by ID  
        if($ID){
            $UriString = ($UriObject + '/' + $ID)
            (Invoke-RestMethod -Method Get -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders).content
        }
        # No parameters passed return details of all objects
        if($PSCmdlet.ParameterSetName -eq 'AllControllers'){
            $UriString = ($UriObject + '/')
            (Get-XIOItem -UriString $UriObject).$UriObject | ForEach-Object{(Invoke-RestMethod -Method Get -Uri ($Global:XIOAPIBaseUri + $UriString + '?name=' + ($_.Name)) -Headers $Global:XIOAPIHeaders).Content}
        }
    }
} # Get-XIOStorageControllerPSU

# .ExternalHelp MTSXtremIO.psm1-Help.xml
function Get-XIODataProtectionGroup{
[CmdletBinding(DefaultParameterSetName='AllDPGroups')]
param ( [Parameter(Mandatory=$true,
                   ValueFromPipeline=$true,
                   Position=0, 
                   ParameterSetName='DPGByName')]
        [Alias('n')] 
        [string]$Name=$null,
        [Parameter(Mandatory=$true,ParameterSetName='DPGByIndex')]
        [Alias('i')] 
        [string]$ID=$null
)
    Begin{
        $UriObject = 'data-protection-groups'
    }
    Process{
        # Return details of data protection group by name passed by parameter or pipeline
        if($Name){
            $UriString = ($UriObject + '/?name=' + $Name)
            (Invoke-RestMethod -Method Get -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders).content
        }
    }
    End{
        # Return detail of specific data protection group by ID
        if($ID){
            $UriString = ($UriObject + '/' + $ID)
            (Invoke-RestMethod -Method Get -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders).content
        }
        # No parameters passed return details of all data protection groups
        if($PSCmdlet.ParameterSetName -eq 'AllDPGroups'){
            $UriString = ($UriObject + '/')
            (Get-XIOItem -UriString $UriObject).$UriObject | ForEach-Object{(Invoke-RestMethod -Method Get -Uri ($Global:XIOAPIBaseUri + $UriString + '?name=' + ($_.Name)) -Headers $Global:XIOAPIHeaders).Content}
        }
    }

    # TODO - Add multiple cluster support

} # Get-XIODataProtectionGroup

# .ExternalHelp MTSXtremIO.psm1-Help.xml
function Get-XIOTag{
[CmdletBinding(DefaultParameterSetName='AllTags')]
param ( [Parameter(Mandatory=$true,ParameterSetName='TagByName',
                   ValueFromPipeline=$true, 
                   Position=0)]
        [Alias('n')] 
        [string]$Name=$null
)
    Begin{
        $UriObject = 'tags'
    }
    Process{
        
        # Return details of tag names passed by parameter or pipeline       
        if($Name){
            $UriString = ($UriObject + '/?name=' + $Name)
            (Invoke-RestMethod -Method Get -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders).content
        }
    }
    End{
        
        # No parameters passed return details of all tags
        if($PSCmdlet.ParameterSetName -eq 'AllTags'){
            $UriString = ($UriObject + '/')
            (Get-XIOItem -UriString $UriObject).$UriObject | ForEach-Object{(Invoke-RestMethod -Method Get -Uri ($Global:XIOAPIBaseUri + $UriString + '?name=' + ($_.Name)) -Headers $Global:XIOAPIHeaders).Content}
        }
    }
} # Get-XIOTag

# .ExternalHelp MTSXtremIO.psm1-Help.xml
function Get-XIOVolume{
[CmdletBinding(DefaultParameterSetName='AllVolumes')]
param ( [Parameter(Mandatory=$true, 
                    ValueFromPipeline=$true,
                    Position=0,
                    ParameterSetName='VolByName')]
        [Alias('n')] 
        [string]$Name,
        [Parameter(Mandatory=$true,
                    ParameterSetName='VolByIndex')]
        [Alias('i')] 
        [string]$ID,
        [Parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [Alias('c')] 
        $Cluster
)
    Begin{
        $UriObject = 'volumes'
    }
    Process{
        # Return details of volume names passed by parameter or pipeline
        if($Name){
            $UriString = ($UriObject + '/?name=' + $Name)
            if($Cluster){
                if(Test-ClusterID -TestValue $Cluster){
                    $UriString = $UriString + '&cluster-id=' + $Cluster
                }Else{
                    $UriString = $UriString + '&cluster-name=' + $Cluster
                }

            }
            $ReturnObj = (Invoke-RestMethod -Method Get -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders).content
            $ReturnObj
        }
    }
    End{
        # Return detail of specific volume by ID
        if($ID){
            $UriString = ($UriObject + '/' + $ID)
            if($Cluster){
                if(Test-ClusterID -TestValue $Cluster){
                    $UriString = $UriString + '&cluster-id=' + $Cluster
                }Else{
                    $UriString = $UriString + '&cluster-name=' + $Cluster
                }
            }
            $ReturnObj = (Invoke-RestMethod -Method Get -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders).content
            $ReturnObj
        }
        # No parameters passed return details of all volumes
        if($PSCmdlet.ParameterSetName -eq 'AllVolumes'){
            $UriString = ($UriObject + '/')
            if($Cluster){
                if(Test-ClusterID -TestValue $Cluster){
                    $UriString = $UriString + '&cluster-id=' + $Cluster
                }Else{
                    $UriString = $UriString + '&cluster-name=' + $Cluster
                }
            }
            $ReturnObj = (Get-XIOItem -UriString $UriObject).$UriObject | ForEach-Object{(Invoke-RestMethod -Method Get -Uri ($Global:XIOAPIBaseUri + $UriObject + '?name=' + ($_.Name)) -Headers $Global:XIOAPIHeaders).Content}
            $ReturnObj
        }
    }

    # TODO - Test multiple cluster support

} # Get-XIOVolume - Note: This is to be used for multi cluster testing

# .ExternalHelp MTSXtremIO.psm1-Help.xml
function Get-XIOSnapshot{
[CmdletBinding(DefaultParameterSetName='AllSnapshots')]
param ( [Parameter(Mandatory=$true, 
                    ValueFromPipeline=$true,
                    Position=0,
                    ParameterSetName='SnapshotByName')]
        [Alias('n')] 
        [string]$Name=$null,
        [Parameter(Mandatory=$true,
                    ParameterSetName='SnapshotByIndex')]
        [Alias('i')] 
        [string]$ID=$null
)
    Begin{
        $UriObject = 'snapshots'
    }
    Process{
        # Return details of snapshot by name passed by parameter or pipeline
        if($Name){
            $UriString = ($UriObject + '/?name=' + $Name)
            (Invoke-RestMethod -Method Get -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders).content
        }
    }
    End{
        # Return detail of specific snapshot by ID
        if($ID){
            $UriString = ($UriObject + '/' + $ID)
            (Invoke-RestMethod -Method Get -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders).content
        }
        # No parameters passed return details of all snapshots
        if($PSCmdlet.ParameterSetName -eq 'AllSnapshots'){
            $UriString = ($UriObject + '/')
            (Get-XIOItem -UriString $UriObject).$UriObject | ForEach-Object{(Invoke-RestMethod -Method Get -Uri ($Global:XIOAPIBaseUri + $UriString + '?name=' + ($_.Name)) -Headers $Global:XIOAPIHeaders).Content}
        }
    }

    # TODO - Add multiple cluster support

} # Get-XIOSnapshot

# .ExternalHelp MTSXtremIO.psm1-Help.xml
function Get-XIOSnapshotSet{
[CmdletBinding(DefaultParameterSetName='AllSnapSets')]
param ( [Parameter(Mandatory=$true, 
                    ValueFromPipeline=$true,
                    Position=0,
                    ParameterSetName='SnapSetByName')]
        [Alias('n')] 
        [string]$Name=$null,
        [Parameter(Mandatory=$true,
                    ParameterSetName='SnapSetByIndex')]
        [Alias('i')] 
        [string]$ID=$null
)
    Begin{
        $UriObject = 'snapshot-sets'
    }
    Process{
        # Return details of snapshot by name passed by parameter or pipeline
        if($Name){
            $UriString = ($UriObject + '/?name=' + $Name)
            (Invoke-RestMethod -Method Get -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders).content
        }
    }
    End{
        # Return detail of specific snapshot by ID
        if($ID){
            $UriString = ($UriObject + '/' + $ID)
            (Invoke-RestMethod -Method Get -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders).content
        }
        # No parameters passed return details of all snapshots
        if($PSCmdlet.ParameterSetName -eq 'AllSnapSets'){
            $UriString = ($UriObject + '/')
            (Get-XIOItem -UriString $UriObject).$UriObject | ForEach-Object{(Invoke-RestMethod -Method Get -Uri ($Global:XIOAPIBaseUri + $UriString + '?name=' + ($_.Name)) -Headers $Global:XIOAPIHeaders).Content}
        }
    }

    # TODO - Add multiple cluster support

} # Get-XIOSnapshotSet

# .ExternalHelp MTSXtremIO.psm1-Help.xml
function Get-XIOScheduler{
[CmdletBinding(DefaultParameterSetName='AllSchedulers')]
param ( [Parameter(Mandatory=$true, 
                    ValueFromPipeline=$true,
                    Position=0,
                    ParameterSetName='SchedulerByName')]
        [Alias('n')] 
        [string]$Name=$null,
        [Parameter(Mandatory=$true,
                    ParameterSetName='SchedulerByIndex')]
        [Alias('i')] 
        [string]$ID=$null
)
    Begin{
        $UriObject = 'schedulers'
    }
    Process{
        # Return details of scheduler by name passed by parameter or pipeline
        if($Name){
            $UriString = ($UriObject + '/?name=' + $Name)
            (Invoke-RestMethod -Method Get -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders).content
        }
    }
    End{
        # Return detail of specific scheduler by ID
        if($ID){
            $UriString = ($UriObject + '/' + $ID)
            (Invoke-RestMethod -Method Get -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders).content
        }
        # No parameters passed return details of all snapshots
        if($PSCmdlet.ParameterSetName -eq 'AllSchedulers'){
            $UriString = ($UriObject + '/')
            (Get-XIOItem -UriString $UriObject).$UriObject | ForEach-Object{(Invoke-RestMethod -Method Get -Uri ($Global:XIOAPIBaseUri + $UriString + '?name=' + ($_.Name)) -Headers $Global:XIOAPIHeaders).Content}
        }
    }

    # TODO - Add multiple cluster support

} # Get-XIOScheduler

# .ExternalHelp MTSXtremIO.psm1-Help.xml
function Get-XIOInitiator{
[CmdletBinding(DefaultParameterSetName='AllInitiators')]
param ( [Parameter(Mandatory=$true, 
                    ValueFromPipeline=$true,  
                    Position=0,
                    ParameterSetName='InitiatorByName')]
        [Alias('n')] 
        [string]$Name=$null,
        [Parameter(Mandatory=$true,
                    ParameterSetName='InitiatorByIndex')]
        [Alias('i')] 
        [string]$ID=$null
)
    Begin{
        $UriObject = 'initiators'
    }
    Process{
        # Return details of initiator by name passed by parameter or pipeline
        if($Name){
            $UriString = ($UriObject + '/?name=' + $Name)
            (Invoke-RestMethod -Method Get -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders).content
        }
    }
    End{
        # Return detail of specific initiator by ID
        if($ID){
            $UriString = ($UriObject + '/' + $ID)
            (Invoke-RestMethod -Method Get -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders).content
        }
        # No parameters passed return details of all initiator
        if($PSCmdlet.ParameterSetName -eq 'AllInitiators'){
            $UriString = ($UriObject + '/')
            (Get-XIOItem -UriString $UriObject).$UriObject | ForEach-Object{(Invoke-RestMethod -Method Get -Uri ($Global:XIOAPIBaseUri + $UriString + '?name=' + ($_.Name)) -Headers $Global:XIOAPIHeaders).Content}
        }
    }

    # TODO - Add multiple cluster support

} # Get-XIOInitiator

# .ExternalHelp MTSXtremIO.psm1-Help.xml
function Get-XIOInitiatorGroup{
[CmdletBinding(DefaultParameterSetName='AllInitiatorGroups')]
param ( [Parameter(Mandatory=$true,
                   ValueFromPipeline=$true,
                   Position=0, 
                   ParameterSetName='IGByName')]
        [Alias('n')] 
        [string]$Name,
        [Parameter(Mandatory=$true,ParameterSetName='IGByIndex')]
        [Alias('i')] 
        [int]$ID
)
    Begin{
        $UriObject = 'initiator-groups'
    }
    Process{
        # Return details of initiator group by name passed by parameter or pipeline          
        if($Name){
            $UriString = ($UriObject + '/?name=' + $Name)
            (Invoke-RestMethod -Method Get -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders).content
        }
    }
    End{
        # Return detail of specific initiator group by ID
        if($ID){ 
            $UriString = ($UriObject + '/' + $ID)
            (Invoke-RestMethod -Method Get -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders).content
        }
        # No parameters passed return details of all initiator groups
        if($PSCmdlet.ParameterSetName -eq 'AllInitiatorGroups'){
            $UriString = ($UriObject + '/')
            (Get-XIOItem -UriString $UriObject).$UriObject | ForEach-Object{(Invoke-RestMethod -Method Get -Uri ($Global:XIOAPIBaseUri + $UriString + '?name=' + ($_.Name)) -Headers $Global:XIOAPIHeaders).Content}
        }
    }

    # TODO - Add multiple cluster support

} # Get-XIOInitiatorGroup

# .ExternalHelp MTSXtremIO.psm1-Help.xml
function Get-XIOTarget{
[CmdletBinding(DefaultParameterSetName='AllTargets')]
param ( [Parameter(Mandatory=$true, 
                    ValueFromPipeline=$true,
                    Position=0,
                    ParameterSetName='TargetByName')]
        [Alias('n')] 
        [string]$Name=$null,
        [Parameter(Mandatory=$true,
                    ParameterSetName='TargetByIndex')]
        [Alias('i')] 
        [string]$ID=$null
)
    Begin{
        $UriObject = 'targets'
    }
    Process{
        # Return details of target by name passed by parameter or pipeline
        if($Name){
            $UriString = ($UriObject + '/?name=' + $Name)
            (Invoke-RestMethod -Method Get -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders).content
        }
    }
    End{
        # Return detail of specific target by ID
        if($ID){
            $UriString = ($UriObject + '/' + $ID)
            (Invoke-RestMethod -Method Get -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders).content
        }
        
        # No parameters passed return details of all targets
        if($PSCmdlet.ParameterSetName -eq 'AllTargets'){
            $UriString = ($UriObject + '/')
            (Get-XIOItem -UriString $UriObject).$UriObject | ForEach-Object{(Invoke-RestMethod -Method Get -Uri ($Global:XIOAPIBaseUri + $UriString + '?name=' + ($_.Name)) -Headers $Global:XIOAPIHeaders).Content}
        }
    }

    # TODO - Add multiple cluster support

} # Get-XIOTarget

# .ExternalHelp MTSXtremIO.psm1-Help.xml
function Get-XIOTargetGroup{
[CmdletBinding(DefaultParameterSetName='AllTargetGroups')]
param ( [Parameter(Mandatory=$true,
                   ValueFromPipeline=$true,
                   Position=0, 
                   ParameterSetName='TGByName')]
        [Alias('n')] 
        [string]$Name=$null,
        [Parameter(Mandatory=$true,ParameterSetName='TGByIndex')]
        [Alias('i')] 
        [string]$ID=$null
)
    Begin{
        $UriObject = 'target-groups'
    }
    Process{
        
        # Return details of target group by name passed by parameter or pipeline
        if($Name){
            $UriString = ($UriObject + '/?name=' + $Name)
            (Invoke-RestMethod -Method Get -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders).content
        }
    }
    End{
        # Return detail of specific target group by ID   
        if($ID){
            $UriString = ($UriObject + '/' + $ID)
            (Invoke-RestMethod -Method Get -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders).content
        }
        # No parameters passed return details of all target groups
        if($PSCmdlet.ParameterSetName -eq 'AllTargetGroups'){
            $UriString = ($UriObject + '/')
            (Get-XIOItem -UriString $UriObject).$UriObject | ForEach-Object{(Invoke-RestMethod -Method Get -Uri ($Global:XIOAPIBaseUri + $UriString + '?name=' + ($_.Name)) -Headers $Global:XIOAPIHeaders).Content}
        }
    }

    # TODO - Add multiple cluster support

} # Get-XIOTargetGroup

# .ExternalHelp MTSXtremIO.psm1-Help.xml
function Get-XIOConsistencyGroup{
[CmdletBinding(DefaultParameterSetName='AllConsistencyGroups')]
param ( [Parameter(Mandatory=$true,
                   ValueFromPipeline=$true,
                   Position=0, 
                   ParameterSetName='CGByName')]
        [Alias('n')] 
        [string]$Name,
        [Parameter(Mandatory=$true,ParameterSetName='CGByIndex')]
        [Alias('i')] 
        [string]$ID,
        [Parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [Alias('c')] 
        $Cluster
) 
    Begin{
        $UriObject = 'consistency-groups'
        
    }
    Process{
        
        # Return details of target group by name passed by parameter or pipeline
        if($Name){
            $UriString = ($UriObject + '/?name=' + $Name)
            if($Cluster){
                if(Test-ClusterID -TestValue $Cluster){
                    $UriString = $UriString + '&cluster-id=' + $Cluster
                }Else{
                    $UriString = $UriString + '&cluster-name=' + $Cluster
                }
            }
        }
        (Invoke-RestMethod -Method Get -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders).content
    }
    
    End{
        # Return detail of specific target group by ID   
        if($ID){
            $UriString = ($UriObject + '/' + $ID)
            if($Cluster){
                if(Test-ClusterID -TestValue $Cluster){
                    $UriString = $UriString + '&cluster-id=' + $Cluster
                }Else{
                    $UriString = $UriString + '&cluster-name=' + $Cluster
                }
            }
            <#
            if($Cluster){
                $JSoNBody = New-Object -TypeName psobject
                if(Test-ClusterID -TestValue $Cluster){
                    $JSoNBody | Add-Member -MemberType NoteProperty -Name cluster-id -Value $Cluster
                }Else{
                    $JSoNBody | Add-Member -MemberType NoteProperty -Name cluster-name -Value $Cluster
                }
                if($JSoNBody){
                    (Get-XIOItem -UriString $UriObject).$UriObject | ForEach-Object{(Invoke-RestMethod -Method Get -Uri ($Global:XIOAPIBaseUri + $UriString + '?name=' + ($_.Name)) -Headers $Global:XIOAPIHeaders -Body ($JSoNBody | ConvertTo-Json)).Content}
                }else{
                    (Get-XIOItem -UriString $UriObject).$UriObject | ForEach-Object{(Invoke-RestMethod -Method Get -Uri ($Global:XIOAPIBaseUri + $UriString + '?name=' + ($_.Name)) -Headers $Global:XIOAPIHeaders).Content}    
                }
            }
            #>
            (Invoke-RestMethod -Method Get -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders).content
            
        }
        # No parameters passed return details of all target groups
        if($PSCmdlet.ParameterSetName -eq 'AllConsistencyGroups'){
            $UriString = ($UriObject + '/')
            (Get-XIOItem -UriString $UriObject).$UriObject | ForEach-Object{(Invoke-RestMethod -Method Get -Uri ($Global:XIOAPIBaseUri + $UriString + '?name=' + ($_.Name)) -Headers $Global:XIOAPIHeaders).Content}    
        }
    }


} # Get-XIOConsistencyGroup

# .ExternalHelp MTSXtremIO.psm1-Help.xml
function Get-XIOConsistencyGroupVolume{
[CmdletBinding(DefaultParameterSetName='AllCGVolumes')]
param ( [Parameter(Mandatory=$true,
                   ValueFromPipeline=$true,
                   Position=0, 
                   ParameterSetName='CGVolumesByName')]
        [Alias('n')] 
        [string]$Name,
        [Parameter(Mandatory=$true,ParameterSetName='CGVOlumesByIndex')]
        [Alias('i')] 
        [string]$ID
)

    Begin{
        $UriObject = 'consistency-group-volumes'
    }
    Process{
        
        # Return details of target group by name passed by parameter or pipeline
        if($Name){
            $UriString = ($UriObject + '/?name=' + $Name)
            (Invoke-RestMethod -Method Get -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders).content
        }
    }
    End{
        # Return detail of specific target group by ID   
        if($ID){
            $UriString = ($UriObject + '/' + $ID)
            (Invoke-RestMethod -Method Get -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders).content
        }
        # No parameters passed return details of all target groups
        if($PSCmdlet.ParameterSetName -eq 'AllCGVolumes'){
            $UriString = ($UriObject + '/')
            (Get-XIOItem -UriString $UriObject).$UriObject | ForEach-Object{(Invoke-RestMethod -Method Get -Uri ($Global:XIOAPIBaseUri + $UriString + '?name=' + ($_.Name)) -Headers $Global:XIOAPIHeaders).Content}
        }
    }

    # TODO - Add multiple cluster support

} # Get-XIOConsistencyGroupVolume

# .ExternalHelp MTSXtremIO.psm1-Help.xml
function Get-XIOIscsiPortal{
[CmdletBinding(DefaultParameterSetName='AllISCSIPortals')]
param ( [Parameter(Mandatory=$true,
                   ValueFromPipeline=$true,
                   ValueFromPipelineByPropertyName=$true,
                   Position=0, 
                   ParameterSetName='IsPortalByName')]
        [Alias('n')] 
        [string]$Name,
        [Parameter(Mandatory=$true,ParameterSetName='IsPortalByIndex')]
        [Alias('i')] 
        [string]$ID
)
    Begin{
        $UriObject = 'iscsi-portals'
    }
    Process{
        # Return details of iscsi portal by name passed by parameter or pipeline                
        if($Name){
            $UriString = ($UriObject + '/?name=' + $Name)
            (Invoke-RestMethod -Method Get -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders).content
        }
    }
    End{
        # Return detail of specific iscsi portal by ID
        if($ID){ 
            $UriString = ($UriObject + '/' + $ID)
            (Invoke-RestMethod -Method Get -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders).content
        }
        # No parameters passed return details of all iscsi portals
        if($PSCmdlet.ParameterSetName -eq 'AllISCSIPortals'){
            $UriString = ($UriObject + '/')
            (Get-XIOItem -UriString $UriObject).$UriObject | ForEach-Object{(Invoke-RestMethod -Method Get -Uri ($Global:XIOAPIBaseUri + $UriString + '?name=' + ($_.Name)) -Headers $Global:XIOAPIHeaders).Content}
        }
    }

    # TODO - Add multiple cluster support

} # Get-XIOIscsiPortal

# .ExternalHelp MTSXtremIO.psm1-Help.xml
function Get-XIOIscsiRoute{
[CmdletBinding(DefaultParameterSetName='AllISCSIRoutes')]
param ( [Parameter(Mandatory=$true,
                   ValueFromPipeline=$true,
                   Position=0, 
                   ParameterSetName='IsRouteByName')]
        [Alias('n')] 
        [string]$Name=$null,
        [Parameter(Mandatory=$true,ParameterSetName='IsRouteByIndex')]
        [Alias('i')] 
        [string]$ID=$null
)

    Begin{
        $UriObject = 'iscsi-routes'
    }
    Process{
        # Return details of iscsi route by name passed by parameter or pipeline           
        if($Name){
            $UriString = ($UriObject + '/?name=' + $Name)
            (Invoke-RestMethod -Method Get -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders).content
        }
    }
    End{
        # Return detail of specific iscsi route by ID
        if($ID){
            $UriString = ($UriObject + '/' + $ID)
            (Invoke-RestMethod -Method Get -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders).content
        }
        # No parameters passed return details of all iscsi routes
        if($PSCmdlet.ParameterSetName -eq 'AllISCSIRoutes'){
            $UriString = ($UriObject + '/')
            (Get-XIOItem -UriString $UriObject).$UriObject | ForEach-Object{(Invoke-RestMethod -Method Get -Uri ($Global:XIOAPIBaseUri + $UriString + '?name=' + ($_.Name)) -Headers $Global:XIOAPIHeaders).Content}
        }
    }

    # TODO - Add multiple cluster support

} # Get-XIOIscsiRoute

# .ExternalHelp MTSXtremIO.psm1-Help.xml
function Get-XIOLunMap{
[CmdletBinding(DefaultParameterSetName='AllLunMaps')]
param ( [Parameter(Mandatory=$true,
                   ValueFromPipeline=$true,
                   Position=0, 
                   ParameterSetName='LunMapByName')]
        [Alias('n')] 
        [string]$Name=$null,
        [Parameter(Mandatory=$true,ParameterSetName='LunMapByIndex')]
        [Alias('i')] 
        [string]$ID=$null
)

    Begin{
        $UriObject = 'lun-maps'
    }
    Process{
        # Return details of lun map by name passed by parameter or pipeline                
        if($Name){
            $UriString = ($UriObject + '/?name=' + $Name)
            (Invoke-RestMethod -Method Get -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders).content
        }
    }
    End{
        # Return detail of specific lun map by ID
        if($ID){
            $UriString = ($UriObject + '/' + $ID)
            (Invoke-RestMethod -Method Get -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders).content
        }
        # No parameters passed return details of all lun maps
        if($PSCmdlet.ParameterSetName -eq 'AllLunMaps'){
            $UriString = ($UriObject + '/')
            (Get-XIOItem -UriString $UriObject).$UriObject | ForEach-Object{(Invoke-RestMethod -Method Get -Uri ($Global:XIOAPIBaseUri + $UriString + '?name=' + ($_.Name)) -Headers $Global:XIOAPIHeaders).Content}
        }
    }

    # TODO - Add multiple cluster support

} # Get-XIOLunMap

# .ExternalHelp MTSXtremIO.psm1-Help.xml
function Get-XIOSSD{
[CmdletBinding(DefaultParameterSetName='AllSSDs')]
param ( [Parameter(Mandatory=$true, 
                    ValueFromPipeline=$true,
                    Position=0,
                    ParameterSetName='SSDByName')]
        [Alias('n')] 
        [string]$Name=$null,
        [Parameter(Mandatory=$true,
                    ParameterSetName='SSDByIndex')]
        [Alias('i')] 
        [string]$ID=$null
)
    Begin{
        $UriObject = 'ssds'
    }
    Process{
        # Return details of ssd by name passed by parameter or pipeline
        if($Name){
            $UriString = ($UriObject + '/?name=' + $Name)
            (Invoke-RestMethod -Method Get -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders).content
        }
    }
    End{
        # Return detail of ssd by ID
        if($ID){
                $UriString = ($UriObject + '/' + $ID)
                (Invoke-RestMethod -Method Get -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders).content
            }
        # No parameters passed return details of all ssds
        if($PSCmdlet.ParameterSetName -eq 'AllSSDs'){
            $UriString = ($UriObject + '/')
            (Get-XIOItem -UriString $UriObject).$UriObject | ForEach-Object{(Invoke-RestMethod -Method Get -Uri ($Global:XIOAPIBaseUri + $UriString + '?name=' + ($_.Name)) -Headers $Global:XIOAPIHeaders).Content}
        }
    }

    # TODO - Add multiple cluster support

} # Get-XIOSSD

# .ExternalHelp MTSXtremIO.psm1-Help.xml
function Get-XIOSlot{
[CmdletBinding(DefaultParameterSetName='AllSlots')]
param ()
    
    # No parameters passed return details of all ssds
    if($PSCmdlet.ParameterSetName -eq 'AllSlots'){
        $UriString = 'slots'
        (Get-XIOItem -UriString 'slots').slots | ForEach-Object{(Invoke-RestMethod -Method Get -Uri ($Global:XIOAPIBaseUri + $UriString + '?name=' + ($_.Name)) -Headers $Global:XIOAPIHeaders).Content}
    }
    
} # Get-XIOSlot

# .ExternalHelp MTSXtremIO.psm1-Help.xml
function Get-XIOLocalDisk{
[CmdletBinding(DefaultParameterSetName='AllLocalDisks')]
param ( [Parameter(Mandatory=$true, 
                    ValueFromPipeline=$true,
                    Position=0,
                    ParameterSetName='DisksByName')]
        [Alias('n')] 
        [string]$Name=$null,
        [Parameter(Mandatory=$true,
                    ParameterSetName='DisksByIndex')]
        [Alias('i')] 
        [string]$ID=$null
)
    Begin{
        $UriObject = 'local-disks'
    }
    Process{
        # Return details of local disk by name passed by parameter or pipeline
        if($Name){
            $UriString = ($UriObject + '/?name=' + $Name)
            (Invoke-RestMethod -Method Get -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders).content
        }
    }
    End{
        # Return detail of local disk by ID
        if($ID){
            $UriString = ($UriObject + '/' + $ID)
            (Invoke-RestMethod -Method Get -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders).content
        }
        
        # No parameters passed return details of all local disks
        if($PSCmdlet.ParameterSetName -eq 'AllLocalDisks'){
            $UriString = ($UriObject + '/')
            (Get-XIOItem -UriString $UriObject).$UriObject | ForEach-Object{(Invoke-RestMethod -Method Get -Uri ($Global:XIOAPIBaseUri + $UriString + '?name=' + ($_.Name)) -Headers $Global:XIOAPIHeaders).Content}
        }
    }

    # TODO - Add multiple cluster support

} # Get-XIOLocalDisk

# .ExternalHelp MTSXtremIO.psm1-Help.xml
function Get-XIOBBU{
[CmdletBinding(DefaultParameterSetName='AllBBUs')]
param ( [Parameter(Mandatory=$true, 
                    ValueFromPipeline=$true,
                    Position=0,
                    ParameterSetName='BBUByName')]
        [Alias('n')] 
        [string]$Name=$null,
        [Parameter(Mandatory=$true,
                    ParameterSetName='BBUByIndex')]
        [Alias('i')] 
        [string]$ID=$null
)
    Begin{
        $UriObject = 'bbus'
    }
    Process{
        # Return details of BBU by name passed by parameter or pipeline
        if($Name){
            $UriString = ($UriObject + '/?name=' + $Name)
            (Invoke-RestMethod -Method Get -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders).content
        }
    }
    End{
        # Return detail of BBU by ID
        if($ID){
            $UriString = ($UriObject + '/' + $ID)
            (Invoke-RestMethod -Method Get -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders).content
        }
        
        # No parameters passed return details of all BBUs
        if($PSCmdlet.ParameterSetName -eq 'AllBBUs'){
            $UriString = ($UriObject + '/')
            (Get-XIOItem -UriString $UriObject).$UriObject | ForEach-Object{(Invoke-RestMethod -Method Get -Uri ($Global:XIOAPIBaseUri + $UriString + '?name=' + ($_.Name)) -Headers $Global:XIOAPIHeaders).Content}
        }
    }

    # TODO - Add multiple cluster support

} # Get-XIOBBU

# .ExternalHelp MTSXtremIO.psm1-Help.xml
function Get-XIODAE{
[CmdletBinding(DefaultParameterSetName='AllDAEs')]
param ( [Parameter(Mandatory=$true, 
                    ValueFromPipeline=$true,
                    Position=0,
                    ParameterSetName='DAEByName')]
        [Alias('n')] 
        [string]$Name=$null,
        [Parameter(Mandatory=$true,
                    ParameterSetName='DAEByIndex')]
        [Alias('i')] 
        [string]$ID=$null
)
    Begin{
        $UriObject = 'daes'
    }
    Process{
        # Return details of DAE by name passed by parameter or pipeline
        if($Name){
            $UriString = ($UriObject + '/?name=' + $Name)
            (Invoke-RestMethod -Method Get -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders).content
        }
    }
    End{
        # Return detail of DAE by ID
        if($ID){
            $UriString = ($UriObject + '/' + $ID)
            (Invoke-RestMethod -Method Get -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders).content
        }
        
        # No parameters passed return details of all DAEs
        if($PSCmdlet.ParameterSetName -eq 'AllDAEs'){
            $UriString = ($UriObject + '/')
            (Get-XIOItem -UriString $UriObject).$UriObject | ForEach-Object{(Invoke-RestMethod -Method Get -Uri ($Global:XIOAPIBaseUri + $UriString + '?name=' + ($_.Name)) -Headers $Global:XIOAPIHeaders).Content}
        }
    }

    # TODO - Add multiple cluster support

} # Get-XIODAE

# .ExternalHelp MTSXtremIO.psm1-Help.xml
function Get-XIODAEController{
[CmdletBinding(DefaultParameterSetName='AllDAEControllers')]
param ( [Parameter(Mandatory=$true, 
                    ValueFromPipeline=$true,
                    Position=0,
                    ParameterSetName='DAEControllerByName')]
        [Alias('n')] 
        [string]$Name=$null,
        [Parameter(Mandatory=$true,
                    ParameterSetName='DAEControllerByIndex')]
        [Alias('i')] 
        [string]$ID=$null
)
    Begin{
        $UriObject = 'dae-controllers'
    }
    Process{
        # Return details of DAE Controller by name passed by parameter or pipeline
        if($Name){
            $UriString = ($UriObject + '/?name=' + $Name)
            (Invoke-RestMethod -Method Get -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders).content
        }
    }
    End{
        # Return detail of DAE Controller by ID
        if($ID){
            $UriString = ($UriObject + '/' + $ID)
            (Invoke-RestMethod -Method Get -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders).content
        }
        
        # No parameters passed return details of all DAE Controllers
        if($PSCmdlet.ParameterSetName -eq 'AllDAEControllers'){
            $UriString = ($UriObject + '/')
            (Get-XIOItem -UriString $UriObject).$UriObject | ForEach-Object{(Invoke-RestMethod -Method Get -Uri ($Global:XIOAPIBaseUri + $UriString + '?name=' + ($_.Name)) -Headers $Global:XIOAPIHeaders).Content}
        }
    }

    # TODO - Add multiple cluster support

} # Get-XIODAEController

# .ExternalHelp MTSXtremIO.psm1-Help.xml
function Get-XIODAEPSU{
[CmdletBinding(DefaultParameterSetName='AllDAEPSUs')]
param ( [Parameter(Mandatory=$true, 
                    ValueFromPipeline=$true,
                    Position=0,
                    ParameterSetName='DAEPSUByName')]
        [Alias('n')] 
        [string]$Name=$null,
        [Parameter(Mandatory=$true,
                    ParameterSetName='DAEPSUByIndex')]
        [Alias('i')] 
        [string]$ID=$null
)
    Begin{
        $UriObject = 'dae-psus'
    }
    Process{
        # Return details of DAE PSU by name passed by parameter or pipeline
        if($Name){
            $UriString = ($UriObject + '/?name=' + $Name)
            (Invoke-RestMethod -Method Get -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders).content
        }
    }
    End{
        # Return detail of DAE PSU by ID
        if($ID){
            $UriString = ($UriObject + '/' + $ID)
            (Invoke-RestMethod -Method Get -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders).content
        }
        
        # No parameters passed return details of all DAE PSUs
        if($PSCmdlet.ParameterSetName -eq 'AllDAEPSUs'){
            $UriString = ($UriObject + '/')
            (Get-XIOItem -UriString $UriObject).$UriObject | ForEach-Object{(Invoke-RestMethod -Method Get -Uri ($Global:XIOAPIBaseUri + $UriString + '?name=' + ($_.Name)) -Headers $Global:XIOAPIHeaders).Content}
        }
    }

    # TODO - Add multiple cluster support

} # Get-XIODAEPSU

# .ExternalHelp MTSXtremIO.psm1-Help.xml
function Get-XIOInfinibandSwitch{
[CmdletBinding(DefaultParameterSetName='AllInfinibandSwitches')]
param ( [Parameter(Mandatory=$true, 
                    ValueFromPipeline=$true,
                    Position=0,
                    ParameterSetName='IBSwitchByName')]
        [Alias('n')] 
        [string]$Name=$null,
        [Parameter(Mandatory=$true,
                    ParameterSetName='IBSwitchByIndex')]
        [Alias('i')] 
        [string]$ID=$null
)
    Begin{
        $UriObject = 'infiniband-switches'
    }
    Process{
        # Return details of object by name passed by parameter or pipeline
        if($Name){
            $UriString = ($UriObject + '/?name=' + $Name)
            (Invoke-RestMethod -Method Get -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders).content
        }
    }
    End{
        # Return detail of object by ID
        if($ID){
            $UriString = ($UriObject + '/' + $ID)
            (Invoke-RestMethod -Method Get -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders).content
        }
        
        # No parameters passed return details of all objects
        if($PSCmdlet.ParameterSetName -eq 'AllInfinibandSwitches'){
            $UriString = ($UriObject + '/')
            (Get-XIOItem -UriString $UriObject).$UriObject | ForEach-Object{(Invoke-RestMethod -Method Get -Uri ($Global:XIOAPIBaseUri + $UriString + '?name=' + ($_.Name)) -Headers $Global:XIOAPIHeaders).Content}
        }
    }

    # TODO - Add multiple cluster support

} # Get-XIOInfinibandSwitch

# .ExternalHelp MTSXtremIO.psm1-Help.xml
function Get-XIOLDAPConfiguration{
[CmdletBinding(DefaultParameterSetName='AllLDAPConfigs')]
param ( [Parameter(Mandatory=$true, 
                    ValueFromPipeline=$true,
                    Position=0,
                    ParameterSetName='LDAPConfigByName')]
        [Alias('n')] 
        [string]$Name=$null,
        [Parameter(Mandatory=$true,
                    ParameterSetName='LDAPConfigByIndex')]
        [Alias('i')] 
        [string]$ID=$null
)
    Begin{
        $UriObject = 'ldap-configs'
    }
    Process{
        # Return details of object by name passed by parameter or pipeline
        if($Name){
            $UriString = ($UriObject + '/?name=' + $Name)
            (Invoke-RestMethod -Method Get -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders).content
        }
    }
    End{
        # Return detail of object by ID
        if($ID){
            $UriString = ($UriObject + '/' + $ID)
            (Invoke-RestMethod -Method Get -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders).content
        }
        
        # No parameters passed return details of all objects
        if($PSCmdlet.ParameterSetName -eq 'AllLDAPConfigs'){
            $UriString = ($UriObject + '/')
            (Get-XIOItem -UriString $UriObject).$UriObject | ForEach-Object{(Invoke-RestMethod -Method Get -Uri ($Global:XIOAPIBaseUri + $UriString + '?name=' + ($_.Name)) -Headers $Global:XIOAPIHeaders).Content}
        }
    }

    # TODO - Add multiple cluster support

} # Get-XIOLDAPConfiguration

# .ExternalHelp MTSXtremIO.psm1-Help.xml
function Get-XIOAlert{
[CmdletBinding(DefaultParameterSetName='AllAlerts')]
param ( [Parameter(Mandatory=$true, 
                    ValueFromPipeline=$true,
                    Position=0,
                    ParameterSetName='AlertByName')]
        [Alias('n')] 
        [string]$Name=$null,
        [Parameter(Mandatory=$true,
                    ParameterSetName='AlertByIndex')]
        [Alias('i')] 
        [string]$ID=$null
)
    Begin{
        $UriObject = 'alerts'
    }
    Process{
        # Return details of object by name passed by parameter or pipeline
        if($Name){
            $UriString = ($UriObject + '/?name=' + $Name)
            (Invoke-RestMethod -Method Get -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders).content
        }
    }
    End{
        # Return detail of object by ID
        if($ID){
            $UriString = ($UriObject + '/' + $ID)
            (Invoke-RestMethod -Method Get -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders).content
        }
        
        # No parameters passed return details of all objects
        if($PSCmdlet.ParameterSetName -eq 'AllAlerts'){
            $UriString = ($UriObject + '/')
            (Get-XIOItem -UriString $UriObject).$UriObject | ForEach-Object{(Invoke-RestMethod -Method Get -Uri ($Global:XIOAPIBaseUri + $UriString + '?name=' + ($_.Name)) -Headers $Global:XIOAPIHeaders).Content}
        }
    }

} # Get-XIOAlert

# .ExternalHelp MTSXtremIO.psm1-Help.xml
function Get-XIOAlertDefinition{
[CmdletBinding(DefaultParameterSetName='AllAlertDefinitions')]
param ( [Parameter(Mandatory=$true, 
                    ValueFromPipeline=$true,
                    Position=0,
                    ParameterSetName='AlertByName')]
        [Alias('n')] 
        [string]$Name=$null,
        [Parameter(Mandatory=$true,
                    ParameterSetName='AlertByIndex')]
        [Alias('i')] 
        [string]$ID=$null
)
    Begin{
        $UriObject = 'alert-definitions'
    }
    Process{
        # Return details of object by name passed by parameter or pipeline
        if($Name){
            $UriString = ($UriObject + '/?name=' + $Name)
            (Invoke-RestMethod -Method Get -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders).content
        }
    }
    End{
        # Return detail of object by ID
        if($ID){
            $UriString = ($UriObject + '/' + $ID)
            (Invoke-RestMethod -Method Get -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders).content
        }
        
        # No parameters passed return details of all objects
        if($PSCmdlet.ParameterSetName -eq 'AllAlertDefinitions'){
            $UriString = ($UriObject + '/')
            (Get-XIOItem -UriString $UriObject).$UriObject | ForEach-Object{(Invoke-RestMethod -Method Get -Uri ($Global:XIOAPIBaseUri + $UriString + '?name=' + ($_.Name)) -Headers $Global:XIOAPIHeaders).Content}
        }
    }

} # Get-XIOAlertDefinition

# .ExternalHelp MTSXtremIO.psm1-Help.xml
function Get-XIOEmailNotifier{
[CmdletBinding(DefaultParameterSetName='AllEmailNotifiers')]
param ( [Parameter(Mandatory=$true, 
                    ValueFromPipeline=$true,
                    Position=0,
                    ParameterSetName='ENotifyByName')]
        [Alias('n')] 
        [string]$Name=$null,
        [Parameter(Mandatory=$true,
                    ParameterSetName='ENotifyByIndex')]
        [Alias('i')] 
        [string]$ID=$null
)
    Begin{
        $UriObject = 'email-notifier'
    }
    Process{
        # Return details of object by name passed by parameter or pipeline
        if($Name){
            $UriString = ($UriObject + '/?name=' + $Name)
            (Invoke-RestMethod -Method Get -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders).content
        }
    }
    End{
        # Return detail of object by ID
        if($ID){
            $UriString = ($UriObject + '/' + $ID)
            (Invoke-RestMethod -Method Get -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders).content
        }
        
        # No parameters passed return details of all objects
        if($PSCmdlet.ParameterSetName -eq 'AllEmailNotifiers'){
            $UriString = ($UriObject + '/')
            (Get-XIOItem -UriString $UriObject).$UriObject | ForEach-Object{(Invoke-RestMethod -Method Get -Uri ($Global:XIOAPIBaseUri + $UriString + '?name=' + ($_.Name)) -Headers $Global:XIOAPIHeaders).Content}
        }
    }

} # Get-XIOEmailNotifier

# .ExternalHelp MTSXtremIO.psm1-Help.xml
function Get-XIOSNMPNotifier{
[CmdletBinding(DefaultParameterSetName='AllSNMPNotifiers')]
param ( [Parameter(Mandatory=$true, 
                    ValueFromPipeline=$true,
                    Position=0,
                    ParameterSetName='SNMPNotifyByName')]
        [Alias('n')] 
        [string]$Name=$null,
        [Parameter(Mandatory=$true,
                    ParameterSetName='SNMPNotifyByIndex')]
        [Alias('i')] 
        [string]$ID=$null
)
    Begin{
        $UriObject = 'snmp-notifier'
    }
    Process{
        # Return details of object by name passed by parameter or pipeline
        if($Name){
            $UriString = ($UriObject + '/?name=' + $Name)
            (Invoke-RestMethod -Method Get -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders).content
        }
    }
    End{
        # Return detail of object by ID
        if($ID){
            $UriString = ($UriObject + '/' + $ID)
            (Invoke-RestMethod -Method Get -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders).content
        }
        
        # No parameters passed return details of all objects
        if($PSCmdlet.ParameterSetName -eq 'AllSNMPNotifiers'){
            $UriString = ($UriObject + '/')
            (Get-XIOItem -UriString $UriObject).$UriObject | ForEach-Object{(Invoke-RestMethod -Method Get -Uri ($Global:XIOAPIBaseUri + $UriString + '?name=' + ($_.Name)) -Headers $Global:XIOAPIHeaders).Content}
        }
    }

} # Get-XIOSNMPNotifier

# .ExternalHelp MTSXtremIO.psm1-Help.xml
function Get-XIOSYRNotifier{
[CmdletBinding(DefaultParameterSetName='AllSYRNotifiers')]
param ( [Parameter(Mandatory=$true, 
                    ValueFromPipeline=$true,
                    Position=0,
                    ParameterSetName='SYRNotifyByName')]
        [Alias('n')] 
        [string]$Name=$null,
        [Parameter(Mandatory=$true,
                    ParameterSetName='SYRNotifyByIndex')]
        [Alias('i')] 
        [string]$ID=$null
)
    Begin{
        $UriObject = 'syr-notifier'
    }
    Process{
        # Return details of object by name passed by parameter or pipeline
        if($Name){
            $UriString = ($UriObject + '/?name=' + $Name)
            (Invoke-RestMethod -Method Get -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders).content
        }
    }
    End{
        # Return detail of object by ID
        if($ID){
            $UriString = ($UriObject + '/' + $ID)
            (Invoke-RestMethod -Method Get -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders).content
        }
        
        # No parameters passed return details of all objects
        if($PSCmdlet.ParameterSetName -eq 'AllSYRNotifiers'){
            $UriString = ($UriObject + '/')
            (Get-XIOItem -UriString $UriObject).$UriObject | ForEach-Object{(Invoke-RestMethod -Method Get -Uri ($Global:XIOAPIBaseUri + $UriString + '?name=' + ($_.Name)) -Headers $Global:XIOAPIHeaders).Content}
        }
    }

} # Get-XIOSYRNotifier

# .ExternalHelp MTSXtremIO.psm1-Help.xml
function Get-XIOSyslogNotifier{
[CmdletBinding(DefaultParameterSetName='AllSyslogNotifiers')]
param ( [Parameter(Mandatory=$true, 
                    ValueFromPipeline=$true,
                    Position=0,
                    ParameterSetName='SyslogNotifyByName')]
        [Alias('n')] 
        [string]$Name=$null,
        [Parameter(Mandatory=$true,
                    ParameterSetName='SyslogNotifyByIndex')]
        [Alias('i')] 
        [string]$ID=$null
)
    Begin{
        $UriObject = 'syslog-notifier'
    }
    Process{
        # Return details of object by name passed by parameter or pipeline
        if($Name){
            $UriString = ($UriObject + '/?name=' + $Name)
            (Invoke-RestMethod -Method Get -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders).content
        }
    }
    End{
        # Return detail of object by ID
        if($ID){
            $UriString = ($UriObject + '/' + $ID)
            (Invoke-RestMethod -Method Get -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders).content
        }
        
        # No parameters passed return details of all objects
        if($PSCmdlet.ParameterSetName -eq 'AllSyslogNotifiers'){
            $UriString = ($UriObject + '/')
            (Get-XIOItem -UriString $UriObject).$UriObject | ForEach-Object{(Invoke-RestMethod -Method Get -Uri ($Global:XIOAPIBaseUri + $UriString + '?name=' + ($_.Name)) -Headers $Global:XIOAPIHeaders).Content}
        }
    }

} # Get-XIOSyslogNotifier

# .ExternalHelp MTSXtremIO.psm1-Help.xml
function Get-XIOEvent{
[CmdletBinding(DefaultParameterSetName='AllEvents')]
param ( [Parameter(Mandatory=$true,
                    ParameterSetName='EventsByDateTime')]
        [ValidateNotNull()]
        [Alias('f')] 
        [Alias('From')]
        [datetime]$FromDateTime,
        [Parameter(Mandatory=$true,
                    ParameterSetName='EventsByDateTime')]
        [ValidateNotNull()]
        [Alias('t')] 
        [Alias('To')]
        [datetime]$ToDateTime
)
    
    $UriString = 'events/'
    # Return events by from date and time
    if($FromDateTime){
        $UriString += ('from-date-time="' + ($FromDateTime.ToString('u').Replace('Z',[string]::Empty)) + '"')
        if($ToDateTime){
            $UriString += ('?to-date-time="' + ($ToDateTime.ToString('u').Replace('Z',[string]::Empty)) + '"')   
        }
    }
    else{
        # Return events by to date and time
        if($ToDateTime){
            $UriString += ('to-date-time="' + ($ToDateTime.ToString('u').Replace('Z',[string]::Empty)) + '"')   
        }
    }
    # No parameters passed return details of all events
    if($PSCmdlet.ParameterSetName -eq 'AllEvents'){
        (Get-XIOItem -UriString 'events').events
    }
    else{
        (Invoke-RestMethod -Method Get -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders).events
    }

    # TODO - Need to revist this after feedback from EMC on from and to behavior. From does not seem to work and all requests appear to retrieve 504 records
    
} # Get-XIOEvent


# New functions
# .ExternalHelp MTSXtremIO.psm1-Help.xml
function New-XIOUserAccount{
[CmdletBinding()]
param ( [Parameter(Mandatory=$true,
                    ValueFromPipeline=$true, 
                    Position=0)] 
        [Alias('n')]
        [string]$Name,
        [Parameter(Mandatory=$true)] 
        [ValidateSet('read_only','admin','configuration','technician')]
        [Alias('r')]
        [string]$Role,
        [Parameter(Mandatory=$false)]
        [ValidateNotNull()]
        [Alias('t')] 
        [int]$TimeoutMins,
        [Parameter(Mandatory=$true,ParameterSetName='AuthByPwd')]
        [Alias('pw')] 
        [string]$Password,
        [Parameter(Mandatory=$true,ParameterSetName='AuthByKey')]
        [Alias('pk')] 
        [string]$PublicKey
)
    Begin{

        $UriObject = 'user-accounts'
    }
    Process{

        $UriString = $UriObject
        $JSoNBody = New-Object -TypeName psobject

        # Required Parameters
        $JSoNBody | Add-Member -MemberType NoteProperty -Name usr-name -Value $Name
        $JSoNBody | Add-Member -MemberType NoteProperty -Name role -Value $Role
        
        # Optional Parameters
        if($TimeoutMins){$JSoNBody | Add-Member -MemberType NoteProperty -Name inactivity-timeout -Value $TimeoutMins}
        if($Password){$JSoNBody | Add-Member -MemberType NoteProperty -Name password -Value $Password}
        if($PublicKey){$JSoNBody | Add-Member -MemberType NoteProperty -Name public-key -Value $PublicKey}    

        Invoke-RestMethod -Method Post -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders -Body ($JSoNBody | ConvertTo-Json)

    }
    
} # New-XIOUserAccount

# .ExternalHelp MTSXtremIO.psm1-Help.xml
function New-XIOTag{
[CmdletBinding()]
param ( [Parameter(Mandatory=$true, 
                    ValueFromPipeline=$true,
                    Position=0)]
        [Alias('n')] 
        [string]$Name,
        [Parameter(Mandatory=$true)]
        [ValidateSet('Volume','ConsistencyGroup','Snapshot','SnapshotSet','InitiatorGroup','Initiator','Scheduler')]
        [Alias('t')] 
        [string]$Type,
        [Parameter(Mandatory=$false)]
        [Alias('o')] 
        [string]$ObjectName
)
    Begin{
        $UriObject = 'tags'
    }
    Process{
        $UriString = $UriObject
        $JSoNBody = New-Object -TypeName psobject
        $JSoNBody | Add-Member -MemberType NoteProperty -Name entity -Value $Type
        $JSoNBody | Add-Member -MemberType NoteProperty -Name tag-name -Value $Name
        if($ObjectName){$JSoNBody | Add-Member -MemberType NoteProperty -Name entity-details -Value $ObjectName}        

        (Invoke-RestMethod -Method Post -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders -Body ($JSoNBody | ConvertTo-Json)).Links
    }

    # Note - EMC Documentation appears to be incorrect entity-details is only required when assigning tag but is optional
    
} # New-XIOTag

# .ExternalHelp MTSXtremIO.psm1-Help.xml
function New-XIOVolume{
[CmdletBinding()]
param ( [Parameter(Mandatory=$false, 
                    ValueFromPipeline=$true,
                    Position=0)]
        [ValidateNotNullOrEmpty()]
        [Alias('n')] 
        [Alias('vn')]
        [Alias('VolName')]
        [string]$Name,
        [Parameter(Mandatory=$true)]
        [Alias('s')]
        [Alias('vs')]
        [Alias('VolSize')]
        [string]$Size,
        [Parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [ValidateSet('0','1','2','3','4','5','6','7')]
        [Alias('of')] 
        [string]$Offset=$null,
        [Parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [ValidateSet('512','4096')]
        [Alias('lbs')] 
        [string]$LBSize=$null,
        [Parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [Alias('sid')] 
        [string]$SysID=$null,
        [Parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [Alias('pf')] 
        [string]$ParentFolderID=$null
)
    Begin{
        $UriObject = 'volumes'
    }
    Process{
        $UriString = $UriObject
        $JSoNBody = New-Object -TypeName psobject
        $JSoNBody | Add-Member -MemberType NoteProperty -Name vol-size -Value $Size 
        if($Name){$JSoNBody | Add-Member -MemberType NoteProperty -Name vol-name -Value $Name}
        if($LBSize){
            switch ($LBSize)
            {
                '512' {
                    $JSoNBody | Add-Member -MemberType NoteProperty -Name lb-size -Value $LBSize
                    if($Offset){$JSoNBody | Add-Member -MemberType NoteProperty -Name alignment-offset -Value $Offset}
                }
                '4096' {
                    $JSoNBody | Add-Member -MemberType NoteProperty -Name lb-size -Value $LBSize
                }
            }
        }
        if($SysID){$JSoNBody | Add-Member -MemberType NoteProperty -Name sys-id -Value $SysID}
        if($ParentFolderID){$JSoNBody | Add-Member -MemberType NoteProperty -Name parent-folder-id -Value $ParentFolderID}

        Invoke-RestMethod -Method Post -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders -Body ($JSoNBody | ConvertTo-Json)
    }
} # New-XIOVolume

# .ExternalHelp MTSXtremIO.psm1-Help.xml
function New-XIOSnapshot{
[CmdletBinding()]
param ( [Parameter(Mandatory=$true,ParameterSetName='SnapByCG')]
        [Alias('cid')]
        [Int]$CGID,
        [Parameter(Mandatory=$true,ParameterSetName='SnapBySet')]
        [Alias('ssid')]
        [int]$SnapSetID,
        [Parameter(Mandatory=$true,ParameterSetName='SnapByVol')]
        [Alias('vl')] 
        [string[]]$VolList,
        [Parameter(Mandatory=$true,ParameterSetName='SnapByTag')]
        [Alias('tl')]
        [string[]]$TagList,
        [Parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [Alias('sfx')]
        [string]$SnapSuffix,
        [Parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [Alias('ssn')]
        [string]$SnapSetName,
        [Parameter(Mandatory=$false)]
        [ValidateSet('ReadWrite','ReadOnly')]
        [Alias('st')]
        [string]$SnapType
)

    $UriString = 'snapshots'
    $JSoNBody = New-Object -TypeName psobject
    if($CGID){$JSoNBody | Add-Member -MemberType NoteProperty -Name consistency-group-id -Value $CGID}        
    if($SnapSetID){$JSoNBody | Add-Member -MemberType NoteProperty -Name snapshot-set-id -Value $SnapSetID}
    if($VolList){$JSoNBody | Add-Member -MemberType NoteProperty -Name volume-list -Value $VolList}
    if($TagList){$JSoNBody | Add-Member -MemberType NoteProperty -Name tag-list -Value $TagList}
    if($SnapSuffix){$JSoNBody | Add-Member -MemberType NoteProperty -Name snap-suffix -Value $SnapSuffix}
    if($SnapSetName){$JSoNBody | Add-Member -MemberType NoteProperty -Name snapshot-set-name -Value $SnapSetName}
    if($SnapType){$JSoNBody | Add-Member -MemberType NoteProperty -Name snapshot-type -Value $SnapType}


    $JSoNBody | ConvertTo-Json


    Invoke-RestMethod -Method Post -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders -Body ($JSoNBody | ConvertTo-Json)
            
    
    # TODO - Does not implement REST API functionality to complete snapshot of set of volumes, but easily done using PowerShell features
    # TODO - Add multiple cluster support

} # New-XIOSnapshot

# .ExternalHelp MTSXtremIO.psm1-Help.xml
function New-XIOScheduler{
[CmdletBinding()]
param ( [Parameter(Mandatory=$true,ParameterSetName='KeepNumber')]
        [Alias('skn')]
        [int]$SnapsToKeepNumber,
        [Parameter(Mandatory=$true,ParameterSetName='KeepTime')] 
        [Alias('skt')]
        [string]$SnapsToKeepTime,
        [Parameter(Mandatory=$true,ParameterSetName='KeepNumber')]
        [Parameter(ParameterSetName='KeepTime')] 
        [ValidateSet('Interval','Explicit')]
        [Alias('st')]
        [string]$SchedulerType,
        [Parameter(Mandatory=$true,ParameterSetName='KeepNumber')]
        [Parameter(ParameterSetName='KeepTime')] 
        [Alias('oi')]
        [string]$ObjectID,
        [Parameter(Mandatory=$true,ParameterSetName='KeepNumber')]
        [Parameter(ParameterSetName='KeepTime')] 
        [ValidateSet('Volume','SnapshotSet','TagList','ConsistencyGroup')]
        [Alias('ot')]
        [string]$ObjectType,
        [Parameter(Mandatory=$true,ParameterSetName='KeepNumber')]
        [Parameter(ParameterSetName='KeepTime')] 
        [Alias('t')]
        [string]$Time,
        [Parameter(Mandatory=$false,ParameterSetName='KeepNumber')]
        [Parameter(ParameterSetName='KeepTime')]
        [ValidateNotNullOrEmpty()]
        [ValidateSet('ReadWrite','ReadOnly')]
        [Alias('snt')] 
        [string]$SnapType,
        [Parameter(Mandatory=$false,ParameterSetName='KeepNumber')]
        [Parameter(ParameterSetName='KeepTime')]
        [ValidateNotNullOrEmpty()]
        [Alias('s')] 
        [string]$Suffix,
        [Parameter(Mandatory=$false,ParameterSetName='KeepNumber')]
        [Parameter(ParameterSetName='KeepTime')]
        [ValidateNotNullOrEmpty()]
        [Alias('c')] 
        $Cluster

)

    $UriString = 'schedulers'
    $JSoNBody = New-Object -TypeName psobject

    # Required Parameters
    $JSoNBody | Add-Member -MemberType NoteProperty -Name scheduler-type -Value $SchedulerType
    $JSoNBody | Add-Member -MemberType NoteProperty -Name snapshot-object-id -Value $ObjectID
    $JSoNBody | Add-Member -MemberType NoteProperty -Name snapshot-object-type -Value $ObjectType
    $JSoNBody | Add-Member -MemberType NoteProperty -Name time -Value $Time

    # Optional Parameters
    if($Suffix){$JSoNBody | Add-Member -MemberType NoteProperty -Name suffix -Value $Suffix}
    if($SnapType){$JSoNBody | Add-Member -MemberType NoteProperty -Name snapshot-type -Value $SnapType}
    if($Cluster){$JSoNBody | Add-Member -MemberType NoteProperty -Name cluster-id -Value $Cluster}
    if($SnapsToKeepNumber){$JSoNBody | Add-Member -MemberType NoteProperty -Name snapshots-to-keep-number -Value $SnapsToKeepNumber}
    if($SnapsToKeepTime){$JSoNBody | Add-Member -MemberType NoteProperty -Name snapshots-to-keep-time -Value $SnapsToKeepTime}
    
    Invoke-RestMethod -Method Post -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders -Body ($JSoNBody | ConvertTo-Json)
    
} # New-XIOScheduler

# .ExternalHelp MTSXtremIO.psm1-Help.xml
function New-XIOInitiator{
[CmdletBinding()]
param ( [Parameter(Mandatory=$true)]
        [Alias('ig')]
        [int]$IgID,
        [Parameter(Mandatory=$true)]
        [Alias('p')]
        [string]$PortAddress,
        [Parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [Alias('n')] 
        [string]$Name,
        [Parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [Alias('cid')] 
        [string]$ClusterID,
        [Parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [Alias('ccau')] 
        [string]$ChapClusterAuthUser,
        [Parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [Alias('ccap')] 
        [string]$ChapClusterAuthPassword,
        [Parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [Alias('ccdu')] 
        [string]$ChapClusterDiscoverUser,
        [Parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [Alias('ccdp')] 
        [string]$ChapClusterDiscoverPassword,
        [Parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [Alias('ciau')] 
        [string]$ChapInitiatorAuthUser,
        [Parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [Alias('ciap')] 
        [string]$ChapInitiatorAuthPassword,
        [Parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [Alias('cidu')] 
        [string]$ChapInitiatorDiscoverUser,
        [Parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [Alias('cidp')] 
        [string]$ChapInitiatorDiscoverPassword



)

    $UriString = 'Initiators'
    $JSoNBody = New-Object -TypeName psobject

    # Required Parameters
    $JSoNBody | Add-Member -MemberType NoteProperty -Name ig-id -Value $IgID
    $JSoNBody | Add-Member -MemberType NoteProperty -Name port-address -Value $PortAddress
    

    # Optional Parameters
    if($Name){$JSoNBody | Add-Member -MemberType NoteProperty -Name initiator-name -Value $Name}
    if($ClusterID){$JSoNBody | Add-Member -MemberType NoteProperty -Name cluster-id -Value $ClusterID}
    if($ChapClusterAuthUser){$JSoNBody | Add-Member -MemberType NoteProperty -Name snapshot-type -Value $ChapClusterAuthUser}
    if($ChapClusterAuthPassword){$JSoNBody | Add-Member -MemberType NoteProperty -Name snapshots-to-keep-number -Value $ChapClusterAuthPassword}
    if($ChapClusterDiscoverUser){$JSoNBody | Add-Member -MemberType NoteProperty -Name snapshots-to-keep-time -Value $ChapClusterDiscoverUser}
    if($ChapClusterDiscoverPassword){$JSoNBody | Add-Member -MemberType NoteProperty -Name snapshots-to-keep-time -Value $ChapClusterDiscoverPassword}
    if($ChapInitiatorAuthUser){$JSoNBody | Add-Member -MemberType NoteProperty -Name snapshot-type -Value $ChapInitiatorAuthUser}
    if($ChapInitiatorAuthPassword){$JSoNBody | Add-Member -MemberType NoteProperty -Name snapshots-to-keep-number -Value $ChapInitiatorAuthPassword}
    if($ChapInitiatorDiscoverUser){$JSoNBody | Add-Member -MemberType NoteProperty -Name snapshots-to-keep-time -Value $ChapInitiatorDiscoverUser}
    if($ChapInitiatorDiscoverPassword){$JSoNBody | Add-Member -MemberType NoteProperty -Name snapshots-to-keep-time -Value $ChapInitiatorDiscoverPassword}
    

    Invoke-RestMethod -Method Post -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders -Body ($JSoNBody | ConvertTo-Json)
    

} # New-XIOInitiator

# .ExternalHelp MTSXtremIO.psm1-Help.xml
function New-XIOInitiatorGroup{
[CmdletBinding()]
param ( [Parameter(Mandatory=$true)]
        [Alias('n')] 
        [string]$Name,
        [Parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [Alias('t')] 
        [string]$InitiatorList,
        [Parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [Alias('p')] 
        [string]$ParentTag,
        [Parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [Alias('c')] 
        $Cluster
)
    
        $UriString = 'initiator-groups'
        $JSoNBody = New-Object -TypeName psobject

        # Required Parameters
        $JSoNBody | Add-Member -MemberType NoteProperty -Name ig-name -Value $Name

        # Optional Parameters
        if($Cluster){$JSoNBody | Add-Member -MemberType NoteProperty -Name cluster-id -Value $Cluster}
        if($InitiatorList){$JSoNBody | Add-Member -MemberType NoteProperty -Name initiator-list -Value $InitiatorList}
        if($ParentTag){$JSoNBody | Add-Member -MemberType NoteProperty -Name parent-tag-id -Value $ParentTag}

        (Invoke-RestMethod -Method Post -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders -Body ($JSoNBody | ConvertTo-Json)).Links
        

} # New-XIOInitiatorGroup

# .ExternalHelp MTSXtremIO.psm1-Help.xml
function New-XIOConsistencyGroup{
[CmdletBinding()]
param ( [Parameter(Mandatory=$true)]
        [Alias('n')] 
        [string]$Name,
        [Parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [Alias('t')] 
        [string[]]$TagList,
        [Parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [Alias('v')] 
        [string[]]$VolList,
        [Parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [Alias('c')] 
        $Cluster
)
    
        $UriString = 'consistency-groups'
        $JSoNBody = New-Object -TypeName psobject

        # Required Parameters
        $JSoNBody | Add-Member -MemberType NoteProperty -Name consistency-group-name -Value $Name

        # Optional Parameters
        if($Cluster){$JSoNBody | Add-Member -MemberType NoteProperty -Name cluster-id -Value $Cluster}
        if($VolList){$JSoNBody | Add-Member -MemberType NoteProperty -Name vol-list -Value $VolList}
        if($TagList){$JSoNBody | Add-Member -MemberType NoteProperty -Name tag-list -Value $TagList}

        (Invoke-RestMethod -Method Post -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders -Body ($JSoNBody | ConvertTo-Json)).Links
        

} # New-XIOConsistencyGroup

# .ExternalHelp MTSXtremIO.psm1-Help.xml
function New-XIOIscsiPortal{
[CmdletBinding()]
param ( [Parameter(Mandatory=$true,ParameterSetName='TargetByName',
                    ValueFromPipeline=$true, 
                    Position=0)] 
        [Alias('n')]
        [string]$Name,
        [Parameter(Mandatory=$true,ParameterSetName='TargetByID')] 
        [Alias('i')]
        [string]$ID,
        [Parameter(Mandatory=$true)]
        [ValidateNotNull()]
        [Alias('ip')] 
        [int]$IPAddress,
        [Parameter(Mandatory=$false)]
        [ValidateNotNull()]
        [Alias('v')] 
        [int]$Vlan,
        [Parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [Alias('c')] 
        $Cluster
)
    Begin{
        $UriObject = 'iscsi-portals'
    }
    Process{
        if($Name){
            $UriString = $UriObject
            $JSoNBody = New-Object -TypeName psobject

            # Required Parameters
            $JSoNBody | Add-Member -MemberType NoteProperty -Name tar-id -Value $Name
            $JSoNBody | Add-Member -MemberType NoteProperty -Name ip-addr -Value $IPAddress
        
            # Optional Parameters
            if($Vlan){$JSoNBody | Add-Member -MemberType NoteProperty -Name vlan -Value $Vlan}
            if($Cluster){$JSoNBody | Add-Member -MemberType NoteProperty -Name cluster-id -Value $Cluster}
            
            Invoke-RestMethod -Method Post -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders -Body ($JSoNBody | ConvertTo-Json)
        }
    }
    End{
        if($ID){
            
            $UriString = $UriObject
            $JSoNBody = New-Object -TypeName psobject

            # Required Parameters
            $JSoNBody | Add-Member -MemberType NoteProperty -Name tar-id -Value $ID
            $JSoNBody | Add-Member -MemberType NoteProperty -Name ip-addr -Value $IPAddress
        
            # Optional Parameters
            if($Vlan){$JSoNBody | Add-Member -MemberType NoteProperty -Name vlan -Value $Vlan}
            if($Cluster){$JSoNBody | Add-Member -MemberType NoteProperty -Name cluster-id -Value $Cluster}
            
            Invoke-RestMethod -Method Post -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders -Body ($JSoNBody | ConvertTo-Json)
        }
    }
} # New-XIOIscsiPortal

# .ExternalHelp MTSXtremIO.psm1-Help.xml
function New-XIOIscsiRoute{
[CmdletBinding()]
param ( [Parameter(Mandatory=$true)] 
        [Alias('dn')]
        [string]$DestNetwok,
        [Parameter(Mandatory=$true)] 
        [Alias('g')]
        [string]$Gateway,
        [Parameter(Mandatory=$false)]
        [ValidateNotNull()]
        [Alias('n')] 
        [int]$Name

)

    $UriObject = 'iscsi-routes'
    
    $UriString = $UriObject
    $JSoNBody = New-Object -TypeName psobject

    # Required Parameters
    $JSoNBody | Add-Member -MemberType NoteProperty -Name destination-network-and-mask -Value $DestNetwok
    $JSoNBody | Add-Member -MemberType NoteProperty -Name gateway -Value $Gateway
        
    # Optional Parameters
    if($Name){$JSoNBody | Add-Member -MemberType NoteProperty -Name iscsi-route-name -Value $Name}
               

    Invoke-RestMethod -Method Post -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders -Body ($JSoNBody | ConvertTo-Json)

    # TODO - Add multiple cluster support
    
} # New-XIOIscsiRoute

# .ExternalHelp MTSXtremIO.psm1-Help.xml
function New-XIOLunMap{
[CmdletBinding()]
param ( [Parameter(Mandatory=$true,
                    ValueFromPipeline=$true, 
                    Position=0,
                    ParameterSetName='VolByName')]
        [Alias('n')] 
        [string]$Name,
        [Parameter(Mandatory=$true,ParameterSetName='VolByID')]
        [Alias('i')] 
        [int]$ID,
        [Parameter(Mandatory=$true)]
        [ValidateNotNull()]
        [Alias('ig')] 
        $InitiatorGroup,
        [Parameter(Mandatory=$false)]
        [ValidateNotNull()]
        [Alias('hi')] 
        [int]$HostID,
        [Parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [Alias('tgn')] 
        $TargetGroup
)
        Begin{
            $UriString = 'lun-maps'
        }
        Process{
            
            $JSoNBody = New-Object -TypeName psobject
            if($Name){$JSoNBody | Add-Member -MemberType NoteProperty -Name vol-id -Value $Name} # Note error in EMC documentation - specified vol-name as parameter but vol-id must be used with string as type
            if($ID){$JSoNBody | Add-Member -MemberType NoteProperty -Name vol-id -Value $ID}
            if($InitiatorGroup){$JSoNBody | Add-Member -MemberType NoteProperty -Name ig-id -Value $InitiatorGroup} # Note error in EMC documentation - specifies name or id can be used but only ID appears to work
            if($HostID){$JSoNBody | Add-Member -MemberType NoteProperty -Name lun -Value $HostID}
            if($TargetGroup){$JSoNBody | Add-Member -MemberType NoteProperty -Name tg-id -Value $TargetGroup}
            
            Invoke-RestMethod -Method Post -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders -Body ($JSoNBody | ConvertTo-Json)


        }

} # New-XIOLunMap


# Add, Set, Update functions
# .ExternalHelp MTSXtremIO.psm1-Help.xml
function Set-XIOTag{
[CmdletBinding()]
param ( [Parameter(Mandatory=$true)]
        [Alias('n')] 
        [string]$Name,
        [Parameter(Mandatory=$true)]
        [Alias('nn')] 
        [string]$NewName,
        [Parameter(Mandatory=$false)]
        [ValidateNotNull()]
        [Alias('x')] 
        [string]$XmsID
       )
    
    $UriObject = 'tags'
    
    $UriString = ($UriObject + '/?name=' + $Name)
    $JSoNBody = New-Object -TypeName psobject
    $JSoNBody | Add-Member -MemberType NoteProperty -Name caption -Value $NewName
    if($XmsID){$JSoNBody | Add-Member -MemberType NoteProperty -Name xms-id -Value $XmsID}

    Invoke-RestMethod -Method Put -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders -Body ($JSoNBody | ConvertTo-Json)

} # Set-XIOTag

# .ExternalHelp MTSXtremIO.psm1-Help.xml
function Set-XIOVolume{
[CmdletBinding()]
param ( [Parameter(Mandatory=$true,ParameterSetName='VolUpdateByName',
                    ValueFromPipelineByPropertyName=$true)]
        [Parameter(ParameterSetName='VolNameUpdate')]
        [Parameter(ParameterSetName='VolSizeUpdate')]
        [Parameter(ParameterSetName='SmallIOAlertUpdate')]
        [Parameter(ParameterSetName='UnalignedIOAlertUpdate')]
        [Parameter(ParameterSetName='VAAITPAlertUpdate')]
        [string]$Name,
        [Parameter(Mandatory=$true,ParameterSetName='VolUpdateByIndex')]
        [Parameter(ParameterSetName='VolNameUpdate')]
        [Parameter(ParameterSetName='VolSizeUpdate')]
        [Parameter(ParameterSetName='SmallIOAlertUpdate')]
        [Parameter(ParameterSetName='UnalignedIOAlertUpdate')]
        [Parameter(ParameterSetName='VAAITPAlertUpdate')]
        [string]$ID,
        [Parameter(Mandatory=$false,ParameterSetName='VolNameUpdate')]
        [ValidateNotNullOrEmpty()]
        [string]$NewVolName,
        [Parameter(Mandatory=$false,ParameterSetName='VolSizeUpdate')]
        [ValidateNotNullOrEmpty()]
        [string]$NewVolSize,
        [Parameter(Mandatory=$false,ParameterSetName='SmallIOAlertUpdate')]
        [ValidateSet('enable','disable')]
        [ValidateNotNullOrEmpty()]
        [string]$SmallIOAlerts,
        [Parameter(Mandatory=$false,ParameterSetName='UnalignedIOAlertUpdate')]
        [ValidateSet('enable','disable')]
        [ValidateNotNullOrEmpty()]
        [string]$UnalignedIOAlerts,
        [Parameter(Mandatory=$false,ParameterSetName='VAAITPAlertUpdate')]
        [ValidateSet('enable','disable')]
        [ValidateNotNullOrEmpty()]
        [string]$VaaiTpAlerts,
        [Parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [Alias('c')] 
        $Cluster
)
    Begin{
        $UriObject = 'volumes'
    }
    Process{
        if($Name){
            $UriString = ($UriObject + '/?name=' + $Name)
            $JSoNBody = New-Object -TypeName psobject

            # Optional Parameters
            if($NewVolName){$JSoNBody | Add-Member -MemberType NoteProperty -Name vol-name -Value $NewVolName}
            if($NewVolSize){$JSoNBody | Add-Member -MemberType NoteProperty -Name vol-size -Value $NewVolSize}
            if($Cluster){$JSoNBody | Add-Member -MemberType NoteProperty -Name cluster-id -Value $Cluster}
            if($SmallIOAlerts){
                switch ($SmallIOAlerts)
                {
                    'enable' {$JSoNBody | Add-Member -MemberType NoteProperty -Name small-io-alerts -Value 'enabled'}
                    'disable' {$JSoNBody | Add-Member -MemberType NoteProperty -Name small-io-alerts -Value 'disabled'}
                }
            }
            if($UnalignedIOAlerts){
                switch ($UnalignedIOAlerts)
                {
                    'enable' {$JSoNBody | Add-Member -MemberType NoteProperty -Name unaligned-io-alerts -Value 'enabled'}
                    'disable' {$JSoNBody | Add-Member -MemberType NoteProperty -Name unaligned-io-alerts -Value 'disabled'}
                }
            }
            if($VaaiTpAlerts){
                switch ($VaaiTpAlerts)
                {
                    'enable' {$JSoNBody | Add-Member -MemberType NoteProperty -Name vaai-tp-alerts -Value 'enabled'}
                    'disable' {$JSoNBody | Add-Member -MemberType NoteProperty -Name vaai-tp-alerts -Value 'disabled'}
                }
            }
            Invoke-RestMethod -Method Put -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders -Body ($JSoNBody | ConvertTo-Json)
            
        }
    }     
    End{
        if($ID){
            $UriString = ($UriObject + '/' + $ID)
            $JSoNBody = New-Object -TypeName psobject

            # Optional Parameters
            if($NewVolName){$JSoNBody | Add-Member -MemberType NoteProperty -Name vol-name -Value $NewVolName}
            if($NewVolSize){$JSoNBody | Add-Member -MemberType NoteProperty -Name vol-size -Value $NewVolSize}
            if($Cluster){$JSoNBody | Add-Member -MemberType NoteProperty -Name cluster-id -Value $Cluster}
            if($SmallIOAlerts){
            
                switch ($SmallIOAlerts)
                {
                    'enable' {$JSoNBody | Add-Member -MemberType NoteProperty -Name small-io-alerts -Value 'enabled'}
                    'disable' {$JSoNBody | Add-Member -MemberType NoteProperty -Name small-io-alerts -Value 'disabled'}
                }
            }
            if($UnalignedIOAlerts){
                switch ($UnalignedIOAlerts)
                {
                    'enable' {$JSoNBody | Add-Member -MemberType NoteProperty -Name unaligned-io-alerts -Value 'enabled'}
                    'disable' {$JSoNBody | Add-Member -MemberType NoteProperty -Name unaligned-io-alerts -Value 'disabled'}
                }
            }
            if($VaaiTpAlerts){
                switch ($VaaiTpAlerts)
                {
                    'enable' {$JSoNBody | Add-Member -MemberType NoteProperty -Name vaai-tp-alerts -Value 'enabled'}
                    'disable' {$JSoNBody | Add-Member -MemberType NoteProperty -Name vaai-tp-alerts -Value 'disabled'}
                }
            }
            Invoke-RestMethod -Method Put -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders -Body ($JSoNBody | ConvertTo-Json)
        }
    }

    # TODO - Pipeline issue when using get-volume and piping into set. Parametername not being identified, input trying to use entire hash table.

} # Set-XIOVolume

# .ExternalHelp MTSXtremIO.psm1-Help.xml
function Set-XIOSnapshot{
[CmdletBinding()]
param ( [Parameter(Mandatory=$true, 
                    ParameterSetName='SnapNameUpdateByIndex')]
        [Parameter(ParameterSetName='SnapSizeUpdateByIndex')]
        [Parameter(ParameterSetName='SmallIOAlertUpdateByIndex')]
        [Parameter(ParameterSetName='UnalignedIOAlertUpdateByIndex')]
        [Parameter(ParameterSetName='VAAITPAlertUpdateByIndex')]
        [Alias('vid')]
        [Alias('VolID')] 
        [string]$ID=$null,
        [Parameter(Mandatory=$true, 
                    ParameterSetName='SnapNameUpdateByName')]
        [Parameter(ParameterSetName='SnapSizeUpdateByName')]
        [Parameter(ParameterSetName='SmallIOAlertUpdateByName')]
        [Parameter(ParameterSetName='UnalignedIOAlertUpdateByName')]
        [Parameter(ParameterSetName='VAAITPAlertUpdateByName')]
        [Alias('vn')]
        [Alias('VolName')] 
        [string]$Name=$null,
        [Parameter(Mandatory=$false,ParameterSetName='SnapNameUpdateByIndex')]
        [Parameter(ParameterSetName='SnapNameUpdateByName')]
        [ValidateNotNullOrEmpty()]
        [string]$NewVolName=$null,
        [Parameter(Mandatory=$false,ParameterSetName='SnapSizeUpdateByIndex')]
        [Parameter(ParameterSetName='SnapSizeUpdateByName')]
        [ValidateNotNullOrEmpty()]
        [string]$NewVolSize=$null,
        [Parameter(Mandatory=$false,ParameterSetName='SmallIOAlertUpdateByIndex')]
        [Parameter(ParameterSetName='SmallIOAlertUpdateByName')]
        [ValidateSet('enable','disable')]
        [ValidateNotNullOrEmpty()]
        [string]$SmallIOAlerts=$null,
        [Parameter(Mandatory=$false,ParameterSetName='UnalignedIOAlertUpdateByIndex')]
        [Parameter(ParameterSetName='UnalignedIOAlertUpdateByName')]
        [ValidateSet('enable','disable')]
        [ValidateNotNullOrEmpty()]
        [string]$UnalignedIOAlerts=$null,
        [Parameter(Mandatory=$false,ParameterSetName='VAAITPAlertUpdateByIndex')]
        [Parameter(ParameterSetName='VAAITPAlertUpdateByName')]
        [ValidateSet('enable','disable')]
        [ValidateNotNullOrEmpty()]
        [string]$VaaiTpAlerts=$null

)
    
    
        
    $UriString = 'snapshots/'
    if($VolID){
        $UriString += $ID
    }
    if($VolName){
        $UriString += ('?name=' + $Name)
    }

    $JSoNBody = New-Object -TypeName psobject
    if($NewVolName){$JSoNBody | Add-Member -MemberType NoteProperty -Name vol-name -Value $NewVolName}
    if($NewVolSize){$JSoNBody | Add-Member -MemberType NoteProperty -Name vol-size -Value $NewVolSize}
    if($SmallIOAlerts){
            
        switch ($SmallIOAlerts)
        {
            'enable' {$JSoNBody | Add-Member -MemberType NoteProperty -Name small-io-alerts -Value 'enabled'}
            'disable' {$JSoNBody | Add-Member -MemberType NoteProperty -Name small-io-alerts -Value 'disabled'}
        }
    }
    if($UnalignedIOAlerts){
        switch ($UnalignedIOAlerts)
        {
            'enable' {$JSoNBody | Add-Member -MemberType NoteProperty -Name unaligned-io-alerts -Value 'enabled'}
            'disable' {$JSoNBody | Add-Member -MemberType NoteProperty -Name unaligned-io-alerts -Value 'disabled'}
        }
    }
    if($VaaiTpAlerts){
        switch ($VaaiTpAlerts)
        {
            'enable' {$JSoNBody | Add-Member -MemberType NoteProperty -Name vaai-tp-alerts -Value 'enabled'}
            'disable' {$JSoNBody | Add-Member -MemberType NoteProperty -Name vaai-tp-alerts -Value 'disabled'}
        }
    }

    Invoke-RestMethod -Method Put -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders -Body ($JSoNBody | ConvertTo-Json)
    

} # Set-XIOSnapshot

# .ExternalHelp MTSXtremIO.psm1-Help.xml
function Update-XIOSnapshot{
[CmdletBinding()]
param ( [Parameter(Mandatory=$true,ParameterSetName='SnapByCG')]
        [Alias('scg')]
        [string]$SourceCG,
        [Parameter(Mandatory=$true,ParameterSetName='SnapBySet')]
        [Alias('ss')]
        [string]$SourceSnapSet,
        [Parameter(Mandatory=$true,ParameterSetName='SnapByVol')] 
        [Alias('sv')]
        [string]$SourceVol,
        [Parameter(Mandatory=$true,ParameterSetName='SnapByCG')]
        [Alias('dcg')]
        [string]$DestCGID,
        [Parameter(Mandatory=$true,ParameterSetName='SnapBySet')]
        [Alias('ds')]
        [string]$DestSnapSet,
        [Parameter(Mandatory=$true,ParameterSetName='SnapByVol')] 
        [Alias('dv')]
        [string]$DestVol,
        [Parameter(Mandatory=$false)]
        [Alias('nb')] 
        [switch]$NoBackup,
        [Parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [Alias('bsx')] 
        [string]$BackupSnapSuffix,
        [Parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [Alias('ssn')] 
        [string]$SnapSetName
)

    
    $UriString = 'snapshots'
    $JSoNBody = New-Object -TypeName psobject
    if($SourceCG){$JSoNBody | Add-Member -MemberType NoteProperty -Name from-consistency-group-id -Value $SourceCG}
    if($SourceSnapSet){$JSoNBody | Add-Member -MemberType NoteProperty -Name from-snapshot-set-id -Value $SourceSnapSet}
    if($SourceVol){$JSoNBody | Add-Member -MemberType NoteProperty -Name from-volume-id -Value $SourceVol}
    if($DestCG){$JSoNBody | Add-Member -MemberType NoteProperty -Name to-consistency-group-id -Value $DestCG}
    if($DestSnapSet){$JSoNBody | Add-Member -MemberType NoteProperty -Name to-snapshot-set-id -Value $DestSnapSet}
    if($DestVol){$JSoNBody | Add-Member -MemberType NoteProperty -Name to-volume-id -Value $DestVol}
    if($NoBackup){$JSoNBody | Add-Member -MemberType NoteProperty -Name no-backup -Value $true}
    if($BackupSnapSuffix){$JSoNBody | Add-Member -MemberType NoteProperty -Name backup-snap-suffix -Value $BackupSnapSuffix}
    if($SnapSetName){$JSoNBody | Add-Member -MemberType NoteProperty -Name snapshot-set-name -Value $SnapSetName}

    Invoke-RestMethod -Method Post -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders -Body ($JSoNBody | ConvertTo-Json)

    
    # TODO - Does not implement REST API functionality to complete snapshot of set of volumes, but easily done using PowerShell features
    # TODO - Add multiple cluster support
    <#
        
        [Parameter(ParameterSetName='DestSnapByCG')] 
        [Parameter(ParameterSetName='DestSnapBySetID')]
        [Parameter(ParameterSetName='DestSnapByVolID')]
        [Parameter(ParameterSetName='SourceSnapByCG')] 
        [Parameter(ParameterSetName='SourceSnapBySetID')]
        [Parameter(ParameterSetName='SourceSnapByVolID')]

    #>

} # Update-XIOSnapshot

# .ExternalHelp MTSXtremIO.psm1-Help.xml
function Set-XIOScheduler{
[CmdletBinding()]
param ( [Parameter(Mandatory=$true,ParameterSetName='SchedulerByName')]
        [Alias('n')] 
        [string]$Name,
        [Parameter(Mandatory=$true,ParameterSetName='SchedulerByIndex')]
        [Alias('i')] 
        [int]$ID,
        [Parameter(Mandatory=$false,ParameterSetName='SchedulerByName')]
        [Parameter(ParameterSetName='SchedulerByIndex')] 
        [ValidateSet('Interval','Explicit')]
        [Alias('st')]
        [string]$SchedulerType,
        [Parameter(Mandatory=$false,ParameterSetName='SchedulerByName')]
        [Parameter(ParameterSetName='SchedulerByIndex')] 
        [Alias('oi')]
        [string]$ObjectID,
        [Parameter(Mandatory=$false,ParameterSetName='SchedulerByName')]
        [Parameter(ParameterSetName='SchedulerByIndex')] 
        [ValidateSet('Volume','SnapshotSet','TagList','ConsistencyGroup')]
        [Alias('ot')]
        [string]$ObjectType,
        [Parameter(Mandatory=$false,ParameterSetName='SchedulerByName')]
        [Parameter(ParameterSetName='SchedulerByIndex')] 
        [Alias('t')]
        [string]$Time,
        [Parameter(Mandatory=$false,ParameterSetName='SchedulerByName')]
        [Parameter(ParameterSetName='SchedulerByIndex')]
        [ValidateNotNullOrEmpty()]
        [ValidateSet('ReadWrite','ReadOnly')]
        [Alias('snt')] 
        [string]$SnapType,
        [Parameter(Mandatory=$false,ParameterSetName='SchedulerByName')]
        [Parameter(ParameterSetName='SchedulerByIndex')]
        [ValidateNotNullOrEmpty()]
        [Alias('s')] 
        [string]$Suffix,
        [Parameter(Mandatory=$true,ParameterSetName='SchedulerByName')]
        [Parameter(ParameterSetName='SchedulerByIndex')]
        [Alias('skn')]
        [int]$SnapsToKeepNumber,
        [Parameter(Mandatory=$true,ParameterSetName='SchedulerByName')] 
        [Parameter(ParameterSetName='SchedulerByIndex')]
        [Alias('skt')]
        [string]$SnapsToKeepTime,
        [Parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [Alias('c')] 
        $Cluster

)
    
    
    $UriString = 'schedulers'
    $JSoNBody = New-Object -TypeName psobject

    # Required Parameters
    $JSoNBody | Add-Member -MemberType NoteProperty -Name scheduler-type -Value $SchedulerType
    $JSoNBody | Add-Member -MemberType NoteProperty -Name snapshot-object-id -Value $ObjectID
    $JSoNBody | Add-Member -MemberType NoteProperty -Name snapshot-object-type -Value $ObjectType
    $JSoNBody | Add-Member -MemberType NoteProperty -Name time -Value $Time


    # Optional Parameters
    if($SnapSuffix){$JSoNBody | Add-Member -MemberType NoteProperty -Name suffix -Value $SnapSuffix}
    if($SnapType){$JSoNBody | Add-Member -MemberType NoteProperty -Name snapshot-type -Value $SnapType}
    if($Cluster){$JSoNBody | Add-Member -MemberType NoteProperty -Name cluster-id -Value $Cluster}
    if($SnapsToKeepNumber){$JSoNBody | Add-Member -MemberType NoteProperty -Name snapshots-to-keep-number -Value $SnapsToKeepNumber}
    if($SnapsToKeepTime){$JSoNBody | Add-Member -MemberType NoteProperty -Name snapshots-to-keep-time -Value $SnapsToKeepTime}
    

    Invoke-RestMethod -Method Put -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders -Body ($JSoNBody | ConvertTo-Json)


} # Set-XIOScheduler

# .ExternalHelp MTSXtremIO.psm1-Help.xml
function Set-XIOInitiator{
[CmdletBinding()]
param ( [Parameter(Mandatory=$true,ParameterSetName='PortAddress')]
        [Parameter(ParameterSetName='InitiatorName')]
        [Parameter(ParameterSetName='ChapClusterAuthUser')]
        [Parameter(ParameterSetName='ChapClusterAuthPassword')]
        [Parameter(ParameterSetName='ChapClusterDiscoverUser')]
        [Parameter(ParameterSetName='ChapClusterDiscoverPassword')]
        [Parameter(ParameterSetName='ChapInitiatorAuthUser')]
        [Parameter(ParameterSetName='ChapInitiatorAuthPassword')]
        [Parameter(ParameterSetName='ChapInitiatorDiscoverUser')]
        [Parameter(ParameterSetName='ChapInitiatorDiscoverPassword')]
        [Alias('i')]
        [int]$ID,
        [Parameter(Mandatory=$false,ParameterSetName='PortAddress')]
        [Parameter(ParameterSetName='InitiatorName')]
        [Parameter(ParameterSetName='ChapClusterAuthUser')]
        [Parameter(ParameterSetName='ChapClusterAuthPassword')]
        [Parameter(ParameterSetName='ChapClusterDiscoverUser')]
        [Parameter(ParameterSetName='ChapClusterDiscoverPassword')]
        [Parameter(ParameterSetName='ChapInitiatorAuthUser')]
        [Parameter(ParameterSetName='ChapInitiatorAuthPassword')]
        [Parameter(ParameterSetName='ChapInitiatorDiscoverUser')]
        [Parameter(ParameterSetName='ChapInitiatorDiscoverPassword')]
        [ValidateNotNullOrEmpty()]
        [Alias('cid')] 
        [string]$ClusterID,
        [Parameter(Mandatory=$true,ParameterSetName='PortAddress')]
        [Alias('p')]
        [string]$PortAddress,
        [Parameter(Mandatory=$false,ParameterSetName='InitiatorName')]
        [ValidateNotNullOrEmpty()]
        [Alias('n')] 
        [string]$Name,
        [Parameter(Mandatory=$false,ParameterSetName='ChapClusterAuthUser')]
        [ValidateNotNullOrEmpty()]
        [Alias('ccau')] 
        [string]$ChapClusterAuthUser,
        [Parameter(Mandatory=$false,ParameterSetName='ChapClusterAuthPassword')]
        [ValidateNotNullOrEmpty()]
        [Alias('ccap')] 
        [string]$ChapClusterAuthPassword,
        [Parameter(Mandatory=$false,ParameterSetName='ChapClusterDiscoverUser')]
        [ValidateNotNullOrEmpty()]
        [Alias('ccdu')] 
        [string]$ChapClusterDiscoverUser,
        [Parameter(Mandatory=$false,ParameterSetName='ChapClusterDiscoverPassword')]
        [ValidateNotNullOrEmpty()]
        [Alias('ccdp')] 
        [string]$ChapClusterDiscoverPassword,
        [Parameter(Mandatory=$false,ParameterSetName='ChapInitiatorAuthUser')]
        [ValidateNotNullOrEmpty()]
        [Alias('ciau')] 
        [string]$ChapInitiatorAuthUser,
        [Parameter(Mandatory=$false,ParameterSetName='ChapInitiatorAuthPassword')]
        [ValidateNotNullOrEmpty()]
        [Alias('ciap')] 
        [string]$ChapInitiatorAuthPassword,
        [Parameter(Mandatory=$false,ParameterSetName='ChapInitiatorDiscoverUser')]
        [ValidateNotNullOrEmpty()]
        [Alias('cidu')] 
        [string]$ChapInitiatorDiscoverUser,
        [Parameter(Mandatory=$false,ParameterSetName='ChapInitiatorDiscoverPassword')]
        [ValidateNotNullOrEmpty()]
        [Alias('cidp')] 
        [string]$ChapInitiatorDiscoverPassword

)

    $UriString = 'Initiators'
    $JSoNBody = New-Object -TypeName psobject

    # Required Parameters
    $JSoNBody | Add-Member -MemberType NoteProperty -Name ig-id -Value $IgID
    $JSoNBody | Add-Member -MemberType NoteProperty -Name port-address -Value $PortAddress
    

    # Optional Parameters
    if($Name){$JSoNBody | Add-Member -MemberType NoteProperty -Name initiator-name -Value $Name}
    if($ClusterID){$JSoNBody | Add-Member -MemberType NoteProperty -Name cluster-id -Value $ClusterID}
    if($ChapClusterAuthUser){$JSoNBody | Add-Member -MemberType NoteProperty -Name snapshot-type -Value $ChapClusterAuthUser}
    if($ChapClusterAuthPassword){$JSoNBody | Add-Member -MemberType NoteProperty -Name snapshots-to-keep-number -Value $ChapClusterAuthPassword}
    if($ChapClusterDiscoverUser){$JSoNBody | Add-Member -MemberType NoteProperty -Name snapshots-to-keep-time -Value $ChapClusterDiscoverUser}
    if($ChapClusterDiscoverPassword){$JSoNBody | Add-Member -MemberType NoteProperty -Name snapshots-to-keep-time -Value $ChapClusterDiscoverPassword}
    if($ChapInitiatorAuthUser){$JSoNBody | Add-Member -MemberType NoteProperty -Name snapshot-type -Value $ChapInitiatorAuthUser}
    if($ChapInitiatorAuthPassword){$JSoNBody | Add-Member -MemberType NoteProperty -Name snapshots-to-keep-number -Value $ChapInitiatorAuthPassword}
    if($ChapInitiatorDiscoverUser){$JSoNBody | Add-Member -MemberType NoteProperty -Name snapshots-to-keep-time -Value $ChapInitiatorDiscoverUser}
    if($ChapInitiatorDiscoverPassword){$JSoNBody | Add-Member -MemberType NoteProperty -Name snapshots-to-keep-time -Value $ChapInitiatorDiscoverPassword}
    

    Invoke-RestMethod -Method Put -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders -Body ($JSoNBody | ConvertTo-Json)
    

} # Set-XIOInitiator

# .ExternalHelp MTSXtremIO.psm1-Help.xml
function Set-XIOInitiatorGroup{
[CmdletBinding()]
param ( [Parameter(Mandatory=$true,ParameterSetName='IGByName')]
        [Alias('n')] 
        [string]$Name,
        [Parameter(Mandatory=$true,ParameterSetName='IGByIndex')]
        [Alias('i')] 
        [string]$ID,
        [Parameter(Mandatory=$true)]
        [Alias('nn')] 
        [string]$NewName

       )
    
    $UriString = 'initiator-groups/'
    if($Name){
        
        $UriString += ('?name=' + $Name)

    }
    if($ID){

        $UriString += $ID

    }
    $JSoNBody = New-Object -TypeName psobject
    $JSoNBody | Add-Member -MemberType NoteProperty -Name new-name -Value $NewName
    Invoke-RestMethod -Method Put -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders -Body ($JSoNBody | ConvertTo-Json)
    

} # Set-XIOInitiatorGroup

# .ExternalHelp MTSXtremIO.psm1-Help.xml
function Set-XIOTarget{
[CmdletBinding()]
param ( [Parameter(Mandatory=$true,ParameterSetName='TargetByName')]
        [Alias('n')] 
        [string]$Name,
        [Parameter(Mandatory=$true,ParameterSetName='TargetByIndex')]
        [Alias('i')] 
        [string]$ID,
        [ValidateNotNullOrEmpty()]
        [Alias('m')] 
        [string]$MTU,
        [Parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [Alias('c')] 
        $Cluster

       )
    
    $UriString = 'targets/'
    $JSoNBody = New-Object -TypeName psobject

    if($Name){
        $UriString += ('?name=' + $Name)
    }
    if($ID){
        $UriString += $ID
    }
    if($ID){$JSoNBody | Add-Member -MemberType NoteProperty -Name tar-id -Value $ID}
    if($Cluster){$JSoNBody | Add-Member -MemberType NoteProperty -Name cluster-id -Value $Cluster}

    Invoke-RestMethod -Method Put -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders -Body ($JSoNBody | ConvertTo-Json)

    # TODO - Documentation ambiguous need to experiment

} # Set-XIOTarget

# .ExternalHelp MTSXtremIO.psm1-Help.xml
function Set-XIOConsistencyGroup{
[CmdletBinding()]
param ( [Parameter(Mandatory=$true,ParameterSetName='CGByName',
                   ValueFromPipeline=$true)]
        [Alias('n')] 
        [string]$Name,
        [Parameter(Mandatory=$true,ParameterSetName='CGByIndex')]
        [Alias('i')] 
        [string]$ID,
        [Parameter(Mandatory=$true)]
        [Alias('nn')] 
        [string]$NewName,
        [Parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [Alias('c')] 
        $Cluster

       )
    Begin{
        $UriObject = 'consistency-groups'
    }
    Process{
        if($Name){
            $UriString = ($UriObject + '/?name=' + $Name)
            $JSoNBody = New-Object -TypeName psobject
            $JSoNBody | Add-Member -MemberType NoteProperty -Name new-name -Value $NewName
            if($Cluster){$JSoNBody | Add-Member -MemberType NoteProperty -Name cluster-id -Value $Cluster}
            Invoke-RestMethod -Method Put -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders -Body ($JSoNBody | ConvertTo-Json)
        }

    }
    End{
        if($ID){
            $UriString = ($UriObject + '/' + $ID)
            $JSoNBody = New-Object -TypeName psobject
            $JSoNBody | Add-Member -MemberType NoteProperty -Name new-name -Value $NewName
            if($Cluster){$JSoNBody | Add-Member -MemberType NoteProperty -Name cluster-id -Value $Cluster}
            Invoke-RestMethod -Method Put -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders -Body ($JSoNBody | ConvertTo-Json)
        }   
    }
} # Set-XIOConsistencyGroup

# .ExternalHelp MTSXtremIO.psm1-Help.xml
function Add-XIOConsistencyGroupVolume{
[CmdletBinding()]
param ( [Parameter(Mandatory=$true,ParameterSetName='VolByName',
                   ValueFromPipeline=$true,position=0)]
        [Alias('n')] 
        [string]$Name,
        [Parameter(Mandatory=$true,ParameterSetName='VolByIndex')]
        [Alias('i')] 
        [int]$ID,
        [Parameter(Mandatory=$true)]
        [Alias('cgn')] 
        [string]$ConsistencyGroup,
        [Parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [Alias('c')] 
        $Cluster
    )
    Begin{
        $UriObject = 'consistency-group-volumes'
    }
    Process{
        if($Name){
            $UriString += ($UriObject + '/?name=' + $Name)
            $JSoNBody = New-Object -TypeName psobject
            $JSoNBody | Add-Member -MemberType NoteProperty -Name vol-id -Value $Name
            $JSoNBody | Add-Member -MemberType NoteProperty -Name cg-id -Value $ConsistencyGroup
            # $JSoNBody | Add-Member -MemberType NoteProperty -Name cg-id -Value $ConsistencyGroupID
            if($Cluster){$JSoNBody | Add-Member -MemberType NoteProperty -Name cluster-id -Value $Cluster}
            <#
            if($Cluster){
                if(Test-ClusterID -TestValue $Cluster){
                    $JSoNBody | Add-Member -MemberType NoteProperty -Name cluster-id -Value $Cluster
                }Else{
                    $JSoNBody | Add-Member -MemberType NoteProperty -Name cluster-id -Value $Cluster
                }
            }
            #>
            Invoke-RestMethod -Method Post -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders -Body ($JSoNBody | ConvertTo-Json)
        }
    }
    End{
        if($ID){
            $UriString = ($UriObject + '/' + $ID)
            $JSoNBody = New-Object -TypeName psobject
            $JSoNBody | Add-Member -MemberType NoteProperty -Name vol-id -Value $ID
            $JSoNBody | Add-Member -MemberType NoteProperty -Name cg-id -Value $ConsistencyGroup
            # $JSoNBody | Add-Member -MemberType NoteProperty -Name cg-id -Value $ConsistencyGroupID
            if($Cluster){$JSoNBody | Add-Member -MemberType NoteProperty -Name cluster-id -Value $Cluster}
            <#
            if($Cluster){
                if(Test-ClusterID -TestValue $Cluster){
                    $JSoNBody | Add-Member -MemberType NoteProperty -Name cluster-id -Value $Cluster
                }Else{
                    $JSoNBody | Add-Member -MemberType NoteProperty -Name cluster-id -Value $Cluster
                }
            }
            #>
            Invoke-RestMethod -Method Post -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders -Body ($JSoNBody | ConvertTo-Json)
        }
    }

# TODO - Figure out how to use dynamic parameters to allow use of index in CG and Vol only supports name at the moment
<#
param ( [Parameter(Mandatory=$true,ParameterSetName='VolByName',
                   ValueFromPipeline=$true,position=0)]
        [Parameter(Mandatory=$false,ParameterSetName='CGByName')]
        [Parameter(Mandatory=$false,ParameterSetName='CGByIndex')]
        [Alias('n')] 
        [string]$Name,
        [Parameter(Mandatory=$true,ParameterSetName='VolByIndex')]
        [Parameter(Mandatory=$false,ParameterSetName='CGByName')]
        [Parameter(Mandatory=$false,ParameterSetName='CGByIndex')]
        [Alias('i')] 
        [int]$ID,
        [Parameter(Mandatory=$true,ParameterSetName='CGByName')]
        [Alias('cgn')] 
        [string]$ConsistencyGroupName,
        [Parameter(Mandatory=$true,ParameterSetName='CGByIndex')]
        [Alias('cgi')] 
        [int]$ConsistencyGroupID,
        [Parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [Alias('cl')] 
        $Cluster
    )

#>

} # Add-XIOConsistencyGroupVolume

# .ExternalHelp MTSXtremIO.psm1-Help.xml
function Set-XIOLDAPConfiguration{
[CmdletBinding()]
param ( [Parameter(Mandatory=$true,ParameterSetName='LDAPUpdateByName')]
        [Parameter(ParameterSetName='BindDN')]
        [Parameter(ParameterSetName='BindPW')]
        [Parameter(ParameterSetName='X509Cert')]
        [Parameter(ParameterSetName='ExpireHours')]
        [Parameter(ParameterSetName='Roles')]
        [Parameter(ParameterSetName='SearchBaseDN')]
        [Parameter(ParameterSetName='SearchFilter')]
        [Parameter(ParameterSetName='ServerUrls')]
        [Parameter(ParameterSetName='Timeout')]
        [Parameter(ParameterSetName='UserToDNSubstitution')]
        [Alias('n')] 
        [string]$Name,
        [Parameter(Mandatory=$true,ParameterSetName='LDAPUpdateByIndex')]
        [Parameter(ParameterSetName='BindDN')]
        [Parameter(ParameterSetName='BindPW')]
        [Parameter(ParameterSetName='X509Cert')]
        [Parameter(ParameterSetName='ExpireHours')]
        [Parameter(ParameterSetName='Roles')]
        [Parameter(ParameterSetName='SearchBaseDN')]
        [Parameter(ParameterSetName='SearchFilter')]
        [Parameter(ParameterSetName='ServerUrls')]
        [Parameter(ParameterSetName='Timeout')]
        [Parameter(ParameterSetName='UserToDNSubstitution')]
        [Alias('i')] 
        [string]$ID,
        [Parameter(Mandatory=$true,ParameterSetName='BindDN')]
        [Parameter(ParameterSetName='LDAPUpdateByName')]
        [Parameter(ParameterSetName='LDAPUpdateByIndex')]
        [string]$BindDN,
        [Parameter(Mandatory=$true,ParameterSetName='BindPW')]
        [Parameter(ParameterSetName='LDAPUpdateByName')]
        [Parameter(ParameterSetName='LDAPUpdateByIndex')]
        [string]$BindPW,
        [Parameter(Mandatory=$true,ParameterSetName='X509Cert')]
        [Parameter(ParameterSetName='LDAPUpdateByName')]
        [Parameter(ParameterSetName='LDAPUpdateByIndex')]
        [string]$X509Cert,
        [Parameter(Mandatory=$true,ParameterSetName='ExpireHours')]
        [Parameter(ParameterSetName='LDAPUpdateByName')]
        [Parameter(ParameterSetName='LDAPUpdateByIndex')]
        [string]$ExpireHours,
        [Parameter(Mandatory=$true,ParameterSetName='Roles')]
        [Parameter(ParameterSetName='LDAPUpdateByName')]
        [Parameter(ParameterSetName='LDAPUpdateByIndex')]
        [string]$Roles,
        [Parameter(Mandatory=$true,ParameterSetName='SearchBaseDN')]
        [Parameter(ParameterSetName='LDAPUpdateByName')]
        [Parameter(ParameterSetName='LDAPUpdateByIndex')]
        [string]$SearchBaseDN,
        [Parameter(Mandatory=$true,ParameterSetName='SearchFilter')]
        [Parameter(ParameterSetName='LDAPUpdateByName')]
        [Parameter(ParameterSetName='LDAPUpdateByIndex')]
        [string]$SearchFilter,
        [Parameter(Mandatory=$true,ParameterSetName='ServerUrls')]
        [Parameter(ParameterSetName='LDAPUpdateByName')]
        [Parameter(ParameterSetName='LDAPUpdateByIndex')]
        [string]$ServerUrls,
        [Parameter(Mandatory=$true,ParameterSetName='Timeout')]
        [Parameter(ParameterSetName='LDAPUpdateByName')]
        [Parameter(ParameterSetName='LDAPUpdateByIndex')]
        [string]$Timeout,
        [Parameter(Mandatory=$true,ParameterSetName='UserToDNSubstitution')]
        [Parameter(ParameterSetName='LDAPUpdateByName')]
        [Parameter(ParameterSetName='LDAPUpdateByIndex')]
        [string]$UserToDNSubstitution



)
    
    $UriObject = 'ldap-configs'
     

    if($ID){
        $UriString = ($UriObject + '/' + $ID)
    }
    if($Name){
        $UriString += ($UriObject + '/?name=' + $Name)
    }

    $JSoNBody = New-Object -TypeName psobject
    if($BindDN){$JSoNBody | Add-Member -MemberType NoteProperty -Name binddn -Value $BindDN}
    if($BindPW){$JSoNBody | Add-Member -MemberType NoteProperty -Name bindpw -Value $BindPW}
    if($X509Cert){$JSoNBody | Add-Member -MemberType NoteProperty -Name ca-cert-data -Value $X509Cert}
    if($ExpireHours){$JSoNBody | Add-Member -MemberType NoteProperty -Name cache-expire-hours -Value $ExpireHours}
    if($Roles){$JSoNBody | Add-Member -MemberType NoteProperty -Name roles -Value $Roles}
    if($SearchBaseDN){$JSoNBody | Add-Member -MemberType NoteProperty -Name search-base -Value $SearchBaseDN}
    if($SearchFilter){$JSoNBody | Add-Member -MemberType NoteProperty -Name search-filter -Value $SearchFilter}
    if($ServerUrls){$JSoNBody | Add-Member -MemberType NoteProperty -Name server-urls -Value $ServerUrls}
    if($Timeout){$JSoNBody | Add-Member -MemberType NoteProperty -Name timeout -Value $Timeout}
    if($UserToDNSubstitution){$JSoNBody | Add-Member -MemberType NoteProperty -Name user-to-dn-rule -Value $UserToDNSubstitution}
    

    Invoke-RestMethod -Method Put -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders -Body ($JSoNBody | ConvertTo-Json)

    # Note - This is an XMS function - multiple cluster support not applicable
    # TODO - need to consider and test pipline input scenarios

} # Set-XIOLDAPConfiguration

# .ExternalHelp MTSXtremIO.psm1-Help.xml
function Set-XIOAlertDefinition{
[CmdletBinding()]
param ( [Parameter(Mandatory=$true,ParameterSetName='AlertDefinitionByName')]
        [Parameter(ParameterSetName='ActivityMode')]
        [Parameter(ParameterSetName='ClearanceMode')]
        [Parameter(ParameterSetName='Severity')]
        [Alias('n')] 
        [string]$Name,
        [Parameter(Mandatory=$true,ParameterSetName='AlertDefinitionByIndex')]
        [Parameter(ParameterSetName='ActivityMode')]
        [Parameter(ParameterSetName='ClearanceMode')]
        [Parameter(ParameterSetName='Severity')]
        [Alias('i')] 
        [string]$ID,
        [Parameter(Mandatory=$true,ParameterSetName='ActivityMode')]
        [Parameter(ParameterSetName='AlertDefinitionByName')]
        [Parameter(ParameterSetName='AlertDefinitionByIndex')]
        [string]$ActivityMode,
        [Parameter(Mandatory=$true,ParameterSetName='ClearanceMode')]
        [Parameter(ParameterSetName='AlertDefinitionByName')]
        [Parameter(ParameterSetName='AlertDefinitionByIndex')]
        [string]$ClearanceMode,
        [Parameter(Mandatory=$true,ParameterSetName='Severity')]
        [Parameter(ParameterSetName='AlertDefinitionByName')]
        [Parameter(ParameterSetName='AlertDefinitionByIndex')]
        [string]$Severity

)
    
    $UriObject = 'alert-definition'
     

    if($ID){
        $UriString = ($UriObject + '/' + $ID)
    }
    if($Name){
        $UriString += ($UriObject + '/?name=' + $Name)
    }

    $JSoNBody = New-Object -TypeName psobject
    if($ActivityMode){$JSoNBody | Add-Member -MemberType NoteProperty -Name binddn -Value $ActivityMode}
    if($ClearanceMode){$JSoNBody | Add-Member -MemberType NoteProperty -Name bindpw -Value $ClearanceMode}
    if($Severity){$JSoNBody | Add-Member -MemberType NoteProperty -Name ca-cert-data -Value $Severity}
        

    Invoke-RestMethod -Method Put -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders -Body ($JSoNBody | ConvertTo-Json)

    # Note - This is an XMS function - multiple cluster support not applicable
    # TODO - need to consider and test pipline input scenarios

} # Set-XIOAlertDefinition

# .ExternalHelp MTSXtremIO.psm1-Help.xml
function Set-XIOEmailNotifier{
[CmdletBinding()]
param ( [Parameter(Mandatory=$true,ParameterSetName='NotifierByName')]
        [Alias('n')] 
        [string]$Name,
        [Parameter(Mandatory=$true,ParameterSetName='NotifierByIndex')]
        [Alias('i')] 
        [string]$ID,
        [Parameter(Mandatory=$true)]
        [ValidateSet('enable','disable')]
        [string]$State,
        [Parameter(Mandatory=$false)]
        [string]$CompanyName,
        [Parameter(Mandatory=$false)]
        [string]$ContactDetails,
        [Parameter(Mandatory=$false)]
        [string]$MailPassword,
        [Parameter(Mandatory=$false)]
        [string]$MailRelayAddress,
        [Parameter(Mandatory=$false)]
        [string]$MailUser,
        [Parameter(Mandatory=$false)]
        [string]$ProxyAddress,
        [Parameter(Mandatory=$false)]
        [string]$ProxyPassword,
        [Parameter(Mandatory=$false)]
        [string]$ProxyPort,
        [Parameter(Mandatory=$false)]
        [string]$ProxyUser,
        [Parameter(Mandatory=$false)]
        [string[]]$RecipientList,
        [Parameter(Mandatory=$false)]
        [string]$sender,
        [Parameter(Mandatory=$false)]
        [string]$transport
)
    
    $UriObject = 'email-notifier'

    if($ID){
        $UriString = ($UriObject + '/' + $ID)
    }
    if($Name){
        $UriString += ($UriObject + '/?name=' + $Name)
    }

    $JSoNBody = New-Object -TypeName psobject
    if($CompanyName){$JSoNBody | Add-Member -MemberType NoteProperty -Name company-name -Value $CompanyName}
    if($ContactDetails){$JSoNBody | Add-Member -MemberType NoteProperty -Name contact-details -Value $ContactDetails}
    if($MailPassword){$JSoNBody | Add-Member -MemberType NoteProperty -Name mail-password -Value $MailPassword}
    if($MailRelayAddress){$JSoNBody | Add-Member -MemberType NoteProperty -Name mail-relay-address -Value $MailRelayAddress}
    if($MailUser){$JSoNBody | Add-Member -MemberType NoteProperty -Name mail-user -Value $MailUser}
    if($ProxyAddress){$JSoNBody | Add-Member -MemberType NoteProperty -Name proxy-address -Value $ProxyAddress}
    if($ProxyPassword){$JSoNBody | Add-Member -MemberType NoteProperty -Name proxy-password -Value $ProxyPassword}
    if($ProxyPort){$JSoNBody | Add-Member -MemberType NoteProperty -Name proxy-port -Value $ProxyPort}
    if($ProxyUser){$JSoNBody | Add-Member -MemberType NoteProperty -Name proxy-user -Value $ProxyUser}
    if($RecipientList){$JSoNBody | Add-Member -MemberType NoteProperty -Name recipient-list -Value $RecipientList}
    if($sender){$JSoNBody | Add-Member -MemberType NoteProperty -Name sender -Value $sender}
    if($transport){$JSoNBody | Add-Member -MemberType NoteProperty -Name transport -Value $transport}

    if($State){
        switch ($State)
        {
            'enable' {$JSoNBody | Add-Member -MemberType NoteProperty -Name enable -Value $true}
            'disable' {$JSoNBody | Add-Member -MemberType NoteProperty -Name disable -Value $true}
        }
    }
    
    
    Invoke-RestMethod -Method Put -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders -Body ($JSoNBody | ConvertTo-Json)

    # Note - This is an XMS function - multiple cluster support not applicable
    # TODO - need to consider and test pipline input scenarios

} # Set-XIOEmailNotifier

# .ExternalHelp MTSXtremIO.psm1-Help.xml
function Set-XIOSNMPNotifier{
[CmdletBinding()]
param ( [Parameter(Mandatory=$true,ParameterSetName='NotifierByName')]
        [Alias('n')] 
        [string]$Name,
        [Parameter(Mandatory=$true,ParameterSetName='NotifierByIndex')]
        [Alias('i')] 
        [string]$ID,
        [Parameter(Mandatory=$true)]
        [ValidateSet('enable','disable')]
        [string]$State,
        [Parameter(Mandatory=$false)]
        [string]$AuthKey,
        [Parameter(Mandatory=$false)]
        [string]$AuthProtocol,
        [Parameter(Mandatory=$false)]
        [string]$Community,
        [Parameter(Mandatory=$false)]
        [string]$Port,
        [Parameter(Mandatory=$false)]
        [string]$PrivateKey,
        [Parameter(Mandatory=$false)]
        [string]$PrivateProtocol,
        [Parameter(Mandatory=$false)]
        [string[]]$RecipientList,
        [Parameter(Mandatory=$false)]
        [string]$Username,
        [Parameter(Mandatory=$false)]
        [string]$Version
)
    
    $UriObject = 'snmp-notifier'

    if($ID){
        $UriString = ($UriObject + '/' + $ID)
    }
    if($Name){
        $UriString += ($UriObject + '/?name=' + $Name)
    }

    $JSoNBody = New-Object -TypeName psobject
    if($AuthKey){$JSoNBody | Add-Member -MemberType NoteProperty -Name auth-key -Value $AuthKey}
    if($AuthProtocol){$JSoNBody | Add-Member -MemberType NoteProperty -Name auth-protocol -Value $AuthProtocol}
    if($Community){$JSoNBody | Add-Member -MemberType NoteProperty -Name community -Value $Community}
    if($Port){$JSoNBody | Add-Member -MemberType NoteProperty -Name port -Value $Port}
    if($PrivateKey){$JSoNBody | Add-Member -MemberType NoteProperty -Name priv-key -Value $PrivateKey}
    if($PrivateProtocol){$JSoNBody | Add-Member -MemberType NoteProperty -Name priv-protocol -Value $PrivateProtocol}
    if($RecipientList){$JSoNBody | Add-Member -MemberType NoteProperty -Name recipient-list -Value $RecipientList}
    if($Username){$JSoNBody | Add-Member -MemberType NoteProperty -Name username -Value $Username}
    if($Version){$JSoNBody | Add-Member -MemberType NoteProperty -Name version -Value $Version}
    if($State){
        switch ($State)
        {
            'enable' {$JSoNBody | Add-Member -MemberType NoteProperty -Name enable -Value $true}
            'disable' {$JSoNBody | Add-Member -MemberType NoteProperty -Name disable -Value $true}
        }
    }
    
    Invoke-RestMethod -Method Put -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders -Body ($JSoNBody | ConvertTo-Json)

    # Note - This is an XMS function - multiple cluster support not applicable
    # TODO - need to consider and test pipline input scenarios

} # Set-XIOSNMPNotifier

# .ExternalHelp MTSXtremIO.psm1-Help.xml
function Set-XIOSYRNotifier{
[CmdletBinding()]
param ( [Parameter(Mandatory=$true,ParameterSetName='NotifierByName')]
        [Alias('n')] 
        [string]$Name,
        [Parameter(Mandatory=$true,ParameterSetName='NotifierByIndex')]
        [Alias('i')] 
        [string]$ID,
        [Parameter(Mandatory=$true)]
        [ValidateSet('enable','disable')]
        [string]$State,
        [Parameter(Mandatory=$true,ParameterSetName='ConnectionType')]
        [Parameter(ParameterSetName='NotifierByName')]
        [Parameter(ParameterSetName='NotifierByIndex')]
        [string]$ConnectionType,
        [Parameter(Mandatory=$true,ParameterSetName='Frequency')]
        [Parameter(ParameterSetName='NotifierByName')]
        [Parameter(ParameterSetName='NotifierByIndex')]
        [string]$Frequency,
        [Parameter(Mandatory=$true,ParameterSetName='SiteName')]
        [Parameter(ParameterSetName='NotifierByName')]
        [Parameter(ParameterSetName='NotifierByIndex')]
        [string]$SiteName,
        [Parameter(Mandatory=$false)]
        [string]$EmailPassword,
        [Parameter(Mandatory=$false)]
        [string]$EmailSender,
        [Parameter(Mandatory=$false)]
        [string]$EmailServer,
        [Parameter(Mandatory=$false)]
        [string]$EmailUser,
        [Parameter(Mandatory=$false)]
        [string]$ESRSGatewayHost,
        [Parameter(Mandatory=$false)]
        [string]$ESRSGatewayHostSecondary
)
    
    $UriObject = 'syr-notifier'

    if($ID){
        $UriString = ($UriObject + '/' + $ID)
    }
    if($Name){
        $UriString += ($UriObject + '/?name=' + $Name)
    }

    $JSoNBody = New-Object -TypeName psobject
    if($ConnectionType){$JSoNBody | Add-Member -MemberType NoteProperty -Name connection-type -Value $ConnectionType}
    if($Frequency){$JSoNBody | Add-Member -MemberType NoteProperty -Name frequency -Value $Frequency}
    if($SiteName){$JSoNBody | Add-Member -MemberType NoteProperty -Name site-name -Value $SiteName}
    if($EmailPassword){$JSoNBody | Add-Member -MemberType NoteProperty -Name email-password -Value $EmailPassword}
    if($EmailSender){$JSoNBody | Add-Member -MemberType NoteProperty -Name email-sender -Value $EmailSender}
    if($EmailServer){$JSoNBody | Add-Member -MemberType NoteProperty -Name email-server -Value $EmailServer}
    if($EmailUser){$JSoNBody | Add-Member -MemberType NoteProperty -Name email-user -Value $EmailUser}
    if($ESRSGatewayHost){$JSoNBody | Add-Member -MemberType NoteProperty -Name esrs-gw-host -Value $ESRSGatewayHost}
    if($ESRSGatewayHostSecondary){$JSoNBody | Add-Member -MemberType NoteProperty -Name esrs-gw-host-secondary -Value $ESRSGatewayHostSecondary}
    if($State){
        switch ($State)
        {
            'enable' {$JSoNBody | Add-Member -MemberType NoteProperty -Name enable -Value $true}
            'disable' {$JSoNBody | Add-Member -MemberType NoteProperty -Name disable -Value $true}
        }
    }
    
    Invoke-RestMethod -Method Put -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders -Body ($JSoNBody | ConvertTo-Json)

    # TODO - Add multiple cluster support
    # TODO - need to consider and test pipline input scenarios

} # Set-XIOSYRNotifier

# .ExternalHelp MTSXtremIO.psm1-Help.xml
function Set-XIOSyslogNotifier{
[CmdletBinding()]
param ( [Parameter(Mandatory=$true,ParameterSetName='NotifierByName')]
        [Alias('n')] 
        [string]$Name,
        [Parameter(Mandatory=$true,ParameterSetName='NotifierByIndex')]
        [Alias('i')] 
        [string]$ID,
        [Parameter(Mandatory=$true)]
        [ValidateSet('enable','disable')]
        [string]$State,
        [Parameter(Mandatory=$false)]
        [string[]]$Targets
)
    
    $UriObject = 'syslog-notifier'

    if($ID){
        $UriString = ($UriObject + '/' + $ID)
    }
    if($Name){
        $UriString += ($UriObject + '/?name=' + $Name)
    }

    $JSoNBody = New-Object -TypeName psobject
    if($Targets){$JSoNBody | Add-Member -MemberType NoteProperty -Name targets -Value $Targets}
    if($State){
        switch ($State)
        {
            'enable' {$JSoNBody | Add-Member -MemberType NoteProperty -Name enable -Value $true}
            'disable' {$JSoNBody | Add-Member -MemberType NoteProperty -Name disable -Value $true}
        }
    }
    
    Invoke-RestMethod -Method Put -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders -Body ($JSoNBody | ConvertTo-Json)

    # TODO - Add multiple cluster support
    # TODO - need to consider and test pipline input scenarios

} # Set-XIOSyslogNotifier


# Remove Functions
# .ExternalHelp MTSXtremIO.psm1-Help.xml
function Remove-XIOUserAccount{
[CmdletBinding()]
param ( [Parameter(Mandatory=$true, 
                    ValueFromPipeline=$true, 
                    Position=0,
                    ParameterSetName='UserByName')]
        [Alias('n')]
        [string]$Name,
        [Parameter(Mandatory=$true,
                    ParameterSetName='UserByIndex')]
        [Alias('i')]
        [string]$ID
        
)

    Begin{
        $UriObject = 'user-accounts'
    }
    Process{
        # Remove Scheduler  by Name
        if($Name){
            $UriString = ($UriObject + '/?name=' + $Name)
            Invoke-RestMethod -Method Delete -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders
        }
    
    }
    End{
        # Remove Scheduler by ID
        if($ID){
            $UriString = ($UriObject + '/' + $ID)
            Invoke-RestMethod -Method Delete -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders
        }
    }
        
} # Remove-XIOUserAccount

# .ExternalHelp MTSXtremIO.psm1-Help.xml
function Remove-XIOTag{
[CmdletBinding()]
param ( [Parameter(Mandatory=$true,ParameterSetName='TagByName', 
                    ValueFromPipeline=$true,
                    Position=0)]
        [Alias('n')] 
        [string]$Name,
        [Parameter(Mandatory=$true,ParameterSetName='TagByIndex')]
        [Alias('i')] 
        [string]$ID
)
    Begin{
        $UriObject = 'tags'
    }
    Process{
        # Remove Volume Folders By Name
        if($Name){
            $UriString = ($UriObject + '/?name=' + $Name)
            Invoke-RestMethod -Method Delete -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders
        }
    }
    End{
        # Remove Volume Folders By ID
        if($ID){
            $UriString = ($UriObject + '/' + $ID)
            Invoke-RestMethod -Method Delete -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders
        }
    }
} # Remove-XIOTag

# .ExternalHelp MTSXtremIO.psm1-Help.xml
function Remove-XIOVolume{
[CmdletBinding()]
param ( [Parameter(Mandatory=$true,ParameterSetName='VolByName', 
                    ValueFromPipeline=$true, 
                    ValueFromPiplineByName=$true,
                    Position=0)]
        [Alias('n')]
        [Alias('vn')] 
        [Alias('VolName')]
        [string]$Name,
        [Parameter(Mandatory=$true,ParameterSetName='VolByIndex')]
        [Alias('i')]
        [Alias('vid')] 
        [Alias('VolId')]
        [string]$ID,
        [Parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [Alias('c')] 
        [string]$Cluster   
)
    Begin{
        $UriObject = 'volumes'
    }
    Process{
        # Remove Snapshot by Name
        if($Name){
            $UriString = ($UriObject + '/?name=' + $Name)
            if($Cluster){
                # Optional Parameters
                $JSoNBody = New-Object -TypeName psobject
                $JSoNBody | Add-Member -MemberType NoteProperty -Name cluster-id -Value $Cluster
                Invoke-RestMethod -Method Delete -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders -Body ($JSoNBody | ConvertTo-Json)
            }else{
                Invoke-RestMethod -Method Delete -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders
            }
        }
    }
    End{
        # Remove Snapshot by ID
        if($ID){
            $UriString = ($UriObject + '/' + $ID)
            if($Cluster){
                # Optional Parameters
                $JSoNBody = New-Object -TypeName psobject
                $JSoNBody | Add-Member -MemberType NoteProperty -Name cluster-id -Value $Cluster
                Invoke-RestMethod -Method Delete -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders -Body ($JSoNBody | ConvertTo-Json)
            }else{
                Invoke-RestMethod -Method Delete -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders
            }
        }
    }    
} # Remove-XIOVolume

# .ExternalHelp MTSXtremIO.psm1-Help.xml
function Remove-XIOSnapshot{
[CmdletBinding()]
param ( [Parameter(Mandatory=$true,ParameterSetName='VolByName', 
                    ValueFromPipeline=$true, 
                    Position=0)]
        [Alias('n')]
        [Alias('vn')] 
        [Alias('VolName')]
        [string]$Name,
        [Parameter(Mandatory=$true,ParameterSetName='VolByIndex')]
        [Alias('i')]
        [Alias('vid')] 
        [Alias('VolId')]
        [int]$ID,
        [Parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [Alias('c')] 
        [string]$Cluster
)
    Begin{
        $UriObject = 'volumes'
    }
    Process{
        # Remove Snapshot by Name
        if($Name){
            $UriString = ($UriObject + '/?name=' + $Name)
            if($Cluster){
                # Optional Parameters
                $JSoNBody = New-Object -TypeName psobject
                $JSoNBody | Add-Member -MemberType NoteProperty -Name cluster-id -Value $Cluster
                Invoke-RestMethod -Method Delete -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders -Body ($JSoNBody | ConvertTo-Json)
            }else{
                Invoke-RestMethod -Method Delete -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders
            }
        }
    }
    End{
        # Remove Snapshot by ID
        if($ID){
            $UriString = ($UriObject + '/' + $ID)
            if($Cluster){
                # Optional Parameters
                $JSoNBody = New-Object -TypeName psobject
                $JSoNBody | Add-Member -MemberType NoteProperty -Name cluster-id -Value $Cluster
                Invoke-RestMethod -Method Delete -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders -Body ($JSoNBody | ConvertTo-Json)
            }else{
                Invoke-RestMethod -Method Delete -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders
            }
        }
    }    
} # Remove-XIOSnapshot

# .ExternalHelp MTSXtremIO.psm1-Help.xml
function Remove-XIOSnapshotSet{
[CmdletBinding()]
param ( [Parameter(Mandatory=$true,ParameterSetName='SnapSetByName', 
                    ValueFromPipeline=$true, 
                    Position=0)]
        [Alias('n')]
        [string]$Name,
        [Parameter(Mandatory=$true,ParameterSetName='SnapSetByIndex')]
        [Alias('i')]
        [string]$ID,
        [Parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [Alias('c')] 
        [string]$Cluster
)
    Begin{
        $UriObject = 'snapshot-sets'
    }
    Process{
        # Remove object by Name
        if($Name){
            $UriString = ($UriObject + '/?name=' + $Name)
            if($Cluster){
                # Optional Parameters
                $JSoNBody = New-Object -TypeName psobject
                $JSoNBody | Add-Member -MemberType NoteProperty -Name cluster-id -Value $Cluster
                Invoke-RestMethod -Method Delete -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders -Body ($JSoNBody | ConvertTo-Json)
            }else{
                Invoke-RestMethod -Method Delete -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders
            }
        }
    }
    End{
        # Remove object by ID
        if($ID){
            $UriString = ($UriObject + '/' + $ID)
            if($Cluster){
                # Optional Parameters
                $JSoNBody = New-Object -TypeName psobject
                $JSoNBody | Add-Member -MemberType NoteProperty -Name cluster-id -Value $Cluster
                Invoke-RestMethod -Method Delete -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders -Body ($JSoNBody | ConvertTo-Json)
            }else{
                Invoke-RestMethod -Method Delete -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders
            }
        }
    }    
} # Remove-XIOSnapshotSet

# .ExternalHelp MTSXtremIO.psm1-Help.xml
function Remove-XIOScheduler{
[CmdletBinding()]
param ( [Parameter(Mandatory=$true,ParameterSetName='SchedulerByName', 
                    ValueFromPipeline=$true, 
                    Position=0)]
        [Alias('n')]
        [string]$Name,
        [Parameter(Mandatory=$true,ParameterSetName='SchedulerByIndex')]
        [Alias('i')]
        [string]$ID,
        [Parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [Alias('c')] 
        [string]$Cluster   
)
    Begin{
        $UriObject = 'schedulers'
    }
    Process{
        # Remove Scheduler  by Name
        if($Name){
            $UriString = ($UriObject + '/?name=' + $Name)
            if($Cluster){
                # Optional Parameters
                $JSoNBody = New-Object -TypeName psobject
                $JSoNBody | Add-Member -MemberType NoteProperty -Name cluster-id -Value $Cluster
                Invoke-RestMethod -Method Delete -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders -Body ($JSoNBody | ConvertTo-Json)
            }else{
                Invoke-RestMethod -Method Delete -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders
            }
        }
    }
    End{
        # Remove Scheduler by ID
        if($ID){
            $UriString = ($UriObject + '/' + $ID)
            if($Cluster){
                # Optional Parameters
                $JSoNBody = New-Object -TypeName psobject
                $JSoNBody | Add-Member -MemberType NoteProperty -Name cluster-id -Value $Cluster
                Invoke-RestMethod -Method Delete -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders -Body ($JSoNBody | ConvertTo-Json)
            }else{
                Invoke-RestMethod -Method Delete -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders
            }
        }
    }  
} # Remove-XIOScheduler

# .ExternalHelp MTSXtremIO.psm1-Help.xml
function Remove-XIOInitiator{
[CmdletBinding()]
param ( [Parameter(Mandatory=$true,ParameterSetName='InitiatorByName', 
                    ValueFromPipeline=$true,
                    Position=0)]
        [Alias('n')]
        [string]$Name,
        [Parameter(Mandatory=$true,ParameterSetName='InitiatorByIndex')]
        [Alias('i')]
        [string]$ID,
        [Parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [Alias('c')] 
        [string]$Cluster
)
    Begin{ 
        $UriObject = 'initiators'        
    }
    Process{
        # Remove object by Name
        if($Name){
            $UriString = ($UriObject + '/?name=' + $Name)
            if($Cluster){
                # Optional Parameters
                $JSoNBody = New-Object -TypeName psobject
                $JSoNBody | Add-Member -MemberType NoteProperty -Name cluster-id -Value $Cluster
                Invoke-RestMethod -Method Delete -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders -Body ($JSoNBody | ConvertTo-Json)
            }else{
                Invoke-RestMethod -Method Delete -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders
            }
        }
    }
    End{
        # Remove object by ID
        if($ID){
            $UriString = ($UriObject + '/' + $ID)
            if($Cluster){
                # Optional Parameters
                $JSoNBody = New-Object -TypeName psobject
                $JSoNBody | Add-Member -MemberType NoteProperty -Name cluster-id -Value $Cluster
                Invoke-RestMethod -Method Delete -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders -Body ($JSoNBody | ConvertTo-Json)
            }else{
                Invoke-RestMethod -Method Delete -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders
            }
        }
    }
} # Remove-XIOInitiator

# .ExternalHelp MTSXtremIO.psm1-Help.xml
function Remove-XIOInitiatorGroup{
[CmdletBinding()]
param ( [Parameter(Mandatory=$true,ParameterSetName='IGByName', 
                    ValueFromPipeline=$true,
                    Position=0)]
        [Alias('n')] 
        [string]$Name,
        [Parameter(Mandatory=$true,ParameterSetName='IGByIndex')]
        [Alias('i')] 
        [string]$ID
)
    Begin{
        $UriObject = 'initiator-groups'
    }
    Process{
        # Remove IG by Name
        if($Name){
            $UriString = ($UriObject + '/?name=' + $Name)
            Invoke-RestMethod -Method Delete -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders
        }
    }
    End{
        # Remove IG by Index
        if($ID){
            $UriString = ($UriObject + '/' + $ID)
            Invoke-RestMethod -Method Delete -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders
        }
    }
} # Remove-XIOInitiatorGroup

# .ExternalHelp MTSXtremIO.psm1-Help.xml
function Remove-XIOConsistencyGroup{
[CmdletBinding()]
param ( [Parameter(Mandatory=$true,ParameterSetName='CGByName', 
                   ValueFromPipeline=$true,
                   Position=0)]
        [Alias('n')] 
        [string]$Name,
        [Parameter(Mandatory=$true,ParameterSetName='CGByIndex')]
        [Alias('i')] 
        [string]$ID,
        [Parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [Alias('c')] 
        $Cluster
)
    Begin{
        $UriObject = 'consistency-groups'
    }
    Process{
        # Remove object by Name
        if($Name){
            $UriString = ($UriObject + '/?name=' + $Name)
            if($Cluster){
                $JSoNBody = New-Object -TypeName psobject
                if($Cluster){$JSoNBody | Add-Member -MemberType NoteProperty -Name cluster-id -Value $Cluster}
                Invoke-RestMethod -Method Delete -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders -Body ($JSoNBody | ConvertTo-Json)
            }else{
                Invoke-RestMethod -Method Delete -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders
            }
        }
    }
    End{
        # Remove object by Index
        if($ID){
            $UriString = ($UriObject + '/' + $ID)
            if($Cluster){
                $JSoNBody = New-Object -TypeName psobject
                if($Cluster){$JSoNBody | Add-Member -MemberType NoteProperty -Name cluster-id -Value $Cluster}
                Invoke-RestMethod -Method Delete -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders -Body ($JSoNBody | ConvertTo-Json)
            }else{
                Invoke-RestMethod -Method Delete -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders
            }
        }
    }

    # Note - Ambiguous documentation on cg-id syntax

} # Remove-XIOConsistencyGroup

# .ExternalHelp MTSXtremIO.psm1-Help.xml
function Remove-XIOConsistencyGroupVolume{
[CmdletBinding()]
param ( [Parameter(Mandatory=$true,ParameterSetName='CGByName',
                   ValueFromPipeline=$true,position=0)]
        [Alias('n')] 
        [string]$Name,
        [Parameter(Mandatory=$true,ParameterSetName='CGByIndex')]
        [Alias('i')] 
        [string]$ID,
        [Parameter(Mandatory=$true)]
        [Alias('cg')] 
        [string]$ConsistencyGroup,
        [Parameter(Mandatory=$false)]
        [Alias('c')] 
        [string]$Cluster
) 
    Begin{
        $UriObject = 'consistency-group-volumes'
    }
    Process{
        # Remove object by Name
        if($Name){
            $UriString = ($UriObject + '/?name=' + $Name)
            $JSoNBody = New-Object -TypeName psobject
            $JSoNBody | Add-Member -MemberType NoteProperty -Name vol-id -Value $Name
            $JSoNBody | Add-Member -MemberType NoteProperty -Name cg-id -Value $ConsistencyGroup
            if($Cluster){$JSoNBody | Add-Member -MemberType NoteProperty -Name cluster-id -Value $Cluster}
            Invoke-RestMethod -Method Delete -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders -Body ($JSoNBody | ConvertTo-Json)
        } 
    }
    End{
        # Remove object by Index
        if($ID){
            $UriString = ($UriObject + '/' + $ID)
            $JSoNBody = New-Object -TypeName psobject
            $JSoNBody | Add-Member -MemberType NoteProperty -Name vol-id -Value $Name
            $JSoNBody | Add-Member -MemberType NoteProperty -Name cg-id -Value $ConsistencyGroup
            if($Cluster){$JSoNBody | Add-Member -MemberType NoteProperty -Name cluster-id -Value $Cluster}
            Invoke-RestMethod -Method Delete -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders -Body ($JSoNBody | ConvertTo-Json)
        }
    }

    # Note - Need to experiment with pipeline and command options

} # Remove-XIOConsistencyGroupVolume

# .ExternalHelp MTSXtremIO.psm1-Help.xml
function Remove-XIOIscsiPortal{
[CmdletBinding()]
param ( [Parameter(Mandatory=$true,ParameterSetName='PortalByName',
                    ValueFromPipeline=$true, 
                    Position=0)] 
        [Alias('n')]
        [string]$Name,
        [Parameter(Mandatory=$true,ParameterSetName='PortalByID')] 
        [Alias('i')]
        [string]$ID,
        [Parameter(Mandatory=$true)]
        [Alias('ip')] 
        [string]$IPAddress,
        [Parameter(Mandatory=$false)]
        [Alias('c')] 
        [string]$Cluster
)
    Begin{
        $UriObject = 'iscsi-portals'
    }
    Process{
        if($Name){
            $UriString = ($UriObject + '/?name=' + $Name)
            $JSoNBody = New-Object -TypeName psobject

            # Required Parameters
            $JSoNBody | Add-Member -MemberType NoteProperty -Name ip-addr -Value $IPAddress
        
            # Optional Parameters
            if($Cluster){$JSoNBody | Add-Member -MemberType NoteProperty -Name cluster-id -Value $Cluster}
               
            Invoke-RestMethod -Method Post -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders -Body ($JSoNBody | ConvertTo-Json)
        }
    }
    End{
        if($ID){
            $UriString = ($UriObject + '/' + $ID)
            $JSoNBody = New-Object -TypeName psobject

            # Required Parameters
            $JSoNBody | Add-Member -MemberType NoteProperty -Name ip-addr -Value $IPAddress
        
            # Optional Parameters
            if($Cluster){$JSoNBody | Add-Member -MemberType NoteProperty -Name cluster-id -Value $Cluster}
            
            Invoke-RestMethod -Method Post -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders -Body ($JSoNBody | ConvertTo-Json)
        }
    }
} # Remove-XIOIscsiPortal

# .ExternalHelp MTSXtremIO.psm1-Help.xml
function Remove-XIOIscsiRoute{
[CmdletBinding()]
param ( [Parameter(Mandatory=$true,ParameterSetName='RouteByName',
                    ValueFromPipeline=$true, 
                    Position=0)] 
        [Alias('n')]
        [string]$Name,
        [Parameter(Mandatory=$true,ParameterSetName='RouteByID')] 
        [Alias('i')]
        [int]$ID,
        [Parameter(Mandatory=$false)]
        [ValidateNotNull()]
        [Alias('c')] 
        [string]$Cluster
)
    Begin{
        $UriObject = 'iscsi-routes'
    }
    Process{
        if($Name){
            $UriString = ($UriObject + '/?name=' + $Name)
            if($Cluster){
                # Optional Parameters
                $JSoNBody = New-Object -TypeName psobject
                $JSoNBody | Add-Member -MemberType NoteProperty -Name cluster-id -Value $Cluster
                Invoke-RestMethod -Method Delete -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders -Body ($JSoNBody | ConvertTo-Json)
            }else{
                Invoke-RestMethod -Method Delete -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders
            }   
        }
    }
    End{
        if($ID){
            $UriString = ($UriObject + '/' + $ID)
            if($Cluster){
                # Optional Parameters
                $JSoNBody = New-Object -TypeName psobject
                $JSoNBody | Add-Member -MemberType NoteProperty -Name cluster-id -Value $Cluster
                Invoke-RestMethod -Method Delete -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders -Body ($JSoNBody | ConvertTo-Json)
            }else{
                Invoke-RestMethod -Method Delete -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders
            }
        }
    }
    
} # Remove-XIOIscsiRoute

# .ExternalHelp MTSXtremIO.psm1-Help.xml
function Remove-XIOLunMap{
[CmdletBinding()]
param ( [Parameter(Mandatory=$true,ParameterSetName='LMByName', 
                    ValueFromPipeline=$true,
                    Position=0)]
        [Alias('n')] 
        [string]$Name,
        [Parameter(Mandatory=$true,ParameterSetName='LMByIndex')]
        [Alias('i')] 
        [string]$ID,
        [Parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [Alias('c')] 
        [string]$Cluster
)
    Begin{
        $UriObject = 'lun-maps'
    }
    Process{
        # Remove object by Name
        if($Name){
            $UriString = ($UriObject + '/?name=' + $Name)
            if($Cluster){
                # Optional Parameters
                $JSoNBody = New-Object -TypeName psobject
                $JSoNBody | Add-Member -MemberType NoteProperty -Name cluster-id -Value $Cluster
                Invoke-RestMethod -Method Delete -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders -Body ($JSoNBody | ConvertTo-Json)
            }else{
                Invoke-RestMethod -Method Delete -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders
            }
        }
    }
    End{
        # Remove object by ID
        if($ID){
            $UriString = ($UriObject + '/' + $ID)
            if($Cluster){
                # Optional Parameters
                $JSoNBody = New-Object -TypeName psobject
                $JSoNBody | Add-Member -MemberType NoteProperty -Name cluster-id -Value $Cluster
                Invoke-RestMethod -Method Delete -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders -Body ($JSoNBody | ConvertTo-Json)
            }else{
                Invoke-RestMethod -Method Delete -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders
            }
        }
    } 
} # Remove-XIOLunMap



Export-ModuleMember -Function New-PasswordFile
Export-ModuleMember -Function Get-PasswordFromFile
Export-ModuleMember -Function Disable-CertificateValidation
Export-ModuleMember -Function Set-XIOAPIConnectionInfo
Export-ModuleMember -Function Get-XIOAPITypes
Export-ModuleMember -Function Get-XIOItem


Export-ModuleMember -Function Get-XIOPerformance
Export-ModuleMember -Function Get-XIOXms
Export-ModuleMember -Function Get-XIOUserAccount
Export-ModuleMember -Function Get-XIOCluster
Export-ModuleMember -Function Get-XIOBrick
Export-ModuleMember -Function Get-XIOXenvs
Export-ModuleMember -Function Get-XIOStorageController
Export-ModuleMember -Function Get-XIOStorageControllerPSU
Export-ModuleMember -Function Get-XIODataProtectionGroup
Export-ModuleMember -Function Get-XIOTag
Export-ModuleMember -Function Get-XIOVolume
Export-ModuleMember -Function Get-XIOSnapshot
Export-ModuleMember -Function Get-XIOSnapshotSet
Export-ModuleMember -Function Get-XIOScheduler
Export-ModuleMember -Function Get-XIOInitiator
Export-ModuleMember -Function Get-XIOInitiatorGroup
Export-ModuleMember -Function Get-XIOTarget
Export-ModuleMember -Function Get-XIOTargetGroup
Export-ModuleMember -Function Get-XIOConsistencyGroup
Export-ModuleMember -Function Get-XIOConsistencyGroupVolume
Export-ModuleMember -Function Get-XIOIscsiPortal
Export-ModuleMember -Function Get-XIOIscsiRoute
Export-ModuleMember -Function Get-XIOLunMap
Export-ModuleMember -Function Get-XIOSSD
Export-ModuleMember -Function Get-XIOSlot
Export-ModuleMember -Function Get-XIOLocalDisk
Export-ModuleMember -Function Get-XIOBBU
Export-ModuleMember -Function Get-XIODAE
Export-ModuleMember -Function Get-XIODAEController
Export-ModuleMember -Function Get-XIODAEPSU
Export-ModuleMember -Function Get-XIOInfinibandSwitch
Export-ModuleMember -Function Get-XIOLDAPConfiguration
Export-ModuleMember -Function Get-XIOAlert
Export-ModuleMember -Function Get-XIOAlertDefinition
Export-ModuleMember -Function Get-XIOEmailNotifier
Export-ModuleMember -Function Get-XIOSNMPNotifier
Export-ModuleMember -Function Get-XIOSYRNotifier
Export-ModuleMember -Function Get-XIOSyslogNotifier
Export-ModuleMember -Function Get-XIOEvent


Export-ModuleMember -Function New-XIOUserAccount
Export-ModuleMember -Function New-XIOTag
Export-ModuleMember -Function New-XIOVolume
Export-ModuleMember -Function New-XIOSnapshot
Export-ModuleMember -Function New-XIOScheduler
Export-ModuleMember -Function New-XIOInitiator
Export-ModuleMember -Function New-XIOInitiatorGroup
Export-ModuleMember -Function New-XIOConsistencyGroup
Export-ModuleMember -Function New-XIOIscsiPortal
Export-ModuleMember -Function New-XIOIscsiRoute
Export-ModuleMember -Function New-XIOLunMap


Export-ModuleMember -Function Set-XIOTag
New-Alias -Name Rename-XIOTag -Value Set-XIOTag
Export-ModuleMember -Function Set-XIOVolume
Export-ModuleMember -Function Set-XIOSnapshot
Export-ModuleMember -Function Update-XIOSnapshot
Export-ModuleMember -Function Set-XIOScheduler
Export-ModuleMember -Function Set-XIOInitiator
Export-ModuleMember -Function Set-XIOInitiatorGroup
New-Alias -Name Rename-XIOInitiatorGroup -Value Set-XIOInitiatorGroup
Export-ModuleMember -Function Set-XIOConsistencyGroup
New-Alias -Name Rename-XIOConsistencyGroup -Value Set-XIOConsistencyGroup
Export-ModuleMember -Function Add-XIOConsistencyGroupVolume
Export-ModuleMember -Function Set-XIOTarget
Export-ModuleMember -Function Set-XIOLDAPConfiguration
Export-ModuleMember -Function Set-XIOAlertDefinition
Export-ModuleMember -Function Set-XIOEmailNotifier
Export-ModuleMember -Function Set-XIOSNMPNotifier
Export-ModuleMember -Function Set-XIOSYRNotifier
Export-ModuleMember -Function Set-XIOSyslogNotifier


Export-ModuleMember -Function Remove-XIOUserAccount
Export-ModuleMember -Function Remove-XIOTag
Export-ModuleMember -Function Remove-XIOVolume
Export-ModuleMember -Function Remove-XIOSnapshot
Export-ModuleMember -Function Remove-XIOSnapshotSet
Export-ModuleMember -Function Remove-XIOScheduler
Export-ModuleMember -Function Remove-XIOInitiator
Export-ModuleMember -Function Remove-XIOInitiatorGroup
Export-ModuleMember -Function Remove-XIOConsistencyGroup
Export-ModuleMember -Function Remove-XIOConsistencyGroupVolume
Export-ModuleMember -Function Remove-XIOIscsiPortal
Export-ModuleMember -Function Remove-XIOIscsiRoute
Export-ModuleMember -Function Remove-XIOLunMap