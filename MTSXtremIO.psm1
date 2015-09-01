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

# Base, helper and connection functions
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
    $baseuri = 'https://' + $hostname + '/api/json/types/'

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




# Read functions
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

    Process{
        # Return details of cluster names passed by parameter or pipeline
        if($Name){
            $UriString = 'clusters/'
            $UriString += ('?name=' + $Name)
            (Invoke-RestMethod -Method Get -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders).Content
        }
    }
    End{
        
        # Return detail of specific cluster by ID
        if($ID){
            $UriString = 'clusters/'
            $UriString += $ID
            (Invoke-RestMethod -Method Get -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders).Content
        }

        # No parameters passed return details of all clusters
        if($PSCmdlet.ParameterSetName -eq 'AllClusters'){
            $UriString = 'clusters/'
            (Get-XIOItem -UriString 'clusters').clusters | ForEach-Object{(Invoke-RestMethod -Method Get -Uri ($Global:XIOAPIBaseUri + $UriString + '?name=' + ($_.Name)) -Headers $Global:XIOAPIHeaders).Content}
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
   
    Process{
        # Return details of brick names passed by parameter or pipeline
        if($Name){
            $UriString = 'bricks/'
            $UriString += ('?name=' + $Name)
            (Invoke-RestMethod -Method Get -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders).content
        }
        
    }
    End{
        
        # Return detail of specific brick by ID
        if($ID){
            $UriString = 'bricks/'
            $UriString += $ID
            (Invoke-RestMethod -Method Get -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders).content
        }

        # No parameters passed return details of all bricks
        if($PSCmdlet.ParameterSetName -eq 'AllBricks'){
            $UriString = 'bricks/'
            (Get-XIOItem -UriString 'bricks').bricks | ForEach-Object{(Invoke-RestMethod -Method Get -Uri ($Global:XIOAPIBaseUri + $UriString + '?name=' + ($_.Name)) -Headers $Global:XIOAPIHeaders).Content}
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
   
    Process 
    {
        
        # Return details of xenv names passed by parameter or pipeline
        if($Name){
            $UriString = 'xenvs/'
            $UriString += ('?name=' + $Name)
            (Invoke-RestMethod -Method Get -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders).content
                
        }
        
    }
    End 
    {
        # Return detail of specific xenv by ID
        if($ID){
            $UriString = 'xenvs/'
            $UriString += $ID
            (Invoke-RestMethod -Method Get -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders).content
        }

        # No parameters passed return details of all xenvs
        if($PSCmdlet.ParameterSetName -eq 'AllXEnvs'){
            $UriString = 'xenvs/'
            (Get-XIOItem -UriString 'xenvs').xenvs | ForEach-Object{(Invoke-RestMethod -Method Get -Uri ($Global:XIOAPIBaseUri + $UriString + '?name=' + ($_.Name)) -Headers $Global:XIOAPIHeaders).Content}
        }

    }
    
} # Get-XIOXenvs

# .ExternalHelp MTSXtremIO.psm1-Help.xml
function Get-XIOVolume{
[CmdletBinding(DefaultParameterSetName='AllVolumes')]
param ( [Parameter(Mandatory=$true, 
                    ValueFromPipeline=$true,
                    Position=0,
                    ParameterSetName='VolByName')]
        [Alias('n')] 
        [string]$Name=$null,
        [Parameter(Mandatory=$true,
                    ParameterSetName='VolByIndex')]
        [Alias('i')] 
        [string]$ID=$null
)

    Process{
        # Return details of volume names passed by parameter or pipeline
        if($Name){
            $UriString = 'volumes/'
            $UriString += ('?name=' + $Name)
        }
        (Invoke-RestMethod -Method Get -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders).content

    }
    End{
        # Return detail of specific volume by ID
        if($ID){
            $UriString = 'volumes/'
            $UriString += $ID
            (Invoke-RestMethod -Method Get -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders).content
        }
        # No parameters passed return details of all volumes
        if($PSCmdlet.ParameterSetName -eq 'AllVolumes'){
            $UriString = 'volumes/'
            (Get-XIOItem -UriString 'volumes').volumes | ForEach-Object{(Invoke-RestMethod -Method Get -Uri ($Global:XIOAPIBaseUri + $UriString + '?name=' + ($_.Name)) -Headers $Global:XIOAPIHeaders).Content}
        }

    }
} # Get-XIOVolume

# .ExternalHelp MTSXtremIO.psm1-Help.xml
function Get-XIOVolumeFolder{
[CmdletBinding(DefaultParameterSetName='AllVolumeFolders')]
param ( [Parameter(Mandatory=$true,
                   ValueFromPipeline=$true, 
                   Position=0, 
                   ParameterSetName='FolderByName')]
        [Alias('n')] 
        [string]$Name=$null,
        [Parameter(Mandatory=$true,ParameterSetName='FolderByIndex')]
        [Alias('i')] 
        [string]$ID=$null
)

    Process{
        
        # Return details of volume folder names passed by parameter or pipeline       
        if($Name){
            $UriString = 'volume-folders/'
            $UriString += ('?name=' + $Name)
            (Invoke-RestMethod -Method Get -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders).content
        }
    }
    End{
        # Return detail of specific volume folder by ID            
        if($ID){
            $UriString = 'volume-folders/'
            $UriString += $ID
            (Invoke-RestMethod -Method Get -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders).content
        }
        # No parameters passed return details of all volume folders
        if($PSCmdlet.ParameterSetName -eq 'AllVolumeFolders'){
            $UriString = 'volume-folders/'
            (Get-XIOItem -UriString 'volume-folders').folders | ForEach-Object{(Invoke-RestMethod -Method Get -Uri ($Global:XIOAPIBaseUri + $UriString + '?name=' + ($_.Name)) -Headers $Global:XIOAPIHeaders).Content}
        }
    }
} # Get-XIOVolumeFolder

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
    Process{
        # Return details of storage controller names passed by parameter or pipeline             
        if($Name){
            $UriString = 'storage-controllers/'
            $UriString += ('?name=' + $Name)
            (Invoke-RestMethod -Method Get -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders).content
        }
    }
    End{
        # Return detail of specific  storage controller by ID  
        if($ID){
            $UriString = 'storage-controllers/' 
            $UriString += $ID
            (Invoke-RestMethod -Method Get -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders).content
        }
        # No parameters passed return details of all  storage controllers
        if($PSCmdlet.ParameterSetName -eq 'AllControllers'){
            $UriString = 'storage-controllers/'
            (Get-XIOItem -UriString 'storage-controllers').'storage-controllers' | ForEach-Object{(Invoke-RestMethod -Method Get -Uri ($Global:XIOAPIBaseUri + $UriString + '?name=' + ($_.Name)) -Headers $Global:XIOAPIHeaders).Content}
        }
    }
} # Get-XIOStorageController

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

    Process{
        # Return details of data protection group by name passed by parameter or pipeline
        if($Name){
            $UriString = 'data-protection-groups/'
            $UriString += ('?name=' + $Name)
            (Invoke-RestMethod -Method Get -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders).content
        }
    }
    End{
        # Return detail of specific data protection group by ID
        if($ID){
            $UriString = 'data-protection-groups/'
            $UriString += $ID
            (Invoke-RestMethod -Method Get -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders).content
        }
        # No parameters passed return details of all data protection groups
        if($PSCmdlet.ParameterSetName -eq 'AllDPGroups'){
            $UriString = 'data-protection-groups/'
            (Get-XIOItem -UriString 'data-protection-groups').'data-protection-groups' | ForEach-Object{(Invoke-RestMethod -Method Get -Uri ($Global:XIOAPIBaseUri + $UriString + '?name=' + ($_.Name)) -Headers $Global:XIOAPIHeaders).Content}
        }
    }
} # Get-XIODataProtectionGroup

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

    Process{
        # Return details of snapshot by name passed by parameter or pipeline
        if($Name){
            $UriString = 'snapshots/'
            $UriString += ('?name=' + $Name)
            (Invoke-RestMethod -Method Get -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders).content
        }
        
    }
    End{
        # Return detail of specific snapshot by ID
        if($ID){
            $UriString = 'snapshots/'
            $UriString += $ID
            (Invoke-RestMethod -Method Get -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders).content
        }
        # No parameters passed return details of all snapshots
        if($PSCmdlet.ParameterSetName -eq 'AllSnapshots'){
            $UriString = 'snapshots/'
            (Get-XIOItem -UriString 'snapshots').snapshots | ForEach-Object{(Invoke-RestMethod -Method Get -Uri ($Global:XIOAPIBaseUri + $UriString + '?name=' + ($_.Name)) -Headers $Global:XIOAPIHeaders).Content}
        }
    }
} # Get-XIOSnapshot

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

    Process{
        # Return details of initiator by name passed by parameter or pipeline
        if($Name){
            $UriString = 'initiators/'
            $UriString += ('?name=' + $Name)

        }
        (Invoke-RestMethod -Method Get -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders).content
    }
    End{
        # Return detail of specific initiator by ID
        if($ID){
            $UriString = 'initiators/'
            $UriString += $ID
            (Invoke-RestMethod -Method Get -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders).content
        }
        # No parameters passed return details of all initiator
        if($PSCmdlet.ParameterSetName -eq 'AllInitiators'){
            $UriString = 'initiators/'
            (Get-XIOItem -UriString 'initiators').initiators | ForEach-Object{(Invoke-RestMethod -Method Get -Uri ($Global:XIOAPIBaseUri + $UriString + '?name=' + ($_.Name)) -Headers $Global:XIOAPIHeaders).Content}
        }
    }
} # Get-XIOInitiator

# .ExternalHelp MTSXtremIO.psm1-Help.xml
function Get-XIOInitiatorGroup{
[CmdletBinding(DefaultParameterSetName='AllInitiatorGroups')]
param ( [Parameter(Mandatory=$true,
                   ValueFromPipeline=$true,
                   Position=0, 
                   ParameterSetName='IGByName')]
        [Alias('n')] 
        [string]$Name=$null,
        [Parameter(Mandatory=$true,ParameterSetName='IGByIndex')]
        [Alias('i')] 
        [string]$ID=$null
)

    Process{
        # Return details of initiator group by name passed by parameter or pipeline          
        if($Name){
            $UriString = 'initiator-groups/'
            $UriString += ('?name=' + $Name)
            (Invoke-RestMethod -Method Get -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders).content
        }
    }
    End{
        # Return detail of specific initiator group by ID
        if($ID){ 
            $UriString = 'initiator-groups/'
            $UriString += $ID
            (Invoke-RestMethod -Method Get -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders).content
        }
        # No parameters passed return details of all initiator groups
        if($PSCmdlet.ParameterSetName -eq 'AllInitiatorGroups'){
            $UriString = 'initiator-groups/'
            (Get-XIOItem -UriString 'initiator-groups').'initiator-groups' | ForEach-Object{(Invoke-RestMethod -Method Get -Uri ($Global:XIOAPIBaseUri + $UriString + '?name=' + ($_.Name)) -Headers $Global:XIOAPIHeaders).Content}
        }
    }
} # Get-XIOInitiatorGroup

# .ExternalHelp MTSXtremIO.psm1-Help.xml
function Get-XIOInitiatorGroupFolder{
[CmdletBinding(DefaultParameterSetName='AllIGFolders')]
param ( [Parameter(Mandatory=$true,
                   ValueFromPipeline=$true,
                   Position=0, 
                   ParameterSetName='IGFolderByName')]
        [Alias('n')] 
        [string]$Name=$null,
        [Parameter(Mandatory=$true,ParameterSetName='IGFolderByIndex')]
        [Alias('i')] 
        [string]$ID=$null
)

    Process{
        # Return details of initiator group folder by name passed by parameter or pipeline
        if($Name){
            $UriString = 'ig-folders/'
            $UriString += ('?name=' + $Name)
            (Invoke-RestMethod -Method Get -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders).content
        }
    }
    End{
        # Return detail of specific initiator group folder by ID
        if($ID){
            $UriString = 'ig-folders/'
            $UriString += $ID
            (Invoke-RestMethod -Method Get -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders).content
        }
        # No parameters passed return details of all initiator group folders
        if($PSCmdlet.ParameterSetName -eq 'AllIGFolders'){
            $UriString = 'ig-folders/'
            (Get-XIOItem -UriString 'ig-folders').folders | ForEach-Object{(Invoke-RestMethod -Method Get -Uri ($Global:XIOAPIBaseUri + $UriString + '?name=' + ($_.Name)) -Headers $Global:XIOAPIHeaders).Content}
        }
    }
} # Get-XIOInitiatorGroupFolder

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

    Process{
        # Return details of target by name passed by parameter or pipeline
        if($Name){
            $UriString = 'targets/'
            $UriString += ('?name=' + $Name)
            (Invoke-RestMethod -Method Get -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders).content
        }
    }
    End{
        # Return detail of specific target by ID
        if($ID){
            $UriString = 'targets/'
            $UriString += $ID
            (Invoke-RestMethod -Method Get -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders).content
        }
        
        # No parameters passed return details of all targets
        if($PSCmdlet.ParameterSetName -eq 'AllTargets'){
            $UriString = 'targets/'
            (Get-XIOItem -UriString 'targets').targets | ForEach-Object{(Invoke-RestMethod -Method Get -Uri ($Global:XIOAPIBaseUri + $UriString + '?name=' + ($_.Name)) -Headers $Global:XIOAPIHeaders).Content}
        }
    }
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
    Process{
        
        # Return details of target group by name passed by parameter or pipeline
        if($Name){
            $UriString = 'target-groups/'
            $UriString += ('?name=' + $Name)
            (Invoke-RestMethod -Method Get -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders).content
        }
    }
    End{
        # Return detail of specific target group by ID   
        if($ID){
            $UriString = 'target-groups/'
            $UriString += $ID
            (Invoke-RestMethod -Method Get -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders).content
        }
        # No parameters passed return details of all target groups
        if($PSCmdlet.ParameterSetName -eq 'AllTargetGroups'){
            $UriString = 'target-groups/'
            (Get-XIOItem -UriString 'target-groups').'target-groups' | ForEach-Object{(Invoke-RestMethod -Method Get -Uri ($Global:XIOAPIBaseUri + $UriString + '?name=' + ($_.Name)) -Headers $Global:XIOAPIHeaders).Content}
        }
    }
} # Get-XIOTargetGroup

# .ExternalHelp MTSXtremIO.psm1-Help.xml
function Get-XIOIscsiPortal{
[CmdletBinding(DefaultParameterSetName='AllISCSIPortals')]
param ( [Parameter(Mandatory=$true,
                   ValueFromPipeline=$true,
                   Position=0, 
                   ParameterSetName='IsPortalByName')]
        [Alias('n')] 
        [string]$Name=$null,
        [Parameter(Mandatory=$true,ParameterSetName='IsPortalByIndex')]
        [Alias('i')] 
        [string]$ID=$null
)

    Process{
        # Return details of iscsi portal by name passed by parameter or pipeline                
        if($Name){
            $UriString = 'iscsi-portals/'
            $UriString += ('?name=' + $Name)
            (Invoke-RestMethod -Method Get -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders).content
        }
    }
    End{
        # Return detail of specific iscsi portal by ID
        if($ID){ 
            $UriString = 'iscsi-portals/'
            $UriString += $ID
            (Invoke-RestMethod -Method Get -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders).content
        }
        # No parameters passed return details of all iscsi portals
        if($PSCmdlet.ParameterSetName -eq 'AllISCSIPortals'){
            $UriString = 'iscsi-portals/'
            (Get-XIOItem -UriString 'iscsi-portals').'iscsi-portals' | ForEach-Object{(Invoke-RestMethod -Method Get -Uri ($Global:XIOAPIBaseUri + $UriString + '?name=' + ($_.Name)) -Headers $Global:XIOAPIHeaders).Content}
        }
    }
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

    Process{
        # Return details of iscsi route by name passed by parameter or pipeline           
        if($Name){
            $UriString = 'iscsi-routes/'
            $UriString += ('?name=' + $Name)
            (Invoke-RestMethod -Method Get -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders).content
        }
    }
    End{
        # Return detail of specific iscsi route by ID
        if($ID){
            $UriString = 'iscsi-routes/' 
            $UriString += $ID
            (Invoke-RestMethod -Method Get -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders).content
        }
        # No parameters passed return details of all iscsi routes
        if($PSCmdlet.ParameterSetName -eq 'AllISCSIRoutes'){
            $UriString = 'iscsi-routes/'
            (Get-XIOItem -UriString 'iscsi-routes').'iscsi-routes' | ForEach-Object{(Invoke-RestMethod -Method Get -Uri ($Global:XIOAPIBaseUri + $UriString + '?name=' + ($_.Name)) -Headers $Global:XIOAPIHeaders).Content}
        }
    }
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

    Process{
        # Return details of lun map by name passed by parameter or pipeline                
        if($Name){
            $UriString = 'lun-maps/'
            $UriString += ('?name=' + $Name)
            (Invoke-RestMethod -Method Get -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders).content
        }
    }
    End{
        # Return detail of specific lun map by ID
        if($ID){
            $UriString = 'lun-maps/'
            $UriString += $ID
            (Invoke-RestMethod -Method Get -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders).content
        }
        # No parameters passed return details of all lun maps
        if($PSCmdlet.ParameterSetName -eq 'AllLunMaps'){
            $UriString = 'lun-maps/'
            (Get-XIOItem -UriString 'lun-maps').'lun-maps' | ForEach-Object{(Invoke-RestMethod -Method Get -Uri ($Global:XIOAPIBaseUri + $UriString + '?name=' + ($_.Name)) -Headers $Global:XIOAPIHeaders).Content}
        }
    }
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
    Process{
        # Return details of ssd by name passed by parameter or pipeline
        if($Name){
            $UriString = 'ssds/'
            $UriString += ('?name=' + $Name)
            (Invoke-RestMethod -Method Get -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders).content
        }
        
    }
    End{
        # Return detail of specific ssd by ID
        if($ID){
                $UriString = 'ssds/'
                $UriString += $ID
                (Invoke-RestMethod -Method Get -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders).content
            }
        # No parameters passed return details of all ssds
        if($PSCmdlet.ParameterSetName -eq 'AllSSDs'){
            $UriString = 'ssds/'
            (Get-XIOItem -UriString 'ssds').ssds | ForEach-Object{(Invoke-RestMethod -Method Get -Uri ($Global:XIOAPIBaseUri + $UriString + '?name=' + ($_.Name)) -Headers $Global:XIOAPIHeaders).Content}
        }
    }
} # Get-XIOSSD

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




# Create functions
# .ExternalHelp MTSXtremIO.psm1-Help.xml
function New-XIOVolume{
[CmdletBinding()]
param ( [Parameter(Mandatory=$true)]
        [Alias('s')]
        [Alias('vs')]
        [Alias('VolSize')]
        [string]$Size=$null,
        [Parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [Alias('n')] 
        [Alias('vn')]
        [Alias('VolName')]
        [string]$Name=$null,
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
    
    
    $UriString = 'volumes'
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
    
    # TODO - Need to experiment with options of using pipline.
    
} # New-XIOVolume

# .ExternalHelp MTSXtremIO.psm1-Help.xml
function New-XIOVolumeFolder{
[CmdletBinding()]
param ( [Parameter(Mandatory=$true)]
        [Alias('c')] 
        [string]$Caption=$null,
        [Parameter(Mandatory=$true)]
        [Alias('pn')] 
        [string]$ParentFolderName=$null
)
    
    
    $UriString = 'volume-folders'
    $JSoNBody = New-Object -TypeName psobject
    $JSoNBody | Add-Member -MemberType NoteProperty -Name caption -Value $Caption
    if($ParentFolderName){$JSoNBody | Add-Member -MemberType NoteProperty -Name parent-folder-id -Value $ParentFolderName}        

    (Invoke-RestMethod -Method Post -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders -Body ($JSoNBody | ConvertTo-Json)).Links
    


} # New-XIOVolumeFolder

# .ExternalHelp MTSXtremIO.psm1-Help.xml
function New-XIOLunMap{
[CmdletBinding()]
param ( [Parameter(Mandatory=$true,
                    ValueFromPipeline=$true, 
                    Position=0,
                    ParameterSetName='VolByName')]
        [Alias('n')] 
        [string]$Name=$null,
        [Parameter(Mandatory=$true,ParameterSetName='VolByID')]
        [Alias('i')] 
        [int]$ID=$null,
        [Parameter(Mandatory=$false)]
        [ValidateNotNull()]
        [Alias('ig')] 
        [int]$InitiatorGroup=$null,
        [Parameter(Mandatory=$false)]
        [ValidateNotNull()]
        [Alias('hi')] 
        [int]$HostID=$null,
        [Parameter(Mandatory=$false,ParameterSetName='TGByID')]
        [Parameter(ParameterSetName='VolByName')]
        [Parameter(ParameterSetName='VolByID')]
        [ValidateNotNull()]
        [Alias('tgi')] 
        [int]$TargetGroupID=$null,
        [Parameter(Mandatory=$false,ParameterSetName='TGByName')]
        [Parameter(ParameterSetName='VolByName')]
        [Parameter(ParameterSetName='VolByID')]
        [ValidateNotNullOrEmpty()]
        [Alias('tgn')] 
        [string]$TargetGroupName=$null
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
            if($TargetGroupID){$JSoNBody | Add-Member -MemberType NoteProperty -Name tg-id -Value $TargetGroupID}
            if($TargetGroupName){$JSoNBody | Add-Member -MemberType NoteProperty -Name tg-name -Value $TargetGroupName}
            Invoke-RestMethod -Method Post -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders -Body ($JSoNBody | ConvertTo-Json)
            
        }


} # New-XIOLunMap

# .ExternalHelp MTSXtremIO.psm1-Help.xml
function New-XIOSnapshot{
[CmdletBinding()]
param ( [Parameter(Mandatory=$true,
                    ValueFromPipeline=$true, 
                    Position=0)]
        [Alias('n')] 
        [Alias('VolName')]
        [Alias('vn')]
        [string]$Name=$null,
        [Parameter(Mandatory=$true)]
        [Alias('sn')] 
        [string]$SnapName=$null,
        [Parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [Alias('f')] 
        [string]$FolderID=$null
)

    Begin{

        $UriString = 'snapshots'

    }

    Process{
            
        $JSoNBody = New-Object -TypeName psobject
        if($Name){$JSoNBody | Add-Member -MemberType NoteProperty -Name ancestor-vol-id -Value $Name}
        if($SnapName){$JSoNBody | Add-Member -MemberType NoteProperty -Name snap-vol-name -Value $SnapName}
        if($FolderID){$JSoNBody | Add-Member -MemberType NoteProperty -Name folder-id -Value $FolderID}
        Invoke-RestMethod -Method Post -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders -Body ($JSoNBody | ConvertTo-Json)
            
    }

    # TODO - Does not implement REST API functionality to complete snapshot of set of volumes, but easily done using PowerShell features

} # New-XIOSnapshot

# .ExternalHelp MTSXtremIO.psm1-Help.xml
function New-XIOIGFolder{
[CmdletBinding()]
param ( [Parameter(Mandatory=$true)]
        [Alias('c')] 
        [string]$Caption=$null,
        [Parameter(Mandatory=$true)]
        [Alias('pn')] 
        [string]$ParentFolderName=$null
)
    
        $UriString = 'ig-folders'
        $JSoNBody = New-Object -TypeName psobject
        $JSoNBody | Add-Member -MemberType NoteProperty -Name caption -Value $Caption
        if($ParentFolderName){$JSoNBody | Add-Member -MemberType NoteProperty -Name parent-folder-id -Value $ParentFolderName}        

        (Invoke-RestMethod -Method Post -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders -Body ($JSoNBody | ConvertTo-Json)).Links
        

} # New-XIOIGFolder





# TODO - New-XIOInitiator

# TODO - New-XIOInitiatorGroup

# TODO - New-XIOIscsiPortal

# TODO - New-XIOIscsiRoute



# Set functions
# .ExternalHelp MTSXtremIO.psm1-Help.xml
function Set-XIOVolumeFolder{
[CmdletBinding()]
param ( [Parameter(Mandatory=$true)]
        [Alias('c')] 
        [string]$Caption=$null,
        [Parameter(Mandatory=$true,ParameterSetName='FolderByName')]
        [Alias('fn')] 
        [string]$FolderName=$null,
        [Parameter(Mandatory=$true,ParameterSetName='FolderByID')]
        [Alias('fid')] 
        [string]$FolderID=$null
       )
    

    $UriString = 'volume-folders/'
    $JSoNBody = New-Object -TypeName psobject
    $JSoNBody | Add-Member -MemberType NoteProperty -Name new-caption -Value $Caption
    if($FolderName){$UriString += ('?name=' + $FolderName)}
    if($FolderID){$UriString += $FolderID}

    $ReturnData = Invoke-RestMethod -Method Put -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders -Body ($JSoNBody | ConvertTo-Json)
    $ReturnData

} # Set-XIOVolumeFolder

# .ExternalHelp MTSXtremIO.psm1-Help.xml
function Set-XIOVolume{
[CmdletBinding()]
param ( [Parameter(Mandatory=$true, 
                    ParameterSetName='VolNameUpdateByIndex')]
        [Parameter(ParameterSetName='VolSizeUpdateByIndex')]
        [Parameter(ParameterSetName='SmallIOAlertUpdateByIndex')]
        [Parameter(ParameterSetName='UnalignedIOAlertUpdateByIndex')]
        [Parameter(ParameterSetName='VAAITPAlertUpdateByIndex')]
        [Alias('vid')] 
        [string]$VolID=$null,
        [Parameter(Mandatory=$true, 
                    ParameterSetName='VolNameUpdateByName')]
        [Parameter(ParameterSetName='VolSizeUpdateByName')]
        [Parameter(ParameterSetName='SmallIOAlertUpdateByName')]
        [Parameter(ParameterSetName='UnalignedIOAlertUpdateByName')]
        [Parameter(ParameterSetName='VAAITPAlertUpdateByName')]
        [Alias('vn')] 
        [string]$VolName=$null,
        [Parameter(Mandatory=$false,ParameterSetName='VolNameUpdateByIndex')]
        [Parameter(ParameterSetName='VolNameUpdateByName')]
        [ValidateNotNullOrEmpty()]
        [string]$NewVolName=$null,
        [Parameter(Mandatory=$false,ParameterSetName='VolSizeUpdateByIndex')]
        [Parameter(ParameterSetName='VolSizeUpdateByName')]
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
    
    
        
    $UriString = 'volumes/'
    if($VolID){
        $UriString += $VolID
    }
    if($VolName){
        $UriString += ('?name=' + $VolName)
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

    $ReturnData = Invoke-RestMethod -Method Put -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders -Body ($JSoNBody | ConvertTo-Json)
    $ReturnData

} # Set-XIOVolume

# .ExternalHelp MTSXtremIO.psm1-Help.xml
function Set-XIOIGFolder{
[CmdletBinding()]
param ( [Parameter(Mandatory=$true)]
        [Alias('c')] 
        [string]$Caption=$null,
        [Parameter(Mandatory=$true,ParameterSetName='FolderByName')]
        [Alias('fn')] 
        [string]$FolderName=$null,
        [Parameter(Mandatory=$true,ParameterSetName='FolderByID')]
        [Alias('fid')] 
        [string]$FolderID=$null
       )
    
    
    $UriString = 'ig-folders/'
    $JSoNBody = New-Object -TypeName psobject
    $JSoNBody | Add-Member -MemberType NoteProperty -Name new-caption -Value $Caption
    if($FolderName){$UriString += ('?name=' + $FolderName)}
    if($FolderID){$UriString += $FolderID}

    $ReturnData = Invoke-RestMethod -Method Put -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders -Body ($JSoNBody | ConvertTo-Json)
    $ReturnData

} # Set-XIOIGFolder

# TODO - Set/Update-XIOInitiator

# TODO - Set/Rename-XIOInitiatorGroup



# Remove Functions
# .ExternalHelp MTSXtremIO.psm1-Help.xml
function Remove-XIOVolume{
[CmdletBinding()]
param ( [Parameter(Mandatory=$true, 
                    ValueFromPipeline=$true,
                    Position=0,
                    ParameterSetName='VolByName')]
        [Alias('n')]
        [Alias('vn')] 
        [Alias('VolName')]
        [string]$Name=$null,
        [Parameter(Mandatory=$true, 
                    ParameterSetName='VolByIndex')]
        [Alias('vid')]
        [Alias('i')]
        [Alias('VolID')] 
        [string]$ID=$null
        
)
    
    Process{
        # Remove Volume by Name
        if($Name){
            $UriString = 'volumes/'
            $UriString += ('?name=' + $Name)
            Invoke-RestMethod -Method Delete -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders
        }
        
    }
    End{
        # Remove Volume by ID
        if($ID){
            $UriString = 'volumes/'
            $UriString += $ID
            Invoke-RestMethod -Method Delete -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders
        }
    }

    
} # Remove-XIOVolume

# .ExternalHelp MTSXtremIO.psm1-Help.xml
function Remove-XIOVolumeFolder{
[CmdletBinding()]
param ( [Parameter(Mandatory=$true, 
                    ValueFromPipeline=$true,
                    Position=0,
                    ParameterSetName='FolderByName')]
        [Alias('n')] 
        [string]$Name=$null,
        [Parameter(Mandatory=$true, 
                    ParameterSetName='FolderByIndex')]
        [Alias('i')] 
        [string]$ID=$null
        
)
    
    Process{

        # Remove Volume Folders By Name
        if($Name){
            $UriString = 'volume-folders/'
            $UriString += ('?name=' + $Name)
            Invoke-RestMethod -Method Delete -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders
        }

    }
    End{
        # Remove Volume Folders By ID
        if($ID){
            $UriString = 'volume-folders/'
            $UriString += $ID
            Invoke-RestMethod -Method Delete -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders
        }

    }

    
     
} # Remove-XIOVolumeFolder

# .ExternalHelp MTSXtremIO.psm1-Help.xml
function Remove-XIOLunMap{
[CmdletBinding()]
param ( [Parameter(Mandatory=$true, 
                    ValueFromPipeline=$true,
                    Position=0,
                    ParameterSetName='LMByName')]
        [Alias('n')] 
        [string]$Name=$null,
        [Parameter(Mandatory=$true, 
                    ParameterSetName='LMByIndex')]
        [Alias('i')] 
        [string]$ID=$null
)
    
    Process{
        # Remove LUN Map by Name
        if($Name){
            $UriString = 'lun-maps/'
            $UriString += ('?name=' + $Name)
            Invoke-RestMethod -Method Delete -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders
        }
    }
    End{
        # Remove LUN Map by ID
        if($ID){
            $UriString = 'lun-maps/'
            $UriString += $ID
            Invoke-RestMethod -Method Delete -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders
        }
    } 
    
    
    

} # Remove-XIOLunMap

# .ExternalHelp MTSXtremIO.psm1-Help.xml
function Remove-XIOSnapshot{
[CmdletBinding()]
param ( [Parameter(Mandatory=$true, 
                    ValueFromPipeline=$true, 
                    Position=0,
                    ParameterSetName='VolByName')]
        [Alias('n')]
        [Alias('vn')] 
        [Alias('VolName')]
        [string]$Name=$null,
        [Parameter(Mandatory=$true,
                    ParameterSetName='VolByIndex')]
        [Alias('i')]
        [Alias('vid')] 
        [Alias('VolId')]
        [string]$ID=$null
        
)
    Process{
        # Remove Snapshot by Name
        if($Name){
            $UriString = 'volumes/'
            $UriString += ('?name=' + $Name)
            Invoke-RestMethod -Method Delete -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders
        }
    
    }
    End{
        # Remove Snapshot by ID
        if($ID){
            $UriString = 'volumes/'
            $UriString += $ID
            Invoke-RestMethod -Method Delete -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders
        }
    }
        
} # Remove-XIOSnapshot


# TODO - Remove-XIOInitiator

# TODO - Remove-XIOInitiatorGroup

# TODO - Remove-XIOIGFolder

# TODO - Remove-XIOIscsiPortal

# TODO - Remove-XIOIscsiRoute





Export-ModuleMember -Function New-PasswordFile
Export-ModuleMember -Function Get-PasswordFromFile
Export-ModuleMember -Function Disable-CertificateValidation
Export-ModuleMember -Function Set-XIOAPIConnectionInfo


Export-ModuleMember -Function Get-XIOAPITypes
Export-ModuleMember -Function Get-XIOItem


Export-ModuleMember -Function Get-XIOCluster
Export-ModuleMember -Function Get-XIOBrick
Export-ModuleMember -Function Get-XIOXenvs
Export-ModuleMember -Function Get-XIOVolume
Export-ModuleMember -Function Get-XIOVolumeFolder
Export-ModuleMember -Function Get-XIOStorageController
Export-ModuleMember -Function Get-XIOTargetGroup
Export-ModuleMember -Function Get-XIODataProtectionGroup
Export-ModuleMember -Function Get-XIOSnapshot
Export-ModuleMember -Function Get-XIOInitiator
Export-ModuleMember -Function Get-XIOInitiatorGroup
Export-ModuleMember -Function Get-XIOInitiatorGroupFolder
Export-ModuleMember -Function Get-XIOTarget
Export-ModuleMember -Function Get-XIOTargetGroup
Export-ModuleMember -Function Get-XIOIscsiPortal
Export-ModuleMember -Function Get-XIOIscsiRoute
Export-ModuleMember -Function Get-XIOLunMap
Export-ModuleMember -Function Get-XIOSSD
Export-ModuleMember -Function Get-XIOEvent


Export-ModuleMember -Function New-XIOVolume
Export-ModuleMember -Function New-XIOVolumeFolder
Export-ModuleMember -Function New-XIOLunMap
Export-ModuleMember -Function New-XIOSnapshot
Export-ModuleMember -Function New-XIOIGFolder


Export-ModuleMember -Function Rename-XIOVolumeFolder
Export-ModuleMember -Function Update-XIOVolume
Export-ModuleMember -Function Rename-XIOIGFolder

New-Alias -Name Rename-XIOVolumeFolder -Value Set-XIOVolumeFolder
New-Alias -Name Update-XIOVolume -Value Set-XIOVolume
New-Alias -Name Rename-XIOIGFolder -Value Set-XIOIGFolder

Export-ModuleMember -Function Remove-XIOVolume
Export-ModuleMember -Function Remove-XIOVolumeFolder
Export-ModuleMember -Function Remove-XIOLunMap
Export-ModuleMember -Function Remove-XIOSnapshot