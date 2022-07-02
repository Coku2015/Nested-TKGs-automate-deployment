# Before you start, please install VMware PowerCLI in your Powershell 7 console.
# This Script is based on William Lam's automation tkg script.
# Please find detail from https://williamlam.com/2020/11/complete-vsphere-with-tanzu-homelab-with-just-32gb-of-memory.html
# Author: Lei Wei
# Website: https://blog.backupnext.cloud/

Set-PowerCLIConfiguration -InvalidCertificateAction:Ignore -Confirm:$false

# vCenter Server used to deploy vSphere with Tanzu  Basic Lab
$VIServer = "172.19.226.20"
$VIUsername = "administrator@vsphere.local"
$VIPassword = "P@ssw0rd"

# Full Path to both the Nested ESXi 7.0 VA, Extracted VCSA 7.0 ISO & HA Proxy OVAs
$NestedESXiApplianceOVA = "C:\Temp\Nested_ESXi7.0u3c_Appliance_Template_v1.ova"
$VCSAInstallerPath = "E:\"
$HAProxyOVA = "C:\Temp\haproxy-v0.2.0.ova"
$tkgrouterOVA = "C:\Temp\tkgrouter.ova"

# TKG Content Library URL
$TKGContentLibraryName = "TKG-Content-Library"
$TKGContentLibraryURL = "https://wp-content.vmware.com/v2/latest/lib.json"

#tkgrouter configuration
$tkgrouterdisplayname = "tkgopenwrt"
$WANNETWORK = "SHASELAB_NET01"
$WANIP = "172.19.226.149"
$WANGW = "172.19.226.1"
$WANDNS1 = "172.19.226.21"
$WANDNS2 = "172.19.192.10"
$WANNETMASK = "255.255.255.0"
$TKGMGMTNETWORK = "TKG-MGMT"
$TKGMGMTIP = "10.10.1.1"
$TKGWORKLOADNETWORK = "TKG-Workload"
$TKGWORKLOADIP = "10.10.2.1"
$TKGFRONTENDNETWORK = "TKG-Frontend"
$TKGFRONTENDIP = "10.10.3.1"


# Nested ESXi VMs to deploy
$NestedESXiHostnameToIPs = @{
    "tkgesxi1" = "10.10.1.100";
}

# Nested ESXi VM Resources
$NestedESXivCPU = "4"
$NestedESXivMEM = "32" #GB
$NestedESXiCapacityvDisk = "1000" #GB

# VCSA Deployment Configuration
$VCSADeploymentSize = "tiny"
$VCSADisplayName = "tkgsvc"
$VCSAIPAddress = "10.10.1.101"
$VCSAHostname = "10.10.1.101" #Change to IP if you don't have valid DNS
$VCSAPrefix = "24"
$VCSASSODomainName = "tkg.local"
$VCSASSOPassword = "P@ssw0rd"
$VCSARootPassword = "P@ssw0rd"
$VCSASSHEnable = "true"

# HA Proxy Configuration
$HAProxyDisplayName = "tkghaproxy"
$HAProxyHostname = "haproxy.tkg.local"
$HAProxyDNS = "10.10.1.1"
$HAProxyManagementNetwork = "TKG-Mgmt"
$HAProxyManagementIPAddress = "10.10.1.102/24" # Format is IP Address/CIDR Prefix
$HAProxyManagementGateway = "10.10.1.1"
$HAProxyFrontendNetwork = "TKG-Frontend"
$HAProxyFrontendIPAddress = "10.10.3.2/24" # Format is IP Address/CIDR Prefix
$HAProxyFrontendGateway = "10.10.3.1"
$HAProxyWorkloadNetwork = "TKG-Workload"
$HAProxyWorkloadIPAddress = "10.10.2.2/24" # Format is IP Address/CIDR Prefix
$HAProxyWorkloadGateway = "10.10.2.1"
$HAProxyLoadBalanceIPRange = "10.10.3.64/26" # Format is Network CIDR Notation
$HAProxyOSPassword = "P@ssw0rd"
$HAProxyPort = "5556"
$HAProxyUsername = "wcp"
$HAProxyPassword = "P@ssw0rd"

# General Deployment Configuration for Nested ESXi, VCSA & HA Proxy VM
$VMDatacenter = "SHALABDC"
$VMCluster = "SHALAB"
$VMNetwork = "TKG-Mgmt"
$VMDatastore = "SHASEESX_DS_01"
$VMNetmask = "255.255.255.0"
$VMGateway = "10.10.1.1"
$VMDNS = "172.19.226.21"
$VMNTP = "172.19.226.21"
$VMPassword = "P@ssw0rd"
$VMDomain = "shlab.local"
$VMSyslog = "10.10.1.1"
$VMFolder = "Lab Infra"
# Applicable to Nested ESXi only
$VMSSH = "true"
$VMVMFS = "false"

# Name of new vSphere Datacenter/Cluster when VCSA is deployed
$NewVCDatacenterName = "tkgs-dc"
$NewVCVSANClusterName = "tkgs-Cluster"
$NewVCVDSName = "tkgs-VDS"
$NewVCMgmtPortgroupName = "tkgs-mgmt"
$NewVCWorkloadPortgroupName = "tkgs-workload"

# Tanzu Configuration
$StoragePolicyName = "tkgs-demo-storage-policy"
$StoragePolicyTagCategory = "tkgs-demo-tag-category"
$StoragePolicyTagName = "tkgs-demo-storage"

# Advanced Configurations
# Set to 1 only if you have DNS (forward/reverse) for ESXi hostnames
$addHostByDnsName = 0

#### DO NOT EDIT BEYOND HERE ####

$debug = $true
$verboseLogFile = "tanzu-basic-lab-deployment.log"
$random_string = -join ((65..90) + (97..122) | Get-Random -Count 8 | % { [char]$_ })
$VAppName = "Tanzu-Nested-Lab-$random_string"

$preCheck = 1
$confirmDeployment = 1
$deployHAProxy = 1
$deployNestedESXiVMs = 1
$deployVCSA = 1
$deploytkgrouter = 1
$setupNewVC = 1
$addESXiHostsToVC = 1
$configurelocalvmfs = 1
$configureVDS = 1
$setupPacificStoragePolicy = 1
$setupPacific = 1
$moveVMsIntovApp = 1

$vcsaSize2MemoryStorageMap = @{
    "tiny"   = @{"cpu" = "2"; "mem" = "12"; "disk" = "415" };
    "small"  = @{"cpu" = "4"; "mem" = "19"; "disk" = "480" };
    "medium" = @{"cpu" = "8"; "mem" = "28"; "disk" = "700" };
    "large"  = @{"cpu" = "16"; "mem" = "37"; "disk" = "1065" };
    "xlarge" = @{"cpu" = "24"; "mem" = "56"; "disk" = "1805" }
}

$esxiTotalCPU = 0
$vcsaTotalCPU = 0
$esxiTotalMemory = 0
$vcsaTotalMemory = 0
$esxiTotalStorage = 0
$vcsaTotalStorage = 0
$tkgrouterTotalCPU = 1
$tkgrouterTotalMemory = 0.5
$tkgrouterTotalStorage = 1
$haproxyTotalCPU = 2
$haproxyTotalMemory = 4
$haproxyTotalStorage = 5

$StartTime = Get-Date

Function Get-SSLThumbprint {
    param(
        [Parameter(
            Position = 0,
            Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true)
        ]
        [Alias('FullName')]
        [String]$URL
    )

    $Code = @'
using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
namespace CertificateCapture
{
    public class Utility
    {
        public static Func<HttpRequestMessage,X509Certificate2,X509Chain,SslPolicyErrors,Boolean> ValidationCallback =
            (message, cert, chain, errors) => {
                var newCert = new X509Certificate2(cert);
                var newChain = new X509Chain();
                newChain.Build(newCert);
                CapturedCertificates.Add(new CapturedCertificate(){
                    Certificate =  newCert,
                    CertificateChain = newChain,
                    PolicyErrors = errors,
                    URI = message.RequestUri
                });
                return true;
            };
        public static List<CapturedCertificate> CapturedCertificates = new List<CapturedCertificate>();
    }
    public class CapturedCertificate
    {
        public X509Certificate2 Certificate { get; set; }
        public X509Chain CertificateChain { get; set; }
        public SslPolicyErrors PolicyErrors { get; set; }
        public Uri URI { get; set; }
    }
}
'@
    if ($PSEdition -ne 'Core') {
        Add-Type -AssemblyName System.Net.Http
        if (-not ("CertificateCapture" -as [type])) {
            Add-Type $Code -ReferencedAssemblies System.Net.Http
        }
    }
    else {
        if (-not ("CertificateCapture" -as [type])) {
            Add-Type $Code
        }
    }

    $Certs = [CertificateCapture.Utility]::CapturedCertificates

    $Handler = [System.Net.Http.HttpClientHandler]::new()
    $Handler.ServerCertificateCustomValidationCallback = [CertificateCapture.Utility]::ValidationCallback
    $Client = [System.Net.Http.HttpClient]::new($Handler)
    $Result = $Client.GetAsync($Url).Result

    $sha1 = [Security.Cryptography.SHA1]::Create()
    $certBytes = $Certs[-1].Certificate.GetRawCertData()
    $hash = $sha1.ComputeHash($certBytes)
    $thumbprint = [BitConverter]::ToString($hash).Replace('-', ':')
    return $thumbprint.toLower()
}

Function My-Logger {
    param(
        [Parameter(Mandatory = $true)]
        [String]$message
    )

    $timeStamp = Get-Date -Format "MM-dd-yyyy_hh:mm:ss"

    Write-Host -NoNewline -ForegroundColor White "[$timestamp]"
    Write-Host -ForegroundColor Green " $message"
    $logMessage = "[$timeStamp] $message"
    $logMessage | Out-File -Append -LiteralPath $verboseLogFile
}

if ($preCheck -eq 1) {
    if (!(Test-Path $NestedESXiApplianceOVA)) {
        Write-Host -ForegroundColor Red "`nUnable to find $NestedESXiApplianceOVA ...`n"
        exit
    }

    if (!(Test-Path $VCSAInstallerPath)) {
        Write-Host -ForegroundColor Red "`nUnable to find $VCSAInstallerPath ...`n"
        exit
    }

    if (!(Test-Path $HAProxyOVA)) {
        Write-Host -ForegroundColor Red "`nUnable to find $HAProxyOVA ...`n"
        exit
    }
    if (!(Test-Path $tkgrouterOVA)) {
        Write-Host -ForegroundColor Red "`nUnable to find $tkgrouterOVA ...`n"
        exit
    }

    if ($PSVersionTable.PSEdition -ne "Core") {
        Write-Host -ForegroundColor Red "`tPowerShell Core was not detected, please install that before continuing ... `n"
        exit
    }
}

if ($confirmDeployment -eq 1) {
    Write-Host -ForegroundColor Magenta "`nPlease confirm the following configuration will be deployed:`n"

    Write-Host -ForegroundColor Yellow "---- vSphere with Tanzu Basic Automated Lab Deployment Configuration ---- "
    Write-Host -NoNewline -ForegroundColor Green "Nested ESXi Image Path: "
    Write-Host -ForegroundColor White $NestedESXiApplianceOVA
    Write-Host -NoNewline -ForegroundColor Green "VCSA Image Path: "
    Write-Host -ForegroundColor White $VCSAInstallerPath
    Write-Host -NoNewline -ForegroundColor Green "HA Proxy Image Path: "
    Write-Host -ForegroundColor White $HAProxyOVA
    Write-Host -NoNewline -ForegroundColor Green "tkgrouter Image Path: "
    Write-Host -ForegroundColor White $tkgrouterOVA

    Write-Host -ForegroundColor Yellow "`n---- vCenter Server Deployment Target Configuration ----"
    Write-Host -NoNewline -ForegroundColor Green "vCenter Server Address: "
    Write-Host -ForegroundColor White $VIServer
    Write-Host -NoNewline -ForegroundColor Green "VM Network: "
    Write-Host -ForegroundColor White $VMNetwork

    Write-Host -NoNewline -ForegroundColor Green "VM Storage: "
    Write-Host -ForegroundColor White $VMDatastore
    Write-Host -NoNewline -ForegroundColor Green "VM Cluster: "
    Write-Host -ForegroundColor White $VMCluster
    Write-Host -NoNewline -ForegroundColor Green "VM vApp: "
    Write-Host -ForegroundColor White $VAppName

    Write-Host -ForegroundColor Yellow "`n---- vESXi Configuration ----"
    Write-Host -NoNewline -ForegroundColor Green "# of Nested ESXi VMs: "
    Write-Host -ForegroundColor White $NestedESXiHostnameToIPs.count
    Write-Host -NoNewline -ForegroundColor Green "vCPU: "
    Write-Host -ForegroundColor White $NestedESXivCPU
    Write-Host -NoNewline -ForegroundColor Green "vMEM: "
    Write-Host -ForegroundColor White "$NestedESXivMEM GB"
    Write-Host -NoNewline -ForegroundColor Green "Capacity VMDK: "
    Write-Host -ForegroundColor White "$NestedESXiCapacityvDisk GB"
    Write-Host -NoNewline -ForegroundColor Green "IP Address(s): "
    Write-Host -ForegroundColor White $NestedESXiHostnameToIPs.Values
    Write-Host -NoNewline -ForegroundColor Green "Netmask "
    Write-Host -ForegroundColor White $VMNetmask
    Write-Host -NoNewline -ForegroundColor Green "Gateway: "
    Write-Host -ForegroundColor White $VMGateway
    Write-Host -NoNewline -ForegroundColor Green "DNS: "
    Write-Host -ForegroundColor White $VMDNS
    Write-Host -NoNewline -ForegroundColor Green "NTP: "
    Write-Host -ForegroundColor White $VMNTP
    Write-Host -NoNewline -ForegroundColor Green "Syslog: "
    Write-Host -ForegroundColor White $VMSyslog
    Write-Host -NoNewline -ForegroundColor Green "Enable SSH: "
    Write-Host -ForegroundColor White $VMSSH
    Write-Host -NoNewline -ForegroundColor Green "Create VMFS Volume: "
    Write-Host -ForegroundColor White $VMVMFS

    Write-Host -ForegroundColor Yellow "`n---- VCSA Configuration ----"
    Write-Host -NoNewline -ForegroundColor Green "Deployment Size: "
    Write-Host -ForegroundColor White $VCSADeploymentSize
    Write-Host -NoNewline -ForegroundColor Green "SSO Domain: "
    Write-Host -ForegroundColor White $VCSASSODomainName
    Write-Host -NoNewline -ForegroundColor Green "Enable SSH: "
    Write-Host -ForegroundColor White $VCSASSHEnable
    Write-Host -NoNewline -ForegroundColor Green "Hostname: "
    Write-Host -ForegroundColor White $VCSAHostname
    Write-Host -NoNewline -ForegroundColor Green "IP Address: "
    Write-Host -ForegroundColor White $VCSAIPAddress
    Write-Host -NoNewline -ForegroundColor Green "Netmask "
    Write-Host -ForegroundColor White $VMNetmask
    Write-Host -NoNewline -ForegroundColor Green "Gateway: "
    Write-Host -ForegroundColor White $VMGateway

    Write-Host -ForegroundColor Yellow "`n---- HA Proxy Configuration ----"
    Write-Host -NoNewline -ForegroundColor Green "Hostname: "
    Write-Host -ForegroundColor White $HAProxyHostname
    Write-Host -NoNewline -ForegroundColor Green "Load balancer Network: "
    Write-Host -ForegroundColor White $HAProxyLoadBalanceIPRange
    Write-Host -NoNewline -ForegroundColor Green "Management IP Address: "
    Write-Host -ForegroundColor White $HAProxyManagementIPAddress
    Write-Host -NoNewline -ForegroundColor Green "Workload IP Address: "
    Write-Host -ForegroundColor White $HAProxyWorkloadIPAddress
    Write-Host -NoNewline -ForegroundColor Green "Frontend IP Address: "
    Write-Host -ForegroundColor White $HAProxyFrontendIPAddress

    $esxiTotalCPU = $NestedESXiHostnameToIPs.count * [int]$NestedESXivCPU
    $esxiTotalMemory = $NestedESXiHostnameToIPs.count * [int]$NestedESXivMEM
    $esxiTotalStorage = $NestedESXiHostnameToIPs.count * [int]$NestedESXiCapacityvDisk
    $vcsaTotalCPU = $vcsaSize2MemoryStorageMap.$VCSADeploymentSize.cpu
    $vcsaTotalMemory = $vcsaSize2MemoryStorageMap.$VCSADeploymentSize.mem
    $vcsaTotalStorage = $vcsaSize2MemoryStorageMap.$VCSADeploymentSize.disk

    Write-Host -ForegroundColor Yellow "`n---- Resource Requirements ----"
    Write-Host -NoNewline -ForegroundColor Green "ESXi     VM CPU: "
    Write-Host -NoNewline -ForegroundColor White $esxiTotalCPU
    Write-Host -NoNewline -ForegroundColor Green " ESXi     VM Memory: "
    Write-Host -NoNewline -ForegroundColor White $esxiTotalMemory "GB "
    Write-Host -NoNewline -ForegroundColor Green "ESXi     VM Storage: "
    Write-Host -ForegroundColor White $esxiTotalStorage "GB"
    Write-Host -NoNewline -ForegroundColor Green "VCSA     VM CPU: "
    Write-Host -NoNewline -ForegroundColor White $vcsaTotalCPU
    Write-Host -NoNewline -ForegroundColor Green " VCSA     VM Memory: "
    Write-Host -NoNewline -ForegroundColor White $vcsaTotalMemory "GB "
    Write-Host -NoNewline -ForegroundColor Green "VCSA     VM Storage: "
    Write-Host -ForegroundColor White $vcsaTotalStorage "GB"
    Write-Host -NoNewline -ForegroundColor Green "HAProxy     VM CPU: "
    Write-Host -NoNewline -ForegroundColor White $haproxyTotalCPU
    Write-Host -NoNewline -ForegroundColor Green " HAProxy     VM Memory: "
    Write-Host -NoNewline -ForegroundColor White $haproxyTotalMemory "GB "
    Write-Host -NoNewline -ForegroundColor Green "HAProxy     VM Storage: "
    Write-Host -ForegroundColor White $haproxyTotalStorage "GB"
    Write-Host -NoNewline -ForegroundColor Green "TKGRouter     VM CPU: "
    Write-Host -NoNewline -ForegroundColor White $tkgrouterTotalCPU
    Write-Host -NoNewline -ForegroundColor Green "TKGRouter     VM Memory: "
    Write-Host -NoNewline -ForegroundColor White $tkgrouterTotalMemory "GB "
    Write-Host -NoNewline -ForegroundColor Green "TKGRouter     VM Storage: "
    Write-Host -ForegroundColor White $tkgrouterTotalStorage "GB"

    Write-Host -ForegroundColor White "---------------------------------------------"
    Write-Host -NoNewline -ForegroundColor Green "Total CPU: "
    Write-Host -ForegroundColor White ($esxiTotalCPU + $vcsaTotalCPU + $haproxyTotalCPU + $tkgrouterTotalCPU)
    Write-Host -NoNewline -ForegroundColor Green "Total Memory: "
    Write-Host -ForegroundColor White ($esxiTotalMemory + $vcsaTotalMemory + $haproxyTotalMemory + $tkgrouterTotalMemory) "GB"
    Write-Host -NoNewline -ForegroundColor Green "Total Storage: "
    Write-Host -ForegroundColor White ($esxiTotalStorage + $vcsaTotalStorage + $haproxyTotalStorage + $tkgrouterTotalStorage) "GB"

    Write-Host -ForegroundColor Magenta "`nWould you like to proceed with this deployment?`n"
    $answer = Read-Host -Prompt "Do you accept (Y or N)"
    if ($answer -ne "Y" -or $answer -ne "y") {
        exit
    }
    Clear-Host
}

if ( $deployNestedESXiVMs -eq 1 -or $deployVCSA -eq 1 -or $deployHAProxy -eq 1) {
    My-Logger "Connecting to Management vCenter Server $VIServer ..."
    $viConnection = Connect-VIServer $VIServer -User $VIUsername -Password $VIPassword -WarningAction SilentlyContinue

    $datastore = Get-Datastore -Server $viConnection -Name $VMDatastore | Select -First 1
    $cluster = Get-Cluster -Server $viConnection -Name $VMCluster
    $datacenter = $cluster | Get-Datacenter
    $vmhost = $cluster | Get-VMHost | Select -First 1
}

if ($deploytkgrouter -eq 1) {
    $ovfconfig = Get-OvfConfiguration $tkgrouterOVA

    $ovfconfig.NetworkMapping.SHASELABNET01.value = $WANNETWORK
    $ovfconfig.NetworkMapping.TKGMgmt.value = $TKGMGMTNETWORK
    $ovfconfig.NetworkMapping.TKGWorkload.value = $TKGWORKLOADNETWORK
    $ovfconfig.NetworkMapping.TKGFrontend.value = $TKGFRONTENDNETWORK

    $ovfconfig.common.guestinfo.wanip.value = $WANIP
    $ovfconfig.common.guestinfo.wangw.value = $WANGW
    $ovfconfig.common.guestinfo.wandns1.value = $WANDNS1
    $ovfconfig.common.guestinfo.wandns2.value = $WANDNS2
    $ovfconfig.common.guestinfo.wanmask.value = $WANNETMASK
    $ovfconfig.common.guestinfo.tkgmgmtip.value = $TKGMGMTIP
    $ovfconfig.common.guestinfo.tkgworkloadip.value = $TKGWORKLOADIP
    $ovfconfig.common.guestinfo.tkgfrontendip.value = $TKGFRONTENDIP

    My-Logger "Deploying openwrt router VM $tkgrouterdisplayname ..."
    $vm = Import-VApp -Source $tkgrouterOVA -OvfConfiguration $ovfconfig -Name $tkgrouterdisplayname -Location $cluster -VMHost $vmhost -Datastore $datastore -DiskStorageFormat thin
    My-Logger "Powering On $tkgrouterdisplayname ..."
    $vm | Start-Vm -RunAsync | Out-Null
}

if($deployNestedESXiVMs -eq 1) {
    $NestedESXiHostnameToIPs.GetEnumerator() | Sort-Object -Property Value | Foreach-Object {
        $VMName = $_.Key
        $VMIPAddress = $_.Value

        $ovfconfig = Get-OvfConfiguration $NestedESXiApplianceOVA
        $networkMapLabel = ($ovfconfig.ToHashTable().keys | where {$_ -Match "NetworkMapping"}).replace("NetworkMapping.","").replace("-","_").replace(" ","_")
        $ovfconfig.NetworkMapping.$networkMapLabel.value = $VMNetwork

        $ovfconfig.common.guestinfo.hostname.value = $VMName
        $ovfconfig.common.guestinfo.ipaddress.value = $VMIPAddress
        $ovfconfig.common.guestinfo.netmask.value = $VMNetmask
        $ovfconfig.common.guestinfo.gateway.value = $VMGateway
        $ovfconfig.common.guestinfo.dns.value = $VMDNS
        $ovfconfig.common.guestinfo.domain.value = $VMDomain
        $ovfconfig.common.guestinfo.ntp.value = $VMNTP
        $ovfconfig.common.guestinfo.syslog.value = $VMSyslog
        $ovfconfig.common.guestinfo.password.value = $VMPassword
        if($VMSSH -eq "true") {
            $VMSSHVar = $true
        } else {
            $VMSSHVar = $false
        }
        $ovfconfig.common.guestinfo.ssh.value = $VMSSHVar

        My-Logger "Deploying Nested ESXi VM $VMName ..."
        $vm = Import-VApp -Source $NestedESXiApplianceOVA -OvfConfiguration $ovfconfig -Name $VMName -Location $cluster -VMHost $vmhost -Datastore $datastore -DiskStorageFormat thin

        My-Logger "Adding vmnic2 for `"$TKGWORKLOADNETWORK`" to passthrough to Nested ESXi VMs ..."
        New-NetworkAdapter -VM $vm -Type Vmxnet3 -NetworkName $TKGWORKLOADNETWORK -StartConnected -confirm:$false | Out-File -Append -LiteralPath $verboseLogFile

        $vm | New-AdvancedSetting -name "ethernet2.filter4.name" -value "dvfilter-maclearn" -confirm:$false -ErrorAction SilentlyContinue | Out-File -Append -LiteralPath $verboseLogFile
        $vm | New-AdvancedSetting -Name "ethernet2.filter4.onFailure" -value "failOpen" -confirm:$false -ErrorAction SilentlyContinue | Out-File -Append -LiteralPath $verboseLogFile

        My-Logger "Updating vCPU Count to $NestedESXivCPU & vMEM to $NestedESXivMEM GB ..."
        Set-VM -Server $viConnection -VM $vm -NumCpu $NestedESXivCPU -MemoryGB $NestedESXivMEM -Confirm:$false | Out-File -Append -LiteralPath $verboseLogFile

        My-Logger "Updating local VMDK size to $NestedESXiCapacityvDisk GB ..."
        Get-HardDisk -Server $viConnection -VM $vm -Name "Hard disk 2" | Set-HardDisk -CapacityGB $NestedESXiCapacityvDisk -Confirm:$false | Out-File -Append -LiteralPath $verboseLogFile

        My-Logger "Powering On $vmname ..."
        $vm | Start-Vm -RunAsync | Out-Null
    }
}

if ($deployHAProxy -eq 1) {
    $ovfconfig = Get-OvfConfiguration $HAProxyOVA

    $ovfconfig.DeploymentOption.value = "frontend"

    $ovfconfig.network.hostname.value = $HAProxyHostname
    $ovfconfig.network.nameservers.value = $HAProxyDNS

    $ovfconfig.NetworkMapping.Management.value = $HAProxyManagementNetwork
    $ovfconfig.NetworkMapping.Frontend.value = $HAProxyFrontendNetwork
    $ovfconfig.NetworkMapping.Workload.value = $HAProxyWorkloadNetwork

    # Management
    $ovfconfig.network.management_ip.value = $HAProxyManagementIPAddress
    $ovfconfig.network.management_gateway.value = $HAProxyManagementGateway

    # Workload
    $ovfconfig.network.workload_ip.value = $HAProxyWorkloadIPAddress
    $ovfconfig.network.workload_gateway.value = $HAProxyWorkloadGateway

    $ovfconfig.loadbalance.service_ip_range.value = $HAProxyLoadBalanceIPRange
    $ovfconfig.appliance.root_pwd.value = $HAProxyOSPassword
    $ovfconfig.loadbalance.dataplane_port.value = $HAProxyPort
    $ovfconfig.loadbalance.haproxy_user.value = $HAProxyUsername
    $ovfconfig.loadbalance.haproxy_pwd.value = $HAProxyPassword

    My-Logger "Deploying HAProxy VM $HAProxyDisplayName ..."
    $vm = Import-VApp -Source $HAProxyOVA -OvfConfiguration $ovfconfig -Name $HAProxyDisplayName -Location $Cluster -VMHost $VMHost -Datastore $Datastore -DiskStorageFormat thin

    $vappProperties = $vm.ExtensionData.Config.VAppConfig.Property
    $spec = New-Object VMware.Vim.VirtualMachineConfigSpec
    $spec.vAppConfig = New-Object VMware.Vim.VmConfigSpec

    $ovfChanges = @{
        "frontend_ip"      = $HAProxyFrontendIPAddress
        "frontend_gateway" = $HAProxyFrontendGateway
    }

    # Retrieve existing OVF properties from VM
    $vappProperties = $VM.ExtensionData.Config.VAppConfig.Property

    # Create a new Update spec based on the # of OVF properties to update
    $spec = New-Object VMware.Vim.VirtualMachineConfigSpec
    $spec.vAppConfig = New-Object VMware.Vim.VmConfigSpec
    $propertySpec = New-Object VMware.Vim.VAppPropertySpec[]($ovfChanges.count)

    # Find OVF property Id and update the Update Spec
    foreach ($vappProperty in $vappProperties) {
        if ($ovfChanges.ContainsKey($vappProperty.Id)) {
            $tmp = New-Object VMware.Vim.VAppPropertySpec
            $tmp.Operation = "edit"
            $tmp.Info = New-Object VMware.Vim.VAppPropertyInfo
            $tmp.Info.Key = $vappProperty.Key
            $tmp.Info.value = $ovfChanges[$vappProperty.Id]
            $propertySpec += ($tmp)
        }
    }
    $spec.VAppConfig.Property = $propertySpec

    My-Logger "Updating HAProxy Frontend Properties"
    $task = $vm.ExtensionData.ReconfigVM_Task($spec)
    $task1 = Get-Task -Id ("Task-$($task.value)")
    $task1 | Wait-Task

    My-Logger "Powering On $HAProxyDisplayName ..."
    $vm | Start-Vm -RunAsync | Out-Null
}

if ($deployVCSA -eq 1) {
    if ($IsWindows) {
        $config = (Get-Content -Raw "$($VCSAInstallerPath)\vcsa-cli-installer\templates\install\embedded_vCSA_on_VC.json") | convertfrom-json
    }
    else {
        $config = (Get-Content -Raw "$($VCSAInstallerPath)/vcsa-cli-installer/templates/install/embedded_vCSA_on_VC.json") | convertfrom-json
    }
    $config.'new_vcsa'.vc.hostname = $VIServer
    $config.'new_vcsa'.vc.username = $VIUsername
    $config.'new_vcsa'.vc.password = $VIPassword
    $config.'new_vcsa'.vc.deployment_network = $VMNetwork
    $config.'new_vcsa'.vc.datastore = $datastore
    $config.'new_vcsa'.vc.datacenter = $datacenter.name
    $config.'new_vcsa'.vc.target = $VMCluster
    $config.'new_vcsa'.appliance.thin_disk_mode = $true
    $config.'new_vcsa'.appliance.deployment_option = $VCSADeploymentSize
    $config.'new_vcsa'.appliance.name = $VCSADisplayName
    $config.'new_vcsa'.network.ip_family = "ipv4"
    $config.'new_vcsa'.network.mode = "static"
    $config.'new_vcsa'.network.ip = $VCSAIPAddress
    $config.'new_vcsa'.network.dns_servers[0] = $VMDNS
    $config.'new_vcsa'.network.prefix = $VCSAPrefix
    $config.'new_vcsa'.network.gateway = $VMGateway
    $config.'new_vcsa'.os.ntp_servers = $VMNTP
    $config.'new_vcsa'.network.system_name = $VCSAHostname
    $config.'new_vcsa'.os.password = $VCSARootPassword
    if ($VCSASSHEnable -eq "true") {
        $VCSASSHEnableVar = $true
    }
    else {
        $VCSASSHEnableVar = $false
    }
    $config.'new_vcsa'.os.ssh_enable = $VCSASSHEnableVar
    $config.'new_vcsa'.sso.password = $VCSASSOPassword
    $config.'new_vcsa'.sso.domain_name = $VCSASSODomainName

    if ($IsWindows) {
        My-Logger "Creating VCSA JSON Configuration file for deployment ..."
        $config | ConvertTo-Json | Set-Content -Path "$($ENV:Temp)\jsontemplate.json"

        My-Logger "Deploying the VCSA ..."
        Invoke-Expression "$($VCSAInstallerPath)\vcsa-cli-installer\win32\vcsa-deploy.exe install --no-esx-ssl-verify --accept-eula --acknowledge-ceip $($ENV:Temp)\jsontemplate.json" | Out-File -Append -LiteralPath $verboseLogFile
    }
    elseif ($IsMacOS) {
        My-Logger "Creating VCSA JSON Configuration file for deployment ..."
        $config | ConvertTo-Json | Set-Content -Path "$($ENV:TMPDIR)jsontemplate.json"

        My-Logger "Deploying the VCSA ..."
        Invoke-Expression "$($VCSAInstallerPath)/vcsa-cli-installer/mac/vcsa-deploy install --no-esx-ssl-verify --accept-eula --acknowledge-ceip $($ENV:TMPDIR)jsontemplate.json" | Out-File -Append -LiteralPath $verboseLogFile
    }
    elseif ($IsLinux) {
        My-Logger "Creating VCSA JSON Configuration file for deployment ..."
        $config | ConvertTo-Json | Set-Content -Path "/tmp/jsontemplate.json"

        My-Logger "Deploying the VCSA ..."
        Invoke-Expression "$($VCSAInstallerPath)/vcsa-cli-installer/lin64/vcsa-deploy install --no-esx-ssl-verify --accept-eula --acknowledge-ceip /tmp/jsontemplate.json" | Out-File -Append -LiteralPath $verboseLogFile
    }
}

if ($moveVMsIntovApp -eq 1) {
    My-Logger "Creating vApp $VAppName ..."
    $VApp = New-VApp -Name $VAppName -Server $viConnection -Location $cluster

    if (-Not (Get-Folder $VMFolder -ErrorAction Ignore)) {
        My-Logger "Creating VM Folder $VMFolder ..."
        $folder = New-Folder -Name $VMFolder -Server $viConnection -Location (Get-Datacenter $VMDatacenter | Get-Folder vm)
    }

    if ($deployNestedESXiVMs -eq 1) {
        My-Logger "Moving Nested ESXi VMs into $VAppName vApp ..."
        $NestedESXiHostnameToIPs.GetEnumerator() | Sort-Object -Property Value | Foreach-Object {
            $vm = Get-VM -Name $_.Key -Server $viConnection
            Move-VM -VM $vm -Server $viConnection -Destination $VApp -Confirm:$false | Out-File -Append -LiteralPath $verboseLogFile
        }
    }

    if ($deployVCSA -eq 1) {
        $vcsaVM = Get-VM -Name $VCSADisplayName -Server $viConnection
        My-Logger "Moving $VCSADisplayName into $VAppName vApp ..."
        Move-VM -VM $vcsaVM -Server $viConnection -Destination $VApp -Confirm:$false | Out-File -Append -LiteralPath $verboseLogFile
    }

    if ($deployHAProxy -eq 1) {
        $haProxyVM = Get-VM -Name $HAProxyDisplayName -Server $viConnection
        My-Logger "Moving $HAProxyDisplayName into $VAppName vApp ..."
        Move-VM -VM $haProxyVM -Server $viConnection -Destination $VApp -Confirm:$false | Out-File -Append -LiteralPath $verboseLogFile
    }
    if ($deploytkgrouter -eq 1) {
        $tkgrouterVM = Get-VM -Name $tkgrouterdisplayname -Server $viConnection
        My-Logger "Moving $tkgrouterdisplayname into $VAppName vApp ..."
        Move-VM -VM $tkgrouterdisplayname -Server $viConnection -Destination $VApp -Confirm:$false | Out-File -Append -LiteralPath $verboseLogFile
    }

    My-Logger "Moving $VAppName to VM Folder $VMFolder ..."
    Move-VApp -Server $viConnection $VAppName -Destination (Get-Folder -Server $viConnection $VMFolder) | Out-File -Append -LiteralPath $verboseLogFile
}

if ( $deployNestedESXiVMs -eq 1 -or $deployVCSA -eq 1 -or $deployHAProxy -eq 1) {
    My-Logger "Disconnecting from $VIServer ..."
    Disconnect-VIServer -Server $viConnection -Confirm:$false
}

if ($setupNewVC -eq 1) {
    My-Logger "Connecting to the new VCSA ..."
    $vc = Connect-VIServer $VCSAIPAddress -User "administrator@$VCSASSODomainName" -Password $VCSASSOPassword -WarningAction SilentlyContinue

    $d = Get-Datacenter -Server $vc $NewVCDatacenterName -ErrorAction Ignore
    if ( -Not $d) {
        My-Logger "Creating Datacenter $NewVCDatacenterName ..."
        New-Datacenter -Server $vc -Name $NewVCDatacenterName -Location (Get-Folder -Type Datacenter -Server $vc) | Out-File -Append -LiteralPath $verboseLogFile
    }

    $c = Get-Cluster -Server $vc $NewVCVSANClusterName -ErrorAction Ignore
    if ( -Not $c) {
        My-Logger "Creating Cluster $NewVCVSANClusterName ..."
        New-Cluster -Server $vc -Name $NewVCVSANClusterName -Location (Get-Datacenter -Name $NewVCDatacenterName -Server $vc) -DrsEnabled -HAEnabled | Out-File -Append -LiteralPath $verboseLogFile

        (Get-Cluster $NewVCVSANClusterName) | New-AdvancedSetting -Name "das.ignoreRedundantNetWarning" -Type ClusterHA -Value $true -Confirm:$false | Out-File -Append -LiteralPath $verboseLogFile
    }

    if ($addESXiHostsToVC -eq 1) {
        $NestedESXiHostnameToIPs.GetEnumerator() | Sort-Object -Property Value | Foreach-Object {
            $VMName = $_.Key
            $VMIPAddress = $_.Value

            $targetVMHost = $VMIPAddress
            if ($addHostByDnsName -eq 1) {
                $targetVMHost = $VMName
            }
            My-Logger "Adding ESXi host $targetVMHost to Cluster ..."
            Add-VMHost -Server $vc -Location (Get-Cluster -Name $NewVCVSANClusterName) -User "root" -Password $VMPassword -Name $targetVMHost -Force | Out-File -Append -LiteralPath $verboseLogFile
        }

        $haRuntime = (Get-Cluster $NewVCVSANClusterName).ExtensionData.RetrieveDasAdvancedRuntimeInfo
        $totalHaHosts = $haRuntime.TotalHosts
        $totalHaGoodHosts = $haRuntime.TotalGoodHosts
        while ($totalHaGoodHosts -ne $totalHaHosts) {
            My-Logger "Waiting for vSphere HA configuration to complete ..."
            Start-Sleep -Seconds 60
            $haRuntime = (Get-Cluster $NewVCVSANClusterName).ExtensionData.RetrieveDasAdvancedRuntimeInfo
            $totalHaHosts = $haRuntime.TotalHosts
            $totalHaGoodHosts = $haRuntime.TotalGoodHosts
        }
    }


    if ($configurelocalvmfs -eq 1) {
        My-Logger "Formatting local vmfs ..."

        foreach ($vmhost in Get-Cluster -Server $vc | Get-VMHost) {
            $luns = $vmhost | Get-ScsiLun | select CanonicalName, CapacityGB

            My-Logger "Querying ESXi host disks to create local vmfs ..."
            foreach ($lun in $luns) {
                if (([int]($lun.CapacityGB)).toString() -eq "$NestedESXiCapacityvDisk") {
                    $localCapacityDisk = $lun.CanonicalName
                }
            }
            My-Logger "Creating localdisk for $vmhost ..."
            New-Datastore  -Server $vc -VMHost $vmhost -Name tkgsds -Path $localCapacityDisk -Vmfs -FileSystemVersion 6
        }
    }

    if ($configureVDS -eq 1) {
        # vmnic0 = Management on VSS
        # vmnic1 = unset
        # vmnic2 = Workload on VDS (uplink1)
        Get-VirtualPortGroup -Name "VM Network" | Set-VirtualPortGroup -Name $NewVCMgmtPortgroupName

        $vds = New-VDSwitch -Server $vc -Name $NewVCVDSName -Location (Get-Datacenter -Name $NewVCDatacenterName) -Mtu 1600 -NumUplinkPorts 1

        My-Logger "Creating VDS Workload Network Portgroup"
        New-VDPortgroup -Server $vc -Name $NewVCWorkloadPortgroupName -Vds $vds | Out-File -Append -LiteralPath $verboseLogFile
        Get-VDPortgroup -Server $vc $NewVCWorkloadPortgroupName | Get-VDUplinkTeamingPolicy | Set-VDUplinkTeamingPolicy -ActiveUplinkPort @("dvUplink1") | Out-File -Append -LiteralPath $verboseLogFile

        foreach ($vmhost in Get-Cluster -Server $vc | Get-VMHost) {
            My-Logger "Adding $vmhost to $NewVCVDSName"
            $vds | Add-VDSwitchVMHost -VMHost $vmhost | Out-Null

            $vmhostNetworkAdapter = Get-VMHost $vmhost | Get-VMHostNetworkAdapter -Physical -Name vmnic2
            $vds | Add-VDSwitchPhysicalNetworkAdapter -VMHostNetworkAdapter $vmhostNetworkAdapter -Confirm:$false
        }
    }


    # Final configure and then exit maintanence mode in case patching was done earlier
    foreach ($vmhost in Get-Cluster -Server $vc | Get-VMHost) {
        # Disable Core Dump Warning
        Get-AdvancedSetting -Entity $vmhost -Name UserVars.SuppressCoredumpWarning | Set-AdvancedSetting -Value 1 -Confirm:$false | Out-File -Append -LiteralPath $verboseLogFile

        # Enable vMotion traffic
        $vmhost | Get-VMHostNetworkAdapter -VMKernel | Set-VMHostNetworkAdapter -VMotionEnabled $true -Confirm:$false | Out-File -Append -LiteralPath $verboseLogFile

        if ($vmhost.ConnectionState -eq "Maintenance") {
            Set-VMHost -VMhost $vmhost -State Connected -RunAsync -Confirm:$false | Out-File -Append -LiteralPath $verboseLogFile
        }
    }

    if ($setupPacificStoragePolicy -eq 1) {
        $datastoreName = "tkgsds"

        My-Logger "Creating Tanzu Storage Policies and attaching to $datastoreName ..."
        New-TagCategory -Server $vc -Name $StoragePolicyTagCategory -Cardinality single -EntityType Datastore | Out-File -Append -LiteralPath $verboseLogFile
        New-Tag -Server $vc -Name $StoragePolicyTagName -Category $StoragePolicyTagCategory | Out-File -Append -LiteralPath $verboseLogFile
        Get-Datastore -Server $vc -Name $datastoreName | New-TagAssignment -Server $vc -Tag $StoragePolicyTagName | Out-File -Append -LiteralPath $verboseLogFile
        New-SpbmStoragePolicy -Server $vc -Name $StoragePolicyName -AnyOfRuleSets (New-SpbmRuleSet -Name "tanzu-ruleset" -AllOfRules (New-SpbmRule -AnyOfTags (Get-Tag $StoragePolicyTagName))) | Out-File -Append -LiteralPath $verboseLogFile
    }

    My-Logger "Disconnecting from new VCSA ..."
    Disconnect-VIServer $vc -Confirm:$false
}

if ($setupPacific -eq 1) {

    $vc = Connect-VIServer $VCSAIPAddress -User "administrator@$VCSASSODomainName" -Password $VCSASSOPassword -WarningAction SilentlyContinue

    My-Logger "Creating TKG Subscribed Content Library $TKGContentLibraryName ..."
    $clScheme = ([System.Uri]$TKGContentLibraryURL).scheme
    $clHost = ([System.Uri]$TKGContentLibraryURL).host
    $clPort = ([System.Uri]$TKGContentLibraryURL).port
    $clThumbprint = Get-SSLThumbprint -Url "${clScheme}://${clHost}:${clPort}"

    New-ContentLibrary -Server $vc -Name $TKGContentLibraryName -Description "Subscribed TKG Content Library" -Datastore (Get-Datastore -Server $vc "tkgsds") -AutomaticSync -SubscriptionUrl $TKGContentLibraryURL -SslThumbprint $clThumbprint | Out-File -Append -LiteralPath $verboseLogFile

    Disconnect-VIServer $vc -Confirm:$false | Out-Null
}

$EndTime = Get-Date
$duration = [math]::Round((New-TimeSpan -Start $StartTime -End $EndTime).TotalMinutes, 2)

My-Logger "vSphere with Tanzu Basic Lab Deployment Complete!"
My-Logger "StartTime: $StartTime"
My-Logger "  EndTime: $EndTime"
My-Logger " Duration: $duration minutes" 
 
