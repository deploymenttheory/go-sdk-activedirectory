# Current-source public collector; one declared read per remaining scope, no retries.
#Requires -Version 7.0
[CmdletBinding()]
param([Parameter(Mandatory)][ValidateSet('windows','linux')][string]$Client,[Parameter(Mandatory)][ValidatePattern('\Asdk07-p25-[a-z0-9-]{10,25}\z')][string]$ActorFixture,[ValidateSet('explicit-two','domain','forest','site')][string[]]$Variants=@('explicit-two','domain','forest','site'))
$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
$revision='4022967311b983ffb27f9cb59fedd100a3aca4b9'
$stamp=[DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfffZ').ToLowerInvariant()
$path=Join-Path $PSScriptRoot ('sdk209-'+$Client+'-ordinary-scopes-'+$stamp+'.json')
if(Test-Path -LiteralPath $path){throw 'Fresh scope batch receipt required.'}
if(@($Variants|Select-Object -Unique).Count-ne$Variants.Count){throw 'Duplicate scope variant is not allowed.'}
Copy-Item -LiteralPath $PSCommandPath -Destination ($path+'.source.ps1.txt')
$record=@{client=$Client;revision=$revision;actor_fixture=$ActorFixture;calls=@();complete=$false;directory_mutations=0}
function Save-Batch {$record|ConvertTo-Json -Depth 12|Set-Content -LiteralPath $path -Encoding utf8}
Save-Batch
$declaredScopes=@(@{name='explicit-two';scope='server';explicit=$true},@{name='domain';scope='domain';explicit=$false},@{name='forest';scope='forest';explicit=$false},@{name='site';scope='site';explicit=$false})
$driver=Join-Path $PSScriptRoot ('run-sdk07-'+$Client+'-password.ps1')
foreach($variant in @($declaredScopes|Where-Object {$_.name-cin$Variants})){
    $call=@{variant=$variant.name;scope=$variant.scope;explicit=$variant.explicit;state='before-call';created_utc=[DateTime]::UtcNow.ToString('o')}
    $record.calls+=@($call);Save-Batch
    try{
        $arguments=@{Revision=$revision;ServerVersion='2025';Scope=$variant.scope;ActorFixture=$ActorFixture;ExplicitServers=$variant.explicit}
        $receipt=(& $driver @arguments)|ConvertFrom-Json
        $call.receipt=$receipt;$call.state='result-retained';Save-Batch
        $resultPath=Join-Path $receipt.capture 'result.json';$result=Get-Content -LiteralPath $resultPath -Raw|ConvertFrom-Json
        if($result.source_revision-cne$revision-or-not$result.source_label_matches-or$result.platform-cne($Client+'/amd64')-or$result.backend-cne'portable'-or$result.transport-cne'ldap-seal'-or$result.success-or$result.error_class-cne'denied'-or$result.queries.Count-ne3){throw 'Unexpected public ordinary scope result; preserve it without retries.'}
        $summary=@(foreach($query in $result.queries){
            $statuses=if($query.PSObject.Properties['statuses']){@($query.statuses)}else{@()}
            $errorClass=if($query.PSObject.Properties['error_class']){$query.error_class}else{$null}
            if($query.kind-ceq'partners'){
                if(-not$query.complete-or$statuses-or$errorClass){throw 'Partner success changed; preserve actual partial result.'}
            }elseif($query.kind-cin@('failures','queue')){
                if($query.complete-or$errorClass-cne'denied'-or@($statuses).Count-ne2-or@($statuses|Where-Object {$_.protocol-cne'win32-rpc'-or$_.operation-cne'IDL_DRSGetReplInfo'-or$_.code-ne8453}).Count){throw 'Expected ordinary RPC authorization category changed; preserve actual result.'}
            }else{throw 'Unexpected diagnostic kind.'}
            if($query.result.Servers.Count-ne2){throw 'Both declared scope servers are required.'}
            foreach($server in $query.result.Servers){
                $protection=@($server.Observation.rpc_protection)
                if($protection.Count-ne2-or@($protection|Where-Object {-not$_.complete-or-not$_.mutual_authentication-or-not$_.header_signed-or-not$_.confidential-or$_.encryption_type-ne18-or$_.cipher_bits-ne256}).Count){throw 'Actual complete protected EPM/DRS observations are required.'}
            }
            [pscustomobject]@{kind=$query.kind;complete=$query.complete;status_codes=@($statuses|ForEach-Object{$_.code});server_count=$query.result.Servers.Count;actual_rpc_stages=4}
        })
        $call.summary=$summary;$call.result_sha256=(Get-FileHash -LiteralPath $resultPath -Algorithm SHA256).Hash.ToLowerInvariant();$call.state='observed';Save-Batch
    }catch{
        $call.state='stopped-no-retry';$call.exception_type=$_.Exception.GetType().FullName;Save-Batch;throw
    }
}
$record.complete=$true;Save-Batch
[pscustomobject]@{client=$Client;complete=$true;calls=$record.calls.Count;receipt=$path;directory_mutations=0}|ConvertTo-Json
