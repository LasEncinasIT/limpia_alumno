#requires -version 5.1

<#
.SYNOPSIS
  Audita y, de forma explicita, elimina los datos locales de un usuario de Windows.

.DESCRIPTION
  Sin parametros EJECUTA LA LIMPIEZA REAL COMPLETA. -WhatIf simula sin cambios.
  -AuditOnly solo genera informes. Requiere PowerShell de 64 bits como administrador.
  Limpia el perfil y recrea la cuenta local,
  tareas programadas de ese usuario, su papelera y elementos propiedad de su SID en
  ubicaciones compartidas aprobadas. La limpieza del perfil es independiente de las
  aplicaciones instaladas: elimina AppData, los hives de registro, credenciales,
  caches, configuraciones y aplicaciones instaladas solo para ese usuario.
  Restaura nombre, grupos y atributos compatibles; la cuenta tiene un SID nuevo y queda
  habilitada. Contrasena predeterminada solicitada por el centro: alumno.
  Prepara una cuenta temporal deshabilitada antes de eliminar la anterior.
  Con -Execute tambien purga archivos de maquinas VirtualBox/VMware de TODOS los
  usuarios en unidades locales fijas, sin filtrar por SID. Requiere maquinas apagadas.
  Tambien busca cualquier archivo del SID original fuera del perfil en unidades fijas.
  Windows, aplicaciones y otros perfiles se excluyen del recorrido rapido.
  -AuditProtectedOwnerData permite auditarlos sin borrado general por propietario.

  MariaDB de XAMPP (xampp/mysql) y xampp/tmp quedan excluidos. No requiere maqueta.
  No desinstala aplicaciones compartidas. Los datos guardados por servicios FUERA
  de las purgas enumeradas se auditan, pero no se borran automaticamente porque normalmente
  pertenecen a SYSTEM o a una cuenta de servicio y no se pueden atribuir con seguridad.

.EXAMPLE
  .\Limpiar-RastrosAlumno.ps1 -WhatIf

.EXAMPLE
  .\Limpiar-RastrosAlumno.ps1

.EXAMPLE
  .\Limpiar-RastrosAlumno.ps1 -AuditOnly

#>

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param(
    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$UserName = 'alumno',

    [Parameter()]
    [switch]$Execute = $true,

    [Parameter()]
    [switch]$AuditOnly,

    [Parameter()]
    [Security.SecureString]$NewUserPassword,

    [Parameter()]
    [switch]$PurgeSharedApplicationData = $true,

    [Parameter()]
    # Credencial comun indicada expresamente por el centro; visible en este archivo.
    # Puede sustituirse proporcionando -MySqlCredential.
    [System.Management.Automation.PSCredential]$MySqlCredential = [pscredential]::new('root', (ConvertTo-SecureString '1234' -AsPlainText -Force)),

    [Parameter()]
    [switch]$RemoveUserServices = $true,

    [Parameter()]
    [switch]$AuditProtectedOwnerData = $true,

    [Parameter()]
    # Compatibilidad: las unidades fijas ya se buscan; no permite saltar protecciones.
    [string[]]$AdditionalUserOwnedRoots = @(),

    [Parameter()]
    [switch]$Force = $true,

    # -Force no omite los controles de repeticion ni de reanudacion.
    [switch]$AllowRepeat,
    [string]$ExpectedSourceSID,
    [switch]$Resume,
    [ValidateSet('VM','MySQL','XAMPP','Tasks','Services','Recycle','Profile','ExternalOwner','Verify')]
    [string]$RetryInterruptedPhase,
    [string]$BaselinePath,
    [ValidatePattern('^[a-fA-F0-9]{64}$')][string]$BaselineSHA256,

    [Parameter()]
    [string]$ReportPath
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
# La auditoria explicita siempre impide el borrado, incluso si se indica -Execute.
if ($AuditOnly) { $Execute = $false }
$script:ReportPathReady = $null
$script:AuditIssues = New-Object 'System.Collections.Generic.List[string]'
$script:VerificationIssues = New-Object 'System.Collections.Generic.List[string]'
$script:Findings = New-Object 'System.Collections.Generic.List[object]'
$script:Run = $null
$script:RunPath = $null
$script:RunLock = $null
$script:Baseline = $null
$script:BaselineIndex = @{}
$script:Outcome = 'NotStarted'

function Add-Finding {
    param([string]$Status, [string]$Category, [string]$Item, [string]$Detail)
    if (-not (Get-Variable Findings -Scope Script -ErrorAction SilentlyContinue)) {
        $script:Findings = New-Object 'System.Collections.Generic.List[object]'
    }
    $script:Findings.Add([pscustomobject]@{Status=$Status;Category=$Category;Item=$Item;Detail=$Detail;Time=(Get-Date).ToString('o')})
}

function Write-JsonAtomic {
    param([string]$Path, $Value)
    Assert-NoReparseAncestors $Path
    $temp = $Path + '.' + [guid]::NewGuid().ToString('N') + '.tmp'
    $bytes = [Text.Encoding]::UTF8.GetBytes(($Value | ConvertTo-Json -Depth 14))
    $stream = [IO.File]::Open($temp,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
    try {
        if ((Get-Variable RunPath -Scope Script -ErrorAction SilentlyContinue) -and $script:RunPath -eq $Path) {
            $acl=$stream.GetAccessControl()
            $acl.SetOwner([Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'))
            $stream.SetAccessControl($acl)
        }
        $stream.Write($bytes,0,$bytes.Length); $stream.Flush($true)
    } finally { $stream.Dispose() }
    if ([IO.File]::Exists($Path)) { [IO.File]::Replace($temp,$Path,[NullString]::Value) }
    else { [IO.File]::Move($temp,$Path) }
}

function Save-RunCheckpoint {
    if (-not $script:Run) { return }
    $null=Get-ResultExitCode
    $script:Run.Findings = @($script:Findings.ToArray())
    $script:Run | Add-Member -NotePropertyName AuditWarnings -NotePropertyValue @($script:AuditIssues.ToArray()) -Force
    $script:Run | Add-Member -NotePropertyName VerificationWarnings -NotePropertyValue @($script:VerificationIssues.ToArray()) -Force
    $script:Run.Updated = (Get-Date).ToString('o')
    Write-JsonAtomic $script:RunPath $script:Run
}

function Open-RunLedger {
    if (-not $Execute -or $WhatIfPreference) {
        if ($Resume -or $AllowRepeat -or $RetryInterruptedPhase) { throw 'Las opciones de recuperacion/repeticion solo se admiten con -Execute real.' }
        return
    }
    if (-not (Test-IsAdministrator)) { throw 'Se requiere administrador para abrir el registro de ejecuciones.' }
    $dir = Get-FullLiteralPath (Join-Path $env:ProgramData 'LimpiezaDAM-State')
    Assert-NoReparseAncestors $dir
    if (-not (Test-Path -LiteralPath $dir)) {
        $acl = New-Object Security.AccessControl.DirectorySecurity
        $acl.SetAccessRuleProtection($true,$false)
        $acl.SetOwner([Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'))
        foreach ($sid in @('S-1-5-32-544','S-1-5-18')) {
            $rule = [Security.AccessControl.FileSystemAccessRule]::new(
                [Security.Principal.SecurityIdentifier]::new($sid),'FullControl','ContainerInherit,ObjectInherit','None','Allow')
            $acl.AddAccessRule($rule)
        }
        # ACL aplicada en la creacion, no despues de escribir el estado.
        $null = [IO.Directory]::CreateDirectory($dir,$acl)
    }
    $acl = Get-Acl -LiteralPath $dir
    if ($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -notin @('S-1-5-32-544','S-1-5-18')) { throw 'Propietario no fiable del directorio de estado.' }
    foreach ($rule in $acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])) {
        if ($rule.AccessControlType -eq 'Allow' -and $rule.IdentityReference.Value -notin @('S-1-5-32-544','S-1-5-18')) {
            throw 'El registro de ejecuciones permite acceso a identidades no administrativas.'
        }
    }
    # Bloqueo global del equipo: las purgas compartidas afectan a todas las cuentas.
    $lockPath = Join-Path $dir 'machine.lock'
    Assert-NoReparseAncestors $lockPath
    Assert-TrustedStateFile $lockPath
    $script:RunLock = [IO.File]::Open($lockPath,[IO.FileMode]::OpenOrCreate,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)
    $lockAcl=$script:RunLock.GetAccessControl()
    $lockAcl.SetOwner([Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'))
    $script:RunLock.SetAccessControl($lockAcl)
    $sha = [Security.Cryptography.SHA256]::Create()
    try { $key = ([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($UserName.ToLowerInvariant())))).Replace('-','') }
    finally { $sha.Dispose() }
    $script:RunPath = Join-Path $dir ($key + '.json')
    Assert-NoReparseAncestors $script:RunPath
    Assert-TrustedStateFile $script:RunPath
    if (Test-Path -LiteralPath $script:RunPath) {
        $prior = Get-Content -LiteralPath $script:RunPath -Raw | ConvertFrom-Json
        Assert-RunRecord $prior
        if ($prior.Version -ne 1 -or $prior.Computer -cne $env:COMPUTERNAME -or $prior.UserName -ine $UserName) { throw 'Registro de ejecucion incompatible.' }
        if ($prior.Status -eq 'Completed') {
            if ($Resume) { throw 'La ejecucion ya termino. No hay fases que reanudar.' }
            if (-not $AllowRepeat -or $ExpectedSourceSID -cne $prior.Staged.SID) {
                throw "Cuenta ya recreada. Para otra promocion use -AllowRepeat -ExpectedSourceSID $($prior.Staged.SID), tras verificar su identidad."
            }
        }
        else {
            if (-not $Resume -or $AllowRepeat) { throw "Hay una ejecucion incompleta. Revise $script:RunPath y use -Resume; no inicie otra limpieza." }
            if ($RetryInterruptedPhase -and $RetryInterruptedPhase -cne $prior.Phase) { throw '-RetryInterruptedPhase no coincide con la fase interrumpida.' }
            if ($prior.ScriptSHA256 -cne (Get-FileHash -LiteralPath $PSCommandPath -Algorithm SHA256).Hash) { throw 'El script difiere del que inicio la ejecucion; no se reanuda automaticamente.' }
            if ([bool]$prior.Options.Shared -ne [bool]$PurgeSharedApplicationData -or [bool]$prior.Options.Services -ne [bool]$RemoveUserServices -or [bool]$prior.Options.Deep -ne [bool]$AuditProtectedOwnerData -or $prior.Options.BaselineSHA256 -ine $BaselineSHA256) {
                throw 'Reanude con las mismas opciones de alcance y referencia de maqueta.'
            }
            foreach ($field in @('PasswordLastSet','PasswordExpires','AccountExpires')) {
                if ($prior.Original.$field) { $prior.Original.$field = [datetime]$prior.Original.$field }
            }
            $script:Run = $prior
            foreach ($finding in @($prior.Findings)) { $script:Findings.Add($finding) }
            foreach ($warning in @($prior.AuditWarnings)) { $script:AuditIssues.Add($warning) }
            foreach ($warning in @($prior.VerificationWarnings)) { $script:VerificationIssues.Add($warning) }
            if ($prior.Phase -eq 'Staging') { throw "Preparacion de cuenta interrumpida; requiere revision manual del manifiesto y las cuentas dam-*. No se crea otra cuenta." }
            return
        }
    }
    elseif ($Resume) { throw 'No existe un punto de control para esta cuenta en este equipo.' }
    if ($RetryInterruptedPhase) { throw '-RetryInterruptedPhase requiere una ejecucion incompleta y -Resume.' }
    if ($AllowRepeat -and -not $ExpectedSourceSID) { throw '-AllowRepeat requiere -ExpectedSourceSID.' }
}

function Assert-RunRecord {
    param($Record)
    if ($Record.Version -ne 1 -or $Record.Computer -cne $env:COMPUTERNAME -or $Record.UserName -ine $UserName -or
        $Record.Status -notin @('Active','Completed') -or $Record.Original.Name -ine $UserName -or
        $Record.Original.SID -notmatch '^S-1-5-21-(\d+-){3}\d+$') { throw 'Identidad o formato del punto de control invalido.' }
    if ($Record.Staged -and ($Record.Staged.SID -eq $Record.Original.SID -or
        $Record.Staged.SID -notmatch '^S-1-5-21-(\d+-){3}\d+$' -or $Record.Staged.Name -notmatch '^dam-[a-f0-9]{15}$')) { throw 'Cuenta temporal invalida en el punto de control.' }
    $order=@('VM')
    if ($Record.Options.Shared) { $order+=@('MySQL','XAMPP') }
    $order+=@('Tasks','Services','Recycle','Profile','ExternalOwner','Verify','SwitchAccount')
    if (@($Record.Completed).Count -gt $order.Count) { throw 'Demasiadas fases en el punto de control.' }
    for ($i=0;$i -lt @($Record.Completed).Count;$i++) {
        if ($Record.Completed[$i] -cne $order[$i]) { throw 'Orden de fases inconsistente en el punto de control.' }
    }
    if ($Record.Phase -eq 'Staging') {
        if ($Record.Staged -or @($Record.Completed).Count) { throw 'Estado de preparacion inconsistente.' }
    }
    elseif (-not $Record.Staged) { throw 'Falta la cuenta temporal del punto de control.' }
    elseif ($Record.Phase -and (@($Record.Completed).Count -ge $order.Count -or $Record.Phase -cne $order[@($Record.Completed).Count])) { throw 'Fase interrumpida inconsistente.' }
    if ($Record.Status -eq 'Completed' -and (@($Record.Completed).Count -ne $order.Count -or $Record.Phase)) { throw 'Finalizacion inconsistente en el punto de control.' }
}

function Assert-TrustedStateFile {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return }
    $acl=Get-Acl -LiteralPath $Path
    if ($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -notin @('S-1-5-32-544','S-1-5-18')) { throw "Propietario no fiable del estado: $Path" }
    foreach ($rule in $acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])) {
        if ($rule.AccessControlType -eq 'Allow' -and $rule.IdentityReference.Value -notin @('S-1-5-32-544','S-1-5-18')) { throw "Permisos no fiables del estado: $Path" }
    }
}

function Assert-RepeatGuard {
    param($Target)
    if ($ExpectedSourceSID -and $Target.SID -cne $ExpectedSourceSID) { throw 'El SID actual no coincide con -ExpectedSourceSID.' }
    if ($script:Run) {
        if ($Target.SID -cne $script:Run.Original.SID) { throw 'Reanudacion rechazada: el SID original ha cambiado.' }
        return
    }
    # Compatibilidad con ejecuciones anteriores a los puntos de control.
    # Solo bloquea: un manifiesto antiguo nunca autoriza operaciones.
    $folders = @($PSScriptRoot, (Join-Path $env:ProgramData 'LimpiezaDAM')) | Select-Object -Unique
    foreach ($folder in $folders) {
        if (-not (Test-Path -LiteralPath $folder)) { continue }
        foreach ($file in @(Get-ChildItem -LiteralPath $folder -Filter '*.cuenta.json' -File -ErrorAction Stop)) {
            $record = Get-Content -LiteralPath $file.FullName -Raw | ConvertFrom-Json
            if ($record.Computer -ieq $env:COMPUTERNAME -and $record.Original.Name -ieq $UserName -and
                @($record.Replacement | Where-Object { $_ -and $_.SID -ceq $Target.SID }).Count) {
                if (-not $AllowRepeat -or $ExpectedSourceSID -cne $Target.SID) {
                    throw "Un manifiesto anterior identifica esta cuenta como reemplazo. No se limpia otra vez sin -AllowRepeat -ExpectedSourceSID $($Target.SID)."
                }
            }
        }
    }
}

function Start-RunCheckpoint {
    param($Target,$Original)
    if ($script:Run) { return }
    if (Test-Path -LiteralPath $script:RunPath) {
        $archive = $script:RunPath + '.' + [guid]::NewGuid().ToString('N') + '.history'
        [IO.File]::Copy($script:RunPath,$archive,$false)
    }
    $script:Run = [pscustomobject]@{
        Version=1;RunID=[guid]::NewGuid().ToString('N');Computer=$env:COMPUTERNAME;UserName=$UserName
        ScriptSHA256=(Get-FileHash -LiteralPath $PSCommandPath -Algorithm SHA256).Hash
        Original=$Original;ProfilePath=$Target.ProfilePath;Staged=$null;Status='Active';Phase='Staging'
        Completed=@();Findings=@();Updated=$null;Report=$script:ReportPathReady
        Options=[pscustomobject]@{Shared=[bool]$PurgeSharedApplicationData;Services=[bool]$RemoveUserServices;Deep=[bool]$AuditProtectedOwnerData;BaselineSHA256=$BaselineSHA256}
    }
    Save-RunCheckpoint
}

function Invoke-CheckpointPhase {
    param([string]$Name,[scriptblock]$Action)
    if ($script:Run.Completed -contains $Name) { Write-Report "Fase ya completada, no se repite: $Name"; return }
    if ($script:Run.Phase -and $script:Run.Phase -ne $Name) { throw "Fase interrumpida pendiente: $($script:Run.Phase)." }
    if ($script:Run.Phase -eq $Name -and $Resume -and $Name -ne 'SwitchAccount' -and $RetryInterruptedPhase -cne $Name) {
        throw "Fase $Name interrumpida: puede haber acciones aplicadas. Revise el informe; para repetir solo esa fase use -Resume -RetryInterruptedPhase $Name."
    }
    $script:Run.Phase=$Name
    Save-RunCheckpoint
    & $Action
    Add-Finding 'Completed' 'Phase' $Name 'Fase terminada y comprobada; el detalle de operaciones esta en el registro.'
    $script:Run.Completed = @($script:Run.Completed) + $Name
    $script:Run.Phase=$null
    Save-RunCheckpoint
}

function Read-TrustedBaseline {
    if (-not $BaselinePath) {
        if ($BaselineSHA256) { throw 'Falta -BaselinePath.' }
        return
    }
    if (-not $BaselineSHA256) { throw 'La referencia requiere -BaselineSHA256 obtenido por un canal fiable.' }
    $path=Get-FullLiteralPath $BaselinePath
    Assert-NoReparseAncestors $path
    # Validar exactamente los mismos bytes que se interpretan, sin segunda lectura.
    $bytes=[IO.File]::ReadAllBytes($path)
    $sha=[Security.Cryptography.SHA256]::Create()
    try { $actualHash=([BitConverter]::ToString($sha.ComputeHash($bytes))).Replace('-','') } finally { $sha.Dispose() }
    if ($actualHash -ine $BaselineSHA256) { throw 'El hash de la referencia no coincide.' }
    $script:Baseline = [Text.Encoding]::UTF8.GetString($bytes).TrimStart([char]0xFEFF) | ConvertFrom-Json
    if ($script:Baseline.Version -ne 1 -or -not $script:Baseline.Entries) { throw 'Referencia de maqueta vacia o incompatible.' }
    $script:BaselineIndex=@{}
    foreach ($entry in $script:Baseline.Entries) {
        $key=Get-FullLiteralPath $entry.Path
        if ($script:BaselineIndex.ContainsKey($key)) { throw 'Referencia con rutas duplicadas.' }
        $script:BaselineIndex[$key]=$entry
    }
}

function Get-ProtectedClassification {
    param([string]$Path)
    $category='Other'
    if ($Path -match '(?i)\\(cache|caches|temp|tmp|logs?|configuration)\\') { $category='CacheOrConfiguration' }
    elseif ([IO.Path]::GetExtension($Path) -match '(?i)^\.(exe|dll|jar|msi|sys)$') { $category='Application' }
    elseif ([IO.Path]::GetExtension($Path) -match '(?i)^\.(ini|xml|json|config|properties|conf|yaml|yml)$') { $category='Configuration' }
    elseif ([IO.Path]::GetExtension($Path) -match '(?i)^\.(docx?|xlsx?|pptx?|pdf|txt|sql|java|py|cs|cpp|zip|7z)$') { $category='DocumentOrProject' }
    $comparison='NoReference'
    if ($script:Baseline) {
        $comparison='NotInReference'
        if ($script:BaselineIndex.ContainsKey($Path)) {
            $reference=$script:BaselineIndex[$Path]
            Assert-NoReparseAncestors $Path
            $item=Get-Item -LiteralPath $Path -Force -ErrorAction Stop
            if ($item.PSIsContainer -and $reference.Kind -eq 'Directory') { $comparison='DirectoryInReference' }
            elseif (-not $item.PSIsContainer -and $reference.Kind -eq 'File' -and $item.Length -eq $reference.Length -and
                (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash -ceq $reference.SHA256) { $comparison='IdenticalToReference' }
            else { $comparison='ChangedFromReference' }
        }
    }
    [pscustomobject]@{Category=$category;Comparison=$comparison}
}

function Record-ProtectedFindings {
    param($Plan)
    foreach ($path in $Plan.ReportOnly) {
        try {
            $classification=Get-ProtectedClassification $path
            $status='Review'
            if ($classification.Comparison -eq 'IdenticalToReference') { $status='Preserved' }
            Add-Finding $status $classification.Category $path ($classification.Comparison + '; categoria orientativa, no atribuye autoria ni autoriza borrado.')
        }
        catch { Add-Finding 'Inaccessible' 'Protected' $path $_.Exception.Message }
    }
    foreach ($path in $Plan.Excluded) { Add-Finding 'Excluded' 'Scope' $path 'No recorrido. No equivale a limpio ni a error de acceso.' }
    foreach ($issue in $Plan.Issues) {
        $status='Inaccessible'
        if ($issue -like 'Enlace no recorrido:*') { $status='Excluded' }
        Add-Finding $status 'OwnerScan' '' $issue
    }
}


function Get-ResultExitCode {
    $known=@{}
    $pending=$false
    foreach ($finding in $script:Findings) {
        if ($finding.Category -eq 'InspectionWarning') { $known[$finding.Item]=$true }
        if ($finding.Status -in @('Review','Inaccessible','Error')) { $pending=$true }
    }
    foreach ($issue in @($script:AuditIssues.ToArray()) + @($script:VerificationIssues.ToArray()) | Sort-Object -Unique) {
        if ($known.ContainsKey($issue)) { continue }
        $status='Review'
        if ($issue -like 'Enlace no recorrido:*') { $status='Excluded' }
        elseif ($issue -match '(?i)no se pudo|no se pudieron|no inspeccionad|error|denegad') { $status='Inaccessible' }
        Add-Finding $status 'InspectionWarning' $issue 'Ver advertencia en el registro.'
        $known[$issue]=$true
        if ($status -ne 'Excluded') { $pending=$true }
    }
    if ($pending) { return 2 }
    return 0
}

function Write-StructuredResult {
    param([int]$ExitCode)
    if ($WhatIfPreference -or -not $script:ReportPathReady) { return }
    if (Test-Path -LiteralPath ($script:ReportPathReady + '.resultado.json')) { throw 'El informe JSON ya existe; no se sobrescribe.' }
    $counts=[ordered]@{}
    foreach ($status in @('Deleted','Completed','Preserved','Excluded','Review','Inaccessible','Error')) {
        $counts[$status]=@($script:Findings | Where-Object { $_.Status -eq $status }).Count
    }
    $result=[pscustomobject]@{
        Version=1;Computer=$env:COMPUTERNAME;UserName=$UserName;ExitCode=$ExitCode
        Outcome=$script:Outcome;RunID=$(if ($script:Run) {$script:Run.RunID} else {$null})
        OldSID=$(if ($script:Run) {$script:Run.Original.SID} else {$null})
        NewSID=$(if ($script:Run -and $script:Run.Staged) {$script:Run.Staged.SID} else {$null})
        Counts=$counts;Findings=@($script:Findings.ToArray())
        AuditWarnings=@($script:AuditIssues.ToArray());VerificationWarnings=@($script:VerificationIssues.ToArray())
        Limits=@('No es borrado forense.','No se atribuyen datos con propietario distinto ni se inspeccionan ubicaciones excluidas.','La referencia compara contenido, no demuestra autoria.')
    }
    Write-JsonAtomic ($script:ReportPathReady + '.resultado.json') $result
    Write-Report ("Resumen: resultado={0}; codigo={1}; eliminados={2}; preservados={3}; excluidos={4}; revisar={5}; inaccesibles={6}; errores={7}" -f $script:Outcome,$ExitCode,$counts.Deleted,$counts.Preserved,$counts.Excluded,$counts.Review,$counts.Inaccessible,$counts.Error)
}

function Test-IsAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Write-Report {
    param(
        [Parameter(Mandatory = $true)][string]$Message,
        [ValidateSet('INFO', 'WARN', 'ERROR', 'OK')][string]$Level = 'INFO'
    )
    $line = '{0} [{1}] {2}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level, $Message
    Write-Host $line
    if ($script:ReportPathReady) {
        Add-Content -LiteralPath $script:ReportPathReady -Value $line -Encoding UTF8
    }
}

function Get-FullLiteralPath {
    param([Parameter(Mandatory = $true)][string]$Path)
    # Una ruta obtenida del disco es literal: %SystemDrive% puede ser un nombre real.
    # La expansion de plantillas se hace exclusivamente al construir el catalogo.
    $expanded = $Path.Replace('/', '\')
    if ($expanded -notmatch '^[A-Za-z]:\\' -or $expanded.Substring(2).Contains(':')) {
        throw "Se requiere una ruta local absoluta, sin ADS ni UNC: $Path"
    }
    foreach ($part in $expanded.Substring(3).Split('\', [StringSplitOptions]::RemoveEmptyEntries)) {
        if ($part -in @('.', '..')) { continue }
        if ($part -match '[. ]$|[*?\x00-\x1F]' -or $part -match '^(?i:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\.|$)') {
            throw "Segmento de ruta ambiguo, reservado o abreviado: $part"
        }
    }
    $full = [IO.Path]::GetFullPath($expanded)
    if ($full.Contains('~')) {
        Initialize-FastScanner
        # Resolver alias 8.3 existentes, no rechazar nombres largos que contienen ~.
        $full = [DamCleanupFast.NativePaths]::ExpandLongName($full)
    }
    if ($full.Length -eq 3) { return $full }
    return $full.TrimEnd('\')
}

function Initialize-FastScanner {
    if ('DamCleanupFast.Scanner' -as [type]) { return }
    [AppContext]::SetSwitch('Switch.System.IO.UseLegacyPathHandling', $false)
    [AppContext]::SetSwitch('Switch.System.IO.BlockLongPaths', $false)
    # Solo lectura. La compilacion no modifica cuentas, permisos ni datos de usuario.
    Add-Type -TypeDefinition @'
using System;
using System.IO;
using System.Text;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Threading;
using System.Threading.Tasks;
namespace DamCleanupFast {
    public static class NativePaths {
        [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
        static extern uint GetLongPathName(string path, StringBuilder result, uint size);
        public static string Extended(string path) { return path.StartsWith(@"\\?\") ? path : @"\\?\" + path; }
        public static string Plain(string path) { return path.StartsWith(@"\\?\") ? path.Substring(4) : path; }
        public static string ExpandLongName(string path) {
            var result = new StringBuilder(32768);
            uint size = GetLongPathName(Extended(path), result, (uint)result.Capacity);
            if (size > 0 && size < result.Capacity) return Plain(result.ToString());
            // No convertir silenciosamente un alias no resuelto en una ruta autorizada.
            if (System.Text.RegularExpressions.Regex.IsMatch(path, @"(?i)(?:^|\\)[^\\ .]{1,6}~[0-9]+(?:\.[^\\ .]{0,3})?(?:\\|$)"))
                throw new IOException("Alias 8.3 no resuelto: " + path);
            return path;
        }
        public static bool Within(string path, string root) {
            return String.Equals(path, root, StringComparison.OrdinalIgnoreCase) || path.StartsWith(root.TrimEnd('\\') + "\\", StringComparison.OrdinalIgnoreCase);
        }
        public static void NoLinks(string path) {
            string current = path;
            while (!String.IsNullOrEmpty(current)) {
                if ((File.GetAttributes(Extended(current)) & FileAttributes.ReparsePoint) != 0) throw new IOException("Enlace no recorrido: " + current);
                if (current.Length <= 3) break;
                current = Path.GetDirectoryName(current);
            }
        }
        [DllImport("advapi32.dll", CharSet=CharSet.Unicode)]
        static extern uint GetNamedSecurityInfo(string name, int type, uint info, out IntPtr owner, out IntPtr group, out IntPtr dacl, out IntPtr sacl, out IntPtr descriptor);
        [DllImport("kernel32.dll")] static extern IntPtr LocalFree(IntPtr memory);
        public static string Owner(string path) {
            IntPtr owner, group, dacl, sacl, descriptor;
            uint error = GetNamedSecurityInfo(Extended(path), 1, 1, out owner, out group, out dacl, out sacl, out descriptor);
            try {
                if (error != 0 || owner == IntPtr.Zero) throw new IOException("Propietario ilegible (" + error + "): " + path);
                return new SecurityIdentifier(owner).Value;
            } finally { if (descriptor != IntPtr.Zero) LocalFree(descriptor); }
        }
    }
    public class Entry {
        public string Path; public bool IsDirectory; public long Length; public long LastWriteUtc;
    }
    public class Result {
        public List<Entry> Files=new List<Entry>(), Directories=new List<Entry>();
        public List<string> ReportOnly=new List<string>(), Issues=new List<string>(), BlockingIssues=new List<string>(), Excluded=new List<string>();
        public long Scanned, OwnerReads; public double Seconds;
    }
    public class Job { public long Scanned; public Task<Result> Task; }
    public static class Scanner {
        static readonly HashSet<string> VmExtensions=new HashSet<string>(new string[] { ".vbox", ".vbox-prev", ".vmx", ".vmxf", ".vdi", ".vmdk", ".vmsd", ".vmsn", ".vmss", ".vmem", ".nvram", ".ova", ".ovf", ".vhd", ".vhdx", ".sav" }, StringComparer.OrdinalIgnoreCase);
        static bool Any(string path, string[] roots) { foreach (string root in roots) if (NativePaths.Within(path, root)) return true; return false; }
        static bool Metadata(string path) {
            foreach (string part in path.Split('\\')) if (String.Equals(part,"$Recycle.Bin",StringComparison.OrdinalIgnoreCase) || String.Equals(part,"System Volume Information",StringComparison.OrdinalIgnoreCase) || String.Equals(part,"Recovery",StringComparison.OrdinalIgnoreCase)) return true;
            return false;
        }
        public static Job Start(string[] roots, string[] protectedRoots, string profile, string users, string publicRoot, string sid, bool deep, bool vm) {
            var job=new Job();
            job.Task=Task.Factory.StartNew(() => Run(job,roots,protectedRoots,profile,users,publicRoot,sid,deep,vm));
            return job;
        }
        static Result Run(Job job, string[] roots, string[] protectedRoots, string profile, string users, string publicRoot, string sid, bool deep, bool vm) {
            var watch=System.Diagnostics.Stopwatch.StartNew(); var result=new Result();
            var pending=new Stack<string>(roots); var seen=new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var dynamicProtected=new List<string>(protectedRoots);
            while (pending.Count>0) {
                string directory=pending.Pop(); if (!seen.Add(directory)) continue;
                bool directoryProtected=Any(directory,dynamicProtected.ToArray());
                try {
                    NativePaths.NoLinks(directory);
                    var entries=new DirectoryInfo(NativePaths.Extended(directory)).GetFileSystemInfos();
                    foreach (var info in entries) {
                        string path=NativePaths.Plain(info.FullName); bool isDir=(info.Attributes & FileAttributes.Directory)!=0;
                        bool protect=directoryProtected || Any(path,protectedRoots);
                        bool usersContainer=!vm && String.Equals(path,users,StringComparison.OrdinalIgnoreCase);
                        if (!vm && !usersContainer && NativePaths.Within(path,users) && !NativePaths.Within(path,publicRoot)) protect=true;
                        if (Metadata(path) || (!String.IsNullOrEmpty(profile) && NativePaths.Within(path,profile))) continue;
                        if (protect && !deep) { result.Excluded.Add(path); continue; }
                        if ((info.Attributes & FileAttributes.ReparsePoint)!=0) { result.Issues.Add("Enlace no recorrido: " + path); continue; }
                        if (!vm && (info.Attributes & FileAttributes.System)!=0 && !usersContainer) {
                            protect=true;
                            if (isDir) dynamicProtected.Add(path);
                            if (!deep) { result.Excluded.Add(path); continue; }
                        }
                        if (isDir) pending.Push(path);
                        Interlocked.Increment(ref job.Scanned);
                        if (usersContainer) continue;
                        try {
                            if (vm) {
                                if (isDir) continue;
                                if (!VmExtensions.Contains(info.Extension) && !System.Text.RegularExpressions.Regex.IsMatch(info.Name,@"^(VBox|vmware)([.-].*)?\.log(\.\d+)?$",System.Text.RegularExpressions.RegexOptions.IgnoreCase)) continue;
                            } else {
                                result.OwnerReads++;
                                if (!String.Equals(NativePaths.Owner(path),sid,StringComparison.OrdinalIgnoreCase)) continue;
                                if (protect) { result.ReportOnly.Add(path); continue; }
                            }
                            var entry=new Entry { Path=path,IsDirectory=isDir,Length=isDir ? 0 : ((FileInfo)info).Length,LastWriteUtc=info.LastWriteTimeUtc.Ticks };
                            if (isDir) result.Directories.Add(entry); else result.Files.Add(entry);
                        } catch (Exception error) {
                            string message="Elemento no inspeccionado: " + path + "; " + error.Message;
                            result.Issues.Add(message); if (!protect) result.BlockingIssues.Add(message);
                        }
                    }
                } catch (Exception error) {
                    string message="Carpeta no inspeccionada: " + directory + "; " + error.Message;
                    result.Issues.Add(message);
                    bool userProtected=!vm && !String.Equals(directory,users,StringComparison.OrdinalIgnoreCase) && NativePaths.Within(directory,users) && !NativePaths.Within(directory,publicRoot);
                    if (!directoryProtected && !userProtected) result.BlockingIssues.Add(message);
                }
            }
            result.Scanned=job.Scanned; result.Seconds=watch.Elapsed.TotalSeconds; return result;
        }
    }
}
'@
}

function Invoke-FastScan {
    param([string[]]$Roots,[string[]]$ProtectedRoots,[string]$ProfilePath='',
        [string]$UsersRoot='',[string]$PublicRoot='',[string]$SID='', [switch]$Deep, [switch]$VM)
    Initialize-FastScanner
    $job=[DamCleanupFast.Scanner]::Start($Roots,$ProtectedRoots,$ProfilePath,$UsersRoot,$PublicRoot,$SID,[bool]$Deep,[bool]$VM)
    $progress=[Diagnostics.Stopwatch]::StartNew()
    while (-not $job.Task.IsCompleted) {
        Start-Sleep -Milliseconds 200
        if ($progress.Elapsed.TotalSeconds -ge 10) {
            Write-Report "Escaneo rapido: $($job.Scanned) elementos revisados; VM=$([bool]$VM)."
            $progress.Restart()
        }
    }
    if ($job.Task.IsFaulted) { throw $job.Task.Exception.GetBaseException() }
    return $job.Task.Result
}

function Test-WithinPath {
    param([string]$Path, [string]$Root)
    return ($Path -ieq $Root -or $Path.StartsWith($Root.TrimEnd('\') + '\', [StringComparison]::OrdinalIgnoreCase))
}

function Assert-NoReparseAncestors {
    param([Parameter(Mandatory = $true)][string]$Path)
    $full = Get-FullLiteralPath $Path
    $current = [IO.Path]::GetPathRoot($full)
    $parts = $full.Substring($current.Length).Split('\', [StringSplitOptions]::RemoveEmptyEntries)
    foreach ($part in $parts) {
        $current = Join-Path $current $part
        if (-not (Test-Path -LiteralPath $current -ErrorAction Stop)) { break }
        $item = Get-Item -LiteralPath $current -Force -ErrorAction Stop
        if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) {
            throw "Ruta con enlace, junction o punto de montaje: $current"
        }
    }
}

function Get-TreeNoLinks {
    param([Parameter(Mandatory = $true)][string]$Path, [switch]$Strict, [switch]$SkipLinks)
    $pending = New-Object 'System.Collections.Generic.Stack[string]'
    try {
        Assert-NoReparseAncestors $Path
        if (-not (Test-Path -LiteralPath $Path -ErrorAction Stop)) { return }
        $pending.Push((Get-FullLiteralPath $Path))
        while ($pending.Count) {
            $directory = $pending.Pop()
            foreach ($item in @(Get-ChildItem -LiteralPath $directory -Force -ErrorAction Stop)) {
                if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) {
                    # No seguir enlaces. Las junctions del perfil las gestiona Windows.
                    if ($Strict -and -not $SkipLinks) { throw "Enlace encontrado dentro del arbol: $($item.FullName)" }
                    $script:AuditIssues.Add("Enlace no recorrido: $($item.FullName)")
                    continue
                }
                $item
                if ($item.PSIsContainer) { $pending.Push($item.FullName) }
            }
        }
    }
    catch {
        if ($Strict) { throw }
        $script:AuditIssues.Add("Arbol no inspeccionado por completo: $Path; $($_.Exception.Message)")
    }
}

function Test-LiteralPathQuiet {
    param([Parameter(Mandatory = $true)][string]$Path)
    try { return [bool](Test-Path -LiteralPath $Path -ErrorAction Stop) }
    catch {
        $script:AuditIssues.Add("No se pudo comprobar la ruta: $Path; $($_.Exception.Message)")
        return $false
    }
}

function Get-OwnerSid {
    param([Parameter(Mandatory = $true)][string]$Path)
    try {
        Initialize-FastScanner
        return [DamCleanupFast.NativePaths]::Owner($Path)
    }
    catch {
        $script:AuditIssues.Add("No se pudo leer el propietario: $Path")
        return $null
    }
}

function Get-DirectoryStats {
    param([Parameter(Mandatory = $true)][string]$Path)
    $count = 0L
    $bytes = 0L
    if (-not (Test-LiteralPathQuiet -Path $Path)) {
        return [pscustomobject]@{ Count = 0L; Bytes = 0L; Accessible = $false }
    }
    $issueCount = $script:AuditIssues.Count
    try {
        Get-TreeNoLinks -Path $Path | Where-Object { -not $_.PSIsContainer } | ForEach-Object {
            $count++
            $bytes += $_.Length
        }
        return [pscustomobject]@{ Count = $count; Bytes = $bytes; Accessible = ($script:AuditIssues.Count -eq $issueCount) }
    }
    catch {
        return [pscustomobject]@{ Count = $count; Bytes = $bytes; Accessible = $false }
    }
}

function Format-Size {
    param([long]$Bytes)
    if ($Bytes -ge 1GB) { return ('{0:N2} GB' -f ($Bytes / 1GB)) }
    if ($Bytes -ge 1MB) { return ('{0:N2} MB' -f ($Bytes / 1MB)) }
    if ($Bytes -ge 1KB) { return ('{0:N2} KB' -f ($Bytes / 1KB)) }
    return "$Bytes bytes"
}

function Get-VmExcludedRoots {
    # No borrar los binarios, imagenes del sistema ni metadatos de volumen.
    Get-XamppPreservedRoots
    @($env:windir, $env:ProgramFiles, ${env:ProgramFiles(x86)}) |
        Where-Object { $_ } | ForEach-Object { Get-FullLiteralPath $_ }
    foreach ($relative in @('Microsoft\Windows Defender','Microsoft\Windows Defender Advanced Threat Protection','Microsoft\Windows\AppRepository','Microsoft\Windows\SystemData','Microsoft\Windows\CapabilityAccessManager')) {
        Get-FullLiteralPath (Join-Path $env:ProgramData $relative)
    }
    foreach ($disk in @(Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' -ErrorAction Stop)) {
        Join-Path ($disk.DeviceID + '\') 'System Volume Information'
        Join-Path ($disk.DeviceID + '\') '$Recycle.Bin'
        Join-Path ($disk.DeviceID + '\') 'Recovery'
    }
}

function Test-VmExcludedPath {
    param([string]$Path, [string[]]$Excluded)
    foreach ($root in @(Get-XamppPreservedRoots)) { if (Test-WithinPath $Path $root) { return $true } }
    foreach ($root in $Excluded) { if (Test-WithinPath $Path $root) { return $true } }
    return $false
}

function Assert-VmEnginesStopped {
    $running = @(Get-CimInstance Win32_Process -ErrorAction Stop | Where-Object {
        $_.Name -in @('VirtualBox.exe','VirtualBoxVM.exe','VBoxHeadless.exe','VBoxSVC.exe',
            'vmware.exe','vmware-vmx.exe','vmplayer.exe')
    })
    if ($running.Count) {
        throw 'Apague todas las maquinas virtuales y cierre VirtualBox/VMware en TODAS las sesiones antes de limpiar. No se fuerza su cierre.'
    }
}

function Get-VmPurgePlan {
    param([string[]]$Roots, [string[]]$Excluded)
    if (-not $Roots) {
        $Roots = @(Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' -ErrorAction Stop |
            ForEach-Object { $_.DeviceID + '\' })
    }
    if (-not $PSBoundParameters.ContainsKey('Excluded')) { $Excluded = @(Get-VmExcludedRoots) }
    $files = @{}
    $ambiguous = @{}
    $issues = New-Object 'System.Collections.Generic.List[string]'
    $blocking = New-Object 'System.Collections.Generic.List[string]'
    # Extensiones de datos VM, nunca ISO, ejecutables ni carpetas completas.
    $extensions = @('.vbox','.vbox-prev','.vmx','.vmxf','.vdi','.vmdk','.vmsd',
        '.vmsn','.vmss','.vmem','.nvram','.ova','.ovf')
    foreach ($root in $Roots) {
        $full = Get-FullLiteralPath $root
        Assert-NoReparseAncestors $full
    }
    $scan=Invoke-FastScan -Roots $Roots -ProtectedRoots $Excluded -VM
    foreach ($issue in $scan.Issues) { $issues.Add($issue) }
    foreach ($issue in $scan.BlockingIssues) { $blocking.Add($issue) }
    Write-Report "Inventario VM rapido: $($scan.Scanned) elementos en $([math]::Round($scan.Seconds,2)) s; zonas excluidas=$($scan.Excluded.Count)."
    foreach ($entry in $scan.Files) {
        try {
            $item=Get-Item -LiteralPath $entry.Path -Force -ErrorAction Stop
            if ($item.Extension -in $extensions -or $item.Name -match '^(VBox|vmware)([.-].*)?\.log(\.\d+)?$') { $files[$item.FullName]=$item }
            elseif ($item.Extension -in @('.vhd','.vhdx','.sav')) { $ambiguous[$item.FullName]=$item }
        }
        catch {
            $message = "Archivo VM no inspeccionado: $($entry.Path); $($_.Exception.Message)"
            $issues.Add($message); $blocking.Add($message)
        }
    }
    # Resolver referencias explicitas, tambien discos externos con nombres no estandar.
    # XML sin DTD/entidades externas: las configuraciones son datos no confiables.
    foreach ($config in @($files.Values | Where-Object { $_.Extension -in @('.vbox','.vbox-prev','.vmx','.ovf') })) {
        $references = New-Object 'System.Collections.Generic.List[string]'
        try {
            if ($config.Length -gt 8MB) { throw 'Configuracion demasiado grande para inspeccion segura.' }
            if ($config.Extension -eq '.vmx') {
                foreach ($line in @(Get-Content -LiteralPath $config.FullName -ErrorAction Stop)) {
                    if ($line -match '^\s*(?:[a-z]+\d+:\d+\.fileName|nvram|checkpoint\.vmState)\s*=\s*"([^"]+)"') {
                        if ([IO.Path]::GetExtension($Matches[1]) -notin @('.iso','.img','.flp')) { $references.Add($Matches[1]) }
                    }
                }
            }
            else {
                $settings = New-Object System.Xml.XmlReaderSettings
                $settings.DtdProcessing = [System.Xml.DtdProcessing]::Prohibit
                $settings.XmlResolver = $null
                $reader = [System.Xml.XmlReader]::Create($config.FullName, $settings)
                try {
                    $xml = New-Object System.Xml.XmlDocument
                    $xml.XmlResolver = $null
                    $xml.Load($reader)
                } finally { $reader.Dispose() }
                foreach ($node in @($xml.SelectNodes("//*[local-name()='HardDisk']/@location | //@stateFile | //*[local-name()='File']/@*[local-name()='href']"))) {
                    if ([IO.Path]::GetExtension($node.Value) -notin @('.iso','.img','.flp')) { $references.Add($node.Value) }
                }
            }
            foreach ($reference in $references) {
                if ($reference -match '^auto detect$') { continue }
                $path = $reference
                if (-not [IO.Path]::IsPathRooted($path)) { $path = Join-Path $config.DirectoryName $path }
                $path = Get-FullLiteralPath $path
                if (-not @($Roots | Where-Object { Test-WithinPath $path (Get-FullLiteralPath $_) }).Count -or
                    (Test-VmExcludedPath $path $Excluded)) { throw "Referencia fuera del alcance local: $path" }
                Assert-NoReparseAncestors $path
                if (Test-Path -LiteralPath $path -ErrorAction Stop) {
                    $referenced = Get-Item -LiteralPath $path -Force -ErrorAction Stop
                    # No confiar en una configuracion para borrar archivos arbitrarios.
                    if ($referenced.PSIsContainer -or $referenced.Extension -notin ($extensions + @('.vhd','.vhdx','.sav'))) {
                        throw "Referencia con formato no reconocido; no se borrara: $path"
                    }
                    $files[$path] = $referenced
                    $ambiguous.Remove($path)
                }
            }
        }
        catch {
            $message = "Configuracion VM incompleta: $($config.FullName); $($_.Exception.Message)"
            $issues.Add($message); $blocking.Add($message)
        }
    }
    foreach ($item in $ambiguous.Values) {
        # SAV puede ser un juego; VHD(X) puede ser WSL, contenedor o copia de Windows.
        if ($item.Extension -in @('.vhd','.vhdx')) {
            $issues.Add("Disco virtual sin asociacion VirtualBox/VMware; revisar sin borrar a ciegas: $($item.FullName)")
        }
    }
    [pscustomobject]@{
        Roots = @($Roots); Excluded = @($Excluded)
        Files = @($files.Values | Sort-Object FullName | ForEach-Object {
            [pscustomobject]@{Path=$_.FullName; Length=$_.Length; LastWriteUtc=$_.LastWriteTimeUtc.Ticks}
        })
        Issues = @($issues); BlockingIssues = @($blocking)
    }
}

function Write-VmPurgePlan {
    param($Plan)
    Write-Report "VM de TODOS los usuarios: $($Plan.Files.Count) archivos seleccionados en $($Plan.Roots -join ', '). No se filtra por propietario."
    foreach ($file in $Plan.Files) { Write-Report "VM: $($file.Path); $(Format-Size $file.Length)" }
    foreach ($issue in $Plan.Issues) { Write-Report $issue 'WARN' }
    Write-Report 'VM: no se recorren red, USB extraibles, enlaces ni zonas protegidas; no se inspeccionan archivos comprimidos. Revisar tambien papeleras de otros usuarios.' 'WARN'
}

function Invoke-VmPurge {
    param([Parameter(Mandatory=$true)]$Plan)
    if ($WhatIfPreference -or -not $Execute) { return }
    if ($Plan.BlockingIssues.Count) { throw 'La inspeccion VM esta incompleta. Resuelva los errores de acceso/configuracion del informe antes de borrar.' }
    Assert-VmEnginesStopped
    # Validar TODO el manifiesto antes del primer borrado; nunca borrar una carpeta.
    foreach ($file in $Plan.Files) {
        $full = Get-FullLiteralPath $file.Path
        if (-not @($Plan.Roots | Where-Object { Test-WithinPath $full (Get-FullLiteralPath $_) }).Count -or
            (Test-VmExcludedPath $full $Plan.Excluded)) { throw "Archivo VM fuera del alcance: $full" }
        Assert-NoReparseAncestors $full
        $current = Get-Item -LiteralPath $full -Force -ErrorAction Stop
        if ($current.PSIsContainer -or $current.Length -ne $file.Length -or $current.LastWriteTimeUtc.Ticks -ne $file.LastWriteUtc) {
            throw "Archivo VM cambiado desde la auditoria: $full"
        }
    }
    foreach ($file in $Plan.Files) {
        if ($PSCmdlet.ShouldProcess($file.Path, 'Eliminar datos de maquina virtual de cualquier usuario')) {
            Assert-VmEnginesStopped
            Assert-NoReparseAncestors $file.Path
            $current = Get-Item -LiteralPath $file.Path -Force -ErrorAction Stop
            if ($current.PSIsContainer -or $current.Length -ne $file.Length -or $current.LastWriteTimeUtc.Ticks -ne $file.LastWriteUtc) {
                throw "Archivo VM cambiado antes del borrado: $($file.Path)"
            }
            Remove-Item -LiteralPath $file.Path -Force -ErrorAction Stop
            Write-Report "Archivo VM eliminado: $($file.Path)" 'OK'
            Add-Finding 'Deleted' 'VMFile' $file.Path 'Archivo de VM reconocida; cualquier propietario.'
        }
    }
    $remaining = Get-VmPurgePlan -Roots $Plan.Roots -Excluded $Plan.Excluded
    if ($remaining.Files.Count -or $remaining.BlockingIssues.Count) { throw 'Quedan archivos VM reconocidos o no se pudo verificar su ausencia. Limpieza incompleta; revisar antes de repetir.' }
    foreach ($issue in @($Plan.Issues) + @($remaining.Issues)) { $script:VerificationIssues.Add($issue) }
    Write-Report 'No quedan archivos VM reconocidos en las ubicaciones inspeccionadas. Las exclusiones e incidencias requieren revision; no certifica las zonas no accesibles.' 'OK'
}

function Resolve-TargetIdentity {
    param([Parameter(Mandatory = $true)][string]$Name)

    $matchingUsers = @(Get-LocalUser -ErrorAction Stop | Where-Object { $_.Name -ieq $Name })
    if ($matchingUsers.Count -gt 1) {
        throw "Hay mas de una cuenta local que coincide con '$Name'."
    }
    if ($matchingUsers.Count -eq 0) {
        throw "La cuenta local '$Name' no existe. Se requiere una cuenta de origen para copiar sus grupos y atributos; revise el manifiesto de una ejecucion anterior."
    }

    $localUser = $null
    $sid = $null
    if ($matchingUsers.Count -eq 1) {
        $localUser = $matchingUsers[0]
        $sid = $localUser.SID.Value
    }

    $profiles = @(Get-CimInstance Win32_UserProfile -ErrorAction Stop)
    $profile = $null
    if ($sid) {
        $matches = @($profiles | Where-Object { $_.SID -eq $sid })
        if ($matches.Count -gt 1) { throw 'Mas de un perfil asociado al SID.' }
        if ($matches.Count -eq 1) { $profile = $matches[0] }
    }

    if (-not $profile) {
        $matches = @($profiles | Where-Object {
            $_.LocalPath -and ([IO.Path]::GetFileName($_.LocalPath.TrimEnd('\')) -ieq $Name)
        })
        if ($matches.Count -gt 1) { throw 'Nombre de perfil ambiguo. No se selecciona ninguno.' }
        if ($matches.Count -eq 1) {
            if ($sid -and $sid -ne $matches[0].SID) {
                throw "La cuenta y la carpeta de perfil tienen SID distintos. Se requiere revision manual."
            }
            $profile = $matches[0]
            $sid = $profile.SID
        }
    }

    $profilePath = $null
    if ($profile -and $profile.LocalPath) {
        $profilePath = Get-FullLiteralPath $profile.LocalPath
    }
    else {
        $candidate = Join-Path (Join-Path $env:SystemDrive 'Users') $Name
        if (Test-Path -LiteralPath $candidate -ErrorAction Stop) {
            throw "Existe $candidate sin una asociacion de perfil verificable. No se borra por nombre."
        }
    }

    if (-not $localUser -and -not $profilePath -and -not $sid) {
        throw "No se encontro la cuenta, el perfil ni un SID residual para '$Name'."
    }

    return [pscustomobject]@{
        LocalUser   = $localUser
        SID         = $sid
        Profile     = $profile
        ProfilePath = $profilePath
    }
}

function Assert-SafeTarget {
    param([Parameter(Mandatory = $true)]$Target, [switch]$Refresh)

    if ($Refresh) {
        $live = Resolve-TargetIdentity -Name $UserName
        if ($live.SID -ne $Target.SID -or $live.ProfilePath -ine $Target.ProfilePath) {
            throw 'La identidad o la ruta han cambiado desde la auditoria.'
        }
        Assert-SafeTarget -Target $live
    }
    if ($Target.Profile -and $Target.Profile.SID -ne $Target.SID) {
        throw 'El SID de la cuenta no coincide con el SID del perfil.'
    }
    if ($Target.LocalUser -and $Target.LocalUser.SID.Value -ne $Target.SID) {
        throw 'El SID de la cuenta local ha cambiado.'
    }

    if (-not $Target.SID -or $Target.SID -notmatch '^S-1-5-21-(\d+-){3}\d+$') {
        throw "El SID del objetivo no es un SID normal de usuario local: '$($Target.SID)'."
    }

    $currentSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    if ($Target.SID -eq $currentSid) {
        throw 'Se ha rechazado borrar el usuario que esta ejecutando el script.'
    }

    if ($Target.Profile -and $Target.Profile.Special) {
        throw 'Se ha rechazado borrar un perfil especial de Windows.'
    }
    if ($Target.Profile -and $Target.Profile.Loaded) {
        throw "El perfil esta cargado. Cierre la sesion de '$UserName' antes de continuar."
    }

    if ($Target.ProfilePath) {
        Assert-NoReparseAncestors $Target.ProfilePath
        $usersRoot = Get-FullLiteralPath (Join-Path $env:SystemDrive 'Users')
        $parent = Get-FullLiteralPath ([IO.Path]::GetDirectoryName($Target.ProfilePath))
        $leaf = [IO.Path]::GetFileName($Target.ProfilePath)
        $protected = @('Public', 'Default', 'Default User', 'All Users', 'Administrador', 'Administrator', 'Admin')
        if ($parent -ine $usersRoot) {
            throw "Ruta de perfil fuera de la ubicacion segura esperada: $($Target.ProfilePath)"
        }
        if ($protected -icontains $leaf) {
            throw "El perfil '$leaf' esta en la lista de proteccion."
        }
    }
}

function Get-InstalledApplications {
    $roots = @(
        'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )
    return @(Get-ItemProperty $roots -ErrorAction SilentlyContinue |
        Where-Object { $_.PSObject.Properties['DisplayName'] -and $_.DisplayName } |
        Select-Object DisplayName, DisplayVersion, Publisher, InstallLocation |
        Sort-Object DisplayName -Unique)
}

function Get-ApplicationShortcuts {
    $shortcutRoots = @(
        (Join-Path $env:Public 'Desktop'),
        (Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs')
    )
    $shell = New-Object -ComObject WScript.Shell
    $results = New-Object System.Collections.Generic.List[object]
    foreach ($root in $shortcutRoots) {
        if (-not (Test-LiteralPathQuiet -Path $root)) { continue }
        foreach ($file in @(Get-ChildItem -LiteralPath $root -Filter '*.lnk' -File -Recurse -ErrorAction SilentlyContinue)) {
            try {
                $shortcut = $shell.CreateShortcut($file.FullName)
                $targetPath = $shortcut.TargetPath
                if (-not $targetPath) { continue }
                if ($targetPath.StartsWith($env:windir, [StringComparison]::OrdinalIgnoreCase)) { continue }
                if ([IO.Path]::GetExtension($targetPath) -ine '.exe') { continue }
                if ($file.BaseName -match '^(Uninstall|Desinstalar)|Help$|manual|license|website') { continue }
                $results.Add([pscustomobject]@{
                    DisplayName = [IO.Path]::GetFileNameWithoutExtension($file.Name)
                    TargetPath  = $targetPath
                })
            }
            catch { }
        }
    }
    return @($results | Sort-Object DisplayName, TargetPath -Unique)
}

function Get-TargetScheduledTasks {
    param([Parameter(Mandatory = $true)]$Target)
    $machineName = $env:COMPUTERNAME
    return @(Get-ScheduledTask -ErrorAction Stop | Where-Object {
        $principal = $_.Principal.UserId
        $principal -and (
            $principal -ieq $Target.SID -or
            $principal -ieq $UserName -or
            $principal -ieq ".\$UserName" -or
            $principal -ieq "$machineName\$UserName"
        )
    })
}

function Get-TargetServices {
    param([Parameter(Mandatory = $true)]$Target)
    $machineName = $env:COMPUTERNAME
    return @(Get-CimInstance Win32_Service -ErrorAction Stop | Where-Object {
        $_.StartName -and (
            $_.StartName -ieq $UserName -or
            $_.StartName -ieq ".\$UserName" -or
            $_.StartName -ieq "$machineName\$UserName" -or
            $_.StartName -ieq $Target.SID
        )
    })
}

function Get-UserOwnedItems {
    param(
        [Parameter(Mandatory = $true)][string[]]$Roots,
        [Parameter(Mandatory = $true)][string]$SID,
        [switch]$Strict
    )
    $result = New-Object System.Collections.Generic.List[object]
    foreach ($root in $Roots) {
        $root = Assert-SafeSharedRoot $root
        foreach ($item in @(Get-TreeNoLinks -Path $root -Strict:$Strict -SkipLinks)) {
            $owner = Get-OwnerSid -Path $item.FullName
            if ($Strict -and -not $owner) { throw "Propietario ilegible: $($item.FullName)" }
            if ($owner -eq $SID) {
                $result.Add($item)
            }
        }
    }
    return $result.ToArray()
}

function New-ExternalOwnerPolicy {
    param([Parameter(Mandatory=$true)]$Target)
    $disks = @(Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' -ErrorAction Stop)
    $roots = @($disks | ForEach-Object { Get-FullLiteralPath ($_.DeviceID + '\') })
    if (-not $roots.Count) { throw 'No se identificaron unidades locales fijas.' }
    $protected = @($env:windir, $env:ProgramFiles, ${env:ProgramFiles(x86)}, $env:ProgramData,
        (Join-Path $env:SystemDrive 'xampp'), (Join-Path $env:SystemDrive 'eclipse'))
    foreach ($profile in @(Get-CimInstance Win32_UserProfile -ErrorAction Stop)) {
        if ($profile.SID -ne $Target.SID -and $profile.LocalPath) { $protected += $profile.LocalPath }
    }
    foreach ($app in @(Get-InstalledApplications)) {
        if ($app.InstallLocation) { $protected += $app.InstallLocation }
    }
    foreach ($app in @(Get-ApplicationShortcuts)) {
        if ($app.TargetPath) { $protected += [IO.Path]::GetDirectoryName($app.TargetPath) }
    }
    $canonical = @($protected | Where-Object { $_ } | ForEach-Object { Get-FullLiteralPath $_ } | Sort-Object -Unique)
    # Las rutas antiguas adicionales no amplian el alcance a USB/red ni zonas protegidas.
    foreach ($extra in $AdditionalUserOwnedRoots) {
        $full = Assert-SafeSharedRoot $extra
        if (-not @($roots | Where-Object { Test-WithinPath $full $_ }).Count) {
            throw "Ruta adicional fuera de las unidades fijas: $full"
        }
    }
    [pscustomobject]@{
        SID=$Target.SID; ProfilePath=$Target.ProfilePath; Roots=$roots; ProtectedRoots=$canonical
        UsersRoot=(Get-FullLiteralPath (Join-Path $env:SystemDrive 'Users'))
        PublicRoot=(Get-FullLiteralPath $env:Public)
        AuditProtected=[bool]$AuditProtectedOwnerData
    }
}

function Get-ExternalOwnerPathMode {
    param([string]$Path, $Policy)
    $full = Get-FullLiteralPath $Path
    if (-not @($Policy.Roots | Where-Object { Test-WithinPath $full $_ }).Count) { return 'Skip' }
    if ($Policy.ProfilePath -and (Test-WithinPath $full $Policy.ProfilePath)) { return 'Skip' }
    if ($full -match '(?i)\\(\$Recycle\.Bin|System Volume Information|Recovery)(\\|$)') { return 'Skip' }
    if ($full -ieq [IO.Path]::GetPathRoot($full)) { return 'Report' }
    foreach ($root in $Policy.ProtectedRoots) { if (Test-WithinPath $full $root) { return 'Report' } }
    if ((Test-WithinPath $full $Policy.UsersRoot) -and -not (Test-WithinPath $full $Policy.PublicRoot)) { return 'Report' }
    return 'Delete'
}

function Get-ExternalOwnerPlan {
    param([Parameter(Mandatory=$true)]$Policy)
    $deep=$Policy.PSObject.Properties['AuditProtected'] -and $Policy.AuditProtected
    $scan=Invoke-FastScan -Roots $Policy.Roots -ProtectedRoots $Policy.ProtectedRoots -ProfilePath $Policy.ProfilePath -UsersRoot $Policy.UsersRoot -PublicRoot $Policy.PublicRoot -SID $Policy.SID -Deep:$deep
    [pscustomobject]@{
        Policy=$Policy;Files=$scan.Files.ToArray();Directories=$scan.Directories.ToArray()
        ReportOnly=$scan.ReportOnly.ToArray();Issues=$scan.Issues.ToArray();BlockingIssues=$scan.BlockingIssues.ToArray()
        Excluded=$scan.Excluded.ToArray();Scanned=$scan.Scanned;OwnerReads=$scan.OwnerReads;Seconds=$scan.Seconds
    }
}

function Write-ExternalOwnerPlan {
    param($Plan)
    Write-Report "Busqueda externa por SID $($Plan.Policy.SID): $($Plan.Files.Count) archivos, sin filtro de extension; $($Plan.Directories.Count) carpetas (solo se borran si quedan vacias)."
    Write-Report "Rendimiento: $($Plan.Scanned) elementos; $($Plan.OwnerReads) consultas de propietario; $([math]::Round($Plan.Seconds,2)) s."
    foreach ($path in $Plan.Excluded) { Write-Report "PROPIETARIO - excluido sin recorrer: $path" }
    foreach ($entry in @($Plan.Files) + @($Plan.Directories)) { Write-Report "PROPIETARIO - candidato: $($entry.Path)" }
    foreach ($path in $Plan.ReportOnly) { Write-Report "PROPIETARIO - SOLO INFORMAR, zona protegida: $path" 'WARN' }
    foreach ($issue in $Plan.Issues) { Write-Report $issue 'WARN' }
    Write-Report 'No se atribuyen archivos por permisos de escritura. Perfil y papelera propios tienen limpieza separada; red, extraibles, enlaces y metadatos de volumen quedan fuera.' 'WARN'
}

function Assert-ExternalOwnerEntry {
    param($Entry, $Policy)
    $full = Get-FullLiteralPath $Entry.Path
    if ((Get-ExternalOwnerPathMode $full $Policy) -ne 'Delete') { throw "Ruta externa fuera del alcance de borrado: $full" }
    Assert-NoReparseAncestors $full
    # Las purgas VM/XAMPP anteriores pueden haber eliminado candidatos del manifiesto.
    if (-not (Test-Path -LiteralPath $full -ErrorAction Stop)) { return $false }
    $current = Get-Item -LiteralPath $full -Force -ErrorAction Stop
    if (($current.Attributes -band ([IO.FileAttributes]::ReparsePoint -bor [IO.FileAttributes]::System)) -or
        [bool]$current.PSIsContainer -ne $Entry.IsDirectory -or (Get-OwnerSid $full) -ne $Policy.SID) {
        throw "Cambio de tipo, atributos o propietario: $full"
    }
    if (-not $Entry.IsDirectory -and ($current.Length -ne $Entry.Length -or $current.LastWriteTimeUtc.Ticks -ne $Entry.LastWriteUtc)) {
        throw "Archivo externo cambiado desde la auditoria: $full"
    }
    return $true
}

function Remove-EmptyExternalOwnerDirectory {
    param([string]$Path)
    # Solo se invoca tras validar ruta, SID y ausencia de hijos. Nunca recursivo.
    [IO.Directory]::Delete($Path, $false)
}

function Invoke-ExternalOwnerPurge {
    param([Parameter(Mandatory=$true)]$Plan)
    if ($WhatIfPreference -or -not $Execute) { return }
    if ($Plan.BlockingIssues.Count) { throw 'Inspeccion externa incompleta en zonas de borrado; no se continua.' }
    foreach ($entry in @($Plan.Files) + @($Plan.Directories)) { $null = Assert-ExternalOwnerEntry $entry $Plan.Policy }
    foreach ($entry in $Plan.Files) {
        if ($PSCmdlet.ShouldProcess($entry.Path, 'Eliminar archivo externo del SID original')) {
            if (Assert-ExternalOwnerEntry $entry $Plan.Policy) {
                Remove-Item -LiteralPath $entry.Path -Force -ErrorAction Stop
                Write-Report "Archivo externo eliminado: $($entry.Path)" 'OK'
                Add-Finding 'Deleted' 'ExternalFile' $entry.Path 'SID original verificado.'
            }
        }
    }
    foreach ($entry in @($Plan.Directories | Sort-Object { $_.Path.Length } -Descending)) {
        if ((Assert-ExternalOwnerEntry $entry $Plan.Policy) -and -not @(Get-ChildItem -LiteralPath $entry.Path -Force -ErrorAction Stop).Count) {
            if ($PSCmdlet.ShouldProcess($entry.Path, 'Eliminar carpeta externa vacia del SID original')) {
                if (Assert-ExternalOwnerEntry $entry $Plan.Policy) {
                    Remove-EmptyExternalOwnerDirectory $entry.Path
                    Add-Finding 'Deleted' 'ExternalDirectory' $entry.Path 'Carpeta vacia del SID original.'
                }
            }
        }
    }
}

function Assert-ExternalOwnerResult {
    param($Policy)
    # Verificar solo el alcance de borrado. No repetir la auditoria protegida.
    $verificationPolicy = $Policy.PSObject.Copy()
    $verificationPolicy | Add-Member -NotePropertyName AuditProtected -NotePropertyValue $false -Force
    $remaining = Get-ExternalOwnerPlan $verificationPolicy
    if ($remaining.BlockingIssues.Count -or $remaining.Files.Count) { throw 'Quedan archivos externos del SID o zonas de borrado sin verificar; se conserva la cuenta original.' }
    foreach ($entry in $remaining.Directories) {
        if (-not @(Get-ChildItem -LiteralPath $entry.Path -Force -ErrorAction Stop).Count) { throw "Queda carpeta externa vacia del SID: $($entry.Path)" }
        Add-Finding 'Preserved' 'NonEmptyDirectory' $entry.Path 'Contiene elementos conservados; nunca se elimina recursivamente por ser propietario de la carpeta.'
    }
    foreach ($issue in $remaining.Issues) { $script:VerificationIssues.Add($issue) }
    Write-Report 'Verificada la limpieza externa por propietario en las zonas autorizadas. Las carpetas con contenido ajeno se conservan.' 'OK'
}

function Assert-SafeSharedRoot {
    param([Parameter(Mandatory = $true)][string]$Path)
    $full = Get-FullLiteralPath $Path
    if ($full -ieq [IO.Path]::GetPathRoot($full)) { throw "Raiz de unidad rechazada: $full" }
    $blocked = @(
        (Get-FullLiteralPath $env:windir),
        (Get-FullLiteralPath $env:ProgramFiles),
        (Get-FullLiteralPath $env:ProgramData),
        (Get-FullLiteralPath (Join-Path $env:SystemDrive 'Users'))
    )
    if (${env:ProgramFiles(x86)}) { $blocked += Get-FullLiteralPath ${env:ProgramFiles(x86)} }
    $publicAllowed = @((Join-Path $env:Public 'Documents'), (Join-Path $env:Public 'Desktop'))
    $isPublic = @($publicAllowed | Where-Object { Test-WithinPath $full $_ }).Count -gt 0
    foreach ($protected in $blocked) {
        if ((Test-WithinPath $full $protected) -and -not $isPublic) {
            throw "Zona protegida rechazada: $full"
        }
    }
    if ($full -match '(?i)\\(\$Recycle\.Bin|System Volume Information|Recovery)(\\|$)') {
        throw "Carpeta de sistema rechazada: $full"
    }
    Assert-NoReparseAncestors $full
    return $full
}

function Get-ApplicationCoverage {
    param([Parameter(Mandatory = $true)][string]$DisplayName)

    switch -Regex ($DisplayName) {
        '^MySQL Server' {
            return 'Perfil; purga LOGICA predeterminada de bases y cuentas no protegidas. Logs, copias y configuracion global requieren revision.'
        }
        '^XAMPP' {
            return 'Perfil; purga predeterminada de htdocs y carpetas enumeradas de logs/Tomcat/correo. MariaDB (mysql) y tmp compartido quedan excluidos.'
        }
        'VirtualBox|VMware' {
            return 'Con -Execute: archivos VM reconocidos de TODOS los usuarios en unidades locales fijas, sin raiz adicional ni filtro SID. Exclusiones e incidencias se informan.'
        }
        'Windows Subsystem for Linux|^Eclipse IDE|Jaspersoft' {
            return 'Perfil completo; las maquinas, distros o workspaces importados fuera del perfil requieren raiz adicional verificada.'
        }
        'OneDrive|Copilot|Google Chrome|Microsoft Edge|Mozilla Firefox|Lightshot' {
            return 'Datos locales del perfil. Las copias o cuentas en la nube no se eliminan desde este equipo.'
        }
        default {
            return 'Se eliminan los datos dentro del perfil y su registro. Datos exportados o compartidos fuera del perfil: revision pendiente.'
        }
    }
}

function Invoke-MySqlQuery {
    param(
        [Parameter(Mandatory = $true)][string]$ClientPath,
        [Parameter(Mandatory = $true)][System.Management.Automation.PSCredential]$Credential,
        [Parameter(Mandatory = $true)][string]$Query
    )
    if ($WhatIfPreference -or -not $Execute) { throw 'MySQL solo puede abrirse durante la ejecucion real.' }
    if ($Credential.UserName -notmatch '^[A-Za-z0-9_.@-]+$') {
        throw 'Esta version admite cuentas MySQL con letras, numeros y _.@-.'
    }
    Assert-NoReparseAncestors $ClientPath
    $info = New-Object Diagnostics.ProcessStartInfo
    $info.FileName = $ClientPath
    $info.Arguments = '--no-defaults --batch --binary-mode --raw --skip-column-names --default-character-set=utf8mb4 --connect-timeout=5 --host=127.0.0.1 --port=3306 --protocol=TCP --user=' + $Credential.UserName
    $info.UseShellExecute = $false
    $info.CreateNoWindow = $true
    $info.RedirectStandardInput = $true
    $info.RedirectStandardOutput = $true
    $info.RedirectStandardError = $true
    $info.StandardOutputEncoding = [Text.Encoding]::UTF8
    # Entorno privado del hijo: no se cambia $env:MYSQL_PWD ni se escribe una clave en disco.
    $info.EnvironmentVariables['MYSQL_PWD'] = $Credential.GetNetworkCredential().Password
    # MySQL 8.0 lee .mylogin.cnf aun con --no-defaults. Se redirige a una ruta inexistente,
    # sin crearla: https://dev.mysql.com/doc/refman/8.0/en/option-file-options.html
    $unusedLoginPath = Join-Path $env:TEMP ('limpieza-login-inexistente-' + [guid]::NewGuid().ToString('N'))
    if (Test-Path -LiteralPath $unusedLoginPath -ErrorAction Stop) { throw 'Ruta de aislamiento MySQL ya existente.' }
    $info.EnvironmentVariables['MYSQL_TEST_LOGIN_FILE'] = $unusedLoginPath
    $process = New-Object Diagnostics.Process
    $process.StartInfo = $info
    try {
        if (-not $process.Start()) { throw 'No se pudo iniciar el cliente MySQL.' }
        $info.EnvironmentVariables.Remove('MYSQL_PWD')
        $stdout = $process.StandardOutput.ReadToEndAsync()
        $stderr = $process.StandardError.ReadToEndAsync()
        $sqlBytes = [Text.Encoding]::UTF8.GetBytes("SET SESSION sql_mode = 'NO_BACKSLASH_ESCAPES';`n" + $Query + "`n")
        $process.StandardInput.BaseStream.Write($sqlBytes, 0, $sqlBytes.Length)
        $process.StandardInput.BaseStream.Flush()
        $process.StandardInput.Close()
        if (-not $process.WaitForExit(120000)) {
            $process.Kill()
            throw 'MySQL excedio 120 segundos. La operacion puede estar incompleta.'
        }
        $outText = $stdout.GetAwaiter().GetResult()
        $errorText = $stderr.GetAwaiter().GetResult()
        if ($process.ExitCode -ne 0) { throw "MySQL fallo (codigo $($process.ExitCode)): $errorText" }
        return [pscustomobject]@{
            ExitCode = 0
            Lines = @($outText -split '\r?\n' | Where-Object { $_ -ne '' })
        }
    }
    finally {
        $info.EnvironmentVariables.Remove('MYSQL_PWD')
        $process.Dispose()
    }
}

function ConvertFrom-HexUtf8 {
    param([AllowEmptyString()][string]$Hex)
    if ($Hex -notmatch '^(?:[0-9A-Fa-f]{2})*$') { throw 'Salida hexadecimal de MySQL invalida.' }
    $bytes = New-Object byte[] ($Hex.Length / 2)
    for ($i=0; $i -lt $bytes.Length; $i++) { $bytes[$i] = [Convert]::ToByte($Hex.Substring($i*2,2),16) }
    return [Text.Encoding]::UTF8.GetString($bytes)
}

function Test-SharedApplicationPurgePrerequisites {
    if (-not $PurgeSharedApplicationData -or $WhatIfPreference) { return }

    $xamppRoot = Join-Path $env:SystemDrive 'xampp'
    if (Test-LiteralPathQuiet -Path $xamppRoot) {
        foreach ($folder in @(Get-XamppPurgeFolders)) {
            Assert-XamppPurgeFolder $folder
            $null = @(Get-TreeNoLinks $folder -Strict)
        }
    }

    $mysqlClient = Join-Path $env:ProgramFiles 'MySQL\MySQL Server 8.0\bin\mysql.exe'
    if (Test-LiteralPathQuiet -Path $mysqlClient) {
        if (-not $MySqlCredential) {
            throw 'Para -PurgeSharedApplicationData debe proporcionar -MySqlCredential (por ejemplo, Get-Credential).'
        }
        $test = Invoke-MySqlQuery -ClientPath $mysqlClient -Credential $MySqlCredential -Query 'SELECT @@version, HEX(@@datadir);'
        if ($test.Lines.Count -ne 1) { throw 'No se pudo identificar el servidor MySQL.' }
        $parts = $test.Lines[0] -split "`t", 2
        $expectedData = Join-Path $env:ProgramData 'MySQL\MySQL Server 8.0\Data'
        if ($parts.Count -ne 2 -or $parts[0] -notlike '8.0.*') { throw 'El servidor no es MySQL 8.0 de la maqueta.' }
        if ((Get-FullLiteralPath (ConvertFrom-HexUtf8 $parts[1])) -ine (Get-FullLiteralPath $expectedData)) {
            throw 'MySQL usa una ruta de datos distinta de la maqueta. No se purga.'
        }
    }
}

function Invoke-MySqlSharedPurge {
    if ($WhatIfPreference) { Write-Report 'SIMULACION: purga logica MySQL pendiente; no se abre ninguna conexion.'; return }
    $mysqlClient = Join-Path $env:ProgramFiles 'MySQL\MySQL Server 8.0\bin\mysql.exe'
    if (-not (Test-LiteralPathQuiet -Path $mysqlClient)) { return }

        $databaseQuery = "SELECT HEX(SCHEMA_NAME) FROM INFORMATION_SCHEMA.SCHEMATA WHERE SCHEMA_NAME NOT IN ('information_schema','mysql','performance_schema','sys');"
        $databaseResult = Invoke-MySqlQuery -ClientPath $mysqlClient -Credential $MySqlCredential -Query $databaseQuery
        if ($databaseResult.ExitCode -ne 0) { throw "No se pudieron enumerar las bases MySQL: $($databaseResult.Lines -join ' ')" }

        foreach ($hexDatabase in @($databaseResult.Lines | Where-Object { $_ })) {
            $database = ConvertFrom-HexUtf8 $hexDatabase
            $escaped = $database.Replace('`', '``')
            if ($PSCmdlet.ShouldProcess("MySQL database $database", 'DROP DATABASE')) {
                $dropResult = Invoke-MySqlQuery -ClientPath $mysqlClient -Credential $MySqlCredential -Query "DROP DATABASE IF EXISTS ``$escaped``;"
                if ($dropResult.ExitCode -ne 0) { throw "No se pudo borrar la base '$database': $($dropResult.Lines -join ' ')" }
                Write-Report "Base MySQL compartida eliminada: $database" 'OK'
                Add-Finding 'Deleted' 'MySQLDatabase' $database 'DROP DATABASE verificado por el cliente.'
            }
        }

        $credentialUser = $MySqlCredential.UserName.Replace("'", "''")
        $userQuery = "SELECT HEX(user),HEX(host) FROM mysql.user WHERE user NOT IN ('root','mysql.infoschema','mysql.session','mysql.sys','$credentialUser');"
        $userResult = Invoke-MySqlQuery -ClientPath $mysqlClient -Credential $MySqlCredential -Query $userQuery
        if ($userResult.ExitCode -ne 0) { throw "No se pudieron enumerar los usuarios MySQL: $($userResult.Lines -join ' ')" }
        foreach ($line in @($userResult.Lines | Where-Object { $_ })) {
            $parts = $line -split "`t", 2
            if ($parts.Count -ne 2) { throw 'Salida de cuentas MySQL inesperada.' }
            $dbUser = ConvertFrom-HexUtf8 $parts[0]
            $dbHost = ConvertFrom-HexUtf8 $parts[1]
            $quotedUser = "'" + $dbUser.Replace("'", "''") + "'"
            $quotedHost = "'" + $dbHost.Replace("'", "''") + "'"
            if ($PSCmdlet.ShouldProcess("MySQL user $dbUser@$dbHost", 'DROP USER')) {
                $dropUserResult = Invoke-MySqlQuery -ClientPath $mysqlClient -Credential $MySqlCredential -Query "DROP USER IF EXISTS $quotedUser@$quotedHost;"
                if ($dropUserResult.ExitCode -ne 0) { throw "No se pudo borrar el usuario MySQL '$dbUser@$dbHost': $($dropUserResult.Lines -join ' ')" }
                Write-Report "Usuario MySQL compartido eliminado: $dbUser@$dbHost" 'OK'
                Add-Finding 'Deleted' 'MySQLAccount' "$dbUser@$dbHost" 'DROP USER verificado por el cliente.'
            }
        }

        if ($PSCmdlet.ShouldProcess('MySQL 8.0 local: registros binarios', 'RESET MASTER')) {
            $null = Invoke-MySqlQuery -ClientPath $mysqlClient -Credential $MySqlCredential -Query 'RESET MASTER;'
        }
        $remainingDb = Invoke-MySqlQuery -ClientPath $mysqlClient -Credential $MySqlCredential -Query $databaseQuery
        $remainingUsers = Invoke-MySqlQuery -ClientPath $mysqlClient -Credential $MySqlCredential -Query $userQuery
        if ($remainingDb.Lines.Count -or $remainingUsers.Lines.Count) { throw 'La purga MySQL dejo bases o cuentas seleccionadas sin eliminar.' }
        Write-Report 'Verificada la purga LOGICA MySQL. Cuentas protegidas, logs de texto, copias y configuracion no se restablecen.' 'OK'
}

function Get-XamppPurgeFolders {
    $root = Join-Path $env:SystemDrive 'xampp'
    # tmp tambien se conserva: my.ini de esta maqueta lo usa para MariaDB.
    foreach ($relative in @('htdocs','mailoutput','apache\logs','tomcat\logs','tomcat\temp','tomcat\work')) {
        Join-Path $root $relative
    }
}

function Get-XamppPreservedRoots {
    foreach ($relative in @('xampp\mysql','xampp\tmp')) {
        Get-FullLiteralPath (Join-Path $env:SystemDrive $relative)
    }
}

function Assert-XamppPurgeFolder {
    param([string]$Path)
    $full=Get-FullLiteralPath $Path
    $root=Get-FullLiteralPath (Join-Path $env:SystemDrive 'xampp')
    if ($full -ieq $root -or -not (Test-WithinPath $full $root)) { throw "Carpeta XAMPP fuera de alcance: $full" }
    foreach ($preserved in @(Get-XamppPreservedRoots)) {
        if ((Test-WithinPath $full $preserved) -or (Test-WithinPath $preserved $full)) { throw "MariaDB o sus temporales estan excluidos: $full" }
    }
    Assert-NoReparseAncestors $full
}

function Get-ServiceExecutablePath {
    param([string]$CommandLine)
    if ($CommandLine -match '^\s*"([^"]+\.exe)"') { return $Matches[1] }
    if ($CommandLine -match '^\s*(.+?\.exe)(?:\s|$)') { return $Matches[1] }
    return $null
}

function Test-XamppProcessMayStop {
    param([string]$Path)
    if (-not $Path) { return $false }
    $full=Get-FullLiteralPath $Path
    $root=Get-FullLiteralPath (Join-Path $env:SystemDrive 'xampp')
    if (-not (Test-WithinPath $full $root)) { return $false }
    foreach ($preserved in @(Get-XamppPreservedRoots)) {
        if (Test-WithinPath $full $preserved) { return $false }
    }
    # No cerrar el panel que puede gestionar tambien MariaDB.
    return [IO.Path]::GetFileName($full) -ine 'xampp-control.exe'
}

function Clear-VerifiedDirectory {
    param([Parameter(Mandatory = $true)][string]$Path)
    if ($WhatIfPreference) { return }
    Assert-NoReparseAncestors $Path
    if (-not (Test-Path -LiteralPath $Path -ErrorAction Stop)) { return }
    $items = @(Get-TreeNoLinks $Path -Strict | Sort-Object { $_.FullName.Length } -Descending)
    foreach ($item in $items) {
        Assert-NoReparseAncestors $item.FullName
        if (-not (Test-WithinPath (Get-FullLiteralPath $item.FullName) (Get-FullLiteralPath $Path))) {
            throw 'Elemento fuera de la carpeta aprobada.'
        }
        if ($item.PSIsContainer) {
            # Falla si otro proceso introduce contenido: nunca sigue un borrado recursivo.
            [IO.Directory]::Delete($item.FullName, $false)
        }
        else { Remove-Item -LiteralPath $item.FullName -Force -ErrorAction Stop }
    }
    if (@(Get-ChildItem -LiteralPath $Path -Force -ErrorAction Stop).Count) { throw "Quedan datos en $Path" }
}

function Invoke-XamppSharedPurge {
    if ($WhatIfPreference -or -not $Execute) { Write-Report 'SIMULACION/AUDITORIA: no se detiene ni modifica XAMPP.'; return }
    $xamppRoot = Get-FullLiteralPath (Join-Path $env:SystemDrive 'xampp')
    if (-not (Test-LiteralPathQuiet -Path $xamppRoot)) { return }
    $folders=@(Get-XamppPurgeFolders)
    foreach ($folder in $folders) { Assert-XamppPurgeFolder $folder }

    if (-not $PSCmdlet.ShouldProcess($xamppRoot, 'Vaciar carpetas XAMPP enumeradas, EXCEPTO MariaDB y tmp compartido')) {
        throw 'Purga XAMPP cancelada; no se marca la fase completada.'
    }
    $xamppServices = @(Get-CimInstance Win32_Service -ErrorAction Stop | Where-Object {
        Test-XamppProcessMayStop (Get-ServiceExecutablePath $_.PathName)
    })
    foreach ($service in $xamppServices) {
        if ($service.State -ne 'Stopped') {
            # Sin Force: no detener en cascada servicios dependientes no seleccionados.
            Stop-Service -Name $service.Name -ErrorAction Stop
        }
    }
    $xamppProcesses = @(Get-CimInstance Win32_Process -ErrorAction Stop | Where-Object {
        Test-XamppProcessMayStop $_.ExecutablePath
    })
    foreach ($process in $xamppProcesses) {
        $live=@(Get-CimInstance Win32_Process -Filter ("ProcessId=" + $process.ProcessId) -ErrorAction Stop)
        if (-not $live.Count) { continue }
        if ($live.Count -ne 1 -or $live[0].ExecutablePath -ine $process.ExecutablePath -or
            $live[0].CreationDate -ne $process.CreationDate -or -not (Test-XamppProcessMayStop $live[0].ExecutablePath)) {
            throw 'Proceso XAMPP cambiado durante la comprobacion.'
        }
        Stop-Process -Id $process.ProcessId -Force -ErrorAction Stop
    }
    foreach ($folder in $folders) {
        Assert-XamppPurgeFolder $folder
        Clear-VerifiedDirectory $folder
        Write-Report "Carpeta XAMPP vacia o ausente, verificada: $folder" 'OK'
        Add-Finding 'Completed' 'XamppDirectory' $folder 'Vacia o ausente; sin restauracion de MariaDB.'
    }
    foreach ($preserved in @(Get-XamppPreservedRoots)) {
        Add-Finding 'Excluded' 'MariaDB' $preserved 'Excluido expresamente: no borrar, restaurar ni exigir referencia.'
    }
    Write-Report 'XAMPP: carpetas seleccionadas verificadas. MariaDB y xampp/tmp conservados; no se arranca, detiene ni conecta a MariaDB.' 'OK'
}

function Get-SharedApplicationCatalog {
    # Se enumeran ubicaciones potenciales aunque no existan rastros de uso en este PC.
    $entries = @(
        @('MySQL Server','%ProgramData%\MySQL','Logs, copias, configuracion y cuentas protegidas: revisar; la purga SQL es logica.'),
        @('MariaDB de XAMPP','%SystemDrive%\xampp\mysql','Excluido por peticion del centro. No se limpia ni se restaura mysql/backup.'),
        @('MariaDB de XAMPP','%SystemDrive%\xampp\tmp','Temporal compartido usado por MariaDB: conservado.'),
        @('XAMPP FTP','%SystemDrive%\xampp\FileZillaFTP','Cuentas, configuracion y logs FTP: revisar.'),
        @('XAMPP correo','%SystemDrive%\xampp\MercuryMail','Buzones, cuentas y configuracion: revisar.'),
        @('XAMPP sitios','%SystemDrive%\xampp\cgi-bin','Codigo fuera de htdocs: revisar.'),
        @('XAMPP WebDAV','%SystemDrive%\xampp\webdav','Contenido compartido: revisar.'),
        @('XAMPP FTP','%SystemDrive%\xampp\anonymous','Ficheros compartidos: revisar.'),
        @('XAMPP Tomcat','%SystemDrive%\xampp\tomcat\webapps','Aplicaciones desplegadas: revisar frente a la maqueta.'),
        @('XAMPP configuracion','%SystemDrive%\xampp\apache\conf','VirtualHosts y rutas externas: revisar.'),
        @('Eclipse IDE','%SystemDrive%\eclipse\configuration','Configuracion compartida e historial de workspace: revisar.'),
        @('Jaspersoft Studio','%ProgramFiles%\jaspersoftstudio\configuration','Configuracion compartida y referencias a workspaces: revisar.'),
        @('Packet Tracer','%ProgramFiles%\Cisco Packet Tracer 8.2.2\saves','Ejercicios guardados fuera del perfil: revisar.'),
        @('VirtualBox/VMware','%SystemDrive%\VirtualBox VMs','Archivos VM reconocidos: purga por defecto con -Execute, cualquier propietario.'),
        @('VirtualBox/VMware','%SystemDrive%\VMs','Archivos VM reconocidos: purga por defecto con -Execute, cualquier propietario.'),
        @('VirtualBox/VMware','%Public%\Documents\Shared Virtual Machines','Archivos VM reconocidos: purga por defecto con -Execute, cualquier propietario.'),
        @('Crocodile Clips','%ProgramFiles%\Crocodile Clips v3.5','Aplicacion antigua: revisar documentos o configuracion junto al ejecutable.'),
        @('Crocodile Clips','%ProgramFiles(x86)%\Crocodile Clips v3.5','Aplicacion antigua: revisar documentos o configuracion junto al ejecutable.'),
        @('Aplicaciones de la maqueta','%ProgramData%','Solo inventario de subcarpetas. No se borra configuracion global, licencias ni datos de servicios.')
    )
    foreach ($entry in $entries) {
        $path = [Environment]::ExpandEnvironmentVariables($entry[1])
        if ($path.Contains('%')) { continue }
        [pscustomobject]@{Application=$entry[0]; Path=$path; Action=$entry[2]}
    }
    foreach ($path in @(Get-XamppPurgeFolders)) {
        [pscustomobject]@{Application='XAMPP';Path=$path;Action='Vaciado predeterminado; MariaDB y tmp compartido excluidos.'}
    }
}

function Write-Audit {
    param([Parameter(Mandatory = $true)]$Target)

    Write-Report "Equipo: $env:COMPUTERNAME; objetivo: $UserName; SID: $($Target.SID)"
    if ($Target.LocalUser) {
        Write-Report "Cuenta local encontrada. Habilitada=$($Target.LocalUser.Enabled); ultimo inicio=$($Target.LocalUser.LastLogon)"
    }
    else { Write-Report 'La cuenta local ya no existe.' 'WARN' }

    if ($Target.ProfilePath) {
        $stats = Get-DirectoryStats -Path $Target.ProfilePath
        Write-Report "Perfil: $($Target.ProfilePath); ficheros=$($stats.Count); tamano=$(Format-Size $stats.Bytes); accesible=$($stats.Accessible)"
    }
    else { Write-Report 'No se encontro una carpeta de perfil.' 'WARN' }

    $knownRelativePaths = @(
        'AppData\Local', 'AppData\LocalLow', 'AppData\Roaming', 'AppData\Local\Programs',
        '.ssh', '.gnupg', '.gitconfig', '.npmrc', '.pypirc', '.m2', '.gradle', '.nuget', '.android',
        '.VirtualBox', '.eclipse', 'VirtualBox VMs', 'Documents\Virtual Machines', 'Documents\Arduino',
        'Documents\NetBeansProjects', 'source', 'repos', 'Projects', 'workspace', 'IdeaProjects',
        'AndroidStudioProjects', 'OneDrive'
    )
    if ($Target.ProfilePath) {
        foreach ($relative in $knownRelativePaths) {
            $path = Join-Path $Target.ProfilePath $relative
            if (Test-LiteralPathQuiet -Path $path) {
                $stats = Get-DirectoryStats -Path $path
                Write-Report "Rastro de perfil: $relative; ficheros=$($stats.Count); tamano=$(Format-Size $stats.Bytes)"
            }
        }
    }

    $apps = @(Get-InstalledApplications)
    Write-Report "Entradas instaladas: $($apps.Count). Se elimina lo almacenado DENTRO del perfil, con independencia de la aplicacion; esto no acredita los datos externos."
    foreach ($app in $apps) {
        $coverage = Get-ApplicationCoverage -DisplayName $app.DisplayName
        Write-Report "Aplicacion: $($app.DisplayName) $($app.DisplayVersion); ubicacion=$($app.InstallLocation); cobertura=$coverage"
    }
    $shortcuts = @(Get-ApplicationShortcuts)
    Write-Report "Accesos directos compartidos detectados: $($shortcuts.Count). Se incluyen para cubrir programas portables o sin registro de desinstalacion."
    foreach ($shortcut in $shortcuts) {
        $coverage = Get-ApplicationCoverage -DisplayName $shortcut.DisplayName
        Write-Report "Acceso de aplicacion: $($shortcut.DisplayName); destino=$($shortcut.TargetPath); cobertura=$coverage"
    }

    $tasks = @()
    try { $tasks = @(Get-TargetScheduledTasks -Target $Target) }
    catch { $script:AuditIssues.Add("No se pudieron enumerar tareas: $($_.Exception.Message)") }
    foreach ($task in $tasks) { Write-Report "Tarea del usuario: $($task.TaskPath)$($task.TaskName)" 'WARN' }
    if ($tasks.Count -eq 0) { Write-Report 'No se detectaron tareas programadas del usuario.' 'OK' }

    $services = @()
    try { $services = @(Get-TargetServices -Target $Target) }
    catch { $script:AuditIssues.Add("No se pudieron enumerar servicios: $($_.Exception.Message)") }
    foreach ($service in $services) { Write-Report "Servicio que usa la cuenta: $($service.Name); estado=$($service.State); ruta=$($service.PathName)" 'WARN' }
    if ($services.Count -eq 0) { Write-Report 'No se detectaron servicios ejecutados con la cuenta del usuario.' 'OK' }

    Write-Report 'Los archivos del SID fuera del perfil se enumeran en la busqueda global posterior, sin limitarse a Documentos/Escritorio publicos.'

    foreach ($entry in @(Get-SharedApplicationCatalog)) {
        $exists = Test-LiteralPathQuiet $entry.Path
        Write-Report "CATALOGO: $($entry.Application); ruta=$($entry.Path); existe=$exists; alcance=$($entry.Action)"
        if ($exists) {
            try {
                Assert-NoReparseAncestors $entry.Path
                $children = @(Get-ChildItem -LiteralPath $entry.Path -Force -ErrorAction Stop)
                Write-Report "  Primer nivel ($($children.Count) elementos): $(($children | Select-Object -First 40 -ExpandProperty Name) -join ', ')"
            }
            catch { $script:AuditIssues.Add("Almacen no inspeccionado: $($entry.Path); $($_.Exception.Message)") }
        }
    }

    $sharedStores = New-Object System.Collections.Generic.List[string]
    $standardTopLevel = @('$Recycle.Bin', '$WinREAgent', 'Archivos de programa', 'Archivos de programa (x86)', 'Config.Msi', 'Documents and Settings', 'MSOCache', 'PerfLogs', 'Program Files', 'Program Files (x86)', 'ProgramData', 'Recovery', 'System Volume Information', 'Users', 'Windows')
    foreach ($drive in @(Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' -ErrorAction SilentlyContinue)) {
        foreach ($directory in @(Get-ChildItem -LiteralPath ($drive.DeviceID + '\') -Force -Directory -ErrorAction SilentlyContinue)) {
            if ($standardTopLevel -inotcontains $directory.Name) { $sharedStores.Add($directory.FullName) }
        }
    }
    foreach ($app in $apps) {
        if ($app.InstallLocation -and (Test-LiteralPathQuiet -Path $app.InstallLocation)) {
            $location = Get-FullLiteralPath $app.InstallLocation
            $underProgramFiles = $location.StartsWith((Get-FullLiteralPath $env:ProgramFiles), [StringComparison]::OrdinalIgnoreCase)
            $underProgramFilesX86 = $false
            if (${env:ProgramFiles(x86)}) {
                $underProgramFilesX86 = $location.StartsWith((Get-FullLiteralPath ${env:ProgramFiles(x86)}), [StringComparison]::OrdinalIgnoreCase)
            }
            if (-not $underProgramFiles -and -not $underProgramFilesX86) { $sharedStores.Add($location) }
        }
    }
    $sharedStores = @($sharedStores | Sort-Object -Unique)
    foreach ($store in $sharedStores) {
        if (Test-LiteralPathQuiet -Path $store) {
            $stats = Get-DirectoryStats -Path $store
            Write-Report "Almacen compartido para revisar: $store; ficheros=$($stats.Count); tamano=$(Format-Size $stats.Bytes); accesible=$($stats.Accessible)" 'WARN'
            try {
                foreach ($child in @(Get-ChildItem -LiteralPath $store -Force -ErrorAction Stop | Select-Object -First 40)) {
                    Write-Report "  Contenido de primer nivel: $($child.Name); ultima modificacion=$($child.LastWriteTime)"
                }
            }
            catch { Write-Report "  No se pudo enumerar sin mas privilegios: $($_.Exception.Message)" 'WARN' }
        }
    }

    Write-Report 'Los almacenes compartidos FUERA de las purgas enumeradas solo se auditan. Sus datos suelen pertenecer a SYSTEM o a cuentas de servicio y el SID no permite atribuirlos con seguridad.' 'WARN'
    Write-Report 'La busqueda externa por propietario recorre las zonas no protegidas de las unidades fijas. Para auditar Windows, aplicaciones y otros perfiles use -AuditProtectedOwnerData; no autoriza borrarlos.'
    Write-Report 'La purga compartida elimina bases/cuentas MySQL no protegidas y las carpetas XAMPP enumeradas para todos los usuarios. No certifica un restablecimiento completo de aplicaciones.' 'WARN'
}

function Write-CleanupPlan {
    param($Target)
    Write-Report "SIMULACION: cuenta/perfil SID=$($Target.SID); perfil=$($Target.ProfilePath)"
    Write-Report 'Plan: preparar cuenta temporal deshabilitada con la nueva contrasena y los mismos grupos/atributos; limpiar datos del SID antiguo; eliminar cuenta antigua; renombrar la nueva y habilitarla.'
    Write-Report 'La nueva cuenta tendra otro SID. Los permisos directos del SID anterior fuera del alcance no se migran. Windows creara un perfil nuevo al iniciar sesion. No iniciar sesion durante el mantenimiento.'
    Write-Report 'Plan VM: borrar los archivos VirtualBox/VMware reconocidos de TODOS los usuarios en unidades locales fijas, incluidos discos, snapshots y exportaciones. No requiere -PurgeSharedApplicationData.'
    Write-Report 'Plan externo AL FINAL, antes de sustituir la cuenta: borrar archivos del SID original y carpetas suyas vacias en zonas no protegidas. Auditoria protegida activada por defecto, sin borrar. VM y purgas compartidas tienen alcance separado.'
    if ($PurgeSharedApplicationData) {
        Write-Report 'Plan MySQL: identificar servidor 8.0/ruta de maqueta, purgar bases y cuentas no protegidas, RESET MASTER y verificar. No se enumeran bases ni se solicitan credenciales en simulacion.'
        foreach ($path in @(Get-XamppPurgeFolders)) { Write-Report "Plan XAMPP: vaciar $path" }
        Write-Report 'Plan XAMPP: conservar xampp/mysql y xampp/tmp. No conectar, arrancar, detener ni restaurar MariaDB. No se requiere referencia de maqueta.'
        Write-Report 'La simulacion no valida la conexion MySQL ni el registro de repeticion/recuperacion.'
    }
    Write-Report 'SIMULACION FINALIZADA: ninguna cuenta, archivo, servicio o base modificados; sin fichero de informe ni contrasenas temporales.'
}

function Get-AccountSnapshot {
    param([Parameter(Mandatory=$true)][string]$SID)
    $users = @(Get-LocalUser -ErrorAction Stop | Where-Object { $_.SID.Value -eq $SID })
    if ($users.Count -ne 1) { throw 'No se puede verificar la cuenta Windows de origen o destino.' }
    $user = $users[0]
    $groups = @(foreach ($group in @(Get-LocalGroup -ErrorAction Stop)) {
        $members = @(Get-LocalGroupMember -Group $group.Name -ErrorAction Stop)
        if (@($members | Where-Object { $_.SID.Value -eq $SID }).Count) { $group.SID.Value }
    })
    $directoryUser = [ADSI]("WinNT://$env:COMPUTERNAME/$($user.Name),user")
    $flags = [int]$directoryUser.psbase.InvokeGet('UserFlags')
    # La fecha de clave se usa solo para detectar cambios en la cuenta original.
    return [pscustomobject][ordered]@{
        Name = $user.Name
        SID = $user.SID.Value
        Enabled = $user.Enabled
        FullName = $user.FullName
        Description = $user.Description
        PasswordLastSet = $user.PasswordLastSet
        PasswordExpires = $user.PasswordExpires
        PasswordNeverExpires = [bool]($flags -band 65536)
        UserMayChangePassword = $user.UserMayChangePassword
        PasswordRequired = $user.PasswordRequired
        AccountExpires = $user.AccountExpires
        Groups = @($groups | Sort-Object)
    }
}

function Assert-AccountUnchanged {
    param([Parameter(Mandatory=$true)]$Snapshot)
    $current = Get-AccountSnapshot -SID $Snapshot.SID
    if (($current | ConvertTo-Json -Depth 4 -Compress) -cne ($Snapshot | ConvertTo-Json -Depth 4 -Compress)) {
        throw 'La cuenta Windows o sus grupos han cambiado durante la limpieza. Revisar antes de usar el equipo.'
    }
}

function Set-AccountPasswordRequired {
    param([string]$Name, [bool]$Required)
    $account = [ADSI]("WinNT://$env:COMPUTERNAME/$Name,user")
    $flags = [int]$account.psbase.InvokeGet('UserFlags')
    if ($Required) { $flags = $flags -band (-bnot 32) } else { $flags = $flags -bor 32 }
    # ADSI puede emitir un resultado COM nulo en el pipeline. No debe mezclarse
    # con el objeto de cuenta que devuelve New-StagedAccount.
    $null = $account.psbase.InvokeSet('UserFlags', $flags)
    $null = $account.SetInfo()
}

function Assert-ReplacementAccount {
    param($Original, [string]$NewSID, [string]$ExpectedName, [bool]$Enabled)
    if ($NewSID -eq $Original.SID) { throw 'La cuenta nueva debe tener un SID distinto.' }
    $current = Get-AccountSnapshot $NewSID
    if ($current.Name -cne $ExpectedName -or $current.Enabled -ne $Enabled) { throw 'Nombre o estado incorrecto de la nueva cuenta.' }
    foreach ($field in @('FullName','Description','PasswordNeverExpires','UserMayChangePassword','PasswordRequired','AccountExpires')) {
        if ($current.$field -ne $Original.$field) { throw "Atributo no restaurado: $field" }
    }
    if (($current.Groups -join ',') -cne ($Original.Groups -join ',')) { throw 'Los grupos de la nueva cuenta no coinciden.' }
}

function New-StagedAccount {
    param($Original, [Security.SecureString]$Password)
    if ($WhatIfPreference -or -not $Execute) { throw 'La cuenta temporal solo se crea en ejecucion real.' }
    if ($Original.AccountExpires -and $Original.AccountExpires -le (Get-Date)) {
        throw 'La cuenta original esta caducada. Revise su caducidad antes de recrearla para la nueva promocion.'
    }
    $name = 'dam-' + [guid]::NewGuid().ToString('N').Substring(0,15)
    $parameters = @{
        Name=$name; Password=$Password; Disabled=$true
        PasswordNeverExpires=[bool]$Original.PasswordNeverExpires
        UserMayNotChangePassword=(-not $Original.UserMayChangePassword)
        ErrorAction='Stop'; Confirm=$false
    }
    if ($Original.FullName) { $parameters.FullName=$Original.FullName }
    if ($Original.Description) { $parameters.Description=$Original.Description }
    if ($Original.AccountExpires) { $parameters.AccountExpires=$Original.AccountExpires }
    else { $parameters.AccountNeverExpires=$true }
    $newUser = $null
    try {
        $newUser = New-LocalUser @parameters
        $null = Set-AccountPasswordRequired -Name $name -Required $Original.PasswordRequired
        # Quitar posibles grupos predeterminados y restaurar exactamente los del origen.
        $actual = Get-AccountSnapshot $newUser.SID.Value
        foreach ($groupSID in $actual.Groups) {
            if ($Original.Groups -notcontains $groupSID) {
                $null = Remove-LocalGroupMember -SID $groupSID -Member $newUser.SID.Value -Confirm:$false -ErrorAction Stop
            }
        }
        foreach ($groupSID in $Original.Groups) {
            if ($actual.Groups -notcontains $groupSID) {
                $null = Add-LocalGroupMember -SID $groupSID -Member $newUser.SID.Value -ErrorAction Stop
            }
        }
        Assert-ReplacementAccount -Original $Original -NewSID $newUser.SID.Value -ExpectedName $name -Enabled $false
        return [pscustomobject]@{SID=$newUser.SID.Value;Name=$name}
    }
    catch {
        if ($newUser) {
            # Solo limpiar la cuenta temporal creada en esta llamada, nunca una coincidencia por nombre.
            Remove-LocalUser -SID $newUser.SID -Confirm:$false -ErrorAction Stop
        }
        throw
    }
}

function Save-RecreationManifest {
    param($Original, $Staged)
    if (-not $script:ReportPathReady) { throw 'Se necesita un informe en disco antes de sustituir la cuenta.' }
    $path = $script:ReportPathReady + '.cuenta.json'
    $record = [pscustomobject]@{Computer=$env:COMPUTERNAME;Original=$Original;Replacement=$Staged;Created=(Get-Date).ToString('o');PasswordStored=$false}
    $bytes = [Text.Encoding]::UTF8.GetBytes(($record | ConvertTo-Json -Depth 6))
    $stream = [IO.File]::Open($path, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::Read)
    try { $stream.Write($bytes,0,$bytes.Length); $stream.Flush() } finally { $stream.Dispose() }
    Write-Report "Manifiesto de recuperacion sin contrasena: $path"
}

function Complete-AccountRecreation {
    param($Original, $Staged)
    if ($WhatIfPreference -or -not $Execute) { throw 'La sustitucion de cuentas solo se permite en ejecucion real.' }
    $oldUsers = @(Get-LocalUser -ErrorAction Stop | Where-Object { $_.SID.Value -eq $Original.SID })
    $replacement = Get-AccountSnapshot $Staged.SID
    if ($oldUsers.Count) {
        Assert-AccountUnchanged $Original
        Assert-ReplacementAccount -Original $Original -NewSID $Staged.SID -ExpectedName $Staged.Name -Enabled $false
    }
    elseif ($replacement.Name -cne $Staged.Name -and $replacement.Name -cne $Original.Name) { throw 'Nombre inesperado de la cuenta de recuperacion.' }
    else { Assert-ReplacementAccount $Original $Staged.SID $replacement.Name $replacement.Enabled }
    if (@(Get-CimInstance Win32_UserProfile -ErrorAction Stop | Where-Object { $_.SID -eq $Original.SID }).Count) {
        throw 'No se elimina la cuenta original mientras siga registrado su perfil.'
    }
    # Password y grupos ya se han validado antes de este paso irreversible.
    if ($oldUsers.Count) { Remove-LocalUser -SID $Original.SID -Confirm:$false -ErrorAction Stop }
    if (@(Get-LocalUser -ErrorAction Stop | Where-Object { $_.SID.Value -eq $Original.SID }).Count) { throw 'La cuenta original sigue existiendo.' }
    if ($replacement.Name -cne $Original.Name) { Rename-LocalUser -SID $Staged.SID -NewName $Original.Name -Confirm:$false -ErrorAction Stop }
    if (-not $replacement.Enabled) { Enable-LocalUser -SID $Staged.SID -Confirm:$false -ErrorAction Stop }
    Assert-ReplacementAccount -Original $Original -NewSID $Staged.SID -ExpectedName $Original.Name -Enabled $true
    Write-Report "Cuenta recreada y habilitada: $($Original.Name); SID anterior=$($Original.SID); SID nuevo=$($Staged.SID)" 'OK'
}

function Assert-CleanupResult {
    param($Target, [string[]]$SharedRoots, [Parameter(Mandatory=$true)]$AccountSnapshot)
    $failures = New-Object 'System.Collections.Generic.List[string]'
    Assert-AccountUnchanged -Snapshot $AccountSnapshot
    if (@(Get-CimInstance Win32_UserProfile -ErrorAction Stop | Where-Object { $_.SID -eq $Target.SID }).Count) { $failures.Add('El perfil sigue registrado.') }
    if ($Target.ProfilePath -and (Test-Path -LiteralPath $Target.ProfilePath -ErrorAction Stop)) { $failures.Add('La carpeta del perfil sigue existiendo.') }
    if ((Get-Variable Run -Scope Script -ErrorAction SilentlyContinue) -and $script:Run -and $script:Run.ProfilePath -and (Test-Path -LiteralPath $script:Run.ProfilePath)) { $failures.Add('La carpeta de perfil original registrada sigue existiendo.') }
    $key = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\' + $Target.SID
    if (Test-Path -LiteralPath $key -ErrorAction Stop) { $failures.Add('Queda la clave ProfileList.') }
    if (@(Get-TargetScheduledTasks $Target).Count) { $failures.Add('Quedan tareas del usuario.') }
    if (@(Get-TargetServices $Target).Count) { $failures.Add('Quedan servicios de la cuenta.') }
    foreach ($drive in @(Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' -ErrorAction Stop)) {
        $recycle = Join-Path (Join-Path ($drive.DeviceID + '\') '$Recycle.Bin') $Target.SID
        if (Test-Path -LiteralPath $recycle -ErrorAction Stop) { $failures.Add("Queda papelera: $recycle") }
    }
    if ($failures.Count) { throw ('VERIFICACION INCOMPLETA: ' + ($failures -join ' ')) }
    Write-Report 'Verificado: datos del SID anterior limpiados dentro del alcance seleccionado. La cuenta original aun existe y puede sustituirse.' 'OK'
    Add-Finding 'Excluded' 'Scope' 'Almacenes externos, copias y logs no seleccionados' 'Fuera del alcance verificado; no se certifica ausencia total de datos de todas las aplicaciones.'
}

function Remove-TargetData {
    param([Parameter(Mandatory = $true)]$Target)

    if ($WhatIfPreference) { Write-CleanupPlan $Target; return }
    Assert-SafeTarget -Target $Target -Refresh
    if (-not (Test-IsAdministrator)) {
        throw 'Abra Windows PowerShell como administrador para usar -Execute.'
    }
    $accountBefore = Get-AccountSnapshot -SID $Target.SID
    if ($script:Run) { $accountBefore=$script:Run.Original; Assert-AccountUnchanged $accountBefore }
    Assert-VmEnginesStopped
    if ($script:VmPlan.BlockingIssues.Count) { throw 'Inspeccion VM incompleta: resuelva los errores del informe antes de ejecutar la limpieza.' }
    $null = @(Get-TargetScheduledTasks $Target)
    $preServices = @(Get-TargetServices $Target)
    foreach ($service in $preServices) {
        $exe=Get-ServiceExecutablePath $service.PathName
        if ($exe -and (Test-WithinPath (Get-FullLiteralPath $exe) (Get-FullLiteralPath (Join-Path $env:SystemDrive 'xampp\mysql')))) {
            throw 'MariaDB se ejecuta con la cuenta que se pretende recrear. No se altera MariaDB: revise primero su cuenta de servicio.'
        }
    }
    if ($preServices.Count -and -not $RemoveUserServices) {
        throw 'La cuenta se usa en servicios. Revise el informe y use -RemoveUserServices si deben eliminarse.'
    }
    if (-not $script:Run -or $script:Run.Completed -notcontains 'XAMPP') { Test-SharedApplicationPurgePrerequisites }

    if (-not $Force) {
        Write-Host ''
        Write-Host "Se limpiara '$($Target.ProfilePath)' y se ELIMINARA y RECREARA '$UserName', habilitada con SID nuevo y los mismos grupos/atributos compatibles." -ForegroundColor Yellow
        $expected = "RECREAR $UserName"
        $answer = Read-Host "Escriba exactamente '$expected' para continuar"
        if ($answer -cne $expected) { throw 'No se confirmo la eliminacion.' }
        Write-Host "Tambien se borraran archivos de cualquier extension del SID $($Target.SID) fuera del perfil en las unidades fijas, salvo las zonas protegidas del informe." -ForegroundColor Yellow
        $ownerAnswer = Read-Host "Escriba exactamente 'BORRAR ARCHIVOS EXTERNOS' para continuar"
        if ($ownerAnswer -cne 'BORRAR ARCHIVOS EXTERNOS') { throw 'No se confirmo el borrado externo por propietario.' }
        Write-Host 'ATENCION: tambien se borraran los archivos de maquinas virtuales reconocidos de TODOS los usuarios, sin filtrar por propietario.' -ForegroundColor Red
        $vmAnswer = Read-Host "Escriba exactamente 'BORRAR TODAS LAS VM' para continuar"
        if ($vmAnswer -cne 'BORRAR TODAS LAS VM') { throw 'No se confirmo la purga de maquinas virtuales.' }
        if ($PurgeSharedApplicationData) {
            Write-Host 'ATENCION: se purgan bases/cuentas MySQL no protegidas y las carpetas XAMPP enumeradas para TODOS los usuarios.' -ForegroundColor Red
            $sharedAnswer = Read-Host "Escriba exactamente 'PURGAR DATOS COMPARTIDOS' para continuar"
            if ($sharedAnswer -cne 'PURGAR DATOS COMPARTIDOS') { throw 'No se confirmo la purga de datos compartidos.' }
        }
    }

    Assert-SafeTarget -Target $Target -Refresh
    if (-not $PSCmdlet.ShouldProcess($UserName, 'Preparar cuenta nueva, borrar archivos externos del SID y VM de TODOS los usuarios, limpiar datos y sustituir la cuenta anterior')) { return }
    if (-not $NewUserPassword) {
        # Contrasena comun indicada expresamente por el centro.
        $NewUserPassword = ConvertTo-SecureString 'alumno' -AsPlainText -Force
    }
    Start-RunCheckpoint $Target $accountBefore
    try {
        if (-not $script:Run.Staged) {
            $staged = New-StagedAccount -Original $accountBefore -Password $NewUserPassword
            $script:Run.Staged=$staged
            $script:Run.Phase=$null
            Save-RunCheckpoint
            Save-RecreationManifest -Original $accountBefore -Staged $staged
        }
        else {
            $staged=$script:Run.Staged
            Assert-ReplacementAccount $accountBefore $staged.SID $staged.Name $false
        }
        Invoke-CheckpointPhase 'VM' { Invoke-VmPurge -Plan $script:VmPlan }
        if ($PurgeSharedApplicationData) {
            Invoke-CheckpointPhase 'MySQL' { Invoke-MySqlSharedPurge }
            Invoke-CheckpointPhase 'XAMPP' { Invoke-XamppSharedPurge }
        }
        Invoke-CheckpointPhase 'Tasks' {
    foreach ($task in @(Get-TargetScheduledTasks -Target $Target)) {
        $taskLabel = "$($task.TaskPath)$($task.TaskName)"
        if ($PSCmdlet.ShouldProcess($taskLabel, 'Eliminar tarea programada del usuario')) {
            Unregister-ScheduledTask -TaskName $task.TaskName -TaskPath $task.TaskPath -Confirm:$false -ErrorAction Stop
            Write-Report "Tarea eliminada: $taskLabel" 'OK'
            Add-Finding 'Deleted' 'ScheduledTask' $taskLabel 'Tarea de la cuenta original.'
        }
    }

        }
        Invoke-CheckpointPhase 'Services' {
    $services = @(Get-TargetServices -Target $Target)
    if ($services.Count -gt 0 -and -not $RemoveUserServices) {
        Write-Report 'Hay servicios que usan la cuenta. No se eliminan sin -RemoveUserServices.' 'WARN'
    }
    if ($RemoveUserServices) {
        foreach ($service in $services) {
            if ($PSCmdlet.ShouldProcess($service.Name, 'Detener y eliminar servicio configurado con el usuario')) {
                if ($service.State -ne 'Stopped') { Stop-Service -Name $service.Name -ErrorAction Stop }
                & sc.exe delete $service.Name | Out-Null
                if ($LASTEXITCODE -ne 0) { throw "sc.exe no pudo eliminar el servicio $($service.Name)." }
                Write-Report "Servicio eliminado: $($service.Name)" 'OK'
                Add-Finding 'Deleted' 'Service' $service.Name 'Servicio de la cuenta original.'
            }
        }
    }

        }
        Invoke-CheckpointPhase 'Recycle' {
    foreach ($drive in @(Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' -ErrorAction Stop)) {
        $recyclePath = Join-Path (Join-Path ($drive.DeviceID + '\') '$Recycle.Bin') $Target.SID
        if (Test-Path -LiteralPath $recyclePath) {
            if ($PSCmdlet.ShouldProcess($recyclePath, 'Eliminar papelera del SID')) {
                Clear-VerifiedDirectory $recyclePath
                [IO.Directory]::Delete($recyclePath, $false)
                Write-Report "Papelera eliminada: $recyclePath" 'OK'
                Add-Finding 'Deleted' 'RecycleDirectory' $recyclePath 'Papelera del SID original.'
            }
        }
    }

        }
        Invoke-CheckpointPhase 'Profile' {
    if ($Target.Profile) {
        Assert-SafeTarget -Target $Target -Refresh
        if ($PSCmdlet.ShouldProcess($Target.ProfilePath, 'Eliminar perfil con Win32_UserProfile')) {
            $liveProfile = @(Get-CimInstance Win32_UserProfile -ErrorAction Stop | Where-Object { $_.SID -eq $Target.SID })
            if ($liveProfile.Count -ne 1 -or $liveProfile[0].Loaded) { throw 'El perfil ha cambiado o esta cargado.' }
            Remove-CimInstance -InputObject $liveProfile[0] -ErrorAction Stop
            Write-Report "Eliminacion solicitada mediante Win32_UserProfile: $($Target.ProfilePath)"
            Add-Finding 'Completed' 'ProfileRemovalRequest' $Target.ProfilePath 'Solicitud CIM; ausencia comprobada al terminar la fase.'
        }
    }

    if ($Target.ProfilePath -and (Test-Path -LiteralPath $Target.ProfilePath -ErrorAction Stop)) {
        throw "Windows dejo la carpeta de perfil. No se fuerza el borrado: $($Target.ProfilePath)"
    }

        }
        Invoke-CheckpointPhase 'ExternalOwner' {
            $script:ExternalOwnerPlan=Get-ExternalOwnerPlan -Policy $script:ExternalOwnerPolicy
            Write-ExternalOwnerPlan $script:ExternalOwnerPlan
            Record-ProtectedFindings $script:ExternalOwnerPlan
            Save-RunCheckpoint
            Invoke-ExternalOwnerPurge -Plan $script:ExternalOwnerPlan
            Assert-ExternalOwnerResult -Policy $script:ExternalOwnerPolicy
        }
        Invoke-CheckpointPhase 'Verify' {
            Assert-CleanupResult -Target $Target -SharedRoots @() -AccountSnapshot $accountBefore
        }
        Invoke-CheckpointPhase 'SwitchAccount' { Complete-AccountRecreation -Original $accountBefore -Staged $staged }
        $script:Run.Status='Completed'
        Save-RunCheckpoint
        $script:Outcome='CleanupCompleted'
        Write-Report 'RECREACION VERIFICADA. Windows creara el perfil nuevo al iniciar sesion; revisar permisos externos del SID anterior.' 'OK'
    }
    catch {
        # Conservar la cuenta temporal deshabilitada y el SID original registrado.
        # Nunca iniciar otra limpieza sobre una cuenta nueva para recuperar esta.
        Write-Report "Ejecucion incompleta. Punto de control: $script:RunPath; fase=$($script:Run.Phase). Los datos ya borrados no se recuperan." 'WARN'
        try { Save-RunCheckpoint } catch { Write-Warning 'No se pudo actualizar el punto de control tras el fallo. Conserve todos los informes.' }
        throw
    }
}

try {
    if ($UserName -match '[\\/\x00-\x1F]' -or $UserName -in @('.', '..')) { throw 'Nombre de cuenta local invalido.' }
    if ($Execute -and -not $WhatIfPreference -and -not [Environment]::Is64BitProcess) { throw 'Use Windows PowerShell de 64 bits.' }
    if ($Execute -and -not $WhatIfPreference -and $PSVersionTable.PSVersion.Major -ne 5) { throw 'Use Windows PowerShell 5.1 (powershell.exe), no PowerShell 7 (pwsh.exe), para la ejecucion real.' }
    Open-RunLedger
    Read-TrustedBaseline
    if (-not $WhatIfPreference) {
        if (-not $ReportPath) {
            $reportDirectory = Join-Path $env:ProgramData 'LimpiezaDAM'
            $reportName = 'Limpieza-{0}-{1}-{2}.log' -f ($UserName -replace '[^a-zA-Z0-9_.-]', '_'), (Get-Date -Format 'yyyyMMdd-HHmmss'), ([guid]::NewGuid().ToString('N').Substring(0,8))
            $ReportPath = Join-Path $reportDirectory $reportName
        }
        $reportFull = Get-FullLiteralPath $ReportPath
        Assert-NoReparseAncestors $reportFull
        $reportParent = Split-Path -Parent $reportFull
        if (-not (Test-Path -LiteralPath $reportParent -ErrorAction Stop)) { New-Item -ItemType Directory -Path $reportParent -Force | Out-Null }
        # CreateNew impide sobreescribir un informe o cualquier fichero existente.
        $stream = [IO.File]::Open($reportFull, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::Read)
        $stream.Dispose()
        $script:ReportPathReady = $reportFull
    }
    Write-Report "Inicio. Simulacion=$WhatIfPreference; Execute=$Execute; informe=$script:ReportPathReady"
    if (-not (Test-IsAdministrator)) { Write-Report 'Sin elevacion: la auditoria puede quedar incompleta por permisos.' 'WARN' }
    if ($script:Run -and ($script:Run.Phase -eq 'SwitchAccount' -or $script:Run.Completed -contains 'SwitchAccount')) {
        if ($script:Run.Completed -notcontains 'Verify') { throw 'Estado inconsistente: falta la verificacion previa a sustituir la cuenta.' }
        # No resolver alumno como nuevo objetivo ni volver a purgar sus datos.
        Invoke-CheckpointPhase 'SwitchAccount' { Complete-AccountRecreation $script:Run.Original $script:Run.Staged }
        Assert-ReplacementAccount $script:Run.Original $script:Run.Staged.SID $script:Run.Original.Name $true
        $script:Run.Status='Completed'
        Save-RunCheckpoint
        $script:Outcome='CleanupCompleted'
        $code=Get-ResultExitCode
        Write-StructuredResult $code
        exit $code
    }
    $target = Resolve-TargetIdentity -Name $UserName
    Assert-SafeTarget -Target $target
    if ($Execute -and -not $WhatIfPreference) { Assert-RepeatGuard $target }
    if ($script:Run -and $script:Run.ProfilePath -and $target.ProfilePath -and $target.ProfilePath -ine $script:Run.ProfilePath) { throw 'Ruta de perfil distinta de la registrada.' }
    if ($script:ReportPathReady -and $target.ProfilePath -and (Test-WithinPath $script:ReportPathReady $target.ProfilePath)) {
        throw 'El informe debe guardarse fuera del perfil que se va a eliminar.'
    }
    Write-Audit -Target $target
    Write-Report 'Buscando archivos de maquinas virtuales en todas las unidades locales fijas; puede tardar varios minutos.'
    if ($script:Run -and $script:Run.Completed -contains 'VM') {
        $script:VmPlan=[pscustomobject]@{BlockingIssues=@();Issues=@()}
        Write-Report 'VM ya completada: no se vuelve a inventariar ni borrar.'
    }
    else { $script:VmPlan = Get-VmPurgePlan; Write-VmPurgePlan $script:VmPlan }
    foreach ($issue in $script:VmPlan.Issues) { $script:AuditIssues.Add($issue) }
    $script:ExternalOwnerPolicy=New-ExternalOwnerPolicy -Target $target
    if ($script:Run -and $script:Run.ProfilePath) { $script:ExternalOwnerPolicy.ProfilePath=$script:Run.ProfilePath }
    if ($WhatIfPreference -or -not $Execute) {
        Write-Report 'Escaneo rapido por propietario; zonas protegidas excluidas salvo -AuditProtectedOwnerData.'
        $script:ExternalOwnerPlan=Get-ExternalOwnerPlan -Policy $script:ExternalOwnerPolicy
        Write-ExternalOwnerPlan $script:ExternalOwnerPlan
        Record-ProtectedFindings $script:ExternalOwnerPlan
        foreach ($issue in $script:ExternalOwnerPlan.Issues) { $script:AuditIssues.Add($issue) }


    }
    if ($WhatIfPreference) {
        $script:Outcome='Simulated'
        Write-CleanupPlan $target
    }
    elseif ($Execute) {
        Remove-TargetData -Target $target
    }
    else { $script:Outcome='Audited'; Write-Report 'AUDITORIA FINALIZADA. Solo se ha creado el informe; no se ha ejecutado la limpieza.' }
    foreach ($issue in @($script:AuditIssues | Sort-Object -Unique)) { Write-Report $issue 'WARN' }
    foreach ($issue in $script:VerificationIssues) { Write-Report $issue 'WARN' }
    if ((Get-ResultExitCode) -eq 2) {
        Write-Report 'RESULTADO INCOMPLETO/PENDIENTE DE REVISION (codigo 2).' 'WARN'
        Write-StructuredResult 2
        exit 2
    }
    Write-StructuredResult 0
    exit 0
}
catch {
    $message = $_.Exception.Message
    $script:Outcome='Failed'
    Add-Finding 'Error' 'Execution' '' $message
    try { Write-Report "ERROR: $message. No se declara la limpieza completa; revise el informe antes de repetir (codigo 1)." 'ERROR' }
    catch { Write-Host "ERROR: $message (no se pudo escribir el informe)." }
    try { Write-StructuredResult 1 } catch { Write-Host "No se pudo guardar el resultado JSON: $($_.Exception.Message)" }
    exit 1
}
finally {
    if ($script:RunLock) { $script:RunLock.Dispose() }
}
