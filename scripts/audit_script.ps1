# Este script devuelve un objeto JSON para ser leído por Python
# Compatible con PowerShell v2.0+ (Windows 7 / Server 2008 R2)
$ErrorActionPreference = 'Stop'
$results = @{}

# Función auxiliar para compatibilidad CIM vs WMI
function Get-SystemInfoSafe {
    param([string]$Query, [string]$Class)
    
    if (Get-Command "Get-CimInstance" -ErrorAction SilentlyContinue) {
        # Moderno (Win8/Server2012+)
        if ($Query) {
            return Get-CimInstance -Query $Query -ErrorAction SilentlyContinue
        } else {
             return Get-CimInstance -ClassName $Class -ErrorAction SilentlyContinue
        }
    } else {
        # Legacy (Win7/Server2008)
        if ($Query) {
            return Get-WmiObject -Query $Query -ErrorAction SilentlyContinue
        } else {
            return Get-WmiObject -Class $Class -ErrorAction SilentlyContinue
        }
    }
}

try {
    # 1. Verificar SMBv1 (Riesgo Crítico) via Registro (Más ligero y silencioso)
    # HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters -> SMB1
    $smbStatus = "Unknown"
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
    
    if (Test-Path $regPath) {
        $reg = Get-ItemProperty $regPath -Name "SMB1" -ErrorAction SilentlyContinue
        if ($reg -and $reg.SMB1 -eq 0) { 
            $smbStatus = "Disabled" 
        } elseif ($reg -and $reg.SMB1 -eq 1) {
            $smbStatus = "Enabled"
        } else {
            # Si no existe la clave, en versiones antiguas solía estar habilitado por defecto
            $smbStatus = "Likely Enabled (Default)"
        }
    } else {
         $smbStatus = "Unknown (Reg Key Missing)"
    }
    $results["SMBv1_Status"] = $smbStatus

    # 2. Verificar "Unquoted Service Paths" Check
    # OPTIMIZACIÓN: Filtrado Server-Side con WQL para reducir ruido y carga
    # Query: Busca servicios Auto que tienen espacio en el path y no empiezan por comillas
    # Nota: WQL Limitations implican que 'PathName LIKE "% %"' es lo mejor que podemos hacer server-side de forma fiable
    # Luego refina en cliente.
    
    $wql = "Select Name, PathName, StartMode From Win32_Service Where StartMode='Auto' AND PathName LIKE '% %'"
    $candidates = Get-SystemInfoSafe -Query $wql
    
    $unquotedServices = @()
    if ($candidates) {
        foreach ($svc in $candidates) {
            if ($svc.PathName) {
                $path = $svc.PathName
                # Filtrado Client-Side refinado:
                # 1. No debe empezar por comillas
                # 2. No debe ser carpeta system32 (falsos positivos comunes si no se normaliza) - aunque services.exe suele manejarlo bien
                # 3. Debe tener espacios (ya filtrado por WQL pero doble check)
                
                if ($path -notmatch '^"' -and $path -match '\s' -and $path -notmatch '^C:\\Windows\\') {
                    $unquotedServices += $svc.Name
                }
            }
        }
    }

    if ($unquotedServices.Count -gt 0) {
        $results["Unquoted_Services"] = $unquotedServices
        $results["Unquoted_Risk"] = "HIGH"
    } else {
        $results["Unquoted_Services"] = "None"
        $results["Unquoted_Risk"] = "Low"
    }

    # 3. Verificar Último Parche (HotFix) - HotFix suele ser ligero
    # Usamos Get-HotFix directo, existe desde v2.
    $lastPatch = Get-HotFix -ErrorAction SilentlyContinue | Sort-Object InstalledOn -Descending | Select-Object -First 1
    if ($lastPatch) {
        $results["Last_Patch_ID"] = $lastPatch.HotFixID
        
        # Validación de fecha para evitar errores de parsing si viene nula/extraña
        if ($lastPatch.InstalledOn) {
            $results["Last_Patch_Date"] = $lastPatch.InstalledOn.ToString("yyyy-MM-dd")
        } else {
            $results["Last_Patch_Date"] = "Unknown"
        }
    } else {
        $results["Last_Patch_ID"] = "NotFound"
    }

    # Output limpio solo JSON
    $json = $results | ConvertTo-Json -Compress
    Write-Output $json

} catch {
    # En caso de error fatal, devolvemos un JSON de error
    $err = @{ error = $_.Exception.Message }
    $err | ConvertTo-Json -Compress
}
