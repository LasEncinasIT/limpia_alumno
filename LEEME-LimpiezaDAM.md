# Limpieza del usuario de la maqueta DAM

## Doble clic como administrador

Mantén juntos `Iniciar-Limpieza-Administrador.cmd` y `Limpiar-RastrosAlumno.ps1`, en una carpeta de confianza fuera del perfil del alumno. Haz doble clic en **`Iniciar-Limpieza-Administrador.cmd`** y acepta la solicitud UAC de Windows (o introduce credenciales administrativas si las pide).

**Al aceptar UAC comienza la limpieza REAL, sin más preguntas.** No hagas doble clic directamente en el `.ps1`: su asociación puede abrir un editor. El lanzador elige Windows PowerShell de 64 bits, no cambia las asociaciones de archivos ni la política permanente y mantiene abierta la ventana del resultado. El bloqueo de repetición sigue activo. Si cancelas UAC, el script no se ejecuta.

Antes, cierra la sesión de `alumno`, apaga las VM y cierra VirtualBox/VMware. El doble clic siempre solicita la limpieza real; para simular utiliza el comando `-WhatIf` indicado más abajo. El lanzador no sustituye la revisión de los informes ni permite reanudar automáticamente una operación fallida.

## Ejecución directa — versión del 09/09/2026

**Sin parámetros, el script realiza borrados reales, permanentes y sin preguntas.** Esta revisión no ha vuelto a ejecutar la limpieza del equipo.

Desde una cuenta administradora distinta de `alumno`, abre **Windows PowerShell 5.1 de 64 bits como administrador** (no «x86» ni PowerShell 7). Cierra la sesión del alumno y mantén el equipo reservado para mantenimiento. Apaga las VM y cierra VirtualBox/VMware en todas las sesiones.

Copia `Limpiar-RastrosAlumno.ps1` a una carpeta fuera del perfil del alumno. Desde esa carpeta, el comando completo es:

```powershell
.\Limpiar-RastrosAlumno.ps1
```

No necesitas otros archivos, una maqueta limpia, `maqueta.json` ni un SHA256 de referencia. Ya incluye las contraseñas indicadas por el centro: Windows `alumno` y MySQL `root` / `1234`.

Si Windows impide ejecutar el archivo por la política de scripts, permite la ejecución solo en esa ventana:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
.\Limpiar-RastrosAlumno.ps1
```

Las políticas impuestas por el centro pueden prevalecer. El script no cambia permanentemente la política ni se eleva solo.

**En este PC ya se recreó la cuenta el 08/09/2026. El bloqueo de repetición debe impedir limpiarla otra vez por accidente. No lo eludas para intentar resolver los avisos de aquella ejecución.**

## Simulación y auditoría sin borrar

Simular el alcance completo, sin crear informes ni abrir conexiones MySQL:

```powershell
.\Limpiar-RastrosAlumno.ps1 -WhatIf
```

Auditar y guardar informes, sin borrar:

```powershell
.\Limpiar-RastrosAlumno.ps1 -AuditOnly
```

`-AuditOnly` siempre anula la ejecución, incluso si también se indica `-Execute`. La simulación no comprueba la autenticación MySQL ni los controles de repetición/recuperación de una ejecución real. Ver un plan de borrado no significa que los precontroles reales vayan a pasar.

**Cambio respecto de versiones anteriores:** omitir `-Execute` ya no significa auditar. Ahora el modo sin parámetros es destructivo. Usa siempre `-WhatIf` o `-AuditOnly` para no borrar.

## Qué incluye el comando sin parámetros

1. Inventario de aplicaciones de la maqueta y datos potenciales, aunque una aplicación no muestre uso en ese PC.
2. Preparación de una cuenta temporal deshabilitada; Windows debe aceptar la contraseña antes de borrar datos.
3. Borrado de archivos de VM reconocidas de **todos los usuarios** dentro del alcance.
4. Purga lógica del **MySQL Server 8.0 independiente**, en `127.0.0.1:3306`: bases y cuentas no protegidas.
5. Limpieza de las carpetas XAMPP enumeradas abajo, **sin limpiar MariaDB**.
6. Eliminación de tareas y servicios de la cuenta objetivo, su papelera y su perfil mediante Windows.
7. Búsqueda y borrado por el **SID original** fuera del perfil, al final de las purgas.
8. Verificación y sustitución de la cuenta: `alumno` queda habilitado, con contraseña `alumno` y SID nuevo.

Restaura nombre original (incluidas mayúsculas), nombre completo, descripción, grupos, caducidad y opciones compatibles de contraseña. Las fechas de creación/cambio de contraseña son nuevas. Windows creará el perfil en el siguiente inicio de sesión. También desaparecen las aplicaciones instaladas exclusivamente dentro del perfil anterior; las aplicaciones compartidas permanecen instaladas.

Los permisos concedidos directamente al SID antiguo fuera del alcance no pasan al nuevo SID. Los permisos obtenidos mediante los grupos restaurados sí se mantienen. Si la cuenta está caducada, el perfil está cargado, la identidad cambia o hay otra validación fallida, se detiene.

## MariaDB de XAMPP: excluido expresamente

Se conserva `C:\xampp\mysql` completo: bases, cuentas, configuración, ejecutables, logs y `mysql\backup`. No se conecta, arranca, detiene ni restaura MariaDB. **Tampoco se limpia `C:\xampp\tmp`**, porque el `my.ini` de esta maqueta lo utiliza para los temporales de MariaDB.

Ambas rutas se excluyen también del borrado de archivos VM. La búsqueda por propietario protege XAMPP; la auditoría protegida puede leer rutas y propietarios para informar, pero no autoriza borrarlos.

Se conserva el proceso del panel `xampp-control.exe`. Los servicios de otros componentes se detienen sin forzar la parada en cascada de sus dependientes. Si un servicio de MariaDB está configurado para ejecutarse como `alumno`, el script bloquea la recreación: antes debe revisarse su cuenta de servicio para poder conservar MariaDB.

Esta exclusión se aplica desde esta versión. No revierte la limpieza de MariaDB realizada por una versión anterior y documentada al final de esta guía.

## XAMPP que sí se limpia

Se vacían exclusivamente estas carpetas de datos:

- `C:\xampp\htdocs`
- `C:\xampp\mailoutput`
- `C:\xampp\apache\logs`
- `C:\xampp\tomcat\logs`
- `C:\xampp\tomcat\temp`
- `C:\xampp\tomcat\work`

El script detiene los procesos/servicios XAMPP seleccionados, excluyendo MariaDB y el panel. Los componentes detenidos no se reinician automáticamente. `htdocs` queda vacío, incluidos los ejemplos que hubiera. FTP, MercuryMail, WebDAV, CGI, aplicaciones desplegadas en Tomcat y configuración global fuera de esas carpetas requieren revisión; no se promete restablecer todas las aplicaciones a su estado de fábrica.

No se copian archivos desde `mysql\backup` y no se exige ninguna referencia de maqueta.

## MySQL independiente: incluido

Se comprueba que el servidor sea MySQL 8.0 local, puerto 3306, con el directorio `C:\ProgramData\MySQL\MySQL Server 8.0\Data`. No se usa el cliente de XAMPP ni el puerto 3307.

Se eliminan bases salvo `information_schema`, `mysql`, `performance_schema` y `sys`. Se eliminan cuentas salvo `root`, las internas y la cuenta administrativa utilizada. Se ejecuta `RESET MASTER` y se verifica que no queden bases ni cuentas seleccionadas.

La clave `1234` está visible en el script por petición del centro. Se entrega al cliente en su entorno privado, no en la línea de comandos ni en un archivo de contraseñas. Un administrador puede inspeccionar la memoria del proceso. Para otra clave, proporciona `-MySqlCredential`.

Es una purga lógica de datos compartidos de todos los usuarios; no elimina todas las copias, logs de texto ni configuraciones globales. Si el servidor no está disponible, no se fuerza su arranque: se detiene antes de las purgas.

## Archivos fuera del perfil: búsqueda por propietario

Se recorren las unidades locales fijas y se seleccionan archivos de **cualquier extensión, incluidos los que no tienen extensión**, propiedad del SID original de `alumno`. Incluye archivos en la raíz de una unidad y dentro de carpetas de otros propietarios, excepto las zonas protegidas. No se elimina ninguna raíz de unidad.

La búsqueda se realiza al final, después de VM, datos compartidos, tareas, servicios, papelera y perfil. El motor nativo consulta el propietario sin cargar ACL completas ni ejecutar un comando PowerShell por archivo. Muestra progreso y tiempos. La verificación posterior revisa solo las zonas de borrado: **no repite el recorrido de zonas protegidas**.

Windows, Program Files, ProgramData, otros perfiles, instalaciones detectadas, XAMPP, Eclipse y elementos con atributo de sistema quedan protegidos contra el borrado general por propietario. La auditoría de estas zonas está activada por defecto, solo para informar. No se siguen enlaces ni se recorren red, unidades extraíbles, Recovery, System Volume Information o papeleras ajenas.

No se usa el permiso de escritura actual de una carpeta padre para descartar sus subcarpetas: pueden tener permisos distintos. El borrado depende del SID propietario. Antes de borrar cada archivo se revalidan ruta, ausencia de enlaces, propietario, tipo, atributos, tamaño y fecha. Las carpetas solo se eliminan si son del SID antiguo y están vacías.

Ser propietario no demuestra necesariamente autoría. No se detectan por este criterio datos escritos bajo SYSTEM/otro propietario, ni archivos cuyo propietario haya cambiado. Las aplicaciones portables no registradas ni anunciadas en accesos directos podrían no identificarse como instalaciones: revisa la simulación.

`-AdditionalUserOwnedRoots` se conserva por compatibilidad, pero las unidades fijas ya están incluidas; no amplía el borrado a zonas protegidas, red o unidades extraíbles.

## Máquinas virtuales

Se borran archivos reconocidos de VirtualBox/VMware de **cualquier propietario**, incluidas VM de profesorado y administradores: configuraciones, VDI/VMDK, snapshots, estados reconocidos, OVA/OVF y logs reconocidos. Los VHD/VHDX y SAV solo se seleccionan si una configuración de VM los referencia.

No se recorren Windows, Program Files, metadatos de volumen, papeleras ajenas ni los almacenes protegidos de Windows/Defender en ProgramData. También se excluyen `xampp\mysql` y `xampp\tmp`. No se inspecciona el interior de archivos comprimidos ni se eliminan ISO sueltas. No se certifica la eliminación de todas las VM posibles fuera del alcance o en formatos no reconocidos.

Se bloquea la purga si hay motores VM activos, errores de inspección o cambios en los candidatos. Los archivos se eliminan permanentemente; pueden quedar carpetas vacías.

## Opciones y contraseñas

Las opciones `Execute`, `PurgeSharedApplicationData`, `RemoveUserServices`, `AuditProtectedOwnerData` y `Force` están activadas por defecto. No necesitas escribirlas.

Para una excepción consciente, desde Windows PowerShell puedes desactivar una opción usando `:$false`. Por ejemplo, `-AuditProtectedOwnerData:$false` evita el recorrido protegido y acelera la auditoría; no cambia las protecciones de borrado. `-PurgeSharedApplicationData:$false` omite tanto MySQL independiente como las carpetas XAMPP seleccionadas. Si desactivas `-RemoveUserServices` y hay servicios del alumno, se bloquea la limpieza.

`-Force:$false` restaura las confirmaciones escritas antes de borrar. No afecta a las comprobaciones de identidad, permisos, rutas, cuenta o repetición.

Para otra contraseña Windows:

```powershell
$clave = Read-Host 'Nueva contraseña Windows' -AsSecureString
.\Limpiar-RastrosAlumno.ps1 -NewUserPassword $clave
```

## Repetición y recuperación

El registro administrativo en `%ProgramData%\LimpiezaDAM-State` guarda SID original y nuevo, opciones y fases. Un bloqueo exclusivo impide dos ejecuciones simultáneas. Los puntos de control se actualizan mediante sustitución atómica. `-Force` no evita estos controles.

Después de una ejecución terminada, una limpieza de la **siguiente promoción** exige autorización explícita con `-AllowRepeat -ExpectedSourceSID '<SID actual comprobado>'`. Comprueba el SID mediante `Get-LocalUser alumno | Select-Object Name,SID,Enabled`. No uses esa opción para resolver avisos de una limpieza ya realizada.

Los manifiestos antiguos `.cuenta.json` bloquean también la repetición si identifican la cuenta actual como reemplazo y están junto al script o en `%ProgramData%\LimpiezaDAM`. Conserva estos informes, especialmente el de este PC. Los manifiestos antiguos no permiten reanudar operaciones sin puntos de control.

Ante un fallo de esta versión, revisa el informe y usa `-Resume` con las mismas opciones de alcance. Las fases terminadas no se repiten. Si una fase comenzó pero no consta terminada, podría haber aplicado parte de sus operaciones: solo tras revisar el registro, `-RetryInterruptedPhase NombreDeFase` junto con `-Resume` permite repetir esa fase. El error indica su nombre.

La sustitución final tiene recuperación específica: comprueba el SID nuevo guardado y solo realiza el renombrado/habilitación pendiente, sin limpiarlo como si fuera otro alumno. Una interrupción durante `Staging` exige revisión manual de la cuenta temporal y del estado. No se crea otra cuenta ni se elimina una por nombre.

No cambies el script a mitad de una ejecución: la reanudación exige su mismo SHA256. **Una operación incompleta de la versión anterior no debe reanudarse con esta versión de distinto alcance.** No borres ni edites el registro para eludir el bloqueo.

Los puntos de control no son una copia de seguridad. No hay reversión automática de los datos borrados ni recuperación del SID antiguo.

## Informes y resultado

Los informes se guardan en `%ProgramData%\LimpiezaDAM`. `-ReportPath` permite elegir una ruta absoluta nueva, fuera del perfil objetivo. Pueden contener nombres de cuentas y rutas: consérvalos con acceso administrativo.

Junto al registro de texto se guardan el manifiesto `.cuenta.json` y el resultado `.resultado.json` cuando corresponda. El JSON separa:

- `Deleted`: eliminaciones individuales registradas.
- `Completed`: fases/operaciones completadas; no cuenta todos los archivos internos del perfil o XAMPP.
- `Preserved`: elementos conservados, como carpetas no vacías.
- `Excluded`: zonas deliberadamente omitidas, incluidos MariaDB y sus temporales.
- `Review`: restos o advertencias que requieren revisión.
- `Inaccessible`: errores de inspección/acceso.
- `Error`: fallo de ejecución.

Los contadores son registros, no necesariamente rutas únicas. Un corte abrupto puede dejar operaciones en el log de texto todavía no consolidadas en el último punto de control.

| Código | Significado |
|---|---|
| 0 | Terminado sin incidencias pendientes detectadas dentro del alcance. No certifica borrado total. |
| 1 | Error o validación rechazada. Puede haber operaciones previas aplicadas; revisar antes de reanudar. |
| 2 | Datos inaccesibles, restos o advertencias pendientes de revisión. Las exclusiones previstas no fuerzan por sí solas este código. |

No se realiza borrado forense del espacio libre ni se eliminan copias en nube/red. Sin una referencia limpia no se certifica que los restos protegidos sean originales. Las opciones de comparación `-BaselinePath` y `-BaselineSHA256` y el generador `Nueva-ReferenciaMaqueta.ps1` quedan como herramientas **opcionales e informativas**; no se necesitan para ejecutar el comando y nunca autorizan nuevos borrados.

## Comprobaciones de esta revisión

El lanzador de doble clic supera 6 pruebas adicionales: selección de PowerShell de 64 bits, solicitud de elevación, rutas con caracteres especiales, conservación del código de resultado, archivo ausente y cancelación de UAC. La elevación se ha simulado y el proceso de prueba solo ejecuta un archivo inocuo; no se ha abierto una solicitud UAC real ni ejecutado la limpieza para probar el lanzador.

Pruebas de regresión en Windows PowerShell 5.1: 23 de cuentas/MySQL/XAMPP, 10 de VM, 12 de propietario, 10 del motor nativo y 26 de controles, referencias opcionales, resultados y exclusión de MariaDB: **81 pruebas**.

Las operaciones de cuentas, servicios y bases están simuladas. Solo se manipulan archivos sintéticos de pruebas; se verifica que los archivos sintéticos de MariaDB permanecen iguales. No se ha ejecutado la limpieza real del equipo ni se ha arrancado MariaDB. La recuperación tras un corte real elevado requiere validación en un equipo desechable antes del despliegue general.

## Historial anterior (no describe el alcance actual)

## Ejecución real en DAM1-10, 08/09/2026

Ejecución completa autorizada, como administrador, de 13:24:22 a 13:27:18 (2 minutos y 56 segundos). `Alumno` se ha recreado y habilitado con contraseña `alumno`, grupos/atributos compatibles y SID nuevo terminado en `1009`; el SID anterior terminaba en `1001`. El perfil anterior ya no existe: Windows creará uno nuevo al iniciar sesión. No quedan cuentas temporales de la operación y las demás cuentas permanecen iguales.

Se han eliminado los archivos de las dos VM, el perfil y papelera antiguos, cinco tareas del usuario, 11 bases MySQL y 3 cuentas MySQL no protegidas. Se han limpiado las carpetas XAMPP enumeradas y restaurado `mysql/backup` sobre `mysql/data`; sus servicios quedan detenidos. La comprobación SQL posterior muestra únicamente los cuatro esquemas del sistema y las cuentas internas más `root`.

El resultado es **código 2, revisión pendiente**, no una certificación de borrado total: se conservan 2.899 elementos del SID antiguo en zonas protegidas y hay incidencias de acceso/enlaces recogidas en el informe. Los borrados realizados son permanentes, sin reversión automática. Registro: `Limpieza-real-20260908-132422-d7731398.log`; manifiesto de la cuenta: el mismo nombre con sufijo `.cuenta.json`.

Un primer intento se detuvo antes de borrar datos por un resultado COM adicional en la preparación de la cuenta. El script se corrigió, se retiró exclusivamente su cuenta temporal deshabilitada y la ejecución posterior terminó con la verificación indicada arriba. No se debe volver a ejecutar la limpieza sobre la nueva promoción para intentar resolver los avisos protegidos: requieren revisión específica del informe y del SID antiguo.
