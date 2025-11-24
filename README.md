# 🛡️ WinSec Defender

**Herramienta Híbrida de Detección y Sanitización de Vulnerabilidades para Windows Server.**

Combina la potencia de Python, la profundidad de PowerShell y el acceso a bajo nivel de C# para auditar servidores Windows (2012+), detectando fallas críticas como SMBv1, Unquoted Service Paths y configuraciones débiles de UAC.

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)

## 🚀 Instalación

1.  **Clonar repositorio:**
    ```bash
    git clone [https://github.com/TU_USUARIO/WinSec-Defender.git](https://github.com/TU_USUARIO/WinSec-Defender.git)
    cd WinSec-Defender
    ```
2.  **Instalar requisitos:**
    ```bash
    pip install -r requirements.txt
    ```
3.  **Compilar Módulo C#:**
    Necesitas compilar el inspector de registro para que funcione la detección de UAC.
    ```cmd
    cd src/core
    C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe /out:..\..\bin\RegistryInspector.exe RegistryInspector.cs
    cd ..\..
    ```
    *Verifica que `RegistryInspector.exe` aparezca en la carpeta `bin/`.*

## ▶️ Ejecución

1.  Abrir terminal como **Administrador**.
2.  Iniciar el servidor web:
    ```bash
    python src/web/server.py
    ```
3.  Abrir navegador en: `http://127.0.0.1:8000`

## ⚠️ Disclaimer
Herramienta creada con fines educativos y de Blue Teaming. Revisar siempre los scripts de sanitización antes de ejecutarlos en producción.

## 📄 Licencia
MIT License.
