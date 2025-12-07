; ==============================================================================
; SFT (Secure File Transfer) - Windows Installer Script
; Inno Setup 6.x Configuration
; ==============================================================================
; This script creates a standalone Windows installer that includes:
; - Python 3.11 embedded runtime
; - Pre-compiled Rust crypto_accelerator module
; - All Python dependencies (cryptography, etc.)
; - CLI launchers and shortcuts
; ==============================================================================

#define MyAppName "SFT Secure File Transfer"
#define MyAppVersion "2.0.1"
#define MyAppPublisher "SFT Contributors"
#define MyAppURL "https://github.com/yourusername/SFT"
#define MyAppExeName "sft.bat"
#define PythonVersion "3.11.9"

[Setup]
; Application metadata
AppId={{8F9C3D2E-1A4B-4C5D-9E8F-7A6B5C4D3E2F}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppVerName={#MyAppName} {#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}
AppUpdatesURL={#MyAppURL}

; Installation directories
DefaultDirName={autopf}\SFT
DefaultGroupName={#MyAppName}
DisableProgramGroupPage=yes

; Installer output
OutputDir=..\installer\output
OutputBaseFilename=SFT-Setup-{#MyAppVersion}-win64
SetupIconFile=..\installer\assets\sft.ico
UninstallDisplayIcon={app}\sft.ico

; Compression and encryption
Compression=lzma2/ultra64
SolidCompression=yes
; Digital signature (optional, requires certificate)
;SignTool=signtool
;SignedUninstaller=yes

; License and documentation
LicenseFile=..\LICENSE
InfoBeforeFile=..\installer\docs\pre-install.txt
InfoAfterFile=..\installer\docs\post-install.txt
PrivilegesRequired=admin
PrivilegesRequiredOverridesAllowed=dialog

; Windows compatibility (Windows 8 to 11)
MinVersion=6.2
ArchitecturesAllowed=x64
ArchitecturesInstallIn64BitMode=x64

; Visual appearance
WizardStyle=modern
DisableWelcomePage=no
DisableReadyPage=no

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Types]
Name: "full"; Description: "Full installation"
Name: "compact"; Description: "Compact installation (CLI only)"
Name: "custom"; Description: "Custom installation"; Flags: iscustom

[Components]
Name: "core"; Description: "Core SFT application"; Types: full compact custom; Flags: fixed
Name: "python"; Description: "Python {#PythonVersion} Embedded Runtime"; Types: full compact custom; Flags: fixed
Name: "rustmodule"; Description: "Rust Crypto Accelerator Module"; Types: full compact custom; Flags: fixed
Name: "shortcuts"; Description: "Desktop and Start Menu shortcuts"; Types: full

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked
Name: "quicklaunchicon"; Description: "{cm:CreateQuickLaunchIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked; OnlyBelowVersion: 6.1; Check: not IsAdminInstallMode

[Files]
; ===== Python Embedded Runtime =====
; NOTE: Build script must download and extract python-{#PythonVersion}-embed-amd64.zip
; to installer/python-embedded/ before compilation
Source: "..\installer\python-embedded\*"; DestDir: "{app}\python"; Components: python; Flags: ignoreversion recursesubdirs createallsubdirs

; ===== Rust Crypto Module =====
; Pre-compiled .pyd file (built with maturin)
Source: "..\target\wheels\crypto_accelerator.cp311-win_amd64.pyd"; DestDir: "{app}\python\Lib\site-packages"; Components: rustmodule; Flags: ignoreversion

; ===== SFT Application Files =====
Source: "..\sft.py"; DestDir: "{app}"; Components: core; Flags: ignoreversion
Source: "..\python_wrapper.py"; DestDir: "{app}"; Components: core; Flags: ignoreversion
Source: "..\requirements.txt"; DestDir: "{app}"; Components: core; Flags: ignoreversion isreadme
Source: "..\README.md"; DestDir: "{app}"; Components: core; Flags: ignoreversion isreadme
Source: "..\system_requirements.txt"; DestDir: "{app}"; Components: core; Flags: ignoreversion

; ===== Pre-installed Python Dependencies =====
; Build script must pre-install cryptography and other deps to installer/site-packages/
Source: "..\installer\site-packages\*"; DestDir: "{app}\python\Lib\site-packages"; Components: core; Flags: ignoreversion recursesubdirs createallsubdirs

; ===== Launcher Scripts =====
Source: "..\installer\launchers\sft.bat"; DestDir: "{app}"; Components: core; Flags: ignoreversion
Source: "..\installer\launchers\sft-server.bat"; DestDir: "{app}"; Components: core; Flags: ignoreversion
Source: "..\installer\launchers\sft-client.bat"; DestDir: "{app}"; Components: core; Flags: ignoreversion

; ===== Assets =====
Source: "..\installer\assets\sft.ico"; DestDir: "{app}"; Components: core; Flags: ignoreversion

; ===== Visual C++ Redistributable Detection =====
; NOTE: VCRedist installation handled in [Run] section

[Icons]
Name: "{group}\SFT Server"; Filename: "{app}\sft-server.bat"; Components: shortcuts
Name: "{group}\SFT Client"; Filename: "{app}\sft-client.bat"; Components: shortcuts
Name: "{group}\SFT Documentation"; Filename: "{app}\README.md"; Components: shortcuts
Name: "{group}\{cm:UninstallProgram,{#MyAppName}}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\sft-client.bat"; Tasks: desktopicon
Name: "{userappdata}\Microsoft\Internet Explorer\Quick Launch\{#MyAppName}"; Filename: "{app}\sft-client.bat"; Tasks: quicklaunchicon

[Run]
; Install Visual C++ Redistributable if not present (required by Rust module)
Filename: "{tmp}\vc_redist.x64.exe"; Parameters: "/quiet /norestart"; StatusMsg: "Installing Visual C++ Redistributable..."; Flags: waituntilterminated; Check: VCRedistNeedsInstall

; Optional: Open README after installation
Filename: "{app}\README.md"; Description: "{cm:LaunchProgram,{#StringChange('README', '&', '&&')}}"; Flags: postinstall shellexec skipifsilent

[UninstallDelete]
Type: filesandordirs; Name: "{app}\python"
Type: filesandordirs; Name: "{app}\__pycache__"
Type: files; Name: "{app}\*.log"
Type: dirifempty; Name: "{app}"

[Code]
var
  VCRedistPage: TOutputProgressWizardPage;

// Check if Visual C++ Redistributable is already installed
function VCRedistNeedsInstall: Boolean;
var
  Version: String;
begin
  // Check registry for VC++ 2015-2022 Redistributable (x64)
  // HKLM\SOFTWARE\Microsoft\VisualStudio\14.0\VC\Runtimes\X64
  if RegQueryStringValue(HKEY_LOCAL_MACHINE,
    'SOFTWARE\Microsoft\VisualStudio\14.0\VC\Runtimes\X64',
    'Version', Version) then
  begin
    Result := False; // Already installed
    Log('VC++ Redistributable already installed: ' + Version);
  end
  else
  begin
    Result := True; // Not found, needs installation
    Log('VC++ Redistributable not found, will install');
  end;
end;

// Download VC++ Redistributable during installation
procedure InitializeWizard;
begin
  VCRedistPage := CreateOutputProgressPage('Installing Dependencies',
    'Please wait while Setup installs Microsoft Visual C++ Redistributable...');
end;

// Pre-download VC++ Redistributable before actual installation
function PrepareToInstall(var NeedsRestart: Boolean): String;
var
  hWnd: Integer;
  URL: String;
  ResultCode: Integer;
begin
  Result := '';

  if VCRedistNeedsInstall then
  begin
    VCRedistPage.SetText('Downloading Visual C++ Redistributable...', '');
    VCRedistPage.SetProgress(0, 100);
    VCRedistPage.Show;

    try
      // Download VC++ Redistributable (x64) from Microsoft
      URL := 'https://aka.ms/vs/17/release/vc_redist.x64.exe';

      // Use idpDownloadFile from Inno Download Plugin or fallback to manual download
      // For now, assume file is bundled or pre-downloaded
      Log('VC++ Redistributable will be installed from bundled file');

      VCRedistPage.SetProgress(100, 100);
    finally
      VCRedistPage.Hide;
    end;
  end;
end;

// Post-installation configuration
procedure CurStepChanged(CurStep: TSetupStep);
var
  PthFilePath: String;
  PthContent: TStringList;
begin
  if CurStep = ssPostInstall then
  begin
    // Configure Python embedded to recognize site-packages
    // Create or modify python311._pth to include Lib\site-packages
    PthFilePath := ExpandConstant('{app}\python\python311._pth');

    if FileExists(PthFilePath) then
    begin
      PthContent := TStringList.Create;
      try
        PthContent.LoadFromFile(PthFilePath);

        // Ensure these paths are present
        if PthContent.IndexOf('Lib\site-packages') = -1 then
          PthContent.Add('Lib\site-packages');
        if PthContent.IndexOf('..') = -1 then
          PthContent.Add('..');

        PthContent.SaveToFile(PthFilePath);
        Log('Updated python311._pth to include site-packages');
      finally
        PthContent.Free;
      end;
    end;
  end;
end;

// Uninstallation cleanup
procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  if CurUninstallStep = usPostUninstall then
  begin
    // Clean up any remaining files
    Log('Uninstallation complete');
  end;
end;
