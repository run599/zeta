#define AppId "{{a7d7bac3-93b8-4630-8308-c7a56bf7fdf4}}"
#define AppName "ZETA"
#define AppVersion "3.8.0.0"
#define AppPublisher "runqp"
#define AppURL "https://github.com/87owo/ZETA"
#define AppExeName "ZETA.exe"

[Setup]
AppId={#AppId}
AppName={#AppName}
AppVersion={#AppVersion}
AppVerName={#AppName} {#AppVersion}
AppPublisher={#AppPublisher}
AppPublisherURL={#AppURL}
AppSupportURL={#AppURL}
AppUpdatesURL={#AppURL}
VersionInfoVersion={#AppVersion}
VersionInfoCompany={#AppPublisher}
VersionInfoDescription={#AppName} Setup
VersionInfoProductName={#AppName} Setup
VersionInfoProductVersion={#AppVersion}
DefaultDirName={autopf}\{#AppName}
DefaultGroupName={#AppPublisher}\{#AppName}
AllowNoIcons=yes
LicenseFile=SetupResources\licence.rtf
ShowLanguageDialog=yes
WizardStyle=modern
WizardImageFile=SetupResources\wizardImage.bmp
WizardSmallImageFile=SetupResources\headerImage.png
UninstallDisplayIcon={app}\{#AppExeName}
PrivilegesRequired=admin
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0
Compression=lzma2/max
SolidCompression=yes
OutputDir=Output
OutputBaseFilename=ZETA_3.8_Setup
UsePreviousTasks=no

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"
Name: "chinesesimplified"; MessagesFile: "SetupResources\ChineseSimplified.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"
Name: "autostart"; Description: "{cm:AutoStartTask}"; GroupDescription: "{cm:AdditionalIcons}"
Name: "install_vcredist"; Description: "{cm:InstallVCRedist}"; GroupDescription: "{cm:Dependencies}"

[Files]
Source: "Payload\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "Redist\VC_redist.x64.exe"; DestDir: "{tmp}\ZETA_Redist"; Flags: deleteafterinstall ignoreversion

[Registry]
Root: HKCU; Subkey: "Software\Classes\*\shell\ZETA_Scan"; Flags: uninsdeletekey dontcreatekey
Root: HKCU; Subkey: "Software\Classes\Directory\shell\ZETA_Scan"; Flags: uninsdeletekey dontcreatekey

[UninstallDelete]
Type: filesandordirs; Name: "{commonappdata}\ZETA"

[Icons]
Name: "{autodesktop}\{#AppName}"; Filename: "{app}\{#AppExeName}"; Tasks: desktopicon
Name: "{group}\{#AppName}"; Filename: "{app}\{#AppExeName}"
Name: "{group}\Uninstall {#AppName}"; Filename: "{uninstallexe}"

[Run]
Filename: "{tmp}\ZETA_Redist\VC_redist.x64.exe"; Parameters: "/quiet /norestart"; Flags: waituntilterminated runhidden; StatusMsg: "{cm:InstallingVCRuntime}"; Tasks: install_vcredist
Filename: "{app}\{#AppExeName}"; Description: "{cm:LaunchProgram,{#StringChange(AppName, '&', '&&')}}"; Flags: nowait postinstall skipifsilent runascurrentuser

[CustomMessages]
english.InstallingVCRuntime=Installing Microsoft Visual C++ Runtime...
chinesesimplified.InstallingVCRuntime=正在安装 Microsoft Visual C++ 运行库...
english.AutoStartTask=Run ZETA automatically at system startup
chinesesimplified.AutoStartTask=开机时自动运行 ZETA
english.Dependencies=Dependencies:
chinesesimplified.Dependencies=运行环境:
english.InstallVCRedist=Install Microsoft Visual C++ Runtime
chinesesimplified.InstallVCRedist=安装 Microsoft Visual C++ 运行库
english.LegacyVersionDetected=An older version of ZETA was detected. Please uninstall it manually before installing.
chinesesimplified.LegacyVersionDetected=检测到存在旧版 ZETA。请先手动卸载旧版后，再运行本安装程序。

[Code]
var
  TasksInitialized: Boolean;

function IsVCRedistInstalled: Boolean;
var
  Bld: Cardinal;
begin
  Result := False;
  if RegQueryDWordValue(HKLM, 'SOFTWARE\Microsoft\VisualStudio\14.0\VC\Runtimes\x64', 'Bld', Bld) then
    if Bld > 0 then Result := True;
end;

procedure CurPageChanged(CurPageID: Integer);
var
  I: Integer;
  ItemText: string;
begin
  if (CurPageID = wpSelectTasks) and not TasksInitialized then
  begin
    TasksInitialized := True;
    for I := 0 to WizardForm.TasksList.Items.Count - 1 do
    begin
      ItemText := WizardForm.TasksList.Items[I];
      if Pos('Visual C++', ItemText) > 0 then
        WizardForm.TasksList.Checked[I] := not IsVCRedistInstalled;
    end;
  end;
end;

procedure QuitOldInstance(InstallPath: string);
var
  ResultCode: Integer;
  ExePath: string;
begin
  ExePath := InstallPath + '\{#AppExeName}';
  if FileExists(ExePath) then
  begin
    Exec(ExePath, '-quit', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
    Sleep(500);
    Exec(ExpandConstant('{sys}\taskkill.exe'), '/F /IM {#AppExeName} /T', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  end;
end;

function InitializeSetup(): Boolean;
var
  OldInstallPath: string;
  LegacyPath: string;
begin
  LegacyPath := ExpandConstant('{pf32}\{#AppName}');
  if DirExists(LegacyPath) and FileExists(LegacyPath + '\{#AppExeName}') then
  begin
    MsgBox(CustomMessage('LegacyVersionDetected'), mbCriticalError, MB_OK);
    Result := False;
    Exit;
  end;
  if RegQueryStringValue(HKLM, 'Software\Microsoft\Windows\CurrentVersion\Uninstall\' + ExpandConstant('{#AppId}') + '_is1', 'InstallLocation', OldInstallPath) or
     RegQueryStringValue(HKCU, 'Software\Microsoft\Windows\CurrentVersion\Uninstall\' + ExpandConstant('{#AppId}') + '_is1', 'InstallLocation', OldInstallPath) then
  begin
    QuitOldInstance(OldInstallPath);
  end;

  Result := True;
end;

function InitializeUninstall(): Boolean;
begin
  QuitOldInstance(ExpandConstant('{app}'));
  Result := True;
end;

procedure TryCreateStartupTask;
var
  ResultCode: Integer;
  PSExe: string;
  PSCommand: string;
  AppPath: string;
begin
  AppPath := ExpandConstant('{app}\{#AppExeName}');
  PSExe := ExpandConstant('{sys}\WindowsPowerShell\v1.0\powershell.exe');
  PSCommand := '-NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -Command ' +
               '$Action = New-ScheduledTaskAction -Execute ''' + AppPath + ''' -Argument ''-hide''; ' +
               '$Trigger = New-ScheduledTaskTrigger -AtLogOn; ' +
               '$Settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries; ' +
               'Register-ScheduledTask -TaskName ''ZETA_Security_ATS'' -Action $Action -Trigger $Trigger -Settings $Settings -RunLevel Highest -Force';
  if not Exec(PSExe, PSCommand, '', SW_HIDE, ewWaitUntilTerminated, ResultCode) then
  begin
    Log(Format('Failed to create scheduled task, Exec error code: %d', [ResultCode]));
  end
  else if ResultCode <> 0 then
  begin
    Log(Format('powershell returned exit code %d while creating the scheduled task', [ResultCode]));
  end;
end;

procedure TryDeleteStartupTask;
var
  ResultCode: Integer;
begin
  if not Exec(ExpandConstant('{sys}\schtasks.exe'), '/Delete /TN "ZETA_Security_ATS" /F', '', SW_HIDE, ewWaitUntilTerminated, ResultCode) then
  begin
    Log(Format('Failed to delete scheduled task, Exec error code: %d', [ResultCode]));
  end
  else if ResultCode <> 0 then
  begin
    Log(Format('schtasks returned exit code %d while deleting the scheduled task', [ResultCode]));
  end;
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if CurStep = ssPostInstall then
  begin
    if WizardIsTaskSelected('autostart') then
    begin
      TryCreateStartupTask;
    end;
  end;
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  if CurUninstallStep = usUninstall then
  begin
    TryDeleteStartupTask;
  end
  else if CurUninstallStep = usPostUninstall then
  begin
    DelTree(ExpandConstant('{app}'), True, True, True);
  end;
end;
end.
