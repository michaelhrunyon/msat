# PyInstaller spec for MSAT (macOS .app bundle).
# Build on the Mac with:  ./build_app.sh
# Produces dist/MSAT.app — a one-folder, windowed (no console) app.

block_cipher = None

a = Analysis(
    ['src/main.py'],
    pathex=['src'],
    binaries=[],
    datas=[],
    hiddenimports=[
        'winrm',
        'winrm.protocol',
        'ldap3',
        'ldap3.core',
        'requests_ntlm',
        'xmltodict',
    ],
    hookspath=[],
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)
pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name='MSAT',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=False,  # windowed app — no terminal window
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name='MSAT',
)
app = BUNDLE(
    coll,
    name='MSAT.app',
    icon='msat.icns',
    bundle_identifier='com.runyon.msat',
    info_plist={
        'CFBundleName': 'MSAT',
        'CFBundleDisplayName': 'MSAT — macOS Server Administration Tools',
        'CFBundleShortVersionString': '1.8.2',
        'NSHighResolutionCapable': 'True',
    },
)
