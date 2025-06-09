0. Setup
If using a venv set up a compatible python version
```
py -3.12 -m venv .venv
# activate venv depending on OS
pip install -r requirements.txt
# if you get the error "      ValueError: 'editdistance/bycython.pyx' doesn't match any files"
# then run: pip install git+https://github.com/aflc/editdistance.git@v0.6.2
```
If on windows set up strings locally using sysinternals (instructions below)


1. Firmware Pre-processing & TPC and Version Identification
Run 'STEP0_firmware_preprocessing.py' to extract firmware files, collect file metadata, and identify TPCs as well as their versions.

1. CVE Database Lookup
Run 'STEP1_vulnerability_searching.py' to collect all vulnerabilities associated with given TPCs of specific versions.

1. Target Function Locating
Run 'STEP2_function_locating.py' to normalize assembly instructions, generate fuzzy hash values for functions and crypto hash values for basic blocks contained in each function, and locate target functions in firmware-extracted stripped binaries.
Results are stored in 'output_function_locating/'.

1. Security Patch Detection
Run 'STEP3_patch_detection.py' to determine if each vulnerability exists or the security patch has been backported.
Results are stored in 'output_patch_detection/'.

All input arguments can be modified in 'util/config.py'. Step 1 requires firmware name and path. Steps 2 through 4 require vendor name, and all scripts take in corresponding csv file in 'util/fw_lib_list' as input.

All firmware-extracted target binaries and built reference binaries can be found in https://drive.google.com/file/d/1vQ5dv9CgVoh28GbZjrylH3WNVPzY_WHF/view?usp=sharing



# Windows strings setup
Add `strings.exe` to System PATH (Recommended)

To use Sysinternals `strings.exe` from any terminal on Windows, follow these steps:

### 1. Move `strings.exe` to a Permanent Location
Download [strings](https://learn.microsoft.com/en-us/sysinternals/downloads/strings). 
Create a tools directory (if you don't have one already) and move `strings.exe` there:

```
C:\Tools\Sysinternals\
```
---

### 2. Add the Directory to the System PATH

1. Press `Win + R`, type `sysdm.cpl`, and press **Enter**.
2. Go to the **Advanced** tab.
3. Click the **Environment Variables** button.
4. Under **System variables**, find and select the `Path` variable, then click **Edit**.
5. Click **New** and add the following:
   ```
   C:\Tools\Sysinternals\
   ```
6. Click **OK** to save all dialogs.

---

### 3. Test in a New Terminal

Open a new **Command Prompt** or **PowerShell** window and run:

```
strings.exe 
```
Accept the EULA. Next time you can run it without needing to click through. But it still prints our Sysinternals.

### 4. Silence sys internals
Make a subdirectory exe and put all the strings executables in there.
In `C:\Tools\Sysinternals\` make a `strings.cmd` file
Its contents should be 
```
@echo off
for /f "skip=4 delims=" %%A in ('"C:\Tools\Sysinternals\exe\strings.exe" %*') do echo %%A
```