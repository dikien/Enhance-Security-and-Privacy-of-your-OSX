# Hardening your OSX

Thank an author(https://github.com/kristovatlas/osx-config-check) I added some new feature which only checks required items and configuration based on CIS Apple_OSX 10.10 Benchmark. 

Checks your OSX machine against various hardened configuration settings.

You can specify your own preferred configuration baseline by supplying your own [Hjson](https://hjson.org/) file instead of the provided one.

## Disclaimer

The authors of this tool are not responsible if running it breaks stuff; disabling features of your operating system and applications may disrupt normal functionality.

Once applied, the security configurations do not not guarantee security. You will still need to make good decisions in order to stay secure. The configurations will generally not help you if your computer has been previously compromised.

Configurations come from sites like:
* [drduh's OS X Security and Privacy Guide](https://github.com/drduh/OS-X-Security-and-Privacy-Guide)
* [CIS Apple_OSX 10.10 Benchmark](https://benchmarks.cisecurity.org/tools2/osx/CIS_Apple_OSX_10.10_Benchmark_v1.0.0.pdf)

## Usage

**You should download and run this application once for each OS X user account you have on your machine.** Each user may be configured differently, and so each should be audited.

Download this app using Git, GitHub Desktop, or the "download as zip" option offered by GitHub. If you choose the zip option, unarchive the zip file after.

In the `Terminal` application, navigate to the directory that contains this app. You can use the `cd` command (see example below) to change directories. If you've downloaded the file to your "Downloads" directory, you might find the app here:

```bash
cd ~/Downloads/Enhance-Security-and-Privacy-of-your-OSX
```

Next run the app as follows:

```bash
python app.py
```

This will take you through a series of interactive steps that checks your machine's configuration, and offers to fix misconfigurations for you.

Intermediate users and advanced users can also invoke various command-line arguments:
```
Usage: python app.py [OPTIONS]
OPTIONS:
	--debug-print        Enables verbose output for debugging the tool.
	--report-only        Only reports on compliance and does not offer to fix broken configurations.
	--disable-logs       Refrain from creating a log file with the results.
	--disable-prompt     Refrain from prompting user before applying fixes.
	--skip-sudo-checks   Do not perform checks that require sudo privileges.
	--check-required     Check only required items.
	--help -h            Print this usage information.
```

## Sample Output

```bash
$ python app.py
------------------------------------------------------------------------------------------
Enhance-Security-and-Privacy-of-your-OSX v1.0.0 (jack)
Download the latest copy of this tool at: https://github.com/dikien/Enhance-Security-and-Privacy-of-your-OSX 
------------------------------------------------------------------------------------------


CHECK #1: The System Preferences application is currently closed.... PASSED!

CHECK #2: The OSX application firewall is enabled (system-wide).... PASSED!

CHECK #3: The OSX application firewall is enabled (current user only).... PASSED!

CHECK #4: A password is required to wake the computer from sleep or screen saver (system-wide).... PASSED!

CHECK #5: A password is required to wake the computer from sleep or screen saver (current user only).... PASSED!

CHECK #6: There is no delay between starting the screen saver and locking the machine (system-wide).... PASSED!

CHECK #7: There is no delay between starting the screen saver and locking the machine (current user only).... PASSED!

CHECK #8: Logging is enabled for the operating system.... PASSED!

CHECK #9: Homebrew analytics are disabled.... PASSED!

CHECK #10: Stealth mode is enabled for OSX: Computer does not respond to ICMP ping requests or connection attempts from a closed TCP/UDP port. (system-wide)... PASSED!

CHECK #11: Stealth mode is enabled for OSX: Computer does not respond to ICMP ping requests or connection attempts from a closed TCP/UDP port. (current user only)... PASSED!

CHECK #12: Automatic whitelisting of Apple-signed applications through the firewall is disabled (system-wide).... PASSED!

CHECK #13: Automatic whitelisting of Apple-signed applications through the firewall is disabled (current user only).... PASSED!

CHECK #14: OpenSSL is up to date.... PASSED!

CHECK #15: Hidden files are displayed in Finder.... PASSED!
The next configuration check requires elevated privileges; you may be prompted for your current OS X user's password  below. The command to be executed is: 'sudo softwareupdate --schedule | grep -i 'Automatic check is on''

CHECK #16: Automatic check for software updates is enabled.... PASSED!
The next configuration check requires elevated privileges; you may be prompted for your current OS X user's password  below. The command to be executed is: 'sudo defaults read /Library/Preferences/com.apple.SoftwareUpdate AutomaticCheckEnabled'

CHECK #17: Enable Auto Update.... PASSED!

CHECK #18: GateKeeper protection against untrusted applications is enabled.... PASSED!

CHECK #19: Bluetooth is disabled.... FAILED!
	Apply the following RECOMMENDED  fix? This will execute  this command:
		'sudo defaults write /Library/Preferences/com.apple.Bluetooth ControllerPowerState -bool false; sudo killall -HUP blued' [Y/n] n

CHECK #20: The infrared receiver is disabled.... PASSED!

CHECK #21: AirDrop file sharing is disabled.... FAILED!
	Apply the following RECOMMENDED  fix? This will execute  this command:
		'sudo defaults write /Library/Preferences/com.apple.NetworkBrowser DisableAirDrop -bool true' [Y/n] n

CHECK #22: File sharing is disabled.... PASSED!

CHECK #23: Printer sharing is disabled.... PASSED!
The next configuration check requires elevated privileges; you may be prompted for your current OS X user's password  below. The command to be executed is: 'sudo systemsetup -getremotelogin'

CHECK #24: Remote login is disabled.... PASSED!

CHECK #25: Remote Management is disabled.... PASSED!
The next configuration check requires elevated privileges; you may be prompted for your current OS X user's password  below. The command to be executed is: 'sudo systemsetup -getremoteappleevents'

CHECK #26: Remote Apple events are disabled.... PASSED!

CHECK #27: Internet Sharing is disabled on all network interfaces.... PASSED!
The next configuration check requires elevated privileges; you may be prompted for your current OS X user's password  below. The command to be executed is: 'sudo systemsetup getwakeonnetworkaccess'

CHECK #28: Wake on Network Access feature is disabled.... PASSED!

CHECK #29: IPv6 is disabled on all network interfaces.... PASSED!

CHECK #30: An administrator password is required to change system-wide preferences.... PASSED!

CHECK #31: Documents are not stored to iCloud Drive by default. (May be mistaken if iCloud is disabled)... PASSED!

CHECK #32: The File Vault key is protected when going to standby mode.... FAILED!
	Apply the following RECOMMENDED  fix? This will execute  this command:
		'sudo pmset -a destroyfvkeyonstandby 1 ; sudo pmset -a hibernatemode 25 ; sudo pmset -a powernap 0 ; sudo pmset -a standby 0 ; sudo pmset -a standbydelay 0; sudo pmset -a autopoweroff 0' [Y/n] n

CHECK #33: git is up to date or is not installed... PASSED!

CHECK #34: The curl utility is up to date or absent from the system.... PASSED!

CHECK #35: FileVault file system encryption is enabled.... PASSED!

CHECK #36: The idle timer for screen saver activation is set to 10 minutes or less.... PASSED!

CHECK #37: System Integrity Protection (SIP) is enabled.... PASSED!
The next configuration check requires elevated privileges; you may be prompted for your current OS X user's password  below. The command to be executed is: 'sudo systemsetup -getnetworktimeserver'

CHECK #38: Enable Set time and date automatically... PASSED!

CHECK #39: Disable 'Wake for network access'... FAILED!
	Apply the following  fix? This will execute  this command:
		'sudo pmset -a womp 0' [Y/n] n

CHECK #40: Enable Secure Keyboard Entry in terminal.app... PASSED!

CHECK #41: Configure secure Empty Trash... PASSED!

CHECK #42: Retain system.log for 365 or more days... PASSED!

CHECK #43: Retain appfirewall.log for 365 or more days... PASSED!

CHECK #44: Retain authd.log for 365 or more days... PASSED!
The next configuration check requires elevated privileges; you may be prompted for your current OS X user's password  below. The command to be executed is: 'sudo egrep "^flags:" /etc/security/audit_control'

CHECK #45: Configure Security Auditing Flags... PASSED!

CHECK #46: Retain install.log for 365 or more days... PASSED!

CHECK #47: Ensure http server is not running... PASSED!
The next configuration check requires elevated privileges; you may be prompted for your current OS X user's password  below. The command to be executed is: 'sudo launchctl list | grep ftp | wc -l'

CHECK #48: Ensure ftp server is not running... PASSED!

CHECK #49: Ensure nfs server is not running... PASSED!

CHECK #50: Disable automatic login... PASSED!

CHECK #51: Require an administrator password to access system-wide preferenes... PASSED!

CHECK #52: Disable ability to login to another user's active and locked session... PASSED!

CHECK #53: Complex passwords must contain an Alphabetic Character... PASSED!

CHECK #54: Complex passwords must contain an Numeric Character... PASSED!

CHECK #55: Complex passwords must contain an Symbolic Character... PASSED!

CHECK #56: Set a minimum password length... PASSED!

CHECK #57: Configure account lockout threshold... PASSED!

CHECK #58: Display login window as name and password... PASSED!

CHECK #59: Disable 'Show password hints'... PASSED!

CHECK #60: Disable guest account login... PASSED!

CHECK #61: Disable 'Allow guests to connect to shared folders'(AFP)... PASSED!

CHECK #62: Disable 'Allow guests to connect to shared folders'(SMB)... PASSED!

CHECK #63: Turn on filename extensions... PASSED!
The next configuration check requires elevated privileges; you may be prompted for your current OS X user's password  below. The command to be executed is: 'sudo find /System -type d -perm -2 -ls | grep -v "Public/Drop Box"'

CHECK #64: Check System folder for world writable files... PASSED!
The next configuration check requires elevated privileges; you may be prompted for your current OS X user's password  below. The command to be executed is: 'sudo find /Library -type d -perm -2 -ls | grep -v Caches'

CHECK #65: Check Library folder for world writable files... FAILED!

CHECK #66: Check Anti Virus is running... PASSED!

CHECK #67: Check OpenDNS is running... PASSED!

CHECK #68: Check osquery is running... PASSED!

CHECK #69: Check logstash is running... PASSED!
The next configuration check requires elevated privileges; you may be prompted for your current OS X user's password  below. The command to be executed is: 'sudo cat /etc/sudoers | grep timestamp=0 | wc -l'

CHECK #70: Reduce the sudo timeout period... FAILED!

CHECK #71: The Safari application is currently closed.... PASSED!

CHECK #72: Safari will not auto-fill credit card data.... PASSED!

CHECK #73: Safari will not auto-fill your contact data.... PASSED!

CHECK #74: Safari will not auto-fill miscellaneous forms.... PASSED!

CHECK #75: Safari will not auto-fill usernames or passwords.... PASSED!

CHECK #76: Files downloaded in Safari are not automatically opened.... PASSED!

CHECK #77: Cookies and local storage are always blocked in Safari.... FAILED!
	Apply the following RECOMMENDED  fix? This will execute  this command:
		'defaults -currentHost write ~/Library/Preferences/com.apple.Safari BlockStoragePolicy -bool false' [Y/n] n

CHECK #78: Safari extensions are disabled.... PASSED!

CHECK #79: The Safari web browser will warn when visiting known fraudulent websites.... PASSED!

CHECK #80: JavaScript is disabled in the Safari web browser.... FAILED!
	Apply the following RECOMMENDED  fix? This will execute  this command:
		'defaults -currentHost write ~/Library/Preferences/com.apple.Safari com.apple.Safari.ContentPageGroupIdentifier.WebKit2JavaScriptEnabled -bool false' [Y/n] n

CHECK #81: Pop-up windows are blocked in the Safari web browser.... PASSED!

CHECK #82: The WebGL plug-in is disabled in the Safari web browser.... PASSED!

CHECK #83: Plug-ins are disabled in the Safari web browser.... PASSED!

CHECK #84: Plug-ins are blocked by default in the Safari web browser unless a site is explicitly added to a list of allowed sites.... PASSED!

CHECK #85: The Java plug-in for Safari web browser is blocked unless a site is explicitly added to a list of allowed sites.... PASSED!

CHECK #86: The Java plug-in is disabled in the Safari web browser.... PASSED!

CHECK #87: The Safari web browser is configured to treat SHA-1 certificates as insecure.... PASSED!

CHECK #88: The Safari web browser will not pre-load webpages that rank highly as search matches.... PASSED!

CHECK #89: The Safari web browser will not include search engine suggestions for text typed in the location bar.... PASSED!

CHECK #90: The Safari web browser's search suggestions are disabled.... PASSED!

CHECK #91: The Safari web browser uses the Do-Not-Track HTTP header.... PASSED!

CHECK #92: PDF viewing is disabled in the Safari web browser.... PASSED!

CHECK #93: Full website addresses are displayed in the location bar of the Safari web browser.... PASSED!

CHECK #94: Files downloaded in Safari are not automatically opened.... PASSED!

CHECK #95: The Mail application is currently closed.... PASSED!

CHECK #96: Apple Mail does not automatically load remote content in e-mails.... PASSED!

CHECK #97: Mail identified by Apple Mail as junk is sent to the Junk mailbox.... PASSED!

CHECK #98: GPGMail is in use.... PASSED!

CHECK #99: New e-mails composed in Apple Mail are encrypted by GPGMail if the receiver's PGP is present in the keychain.... FAILED!
	Apply the following RECOMMENDED  fix? This will execute  this command:
		'defaults write ~/Library/Preferences/org.gpgtools.gpgmail.plist EncryptNewEmailsByDefault -bool true' [Y/n] n

CHECK #100: New e-mails composed in Apple Mail and saved as drafts are encrypted by GPGMail.... PASSED!

CHECK #101: New e-mails composed in Apple Mail are signed by GPGMail.... PASSED!

CHECK #102: Apple Mail automatically checks for updates to GPGMail.... PASSED!

CHECK #103: The Google Chrome browser is currently closed.... FAILED!
	Apply the following  fix? This will execute  this command:
		'killall "Google Chrome" ; sleep 3' [Y/n] n

CHECK #104: All Google Chrome web browser profiles prevent information leakage through navigation errors.... PASSED!

CHECK #105: All Google Chrome web browser profiles prevent information leakage by blocking security incidents reports to Google.... PASSED!

CHECK #106: All Google Chrome web browser profiles have Google Safe Browsing enabled.... PASSED!

CHECK #107: All Google Chrome web browser profiles prevent information leakage through spell-checking network services.... PASSED!

CHECK #108: All Google Chrome web browser profiles prevent information leakage through reporting usage statistics to Google.... PASSED!

CHECK #109: All Google Chrome web browser profiles use the Do-Not-Track HTTP header.... PASSED!

CHECK #110: All Google Chrome web browser profiles block unsandboxed plug-in software.... PASSED!

CHECK #111: All Google Chrome web browser profiles prevent filling personal information into forms automatically.... PASSED!

CHECK #112: All Google Chrome web browser profiles prevent filling personal information into forms automatically.... PASSED!

CHECK #113: All Google Chrome web browser profiles have disabled automatic sign-in for stored passwords.... PASSED!

CHECK #114: All Google Chrome web browser profiles have disabled Google CloudPrint.... PASSED!

CHECK #115: All Google Chrome web browser profiles block Flash cookies.... PASSED!

CHECK #116: All Google Chrome web browser profiles have disabled the Chrome Pepper Flash Player plug-in.... PASSED!

CHECK #117: All Google Chrome web browser profiles have disabled the Adobe Shockwave Flash plug-in.... PASSED!

CHECK #118: All Google Chrome web browser profiles have disabled the Adobe Flash Player plug-in.... PASSED!

CHECK #119: Google Chrome is the default web browser.... PASSED!

CHECK #120: OSX/Keydnap malware is not present.... PASSED!
Wrote results to '~/Documents/Enhance-Security-and-Privacy-of-your-OSX_2016-11-22_08-07-42.log'.
==========================
2 tests could not be automatically fixed, but manual instructions are available. Please manually remediate these problems and re-run the tool:
TEST #65: Check Library folder for world writable files
sudo chmod -R o-w /Bad/Directory
==========================
TEST #70: Reduce the sudo timeout period
Run the following command in Terminal : sudo visudo
Add the line : Defaults timestamp_timeout=0
```

## Troubleshooting

### Errors related to "sudo" or "sudoers"

If you receive an error message referencing these terms, the user you are currently logged in as may not be permitted to temporarily assume elevated privileges, preventing this tool from fully auditing and/or fixing your user's configuration. If you have added a non-Administrator user to your machine to help secure it, you will find that your non-Administrator user is not part of the "sudoers" list by default. To learn about how to add your user to the "sudoers" list, please [refer to this link](http://osxdaily.com/2014/02/06/add-user-sudoers-file-mac/).

And follow the instructions on the screen carefully.