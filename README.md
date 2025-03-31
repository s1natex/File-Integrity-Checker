# File-Integrity-Checker
Verify the integrity of application log files to detect tampering
# Project Page:
https://roadmap.sh/projects/file-integrity-checker
# How to use:
- Clone Repository
```
git clone https://github.com/s1natex/File-Integrity-Checker
```
- Ensure Python3 is installed
```
python3 --version
# Install if needed
```
- Grant permissions to run the script
```
chmod +x integrity-check
```
- Usage examples
```
# Initialize all hashes in <path> (folder or file .log)
./integrity-check init <path>

# Check a specific log file
./integrity-check check <path>

# Update a hash manually
./integrity-check update <path>
```
- Optional cron job scheduling
```
crontab -e

* * * * * </path/to/>integrity-check check <path> >> </home/yourusername>/integrity-check.log 2>&1
```
```
┌───────────── Minute (0 - 59)
│ ┌───────────── Hour (0 - 23)
│ │ ┌───────────── Day of Month (1 - 31)
│ │ │ ┌───────────── Month (1 - 12)
│ │ │ │ ┌───────────── Day of Week (0 - 6) (Sunday = 0 or 7)
│ │ │ │ │
│ │ │ │ │
* * * * * <command to run>
```