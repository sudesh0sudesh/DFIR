

# Aftermath – Usage Instructions (Direct Binary Execution)

## About
**Aftermath** is a Swift-based, open-source incident response framework for macOS. It enables defenders to collect and analyse data from a potentially compromised Mac. While it’s ideally deployed via MDM, it can also be run directly as a compiled binary.

---

## 1. Prerequisites

- Run **as root** (`sudo`).
- The Terminal (or app running Aftermath) must have **Full Disk Access** (FDA) enabled in System Settings > Privacy & Security.

---

## 2. Download & Prepare the Binary

- Download the latest binary from this folder (Compiled from official Aftermath git and signed using certificate)
- Transfer the binary to the target Mac (e.g., using scp, AirDrop, or USB).
- Make it executable:
  ```sh
  chmod +x /path/to/aftermath
  ```

---

## 3. Run Aftermath

**Basic usage:**
```sh
sudo /path/to/aftermath
```

**Specify output location:**
```sh
sudo /path/to/aftermath -o /path/to/output_directory
```

**Deep scan (thorough, time and memory intensive):**
```sh
sudo /path/to/aftermath -o /path/to/output_directory --deep
```

**Analyse a collected archive:**
```sh
sudo /path/to/aftermath --analyze /path/to/aftermath_collection.zip
```

**Use a custom unified log predicates file:**
```sh
sudo /path/to/aftermath --logs /path/to/predicates.txt
```

**Show help:**
```sh
/path/to/aftermath --help
```

---

## 4. Output

- By default, results are saved to `/tmp` unless `-o` or `--output` is specified.
- Results are archived as a zip file.
- Transfer the archive as needed for analysis.

---

## 5. Notable Options

- `--deep` or `-d`: Deep file system scan (slower, more resource-intensive).
- `-o` or `--output <dir>`: Set output directory.
- `--analyze <archive.zip>`: Analyse a collected archive.
- `--logs <predicates.txt>`: Use custom unified log predicates.
- `--disable <feature>`: Disable specific data collection modules (e.g., browsers, filesystem).
- `--cleanup`: Remove Aftermath folders from default locations (`/tmp`, `/var/folders/zz/`).

---

## 6. Artifact Collection List

Aftermath collects (examples):
- Configuration Profiles
- Log Files
- Shell History and Profiles
- System and Browser Data (Cookies, Downloads, Extensions, History)
- Slack data
- Active network connections
- Persistence mechanisms (Launch Agents, Daemons, Login Items, etc.)
- Process tree (leveraging [TrueTree](https://github.com/themittenmac/TrueTree))
- Installed Applications and Users
- Security settings (SIP, Gatekeeper, Firewall, FileVault status, etc.)
- Default and custom Unified Logs

**Note:** Aftermath does **not** collect memory images.

---

## 7. Example Commands

```sh
# Basic Collection
sudo /path/to/aftermath

# With output to Desktop and deep scan
sudo /path/to/aftermath -o ~/Desktop/aftermath_results --deep

# Analyze a zip archive
sudo /path/to/aftermath --analyze ~/Desktop/aftermath_results.zip
```

---

For more details and the latest options, see the [official documentation](https://github.com/jamf/aftermath) or run:
```sh
/path/to/aftermath --help
```
