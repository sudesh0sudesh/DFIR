## PuTTY Activity Investigation Playbook

``Can be used for Puttylink(PLink) too``

**Custom.Windows.Registry.PuttySessions**
- Extracts SSH host keys from registry
- Path: `Software\SimonTatham\Putty\Sessions\**`
- Captures connection details and timestamps

**Custom.Windows.Registry.PuttySessions.Loglocations**
- Collects PuTTY logging information
- Path: `Software\SimonTatham\Putty\Sessions\*\LogFileName`
- Tracks session logs and modifications

**Custom.Windows.Registry.PuttySessions.HostNames**
- Maps connection history
- Path: `Software\SimonTatham\Putty\Sessions\*\HostName`
- Excludes default settings

**Custom.Windows.Registry.PuttyHostKeys**
- Extracts SSH host key fingerprints
- Path: `Software\SimonTatham\Putty\SshHostKeys\**`
- Supports IP and port-specific filtering
- Format: `ssh-ed12345@22:27.27.27.27`

## Investigation Matrix

| Artifact | Registry Path | Purpose |
|----------|--------------|----------|
| PuttySessions | Sessions\\** | Session details |
| Loglocations | Sessions\\*\\LogFileName | Activity logs |
| HostNames | Sessions\\*\HostName | Connection targets |
| PuttyHostKeys | SshHostKeys\\** | Host fingerprints |

## Investigation Workflow

**Evidence Collection**
1. Gather host keys from both Sessions and SshHostKeys
2. Extract logging configuration
3. Collect connection history
4. Map host fingerprints

**Analysis Steps**
1. Compare host keys across artifacts
2. Review session logs
3. Create connection timeline
4. Identify suspicious patterns

**Reporting**
1. Document all discovered sessions
2. Map connection patterns
3. Flag anomalous activity
4. Create timeline of events

**Velociraptor Artifacts for hunting the same**

1. Custom.Windows.Registry.PuttySessions.Loglocations.yml
2. Custom.Windows.Registry.PuttySessions.HostNames.yml
3. Custom.Windows.Registry.PuttySessions.yml
4. Windows.Registry.PuttyHostKeys.yml

https://research.splunk.com/endpoint/8aac5e1e-0fab-4437-af0b-c6e60af23eed/
