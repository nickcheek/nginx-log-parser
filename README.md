# Nginx Access Log Parser

A powerful CLI tool for analyzing Nginx access logs with advanced filtering, grouping, and analysis capabilities. Supports both local files and remote log parsing via SSH.

## Installation

```bash
# Clone and build
git clone https://github.com/nickcheek/nginx-log-parser.git
cd nginx-access-log-parser
go build accesslog.go

# Make executable (optional)
chmod +x accesslog
```

## Basic Usage

```bash
# Parse local log file
./accesslog /var/log/nginx/access.log

# Parse remote log via SSH
./accesslog production-server

# Parse with filters
./accesslog stage-web --errors-only --compact
```

**Note:** Flags can be placed before or after the target:

```bash
./accesslog --compact stage-web --errors-only
./accesslog stage-web --compact --errors-only
```

## Quick Examples

```bash
# Find all 404 errors in compact format
./accesslog stage-web --status="404" --compact

# Analyze API performance
./accesslog stage-web --path="/api/*" --slow-only --report

# Monitor specific user activity
./accesslog stage-web --user="12865" --since="2025-06-18"

# Group errors by URL to find broken endpoints
./accesslog stage-web --errors-only --group-by="uri" --stats

# Real-time monitoring
./accesslog /var/log/nginx/access.log --follow --errors-only

# Export data for further analysis
./accesslog stage-web --since="2025-06-01" --export="csv"
```

## Command Line Options

### Basic Operations

| Option      | Description                                  | Example      |
| ----------- | -------------------------------------------- | ------------ |
| `--compact` | Compact single-line output format            | `--compact`  |
| `--json`    | Output in JSON format                        | `--json`     |
| `--summary` | Show summary statistics                      | `--summary`  |
| `--stats`   | Show detailed statistics                     | `--stats`    |
| `--report`  | Generate comprehensive analysis report       | `--report`   |
| `--follow`  | Follow log file for new entries (local only) | `--follow`   |
| `--last N`  | Show only last N entries                     | `--last=100` |

### Filtering Options

| Option               | Description                             | Example                                     |
| -------------------- | --------------------------------------- | ------------------------------------------- |
| `--status CODE`      | Filter by HTTP status code              | `--status="404"`, `--status="5xx"`          |
| `--method METHOD`    | Filter by HTTP method                   | `--method="POST"`                           |
| `--ip ADDRESS`       | Filter by IP address or CIDR            | `--ip="192.168.1.100"`, `--ip="10.0.0.0/8"` |
| `--user ID`          | Filter by user ID                       | `--user="12865"`                            |
| `--path PATTERN`     | Filter by URL path (supports wildcards) | `--path="/api/*"`, `--path="*.js"`          |
| `--search TEXT`      | Search for text in URIs                 | `--search="login"`                          |
| `--errors-only`      | Show only 4xx and 5xx responses         | `--errors-only`                             |
| `--slow-only`        | Show only slow requests (>1s)           | `--slow-only`                               |
| `--exclude-bots`     | Filter out bot/crawler traffic          | `--exclude-bots`                            |
| `--min-time SECONDS` | Minimum request time                    | `--min-time=2.0`                            |
| `--max-time SECONDS` | Maximum request time                    | `--max-time=10.0`                           |
| `--min-bytes BYTES`  | Minimum response size                   | `--min-bytes=1000`                          |

### Date/Time Filtering

| Option         | Description          | Example                                              |
| -------------- | -------------------- | ---------------------------------------------------- |
| `--since DATE` | Show logs since date | `--since="2025-06-18"`, `--since="2025-06-18 10:30"` |
| `--until DATE` | Show logs until date | `--until="2025-06-18"`                               |

### Grouping and Analysis

| Option             | Description                     | Example               |
| ------------------ | ------------------------------- | --------------------- |
| `--group-by FIELD` | Group results by field          | `--group-by="status"` |
| `--top N`          | Show top N results in summaries | `--top=20`            |

**Group-by options:** `status`, `method`, `uri`, `ip`, `hour`, `user`

### Export Options

| Option            | Description             | Example                             |
| ----------------- | ----------------------- | ----------------------------------- |
| `--export FORMAT` | Export filtered results | `--export="csv"`, `--export="json"` |

### SSH/Remote Options

| Option               | Description          | Example                                     |
| -------------------- | -------------------- | ------------------------------------------- |
| `--remote-path PATH` | Remote log file path | `--remote-path="/var/log/nginx/access.log"` |
| `--ssh-config PATH`  | SSH config file path | `--ssh-config="~/.ssh/config"`              |

### Display Options

| Option           | Description            | Example          |
| ---------------- | ---------------------- | ---------------- |
| `--no-color`     | Disable colored output | `--no-color`     |
| `--debug`        | Enable debug output    | `--debug`        |
| `--show-samples` | Show sample log lines  | `--show-samples` |

## Analysis Modes

### Summary Mode

```bash
./accesslog stage-web --summary
```

Shows basic statistics: request counts, status code breakdown, top IPs.

### Stats Mode

```bash
./accesslog stage-web --stats
```

Includes detailed breakdowns: top endpoints, error pages, referers.

### Report Mode

```bash
./accesslog stage-web --report
```

Comprehensive analysis with insights, traffic patterns, and recommendations.

### Grouping

```bash
# Group by status code to see error distribution
./accesslog stage-web --group-by="status"

# Group by hour to see traffic patterns
./accesslog stage-web --group-by="hour"

# Group by user to see most active users
./accesslog stage-web --group-by="user" --top=20
```

## Common Use Cases

### Security Analysis

```bash
# Find potential attacks
./accesslog stage-web --status="4xx" --group-by="ip" --stats

# Monitor failed login attempts
./accesslog stage-web --path="/login" --status="4xx" --compact

# Check for unusual user agent patterns
./accesslog stage-web --exclude-bots --group-by="ua" --stats
```

### Performance Monitoring

```bash
# Find slowest endpoints
./accesslog stage-web --slow-only --group-by="uri" --stats

# Monitor API performance
./accesslog stage-web --path="/api/*" --min-time=1.0 --report

# Check bandwidth usage
./accesslog stage-web --min-bytes=1000000 --group-by="uri"
```

### User Activity Analysis

```bash
# Track specific user activity
./accesslog stage-web --user="12865" --since="2025-06-18"

# Find most active users
./accesslog stage-web --group-by="user" --top=20

# Analyze user behavior patterns
./accesslog stage-web --group-by="hour" --user="12865"
```

### Error Investigation

```bash
# Find all 5xx errors
./accesslog stage-web --status="5xx" --compact

# Group 404s by URL to find broken links
./accesslog stage-web --status="404" --group-by="uri" --stats

# Check error patterns by time
./accesslog stage-web --errors-only --group-by="hour"
```

### Real-time Monitoring

```bash
# Monitor errors in real-time
./accesslog /var/log/nginx/access.log --follow --errors-only --compact

# Watch API traffic
./accesslog /var/log/nginx/access.log --follow --path="/api/*"

# Monitor specific user activity
./accesslog /var/log/nginx/access.log --follow --user="12865"
```

## SSH Remote Access

The tool can parse logs from remote servers via SSH:

1. **Setup SSH config** (`~/.ssh/config`):

```
Host production
    HostName prod.example.com
    User ubuntu
    IdentityFile ~/.ssh/prod-key.pem

Host stage-web
    HostName stage.example.com
    User ec2-user
```

2. **Use SSH hostname**:

```bash
./accesslog production --errors-only
./accesslog stage-web --summary
```

The tool will automatically SSH to the server and parse the log file.

## Log Format Support

Supports multiple nginx log formats:

- **Standard Combined Format**
- **Custom formats with extra fields**
- **AWS ELB health checker logs**
- **Formats with timing data**

Example supported formats:

```
# Standard combined
192.168.1.1 - - [18/Jun/2025:07:26:41 -0400] "GET / HTTP/1.1" 200 1234 "ref" "agent"

# Custom with user ID
192.168.1.1 - [18/Jun/2025:07:26:41 -0400] "GET / HTTP/1.1" 200 1234 "ref" "agent" "12865"

# Health checker
- - [18/Jun/2025:07:26:41 -0400] "GET / HTTP/1.1" 200 1234 "-" "ELB-HealthChecker/2.0" "-"
```

## Output Formats

### Compact Format

```bash
./accesslog stage-web --compact
# 07:26:41 200 GET  /api/users (0.123s) 192.168.1.1 [user:12865]
```

### Detailed Format

```bash
./accesslog stage-web
# ╭─ 2025-06-18 07:26:41 200 GET /api/users
# │  IP: 192.168.1.1  Bytes: 1.2 KB  Time: 0.123s  User: 12865
# │  Referer: https://example.com/dashboard
# │  UA: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36...
# ╰─
```

### JSON Output

```bash
./accesslog stage-web --json --last=5
```

### CSV Export

```bash
./accesslog stage-web --since="2025-06-18" --export="csv"
# Creates: nginx_access_20250618_143022.csv
```

## Troubleshooting

### Log Format Issues

```bash
# Check your log format
./accesslog stage-web --show-samples

# Enable debug output
./accesslog stage-web --debug
```

### SSH Connection Issues

```bash
# Test SSH connection manually
ssh stage-web

# Specify custom SSH config
./accesslog stage-web --ssh-config="~/.ssh/custom_config"

# Check remote log path
./accesslog stage-web --remote-path="/custom/path/access.log"
```

### No Results

- Check date filters (`--since`, `--until`)
- Verify filter criteria (`--status`, `--path`, etc.)
- Use `--debug` to see parsing statistics
- Try `--show-samples` to verify log format

## 🎨 Color Output

The tool uses colors to enhance readability:

- **Green**: 2xx status codes
- **Blue**: 3xx redirects
- **Yellow**: 4xx client errors
- **Red**: 5xx server errors
- **Purple**: IP addresses
- **Cyan**: User IDs
- **Gray**: Timestamps and metadata

Disable with `--no-color` for scripts or non-terminal output.

## Tips and Best Practices

1. **Use compact mode** for large datasets: `--compact`
2. **Combine filters** for specific analysis: `--errors-only --user="123" --since="2025-06-18"`
3. **Export data** for further processing: `--export="csv"`
4. **Use grouping** to identify patterns: `--group-by="status"`
5. **Monitor in real-time** with `--follow`
6. **Set reasonable limits** with `--last=1000` for large logs

## Known Limitations

- `--follow` only works with local files (not remote SSH)
- Large log files may take time to process
- Regex parsing assumes well-formed log entries
- SSH requires proper key-based authentication setup

---

**Questions?** Use `./accesslog --help` for a quick reference or `--debug` to troubleshoot parsing issues.
