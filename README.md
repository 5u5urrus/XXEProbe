# XXEProbe  

**XXEProbe** - A tester for detecting XML External Entity (XXE) and XInclude vulnerabilities from raw HTTP requests.  

## Features  
- Sends curated XXE and XInclude payloads  
- Checks `/etc/passwd`, `win.ini`, and parser error patterns  
- Compares responses against a baseline to highlight anomalies  
- Supports custom extra file URIs for extraction  
- Saves injected content and responses for offline analysis  
- Optionally prints and saves raw HTTP requests used in testing  

## Usage  
```bash
python3 xxeprobe.py -f request.txt
````

### Options

* `-f, --file` — Raw HTTP request file (default: stdin)
* `--timeout` — HTTP timeout (default: 8.0)
* `--extra` — Extra file URIs to test (e.g., `file:///etc/passwd`)
* `--print` — Print extracted content preview to stdout
* `--raw` — Save/print raw requests: `none`, `extras`, `success`, or `all` (default: `extras`)

## Example

```bash
python3 xxeprobe.py -f http_request.txt --extra file:///etc/passwd --print
```

Sample output:

```
[baseline] 200 534 bytes

[xxe_passwd] → 200 1123 bytes → LIKELY VULN
  - /etc/passwd content detected
  → raw saved to out/requests/xxe_passwd.http

[xxe_extra_file___etc_passwd] → 200 1123 bytes
  - /etc/passwd content detected
  → saved to out/etc_passwd.txt
----- BEGIN EXTRACT -----
root:x:0:0:root:/root:/bin/bash
...
----- END EXTRACT -----
```

## Notes

* Works directly with raw HTTP requests
* The tool is in its initial draft stages, but works well in many scenarios
* Output is stored under `out/` for later analysis

## License

MIT License.


## Author

Vahe Demirkhanyan
