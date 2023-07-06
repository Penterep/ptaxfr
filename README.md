[![penterepTools](https://www.penterep.com/external/penterepToolsLogo.png)](https://www.penterep.com/)


## PTAXFR
![PyPI - License](https://img.shields.io/pypi/l/ptsecurixt?style=for-the-badge)

> DNS zone transfer testing tool

ptaxfr is a tool that tests domains for DNS zone transfer. <br />
This tool utilizes threading for fast parallel domain testing.

## Installation

```
pip install ptaxfr
```

## Add to PATH
If you cannot invoke the script in your terminal, its probably because its not in your PATH. Fix it by running commands below.

> Add to PATH for Bash
```bash
echo "export PATH=\"`python3 -m site --user-base`/bin:\$PATH\"" >> ~/.bashrc
source ~/.bashrc
```

> Add to PATH for ZSH
```bash
echo "export PATH=\"`python3 -m site --user-base`/bin:\$PATH\"" >> ~/.zshhrc
source ~/.zshhrc
```

## Usage examples
```
ptaxfr -d example.com
ptaxfr -d example.com -pr
ptaxfr -d example.com -ps
ptaxfr -d example.com -ps -s
ptaxfr -d example1.com example2.com example3.com
ptaxfr -f domain_list.txt
ptaxfr -f domain_list.txt -V
ptaxfr -f domain_list.txt -V -s -t 10000
```

## Options
```
-d   --domain            <domain>   Test domain
-f   --file              <file>     Test domains from file
-pr  --print-records                Print full DNS records
-ps  --print-subdomains             Print subdomains only
-u   --unique                       Print unique records only
-V   --vulnerable-only              Print only vulnerable domains
-s   --silent                       Silent mode (show result only)
-t   --threads           <threads>  Number of threads (default 20)
-v   --version                      Show script version and exit
-h   --help                         Show this help message and exit
-j   --json                         Output in JSON format
```

## Dependencies
```
dnspython
ptlibs
```

## Version History
```
1.0.0
    - Release ready
0.0.8
    - Updated for ptlibs v0.1.2
    - Code refactorization and bug fixes
    - Output when printing records now aligns correctly
    - Added additional arg checks for correct business logic
0.0.6 - 0.0.7
    - NS queries now use UDP protocol
0.0.5
    - Fixed double newline when using -V parameter
0.0.4
    - Replaced underscores for dashes in arguments
0.0.3
    - Added unique print argument
0.0.1 - 0.0.2
    - Alpha releases
```
## License

Copyright (c) 2023 Penterep Security s.r.o.

ptaxfr is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

ptaxfr is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with ptaxfr.  If not, see <https://www.gnu.org/licenses/>.

## Warning

You are only allowed to run the tool against the websites which
you have been given permission to pentest. We do not accept any
responsibility for any damage/harm that this application causes to your
computer, or your network. Penterep is not responsible for any illegal
or malicious use of this code. Be Ethical!
