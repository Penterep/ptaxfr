#!/usr/bin/python3
"""
    Copyright (c) 2023 Penterep Security s.r.o.

    ptaxfr - DNS zone transfer testing tool

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
"""

import argparse
import re
import sys; sys.path.append(__file__.rsplit("/", 1)[0])

import dns.resolver
import dns.zone

from _version import __version__
from ptlibs import ptmisclib, ptjsonlib, ptprinthelper
from ptlibs.threads import ptthreads, printlock


class PtAxfr:
    def __init__(self, args):
        self.ptjsonlib                 = ptjsonlib.PtJsonLib()
        self.ptthreads                 = ptthreads.PtThreads()
        self.use_json                  = args.json
        self.silent                    = args.silent
        self.print_records             = args.print_records
        self.print_subdomains          = args.print_subdomains
        self.unique                    = args.unique
        self.print_vulnerable_domains  = args.vulnerable_only

        try:
            self.domains = ptmisclib.read_file(args.file) if args.file else args.domain
            if len(self.domains) > 1 and self.use_json:
                ptprinthelper.ptprint("Error: Cannot test more than 1 domain while --json parameter is present", "ERROR")
                sys.exit(1)
        except FileNotFoundError:
            self.ptjsonlib.end_error(f"File '{args.file}' not found", self.use_json)
        if self.print_records and self.print_subdomains:
            self.ptjsonlib.end_error("Cannot use -pr and -ps parameters together", self.use_json)
        if self.print_vulnerable_domains and (self.print_records or self.print_subdomains):
            self.ptjsonlib.end_error("Cannot use -V parameter while -pr or -ps parameter is present", self.use_json)
        if self.print_vulnerable_domains and self.use_json:
            self.ptjsonlib.end_error("Cannot use -V parameter while -j parameter is present", self.use_json)
        if self.unique and not (self.print_subdomains or self.print_records):
            self.ptjsonlib.end_error("Use -pr or -ps parameter for --unique to have an effect", self.use_json)
        if self.silent and not (self.print_records or self.print_subdomains or self.print_vulnerable_domains):
            self.ptjsonlib.end_error("Use -pr or -ps or -V for --silent parameter to have an effect", self.use_json)

    def run(self, args):
        """Main method"""
        if self.print_vulnerable_domains and not (self.print_records or self.print_subdomains):
            ptmisclib.ptprint("Vulnerable domains:", "TITLE", condition=self.use_json or not self.silent)

        # Threaded ns_check
        self.ptthreads.threads(self.domains, self.ns_check, args.threads)

        self.ptjsonlib.set_status("ok")
        ptprinthelper.ptprint(self.ptjsonlib.get_result_json(), "", self.use_json)

    def ns_check(self, domain: str) -> None:
        """Finds and tests all nameservers of <domain> for zone transfer"""
        printlock_instance  = printlock.PrintLock()
        resolver            = dns.resolver.Resolver()
        is_vulnerable       = False
        resolver.timeout    = 15
        nameserver_list     = []
        printlock_instance.add_string_to_output(ptprinthelper.out_ifnot(ptprinthelper.get_colored_text(f"Testing domain: {domain}", "TITLE"), "TITLE", self.use_json or self.print_vulnerable_domains), silent=self.silent)
        try:
            ns_query = resolver.resolve(domain, "NS", tcp=False, lifetime=8.0)
        except Exception as e:
            printlock_instance.add_string_to_output(ptprinthelper.out_ifnot(f"Error: {e}", "ERROR", self.use_json or self.print_vulnerable_domains), silent=self.silent)
            self.ptjsonlib.set_status("error", message=str(e))
            if not self.use_json:
                printlock_instance.lock_print_output()
            return

        for rdata in ns_query:
            nameserver = str(rdata)[:-1]
            nameserver_ip = [str(ip) for ip in resolver.resolve(nameserver, "A")][0]
            nameserver_list.append({"nameserver": nameserver, "ns_ip": nameserver_ip, "vulnerable": "null", "dns_records": [], "subdomains": []})
            printlock_instance.add_string_to_output(ptprinthelper.out_ifnot(f"Nameserver: {nameserver}", "INFO", self.use_json or self.print_vulnerable_domains), silent=self.silent)
            printlock_instance.add_string_to_output(ptprinthelper.out_ifnot(f"IP: {nameserver_ip}", "INFO", self.use_json or self.print_vulnerable_domains), silent=self.silent)
            try:
                zone = dns.zone.from_xfr(dns.query.xfr(nameserver_ip, domain, lifetime=5.0))
                is_vulnerable = True
                dns_records_data = self._extract_dns_records(zone)
                subdomains_data =  self._extract_subdomains(zone)
                nameserver_list[-1].update({"vulnerable": True, "zone": zone, "dns_records": dns_records_data, "subdomains": subdomains_data})
                self.ptjsonlib.add_vulnerability(f"PTVWAXFR", request=f"nslookup -q=AXFR {nameserver}", response=dns_records_data)
                printlock_instance.add_string_to_output(ptprinthelper.out_ifnot(f"Vulnerable: True", "VULN", self.use_json or self.print_vulnerable_domains), silent=self.silent, end="\n")
            except dns.exception.Timeout:
                nameserver_list[-1].update({"vulnerable": False})
                printlock_instance.add_string_to_output(ptprinthelper.out_ifnot(f"Timeout error", "ERROR", self.use_json or self.print_vulnerable_domains), silent=self.silent)
            except dns.exception.DNSException:
                nameserver_list[-1].update({"vulnerable": False})
                printlock_instance.add_string_to_output(ptprinthelper.out_ifnot(f"Vulnerable: False", "NOTVULN", self.use_json or self.print_vulnerable_domains), silent=self.silent, end="\n")
            except Exception as e:
                nameserver_list[-1].update({"vulnerable": False})
                #printlock_instance.add_string_to_output(ptprinthelper.out_ifnot(f"{re.search(r'.*,(.*),', str(sys.exc_info())).group(1).strip()} error", "ERROR", self.use_json or self.print_vulnerable_domains), silent=self.silent)
                printlock_instance.add_string_to_output(ptprinthelper.out_ifnot(f"Vulnerable: False", "NOTVULN", self.use_json or self.print_vulnerable_domains), silent=self.silent, end="\n")


        if not is_vulnerable:
            printlock_instance.lock_print_output(end="\n")
            return
        if self.print_vulnerable_domains:
            printlock_instance.add_string_to_output(domain, end="")
            printlock_instance.lock_print_output(end="\n")
            return

        merged_subdomains = set()
        merged_dns_records = set()
        for index, nameserver in enumerate(nameserver_list):
            if nameserver["vulnerable"]:
                for dns_record in nameserver['dns_records']:
                    merged_dns_records.add(dns_record)
                for subdomain in nameserver["subdomains"]:
                    merged_subdomains.add((subdomain["subdomain"]))
                if not self.use_json:
                    if self.unique:
                        if index == 0:
                            printlock_instance.add_string_to_output((" "), end="\n", silent=self.silent)
                            printlock_instance.add_string_to_output(ptprinthelper.out_ifnot(ptprinthelper.get_colored_text(f"Unique {'DNS Records' if self.print_records else 'Subdomains'} for nameservers:", "TITLE"), "TITLE", self.use_json or self.print_vulnerable_domains), silent=self.silent)
                        printlock_instance.add_string_to_output(ptprinthelper.out_ifnot(nameserver['nameserver'], "INFO", self.use_json or self.print_vulnerable_domains), silent=self.silent)
                    if not self.unique:
                        # Standard result printing
                        if self.print_records or self.print_subdomains:
                            printlock_instance.add_string_to_output((" "), end="\n", silent=self.silent)
                            printlock_instance.add_string_to_output(ptprinthelper.out_ifnot(f"{nameserver['nameserver']}", "INFO", self.use_json), silent=self.silent)
                        if self.print_records:
                            for dns_record in nameserver["dns_records"]:
                                printlock_instance.add_string_to_output(ptprinthelper.out_ifnot(dns_record, "", self.use_json))
                        if self.print_subdomains:
                            for subdomain in nameserver["subdomains"]:
                                printlock_instance.add_string_to_output(ptprinthelper.out_ifnot(f"{subdomain['subdomain']}", None, self.use_json), trim=True)
        # Unique result printing
        if self.unique:
            if self.print_records:
                printlock_instance.add_string_to_output(ptprinthelper.out_ifnot('\n'.join(sorted(merged_dns_records)), "", self.use_json))
            if self.print_subdomains:
                printlock_instance.add_string_to_output(ptprinthelper.out_ifnot('\n'.join(sorted(merged_subdomains)), "", self.use_json))
        # Fill json with subdomains
        for subdomain in sorted(merged_subdomains):
            if subdomain != "*":
                self.ptjsonlib.json_object['result']['nodes'].append(self.ptjsonlib.create_node_object('subdomain', properties={'name': subdomain}))
        if not self.use_json:
            printlock_instance.lock_print_output(end="\n" if not self.silent else "")

    def _extract_dns_records(self, zone):
        output_list = []
        data = []
        for name, node in zone.nodes.items():
            names = re.findall(r"DNS IN ([\(\)\w]*) rdataset", str(node.rdatasets))
            if not self.print_vulnerable_domains:
                for index, rdataset in enumerate(node.rdatasets):
                    rdataset_records_str  = str(rdataset).replace("\n", ", ")
                    rdataset_records_list = list(rdataset_records_str.split(","))
                    for dns_record in rdataset_records_list:
                        output_string = ""
                        rdataset_data = re.findall(rf"{names[index].replace('(', ' ').replace(')', ' ')}(.*)", dns_record)
                        split_list = dns_record.split()
                        output_string += f"{str(name)}{' '*(30-len(str(name)))}{split_list[0]}{' '*(10-len(str(split_list[0])))}{split_list[1]}{' '*(10-len(str(split_list[1])))}{split_list[2]}{' '*(10-len(str(split_list[2])))}{' '.join(split_list[3:])}".strip()
                        output_list.append(output_string)
                        data.append({"subdomain": str(name), "type": names[index], "content": rdataset_data})
        return output_list

    def _extract_subdomains(self, zone):
        data = []
        subdomains = set(str(name) for name in zone.nodes.keys())
        for name in sorted(subdomains):
            if name == "@":
                continue
            data.append({"subdomain": str(name)})
        return data


def get_help():
    return [
        {"description": ["DNS zone transfer testing tool"]},
        {"usage": ["ptaxfr <options>"]},
        {"usage_example": ["ptaxfr -d example.com", "ptaxfr -d example1.com example2.com example3.com", "ptaxfr -f domain_list.txt"]},
        {"options": [
            ["-d",  "--domain",           "<domain>",   "Test domain"],
            ["-f",  "--file",             "<file>",     "Test domains from file"],
            ["-pr", "--print-records",    "",           "Print full DNS records"],
            ["-ps", "--print-subdomains", "",           "Print subdomains only"],
            ["-u",  "--unique",           "",           "Print unique records only"],
            ["-V",  "--vulnerable-only",  "",           "Print only vulnerable domains"],
            ["-s",  "--silent",           "",           "Silent mode (show result only)"],
            ["-t",  "--threads",          "<threads>",  "Number of threads (default 20)"],
            ["-v",  "--version",          "",           "Show script version and exit"],
            ["-h",  "--help",             "",           "Show this help message and exit"],
            ["-j",  "--json",             "",           "Output in JSON format"],
        ]}
    ]


def parse_args():
    parser = argparse.ArgumentParser(add_help=False)
    exclusive_group = parser.add_argument_group("One of the following arguments is required")
    exclusive_group = exclusive_group.add_mutually_exclusive_group(required=True)
    exclusive_group.add_argument("-d", "--domain",   type=str, nargs="+")
    exclusive_group.add_argument("-f", "--file",     type=str)
    parser.add_argument("-t", "--threads",           type=int, default=20)
    parser.add_argument("-pr", "--print-records",    action="store_true")
    parser.add_argument("-ps", "--print-subdomains", action="store_true")
    parser.add_argument("-u", "--unique",            action="store_true")
    parser.add_argument("-V", "--vulnerable-only",   action="store_true")
    parser.add_argument("-s", "--silent",            action="store_true")
    parser.add_argument("-j", "--json",              action="store_true")
    parser.add_argument("-v", "--version",           action="version", version=f"{SCRIPTNAME} {__version__}")

    if len(sys.argv) == 1 or "-h" in sys.argv or "--help" in sys.argv:
        ptprinthelper.help_print(get_help(), SCRIPTNAME, __version__)
        sys.exit(0)
    args = parser.parse_args()
    ptprinthelper.print_banner(SCRIPTNAME, __version__, args.json or args.silent, space=0)
    return args


def main():
    global SCRIPTNAME
    SCRIPTNAME = "ptaxfr"
    args = parse_args()
    script = PtAxfr(args)
    script.run(args)


if __name__ == "__main__":
    main()
