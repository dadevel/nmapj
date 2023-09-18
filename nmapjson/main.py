from typing import TextIO
from xml.etree import ElementTree
import json
import subprocess
import sys

from nmapjson.model import Host


def main() -> int:
    process = start_nmap(sys.argv[1:])
    try:
        parse_output(process.stdout)  # type: ignore
        return process.wait()
    except Exception:
        process.terminate()
        raise


def start_nmap(args: list[str]) -> subprocess.Popen:
    command = ['nmap', *args, '-oX', '-']
    process = subprocess.Popen(command, stdout=subprocess.PIPE, text=True)
    return process


def parse_output(reader: TextIO) -> None:
    try:
        for event, element in ElementTree.iterparse(reader, events=['start', 'end']):
            if event == 'start' and element.tag == 'nmaprun':
                if not element.attrib.get('xmloutputversion', '').startswith('1.'):
                    print('parser error: unsupported xml schema version', file=sys.stderr)
                    break
            elif event == 'end' and element.tag == 'host':
                host = Host.from_xml(element)
                print_json(host)
            #else:
            #    print(event, element.tag, element.attrib)
    except ElementTree.ParseError as e:
        print(f'parser error: {e}', file=sys.stderr)
    reader.close()


def print_json(host: Host):
    for port in host.ports.values():
        host_attrs = {k: v for k, v in host.__dict__.items() if k != 'ports'}  # remove ports attribute
        port_attrs = {'port' if k == 'number' else k: v for k, v in port.__dict__.items()}  # rename number to port
        print(json.dumps(host_attrs | port_attrs, indent=None, sort_keys=False, separators=(',', ':')))


if __name__ == '__main__':
    exit(main())
