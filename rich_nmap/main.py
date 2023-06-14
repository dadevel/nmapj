#!/usr/bin/env python3
from __future__ import annotations
from argparse import ArgumentParser
from io import StringIO
from threading import Lock, Thread
from xml.etree import ElementTree
from xml.etree.ElementTree import Element
from typing import Any, ClassVar, TextIO, Iterable
import csv
import dataclasses
import ipaddress
import json
import os
import subprocess
import sys
import time

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TimeElapsedColumn, TextColumn, BarColumn, TaskProgressColumn, MofNCompleteColumn
from rich.table import Table
import yaml

# TODO: start new nmap process each 256th target

@dataclasses.dataclass
class Port:
    reachable: bool
    number: int
    protocol: str
    service: str
    product: str
    version: str
    extra: str
    infos: dict[str, str]

    HEADER: ClassVar[dict[str, str|None]] = dict(number='port', protocol=None, service=None, product=None, version=None, extra=None)

    @classmethod
    def from_xml(cls, element: Element) -> Port:
        service = element.find('service')
        if service is None:
            service_name = ''
        else:
            service_name = service.attrib['name']
            service_name = service_name.removesuffix('-alt') if service_name in ('http-alt', 'https-alt') else service_name
        return cls(
            reachable=_subelement(element, 'state').attrib['state'] == 'open',
            number=int(element.attrib['portid']),
            protocol=element.attrib['protocol'],
            service=service_name,
            product=service.attrib.get('product') or '' if service else '',
            version=service.attrib.get('version') or '' if service else '',
            extra=service.attrib.get('extra') or '' if service else '',
            infos={subelement.attrib['id']: subelement.attrib['output'] for subelement in element.iter('script')},
        )

    def to_dict(self) -> dict[str, Any]:
        return self.__dict__

    def get_header(self) -> list[str]:
        return [self.HEADER[k] or k for k in self.__dataclass_fields__ if k in self.HEADER] + list(self.infos)

    def to_row(self) -> list[str]:
        return [str(v) for k, v in self.to_dict().items() if k in self.HEADER] + list(self.infos.values())


@dataclasses.dataclass
class Host:
    reachable: bool
    address: str
    addresstype: str
    ports: dict[int, Port]

    HEADER: ClassVar[dict[str, str|None]] = dict(address=None, addresstype=None)

    @classmethod
    def from_xml(cls, element: Element) -> Host:
        address = _subelement(element, 'address')
        status = _subelement(element, 'status').attrib
        ports = {port.number: port for port in (Port.from_xml(subelement) for subelement in _subelement(element, 'ports').iter('port')) if port.reachable}
        return cls(
            reachable=bool(ports) or (status['state'] == 'up' and status['reason'] != 'user-set'),
            address=address.attrib['addr'],
            addresstype=address.attrib['addrtype'],
            ports=ports,
        )

    def to_dict(self) -> dict[str, Any]:
        return dict(self.__dict__, ports={n: p.to_dict() for n, p in self.ports.items()})

    def get_header(self) -> list[str]:
        if self.ports:
            return [self.HEADER[k] or k for k in self.__dataclass_fields__ if k in self.HEADER] + next(iter(self.ports.values())).get_header()
        else:
            return []

    def to_rows(self) -> list[list[str]]:
        rows = []
        for port in self.ports.values():
            row = [str(v) for k, v in self.to_dict().items() if k in self.HEADER] + port.to_row()
            rows.append(row)
        return rows


def _subelement(element: Element, name: str) -> Element:
    subelement = element.find(name)
    if subelement is None:
        raise ValueError(f'element {name!r} not found')
    return subelement


def start_nmap(args: list[str]) -> subprocess.Popen:
    command = ['nmap', *args, '-iL', '-', '-oX', '-']
    process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    return process


target_counter = 0
target_counter_lock = Lock()

completed_counter = 0
completed_counter_lock = Lock()


def load_targets(targets: Iterable[str], stream: TextIO, allow_files: bool = True) -> None:
    global target_counter
    global target_counter_lock

    for target in targets:
        if not target:
            continue

        if allow_files and target == '-':
            load_targets((line.strip() for line in sys.stdin), stream, allow_files=False)
            continue

        if allow_files and os.path.isfile(target):
            with open(target, 'r') as file:
                load_targets((line.strip() for line in file), stream, allow_files=False)
            continue

        try:
            subnet_counter = 0
            for address in ipaddress.ip_network(target).hosts():
                stream.write(str(address))
                stream.write('\n')
                subnet_counter += 1
            with target_counter_lock:
                target_counter += subnet_counter
            continue
        except ValueError:
            pass

        try:
            address = ipaddress.ip_address(target)
            stream.write(str(address))
            stream.write('\n')
            with target_counter_lock:
                target_counter += 1
            continue
        except ValueError:
            pass

        stream.write(target)
        stream.write('\n')
        with target_counter_lock:
            target_counter += 1
        continue

    if allow_files:
        stream.close()


def main() -> None:
    args = sys.argv[1:]

    try:
        pos = args.index('--')
        python_args = args[:pos]
        nmap_args = args[pos + 1:]
    except ValueError:
        python_args = args
        nmap_args = []

    stdout = Console(stderr=False)
    stderr = Console(stderr=True)
    printers = dict(jsonl=JsonlPrinter, yaml=YamlPrinter, csv=CsvPrinter, ascii=AsciiPrinter)

    entrypoint = ArgumentParser()
    entrypoint.add_argument('-f', '--format', choices=tuple(printers), default='ascii' if os.isatty(sys.stdout.fileno()) else 'jsonl')
    entrypoint.add_argument('targets', nargs='*', default=['-'], metavar='IPADDRESS|FQDN|CIDR|FILE')
    opts = entrypoint.parse_args(python_args)

    printer_class = printers[opts.format]
    printer = printer_class(stdout)

    process = start_nmap(nmap_args)
    assert process.stdin
    assert process.stdout
    assert process.stderr

    global target_counter
    global target_counter_lock
    global completed_counter
    global completed_counter_lock

    progress_output = stdout if os.isatty(sys.stdout.fileno()) else stderr

    input_thread = Thread(target=load_targets, args=(opts.targets, process.stdin))
    input_thread.start()

    output_thread = Thread(target=parse_output, args=(process.stdout, printer, progress_output))
    output_thread.start()

    progress = Progress(
        SpinnerColumn(),
        TextColumn('[progress.description]{task.description}'),
        BarColumn(),
        MofNCompleteColumn(),
        TimeElapsedColumn(),
        console=progress_output,
        transient=True,
    )
    TaskProgressColumn(text_format='')
    with progress:
        with target_counter_lock:
            taskid = progress.add_task('Scanning...', total=target_counter)
        while process.poll() is None or (process.poll() == 0 and not progress.finished):
            with completed_counter_lock, target_counter_lock:
                progress.update(taskid, completed=completed_counter, total=target_counter)
            time.sleep(1)

        input_thread.join()
        output_thread.join()

    rc = process.wait()
    if rc != 0:
        stderr.print(process.stderr.read().strip())
    exit(rc)


def parse_output(reader: TextIO, printer: Printer, stderr: Console) -> None:
    global completed_counter_lock
    global completed_counter

    try:
        for event, element in ElementTree.iterparse(reader, events=['start', 'end']):
            if event == 'start' and element.tag == 'nmaprun':
                if not element.attrib.get('xmloutputversion', '').startswith('1.'):
                    stderr.print('unsupported xml schema version')
                    break
            elif event == 'end' and element.tag == 'host':
                with completed_counter_lock:
                    completed_counter += 1
                host = Host.from_xml(element)
                if host.reachable:
                    printer.add(host)
    except ElementTree.ParseError as e:
        stderr.print(f'xml parser error: {e}')

    printer.finalize()
    reader.close()


class Printer:
    def __init__(self, console: Console) -> None:
        self.console = console

    def add(self, host: Host) -> None:
        raise NotImplementedError()

    def finalize(self) -> None:
        self.console.file.flush()


class JsonlPrinter(Printer):
    def add(self, host: Host) -> None:
        self.console.print(json.dumps(host.to_dict(), indent=None, sort_keys=False, separators=(',', ':')), soft_wrap=True)


class YamlPrinter(Printer):
    def add(self, host: Host) -> None:
         self.console.print('---')
         self.console.print(yaml.safe_dump(host.to_dict(), indent=2, sort_keys=False))


class CsvPrinter(Printer):
    def __init__(self, console: Console) -> None:
        super().__init__(console)
        self.file = StringIO()

    def add(self, host: Host) -> None:
        self.file.seek(0)
        self.file.truncate()
        writer = csv.writer(self.file, quoting=csv.QUOTE_MINIMAL)
        writer.writerows(host.to_rows())
        self.file.seek(0)
        self.console.print(self.file.read().strip())


class AsciiPrinter(Printer):
    def __init__(self, console: Console) -> None:
        self.console = console
        self.table = Table()
        self._header_initialized = False

    def add(self, host: Host) -> None:
        if not self._header_initialized:
            header = host.get_header()
            self._header_initialized = bool(header)
            for key in header:
                self.table.add_column(key, no_wrap=True)

        for row in host.to_rows():
            self.table.add_row(*row)

    def finalize(self) -> None:
        self.console.print(self.table)
        super().finalize()


if __name__ == '__main__':
    main()
