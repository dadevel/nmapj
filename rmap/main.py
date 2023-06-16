from argparse import ArgumentParser
from threading import Lock, Thread
from typing import TextIO, Iterable
from xml.etree import ElementTree
import ipaddress
import os
import subprocess
import sys
import time

from rich.console import Console
from rich.progress import BarColumn, MofNCompleteColumn, Progress, SpinnerColumn, TaskProgressColumn, TextColumn, TimeElapsedColumn

from rmap.model import Host
from rmap import printer

TARGET_COUNTER = 0
TARGET_COUNTER_LOCK = Lock()

COMPLETED_COUNTER = 0
COMPLETED_COUNTER_LOCK = Lock()


def start_nmap(args: list[str]) -> subprocess.Popen:
    command = ['nmap', *args, '--privileged', '-iL', '-', '-oX', '-']
    process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    return process


def load_targets(targets: Iterable[str], stream: TextIO, allow_files: bool = True) -> None:
    global TARGET_COUNTER
    global TARGET_COUNTER_LOCK

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
            with TARGET_COUNTER_LOCK:
                TARGET_COUNTER += subnet_counter
            continue
        except ValueError:
            pass

        try:
            address = ipaddress.ip_address(target)
            stream.write(str(address))
            stream.write('\n')
            with TARGET_COUNTER_LOCK:
                TARGET_COUNTER += 1
            continue
        except ValueError:
            pass

        stream.write(target)
        stream.write('\n')
        with TARGET_COUNTER_LOCK:
            TARGET_COUNTER += 1
        continue

    if allow_files:
        stream.close()


def assert_capabilities(console: Console) -> None:
    process = subprocess.run(['nmap', '--privileged', '-sS', '0.0.0.0'], text=True, capture_output=True, check=False)
    if process.returncode != 0:
        console.print(f'nmap error: {process.stderr.strip()}')
        console.print('run the following command to fix this problem: sudo setcap CAP_NET_RAW=ep "$(which nmap)"')
        exit(1)


def main() -> None:
    args = sys.argv[1:]

    try:
        pos = args.index('--')
        python_args = args[:pos]
        nmap_args = args[pos + 1:]
    except ValueError:
        python_args = args
        nmap_args = []

    entrypoint = ArgumentParser()
    entrypoint.add_argument('-f', '--format', choices=('auto', *printer.CLASSES), default='auto', metavar='|'.join(printer.CLASSES))
    entrypoint.add_argument('-o', '--output', default=None)
    entrypoint.add_argument('targets', nargs='*', default=['-'], metavar='IPADDRESS|CIDR|FQDN|FILE')
    opts = entrypoint.parse_args(python_args)

    stdout = Console(stderr=False)
    stderr = Console(stderr=True)
    console = stdout if os.isatty(sys.stdout.fileno()) else stderr

    if opts.format == 'auto':
        if opts.output:
            opts.format= 'csv'
        elif os.isatty(sys.stdout.fileno()):
            opts.format = 'ascii'
        else:
            opts.format= 'csv'
    printer_class = printer.CLASSES[opts.format]
    printer_instance = printer_class(Console(file=open(opts.output, 'w'), soft_wrap=False) if opts.output else stdout)

    assert_capabilities(console)
    process = start_nmap(nmap_args)
    assert process.stdin
    assert process.stdout
    assert process.stderr

    global TARGET_COUNTER
    global TARGET_COUNTER_LOCK
    global COMPLETED_COUNTER
    global COMPLETED_COUNTER_LOCK

    input_thread = Thread(target=load_targets, args=(opts.targets, process.stdin))
    input_thread.start()

    output_thread = Thread(target=parse_output, args=(process.stdout, printer_instance, console))
    output_thread.start()

    progress = Progress(
        SpinnerColumn(),
        TextColumn('[progress.description]{task.description}'),
        BarColumn(),
        MofNCompleteColumn(),
        TimeElapsedColumn(),
        console=console,
        transient=True,
    )
    TaskProgressColumn(text_format='')
    with progress:
        with TARGET_COUNTER_LOCK:
            taskid = progress.add_task('Scanning...', total=TARGET_COUNTER)
        while process.poll() is None or (process.poll() == 0 and not progress.finished):
            with COMPLETED_COUNTER_LOCK, TARGET_COUNTER_LOCK:
                progress.update(taskid, completed=COMPLETED_COUNTER, total=TARGET_COUNTER)
            time.sleep(1)

        input_thread.join()
        output_thread.join()

    rc = process.wait()
    if rc != 0:
        stderr.print(process.stderr.read().strip())
    exit(rc)


def parse_output(reader: TextIO, printer: printer.Printer, console: Console) -> None:
    global COMPLETED_COUNTER_LOCK
    global COMPLETED_COUNTER

    try:
        for event, element in ElementTree.iterparse(reader, events=['start', 'end']):
            if event == 'start' and element.tag == 'nmaprun':
                if not element.attrib.get('xmloutputversion', '').startswith('1.'):
                    console.print('unsupported xml schema version')
                    break
            elif event == 'end' and element.tag == 'host':
                with COMPLETED_COUNTER_LOCK:
                    COMPLETED_COUNTER += 1
                host = Host.from_xml(element)
                if host.reachable:
                    printer.add(host)
    except ElementTree.ParseError as e:
        console.print(f'xml parser error: {e}')

    printer.finalize()
    reader.close()
