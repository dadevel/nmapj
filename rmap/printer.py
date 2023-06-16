from io import StringIO
import csv
import json

from rich.console import Console
from rich.table import Table

import yaml

from rmap.model import Host


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


CLASSES = dict(
    ascii=AsciiPrinter,
    csv=CsvPrinter,
    jsonl=JsonlPrinter,
    yaml=YamlPrinter,
)
