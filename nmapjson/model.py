from __future__ import annotations
from xml.etree.ElementTree import Element
import dataclasses
import textwrap


@dataclasses.dataclass
class Port:
    reachable: bool
    transport: str
    number: int
    application: str
    product: str
    version: str
    extra: str
    infos: dict[str, list[str]]

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
            transport=element.attrib['protocol'],
            application=service_name,
            product=service.attrib.get('product') or '' if service else '',
            version=service.attrib.get('version') or '' if service else '',
            extra=service.attrib.get('extra') or '' if service else '',
            infos={
                subelement.attrib['id']: [
                    line
                    for index, line in enumerate(textwrap.dedent(subelement.attrib['output']).splitlines())
                    if index > 1 or line
                ]
                for subelement in element.iter('script')
            },
        )


@dataclasses.dataclass
class Host:
    reachable: bool
    network: str
    address: str
    osvendor: str
    osfamily: str
    ports: dict[int, Port]

    @classmethod
    def from_xml(cls, element: Element) -> Host:
        address = _subelement(element, 'address')
        status = _subelement(element, 'status').attrib
        os = element.find('os')
        if os is not None:
            osinfo = next(iter(sorted(os.iter('osclass'), key=lambda i: i.attrib['accuracy'])))
            osvendor = osinfo.attrib['vendor']
            osfamily = osinfo.attrib['osfamily']
        else:
            osvendor = ''
            osfamily = ''
        ports = {port.number: port for port in (Port.from_xml(subelement) for subelement in _subelement(element, 'ports').iter('port')) if port.reachable}
        return cls(
            reachable=bool(ports) or (status['state'] == 'up' and status['reason'] != 'user-set'),
            address=address.attrib['addr'],
            network=address.attrib['addrtype'],
            osvendor=osvendor,
            osfamily=osfamily,
            ports=ports,
        )


def _subelement(element: Element, name: str) -> Element:
    subelement = element.find(name)
    if subelement is None:
        raise ValueError(f'element {name!r} not found')
    return subelement
