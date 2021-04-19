# Description
"""
parser.py: Library for parse MSF exported files
Author: Vladimir Ivanov
License: MIT
Copyright 2021, Python Metasploit Library
"""

# Import
from libmsf.msf import Msf, MsfData
from typing import List, Union
from dataclasses import dataclass
from argparse import ArgumentParser
from xml.etree import ElementTree as ET

# Authorship information
__author__ = 'Vladimir Ivanov'
__copyright__ = 'Copyright 2021, Python Metasploit Library'
__credits__ = ['']
__license__ = 'MIT'
__version__ = '0.1.1'
__maintainer__ = 'Vladimir Ivanov'
__email__ = 'ivanov.vladimir.mail@gmail.com'
__status__ = 'Development'


class MsfParser:

    def parse_file(self, file_name: str) -> Union[None, MsfData]:
        try:
            with open(file_name) as file:
                return self.parse_string(string=file.read())
        except IOError:
            print(f'File: {file_name} not accessible')
        return None

    @staticmethod
    def _parse_xml_element(dataclass_object: dataclass, xml_element: ET) -> dataclass:
        for key in dataclass_object.__dict__:
            try:
                if isinstance(dataclass_object.__dict__[key], int):
                    dataclass_object.__dict__[key] = int(xml_element.findtext(key.replace('_', '-')))
                else:
                    dataclass_object.__dict__[key] = str(xml_element.findtext(key.replace('_', '-')))
            except ValueError:
                continue
            except TypeError:
                continue
        return dataclass_object

    @staticmethod
    def _get_port_by_service_id(service_id: int, services: List[Msf.Service]) -> int:
        for service in services:
            if service.id == service_id:
                return service.port
        return -1

    def _parse_xml_string(self, string: str) -> Union[None, MsfData]:
        try:
            msf_data: MsfData = MsfData()
            tree: ET = ET.ElementTree(ET.fromstring(string))
            root: ET = tree.getroot()
            assert root.tag == 'MetasploitV5', 'This is not Metasploit exported xml file'

            # Get workspace name
            for child in root:
                if child.tag == 'generated':
                    if 'project' in child.attrib:
                        if isinstance(child.attrib.get('project'), str):
                            msf_data.workspace = child.attrib.get('project')
                            break

            # Parse hosts tag
            for hosts in root.iter('hosts'):

                msf_hosts: List[Msf.Host] = list()
                msf_services: List[Msf.Service] = list()
                msf_notes: List[Msf.Note] = list()
                msf_vulns: List[Msf.Vuln] = list()

                # Parse host tag
                for host in hosts.iter('host'):
                    msf_host: Msf.Host = Msf.Host()
                    msf_host = self._parse_xml_element(msf_host, host)
                    msf_host.workspace = msf_data.workspace
                    msf_hosts.append(msf_host)

                    # Parse services tag
                    for services in host.iter('services'):
                        for service in services.iter('service'):
                            msf_service: Msf.Service = Msf.Service()
                            msf_service = self._parse_xml_element(msf_service, service)
                            msf_service.workspace = msf_data.workspace
                            msf_service.host = msf_host.address
                            msf_services.append(msf_service)

                    # Parse notes tag
                    for notes in host.iter('notes'):
                        for note in notes.iter('note'):
                            msf_note: Msf.Note = Msf.Note()
                            msf_note = self._parse_xml_element(msf_note, note)
                            msf_note.workspace = msf_data.workspace
                            msf_note.host = msf_host.address
                            msf_note.port = self._get_port_by_service_id(service_id=msf_note.service_id,
                                                                         services=msf_services)
                            msf_notes.append(msf_note)

                    # Parse vulns tag
                    for vulns in host.iter('vulns'):
                        for vuln in vulns.iter('vuln'):
                            msf_vuln: Msf.Vuln = Msf.Vuln()
                            msf_vuln = self._parse_xml_element(msf_vuln, vuln)
                            msf_vuln.workspace = msf_data.workspace
                            msf_vuln.host = msf_host.address
                            msf_vuln.port = self._get_port_by_service_id(service_id=msf_vuln.service_id,
                                                                         services=msf_services)
                            msf_vuln.refs = list()
                            for refs in host.iter('refs'):
                                for ref in refs.iter('ref'):
                                    msf_vuln.refs.append(ref.text)
                            msf_vulns.append(msf_vuln)

                # Set msf data lists
                msf_data.hosts = msf_hosts
                msf_data.services = msf_services
                msf_data.notes = msf_notes
                msf_data.vulns = msf_vulns

            return msf_data
        except AssertionError as error:
            print(f'Assertion error: {error.args[0]}')
        return None

    def parse_string(self, string: str) -> Union[None, MsfData]:
        try:
            ET.ElementTree(ET.fromstring(string))
            return self._parse_xml_string(string=string)
        except ET.ParseError:
            print('This string is not xml')
        return None


# Main function
def main() -> None:
    # Parse script arguments
    parser: ArgumentParser = ArgumentParser(description='MSF parser console client')
    parser.add_argument('-f', '--file', type=str, help='set MSF exported file', required=True)
    args = parser.parse_args()

    # Init MsfRestApi
    msf_parser: MsfParser = MsfParser()

    # Parse file
    msf_data: MsfData = msf_parser.parse_file(file_name=args.file)
    print(msf_data)
