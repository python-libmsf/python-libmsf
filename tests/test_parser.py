# Description
"""
test_parser.py: Unit tests for MSF parser
Author: Vladimir Ivanov
License: MIT
Copyright 2021, Python Metasploit Library
"""

# Import
from unittest import TestCase
from test_variables import MsfVariablesForTest
from libmsf.parser import MsfParser
from libmsf import Msf, MsfData
from typing import List

# Authorship information
__author__ = "Vladimir Ivanov"
__copyright__ = "Copyright 2021, Python Metasploit Library"
__credits__ = [""]
__license__ = "MIT"
__version__ = "0.2.2"
__maintainer__ = "Vladimir Ivanov"
__email__ = "ivanov.vladimir.mail@gmail.com"
__status__ = "Development"

# Global variables
msf_variables: MsfVariablesForTest = MsfVariablesForTest()
msf_parser: MsfParser = MsfParser()


# Class MsfRestApiTest
class MsfParserApiTest(TestCase):

    msf_data: MsfData = msf_parser.parse_file(file_name="msf_db_export.xml")

    # Get workspaces
    def test01_get_workspaces(self):
        self.assertListEqual(self.msf_data.workspaces, [])

    # Get hosts
    def test02_get_hosts(self):
        # Normal
        hosts: List[Msf.Host] = self.msf_data.hosts
        self.assertIsInstance(hosts, List)
        self.assertEqual(len(hosts), 2)
        for host in hosts:
            self.assertEqual(host.address, msf_variables.host.address)
            self.assertEqual(host.mac, msf_variables.host.mac)
            self.assertEqual(host.name, msf_variables.host.name)
            self.assertEqual(host.state, msf_variables.host.state)
            self.assertEqual(host.os_name, msf_variables.host.os_name)
            self.assertEqual(host.os_flavor, msf_variables.host.os_flavor)
            self.assertEqual(host.os_sp, msf_variables.host.os_sp)
            self.assertEqual(host.os_lang, msf_variables.host.os_lang)
            self.assertEqual(host.arch, msf_variables.host.arch)
            self.assertEqual(host.purpose, msf_variables.host.purpose)
            self.assertEqual(host.info, msf_variables.host.info)
            self.assertEqual(host.comments, msf_variables.host.comments)
            self.assertEqual(host.scope, msf_variables.host.scope)
            self.assertEqual(host.virtual_host, msf_variables.host.virtual_host)
            break

    # Get services
    def test03_get_services(self):
        # Normal
        services: List[Msf.Service] = self.msf_data.services
        self.assertIsInstance(services, List)
        self.assertEqual(len(services), 2)
        for service in services:
            self.assertEqual(service.port, msf_variables.service.port)
            self.assertEqual(service.proto, msf_variables.service.proto)
            self.assertEqual(service.state, msf_variables.service.state)
            self.assertEqual(service.name, msf_variables.service.name)
            self.assertEqual(service.info, msf_variables.service.info)
            self.assertEqual(service.host, msf_variables.host.address)
            break

    # Get vulns
    def test04_get_vulns(self):
        # Normal
        vulns: List[Msf.Vuln] = self.msf_data.vulns
        self.assertIsInstance(vulns, List)
        self.assertEqual(len(vulns), 2)
        for vuln in vulns:
            self.assertEqual(vuln.name, msf_variables.vuln.name)
            self.assertEqual(vuln.info, msf_variables.vuln.info)
            self.assertEqual(vuln.refs[0], msf_variables.vuln.refs[0])
            self.assertEqual(vuln.refs[1], msf_variables.vuln.refs[1])
            self.assertEqual(vuln.host, msf_variables.host.address)
            break

    # Get loots
    def test05_get_loots(self):
        # Normal
        self.assertListEqual(self.msf_data.loots, [])

    # Get notes
    def test06_get_notes(self):
        # Normal
        notes: List[Msf.Note] = self.msf_data.notes
        self.assertIsInstance(notes, List)
        self.assertEqual(len(notes), 2)
        for note in notes:
            self.assertEqual(note.ntype, msf_variables.note.ntype)
            self.assertEqual(note.data, msf_variables.note.data)
            self.assertEqual(note.host, msf_variables.host.address)
            break

    # Get creds
    def test07_get_creds(self):
        # Normal
        self.assertListEqual(self.msf_data.creds, [])

    # Get logins
    def test08_get_logins(self):
        # Normal
        self.assertListEqual(self.msf_data.logins, [])
