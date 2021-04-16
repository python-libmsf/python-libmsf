# Description
"""
test_rest.py: Unit tests for MSF REST API
Author: Vladimir Ivanov
License: MIT
Copyright 2021, Python Metasploit Library
"""

# Import
from unittest import TestCase
from tests.test_variables import MsfVariablesForTest
from libmsf.rest import MsfRestApi, Msf
from typing import Union, List, Dict

# Authorship information
__author__ = 'Vladimir Ivanov'
__copyright__ = 'Copyright 2021, Python Metasploit Library'
__credits__ = ['']
__license__ = 'MIT'
__version__ = '0.0.5'
__maintainer__ = 'Vladimir Ivanov'
__email__ = 'ivanov.vladimir.mail@gmail.com'
__status__ = 'Development'

# Global variables
msf_variables: MsfVariablesForTest = MsfVariablesForTest()
msf_api: MsfRestApi = MsfRestApi(api_key=msf_variables.api_key,
                                 api_url=msf_variables.api_url,
                                 proxy=msf_variables.proxy)


# Class MsfRestApiTest
class MsfRestApiTest(TestCase):

    # Create methods

    # Create workspace
    def test01_create_workspace(self):
        msf_api.delete_workspace(workspace_name=msf_variables.workspace.name)
        workspace_id = msf_api.create_workspace(workspace=msf_variables.workspace)
        self.assertIsInstance(workspace_id, int)
        self.assertLess(0, workspace_id)
        msf_variables.workspace.id = workspace_id

    # Create host
    def test02_create_host(self):
        # Normal
        host_id: Union[None, int] = msf_api.create_host(msf_variables.host)
        self.assertIsInstance(host_id, int)
        self.assertLess(0, host_id)
        msf_variables.host.id = host_id

        # Bad workspace
        bad_host = msf_variables.host
        bad_host.workspace = '_bad_workspace_'
        host_id: Union[None, int] = msf_api.create_host(bad_host)
        self.assertIsNone(host_id)

    # Create service
    def test03_create_service(self):
        # Normal
        service_id: Union[None, int] = msf_api.create_service(msf_variables.service)
        self.assertIsInstance(service_id, int)
        self.assertLess(0, service_id)
        msf_variables.service.id = service_id

        # Bad workspace
        bad_service: Msf.Service = msf_variables.service
        bad_service.workspace = '_bad_workspace_'
        service_id: Union[None, int] = msf_api.create_service(bad_service)
        self.assertIsNone(service_id)

    # Create vuln
    def test04_create_vuln(self):
        # Normal
        vuln_id: Union[None, int] = msf_api.create_vuln(msf_variables.vuln)
        self.assertIsInstance(vuln_id, int)
        self.assertLess(0, vuln_id)
        msf_variables.vuln.id = vuln_id

        # Bad workspace
        bad_vuln: Msf.Vuln = msf_variables.vuln
        bad_vuln.workspace = '_bad_workspace_'
        vuln_id: Union[None, int] = msf_api.create_vuln(bad_vuln)
        self.assertIsNone(vuln_id)

    # Create loot
    def test05_create_loot(self):
        # Normal
        loot_id: Union[None, int] = msf_api.create_loot(msf_variables.loot)
        self.assertIsInstance(loot_id, int)
        self.assertLess(0, loot_id)
        msf_variables.loot.id = loot_id

        # Bad workspace
        bad_loot: Msf.Loot = msf_variables.loot
        bad_loot.workspace = '_bad_workspace_'
        loot_id: Union[None, int] = msf_api.create_loot(bad_loot)
        self.assertIsNone(loot_id)

    # Create note
    def test06_create_note(self):
        # Normal
        note_id: Union[None, int] = msf_api.create_note(msf_variables.note)
        self.assertIsInstance(note_id, int)
        self.assertLess(0, note_id)
        msf_variables.note.id = note_id

        # Bad workspace
        bad_note: Msf.Note = msf_variables.note
        bad_note.workspace = '_bad_workspace_'
        note_id: Union[None, int] = msf_api.create_note(bad_note)
        self.assertIsNone(note_id)

    # Create cred
    def test07_create_cred(self):
        # Normal
        msf_variables.cred.workspace_id = msf_variables.workspace.id
        cred_id: Union[None, int] = msf_api.create_cred(msf_variables.cred)
        self.assertIsInstance(cred_id, int)
        self.assertLess(0, cred_id)
        msf_variables.cred.id = cred_id

        # Bad workspace
        bad_cred: Msf.Cred = msf_variables.cred
        bad_cred.workspace_id = -123
        cred_id: Union[None, int] = msf_api.create_cred(bad_cred)
        self.assertIsNone(cred_id)

    # Create note
    def test08_create_login(self):
        # Normal
        msf_variables.login.workspace_id = msf_variables.workspace.id
        msf_variables.login.core_id = msf_variables.cred.id
        login_id: Union[None, int] = msf_api.create_login(msf_variables.login)
        self.assertIsInstance(login_id, int)
        self.assertLess(0, login_id)
        msf_variables.login.id = login_id

        # Bad workspace
        bad_login: Msf.Login = msf_variables.login
        bad_login.workspace_id = -123
        login_id: Union[None, int] = msf_api.create_login(bad_login)
        self.assertIsNone(login_id)

    # Get methods

    # Get workspaces
    def test11_get_workspaces(self):
        # Get workspace id
        test_workspace_id = msf_api.create_workspace(workspace=msf_variables.workspace)
        self.assertIsInstance(test_workspace_id, int)
        self.assertLess(0, test_workspace_id)
        msf_variables.workspace.id = test_workspace_id

        workspaces = msf_api.get_workspaces()
        self.assertIsInstance(workspaces, List)
        workspace_exist: bool = False
        for workspace in workspaces:
            self.assertIsInstance(workspace, Msf.Workspace)
            if workspace.name == msf_variables.workspace.name and workspace.id == msf_variables.workspace.id:
                workspace_exist = True
        self.assertTrue(workspace_exist)

        workspace = msf_api.get_workspace_by_id(workspace_id=msf_variables.workspace.id)
        self.assertEqual(workspace.name, msf_variables.workspace.name)

    # Get hosts
    def test12_get_hosts(self):
        # Normal
        hosts: List[Msf.Host] = msf_api.get_hosts(workspace=msf_variables.workspace.name)
        host: Msf.Host = hosts[0]
        if msf_variables.host.id != -1:
            self.assertEqual(host.id, msf_variables.host.id)
        else:
            msf_variables.host.id = host.id
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

        # Get host by id
        host: Msf.Host = msf_api.get_host_by_id(workspace=msf_variables.workspace.name,
                                                host_id=msf_variables.host.id)
        self.assertEqual(host.address, msf_variables.host.address)

    # Get services
    def test13_get_services(self):
        # Normal
        services: List[Msf.Service] = msf_api.get_services(workspace=msf_variables.workspace.name)
        service: Msf.Service = services[0]
        if msf_variables.service.id != -1:
            self.assertEqual(service.id, msf_variables.service.id)
        else:
            msf_variables.service.id = service.id
        if msf_variables.host.id != -1:
            self.assertEqual(service.host_id, msf_variables.host.id)
        else:
            msf_variables.host.id = service.host_id
        self.assertEqual(service.port, msf_variables.service.port)
        self.assertEqual(service.proto, msf_variables.service.proto)
        self.assertEqual(service.state, msf_variables.service.state)
        self.assertEqual(service.name, msf_variables.service.name)
        self.assertEqual(service.info, msf_variables.service.info)
        self.assertEqual(service.host.address, msf_variables.host.address)

        # Get service by id
        service: Msf.Service = msf_api.get_service_by_id(workspace=msf_variables.workspace.name,
                                                         service_id=msf_variables.service.id)
        self.assertEqual(service.port, msf_variables.service.port)
        self.assertEqual(service.host.address, msf_variables.host.address)

    # Get vulns
    def test14_get_vulns(self):
        # Normal
        vulns: List[Msf.Vuln] = msf_api.get_vulns(workspace=msf_variables.workspace.name)
        vuln: Msf.Vuln = vulns[0]
        if msf_variables.vuln.id != -1:
            self.assertEqual(vuln.id, msf_variables.vuln.id)
        else:
            msf_variables.vuln.id = vuln.id
        if msf_variables.host.id != -1:
            self.assertEqual(vuln.host_id, msf_variables.host.id)
        else:
            msf_variables.host.id = vuln.host_id
        if msf_variables.service.id != -1:
            self.assertEqual(vuln.service_id, msf_variables.service.id)
        else:
            msf_variables.service.id = vuln.service_id
        self.assertEqual(vuln.name, msf_variables.vuln.name)
        self.assertEqual(vuln.info, msf_variables.vuln.info)
        self.assertEqual(vuln.refs[0]['name'], msf_variables.vuln.refs[0])
        self.assertEqual(vuln.refs[1]['name'], msf_variables.vuln.refs[1])
        self.assertEqual(vuln.host.address, msf_variables.host.address)

        # Get service by id
        vuln: Msf.Vuln = msf_api.get_vuln_by_id(workspace=msf_variables.workspace.name,
                                                vuln_id=msf_variables.vuln.id)
        self.assertEqual(vuln.host.address, msf_variables.host.address)

    # Get loots
    def test15_get_loots(self):
        # Normal
        loots: List[Msf.Loot] = msf_api.get_loots(workspace=msf_variables.workspace.name)
        loot: Msf.Loot = loots[0]
        if msf_variables.loot.id != -1:
            self.assertEqual(loot.id, msf_variables.loot.id)
        else:
            msf_variables.loot.id = loot.id
        if msf_variables.host.id != -1:
            self.assertEqual(loot.host_id, msf_variables.host.id)
        else:
            msf_variables.host.id = loot.host_id
        self.assertEqual(loot.data, msf_variables.loot.data)
        self.assertEqual(loot.content_type, msf_variables.loot.content_type)
        self.assertEqual(loot.name, msf_variables.loot.name)
        self.assertEqual(loot.info, msf_variables.loot.info)
        self.assertEqual(loot.host.address, msf_variables.host.address)

        # Get loot by id
        loot: Msf.Loot = msf_api.get_loot_by_id(workspace=msf_variables.workspace.name,
                                                loot_id=msf_variables.loot.id)
        self.assertEqual(loot.host.address, msf_variables.host.address)

    # Get notes
    def test16_get_notes(self):
        # Normal
        notes: List[Msf.Note] = msf_api.get_notes(workspace=msf_variables.workspace.name)
        note: Msf.Note = notes[0]
        if msf_variables.note.id != -1:
            self.assertEqual(note.id, msf_variables.note.id)
        else:
            msf_variables.note.id = note.id
        if msf_variables.host.id != -1:
            self.assertEqual(note.host_id, msf_variables.host.id)
        else:
            msf_variables.host.id = note.host_id
        self.assertEqual(note.ntype, msf_variables.note.ntype)
        self.assertEqual(note.data, msf_variables.note.data)
        self.assertEqual(note.host.address, msf_variables.host.address)

        # Get loot by id
        note: Msf.Note = msf_api.get_note_by_id(workspace=msf_variables.workspace.name,
                                                note_id=msf_variables.note.id)
        self.assertEqual(note.host.address, msf_variables.host.address)

    # Get creds
    def test17_get_creds(self):
        # Normal
        creds: List[Msf.Cred] = msf_api.get_creds(workspace=msf_variables.workspace.name)
        cred: Msf.Cred = creds[0]
        if msf_variables.cred.id != -1:
            self.assertEqual(cred.id, msf_variables.cred.id)
        else:
            msf_variables.cred.id = cred.id
        self.assertEqual(cred.public.username, msf_variables.cred.username)
        self.assertEqual(cred.private.data, msf_variables.cred.private_data)
        self.assertEqual(cred.private.jtr_format, msf_variables.cred.jtr_format)
        if msf_variables.service.id != -1:
            self.assertEqual(cred.origin.service_id, msf_variables.service.id)
        else:
            msf_variables.service.id = cred.origin.service_id
        self.assertEqual(cred.origin.module_full_name, msf_variables.cred.module_fullname)

        # Get cred by id
        cred: Msf.Cred = msf_api.get_cred_by_id(workspace=msf_variables.workspace.name,
                                                cred_id=msf_variables.cred.id)
        self.assertEqual(cred.id, msf_variables.cred.id)

    # Get logins
    def test18_get_logins(self):
        # Normal
        logins: List[Msf.Login] = msf_api.get_logins()
        for login in logins:
            if login.core_id == msf_variables.cred.id:
                msf_variables.login.id = login.id
            if login.service_id == msf_variables.service.id:
                msf_variables.login.id = login.id
        self.assertNotEqual(msf_variables.login.id, -1)

        # Get login by id
        login: Msf.Login = msf_api.get_login_by_id(login_id=msf_variables.login.id)
        self.assertEqual(login.id, msf_variables.login.id)

    # Delete methods

    # Delete login
    def test21_delete_login(self):
        # Normal
        logins: Union[None, List[Msf.Login]] = msf_api.delete_logins(ids=[msf_variables.login.id])
        login: Msf.Login = logins[0]
        self.assertEqual(login.id, msf_variables.login.id)
        self.assertEqual(login.core_id, msf_variables.cred.id)
        self.assertEqual(login.service_id, msf_variables.service.id)
        self.assertEqual(login.last_attempted_at, msf_variables.login.last_attempted_at)
        self.assertEqual(login.access_level, msf_variables.login.access_level)
        self.assertEqual(login.status, msf_variables.login.status)

        # Bad login id
        login_info: Union[None, List[Dict]] = msf_api.delete_logins(ids=[-123])
        self.assertIsNone(login_info)

    # Delete credential
    def test22_delete_cred(self):
        # Normal
        creds: Union[None, List[Msf.Cred]] = msf_api.delete_creds(ids=[msf_variables.cred.id])
        cred: Msf.Cred = creds[0]
        self.assertEqual(cred.id, msf_variables.cred.id)

        # Get credentials
        cred_info: List[Msf.Cred] = msf_api.get_creds(workspace=msf_variables.workspace.name)
        self.assertListEqual(cred_info, [])

        # Bad credential id
        cred_info: Union[None, List[Dict]] = msf_api.delete_creds(ids=[-123])
        self.assertIsNone(cred_info)

    # Delete note
    def test23_delete_note(self):
        # Normal
        notes: Union[None, List[Msf.Note]] = msf_api.delete_notes(ids=[msf_variables.note.id])
        note: Msf.Note = notes[0]
        self.assertEqual(note.id, msf_variables.note.id)
        self.assertEqual(note.workspace_id, msf_variables.workspace.id)
        self.assertEqual(note.host_id, msf_variables.host.id)
        self.assertEqual(note.ntype, msf_variables.note.ntype)
        self.assertEqual(note.data, msf_variables.note.data)

        # Get Notes
        note_info: List[Msf.Note] = msf_api.get_notes(workspace=msf_variables.workspace.name)
        self.assertListEqual(note_info, [])

        # Bad loot id
        note_info: Union[None, List[Dict]] = msf_api.delete_notes(ids=[-123])
        self.assertIsNone(note_info)

    # Delete loot
    def test24_delete_loot(self):
        # Normal
        loots: Union[None, List[Msf.Loot]] = msf_api.delete_loots(ids=[msf_variables.loot.id])
        loot: Msf.Loot = loots[0]
        self.assertEqual(loot.workspace_id, msf_variables.workspace.id)
        self.assertEqual(loot.host_id, msf_variables.host.id)
        self.assertEqual(loot.ltype, msf_variables.loot.ltype)
        self.assertIn(msf_variables.loot.path, loot.path)
        self.assertEqual(loot.data, msf_variables.loot.data)
        self.assertEqual(loot.content_type, msf_variables.loot.content_type)
        self.assertEqual(loot.name, msf_variables.loot.name)
        self.assertEqual(loot.info, msf_variables.loot.info)

        # Get loots
        loot_info: List[Msf.Loot] = msf_api.get_loots(workspace=msf_variables.workspace.name)
        self.assertListEqual(loot_info, [])

        # Bad loot id
        loot_info: Union[None, List[Dict]] = msf_api.delete_loots(ids=[-123])
        self.assertIsNone(loot_info)

    # Delete vulnerability
    def test25_delete_vuln(self):
        # Normal
        vulns: List[Msf.Vuln] = msf_api.delete_vulns(ids=[msf_variables.vuln.id])
        vuln: Msf.Vuln = vulns[0]
        self.assertEqual(vuln.id, msf_variables.vuln.id)
        self.assertEqual(vuln.host_id, msf_variables.host.id)
        self.assertEqual(vuln.service_id, msf_variables.service.id)
        self.assertEqual(vuln.name, msf_variables.vuln.name)
        self.assertEqual(vuln.info, msf_variables.vuln.info)
        self.assertEqual(vuln.host.address, msf_variables.host.address)

        # Get vulnerabilities
        vuln_info: List[Msf.Vuln] = msf_api.get_vulns(workspace=msf_variables.workspace.name)
        self.assertListEqual(vuln_info, [])

        # Bad vulnerability id
        vuln_info: Union[None, List[Msf.Vuln]] = msf_api.delete_vulns(ids=[-123])
        self.assertIsNone(vuln_info)

    # Delete service
    def test26_delete_service(self):
        # Normal
        services: List[Msf.Service] = msf_api.delete_services(ids=[msf_variables.service.id])
        service: Msf.Service = services[0]
        self.assertEqual(service.id, msf_variables.service.id)
        self.assertEqual(service.host_id, msf_variables.host.id)
        self.assertEqual(service.port, msf_variables.service.port)
        self.assertEqual(service.proto, msf_variables.service.proto)
        self.assertEqual(service.state, msf_variables.service.state)
        self.assertEqual(service.name, msf_variables.service.name)
        self.assertEqual(service.info, msf_variables.service.info)

        # Get services
        service_info: List[Msf.Service] = msf_api.get_services(workspace=msf_variables.workspace.name)
        self.assertListEqual(service_info, [])

        # Bad service id
        service_info: Union[None, List[Dict]] = msf_api.delete_services(ids=[-123])
        self.assertIsNone(service_info)

    # Delete host
    def test27_delete_host(self):
        # Normal
        hosts: List[Msf.Host] = msf_api.delete_hosts(ids=[msf_variables.host.id])
        host: Msf.Host = hosts[0]
        if msf_variables.host.id != -1:
            self.assertEqual(host.id, msf_variables.host.id)
        else:
            msf_variables.host.id = host.id
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

        # Get hosts
        host_info: List[Msf.Host] = msf_api.get_hosts(workspace=msf_variables.workspace.name)
        self.assertListEqual(host_info, [])

        # Bad host id
        host_info: Union[None, List[Dict]] = msf_api.delete_hosts(ids=[-123])
        self.assertIsNone(host_info)

    # Delete workspace
    def test28_delete_workspace(self):
        # Get workspace id
        test_workspace_id = msf_api.create_workspace(workspace=msf_variables.workspace)
        self.assertIsInstance(test_workspace_id, int)
        self.assertLess(0, test_workspace_id)
        msf_variables.workspace.id = test_workspace_id


        # Normal
        workspaces: Union[None, List[Msf.Workspace]] = msf_api.delete_workspaces(ids=[msf_variables.workspace.id])
        self.assertIsInstance(workspaces, list)
        workspace: Msf.Workspace = workspaces[0]
        self.assertEqual(workspace.id, msf_variables.workspace.id)
        self.assertEqual(workspace.name, msf_variables.workspace.name)

        # Get workspaces list
        workspaces = msf_api.get_workspaces()
        self.assertIsInstance(workspaces, list)
        workspace_exist: bool = False
        for workspace in workspaces:
            if workspace.name == msf_variables.workspace.name and workspace.id == msf_variables.workspace.id:
                workspace_exist = True
        self.assertFalse(workspace_exist)

        # Bad workspace id
        workspace_info: Union[None, List[Dict]] = msf_api.delete_workspaces(ids=[-123])
        self.assertIsNone(workspace_info)
