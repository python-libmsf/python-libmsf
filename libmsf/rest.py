# Description
"""
rest.py: MSF REST API library
Author: Vladimir Ivanov
License: MIT
Copyright 2021, Python Metasploit Library
"""

# Import
from libmsf.msf import Msf, MsfData
from requests import Session, Response
from typing import List, Dict, Union, Type
from dataclasses import dataclass
from urllib3 import disable_warnings
from urllib3.exceptions import InsecureRequestWarning
from argparse import ArgumentParser

# Authorship information
__author__ = 'Vladimir Ivanov'
__copyright__ = 'Copyright 2021, Python Metasploit Library'
__credits__ = ['']
__license__ = 'MIT'
__version__ = '0.1.1'
__maintainer__ = 'Vladimir Ivanov'
__email__ = 'ivanov.vladimir.mail@gmail.com'
__status__ = 'Development'


# Class MsfRestApi
class MsfRestApi:
    # Set variables
    @dataclass
    class Endpoints:
        home: str = '/'
        creds: str = '/api/v1/credentials'
        hosts: str = '/api/v1/hosts'
        logins: str = '/api/v1/logins'
        loots: str = '/api/v1/loots'
        notes: str = '/api/v1/notes'
        services: str = '/api/v1/services'
        vulns: str = '/api/v1/vulns'
        workspaces: str = '/api/v1/workspaces'

    _endpoints: Endpoints = Endpoints()

    # Init
    def __init__(self,
                 api_key: str,
                 api_url: str = 'https://msf.corp.test.com:5443',
                 proxy: Union[None, str] = None) -> None:
        """
        Init MsfRestApi Class
        @param api_key: MSF REST API key string, example: 5c28984c3b034d2f30eff0070bd779c8080489bcff6bd79872d62f1411331901fa242ae39b6c6a62
        @param api_url: MSF REST API server URL string, example: 'https://msf.corp.test.com:5443'
        @param proxy: HTTP Proxy URL string, example: 'http://127.0.0.1:8080'
        """
        self._api_url = api_url
        self._api_key = api_key
        self._session: Session = Session()
        self._session.headers.update({
            'User-Agent': 'Metasploit REST API Agent v.0.0.1',
            'Accept': 'application/json',
            'Connection': 'close',
            'Authorization': 'Bearer ' + api_key
        })
        if proxy is not None:
            self._session.proxies.update({
                'http': proxy,
                'https': proxy,
            })
        self._session.verify = False
        disable_warnings(InsecureRequestWarning)
        try:
            self.get_workspaces()
        except AssertionError as error:
            print('[Assert Exception] Error: ' + error.args[0])
            exit(1)

    # Check responses

    @staticmethod
    def _dict_to_dataclass(dict_object: Dict, dataclass_type: Type) -> dataclass:
        """
        Make dataclass object from dictionary
        :param dict_object: Dictionary
        :param dataclass_type: Dataclass type
        :return: Dataclass object
        """
        dataclass_object: dataclass_type = dataclass_type()
        for key in dict_object:
            if key in dataclass_object.__dict__:
                dataclass_object.__dict__[key] = dict_object[key]
        return dataclass_object

    def _check_get_response(self,
                            response: Response,
                            dataclass_type: Type) -> Union[None, List[dataclass]]:
        """
        Check HTTP response for GET request
        @param response: HTTP response
        @return: List of dataclasses if success or None if error
        """
        try:
            assert response.status_code == 200, \
                'Bad status code: ' + str(response.status_code) + \
                ' in request: ' + str(response.request.method) + ' ' + str(response.request.url)
            assert 'data' in response.json(), 'Not found \'data\' object in json response: ' + str(response.json())
            _dataclass_objects: List[dataclass_type] = list()
            for dictionary in response.json()['data']:
                _dataclass_object: dataclass_type = self._dict_to_dataclass(dictionary, dataclass_type)
                if 'host' in dictionary and 'host' in _dataclass_object.__dict__:
                    _dataclass_object.host = self._dict_to_dataclass(dictionary['host'], Msf.Host)
                if dataclass_type == Msf.Cred:
                    if 'logins' in dictionary:
                        _logins: List[Msf.Login] = list()
                        for login_dictionary in dictionary['logins']:
                            _login: Msf.Login = self._dict_to_dataclass(login_dictionary, Msf.Login)
                            _logins.append(_login)
                        _dataclass_object.logins = _logins
                    if 'public' in dictionary:
                        _dataclass_object.public = self._dict_to_dataclass(dictionary['public'], Msf.Public)
                    if 'private' in dictionary:
                        _dataclass_object.private = self._dict_to_dataclass(dictionary['private'], Msf.Private)
                    if 'origin' in dictionary:
                        _dataclass_object.origin = self._dict_to_dataclass(dictionary['origin'], Msf.Origin)
                _dataclass_objects.append(_dataclass_object)
            return _dataclass_objects

        except AssertionError as Error:
            if (response.status_code == 500 or
                response.status_code == 401) and \
                    'error' in response.json() and \
                    'code' in response.json()['error'] and \
                    'message' in response.json()['error']:
                print('[Assertion Exception] Error code: ' + str(response.json()['error']['code']) +
                      '; error message: ' + str(response.json()['error']['message']))
            else:
                print('[Assertion Exception] Error: ' + Error.args[0])
            return None

        except ValueError as Error:
            print('[Value Exception] Error: ' + Error.args[0])
            return None

    @staticmethod
    def _check_create_response(response: Response) -> Union[int, None]:
        """
        Check HTTP response for POST request
        @param response: HTTP response
        @return: Object "id" integer or None if error
        """
        try:
            assert response.status_code == 200, \
                'Bad status code: ' + str(response.status_code) + \
                ' in request: ' + str(response.request.method) + ' ' + str(response.request.url)
            assert 'data' in response.json(), 'Not found \'data\' object in json response: ' + str(response.json())
            if isinstance(response.json()['data'], dict):
                if 'id' in response.json()['data']:
                    if isinstance(response.json()['data']['id'], int):
                        return response.json()['data']['id']
                return None
            else:
                return None

        except AssertionError as Error:
            if (response.status_code == 500 or
                response.status_code == 401) and \
                    'error' in response.json() and \
                    'code' in response.json()['error'] and \
                    'message' in response.json()['error']:
                print('[Assertion Exception] Error code: ' + str(response.json()['error']['code']) +
                      '; error message: ' + str(response.json()['error']['message']))
            else:
                print('[Assertion Exception] Error: ' + Error.args[0])
            return None

        except ValueError as Error:
            print('[Value Exception] Error: ' + Error.args[0])
            return None

    def _check_delete_response(self,
                               response: Response,
                               dataclass_type: Type) -> Union[None, List[dataclass]]:
        """
        Check HTTP response for DELETE request
        @param response: HTTP response
        @return: List of dataclasses if success or None if error
        """
        return self._check_get_response(response=response, dataclass_type=dataclass_type)

    # GET methods

    def get_workspaces(self) -> Union[None, List[Msf.Workspace]]:
        """
        Get list of MSF workspaces
        @return: None if error or List of MSF workspaces example: [Msf.Workspace(id=1,
                                                                                 name='default',
                                                                                 created_at='2021-04-07T16:34:01.279Z',
                                                                                 updated_at='2021-04-07T16:34:01.279Z',
                                                                                 boundary=None,
                                                                                 description=None,
                                                                                 owner_id=None,
                                                                                 limit_to_network=False,
                                                                                 import_fingerprint=False)]
        """
        response = self._session.get(self._api_url + self._endpoints.workspaces)
        return self._check_get_response(response=response, dataclass_type=Msf.Workspace)

    def get_hosts(self, workspace: str = 'default') -> Union[None, List[Msf.Host]]:
        """
        Get hosts from MSF workspace
        @param workspace: MSF workspace name string, example: "default"
        @return: None if error or List of hosts example: [Msf.Host(id=260, workspace=None,
                                                                   created_at='2021-04-15T11:26:33.900Z',
                                                                   address='192.168.1.1',
                                                                   mac='00:11:22:33:44:55',
                                                                   comm='unittest',
                                                                   name='unit.test.com',
                                                                   state='alive',
                                                                   os_name='linux',
                                                                   os_flavor='test',
                                                                   os_sp='test',
                                                                   os_lang='English',
                                                                   arch='x86',
                                                                   workspace_id=230,
                                                                   updated_at='2021-04-15T11:26:33.900Z',
                                                                   purpose='device',
                                                                   info='Host for unit tests',
                                                                   comments='Host for unit tests',
                                                                   scope='unit tests scope',
                                                                   virtual_host='unittest',
                                                                   note_count=1, vuln_count=1,
                                                                   service_count=1, host_detail_count=0,
                                                                   exploit_attempt_count=0, cred_count=0,
                                                                   detected_arch='', os_family='posix')]
        """
        response = self._session.get(self._api_url + self._endpoints.hosts + '?workspace=' + workspace)
        return self._check_get_response(response=response, dataclass_type=Msf.Host)

    def get_services(self, workspace: str = 'default') -> Union[None, List[Msf.Service]]:
        """
        Get services from MSF workspace
        @param workspace: MSF workspace name string, example: "default"
        @return: None if error or List of services example:
        [Msf.Service(id=355, workspace=None,
                     host=Msf.Host(id=291, workspace=None, created_at='2021-04-15T13:45:11.462Z',
                                   address='192.168.1.1', mac='00:11:22:33:44:55', comm='unittest',
                                   name='unit.test.com', state='alive', os_name='linux', os_flavor='test',
                                   os_sp='test', os_lang='English', arch='x86', workspace_id=261,
                                   updated_at='2021-04-15T13:45:11.462Z', purpose='device',
                                   info='Host for unit tests', comments='Host for unit tests',
                                   scope='unit tests scope', virtual_host='unittest', note_count=1,
                                   vuln_count=1, service_count=1, host_detail_count=0, exploit_attempt_count=0,
                                   cred_count=0, detected_arch='', os_family='posix'),
                     host_id=291, created_at='2021-04-15T13:45:11.577Z',
                     port=12345, proto='tcp', state='open', name='http',
                     updated_at='2021-04-15T13:45:11.577Z', info='Unit test')]
        """
        response = self._session.get(self._api_url + self._endpoints.services + '?workspace=' + workspace)
        return self._check_get_response(response=response, dataclass_type=Msf.Service)

    def get_vulns(self, workspace: str = 'default') -> Union[None, List[Msf.Vuln]]:
        """
        Get vulnerabilities from MSF workspace
        @param workspace: MSF workspace name string, example: "default"
        @return: None if error or List of vulnerabilities example:
        [Msf.Vuln(id=282, workspace=None,
                  host=Msf.Host(id=293, workspace=None, created_at='2021-04-15T13:49:34.467Z',
                                address='192.168.1.1', mac='00:11:22:33:44:55', comm='unittest',
                                name='unit.test.com', state='alive', os_name='linux', os_flavor='test',
                                os_sp='test', os_lang='English', arch='x86', workspace_id=263,
                                updated_at='2021-04-15T13:49:34.467Z', purpose='device',
                                info='Host for unit tests', comments='Host for unit tests',
                                scope='unit tests scope', virtual_host='unittest', note_count=1,
                                vuln_count=1, service_count=1, host_detail_count=0, exploit_attempt_count=0,
                                cred_count=0, detected_arch='', os_family='posix'),
                  host_id=293, port=-1, service_id=357,
                  created_at='2021-04-15T13:49:34.805Z',
                  name='Unit test vuln name',
                  updated_at='2021-04-15T13:49:34.805Z',
                  info='Unit test vuln info', exploited_at=None,
                  vuln_detail_count=0, vuln_attempt_count=0,
                  origin_id=None, origin_type=None,
                  refs=[{'id': 29,
                         'ref_id': None,
                         'created_at': '2021-04-15T12:48:48.868Z',
                         'name': 'CVE-2020-2020',
                         'updated_at': '2021-04-15T12:48:48.868Z'},
                        {'id': 30,
                         'ref_id': None,
                         'created_at': '2021-04-15T12:48:48.939Z',
                         'name': 'URL-https://unit.test.com/vuln',
                         'updated_at': '2021-04-15T12:48:48.939Z'}],
                  module_refs=[])]
        """
        response = self._session.get(self._api_url + self._endpoints.vulns + '?workspace=' + workspace)
        return self._check_get_response(response=response, dataclass_type=Msf.Vuln)

    def get_loots(self, workspace: str = 'default') -> Union[None, List[Msf.Loot]]:
        """
        Get loots from MSF workspace
        @param workspace: MSF workspace name string, example: "default"
        @return: None if error or List of loots example:
        [Msf.Loot(id=271, workspace=None, workspace_id=294,
                  host=Msf.Host(id=324, workspace=None, created_at='2021-04-15T15:22:46.627Z',
                                address='192.168.1.1', mac='00:11:22:33:44:55', comm='unittest',
                                name='unit.test.com', state='alive', os_name='linux', os_flavor='test',
                                os_sp='test', os_lang='English', arch='x86', workspace_id=294,
                                updated_at='2021-04-15T15:22:46.627Z', purpose='device',
                                info='Host for unit tests', comments='Host for unit tests',
                                scope='unit tests scope', virtual_host='unittest', note_count=1,
                                vuln_count=1, service_count=1, host_detail_count=0,
                                exploit_attempt_count=0, cred_count=0, detected_arch='',
                                os_family='posix'),
                 host_id=324, port=-1, service_id=None, created_at='2021-04-15T15:23:10.806Z',
                 updated_at='2021-04-15T15:23:10.806Z', ltype='unit.test.type',
                 path='/home/user/.msf4/loot/c4b3f2d85fdc44ac9271-path.txt',
                 data='dGVzdA==', content_type='text/plain',
                 name='/tmp/unit.test', info='Unit test file',
                 module_run_id=None)]
        """
        response = self._session.get(self._api_url + self._endpoints.loots + '?workspace=' + workspace)
        return self._check_get_response(response=response, dataclass_type=Msf.Loot)

    def get_notes(self, workspace: str = 'default') -> Union[None, List[Msf.Note]]:
        """
        Get notes from MSF workspace
        @param workspace: MSF workspace name string, example: "default"
        @return: None if error or List of notes example:
        [Msf.Note(id=603, workspace=None, workspace_id=304,
                  host=Msf.Host(id=334, workspace=None, created_at='2021-04-15T16:04:52.473Z',
                                address='192.168.1.1', mac='00:11:22:33:44:55', comm='unittest', name='unit.test.com',
                                state='alive', os_name='linux', os_flavor='test', os_sp='test', os_lang='English',
                                arch='x86', workspace_id=304, updated_at='2021-04-15T16:04:52.473Z', purpose='device',
                                info='Host for unit tests', comments='Host for unit tests', scope='unit tests scope',
                                virtual_host='unittest', note_count=1, vuln_count=1, service_count=1,
                                host_detail_count=0, exploit_attempt_count=0, cred_count=0, detected_arch='',
                                os_family='posix'),
                  host_id=334,
                  service_id=None,
                  created_at='2021-04-15T16:04:52.969Z',
                  updated_at='2021-04-15T16:04:52.969Z',
                  ntype='host.comments',
                  data='Unit test host comment',
                  critical=None, seen=None)]
        """
        response = self._session.get(self._api_url + self._endpoints.notes + '?workspace=' + workspace)
        return self._check_get_response(response=response, dataclass_type=Msf.Note)

    def get_creds(self, workspace: str = 'default') -> Union[None, List[Msf.Cred]]:
        """
        Get credentials from MSF workspace
        @param workspace: MSF workspace name string, example: "default"
        @return: None if error or List of credentials example:
        [Msf.Cred(id=303, workspace_id=328, username=None, private_data=None, private_type=None,
                  jtr_format=None, address=None, port=-1, service_name=None, protocol=None,
                  origin_type='Metasploit::Credential::Origin::Service', module_fullname=None,
                  created_at='2021-04-15T18:23:58.893Z', updated_at='2021-04-15T18:23:58.893Z',
                  origin_id=318, private_id=3, public_id=4, realm_id=None, logins_count=1,
                  logins=[Msf.Login(id=194, workspace_id=-1, core_id=303, service_id=422,
                                    last_attempted_at='2021-01-01T11:11:11.111Z', address=None,
                                    service_name='ssh', port=-1, protocol='tcp', status='Successful',
                                    access_level='admin', public=None, private=None,
                                    created_at='2021-04-15T18:23:59.027Z',
                                    updated_at='2021-04-15T18:23:59.027Z')],
                  public=Msf.Public(id=4,
                                    username='UnitTestUser',
                                    created_at='2021-04-15T18:17:38.991Z',
                                    updated_at='2021-04-15T18:17:38.991Z',
                                    type='Metasploit::Credential::Username'),
                  private=Msf.Private(id=3,
                                      data='UnitTestPassword',
                                      created_at='2021-04-15T18:17:38.932Z',
                                      updated_at='2021-04-15T18:17:38.932Z',
                                      jtr_format=None,
                                      type='Metasploit::Credential::Password'),
                 origin=Msf.Origin(id=318,
                                   service_id=422,
                                   module_full_name='auxiliary/scanner/http/http_login',
                                   created_at='2021-04-15T18:23:58.873Z',
                                   updated_at='2021-04-15T18:23:58.873Z',
                                   type='Metasploit::Credential::Origin::Service'))]
        """
        response = self._session.get(self._api_url + self._endpoints.creds + '?workspace=' + workspace)
        return self._check_get_response(response=response, dataclass_type=Msf.Cred)

    def get_logins(self) -> Union[None, List[Msf.Login]]:
        """
        Get MSF logins list
        @return: None if error or list of logins example:
        [Msf.Login(id=7, core_id=117, service_id=131, last_attempted_at='2021-04-12T17:19:46.799Z',
                   address=None, service_name='ssh', port=-1, protocol='tcp', status='Successful',
                   access_level=None, public=None, private=None, created_at='2021-04-12T17:19:49.950Z',
                   updated_at='2021-04-12T17:19:49.950Z')]
        """
        response = self._session.get(self._api_url + self._endpoints.logins)
        return self._check_get_response(response=response, dataclass_type=Msf.Login)

    def get_all_data(self, workspace: str = 'default') -> MsfData:
        """
        Get all MSF data in workspace
        @param workspace: MSF workspace name string, example: "default"
        @return: None if error or all MSF data in workspace
        """
        msf_data = MsfData()
        msf_data.workspace = workspace
        msf_data.workspaces = self.get_workspaces()
        msf_data.hosts = self.get_hosts(workspace)
        msf_data.services = self.get_services(workspace)
        msf_data.vulns = self.get_vulns(workspace)
        msf_data.loots = self.get_loots(workspace)
        msf_data.notes = self.get_notes(workspace)
        msf_data.creds = self.get_creds(workspace)
        msf_data.logins = self.get_logins()
        return msf_data

    def get_workspace_id_by_name(self, workspace_name: str = 'default') -> Union[int, None]:
        """
        Get MSF workspace ID by name
        @param workspace_name: MSF workspace name string, example: "default"
        @return: None if error or MSF workspace ID integer, example: 123
        """
        workspaces = self.get_workspaces()
        for workspace in workspaces:
            if workspace.name == workspace_name:
                return workspace.id
        return None

    def get_workspace_by_id(self, workspace_id: int = 1) -> Union[None, Msf.Workspace]:
        """
        Get MSF workspace by ID
        @param workspace_id: MSF workspace ID integer, example: 1
        @return: None if error or Host, example: Msf.Workspace(id=1, name='default',
                                                               created_at='2021-04-07T16:34:01.279Z',
                                                               updated_at='2021-04-07T16:34:01.279Z',
                                                               boundary=None, description=None, owner_id=None,
                                                               limit_to_network=False, import_fingerprint=False)
        """
        workspaces: List[Msf.Workspace] = self.get_workspaces()
        for workspace in workspaces:
            if workspace.id == workspace_id:
                return workspace
        return None

    def get_host_by_id(self, workspace: str = 'default',
                       host_id: int = 1) -> Union[None, Msf.Host]:
        """
        Get MSF host information by ID
        @param workspace: MSF workspace name string, example: "default"
        @param host_id: MSF host ID integer, example: 1
        @return: None if error or Host, example: Msf.Host(id=282, workspace=None,
                                                          created_at='2021-04-15T12:21:05.566Z',
                                                          address='192.168.1.1', mac='00:11:22:33:44:55',
                                                          comm='unittest', name='unit.test.com', state='alive',
                                                          os_name='linux', os_flavor='test', os_sp='test',
                                                          os_lang='English', arch='x86', workspace_id=252,
                                                          updated_at='2021-04-15T12:21:05.566Z', purpose='device',
                                                          info='Host for unit tests', comments='Host for unit tests',
                                                          scope='unit tests scope', virtual_host='unittest',
                                                          note_count=1, vuln_count=1, service_count=1,
                                                          host_detail_count=0, exploit_attempt_count=0,
                                                          cred_count=0, detected_arch='', os_family='posix')
        """
        hosts: List[Msf.Host] = self.get_hosts(workspace=workspace)
        for host in hosts:
            if host.id == host_id:
                return host
        return None

    def get_service_by_id(self, workspace: str = 'default',
                          service_id: int = 1) -> Union[None, Msf.Service]:
        """
        Get MSF service information by ID
        @param workspace: MSF workspace name string, example: "default"
        @param service_id: MSF service ID integer, example: 1
        @return: None if error or Service, example:
        Msf.Service(id=355, workspace=None,
                     host=Msf.Host(id=291, workspace=None, created_at='2021-04-15T13:45:11.462Z',
                                   address='192.168.1.1', mac='00:11:22:33:44:55', comm='unittest',
                                   name='unit.test.com', state='alive', os_name='linux', os_flavor='test',
                                   os_sp='test', os_lang='English', arch='x86', workspace_id=261,
                                   updated_at='2021-04-15T13:45:11.462Z', purpose='device',
                                   info='Host for unit tests', comments='Host for unit tests',
                                   scope='unit tests scope', virtual_host='unittest', note_count=1,
                                   vuln_count=1, service_count=1, host_detail_count=0, exploit_attempt_count=0,
                                   cred_count=0, detected_arch='', os_family='posix'),
                     host_id=291, created_at='2021-04-15T13:45:11.577Z',
                     port=12345, proto='tcp', state='open', name='http',
                     updated_at='2021-04-15T13:45:11.577Z', info='Unit test')
        """
        services: List[Msf.Service] = self.get_services(workspace=workspace)
        for service in services:
            if service.id == service_id:
                return service
        return None

    def get_vuln_by_id(self, workspace: str = 'default',
                       vuln_id: int = 1) -> Union[None, Msf.Vuln]:
        """
        Get MSF vulnerability information by ID
        @param workspace: MSF workspace name string, example: "default"
        @param vuln_id: MSF vulnerability ID integer, example: 1
        @return: None if error or Service, example:
        Msf.Vuln(id=282, workspace=None,
                  host=Msf.Host(id=293, workspace=None, created_at='2021-04-15T13:49:34.467Z',
                                address='192.168.1.1', mac='00:11:22:33:44:55', comm='unittest',
                                name='unit.test.com', state='alive', os_name='linux', os_flavor='test',
                                os_sp='test', os_lang='English', arch='x86', workspace_id=263,
                                updated_at='2021-04-15T13:49:34.467Z', purpose='device',
                                info='Host for unit tests', comments='Host for unit tests',
                                scope='unit tests scope', virtual_host='unittest', note_count=1,
                                vuln_count=1, service_count=1, host_detail_count=0, exploit_attempt_count=0,
                                cred_count=0, detected_arch='', os_family='posix'),
                  host_id=293, port=-1, service_id=357,
                  created_at='2021-04-15T13:49:34.805Z',
                  name='Unit test vuln name',
                  updated_at='2021-04-15T13:49:34.805Z',
                  info='Unit test vuln info', exploited_at=None,
                  vuln_detail_count=0, vuln_attempt_count=0,
                  origin_id=None, origin_type=None,
                  refs=[{'id': 29,
                         'ref_id': None,
                         'created_at': '2021-04-15T12:48:48.868Z',
                         'name': 'CVE-2020-2020',
                         'updated_at': '2021-04-15T12:48:48.868Z'},
                        {'id': 30,
                         'ref_id': None,
                         'created_at': '2021-04-15T12:48:48.939Z',
                         'name': 'URL-https://unit.test.com/vuln',
                         'updated_at': '2021-04-15T12:48:48.939Z'}],
                  module_refs=[])
        """
        vulns: List[Msf.Vuln] = self.get_vulns(workspace=workspace)
        for vuln in vulns:
            if vuln.id == vuln_id:
                return vuln
        return None

    def get_loot_by_id(self, workspace: str = 'default',
                       loot_id: int = 1) -> Union[None, Msf.Loot]:
        """
        Get MSF loot information by ID
        @param workspace: MSF workspace name string, example: "default"
        @param loot_id: MSF loot ID integer, example: 1
        @return: None if error or Loot, example:
        Msf.Loot(id=271, workspace=None, workspace_id=294,
                 host=Msf.Host(id=324, workspace=None, created_at='2021-04-15T15:22:46.627Z',
                                address='192.168.1.1', mac='00:11:22:33:44:55', comm='unittest',
                                name='unit.test.com', state='alive', os_name='linux', os_flavor='test',
                                os_sp='test', os_lang='English', arch='x86', workspace_id=294,
                                updated_at='2021-04-15T15:22:46.627Z', purpose='device',
                                info='Host for unit tests', comments='Host for unit tests',
                                scope='unit tests scope', virtual_host='unittest', note_count=1,
                                vuln_count=1, service_count=1, host_detail_count=0,
                                exploit_attempt_count=0, cred_count=0, detected_arch='',
                                os_family='posix'),
                 host_id=324, port=-1, service_id=None, created_at='2021-04-15T15:23:10.806Z',
                 updated_at='2021-04-15T15:23:10.806Z', ltype='unit.test.type',
                 path='/home/user/.msf4/loot/c4b3f2d85fdc44ac9271-path.txt',
                 data='dGVzdA==', content_type='text/plain',
                 name='/tmp/unit.test', info='Unit test file',
                 module_run_id=None)
        """
        loots: List[Msf.Loot] = self.get_loots(workspace=workspace)
        for loot in loots:
            if loot.id == loot_id:
                return loot
        return None

    def get_note_by_id(self, workspace: str = 'default',
                       note_id: int = 1) -> Union[None, Msf.Note]:
        """
        Get MSF note information by ID
        @param workspace: MSF workspace name string, example: "default"
        @param note_id: MSF loot ID integer, example: 1
        @return: None if error or Note, example:
        Msf.Note(id=603, workspace=None, workspace_id=304,
                  host=Msf.Host(id=334, workspace=None, created_at='2021-04-15T16:04:52.473Z',
                                address='192.168.1.1', mac='00:11:22:33:44:55', comm='unittest', name='unit.test.com',
                                state='alive', os_name='linux', os_flavor='test', os_sp='test', os_lang='English',
                                arch='x86', workspace_id=304, updated_at='2021-04-15T16:04:52.473Z', purpose='device',
                                info='Host for unit tests', comments='Host for unit tests', scope='unit tests scope',
                                virtual_host='unittest', note_count=1, vuln_count=1, service_count=1,
                                host_detail_count=0, exploit_attempt_count=0, cred_count=0, detected_arch='',
                                os_family='posix'),
                  host_id=334,
                  service_id=None,
                  created_at='2021-04-15T16:04:52.969Z',
                  updated_at='2021-04-15T16:04:52.969Z',
                  ntype='host.comments',
                  data='Unit test host comment',
                  critical=None, seen=None)
        """
        notes: List[Msf.Note] = self.get_notes(workspace=workspace)
        for note in notes:
            if note.id == note_id:
                return note
        return None

    def get_cred_by_id(self, workspace: str = 'default',
                       cred_id: int = 1) -> Union[None, Msf.Cred]:
        """
        Get MSF cred by ID
        @param workspace: MSF workspace name string, example: "default"
        @param cred_id: MSF credential ID integer, example: 1
        @return: None if error or Cred, example:
        Msf.Cred(id=303, workspace_id=328, username=None, private_data=None, private_type=None,
                  jtr_format=None, address=None, port=-1, service_name=None, protocol=None,
                  origin_type='Metasploit::Credential::Origin::Service', module_fullname=None,
                  created_at='2021-04-15T18:23:58.893Z', updated_at='2021-04-15T18:23:58.893Z',
                  origin_id=318, private_id=3, public_id=4, realm_id=None, logins_count=1,
                  logins=[Msf.Login(id=194, workspace_id=-1, core_id=303, service_id=422,
                                    last_attempted_at='2021-01-01T11:11:11.111Z', address=None,
                                    service_name='ssh', port=-1, protocol='tcp', status='Successful',
                                    access_level='admin', public=None, private=None,
                                    created_at='2021-04-15T18:23:59.027Z',
                                    updated_at='2021-04-15T18:23:59.027Z')],
                  public=Msf.Public(id=4,
                                    username='UnitTestUser',
                                    created_at='2021-04-15T18:17:38.991Z',
                                    updated_at='2021-04-15T18:17:38.991Z',
                                    type='Metasploit::Credential::Username'),
                  private=Msf.Private(id=3,
                                      data='UnitTestPassword',
                                      created_at='2021-04-15T18:17:38.932Z',
                                      updated_at='2021-04-15T18:17:38.932Z',
                                      jtr_format=None,
                                      type='Metasploit::Credential::Password'),
                 origin=Msf.Origin(id=318,
                                   service_id=422,
                                   module_full_name='auxiliary/scanner/http/http_login',
                                   created_at='2021-04-15T18:23:58.873Z',
                                   updated_at='2021-04-15T18:23:58.873Z',
                                   type='Metasploit::Credential::Origin::Service'))
        """
        creds: List[Msf.Cred] = self.get_creds(workspace=workspace)
        for cred in creds:
            if cred.id == cred_id:
                return cred
        return None

    def get_login_by_id(self, login_id: int = 1) -> Union[None, Msf.Login]:
        """
        Get MSF workspace by ID
        @param login_id: MSF login ID integer, example: 1
        @return: None if error or Host, example:
        Msf.Login(id=7, core_id=117, service_id=131, last_attempted_at='2021-04-12T17:19:46.799Z',
                   address=None, service_name='ssh', port=-1, protocol='tcp', status='Successful',
                   access_level=None, public=None, private=None, created_at='2021-04-12T17:19:49.950Z',
                   updated_at='2021-04-12T17:19:49.950Z')
        """
        logins: List[Msf.Login] = self.get_logins()
        for login in logins:
            if login.id == login_id:
                return login
        return None

    # POST methods

    @staticmethod
    def _dataclass_to_dict(dataclass_object: dataclass) -> Dict:
        """
        Make dictionary for json data in POST requests
        :param dataclass_object: Dataclass object
        :return: Dictionary
        """
        dictionary: Dict = dataclass_object.__dict__.copy()

        if isinstance(dataclass_object, Msf.Host):
            if 'host' in dictionary:
                if dictionary['host'] is None and dictionary['address'] is not None:
                    dictionary['host'] = dataclass_object.address
            del (dictionary['address'])

        if isinstance(dataclass_object, Msf.Login):
            dictionary['core'] = {'id': dataclass_object.core_id}
            del (dictionary['core_id'])
            del (dictionary['public'])
            del (dictionary['private'])

        if isinstance(dataclass_object, Msf.Loot):
            if dataclass_object.port == -1:
                dictionary['port'] = None
            if dataclass_object.path is None:
                dictionary['path'] = 'path'

        if isinstance(dataclass_object, Msf.Note):
            if dataclass_object.port == -1:
                dictionary['port'] = None
            if dataclass_object.vuln_id == -1:
                dictionary['vuln_id'] = None

        if isinstance(dataclass_object, Msf.Cred):
            if dataclass_object.origin_type is None:
                dictionary['origin_type'] = 'service'

        if 'workspace_id' in dictionary and 'workspace' in dictionary:
            del (dictionary['workspace_id'])

        if 'created_at' in dictionary: del (dictionary['created_at'])
        if 'cred_count' in dictionary: del (dictionary['cred_count'])
        if 'exploit_attempt_count' in dictionary: del (dictionary['exploit_attempt_count'])
        if 'exploited_at' in dictionary: del (dictionary['exploited_at'])
        if 'host_detail_count' in dictionary: del (dictionary['host_detail_count'])
        if 'host_id' in dictionary: del (dictionary['host_id'])
        if 'id' in dictionary: del (dictionary['id'])
        if 'logins' in dictionary: del (dictionary['logins'])
        if 'logins_count' in dictionary: del (dictionary['logins_count'])
        if 'module_refs' in dictionary: del (dictionary['module_refs'])
        if 'module_run_id' in dictionary: del (dictionary['module_run_id'])
        if 'note_count' in dictionary: del (dictionary['note_count'])
        if 'origin' in dictionary: del (dictionary['origin'])
        if 'origin_id' in dictionary: del (dictionary['origin_id'])
        if 'owner_id' in dictionary: del (dictionary['owner_id'])
        if 'private' in dictionary: del (dictionary['private'])
        if 'private_id' in dictionary: del (dictionary['private_id'])
        if 'public' in dictionary: del (dictionary['public'])
        if 'public_id' in dictionary: del (dictionary['public_id'])
        if 'realm_id' in dictionary: del (dictionary['realm_id'])
        if 'service_count' in dictionary: del (dictionary['service_count'])
        if 'service_id' in dictionary: del (dictionary['service_id'])
        if 'updated_at' in dictionary: del (dictionary['updated_at'])
        if 'vuln_attempt_count' in dictionary: del (dictionary['vuln_attempt_count'])
        if 'vuln_count' in dictionary: del (dictionary['vuln_count'])
        if 'vuln_detail_count' in dictionary: del (dictionary['vuln_detail_count'])

        return dictionary

    def create_workspace(self, workspace: Msf.Workspace) -> Union[None, int]:
        """
        Create workspace
        :param workspace: Workspace, example: [Msf.Workspace(id=-1, name='my_cool_workspace',
                                                             created_at=None, updated_at=None,
                                                             boundary='10.10.1.1-50,10.10.1.100,10.10.2.0/24',
                                                             description='My cool workspace',
                                                             owner_id=None, limit_to_network=False,
                                                             import_fingerprint=False)]
        :return: None if error or created workspace id, example: 123
        """
        response = self._session.post(self._api_url + self._endpoints.workspaces,
                                      json=self._dataclass_to_dict(workspace))
        return self._check_create_response(response)

    def create_host(self, host: Msf.Host) -> Union[None, int]:
        """
        Create host in MSF workspace
        @param host: Host, example - Msf.Host(id=-1, workspace='unit_test_workspace',
                                              created_at=None, address='1.1.1.1', mac='00:11:22:33:44:55',
                                              comm='unittest', name='unit.test.com', state='alive', os_name='linux',
                                              os_flavor='test', os_sp='test', os_lang='English', arch='x86',
                                              workspace_id=-1, updated_at=None, purpose='device',
                                              info='Host for unit tests', comments='Host for unit tests',
                                              scope='unit tests scope', virtual_host='unittest', note_count=0,
                                              vuln_count=0, service_count=0, host_detail_count=0,
                                              exploit_attempt_count=0, cred_count=0, detected_arch=None,
                                              os_family='posix')
        @return: Created host id or None if error
        """
        response = self._session.post(self._api_url + self._endpoints.hosts,
                                      json=self._dataclass_to_dict(host))
        return self._check_create_response(response)

    def create_hosts(self, hosts: List[Msf.Host]) -> bool:
        """
        Create hosts in MSF workspace
        @param hosts: Hosts list, example - [Msf.Host(id=-1, workspace='unit_test_workspace',
                                              created_at=None, address='1.1.1.1', mac='00:11:22:33:44:55',
                                              comm='unittest', name='unit.test.com', state='alive', os_name='linux',
                                              os_flavor='test', os_sp='test', os_lang='English', arch='x86',
                                              workspace_id=-1, updated_at=None, purpose='device',
                                              info='Host for unit tests', comments='Host for unit tests',
                                              scope='unit tests scope', virtual_host='unittest', note_count=0,
                                              vuln_count=0, service_count=0, host_detail_count=0,
                                              exploit_attempt_count=0, cred_count=0, detected_arch=None,
                                              os_family='posix')]
        @return: True if success or False if error
        """
        for host in hosts:
            if self.create_host(host=host) is None:
                return False
        return True

    def create_service(self, service: Msf.Service) -> Union[None, int]:
        """
        Create service in MSF workspace
        @param service: Service, example - Msf.Service(id=-1, workspace='unit_test_workspace',
                                                       host='192.168.1.1', host_id=-1,
                                                       created_at=None, port=12345, proto='tcp',
                                                       state='open', name='http', updated_at=None,
                                                       info='Unit test')
        @return: Created service id or None if error
        """
        response = self._session.post(self._api_url + self._endpoints.services,
                                      json=self._dataclass_to_dict(service))
        return self._check_create_response(response)

    def create_services(self, services: List[Msf.Service]) -> bool:
        """
        Create services in MSF workspace
        @param services: Services list, example - [Msf.Service(id=-1, workspace='unit_test_workspace',
                                                       host='192.168.1.1', host_id=-1,
                                                       created_at=None, port=12345, proto='tcp',
                                                       state='open', name='http', updated_at=None,
                                                       info='Unit test')]
        @return: True if success or False if error
        """
        for service in services:
            if self.create_service(service=service) is None:
                return False
        return True

    def create_vuln(self, vuln: Msf.Vuln) -> Union[None, int]:
        """
        Create vuln in MSF workspace
        @param vuln: Vuln, example - Msf.Vuln(id=-1, workspace='unit_test_workspace', host='192.168.1.1',
                                              host_id=-1, port=12345, service_id=-1, created_at=None,
                                              name='Unit test vuln name', updated_at=None, info='Unit test vuln info',
                                              exploited_at=None, vuln_detail_count=0, vuln_attempt_count=0,
                                              origin_id=None, origin_type=None,
                                              refs=['CVE-2020-2020', 'URL-https://unit.test.com/vuln'],
                                              module_refs=None)
        @return: Created vuln id or None if error
        """
        response = self._session.post(self._api_url + self._endpoints.vulns,
                                      json=self._dataclass_to_dict(vuln))
        return self._check_create_response(response)

    def create_vulns(self, vulns: List[Msf.Vuln]) -> bool:
        """
        Create vulns in MSF workspace
        @param vulns: Vulns list, example - [Msf.Vuln(id=-1, workspace='unit_test_workspace', host='192.168.1.1',
                                              host_id=-1, port=12345, service_id=-1, created_at=None,
                                              name='Unit test vuln name', updated_at=None, info='Unit test vuln info',
                                              exploited_at=None, vuln_detail_count=0, vuln_attempt_count=0,
                                              origin_id=None, origin_type=None,
                                              refs=['CVE-2020-2020', 'URL-https://unit.test.com/vuln'],
                                              module_refs=None)]
        @return: True if success or False if error
        """
        for vuln in vulns:
            if self.create_vuln(vuln=vuln) is None:
                return False
        return True

    def create_loot(self, loot: Msf.Loot) -> Union[None, int]:
        """
        Create loot in MSF workspace
        @param loot: Loot, example - Msf.Loot(id=-1, workspace='unit_test_workspace', workspace_id=-1,
                                              host='192.168.1.1', host_id=-1, port=12345, service_id=-1,
                                              created_at=None, updated_at=None, ltype='unit.test.type',
                                              path='path.txt', data='dGVzdA==', content_type='text/plain',
                                              name='/tmp/unit.test', info='Unit test file', module_run_id=None)
        @return: Created loot id or None if error
        """
        response = self._session.post(self._api_url + self._endpoints.loots,
                                      json=self._dataclass_to_dict(loot))
        return self._check_create_response(response)

    def create_loots(self, loots: List[Msf.Loot]) -> bool:
        """
        Create loots in MSF workspace
        @param loots: Loots list, example - [Msf.Loot(id=-1, workspace='unit_test_workspace', workspace_id=-1,
                                              host='192.168.1.1', host_id=-1, port=12345, service_id=-1,
                                              created_at=None, updated_at=None, ltype='unit.test.type',
                                              path='path.txt', data='dGVzdA==', content_type='text/plain',
                                              name='/tmp/unit.test', info='Unit test file', module_run_id=None)]
        @return: True if success or False if error
        """
        for loot in loots:
            if self.create_loot(loot=loot) is None:
                return False
        return True

    def create_note(self, note: Msf.Note) -> Union[None, int]:
        """
        Create note in MSF workspace
        @param note: Note, example - Msf.Note(id=-1, workspace='unit_test_workspace', workspace_id=-1,
                                              host='192.168.1.1', host_id=-1, port=-1, service_id=-1,
                                              created_at=None, updated_at=None, ntype='host.comments',
                                              data='Unit test host comment', critical=True, seen=True)
        @return: Created note id or None if error
        """
        response = self._session.post(self._api_url + self._endpoints.notes,
                                      json=self._dataclass_to_dict(note))
        return self._check_create_response(response)

    def create_notes(self, notes: List[Msf.Note]) -> bool:
        """
        Create notes in MSF workspace
        @param notes: Notes list, example - [Msf.Note(id=-1, workspace='unit_test_workspace', workspace_id=-1,
                                              host='192.168.1.1', host_id=-1, port=-1, service_id=-1,
                                              created_at=None, updated_at=None, ntype='host.comments',
                                              data='Unit test host comment', critical=True, seen=True)]
        @return: True if success or False if error
        """
        for note in notes:
            if self.create_note(note=note) is None:
                return False
        return True

    def create_cred(self, cred: Msf.Cred) -> Union[None, int]:
        """
        Create cred in MSF workspace
        @param cred: Cred, example - Msf.Cred(id=-1, workspace_id=327, username='UnitTestUser',
                                              private_data='UnitTestPassword', private_type='password',
                                              jtr_format=None, address='192.168.1.1', port=12345,
                                              service_name='http', protocol='tcp', origin_type='service',
                                              module_fullname='auxiliary/scanner/http/http_login',
                                              created_at=None, updated_at=None, origin_id=-1,
                                              private_id=-1, public_id=-1, realm_id=-1, logins_count=-1,
                                              logins=None, public=None, private=None, origin=None)
        @return: Created cred id or None if error
        """
        response = self._session.post(self._api_url + self._endpoints.creds,
                                      json=self._dataclass_to_dict(cred))
        return self._check_create_response(response)

    def create_creds(self, creds: List[Msf.Cred]) -> bool:
        """
        Create creds in MSF workspace
        @param creds: Creds list, example - [Msf.Cred(id=-1, workspace_id=327, username='UnitTestUser',
                                                      private_data='UnitTestPassword', private_type='password',
                                                      jtr_format=None, address='192.168.1.1', port=12345,
                                                      service_name='http', protocol='tcp', origin_type='service',
                                                      module_fullname='auxiliary/scanner/http/http_login',
                                                      created_at=None, updated_at=None, origin_id=-1,
                                                      private_id=-1, public_id=-1, realm_id=-1, logins_count=-1,
                                                      logins=None, public=None, private=None, origin=None)]
        @return: True if success or False if error
        """
        for cred in creds:
            if self.create_cred(cred=cred) is None:
                return False
        return True

    def create_login(self, login: Msf.Login) -> Union[None, int]:
        """
        Create cred in MSF workspace
        @param login: Login, example - Msf.Login(id=-1, workspace=None, workspace_id=317, core_id=293,
                                                 service_id=-1, last_attempted_at='2021-01-01T11:11:11.111Z',
                                                 address='192.168.1.1', service_name='http',
                                                 port=12345, protocol='tcp', status='Successful',
                                                 access_level='admin', public=None, private=None,
                                                 created_at=None, updated_at=None)
        @return: Created login id or None if error
        """
        response = self._session.post(self._api_url + self._endpoints.logins,
                                      json=self._dataclass_to_dict(login))
        return self._check_create_response(response)

    def create_logins(self, logins: List[Msf.Login]) -> bool:
        """
        Create creds in MSF workspace
        @param logins: Logins info list, example - [Msf.Login(id=-1, workspace=None, workspace_id=317, core_id=293,
                                                         service_id=-1, last_attempted_at='2021-01-01T11:11:11.111Z',
                                                         address='192.168.1.1', service_name='http',
                                                         port=12345, protocol='tcp', status='Successful',
                                                         access_level='admin', public=None, private=None,
                                                         created_at=None, updated_at=None)]
        @return: True if success or False if error
        """
        for login in logins:
            if self.create_login(login=login) is None:
                return False
        return True

    # DELETE methods

    def delete_logins(self, ids: List[int]) -> Union[None, List[Msf.Login]]:
        """
        Delete logins by identifiers
        @param ids: List of logins identifiers, example: [157]
        @return: None if error or List of deleted logins example:
        [Msf.Login(id=7, core_id=117, service_id=131, last_attempted_at='2021-04-12T17:19:46.799Z',
                   address=None, service_name='ssh', port=-1, protocol='tcp', status='Successful',
                   access_level=None, public=None, private=None, created_at='2021-04-12T17:19:49.950Z',
                   updated_at='2021-04-12T17:19:49.950Z')]
        """
        response = self._session.delete(self._api_url + self._endpoints.logins, json={'ids': ids})
        return self._check_delete_response(response=response, dataclass_type=Msf.Login)

    def delete_creds(self, ids: List[int]) -> Union[None, List[Msf.Cred]]:
        """
        Delete credentials by identifiers
        @param ids: List of credentials identifiers, example: [303]
        @return: None if error or List of deleted credentials example:
        [Msf.Cred(id=303, workspace_id=328, username=None, private_data=None, private_type=None,
                  jtr_format=None, address=None, port=-1, service_name=None, protocol=None,
                  origin_type='Metasploit::Credential::Origin::Service', module_fullname=None,
                  created_at='2021-04-15T18:23:58.893Z', updated_at='2021-04-15T18:23:58.893Z',
                  origin_id=318, private_id=3, public_id=4, realm_id=None, logins_count=1,
                  logins=[Msf.Login(id=194, workspace_id=-1, core_id=303, service_id=422,
                                    last_attempted_at='2021-01-01T11:11:11.111Z', address=None,
                                    service_name='ssh', port=-1, protocol='tcp', status='Successful',
                                    access_level='admin', public=None, private=None,
                                    created_at='2021-04-15T18:23:59.027Z',
                                    updated_at='2021-04-15T18:23:59.027Z')],
                  public=Msf.Public(id=4,
                                    username='UnitTestUser',
                                    created_at='2021-04-15T18:17:38.991Z',
                                    updated_at='2021-04-15T18:17:38.991Z',
                                    type='Metasploit::Credential::Username'),
                  private=Msf.Private(id=3,
                                      data='UnitTestPassword',
                                      created_at='2021-04-15T18:17:38.932Z',
                                      updated_at='2021-04-15T18:17:38.932Z',
                                      jtr_format=None,
                                      type='Metasploit::Credential::Password'),
                 origin=Msf.Origin(id=318,
                                   service_id=422,
                                   module_full_name='auxiliary/scanner/http/http_login',
                                   created_at='2021-04-15T18:23:58.873Z',
                                   updated_at='2021-04-15T18:23:58.873Z',
                                   type='Metasploit::Credential::Origin::Service'))]
        """
        response = self._session.delete(self._api_url + self._endpoints.creds, json={'ids': ids})
        return self._check_delete_response(response=response, dataclass_type=Msf.Cred)

    def delete_notes(self, ids: List[int]) -> Union[None, List[Msf.Note]]:
        """
        Delete notes by identifiers
        @param ids: List of notes identifiers, example: [14]
        @return: None if error or List of deleted notes example:
        [Msf.Note(id=603, workspace=None, workspace_id=304,
                  host=Msf.Host(id=334, workspace=None, created_at='2021-04-15T16:04:52.473Z',
                                address='192.168.1.1', mac='00:11:22:33:44:55', comm='unittest', name='unit.test.com',
                                state='alive', os_name='linux', os_flavor='test', os_sp='test', os_lang='English',
                                arch='x86', workspace_id=304, updated_at='2021-04-15T16:04:52.473Z', purpose='device',
                                info='Host for unit tests', comments='Host for unit tests', scope='unit tests scope',
                                virtual_host='unittest', note_count=1, vuln_count=1, service_count=1,
                                host_detail_count=0, exploit_attempt_count=0, cred_count=0, detected_arch='',
                                os_family='posix'),
                  host_id=334,
                  service_id=None,
                  created_at='2021-04-15T16:04:52.969Z',
                  updated_at='2021-04-15T16:04:52.969Z',
                  ntype='host.comments',
                  data='Unit test host comment',
                  critical=None, seen=None)]
        """
        response = self._session.delete(self._api_url + self._endpoints.notes, json={'ids': ids})
        return self._check_delete_response(response=response, dataclass_type=Msf.Note)

    def delete_loots(self, ids: List[int]) -> Union[None, List[Msf.Loot]]:
        """
        Delete loots by identifiers
        @param ids: List of loots identifiers, example: [271]
        @return: None if error or List of deleted loots example:
                [Msf.Loot(id=271, workspace=None, workspace_id=294,
                  host=Msf.Host(id=324, workspace=None, created_at='2021-04-15T15:22:46.627Z',
                                address='192.168.1.1', mac='00:11:22:33:44:55', comm='unittest',
                                name='unit.test.com', state='alive', os_name='linux', os_flavor='test',
                                os_sp='test', os_lang='English', arch='x86', workspace_id=294,
                                updated_at='2021-04-15T15:22:46.627Z', purpose='device',
                                info='Host for unit tests', comments='Host for unit tests',
                                scope='unit tests scope', virtual_host='unittest', note_count=1,
                                vuln_count=1, service_count=1, host_detail_count=0,
                                exploit_attempt_count=0, cred_count=0, detected_arch='',
                                os_family='posix'),
                 host_id=324, port=-1, service_id=None, created_at='2021-04-15T15:23:10.806Z',
                 updated_at='2021-04-15T15:23:10.806Z', ltype='unit.test.type',
                 path='/home/user/.msf4/loot/c4b3f2d85fdc44ac9271-path.txt',
                 data='dGVzdA==', content_type='text/plain',
                 name='/tmp/unit.test', info='Unit test file',
                 module_run_id=None)]
        """
        response = self._session.delete(self._api_url + self._endpoints.loots, json={'ids': ids})
        return self._check_delete_response(response=response, dataclass_type=Msf.Loot)

    def delete_vulns(self, ids: List[int]) -> Union[None, List[Msf.Vuln]]:
        """
        Delete vulnerabilities by identifiers
        @param ids: List of vulnerabilities identifiers, example: [157]
        @return: None if error or List of deleted vulnerabilities example:
        [Msf.Vuln(id=282, workspace=None,
                  host=Msf.Host(id=293, workspace=None, created_at='2021-04-15T13:49:34.467Z',
                                address='192.168.1.1', mac='00:11:22:33:44:55', comm='unittest',
                                name='unit.test.com', state='alive', os_name='linux', os_flavor='test',
                                os_sp='test', os_lang='English', arch='x86', workspace_id=263,
                                updated_at='2021-04-15T13:49:34.467Z', purpose='device',
                                info='Host for unit tests', comments='Host for unit tests',
                                scope='unit tests scope', virtual_host='unittest', note_count=1,
                                vuln_count=1, service_count=1, host_detail_count=0, exploit_attempt_count=0,
                                cred_count=0, detected_arch='', os_family='posix'),
                  host_id=293, port=-1, service_id=357,
                  created_at='2021-04-15T13:49:34.805Z',
                  name='Unit test vuln name',
                  updated_at='2021-04-15T13:49:34.805Z',
                  info='Unit test vuln info', exploited_at=None,
                  vuln_detail_count=0, vuln_attempt_count=0,
                  origin_id=None, origin_type=None,
                  refs=[{'id': 29,
                         'ref_id': None,
                         'created_at': '2021-04-15T12:48:48.868Z',
                         'name': 'CVE-2020-2020',
                         'updated_at': '2021-04-15T12:48:48.868Z'},
                        {'id': 30,
                         'ref_id': None,
                         'created_at': '2021-04-15T12:48:48.939Z',
                         'name': 'URL-https://unit.test.com/vuln',
                         'updated_at': '2021-04-15T12:48:48.939Z'}],
                  module_refs=[])]
        """
        response = self._session.delete(self._api_url + self._endpoints.vulns, json={'ids': ids})
        return self._check_delete_response(response=response, dataclass_type=Msf.Vuln)

    def delete_services(self, ids: List[int]) -> Union[None, List[Msf.Service]]:
        """
        Delete services by identifiers
        @param ids: List of services identifiers, example: [22]
        @return: None if error or List of deleted services example:
        [Msf.Service(id=355, workspace=None,
                     host=Msf.Host(id=291, workspace=None, created_at='2021-04-15T13:45:11.462Z',
                                   address='192.168.1.1', mac='00:11:22:33:44:55', comm='unittest',
                                   name='unit.test.com', state='alive', os_name='linux', os_flavor='test',
                                   os_sp='test', os_lang='English', arch='x86', workspace_id=261,
                                   updated_at='2021-04-15T13:45:11.462Z', purpose='device',
                                   info='Host for unit tests', comments='Host for unit tests',
                                   scope='unit tests scope', virtual_host='unittest', note_count=1,
                                   vuln_count=1, service_count=1, host_detail_count=0, exploit_attempt_count=0,
                                   cred_count=0, detected_arch='', os_family='posix'),
                     host_id=291, created_at='2021-04-15T13:45:11.577Z',
                     port=12345, proto='tcp', state='open', name='http',
                     updated_at='2021-04-15T13:45:11.577Z', info='Unit test')]
        """
        response = self._session.delete(self._api_url + self._endpoints.services, json={'ids': ids})
        return self._check_delete_response(response=response, dataclass_type=Msf.Service)

    def delete_hosts(self, ids: List[int]) -> Union[None, List[Msf.Host]]:
        """
        Delete hosts by identifiers
        @param ids: List of hosts identifiers, example: [157]
        @return: None if error or List of deleted hosts example: [Msf.Host(id=260, workspace=None,
                                                                   created_at='2021-04-15T11:26:33.900Z',
                                                                   address='192.168.1.1',
                                                                   mac='00:11:22:33:44:55',
                                                                   comm='unittest',
                                                                   name='unit.test.com',
                                                                   state='alive',
                                                                   os_name='linux',
                                                                   os_flavor='test',
                                                                   os_sp='test',
                                                                   os_lang='English',
                                                                   arch='x86',
                                                                   workspace_id=230,
                                                                   updated_at='2021-04-15T11:26:33.900Z',
                                                                   purpose='device',
                                                                   info='Host for unit tests',
                                                                   comments='Host for unit tests',
                                                                   scope='unit tests scope',
                                                                   virtual_host='unittest',
                                                                   note_count=1, vuln_count=1,
                                                                   service_count=1, host_detail_count=0,
                                                                   exploit_attempt_count=0, cred_count=0,
                                                                   detected_arch='', os_family='posix')]
        """
        response = self._session.delete(self._api_url + self._endpoints.hosts, json={'ids': ids})
        return self._check_delete_response(response=response, dataclass_type=Msf.Host)

    def delete_workspaces(self, ids: List[int]) -> Union[None, List[Msf.Workspace]]:
        """
        Delete workspaces by identifiers
        @param ids: List of hosts identifiers, example: [157]
        @return: None if error or List of deleted services example: [Msf.Workspace(id=1,
                                                                                 name='default',
                                                                                 created_at='2021-04-07T16:34:01.279Z',
                                                                                 updated_at='2021-04-07T16:34:01.279Z',
                                                                                 boundary=None,
                                                                                 description=None,
                                                                                 owner_id=None,
                                                                                 limit_to_network=False,
                                                                                 import_fingerprint=False)]
        """
        response = self._session.delete(self._api_url + self._endpoints.workspaces, json={'ids': ids})
        return self._check_delete_response(response=response, dataclass_type=Msf.Workspace)

    def delete_workspace(self, workspace_name: str) -> Union[None, Msf.Workspace]:
        """
        Delete workspace by name
        @param workspace_name: Workspace name string, example: 'msf_workspace'
        @return: None if error or List of deleted workspace example: Msf.Workspace(id=1,
                                                                                 name='default',
                                                                                 created_at='2021-04-07T16:34:01.279Z',
                                                                                 updated_at='2021-04-07T16:34:01.279Z',
                                                                                 boundary=None,
                                                                                 description=None,
                                                                                 owner_id=None,
                                                                                 limit_to_network=False,
                                                                                 import_fingerprint=False)
        """
        workspace_id: Union[None, int] = self.get_workspace_id_by_name(workspace_name=workspace_name)
        if workspace_id is None:
            return None
        else:
            return self.delete_workspaces(ids=[workspace_id])[0]


# Main function
def main() -> None:
    # Parse script arguments
    parser: ArgumentParser = ArgumentParser(description='MSF REST API console client')

    # MSF arguments
    parser.add_argument('-u', '--api_url', type=str, help='set MSF REST API server URL', required=True)
    parser.add_argument('-k', '--api_key', type=str, help='set MSF REST API key', required=True)
    parser.add_argument('-w', '--workspace', type=str, help='set MSF Workspace name', default='default')

    # Get DB objects
    parser.add_argument('--get_workspaces', action='store_true', help='get MSF workspaces list')
    parser.add_argument('--get_hosts', action='store_true', help='get MSF hosts list for workspace')
    parser.add_argument('--get_services', action='store_true', help='get MSF services list for workspace')
    parser.add_argument('--get_vulns', action='store_true', help='get MSF vulnerabilities list for workspace')
    parser.add_argument('--get_loots', action='store_true', help='get MSF loots list for workspace')
    parser.add_argument('--get_notes', action='store_true', help='get MSF notes list for workspace')
    parser.add_argument('--get_creds', action='store_true', help='get MSF creds list for workspace')
    parser.add_argument('--get_logins', action='store_true', help='get MSF logins list')
    parser.add_argument('--get_all', action='store_true', help='get MSF all data for workspace')

    # Proxy
    parser.add_argument('-p', '--proxy', type=str, help='Set proxy URL', default=None)
    args = parser.parse_args()

    # Init MsfRestApi
    msf_rest_api: MsfRestApi = MsfRestApi(api_url=args.api_url,
                                          api_key=args.api_key,
                                          proxy=args.proxy)

    # Get DB objects
    if args.get_workspaces:
        for _object in msf_rest_api.get_workspaces():
            if isinstance(_object, Msf.Workspace):
                print(_object)

    if args.get_hosts:
        for _object in msf_rest_api.get_hosts(workspace=args.workspace):
            if isinstance(_object, Msf.Host):
                print(_object)

    if args.get_services:
        for _object in msf_rest_api.get_services(workspace=args.workspace):
            if isinstance(_object, Msf.Service):
                print(_object)

    if args.get_vulns:
        for _object in msf_rest_api.get_vulns(workspace=args.workspace):
            if isinstance(_object, Msf.Vuln):
                print(_object)

    if args.get_loots:
        for _object in msf_rest_api.get_loots(workspace=args.workspace):
            if isinstance(_object, Msf.Loot):
                print(_object)

    if args.get_notes:
        for _object in msf_rest_api.get_notes(workspace=args.workspace):
            if isinstance(_object, Msf.Note):
                print(_object)

    if args.get_creds:
        for _object in msf_rest_api.get_creds(workspace=args.workspace):
            if isinstance(_object, Msf.Cred):
                print(_object)

    if args.get_logins:
        for _object in msf_rest_api.get_logins():
            if isinstance(_object, Msf.Login):
                print(_object)

    if args.get_all:
        msf_data: MsfData = msf_rest_api.get_all_data(workspace=args.workspace)
        print(f'MSF workspace: {msf_data.workspace}')

        print('Workspaces:')
        for _object in msf_data.workspaces:
            print(_object)

        print('Hosts:')
        for _object in msf_data.hosts:
            print(_object)

        print('Services:')
        for _object in msf_data.services:
            print(_object)

        print('Vulnerabilities:')
        for _object in msf_data.vulns:
            print(_object)

        print('Loots:')
        for _object in msf_data.loots:
            print(_object)

        print('Notes:')
        for _object in msf_data.notes:
            print(_object)

        print('Credentials:')
        for _object in msf_data.creds:
            print(_object)

        print('Logins:')
        for _object in msf_data.logins:
            print(_object)
