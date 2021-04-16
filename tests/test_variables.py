# Description
"""
test_msf_api.py: Unit tests for MSF REST API
Author: Vladimir Ivanov
License: MIT
Copyright 2021, Python Metasploit Library
"""

# Import
from typing import Optional
from libmsf.msf import Msf

# Authorship information
__author__ = 'Vladimir Ivanov'
__copyright__ = 'Copyright 2021, Python Metasploit Library'
__credits__ = ['']
__license__ = 'GNU AGPLv3'
__version__ = '0.0.1a'
__maintainer__ = 'Vladimir Ivanov'
__email__ = 'ivanov.vladimir.mail@gmail.com'
__status__ = 'Development'


# Class MsfVariablesForTest
class MsfVariablesForTest:

    api_url: str = 'https://localhost:5443'
    api_key: str = 'cf2dbb7f9d1f92839a84f9c165ee9afef3dd3a3116bc99badf45be4ae5655168c9c2c3c58621b460'
    proxy: Optional[str] = None

    workspace: Msf.Workspace = Msf.Workspace(name='unit_test_workspace',
                                             description='Workspace for unit tests')

    host: Msf.Host = Msf.Host(workspace=workspace.name,
                              address='192.168.1.1',
                              mac='00:11:22:33:44:55',
                              name='unit.test.com',
                              os_name='linux',
                              os_family='posix',
                              os_flavor='test',
                              os_sp='test',
                              os_lang='English',
                              purpose='device',
                              info='Host for unit tests',
                              comments='Host for unit tests',
                              scope='unit tests scope',
                              virtual_host='unittest',
                              arch='x86',
                              state='alive',
                              comm='unittest')

    service: Msf.Service = Msf.Service(workspace=workspace.name,
                                       host=host.address,
                                       port=12345,
                                       proto='tcp',
                                       state='open',
                                       name='http',
                                       info='Unit test')

    vuln: Msf.Vuln = Msf.Vuln(workspace=workspace.name,
                              host=host.address,
                              port=service.port,
                              name='Unit test vuln name',
                              info='Unit test vuln info',
                              refs=['CVE-2020-2020', 'URL-https://unit.test.com/vuln'])

    loot: Msf.Loot = Msf.Loot(workspace=workspace.name,
                              host=host.address,
                              port=service.port,
                              ltype='unit.test.type',
                              data='dGVzdA==',
                              name='/tmp/unit.test',
                              info='Unit test file',
                              content_type='text/plain',
                              path='path.txt')

    note: Msf.Note = Msf.Note(workspace=workspace.name,
                              host=host.address,
                              ntype='host.comments',
                              data='Unit test host comment',
                              critical=True,
                              seen=True)

    login: Msf.Login = Msf.Login(address=host.address,
                                 port=service.port,
                                 last_attempted_at='2021-01-01T11:11:11.111Z',
                                 service_name=service.name,
                                 protocol=service.proto,
                                 status='Successful',
                                 access_level='admin')

    cred: Msf.Cred = Msf.Cred(address=host.address,
                              port=service.port,
                              username='UnitTestUser',
                              private_data='UnitTestPassword',
                              private_type='password',
                              module_fullname='auxiliary/scanner/http/http_login',
                              service_name=service.name,
                              protocol=service.proto,
                              origin_type='service')
