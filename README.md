python-libmsf
===================

[![Site][site-label]][site-link]
[![Required OS][os-label]][os-link]
[![Python3 version][python3-versions-label]][python3-versions-link]
[![License][license-label]][license-link]
[![Version][version-label]][version-link]

[site-label]: https://python-libmsf.github.io/images/labels/site.svg
[site-link]: https://python-libmsf.github.io/
[os-label]: https://python-libmsf.github.io/images/labels/os.svg
[os-link]: https://en.wikipedia.org/wiki/Operating_system
[python3-versions-label]: https://python-libmsf.github.io/images/labels/python3.svg
[python3-versions-link]: https://www.python.org/downloads/release/python-360/
[license-label]: https://python-libmsf.github.io/images/labels/license.svg
[license-link]: https://github.com/python-libmsf/python-libmsf/blob/main/LICENSE
[version-label]: https://python-libmsf.github.io/images/labels/version.svg
[version-link]: https://github.com/python-libmsf/python-libmsf/releases

## Description

libmsf is a python library for working with Metasploit web service and parse Metasploit exported files.

With MsfRestApi you can work with Metasploit REST API objects such as:

 - [Workspaces](#workspaces)
 - [Hosts](#hosts)
 - [Services](#services)
 - [Vulnerabilities](#vulnerabilities)
 - [Loots](#loots)
 - [Notes](#notes)
 - [Credentials](#credentials-and-logins)
 - [Logins](#credentials-and-logins)

MsfRestApi easy to use:

```shell
>>> from libmsf.msf import Msf
>>> from libmsf.rest import MsfRestApi
>>> msf_rest_api = MsfRestApi(api_key='cf2dbb7f9d1f92839a84f9c165ee9afef3dd3a3116bc99badf45be4ae5655168c9c2c3c58621b460', api_url='https://localhost:5443')
>>> workspace: Msf.Workspace = Msf.Workspace(name='test_workspace')
>>> workspace
Msf.Workspace(id=-1, name='test_workspace', created_at=None, updated_at=None, boundary=None, description=None, owner_id=None, limit_to_network=False, import_fingerprint=False)
>>> workspace.id = msf_rest_api.create_workspace(workspace)
>>> msf_rest_api.get_workspace_by_id(workspace.id)
Msf.Workspace(id=197, name='test_workspace', created_at='2021-04-16T11:26:49.900Z', updated_at='2021-04-16T11:26:49.900Z', boundary=None, description=None, owner_id=None, limit_to_network=False, import_fingerprint=False)
```

With MsfParser you can parse Metasploit exported files

MsfParser easy to use:

```shell
>>> from libmsf.msf import MsfData
>>> from libmsf.parser import MsfParser
>>>
>>> msf_parser: MsfParser = MsfParser()
>>> msf_data: MsfData = msf_parser.parse_file(file_name='tests/msf_db_export.xml')
>>> msf_data.workspace
'unit_test_workspace'
>>> msf_data.hosts
[Msf.Host(id=246, workspace='unit_test_workspace', created_at='2021-04-17 14:12:22 UTC', host='None', address='192.168.1.1', mac='00:11:22:33:44:55', comm='unittest', name='unit.test.com', state='alive', os_name='linux', os_flavor='test', os_sp='test', os_lang='English', arch='x86', workspace_id=241, updated_at='2021-04-17 14:12:22 UTC', purpose='device', info='Host for unit tests', comments='Host for unit tests', scope='unit tests scope', virtual_host='unittest', note_count=1, vuln_count=1, service_count=1, host_detail_count=0, exploit_attempt_count=0, cred_count=0, detected_arch='', os_family='posix'), Msf.Host(id=247, workspace='unit_test_workspace', created_at='2021-04-17 14:12:22 UTC', host='None', address='192.168.1.2', mac='00:11:22:33:44:56', comm='unittest2', name='unit.test2.com', state='alive', os_name='linux', os_flavor='test', os_sp='test', os_lang='English', arch='x86', workspace_id=241, updated_at='2021-04-17 14:12:22 UTC', purpose='device', info='Host for unit tests 2', comments='Host for unit tests 2', scope='unit tests scope', virtual_host='unittest', note_count=1, vuln_count=1, service_count=1, host_detail_count=0, exploit_attempt_count=0, cred_count=0, detected_arch='', os_family='posix')]
>>> msf_data.services
[Msf.Service(id=271, workspace='unit_test_workspace', host='192.168.1.1', host_id=246, created_at='2021-04-17 14:12:22 UTC', port=12345, proto='tcp', state='open', name='http', updated_at='2021-04-17 14:12:22 UTC', info='Unit test'), Msf.Service(id=272, workspace='unit_test_workspace', host='192.168.1.2', host_id=247, created_at='2021-04-17 14:12:22 UTC', port=12346, proto='tcp', state='open', name='http', updated_at='2021-04-17 14:12:22 UTC', info='Unit test 2')]
>>> msf_data.vulns
[Msf.Vuln(id=285, workspace='unit_test_workspace', host='192.168.1.1', host_id=246, port=12345, service_id=271, created_at='2021-04-17 14:12:22 UTC', name='Unit test vuln name', updated_at='2021-04-17 14:12:22 UTC', info='Unit test vuln info', exploited_at='', vuln_detail_count=0, vuln_attempt_count=0, origin_id='', origin_type='', refs=['CVE-2020-2020', 'URL-https://unit.test.com/vuln'], module_refs='None'), Msf.Vuln(id=286, workspace='unit_test_workspace', host='192.168.1.2', host_id=247, port=12346, service_id=272, created_at='2021-04-17 14:12:22 UTC', name='Unit test vuln name 2', updated_at='2021-04-17 14:12:22 UTC', info='Unit test vuln info 2', exploited_at='', vuln_detail_count=0, vuln_attempt_count=0, origin_id='', origin_type='', refs=['CVE-2020-2021', 'URL-https://unit.test.com/vuln2'], module_refs='None')]
>>> msf_data.notes
[Msf.Note(id=53, workspace='unit_test_workspace', workspace_id=241, host='192.168.1.1', host_id=246, service_id=-1, vuln_id=-1, port=-1, created_at='2021-04-17 14:12:22 UTC', updated_at='2021-04-17 14:12:22 UTC', ntype='host.comments', data='Unit test host comment', critical=False, seen=False), Msf.Note(id=54, workspace='unit_test_workspace', workspace_id=241, host='192.168.1.2', host_id=247, service_id=-1, vuln_id=-1, port=-1, created_at='2021-04-17 14:12:22 UTC', updated_at='2021-04-17 14:12:22 UTC', ntype='host.comments', data='Unit test host comment 2', critical=False, seen=False)]
```

## Python versions

 - Python 3.6
 - Python 3.7
 - Python 3.8
 - Python 3.9
 - Python 3.10

## Dependencies

 - [requests](https://pypi.org/project/requests/)
 - [urllib3](https://pypi.org/project/urllib3/)

## Installing

libmsf can be installed with [pip](https://pip.pypa.io/en/stable/):
```shell
pip3 install libmsf
```

Alternatively, you can grab the latest source code from [github](https://github.com/python-libmsf/python-libmsf.git):
```shell
git clone https://github.com/python-libmsf/python-libmsf.git
cd python-libmsf
python3 setup.py install
```

## Metasploit web service settings

Metasploit web service wiki: [https://github.com/rapid7/metasploit-framework/wiki/Metasploit-Web-Service](https://github.com/rapid7/metasploit-framework/wiki/Metasploit-Web-Service)

Init Metasploit web service and database: `msfdb init`

Init Metasploit web service: `msfdb --component webservice init`

Start Metasploit web service to listen all network interfaces: `msfdb --component webservice --address 0.0.0.0 start`

<details><summary>Init MSF webservice:</summary>

<pre lang="shell"><code>
$ msfdb --component webservice init
Running the 'init' command for the webservice:
[?] Initial MSF web service account username? [user]: user
[?] Initial MSF web service account password? (Leave blank for random password):
Generating SSL key and certificate for MSF web service
Attempting to start MSF web service...success
MSF web service started and online
Creating MSF web service user user

    ############################################################
    ##              MSF Web Service Credentials               ##
    ##                                                        ##
    ##        Please store these credentials securely.        ##
    ##    You will need them to connect to the webservice.    ##
    ############################################################

MSF web service username: user
MSF web service password: password
MSF web service user API token: cf2dbb7f9d1f92839a84f9c165ee9afef3dd3a3116bc99badf45be4ae5655168c9c2c3c58621b460


MSF web service configuration complete
The web service has been configured as your default data service in msfconsole with the name "local-https-data-service"

If needed, manually reconnect to the data service in msfconsole using the command:
db_connect --token cf2dbb7f9d1f92839a84f9c165ee9afef3dd3a3116bc99badf45be4ae5655168c9c2c3c58621b460 --cert /home/user/.msf4/msf-ws-cert.pem --skip-verify https://localhost:5443

The username and password are credentials for the API account:
https://localhost:5443/api/v1/auth/account

====================================================================
</code></pre>

</details>

Metasploit web service user API token stored in file: `~/.msf4/config`

<details><summary>MSF webservice config:</summary>

<pre lang="shell"><code>
$ cat ~/.msf4/config
[framework/database]
default_db=local-https-data-service

[framework/database/local-https-data-service]
url=https://localhost:5443
cert=/home/user/.msf4/msf-ws-cert.pem
skip_verify=true
api_token=cf2dbb7f9d1f92839a84f9c165ee9afef3dd3a3116bc99badf45be4ae5655168c9c2c3c58621b460
</code></pre>

</details>

Metasploit web service swagger page: `https://localhost:5443/api/v1/api-docs`

## MsfRestApi

### Workspaces

```python
from libmsf.msf import Msf
from libmsf.rest import MsfRestApi
from typing import List

msf_api_key: str = 'cf2dbb7f9d1f92839a84f9c165ee9afef3dd3a3116bc99badf45be4ae5655168c9c2c3c58621b460'
msf_api_url: str = 'https://localhost:5443'
msf_rest_api: MsfRestApi = MsfRestApi(api_key=msf_api_key, api_url=msf_api_url)

print('Create workspace:\n')
workspace: Msf.Workspace = Msf.Workspace(name='test_workspace')

workspace.id = msf_rest_api.create_workspace(workspace=workspace)
print(f'New workspace: {workspace}\n')

all_workspaces: List[Msf.Workspace] = msf_rest_api.get_workspaces()
print(f'All workspaces: {all_workspaces}\n')

removed_workspace: Msf.Workspace = msf_rest_api.delete_workspace(workspace_name=workspace.name)
print(f'Removed workspace: {removed_workspace}\n')

```

Create workspace: 

<details><summary>Example:</summary>

<pre language="shell"><code class="language-shell">
>>> from libmsf.msf import Msf
>>> from libmsf.rest import MsfRestApi
>>> from typing import List
>>>
>>> msf_api_key: str = 'cf2dbb7f9d1f92839a84f9c165ee9afef3dd3a3116bc99badf45be4ae5655168c9c2c3c58621b460'
>>> msf_api_url: str = 'https://localhost:5443'
>>> msf_rest_api: MsfRestApi = MsfRestApi(api_key=msf_api_key, api_url=msf_api_url)
>>>
>>> print('Create workspace:\n')
Create workspace:

>>> workspace: Msf.Workspace = Msf.Workspace(name='test_workspace')
>>>
>>> workspace.id = msf_rest_api.create_workspace(workspace=workspace)
>>> print(f'New workspace: {workspace}\n')
New workspace: Msf.Workspace(id=210, name='test_workspace', created_at=None, updated_at=None, boundary=None, description=None, owner_id=None, limit_to_network=False, import_fingerprint=False)
</code></pre>

<img src="https://python-libmsf.github.io/images/create_workspace.png" alt="Create workspace">

</details>

Get workspaces:

<details>
  <summary>Example:</summary>


<pre lang="shell"><code>
>>> all_workspaces: List[Msf.Workspace] = msf_rest_api.get_workspaces()
>>> print(f'All workspaces: {all_workspaces}\n')
All workspaces: [Msf.Workspace(id=1, name='default', created_at='2021-02-16T16:47:41.137Z', updated_at='2021-02-16T16:47:41.137Z', boundary=None, description=None, owner_id=None, limit_to_network=False, import_fingerprint=False), Msf.Workspace(id=210, name='test_workspace', created_at='2021-04-16T13:28:17.841Z', updated_at='2021-04-16T13:28:17.841Z', boundary=None, description=None, owner_id=None, limit_to_network=False, import_fingerprint=False)]
</code></pre>

</details>

Delete workspace:

<details>
  <summary>Example:</summary>


<pre lang="shell"><code>
>>> removed_workspace: Msf.Workspace = msf_rest_api.delete_workspace(workspace_name=workspace.name)
>>> print(f'Removed workspace: {removed_workspace}\n')
Removed workspace: Msf.Workspace(id=210, name='test_workspace', created_at='2021-04-16T13:28:17.841Z', updated_at='2021-04-16T13:28:17.841Z', boundary=None, description=None, owner_id=None, limit_to_network=False, import_fingerprint=False)
</code></pre>

<img src="https://python-libmsf.github.io/images/delete_workspace.png" alt="Delete workspace">

</details>

### Hosts

```python
from libmsf.msf import Msf
from libmsf.rest import MsfRestApi
from typing import List

msf_api_key: str = 'cf2dbb7f9d1f92839a84f9c165ee9afef3dd3a3116bc99badf45be4ae5655168c9c2c3c58621b460'
msf_api_url: str = 'https://localhost:5443'
msf_rest_api: MsfRestApi = MsfRestApi(api_key=msf_api_key, api_url=msf_api_url)

workspace: Msf.Workspace = Msf.Workspace(name='test_workspace')

host: Msf.Host = Msf.Host()
host.workspace = workspace.name
host.address = '192.168.1.1'
host.mac = '00:11:22:33:44:55'
host.name = 'unit.test.com'
host.os_name = 'linux'
host.os_family = 'posix'
host.os_flavor = 'test'
host.os_sp = 'test'
host.os_lang = 'English'
host.purpose = 'device'
host.info = 'Host for unit tests'
host.comments = 'Host for unit tests'
host.scope = 'unit tests scope'
host.virtual_host = 'unittest'
host.arch = 'x86'
host.state = 'alive'
host.comm = 'unittest'

host.id = msf_rest_api.create_host(host=host)
print(f'New host: {host}\n')

new_host: Msf.Host = msf_rest_api.get_host_by_id(workspace=workspace.name, host_id=host.id)
print(f'New host by id: {new_host}\n')

all_hosts: List[Msf.Host] = msf_rest_api.get_hosts(workspace=workspace.name)
print(f'All hosts: {all_hosts}\n')

removed_hosts: List[Msf.Host] = msf_rest_api.delete_hosts(ids=[host.id])
print(f'Removed hosts: {removed_hosts}\n')

```

Create host:

<details>
  <summary>Example:</summary>

<pre lang="shell"><code>
>>> from libmsf.msf import Msf
>>> from libmsf.rest import MsfRestApi
>>> from typing import List
>>>
>>> msf_api_key: str = 'cf2dbb7f9d1f92839a84f9c165ee9afef3dd3a3116bc99badf45be4ae5655168c9c2c3c58621b460'
>>> msf_api_url: str = 'https://localhost:5443'
>>> msf_rest_api: MsfRestApi = MsfRestApi(api_key=msf_api_key, api_url=msf_api_url)
>>>
>>> workspace: Msf.Workspace = Msf.Workspace(name='test_workspace')
>>>
>>> host: Msf.Host = Msf.Host()
>>> host.workspace = workspace.name
>>> host.address = '192.168.1.1'
>>> host.mac = '00:11:22:33:44:55'
>>> host.name = 'unit.test.com'
>>> host.os_name = 'linux'
>>> host.os_family = 'posix'
>>> host.os_flavor = 'test'
>>> host.os_sp = 'test'
>>> host.os_lang = 'English'
>>> host.purpose = 'device'
>>> host.info = 'Host for unit tests'
>>> host.comments = 'Host for unit tests'
>>> host.scope = 'unit tests scope'
>>> host.virtual_host = 'unittest'
>>> host.arch = 'x86'
>>> host.state = 'alive'
>>> host.comm = 'unittest'
>>>
>>> host.id = msf_rest_api.create_host(host=host)
>>> print(f'New host: {host}\n')
New host: Msf.Host(id=220, workspace='test_workspace', created_at=None, host=None, address='192.168.1.1', mac='00:11:22:33:44:55', comm='unittest', name='unit.test.com', state='alive', os_name='linux', os_flavor='test', os_sp='test', os_lang='English', arch='x86', workspace_id=-1, updated_at=None, purpose='device', info='Host for unit tests', comments='Host for unit tests', scope='unit tests scope', virtual_host='unittest', note_count=0, vuln_count=0, service_count=0, host_detail_count=0, exploit_attempt_count=0, cred_count=0, detected_arch=None, os_family='posix')
</code></pre>

<img src="https://python-libmsf.github.io/images/create_host.png" alt="Create host">

</details>

Get hosts:

<details>
  <summary>Example:</summary>

<pre lang="shell"><code>
>>> new_host: Msf.Host = msf_rest_api.get_host_by_id(workspace=workspace.name, host_id=host.id)
>>> print(f'New host by id: {new_host}\n')
New host by id: Msf.Host(id=220, workspace=None, created_at='2021-04-16T13:03:43.816Z', host=None, address='192.168.1.1', mac='00:11:22:33:44:55', comm='unittest', name='unit.test.com', state='alive', os_name='linux', os_flavor='test', os_sp='test', os_lang='English', arch='x86', workspace_id=206, updated_at='2021-04-16T13:03:43.816Z', purpose='device', info='Host for unit tests', comments='Host for unit tests', scope='unit tests scope', virtual_host='unittest', note_count=0, vuln_count=0, service_count=0, host_detail_count=0, exploit_attempt_count=0, cred_count=0, detected_arch='', os_family='posix')

>>>
>>> all_hosts: List[Msf.Host] = msf_rest_api.get_hosts(workspace=workspace.name)
>>> print(f'All hosts: {all_hosts}\n')
All hosts: [Msf.Host(id=220, workspace=None, created_at='2021-04-16T13:03:43.816Z', host=None, address='192.168.1.1', mac='00:11:22:33:44:55', comm='unittest', name='unit.test.com', state='alive', os_name='linux', os_flavor='test', os_sp='test', os_lang='English', arch='x86', workspace_id=206, updated_at='2021-04-16T13:03:43.816Z', purpose='device', info='Host for unit tests', comments='Host for unit tests', scope='unit tests scope', virtual_host='unittest', note_count=0, vuln_count=0, service_count=0, host_detail_count=0, exploit_attempt_count=0, cred_count=0, detected_arch='', os_family='posix')]
</code></pre>

</details>

Delete host:

<details>
  <summary>Example:</summary>

<pre lang="shell"><code>
>>> removed_hosts: List[Msf.Host] = msf_rest_api.delete_hosts(ids=[host.id])
>>> print(f'Removed hosts: {removed_hosts}\n')
Removed hosts: [Msf.Host(id=220, workspace=None, created_at='2021-04-16T13:03:43.816Z', host=None, address='192.168.1.1', mac='00:11:22:33:44:55', comm='unittest', name='unit.test.com', state='alive', os_name='linux', os_flavor='test', os_sp='test', os_lang='English', arch='x86', workspace_id=206, updated_at='2021-04-16T13:03:43.816Z', purpose='device', info='Host for unit tests', comments='Host for unit tests', scope='unit tests scope', virtual_host='unittest', note_count=0, vuln_count=0, service_count=0, host_detail_count=0, exploit_attempt_count=0, cred_count=0, detected_arch='', os_family='posix')]
</code></pre>

<img src="https://python-libmsf.github.io/images/delete_host.png" alt="Delete host">

</details>

### Services

```python
from libmsf.msf import Msf
from libmsf.rest import MsfRestApi
from typing import List

msf_api_key: str = 'cf2dbb7f9d1f92839a84f9c165ee9afef3dd3a3116bc99badf45be4ae5655168c9c2c3c58621b460'
msf_api_url: str = 'https://localhost:5443'
msf_rest_api: MsfRestApi = MsfRestApi(api_key=msf_api_key, api_url=msf_api_url)

workspace: Msf.Workspace = Msf.Workspace(name='test_workspace')
host: Msf.Host = Msf.Host(address='192.168.1.1')

service: Msf.Service = Msf.Service()
service.workspace = workspace.name
service.host = host.address
service.port = 12345
service.proto = 'tcp'
service.state = 'open'
service.name = 'http'
service.info = 'Unit test'

service.id = msf_rest_api.create_service(service=service)
print(f'New service: {service}\n')

new_service: Msf.Service = msf_rest_api.get_service_by_id(workspace=workspace.name, service_id=service.id)
print(f'New service by id: {new_service}\n')

all_services: List[Msf.Service] = msf_rest_api.get_services(workspace=workspace.name)
print(f'All services: {all_services}\n')

removed_services: List[Msf.Service] = msf_rest_api.delete_services(ids=[service.id])
print(f'Removed services: {removed_services}\n')

```

Create service:

<details>
  <summary>Example:</summary>

<pre lang="shell"><code>
>>> from libmsf.msf import Msf
>>> from libmsf.rest import MsfRestApi
>>> from typing import List
>>>
>>> msf_api_key: str = 'cf2dbb7f9d1f92839a84f9c165ee9afef3dd3a3116bc99badf45be4ae5655168c9c2c3c58621b460'
>>> msf_api_url: str = 'https://localhost:5443'
>>> msf_rest_api: MsfRestApi = MsfRestApi(api_key=msf_api_key, api_url=msf_api_url)
>>>
>>> workspace: Msf.Workspace = Msf.Workspace(name='test_workspace')
>>> host: Msf.Host = Msf.Host(address='192.168.1.1')
>>>
>>> service: Msf.Service = Msf.Service()
>>> service.workspace = workspace.name
>>> service.host = host.address
>>> service.port = 12345
>>> service.proto = 'tcp'
>>> service.state = 'open'
>>> service.name = 'http'
>>> service.info = 'Unit test'
>>>
>>> service.id = msf_rest_api.create_service(service=service)
>>> print(f'New service: {service}\n')
New service: Msf.Service(id=249, workspace='test_workspace', host='192.168.1.1', host_id=-1, created_at=None, port=12345, proto='tcp', state='open', name='http', updated_at=None, info='Unit test')
</code></pre>

<img src="https://python-libmsf.github.io/images/create_service.png" alt="Create service">

</details>

Get services:

<details>
  <summary>Example:</summary>

<pre lang="shell"><code>
>>> new_service: Msf.Service = msf_rest_api.get_service_by_id(workspace=workspace.name, service_id=service.id)
>>> print(f'New service by id: {new_service}\n')
New service by id: Msf.Service(id=249, workspace=None, host=Msf.Host(id=224, workspace=None, created_at='2021-04-16T13:35:50.565Z', host=None, address='192.168.1.1', mac='00:11:22:33:44:55', comm='unittest', name='unit.test.com', state='alive', os_name='linux', os_flavor='test', os_sp='test', os_lang='English', arch='x86', workspace_id=212, updated_at='2021-04-16T13:35:50.565Z', purpose='device', info='Host for unit tests', comments='Host for unit tests', scope='unit tests scope', virtual_host='unittest', note_count=0, vuln_count=0, service_count=1, host_detail_count=0, exploit_attempt_count=0, cred_count=0, detected_arch='', os_family='posix'), host_id=224, created_at='2021-04-16T13:36:13.731Z', port=12345, proto='tcp', state='open', name='http', updated_at='2021-04-16T13:36:13.731Z', info='Unit test')

>>>
>>> all_services: List[Msf.Service] = msf_rest_api.get_services(workspace=workspace.name)
>>> print(f'All services: {all_services}\n')
All services: [Msf.Service(id=249, workspace=None, host=Msf.Host(id=224, workspace=None, created_at='2021-04-16T13:35:50.565Z', host=None, address='192.168.1.1', mac='00:11:22:33:44:55', comm='unittest', name='unit.test.com', state='alive', os_name='linux', os_flavor='test', os_sp='test', os_lang='English', arch='x86', workspace_id=212, updated_at='2021-04-16T13:35:50.565Z', purpose='device', info='Host for unit tests', comments='Host for unit tests', scope='unit tests scope', virtual_host='unittest', note_count=0, vuln_count=0, service_count=1, host_detail_count=0, exploit_attempt_count=0, cred_count=0, detected_arch='', os_family='posix'), host_id=224, created_at='2021-04-16T13:36:13.731Z', port=12345, proto='tcp', state='open', name='http', updated_at='2021-04-16T13:36:13.731Z', info='Unit test')]
</code></pre>

</details>

Delete service:

<details>
  <summary>Example:</summary>

<pre lang="shell"><code>
>>> removed_services: List[Msf.Service] = msf_rest_api.delete_services(ids=[service.id])
>>> print(f'Removed services: {removed_services}\n')
Removed services: [Msf.Service(id=249, workspace=None, host=None, host_id=224, created_at='2021-04-16T13:36:13.731Z', port=12345, proto='tcp', state='open', name='http', updated_at='2021-04-16T13:36:13.731Z', info='Unit test')]
</code></pre>

<img src="https://python-libmsf.github.io/images/delete_service.png" alt="Delete service">

</details>

### Vulnerabilities

```python
from libmsf.msf import Msf
from libmsf.rest import MsfRestApi
from typing import List

msf_api_key: str = 'cf2dbb7f9d1f92839a84f9c165ee9afef3dd3a3116bc99badf45be4ae5655168c9c2c3c58621b460'
msf_api_url: str = 'https://localhost:5443'
msf_rest_api: MsfRestApi = MsfRestApi(api_key=msf_api_key, api_url=msf_api_url)

workspace: Msf.Workspace = Msf.Workspace(name='test_workspace')
host: Msf.Host = Msf.Host(address='192.168.1.1')
service: Msf.Service = Msf.Service(port=12345)

vuln: Msf.Vuln = Msf.Vuln()
vuln.workspace = workspace.name
vuln.host = host.address
vuln.port = service.port
vuln.name = 'Unit test vuln name'
vuln.info = 'Unit test vuln info'
vuln.refs = ['CVE-2020-2020', 'URL-https://unit.test.com/vuln']

vuln.id = msf_rest_api.create_vuln(vuln=vuln)
print(f'New vuln: {vuln}\n')

new_vuln: Msf.Vuln = msf_rest_api.get_vuln_by_id(workspace=workspace.name, vuln_id=vuln.id)
print(f'New vuln by id: {new_vuln}\n')

all_vulns: List[Msf.Vuln] = msf_rest_api.get_vulns(workspace=workspace.name)
print(f'All vulns: {all_vulns}\n')

removed_vulns: List[Msf.Vuln] = msf_rest_api.delete_vulns(ids=[vuln.id])
print(f'Removed vulns: {removed_vulns}\n')

```

Create vulnerability:

<details>
  <summary>Example:</summary>

<pre lang="shell"><code>
>>> from libmsf.msf import Msf
>>> from libmsf.rest import MsfRestApi
>>> from typing import List
>>>
>>> msf_api_key: str = 'cf2dbb7f9d1f92839a84f9c165ee9afef3dd3a3116bc99badf45be4ae5655168c9c2c3c58621b460'
>>> msf_api_url: str = 'https://localhost:5443'
>>> msf_rest_api: MsfRestApi = MsfRestApi(api_key=msf_api_key, api_url=msf_api_url)
>>>
>>> workspace: Msf.Workspace = Msf.Workspace(name='test_workspace')
>>> host: Msf.Host = Msf.Host(address='192.168.1.1')
>>> service: Msf.Service = Msf.Service(port=12345)
>>>
>>> vuln: Msf.Vuln = Msf.Vuln()
>>> vuln.workspace = workspace.name
>>> vuln.host = host.address
>>> vuln.port = service.port
>>> vuln.name = 'Unit test vuln name'
>>> vuln.info = 'Unit test vuln info'
>>> vuln.refs = ['CVE-2020-2020', 'URL-https://unit.test.com/vuln']
>>>
>>> vuln.id = msf_rest_api.create_vuln(vuln=vuln)
>>> print(f'New vuln: {vuln}\n')
New vuln: Msf.Vuln(id=272, workspace='test_workspace', host='192.168.1.1', host_id=-1, port=12345, service_id=-1, created_at=None, name='Unit test vuln name', updated_at=None, info='Unit test vuln info', exploited_at=None, vuln_detail_count=0, vuln_attempt_count=0, origin_id=None, origin_type=None, refs=['CVE-2020-2020', 'URL-https://unit.test.com/vuln'], module_refs=None)
</code></pre>

<img src="https://python-libmsf.github.io/images/create_vuln.png" alt="Create vuln">

</details>

Get vulnerabilities:

<details>
  <summary>Example:</summary>

<pre lang="shell"><code>
>>> new_vuln: Msf.Vuln = msf_rest_api.get_vuln_by_id(workspace=workspace.name, vuln_id=vuln.id)
>>> print(f'New vuln by id: {new_vuln}\n')
New vuln by id: Msf.Vuln(id=272, workspace=None, host=Msf.Host(id=226, workspace=None, created_at='2021-04-16T13:46:17.284Z', host=None, address='192.168.1.1', mac='00:11:22:33:44:55', comm='unittest', name='unit.test.com', state='alive', os_name='linux', os_flavor='test', os_sp='test', os_lang='English', arch='x86', workspace_id=214, updated_at='2021-04-16T13:46:17.284Z', purpose='device', info='Host for unit tests', comments='Host for unit tests', scope='unit tests scope', virtual_host='unittest', note_count=0, vuln_count=1, service_count=1, host_detail_count=0, exploit_attempt_count=0, cred_count=0, detected_arch='', os_family='posix'), host_id=226, port=-1, service_id=251, created_at='2021-04-16T13:47:50.763Z', name='Unit test vuln name', updated_at='2021-04-16T13:47:50.763Z', info='Unit test vuln info', exploited_at=None, vuln_detail_count=0, vuln_attempt_count=0, origin_id=None, origin_type=None, refs=[{'id': 8, 'ref_id': None, 'created_at': '2021-04-15T22:57:21.274Z', 'name': 'CVE-2020-2020', 'updated_at': '2021-04-15T22:57:21.274Z'}, {'id': 9, 'ref_id': None, 'created_at': '2021-04-15T22:57:21.279Z', 'name': 'URL-https://unit.test.com/vuln', 'updated_at': '2021-04-15T22:57:21.279Z'}], module_refs=[])

>>>
>>> all_vulns: List[Msf.Vuln] = msf_rest_api.get_vulns(workspace=workspace.name)
>>> print(f'All vulns: {all_vulns}\n')
All vulns: [Msf.Vuln(id=272, workspace=None, host=Msf.Host(id=226, workspace=None, created_at='2021-04-16T13:46:17.284Z', host=None, address='192.168.1.1', mac='00:11:22:33:44:55', comm='unittest', name='unit.test.com', state='alive', os_name='linux', os_flavor='test', os_sp='test', os_lang='English', arch='x86', workspace_id=214, updated_at='2021-04-16T13:46:17.284Z', purpose='device', info='Host for unit tests', comments='Host for unit tests', scope='unit tests scope', virtual_host='unittest', note_count=0, vuln_count=1, service_count=1, host_detail_count=0, exploit_attempt_count=0, cred_count=0, detected_arch='', os_family='posix'), host_id=226, port=-1, service_id=251, created_at='2021-04-16T13:47:50.763Z', name='Unit test vuln name', updated_at='2021-04-16T13:47:50.763Z', info='Unit test vuln info', exploited_at=None, vuln_detail_count=0, vuln_attempt_count=0, origin_id=None, origin_type=None, refs=[{'id': 8, 'ref_id': None, 'created_at': '2021-04-15T22:57:21.274Z', 'name': 'CVE-2020-2020', 'updated_at': '2021-04-15T22:57:21.274Z'}, {'id': 9, 'ref_id': None, 'created_at': '2021-04-15T22:57:21.279Z', 'name': 'URL-https://unit.test.com/vuln', 'updated_at': '2021-04-15T22:57:21.279Z'}], module_refs=[])]
</code></pre>

</details>

Delete vulnerability:

<details>
  <summary>Example:</summary>

<pre lang="shell"><code>
>>> removed_vulns: List[Msf.Vuln] = msf_rest_api.delete_vulns(ids=[vuln.id])
>>> print(f'Removed vulns: {removed_vulns}\n')
Removed vulns: [Msf.Vuln(id=272, workspace=None, host=Msf.Host(id=226, workspace=None, created_at='2021-04-16T13:46:17.284Z', host=None, address='192.168.1.1', mac='00:11:22:33:44:55', comm='unittest', name='unit.test.com', state='alive', os_name='linux', os_flavor='test', os_sp='test', os_lang='English', arch='x86', workspace_id=214, updated_at='2021-04-16T13:46:17.284Z', purpose='device', info='Host for unit tests', comments='Host for unit tests', scope='unit tests scope', virtual_host='unittest', note_count=0, vuln_count=0, service_count=1, host_detail_count=0, exploit_attempt_count=0, cred_count=0, detected_arch='', os_family='posix'), host_id=226, port=-1, service_id=251, created_at='2021-04-16T13:47:50.763Z', name='Unit test vuln name', updated_at='2021-04-16T13:47:50.763Z', info='Unit test vuln info', exploited_at=None, vuln_detail_count=0, vuln_attempt_count=0, origin_id=None, origin_type=None, refs=[], module_refs=[])]
</code></pre>

<img src="https://python-libmsf.github.io/images/delete_vuln.png" alt="Delete vuln">

</details>

### Loots

```python
from libmsf.msf import Msf
from libmsf.rest import MsfRestApi
from typing import List

msf_api_key: str = 'cf2dbb7f9d1f92839a84f9c165ee9afef3dd3a3116bc99badf45be4ae5655168c9c2c3c58621b460'
msf_api_url: str = 'https://localhost:5443'
msf_rest_api: MsfRestApi = MsfRestApi(api_key=msf_api_key, api_url=msf_api_url)

workspace: Msf.Workspace = Msf.Workspace(name='test_workspace')
host: Msf.Host = Msf.Host(address='192.168.1.1')
service: Msf.Service = Msf.Service(port=12345)

loot: Msf.Loot = Msf.Loot()
loot.workspace = workspace.name
loot.host = host.address
loot.port = service.port
loot.ltype = 'unit.test.type'
loot.data = 'dGVzdA=='
loot.name = '/tmp/unit.test'
loot.info = 'Unit test file'
loot.content_type = 'text/plain'
loot.path = 'path.txt'

loot.id = msf_rest_api.create_loot(loot=loot)
print(f'New loot: {loot}\n')

new_loot: Msf.Loot = msf_rest_api.get_loot_by_id(workspace=workspace.name, loot_id=loot.id)
print(f'New loot by id: {new_loot}\n')

all_loots: List[Msf.Loot] = msf_rest_api.get_loots(workspace=workspace.name)
print(f'All loots: {all_loots}\n')

removed_loots: List[Msf.Loot] = msf_rest_api.delete_loots(ids=[loot.id])
print(f'Removed loots: {removed_loots}\n')

```

Create loot:

<details>
  <summary>Example:</summary>

<pre lang="shell"><code>
>>> from libmsf.msf import Msf
>>> from libmsf.rest import MsfRestApi
>>> from typing import List
>>>
>>> msf_api_key: str = 'cf2dbb7f9d1f92839a84f9c165ee9afef3dd3a3116bc99badf45be4ae5655168c9c2c3c58621b460'
>>> msf_api_url: str = 'https://localhost:5443'
>>> msf_rest_api: MsfRestApi = MsfRestApi(api_key=msf_api_key, api_url=msf_api_url)
>>>
>>> workspace: Msf.Workspace = Msf.Workspace(name='test_workspace')
>>> host: Msf.Host = Msf.Host(address='192.168.1.1')
>>> service: Msf.Service = Msf.Service(port=12345)
>>>
>>> loot: Msf.Loot = Msf.Loot()
>>> loot.workspace = workspace.name
>>> loot.host = host.address
>>> loot.port = service.port
>>> loot.ltype = 'unit.test.type'
>>> loot.data = 'dGVzdA=='
>>> loot.name = '/tmp/unit.test'
>>> loot.info = 'Unit test file'
>>> loot.content_type = 'text/plain'
>>> loot.path = 'path.txt'
>>>
>>> loot.id = msf_rest_api.create_loot(loot=loot)
>>> print(f'New loot: {loot}\n')
New loot: Msf.Loot(id=61, workspace='test_workspace', workspace_id=-1, host='192.168.1.1', host_id=-1, port=12345, service_id=-1, created_at=None, updated_at=None, ltype='unit.test.type', path='path.txt', data='dGVzdA==', content_type='text/plain', name='/tmp/unit.test', info='Unit test file', module_run_id=None)
</code></pre>

<img src="https://python-libmsf.github.io/images/create_loot.png" alt="Create loot">

</details>

Get loots:

<details>
  <summary>Example:</summary>

<pre lang="shell"><code>
>>> new_loot: Msf.Loot = msf_rest_api.get_loot_by_id(workspace=workspace.name, loot_id=loot.id)
>>> print(f'New loot by id: {new_loot}\n')
New loot by id: Msf.Loot(id=61, workspace=None, workspace_id=215, host=Msf.Host(id=227, workspace=None, created_at='2021-04-16T13:55:53.310Z', host=None, address='192.168.1.1', mac='00:11:22:33:44:55', comm='unittest', name='unit.test.com', state='alive', os_name='linux', os_flavor='test', os_sp='test', os_lang='English', arch='x86', workspace_id=215, updated_at='2021-04-16T13:55:53.310Z', purpose='device', info='Host for unit tests', comments='Host for unit tests', scope='unit tests scope', virtual_host='unittest', note_count=0, vuln_count=0, service_count=1, host_detail_count=0, exploit_attempt_count=0, cred_count=0, detected_arch='', os_family='posix'), host_id=227, port=-1, service_id=None, created_at='2021-04-16T13:56:16.838Z', updated_at='2021-04-16T13:56:16.838Z', ltype='unit.test.type', path='/Users/vladimir/.msf4/loot/6f8c35d43dc702b3b866-path.txt', data='dGVzdA==', content_type='text/plain', name='/tmp/unit.test', info='Unit test file', module_run_id=None)

>>>
>>> all_loots: List[Msf.Loot] = msf_rest_api.get_loots(workspace=workspace.name)
>>> print(f'All loots: {all_loots}\n')
All loots: [Msf.Loot(id=61, workspace=None, workspace_id=215, host=Msf.Host(id=227, workspace=None, created_at='2021-04-16T13:55:53.310Z', host=None, address='192.168.1.1', mac='00:11:22:33:44:55', comm='unittest', name='unit.test.com', state='alive', os_name='linux', os_flavor='test', os_sp='test', os_lang='English', arch='x86', workspace_id=215, updated_at='2021-04-16T13:55:53.310Z', purpose='device', info='Host for unit tests', comments='Host for unit tests', scope='unit tests scope', virtual_host='unittest', note_count=0, vuln_count=0, service_count=1, host_detail_count=0, exploit_attempt_count=0, cred_count=0, detected_arch='', os_family='posix'), host_id=227, port=-1, service_id=None, created_at='2021-04-16T13:56:16.838Z', updated_at='2021-04-16T13:56:16.838Z', ltype='unit.test.type', path='/Users/vladimir/.msf4/loot/6f8c35d43dc702b3b866-path.txt', data='dGVzdA==', content_type='text/plain', name='/tmp/unit.test', info='Unit test file', module_run_id=None)]
</code></pre>

</details>

Delete loot:

<details>
  <summary>Example:</summary>

<pre lang="shell"><code>
>>> removed_loots: List[Msf.Loot] = msf_rest_api.delete_loots(ids=[loot.id])
>>> print(f'Removed loots: {removed_loots}\n')
Removed loots: [Msf.Loot(id=None, workspace=None, workspace_id=215, host=None, host_id=227, port=-1, service_id=None, created_at=None, updated_at=None, ltype='unit.test.type', path='/Users/vladimir/.msf4/loot/6f8c35d43dc702b3b866-path.txt', data='dGVzdA==', content_type='text/plain', name='/tmp/unit.test', info='Unit test file', module_run_id=None)]
</code></pre>

<img src="https://python-libmsf.github.io/images/delete_loot.png" alt="Delete loot">

</details>

### Notes

```python
from libmsf.msf import Msf
from libmsf.rest import MsfRestApi
from typing import List

msf_api_key: str = 'cf2dbb7f9d1f92839a84f9c165ee9afef3dd3a3116bc99badf45be4ae5655168c9c2c3c58621b460'
msf_api_url: str = 'https://localhost:5443'
msf_rest_api: MsfRestApi = MsfRestApi(api_key=msf_api_key, api_url=msf_api_url)

workspace: Msf.Workspace = Msf.Workspace(name='test_workspace')
host: Msf.Host = Msf.Host(address='192.168.1.1')
service: Msf.Service = Msf.Service(port=12345)

note: Msf.Note = Msf.Note()
note.workspace = workspace.name
note.host = host.address
note.ntype = 'host.comments'
note.data = 'Unit test host comment'

note.id = msf_rest_api.create_note(note=note)
print(f'New note: {note}\n')

new_note: Msf.Note = msf_rest_api.get_note_by_id(workspace=workspace.name, note_id=note.id)
print(f'New note by id: {new_note}\n')

all_notes: List[Msf.Note] = msf_rest_api.get_notes(workspace=workspace.name)
print(f'All notes: {all_notes}\n')

removed_notes: List[Msf.Note] = msf_rest_api.delete_notes(ids=[note.id])
print(f'Removed notes: {removed_notes}\n')

```

Create note:

<details>
  <summary>Example:</summary>

<pre lang="shell"><code>
>>> from libmsf.msf import Msf
>>> from libmsf.rest import MsfRestApi
>>> from typing import List
>>>
>>> msf_api_key: str = 'cf2dbb7f9d1f92839a84f9c165ee9afef3dd3a3116bc99badf45be4ae5655168c9c2c3c58621b460'
>>> msf_api_url: str = 'https://localhost:5443'
>>> msf_rest_api: MsfRestApi = MsfRestApi(api_key=msf_api_key, api_url=msf_api_url)
>>>
>>> workspace: Msf.Workspace = Msf.Workspace(name='test_workspace')
>>> host: Msf.Host = Msf.Host(address='192.168.1.1')
>>> service: Msf.Service = Msf.Service(port=12345)
>>>
>>> note: Msf.Note = Msf.Note()
>>> note.workspace = workspace.name
>>> note.host = host.address
>>> note.ntype = 'host.comments'
>>> note.data = 'Unit test host comment'
>>>
>>> note.id = msf_rest_api.create_note(note=note)
>>> print(f'New note: {note}\n')
New note: Msf.Note(id=40, workspace='test_workspace', workspace_id=-1, host='192.168.1.1', host_id=-1, service_id=-1, created_at=None, updated_at=None, ntype='host.comments', data='Unit test host comment', critical=False, seen=False)
</code></pre>

<img src="https://python-libmsf.github.io/images/create_note.png" alt="Create note">

</details>

Get notes:

<details>
  <summary>Example:</summary>

<pre lang="shell"><code>
>>> new_note: Msf.Note = msf_rest_api.get_note_by_id(workspace=workspace.name, note_id=note.id)
>>> print(f'New note by id: {new_note}\n')
New note by id: Msf.Note(id=40, workspace=None, workspace_id=215, host=Msf.Host(id=227, workspace=None, created_at='2021-04-16T13:55:53.310Z', host=None, address='192.168.1.1', mac='00:11:22:33:44:55', comm='unittest', name='unit.test.com', state='alive', os_name='linux', os_flavor='test', os_sp='test', os_lang='English', arch='x86', workspace_id=215, updated_at='2021-04-16T13:55:53.310Z', purpose='device', info='Host for unit tests', comments='Host for unit tests', scope='unit tests scope', virtual_host='unittest', note_count=1, vuln_count=0, service_count=1, host_detail_count=0, exploit_attempt_count=0, cred_count=0, detected_arch='', os_family='posix'), host_id=227, service_id=None, created_at='2021-04-16T14:03:46.116Z', updated_at='2021-04-16T14:03:46.116Z', ntype='host.comments', data='Unit test host comment', critical=None, seen=None)

>>>
>>> all_notes: List[Msf.Note] = msf_rest_api.get_notes(workspace=workspace.name)
>>> print(f'All notes: {all_notes}\n')
All notes: [Msf.Note(id=40, workspace=None, workspace_id=215, host=Msf.Host(id=227, workspace=None, created_at='2021-04-16T13:55:53.310Z', host=None, address='192.168.1.1', mac='00:11:22:33:44:55', comm='unittest', name='unit.test.com', state='alive', os_name='linux', os_flavor='test', os_sp='test', os_lang='English', arch='x86', workspace_id=215, updated_at='2021-04-16T13:55:53.310Z', purpose='device', info='Host for unit tests', comments='Host for unit tests', scope='unit tests scope', virtual_host='unittest', note_count=1, vuln_count=0, service_count=1, host_detail_count=0, exploit_attempt_count=0, cred_count=0, detected_arch='', os_family='posix'), host_id=227, service_id=None, created_at='2021-04-16T14:03:46.116Z', updated_at='2021-04-16T14:03:46.116Z', ntype='host.comments', data='Unit test host comment', critical=None, seen=None)]
</code></pre>

</details>

Delete note:

<details>
  <summary>Example:</summary>

<pre lang="shell"><code>
>>> removed_notes: List[Msf.Note] = msf_rest_api.delete_notes(ids=[note.id])
>>> print(f'Removed notes: {removed_notes}\n')
Removed notes: [Msf.Note(id=40, workspace=None, workspace_id=215, host=None, host_id=227, service_id=None, created_at='2021-04-16T14:03:46.116Z', updated_at='2021-04-16T14:03:46.116Z', ntype='host.comments', data='Unit test host comment', critical=None, seen=None)]
</code></pre>

<img src="https://python-libmsf.github.io/images/delete_note.png" alt="Delete note">

</details>

### Credentials and logins

```python
from libmsf.msf import Msf
from libmsf.rest import MsfRestApi
from typing import List

msf_api_key: str = 'cf2dbb7f9d1f92839a84f9c165ee9afef3dd3a3116bc99badf45be4ae5655168c9c2c3c58621b460'
msf_api_url: str = 'https://localhost:5443'
msf_rest_api: MsfRestApi = MsfRestApi(api_key=msf_api_key, api_url=msf_api_url)

workspace: Msf.Workspace = Msf.Workspace(name='test_workspace')
workspace.id = msf_rest_api.get_workspace_id_by_name(workspace.name)
host: Msf.Host = Msf.Host(address='192.168.1.1')
service: Msf.Service = Msf.Service(port=12345, name='http', proto='tcp')

cred: Msf.Cred = Msf.Cred()
cred.workspace_id = workspace.id
cred.address = host.address
cred.port = service.port
cred.username = 'UnitTestUser'
cred.private_data = 'UnitTestPassword'
cred.private_type = 'password'
cred.module_fullname = 'auxiliary/scanner/http/http_login'
cred.service_name = service.name
cred.protocol = service.proto
cred.origin_type = 'service'

login: Msf.Login = Msf.Login()
login.workspace_id = workspace.id
login.address = host.address
login.port = service.port
login.last_attempted_at = '2021-01-01T11:11:11.111Z'
login.service_name = service.name
login.protocol = service.proto
login.status = 'Successful'
login.access_level = 'admin'

cred.id = msf_rest_api.create_cred(cred=cred)
print(f'New cred: {cred}\n')

login.core_id = cred.id
login.id = msf_rest_api.create_login(login=login)
print(f'New login: {login}\n')

new_login: Msf.Login = msf_rest_api.get_login_by_id(login_id=login.id)
print(f'New login by id: {new_login}\n')

new_cred: Msf.Cred = msf_rest_api.get_cred_by_id(workspace=workspace.name, cred_id=cred.id)
print(f'New cred by id: {new_cred}\n')

all_logins: List[Msf.Login] = msf_rest_api.get_logins()
print(f'All logins: {all_logins}\n')

all_creds: List[Msf.Cred] = msf_rest_api.get_creds(workspace=workspace.name)
print(f'All creds: {all_creds}\n')

removed_logins: List[Msf.Login] = msf_rest_api.delete_logins(ids=[login.id])
print(f'Removed logins: {removed_logins}\n')

removed_creds: List[Msf.Cred] = msf_rest_api.delete_creds(ids=[cred.id])
print(f'Removed creds: {removed_creds}\n')

```

Create credentials and login:

<details>
  <summary>Example:</summary>

<pre lang="shell"><code>
>>> from libmsf.msf import Msf
>>> from libmsf.rest import MsfRestApi
>>> from typing import List
>>>
>>> msf_api_key: str = 'cf2dbb7f9d1f92839a84f9c165ee9afef3dd3a3116bc99badf45be4ae5655168c9c2c3c58621b460'
>>> msf_api_url: str = 'https://localhost:5443'
>>> msf_rest_api: MsfRestApi = MsfRestApi(api_key=msf_api_key, api_url=msf_api_url)
>>>
>>> workspace: Msf.Workspace = Msf.Workspace(name='test_workspace')
>>> workspace.id = msf_rest_api.get_workspace_id_by_name(workspace.name)
>>> host: Msf.Host = Msf.Host(address='192.168.1.1')
>>> service: Msf.Service = Msf.Service(port=12345, name='http', proto='tcp')
>>>
>>> cred: Msf.Cred = Msf.Cred()
>>> cred.workspace_id = workspace.id
>>> cred.address = host.address
>>> cred.port = service.port
>>> cred.username = 'UnitTestUser'
>>> cred.private_data = 'UnitTestPassword'
>>> cred.private_type = 'password'
>>> cred.module_fullname = 'auxiliary/scanner/http/http_login'
>>> cred.service_name = service.name
>>> cred.protocol = service.proto
>>> cred.origin_type = 'service'
>>>
>>> login: Msf.Login = Msf.Login()
>>> login.workspace_id = workspace.id
>>> login.address = host.address
>>> login.port = service.port
>>> login.last_attempted_at = '2021-01-01T11:11:11.111Z'
>>> login.service_name = service.name
>>> login.protocol = service.proto
>>> login.status = 'Successful'
>>> login.access_level = 'admin'
>>>
>>> cred.id = msf_rest_api.create_cred(cred=cred)
>>> print(f'New cred: {cred}\n')
New cred: Msf.Cred(id=68, workspace_id=215, username='UnitTestUser', private_data='UnitTestPassword', private_type='password', jtr_format=None, address='192.168.1.1', port=12345, service_name='http', protocol='tcp', origin_type='service', module_fullname='auxiliary/scanner/http/http_login', created_at=None, updated_at=None, origin_id=-1, private_id=-1, public_id=-1, realm_id=-1, logins_count=-1, logins=None, public=None, private=None, origin=None)

>>>
>>> login.core_id = cred.id
>>> login.id = msf_rest_api.create_login(login=login)
>>> print(f'New login: {login}\n')
New login: Msf.Login(id=78, workspace_id=215, core_id=68, service_id=-1, last_attempted_at='2021-01-01T11:11:11.111Z', address='192.168.1.1', service_name='http', port=12345, protocol='tcp', status='Successful', access_level='admin', public=None, private=None, created_at=None, updated_at=None)
</code></pre>

<img src="https://python-libmsf.github.io/images/create_cred.png" alt="Create cred">

</details>

Get credentials and logins:

<details>
  <summary>Example:</summary>

<pre lang="shell"><code>
>>> new_login: Msf.Login = msf_rest_api.get_login_by_id(login_id=login.id)
>>> print(f'New login by id: {new_login}\n')
New login by id: Msf.Login(id=78, workspace_id=-1, core_id=68, service_id=252, last_attempted_at='2021-01-01T11:11:11.111Z', address=None, service_name='ssh', port=-1, protocol='tcp', status='Successful', access_level='admin', public=None, private=None, created_at='2021-04-16T14:16:05.151Z', updated_at='2021-04-16T14:16:05.151Z')

>>>
>>> new_cred: Msf.Cred = msf_rest_api.get_cred_by_id(workspace=workspace.name, cred_id=cred.id)
>>> print(f'New cred by id: {new_cred}\n')
New cred by id: Msf.Cred(id=68, workspace_id=215, username=None, private_data=None, private_type=None, jtr_format=None, address=None, port=-1, service_name=None, protocol=None, origin_type='Metasploit::Credential::Origin::Service', module_fullname=None, created_at='2021-04-16T14:15:36.173Z', updated_at='2021-04-16T14:15:36.173Z', origin_id=77, private_id=2, public_id=5, realm_id=None, logins_count=1, logins=[Msf.Login(id=78, workspace_id=-1, core_id=68, service_id=252, last_attempted_at='2021-01-01T11:11:11.111Z', address=None, service_name='ssh', port=-1, protocol='tcp', status='Successful', access_level='admin', public=None, private=None, created_at='2021-04-16T14:16:05.151Z', updated_at='2021-04-16T14:16:05.151Z')], public=Msf.Public(id=5, username='UnitTestUser', created_at='2021-04-15T22:57:21.572Z', updated_at='2021-04-15T22:57:21.572Z', type='Metasploit::Credential::Username'), private=Msf.Private(id=2, data='UnitTestPassword', created_at='2021-04-15T22:57:21.548Z', updated_at='2021-04-15T22:57:21.548Z', jtr_format=None, type='Metasploit::Credential::Password'), origin=Msf.Origin(id=77, service_id=252, module_full_name='auxiliary/scanner/http/http_login', created_at='2021-04-16T14:11:06.627Z', updated_at='2021-04-16T14:11:06.627Z', type='Metasploit::Credential::Origin::Service'))

>>>
>>> all_logins: List[Msf.Login] = msf_rest_api.get_logins()
>>> print(f'All logins: {all_logins}\n')
All logins: [Msf.Login(id=78, workspace_id=-1, core_id=68, service_id=252, last_attempted_at='2021-01-01T11:11:11.111Z', address=None, service_name='ssh', port=-1, protocol='tcp', status='Successful', access_level='admin', public=None, private=None, created_at='2021-04-16T14:16:05.151Z', updated_at='2021-04-16T14:16:05.151Z')]

>>>
>>> all_creds: List[Msf.Cred] = msf_rest_api.get_creds(workspace=workspace.name)
>>> print(f'All creds: {all_creds}\n')
All creds: [Msf.Cred(id=68, workspace_id=215, username=None, private_data=None, private_type=None, jtr_format=None, address=None, port=-1, service_name=None, protocol=None, origin_type='Metasploit::Credential::Origin::Service', module_fullname=None, created_at='2021-04-16T14:15:36.173Z', updated_at='2021-04-16T14:15:36.173Z', origin_id=77, private_id=2, public_id=5, realm_id=None, logins_count=1, logins=[Msf.Login(id=78, workspace_id=-1, core_id=68, service_id=252, last_attempted_at='2021-01-01T11:11:11.111Z', address=None, service_name='ssh', port=-1, protocol='tcp', status='Successful', access_level='admin', public=None, private=None, created_at='2021-04-16T14:16:05.151Z', updated_at='2021-04-16T14:16:05.151Z')], public=Msf.Public(id=5, username='UnitTestUser', created_at='2021-04-15T22:57:21.572Z', updated_at='2021-04-15T22:57:21.572Z', type='Metasploit::Credential::Username'), private=Msf.Private(id=2, data='UnitTestPassword', created_at='2021-04-15T22:57:21.548Z', updated_at='2021-04-15T22:57:21.548Z', jtr_format=None, type='Metasploit::Credential::Password'), origin=Msf.Origin(id=77, service_id=252, module_full_name='auxiliary/scanner/http/http_login', created_at='2021-04-16T14:11:06.627Z', updated_at='2021-04-16T14:11:06.627Z', type='Metasploit::Credential::Origin::Service'))]
</code></pre>

</details>

Delete credentials and login:

<details>
  <summary>Example:</summary>

<pre lang="shell"><code>
>>> removed_logins: List[Msf.Login] = msf_rest_api.delete_logins(ids=[login.id])
>>> print(f'Removed logins: {removed_logins}\n')
Removed logins: [Msf.Login(id=78, workspace_id=-1, core_id=68, service_id=252, last_attempted_at='2021-01-01T11:11:11.111Z', address=None, service_name='ssh', port=-1, protocol='tcp', status='Successful', access_level='admin', public=None, private=None, created_at='2021-04-16T14:16:05.151Z', updated_at='2021-04-16T14:16:05.151Z')]

>>>
>>> removed_creds: List[Msf.Cred] = msf_rest_api.delete_creds(ids=[cred.id])
>>> print(f'Removed creds: {removed_creds}\n')
Removed creds: [Msf.Cred(id=68, workspace_id=215, username=None, private_data=None, private_type=None, jtr_format=None, address=None, port=-1, service_name=None, protocol=None, origin_type='Metasploit::Credential::Origin::Service', module_fullname=None, created_at='2021-04-16T14:15:36.173Z', updated_at='2021-04-16T14:15:36.173Z', origin_id=77, private_id=2, public_id=5, realm_id=None, logins_count=0, logins=None, public=None, private=None, origin=None)]
</code></pre>

<img src="https://python-libmsf.github.io/images/delete_cred.png" alt="Delete cred">

</details>


## MsfParser

Code example:

```python
from libmsf.msf import MsfData
from libmsf.parser import MsfParser

msf_parser: MsfParser = MsfParser()
msf_data: MsfData = msf_parser.parse_file(file_name='tests/msf_db_export.xml')

print(f'Workspace: {msf_data.workspace}')
print(f'Hosts: {msf_data.hosts}')
print(f'Services: {msf_data.services}')
print(f'Vulnerabilities: {msf_data.vulns}')
print(f'Notes: {msf_data.notes}')
```

Result example:

```shell
Workspace: unit_test_workspace
Hosts: [Msf.Host(id=246, workspace='unit_test_workspace', created_at='2021-04-17 14:12:22 UTC', host='None', address='192.168.1.1', mac='00:11:22:33:44:55', comm='unittest', name='unit.test.com', state='alive', os_name='linux', os_flavor='test', os_sp='test', os_lang='English', arch='x86', workspace_id=241, updated_at='2021-04-17 14:12:22 UTC', purpose='device', info='Host for unit tests', comments='Host for unit tests', scope='unit tests scope', virtual_host='unittest', note_count=1, vuln_count=1, service_count=1, host_detail_count=0, exploit_attempt_count=0, cred_count=0, detected_arch='', os_family='posix'), Msf.Host(id=247, workspace='unit_test_workspace', created_at='2021-04-17 14:12:22 UTC', host='None', address='192.168.1.2', mac='00:11:22:33:44:56', comm='unittest2', name='unit.test2.com', state='alive', os_name='linux', os_flavor='test', os_sp='test', os_lang='English', arch='x86', workspace_id=241, updated_at='2021-04-17 14:12:22 UTC', purpose='device', info='Host for unit tests 2', comments='Host for unit tests 2', scope='unit tests scope', virtual_host='unittest', note_count=1, vuln_count=1, service_count=1, host_detail_count=0, exploit_attempt_count=0, cred_count=0, detected_arch='', os_family='posix')]
Services: [Msf.Service(id=271, workspace='unit_test_workspace', host='192.168.1.1', host_id=246, created_at='2021-04-17 14:12:22 UTC', port=12345, proto='tcp', state='open', name='http', updated_at='2021-04-17 14:12:22 UTC', info='Unit test'), Msf.Service(id=272, workspace='unit_test_workspace', host='192.168.1.2', host_id=247, created_at='2021-04-17 14:12:22 UTC', port=12346, proto='tcp', state='open', name='http', updated_at='2021-04-17 14:12:22 UTC', info='Unit test 2')]
Vulnerabilities: [Msf.Vuln(id=285, workspace='unit_test_workspace', host='192.168.1.1', host_id=246, port=12345, service_id=271, created_at='2021-04-17 14:12:22 UTC', name='Unit test vuln name', updated_at='2021-04-17 14:12:22 UTC', info='Unit test vuln info', exploited_at='', vuln_detail_count=0, vuln_attempt_count=0, origin_id='', origin_type='', refs=['CVE-2020-2020', 'URL-https://unit.test.com/vuln'], module_refs='None'), Msf.Vuln(id=286, workspace='unit_test_workspace', host='192.168.1.2', host_id=247, port=12346, service_id=272, created_at='2021-04-17 14:12:22 UTC', name='Unit test vuln name 2', updated_at='2021-04-17 14:12:22 UTC', info='Unit test vuln info 2', exploited_at='', vuln_detail_count=0, vuln_attempt_count=0, origin_id='', origin_type='', refs=['CVE-2020-2021', 'URL-https://unit.test.com/vuln2'], module_refs='None')]
Notes: [Msf.Note(id=53, workspace='unit_test_workspace', workspace_id=241, host='192.168.1.1', host_id=246, service_id=-1, vuln_id=-1, port=-1, created_at='2021-04-17 14:12:22 UTC', updated_at='2021-04-17 14:12:22 UTC', ntype='host.comments', data='Unit test host comment', critical=False, seen=False), Msf.Note(id=54, workspace='unit_test_workspace', workspace_id=241, host='192.168.1.2', host_id=247, service_id=-1, vuln_id=-1, port=-1, created_at='2021-04-17 14:12:22 UTC', updated_at='2021-04-17 14:12:22 UTC', ntype='host.comments', data='Unit test host comment 2', critical=False, seen=False)]
```