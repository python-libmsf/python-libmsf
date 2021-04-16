# python-libmsf

## Description

libmsf is a python library for work with Metasploit web service.

With libmsf you can work with Metasploit objects such as:

 - [Workspaces](#workspaces)
 - [Hosts](#hosts)
 - [Services](#services)
 - [Vulnerabilities](#vulns)
 - [Loots](#loots)
 - [Notes](#notes)
 - [Credentials](#creds)
 - [Logins](#logins)

libmsf easy to use:

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
pip3 install python-libmsf
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

<details>
  <summary markdown="span">Init MSF webservice:</summary>

```shell
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

```

</details>

Metasploit web service user API token stored in file: `~/.msf4/config`

<details>
  <summary markdown="span">MSF webservice config:</summary>

```shell
$ cat ~/.msf4/config
[framework/database]
default_db=local-https-data-service

[framework/database/local-https-data-service]
url=https://localhost:5443
cert=/home/user/.msf4/msf-ws-cert.pem
skip_verify=true
api_token=cf2dbb7f9d1f92839a84f9c165ee9afef3dd3a3116bc99badf45be4ae5655168c9c2c3c58621b460
```

</details>

Metasploit web service swagger page: `https://localhost:5443/api/v1/api-docs`

## Workspaces

Create workspace:

<details>
  <summary markdown="span">Example:</summary>

```python
from libmsf.msf import Msf
from libmsf.rest import MsfRestApi

msf_api_key: str = 'cf2dbb7f9d1f92839a84f9c165ee9afef3dd3a3116bc99badf45be4ae5655168c9c2c3c58621b460'
msf_api_url: str = 'https://localhost:5443'
msf_rest_api: MsfRestApi = MsfRestApi(api_key=msf_api_key, api_url=msf_api_url)

print('Create workspace:\n')
workspace: Msf.Workspace = Msf.Workspace(name='test_workspace')

workspace.id = msf_rest_api.create_workspace(workspace=workspace)
print(f'New workspace: {workspace}\n')
```

```shell
>>> from libmsf.msf import Msf
>>> from libmsf.rest import MsfRestApi
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
New workspace: Msf.Workspace(id=198, name='test_workspace', created_at=None, updated_at=None, boundary=None, description=None, owner_id=None, limit_to_network=False, import_fingerprint=False)

```

```shell
msf6 > workspace
  test_workspace
* default
msf6 >
```

</details>

![Create workspace](images/create_workspace.png)

Delete workspace:

<details>
  <summary markdown="span">Example:</summary>

```python
from libmsf.msf import Msf
from libmsf.rest import MsfRestApi

msf_api_key: str = 'cf2dbb7f9d1f92839a84f9c165ee9afef3dd3a3116bc99badf45be4ae5655168c9c2c3c58621b460'
msf_api_url: str = 'https://localhost:5443'
msf_rest_api: MsfRestApi = MsfRestApi(api_key=msf_api_key, api_url=msf_api_url)

print('Create workspace:\n')
workspace: Msf.Workspace = Msf.Workspace(name='test_workspace')

workspace.id = msf_rest_api.create_workspace(workspace=workspace)
print(f'New workspace: {workspace}\n')
```

```shell
>>> from libmsf.msf import Msf
>>> from libmsf.rest import MsfRestApi
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
New workspace: Msf.Workspace(id=198, name='test_workspace', created_at=None, updated_at=None, boundary=None, description=None, owner_id=None, limit_to_network=False, import_fingerprint=False)

```

```shell
msf6 > workspace
  test_workspace
* default
msf6 >
```

</details>

