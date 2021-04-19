# Description
"""
msf.py: MSF dataclasses
Author: Vladimir Ivanov
License: MIT
Copyright 2021, Python Metasploit Library
"""

# Import
from typing import List, Optional, Union
from dataclasses import dataclass

# Authorship information
__author__ = 'Vladimir Ivanov'
__copyright__ = 'Copyright 2021, Python Metasploit Library'
__credits__ = ['']
__license__ = 'MIT'
__version__ = '0.1.1'
__maintainer__ = 'Vladimir Ivanov'
__email__ = 'ivanov.vladimir.mail@gmail.com'
__status__ = 'Development'


@dataclass
class Msf:

    @dataclass
    class Workspace:
        id: int = -1
        name: str = 'default'
        created_at: Optional[str] = None
        updated_at: Optional[str] = None
        boundary: Optional[str] = None
        description: Optional[str] = None
        owner_id: Optional[str] = None
        limit_to_network: bool = False
        import_fingerprint: bool = False

    @dataclass
    class Host:
        id: int = -1
        workspace: Optional[str] = None
        created_at: Optional[str] = None
        host: Optional[str] = None
        address: Optional[str] = None
        mac: Optional[str] = None
        comm: Optional[str] = None
        name: Optional[str] = None
        state: Optional[str] = None
        os_name: Optional[str] = None
        os_flavor: Optional[str] = None
        os_sp: Optional[str] = None
        os_lang: Optional[str] = None
        arch: Optional[str] = None
        workspace_id: int = -1
        updated_at: Optional[str] = None
        purpose: Optional[str] = None
        info: Optional[str] = None
        comments: Optional[str] = None
        scope: Optional[str] = None
        virtual_host: Optional[str] = None
        note_count: int = 0
        vuln_count: int = 0
        service_count: int = 0
        host_detail_count: int = 0
        exploit_attempt_count: int = 0
        cred_count: int = 0
        detected_arch: Optional[str] = None
        os_family: Optional[str] = None

    @dataclass
    class Service:
        id: int = -1
        workspace: Optional[str] = None
        host: Union[None, str, 'Msf.Host'] = None
        host_id: int = -1
        created_at: Optional[str] = None
        port: int = -1
        proto: Optional[str] = None
        state: Optional[str] = None
        name: Optional[str] = None
        updated_at: Optional[str] = None
        info: Optional[str] = None

    @dataclass
    class Vuln:
        id: int = -1
        workspace: Optional[str] = None
        host: Union[None, str, 'Msf.Host'] = None
        host_id: int = -1
        port: int = -1
        service_id: int = -1
        created_at: Optional[str] = None
        name: Optional[str] = None
        updated_at: Optional[str] = None
        info: Optional[str] = None
        exploited_at: Optional[str] = None
        vuln_detail_count: int = 0
        vuln_attempt_count: int = 0
        origin_id: Optional[str] = None
        origin_type: Optional[str] = None
        refs: Optional[List] = None
        module_refs: Optional[List] = None

    @dataclass
    class Loot:
        id: int = -1
        workspace: Optional[str] = None
        workspace_id: int = -1
        host: Union[None, str, 'Msf.Host'] = None
        host_id: int = -1
        port: int = -1
        service_id: int = -1
        created_at: Optional[str] = None
        updated_at: Optional[str] = None
        ltype: Optional[str] = None
        path: Optional[str] = None
        data: Optional[str] = None
        content_type: Optional[str] = None
        name: Optional[str] = None
        info: Optional[str] = None
        module_run_id: Optional[str] = None

    @dataclass
    class Note:
        id: int = -1
        workspace: Optional[str] = None
        workspace_id: int = -1
        host: Union[None, str, 'Msf.Host'] = None
        host_id: int = -1
        service_id: int = -1
        vuln_id: int = -1
        port: int = -1
        created_at: Optional[str] = None
        updated_at: Optional[str] = None
        ntype: Optional[str] = None
        data: Optional[str] = None
        critical: bool = False
        seen: bool = False

    @dataclass
    class Cred:
        id: int = -1
        workspace_id: int = -1
        username: Optional[str] = None
        private_data: Optional[str] = None
        private_type: Optional[str] = None
        jtr_format: Optional[str] = None
        address: Optional[str] = None
        port: int = -1
        service_name: Optional[str] = None
        protocol: Optional[str] = None
        origin_type: Optional[str] = None
        module_fullname: Optional[str] = None
        created_at: Optional[str] = None
        updated_at: Optional[str] = None
        origin_id: int = -1
        private_id: int = -1
        public_id: int = -1
        realm_id: int = -1
        logins_count: int = -1
        logins: Optional[List['Msf.Login']] = None
        public: Optional['Msf.Public'] = None
        private: Optional['Msf.Private'] = None
        origin: Optional['Msf.Origin'] = None

    @dataclass
    class Login:
        id: int = -1
        workspace_id: int = -1
        core_id: int = -1
        service_id: int = -1
        last_attempted_at: str = '2021-11-11T11:11:11.111Z'
        address: Optional[str] = None
        service_name: str = 'ssh'
        port: int = -1
        protocol: str = 'tcp'
        status: str = 'Successful'
        access_level: Optional[str] = None
        public: Optional[str] = None
        private: Optional[str] = None
        created_at: Optional[str] = None
        updated_at: Optional[str] = None

    @dataclass
    class Public:
        id: int = -1
        username: Optional[str] = None
        created_at: Optional[str] = None
        updated_at: Optional[str] = None
        type: Optional[str] = None

    @dataclass
    class Private:
        id: int = -1
        data: Optional[str] = None
        created_at: Optional[str] = None
        updated_at: Optional[str] = None
        jtr_format: Optional[str] = None
        type: Optional[str] = None

    @dataclass
    class Origin:
        id: int = -1
        service_id: int = -1
        module_full_name: Optional[str] = None
        created_at: Optional[str] = None
        updated_at: Optional[str] = None
        type: Optional[str] = None


@dataclass
class MsfData:
    workspace: Optional[str] = None
    workspaces: Optional[List[Msf.Workspace]] = None
    hosts: Optional[List[Msf.Host]] = None
    services: Optional[List[Msf.Service]] = None
    vulns: Optional[List[Msf.Vuln]] = None
    loots: Optional[List[Msf.Loot]] = None
    notes: Optional[List[Msf.Note]] = None
    creds: Optional[List[Msf.Cred]] = None
    logins: Optional[List[Msf.Login]] = None
