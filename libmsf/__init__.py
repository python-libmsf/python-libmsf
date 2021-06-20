# Description
"""
MSF dataclasses and marshmallow schemas
Author: Vladimir Ivanov
License: MIT
Copyright 2021, Python Metasploit Library
"""

# Import
from typing import List, Dict, Optional, Union
from dataclasses import dataclass, field
from marshmallow import fields, pre_load, post_load, pre_dump, post_dump, EXCLUDE
from marshmallow import Schema as MarshmallowSchema
from datetime import datetime
from ipaddress import IPv4Address, IPv6Address, ip_address
from pathlib import Path
from os import path
from configparser import ConfigParser


# Authorship information
__author__ = "Vladimir Ivanov"
__copyright__ = "Copyright 2021, Python Metasploit Library"
__credits__ = [""]
__license__ = "MIT"
__version__ = "0.2.4"
__maintainer__ = "Vladimir Ivanov"
__email__ = "ivanov.vladimir.mail@gmail.com"
__status__ = "Development"


class Msf:
    @dataclass
    class Config:
        file: str = f"{str(Path.home())}/.msf4/config"
        url: Optional[str] = None
        cert: Optional[str] = None
        skip_verify: bool = False
        api_token: Optional[str] = None

        class Schema(MarshmallowSchema):
            url = fields.String(missing=None)
            cert = fields.String(missing=None)
            skip_verify = fields.Boolean(missing=False)
            api_token = fields.String(missing=None)

            @post_load
            def make_config(self, data, **kwargs):
                return Msf.Config(**data)

    @dataclass
    class Workspace:
        id: int = 1
        name: str = "default"
        created_at: Optional[datetime] = None
        updated_at: Optional[datetime] = None
        boundary: Optional[str] = None
        description: Optional[str] = None
        owner_id: Optional[str] = None
        limit_to_network: bool = False
        import_fingerprint: bool = False

        class Schema(MarshmallowSchema):
            id = fields.Integer(required=True, load_only=True)
            name = fields.String(required=True)
            created_at = fields.DateTime(
                "%Y-%m-%dT%H:%M:%S.%fZ", missing=None, load_only=True
            )
            updated_at = fields.DateTime(
                "%Y-%m-%dT%H:%M:%S.%fZ", missing=None, load_only=True
            )
            boundary = fields.String(missing=None)
            description = fields.String(missing=None)
            owner_id = fields.String(missing=None, load_only=True)
            limit_to_network = fields.Boolean(missing=False)
            import_fingerprint = fields.Boolean(missing=False)

            @post_dump(pass_many=False)
            def clean_missing_fields(self, data, many, **kwargs):
                clean_data = data.copy()
                for key in filter(lambda key: data[key] is None, data):
                    del clean_data[key]
                for key in filter(lambda key: data[key] == -1, data):
                    del clean_data[key]
                return clean_data

            @post_load
            def make_workspace(self, data, **kwargs):
                return Msf.Workspace(**data)

    @dataclass
    class Host:
        id: int = -1
        workspace: Optional[str] = None
        workspace_id: int = 1
        created_at: Optional[datetime] = None
        updated_at: Optional[datetime] = None
        host: Optional[str] = None
        address: Union[None, IPv4Address, IPv6Address] = None
        mac: Optional[str] = None
        comm: Optional[str] = None
        name: Optional[str] = None
        state: Optional[str] = None
        os_name: Optional[str] = None
        os_flavor: Optional[str] = None
        os_sp: Optional[str] = None
        os_lang: Optional[str] = None
        arch: Optional[str] = None
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

        class Schema(MarshmallowSchema):
            id = fields.Integer(required=True, load_only=True)
            workspace = fields.String(dump_only=True)
            workspace_id = fields.Integer(missing=1, load_only=True)
            created_at = fields.DateTime(
                "%Y-%m-%dT%H:%M:%S.%fZ", missing=None, load_only=True
            )
            updated_at = fields.DateTime(
                "%Y-%m-%dT%H:%M:%S.%fZ", missing=None, load_only=True
            )
            host = fields.String(missing=None)
            address = fields.String(missing=None, load_only=True)
            mac = fields.String(missing=None)
            comm = fields.String(missing=None)
            name = fields.String(missing=None)
            state = fields.String(missing=None)
            os_name = fields.String(missing=None)
            os_flavor = fields.String(missing=None)
            os_sp = fields.String(missing=None)
            os_lang = fields.String(missing=None)
            arch = fields.String(missing=None)
            purpose = fields.String(missing=None)
            info = fields.String(missing=None)
            comments = fields.String(missing=None)
            scope = fields.String(missing=None)
            virtual_host = fields.String(missing=None)
            note_count = fields.Integer(missing=0, load_only=True)
            vuln_count = fields.Integer(missing=0, load_only=True)
            service_count = fields.Integer(missing=0, load_only=True)
            host_detail_count = fields.Integer(missing=0, load_only=True)
            exploit_attempt_count = fields.Integer(missing=0, load_only=True)
            cred_count = fields.Integer(missing=0, load_only=True)
            detected_arch = fields.String(missing=None)
            os_family = fields.String(missing=None)

            @pre_dump(pass_many=False)
            def pre_dump_host(self, data, **kwargs):
                if data.host is None:
                    data.host = data.address
                return data

            @post_dump(pass_many=False)
            def clean_missing_fields(self, data, many, **kwargs):
                clean_data = data.copy()
                for key in filter(lambda key: data[key] is None, data):
                    del clean_data[key]
                for key in filter(lambda key: data[key] == -1, data):
                    del clean_data[key]
                return clean_data

            @post_load
            def make_host(self, data, **kwargs):
                host = Msf.Host(**data)
                host.address = ip_address(host.address)
                return host

    @dataclass
    class Service:
        id: int = -1
        workspace: Optional[str] = None
        workspace_id: int = 1
        host: Union[None, IPv4Address, IPv6Address, "Msf.Host"] = None
        host_id: int = -1
        created_at: Optional[datetime] = None
        updated_at: Optional[datetime] = None
        port: int = -1
        proto: Optional[str] = None
        state: Optional[str] = None
        name: Optional[str] = None
        info: Optional[str] = None

        class Schema(MarshmallowSchema):
            id = fields.Integer(required=True, load_only=True)
            workspace = fields.String(dump_only=True)
            workspace_id = fields.Integer(missing=1, load_only=True)
            host = fields.Raw(missing=None)
            host_id = fields.Integer(missing=-1, load_only=True)
            created_at = fields.DateTime(
                "%Y-%m-%dT%H:%M:%S.%fZ", missing=None, load_only=True
            )
            updated_at = fields.DateTime(
                "%Y-%m-%dT%H:%M:%S.%fZ", missing=None, load_only=True
            )
            port = fields.Integer(missing=-1)
            proto = fields.String(missing=None)
            state = fields.String(missing=None)
            name = fields.String(missing=None)
            info = fields.String(missing=None)

            @pre_dump(pass_many=False)
            def convert_host_address_to_string(self, data, many, **kwargs):
                if isinstance(data.host, IPv4Address) or isinstance(
                    data.host, IPv6Address
                ):
                    data.host = str(data.host)
                return data

            @post_dump(pass_many=False)
            def clean_missing_fields(self, data, many, **kwargs):
                clean_data = data.copy()
                for key in filter(lambda key: data[key] is None, data):
                    del clean_data[key]
                for key in filter(lambda key: data[key] == -1, data):
                    del clean_data[key]
                return clean_data

            @post_load
            def make_service(self, data, **kwargs):
                result = Msf.Service(**data)
                if isinstance(result.host, Dict):
                    result.host = Msf.Host.Schema().load(result.host)
                return result

    @dataclass
    class Vuln:
        id: int = -1
        workspace: Optional[str] = None
        workspace_id: int = 1
        host: Union[None, IPv4Address, IPv6Address, "Msf.Host"] = None
        host_id: int = -1
        created_at: Optional[datetime] = None
        updated_at: Optional[datetime] = None
        port: int = -1
        service_id: int = -1
        name: Optional[str] = None
        info: Optional[str] = None
        exploited_at: Optional[datetime] = None
        vuln_detail_count: int = 0
        vuln_attempt_count: int = 0
        origin_id: Optional[str] = None
        origin_type: Optional[str] = None
        refs: Optional[List] = field(default_factory=lambda: [])
        module_refs: Optional[List] = field(default_factory=lambda: [])

        class Schema(MarshmallowSchema):
            id = fields.Integer(required=True, load_only=True)
            workspace = fields.String(dump_only=True)
            workspace_id = fields.Integer(missing=1, load_only=True)
            host = fields.Raw(missing=None)
            host_id = fields.Integer(missing=-1, load_only=True)
            created_at = fields.DateTime(
                "%Y-%m-%dT%H:%M:%S.%fZ", missing=None, load_only=True
            )
            updated_at = fields.DateTime(
                "%Y-%m-%dT%H:%M:%S.%fZ", missing=None, load_only=True
            )
            port = fields.Integer(missing=-1)
            service_id = fields.Integer(missing=-1, load_only=True, allow_none=True)
            name = fields.String(missing=None)
            info = fields.String(missing=None)
            exploited_at = fields.DateTime(
                "%Y-%m-%dT%H:%M:%S.%fZ", missing=None, load_only=True
            )
            vuln_detail_count = fields.Integer(missing=0, load_only=True)
            vuln_attempt_count = fields.Integer(missing=0, load_only=True)
            origin_id = fields.String(missing=None)
            origin_type = fields.String(missing=None)
            refs = fields.List(fields.String, missing=[])
            module_refs = fields.List(fields.String, missing=[], load_only=True)

            @pre_dump(pass_many=False)
            def convert_host_address_to_string(self, data, many, **kwargs):
                if isinstance(data.host, IPv4Address) or isinstance(
                    data.host, IPv6Address
                ):
                    data.host = str(data.host)
                return data

            @post_dump(pass_many=False)
            def clean_missing_fields(self, data, many, **kwargs):
                clean_data = data.copy()
                for key in filter(lambda key: data[key] is None, data):
                    del clean_data[key]
                for key in filter(lambda key: data[key] == -1, data):
                    del clean_data[key]
                return clean_data

            @pre_load(pass_many=False)
            def pre_load_vuln(self, data, **kwargs):
                result = data.copy()
                result["refs"] = list()
                result["module_refs"] = list()
                for reference in data["refs"]:
                    if "name" in reference:
                        result["refs"].append(reference["name"])
                for reference in data["module_refs"]:
                    if "name" in reference:
                        result["refs"].append(reference["name"])
                return result

            @post_load
            def make_vuln(self, data, **kwargs):
                result = Msf.Vuln(**data)
                if isinstance(result.host, Dict):
                    result.host = Msf.Host.Schema().load(result.host)
                return result

    @dataclass
    class Loot:
        id: int = -1
        workspace: Optional[str] = None
        workspace_id: int = 1
        host: Union[None, IPv4Address, IPv6Address, "Msf.Host"] = None
        host_id: int = -1
        created_at: Optional[datetime] = None
        updated_at: Optional[datetime] = None
        port: int = -1
        service_id: int = -1
        ltype: Optional[str] = None
        path: Optional[str] = None
        data: Optional[str] = None
        content_type: Optional[str] = None
        name: Optional[str] = None
        info: Optional[str] = None
        module_run_id: Optional[str] = None

        class Schema(MarshmallowSchema):
            id = fields.Integer(required=True, load_only=True, allow_none=True)
            workspace = fields.String(dump_only=True)
            workspace_id = fields.Integer(missing=1, load_only=True)
            host = fields.Raw(missing=None)
            host_id = fields.Integer(missing=-1, load_only=True)
            created_at = fields.DateTime(
                "%Y-%m-%dT%H:%M:%S.%fZ", missing=None, load_only=True
            )
            updated_at = fields.DateTime(
                "%Y-%m-%dT%H:%M:%S.%fZ", missing=None, load_only=True
            )
            port = fields.Integer(missing=-1)
            service_id = fields.Integer(missing=-1, load_only=True, allow_none=True)
            ltype = fields.String(missing=None)
            path = fields.String(missing=None)
            data = fields.String(missing=None)
            content_type = fields.String(missing=None)
            name = fields.String(missing=None)
            info = fields.String(missing=None)
            module_run_id = fields.String(missing=None)

            @pre_dump(pass_many=False)
            def convert_host_address_to_string(self, data, many, **kwargs):
                if isinstance(data.host, IPv4Address) or isinstance(
                    data.host, IPv6Address
                ):
                    data.host = str(data.host)
                return data

            @post_dump(pass_many=False)
            def clean_missing_fields(self, data, many, **kwargs):
                clean_data = data.copy()
                for key in filter(lambda key: data[key] is None, data):
                    del clean_data[key]
                for key in filter(lambda key: data[key] == -1, data):
                    del clean_data[key]
                return clean_data

            @post_load
            def make_loot(self, data, **kwargs):
                result = Msf.Loot(**data)
                if isinstance(result.host, Dict):
                    result.host = Msf.Host.Schema().load(result.host)
                return result

    @dataclass
    class Note:
        id: int = -1
        workspace: Optional[str] = None
        workspace_id: int = 1
        host: Union[None, IPv4Address, IPv6Address, "Msf.Host"] = None
        host_id: int = -1
        created_at: Optional[datetime] = None
        updated_at: Optional[datetime] = None
        port: int = -1
        service_id: int = -1
        vuln_id: int = -1
        ntype: Optional[str] = None
        data: Optional[str] = None
        critical: bool = False
        seen: bool = False

        class Schema(MarshmallowSchema):
            id = fields.Integer(required=True, load_only=True)
            workspace = fields.String(dump_only=True)
            workspace_id = fields.Integer(missing=1, load_only=True)
            host = fields.Raw(missing=None)
            host_id = fields.Integer(missing=-1, load_only=True)
            created_at = fields.DateTime(
                "%Y-%m-%dT%H:%M:%S.%fZ", missing=None, load_only=True
            )
            updated_at = fields.DateTime(
                "%Y-%m-%dT%H:%M:%S.%fZ", missing=None, load_only=True
            )
            port = fields.Integer(missing=-1, allow_none=True)
            service_id = fields.Integer(missing=-1, load_only=True, allow_none=True)
            vuln_id = fields.Integer(missing=-1, load_only=True, allow_none=True)
            ntype = fields.String(missing=None)
            data = fields.String(missing=None)
            critical = fields.Boolean(missing=False, allow_none=True)
            seen = fields.Boolean(missing=False, allow_none=True)

            @pre_dump(pass_many=False)
            def convert_host_address_to_string(self, data, many, **kwargs):
                if isinstance(data.host, IPv4Address) or isinstance(
                    data.host, IPv6Address
                ):
                    data.host = str(data.host)
                return data

            @post_dump(pass_many=False)
            def clean_missing_fields(self, data, many, **kwargs):
                clean_data = data.copy()
                for key in filter(lambda key: data[key] is None, data):
                    del clean_data[key]
                for key in filter(lambda key: data[key] == -1, data):
                    del clean_data[key]
                return clean_data

            @pre_load(pass_many=False)
            def pre_make_note(self, data, many, **kwargs):
                if "data" in data:
                    if isinstance(data["data"], Dict):
                        if "output" in data["data"]:
                            data["data"] = str(data["data"]["output"])
                        else:
                            data["data"] = str(data["data"])
                    else:
                        data["data"] = str(data["data"])
                return data

            @post_load
            def make_note(self, data, **kwargs):
                result = Msf.Note(**data)
                if isinstance(result.host, Dict):
                    result.host = Msf.Host.Schema().load(result.host)
                return result

    @dataclass
    class Cred:
        id: int = -1
        workspace_id: int = 1
        username: Optional[str] = None
        private_data: Optional[str] = None
        private_type: Optional[str] = None
        jtr_format: Optional[str] = None
        address: Union[None, IPv4Address, IPv6Address] = None
        port: int = -1
        service_name: Optional[str] = None
        protocol: Optional[str] = None
        origin_type: str = "service"
        module_fullname: Optional[str] = None
        created_at: Optional[datetime] = None
        updated_at: Optional[datetime] = None
        origin_id: int = -1
        private_id: int = -1
        public_id: int = -1
        realm_id: int = -1
        logins_count: int = -1
        logins: Optional[List["Msf.Login"]] = field(default_factory=lambda: [])
        public: Optional["Msf.Public"] = None
        private: Optional["Msf.Private"] = None
        origin: Optional["Msf.Origin"] = None

        class Schema(MarshmallowSchema):
            id = fields.Integer(required=True, load_only=True)
            workspace_id = fields.Integer(required=True)
            username = fields.String(missing=None)
            private_data = fields.String(missing=None)
            private_type = fields.String(missing=None)
            jtr_format = fields.String(missing=None)
            address = fields.String(missing=None)
            port = fields.Integer(missing=-1)
            service_name = fields.String(missing=None)
            protocol = fields.String(missing=None)
            origin_type = fields.String(missing="service")
            module_fullname = fields.String(missing=None)
            created_at = fields.DateTime(
                "%Y-%m-%dT%H:%M:%S.%fZ", missing=None, load_only=True
            )
            updated_at = fields.DateTime(
                "%Y-%m-%dT%H:%M:%S.%fZ", missing=None, load_only=True
            )
            origin_id = fields.Integer(missing=-1, load_only=True)
            private_id = fields.Integer(missing=-1, load_only=True)
            public_id = fields.Integer(missing=-1, load_only=True)
            realm_id = fields.Integer(missing=-1, load_only=True, allow_none=True)
            logins_count = fields.Integer(missing=-1, load_only=True)
            logins = fields.Nested(
                lambda: Msf.Login.Schema, many=True, missing=[], load_only=True
            )
            public = fields.Nested(
                lambda: Msf.Public.Schema, many=False, missing=None, load_only=True
            )
            private = fields.Nested(
                lambda: Msf.Private.Schema, many=False, missing=None, load_only=True
            )
            origin = fields.Nested(
                lambda: Msf.Origin.Schema, many=False, missing=None, load_only=True
            )

            @pre_dump(pass_many=False)
            def convert_host_address_to_string(self, data, many, **kwargs):
                if isinstance(data.address, IPv4Address) or isinstance(
                    data.address, IPv6Address
                ):
                    data.address = str(data.address)
                return data

            @post_dump(pass_many=False)
            def clean_missing_fields(self, data, many, **kwargs):
                clean_data = data.copy()
                for key in filter(lambda key: data[key] is None, data):
                    del clean_data[key]
                for key in filter(lambda key: data[key] == -1, data):
                    del clean_data[key]
                return clean_data

            @post_load
            def make_cred(self, data, **kwargs):
                return Msf.Cred(**data)

    @dataclass
    class Login:
        id: int = -1
        workspace_id: int = 1
        created_at: Optional[datetime] = None
        updated_at: Optional[datetime] = None
        last_attempted_at: Optional[datetime] = None
        core_id: int = -1
        service_id: int = -1
        address: Optional[str] = None
        service_name: str = "ssh"
        port: int = -1
        protocol: str = "tcp"
        status: str = "Successful"
        access_level: Optional[str] = None
        public: Optional[str] = None
        private: Optional[str] = None

        class Schema(MarshmallowSchema):
            id = fields.Integer(required=True, load_only=True)
            workspace_id = fields.Integer(required=True, dump_only=True)
            created_at = fields.DateTime(
                "%Y-%m-%dT%H:%M:%S.%fZ", missing=None, load_only=True
            )
            updated_at = fields.DateTime(
                "%Y-%m-%dT%H:%M:%S.%fZ", missing=None, load_only=True
            )
            last_attempted_at = fields.DateTime("%Y-%m-%dT%H:%M:%S.%fZ", missing=None)
            core_id = fields.Integer(missing=-1)
            service_id = fields.Integer(missing=-1, load_only=True, allow_none=True)
            address = fields.String(missing=None)
            service_name = fields.String(missing=None)
            port = fields.Integer(missing=-1)
            protocol = fields.String(missing=None)
            status = fields.String(missing=None)
            access_level = fields.String(missing=None)
            public = fields.String(missing=None, load_only=True)
            private = fields.String(missing=None, load_only=True)

            @pre_dump(pass_many=False)
            def convert_host_address_to_string(self, data, many, **kwargs):
                if isinstance(data.address, IPv4Address) or isinstance(
                    data.address, IPv6Address
                ):
                    data.address = str(data.address)
                return data

            @post_dump(pass_many=False)
            def post_dump_login(self, data, many, **kwargs):
                if "core_id" in data:
                    data["core"] = {"id": data["core_id"]}
                    del data["core_id"]
                return data

            @post_dump(pass_many=False)
            def clean_missing_fields(self, data, many, **kwargs):
                clean_data = data.copy()
                for key in filter(lambda key: data[key] is None, data):
                    del clean_data[key]
                for key in filter(lambda key: data[key] == -1, data):
                    del clean_data[key]
                return clean_data

            @post_load
            def make_login(self, data, **kwargs):
                return Msf.Login(**data)

    @dataclass
    class Public:
        id: int = -1
        created_at: Optional[datetime] = None
        updated_at: Optional[datetime] = None
        username: Optional[str] = None
        type: Optional[str] = None

        class Schema(MarshmallowSchema):
            id = fields.Integer(required=True, load_only=True)
            created_at = fields.DateTime(
                "%Y-%m-%dT%H:%M:%S.%fZ", missing=None, load_only=True
            )
            updated_at = fields.DateTime(
                "%Y-%m-%dT%H:%M:%S.%fZ", missing=None, load_only=True
            )
            username = fields.String(missing=None, load_only=True)
            type = fields.String(missing=None, load_only=True)

            @post_load
            def make_public(self, data, **kwargs):
                return Msf.Public(**data)

    @dataclass
    class Private:
        id: int = -1
        created_at: Optional[datetime] = None
        updated_at: Optional[datetime] = None
        data: Optional[str] = None
        jtr_format: Optional[str] = None
        type: Optional[str] = None

        class Schema(MarshmallowSchema):
            id = fields.Integer(required=True, load_only=True)
            created_at = fields.DateTime(
                "%Y-%m-%dT%H:%M:%S.%fZ", missing=None, load_only=True
            )
            updated_at = fields.DateTime(
                "%Y-%m-%dT%H:%M:%S.%fZ", missing=None, load_only=True
            )
            data = fields.String(missing=None, load_only=True)
            jtr_format = fields.String(missing=None, load_only=True)
            type = fields.String(missing=None, load_only=True)

            @post_load
            def make_private(self, data, **kwargs):
                return Msf.Private(**data)

    @dataclass
    class Origin:
        id: int = -1
        created_at: Optional[datetime] = None
        updated_at: Optional[datetime] = None
        service_id: int = -1
        module_full_name: Optional[str] = None
        type: Optional[str] = None

        class Schema(MarshmallowSchema):
            id = fields.Integer(required=True, load_only=True)
            created_at = fields.DateTime(
                "%Y-%m-%dT%H:%M:%S.%fZ", missing=None, load_only=True
            )
            updated_at = fields.DateTime(
                "%Y-%m-%dT%H:%M:%S.%fZ", missing=None, load_only=True
            )
            service_id = fields.Integer(missing=-1, load_only=True)
            module_full_name = fields.String(missing=None, load_only=True)
            type = fields.String(missing=None, load_only=True)

            @post_load
            def make_origin(self, data, **kwargs):
                return Msf.Origin(**data)

    @staticmethod
    def load_config() -> Config:
        config: Msf.Config = Msf.Config()
        config_parser: ConfigParser = ConfigParser()
        if path.isfile(config.file) and path.getsize(config.file) > 0:
            config_parser.read(config.file)
            default_db: Optional[str] = None
            if "framework/database" in config_parser.sections():
                if "default_db" in config_parser["framework/database"]:
                    default_db = config_parser["framework/database"]["default_db"]
            if default_db is not None:
                if f"framework/database/{default_db}":
                    config = Msf.Config.Schema(unknown=EXCLUDE).load(
                        config_parser[f"framework/database/{default_db}"]
                    )
        return config


@dataclass
class MsfData:
    workspace: Optional[str] = None
    workspaces: Optional[List[Msf.Workspace]] = field(default_factory=lambda: [])
    hosts: Optional[List[Msf.Host]] = field(default_factory=lambda: [])
    services: Optional[List[Msf.Service]] = field(default_factory=lambda: [])
    vulns: Optional[List[Msf.Vuln]] = field(default_factory=lambda: [])
    loots: Optional[List[Msf.Loot]] = field(default_factory=lambda: [])
    notes: Optional[List[Msf.Note]] = field(default_factory=lambda: [])
    creds: Optional[List[Msf.Cred]] = field(default_factory=lambda: [])
    logins: Optional[List[Msf.Login]] = field(default_factory=lambda: [])
