from libmsf import Msf
from libmsf.rest import MsfRestApi
from typing import List

msf_api_key: str = (
    "cf2dbb7f9d1f92839a84f9c165ee9afef3dd3a3116bc99badf45be4ae5655168c9c2c3c58621b460"
)
msf_api_url: str = "https://localhost:5443"
msf_rest_api: MsfRestApi = MsfRestApi(api_key=msf_api_key, api_url=msf_api_url)

# Create workspace
print("Create workspace:\n")
workspace: Msf.Workspace = Msf.Workspace(name="test_workspace")

workspace.id = msf_rest_api.create_workspace(workspace=workspace)
print(f"New workspace: {workspace}\n")

# Hosts methods
print("Hosts methods:\n")
host: Msf.Host = Msf.Host()
host.workspace = workspace.name
host.address = "192.168.1.1"
host.mac = "00:11:22:33:44:55"
host.name = "unit.test.com"
host.os_name = "linux"
host.os_family = "posix"
host.os_flavor = "test"
host.os_sp = "test"
host.os_lang = "English"
host.purpose = "device"
host.info = "Host for unit tests"
host.comments = "Host for unit tests"
host.scope = "unit tests scope"
host.virtual_host = "unittest"
host.arch = "x86"
host.state = "alive"
host.comm = "unittest"

host.id = msf_rest_api.create_host(host=host)
print(f"New host: {host}\n")

new_host: Msf.Host = msf_rest_api.get_host_by_id(
    workspace=workspace.name, host_id=host.id
)
print(f"New host by id: {new_host}\n")

all_hosts: List[Msf.Host] = msf_rest_api.get_hosts(workspace=workspace.name)
print(f"All hosts: {all_hosts}\n")

removed_hosts: List[Msf.Host] = msf_rest_api.delete_hosts(ids=[host.id])
print(f"Removed hosts: {removed_hosts}\n")

# Services methods
print("Services methods:\n")
service: Msf.Service = Msf.Service()
service.workspace = workspace.name
service.host = host.address
service.port = 12345
service.proto = "tcp"
service.state = "open"
service.name = "http"
service.info = "Unit test"

service.id = msf_rest_api.create_service(service=service)
print(f"New service: {service}\n")

new_service: Msf.Service = msf_rest_api.get_service_by_id(
    workspace=workspace.name, service_id=service.id
)
print(f"New service by id: {new_service}\n")

all_services: List[Msf.Service] = msf_rest_api.get_services(workspace=workspace.name)
print(f"All services: {all_services}\n")

removed_services: List[Msf.Service] = msf_rest_api.delete_services(ids=[service.id])
print(f"Removed services: {removed_services}\n")

# Vulns methods
print("Vulns methods:\n")
vuln: Msf.Vuln = Msf.Vuln()
vuln.workspace = workspace.name
vuln.host = host.address
vuln.port = service.port
vuln.name = "Unit test vuln name"
vuln.info = "Unit test vuln info"
vuln.refs = ["CVE-2020-2020", "URL-https://unit.test.com/vuln"]

vuln.id = msf_rest_api.create_vuln(vuln=vuln)
print(f"New vuln: {vuln}\n")

new_vuln: Msf.Vuln = msf_rest_api.get_vuln_by_id(
    workspace=workspace.name, vuln_id=vuln.id
)
print(f"New vuln by id: {new_vuln}\n")

all_vulns: List[Msf.Vuln] = msf_rest_api.get_vulns(workspace=workspace.name)
print(f"All vulns: {all_vulns}\n")

removed_vulns: List[Msf.Vuln] = msf_rest_api.delete_vulns(ids=[vuln.id])
print(f"Removed vulns: {removed_vulns}\n")

# Loots methods
print("Loots methods:\n")
loot: Msf.Loot = Msf.Loot()
loot.workspace = workspace.name
loot.host = host.address
loot.port = service.port
loot.ltype = "unit.test.type"
loot.data = "dGVzdA=="
loot.name = "/tmp/unit.test"
loot.info = "Unit test file"
loot.content_type = "text/plain"
loot.path = "path.txt"

loot.id = msf_rest_api.create_loot(loot=loot)
print(f"New loot: {loot}\n")

new_loot: Msf.Loot = msf_rest_api.get_loot_by_id(
    workspace=workspace.name, loot_id=loot.id
)
print(f"New loot by id: {new_loot}\n")

all_loots: List[Msf.Loot] = msf_rest_api.get_loots(workspace=workspace.name)
print(f"All loots: {all_loots}\n")

removed_loots: List[Msf.Loot] = msf_rest_api.delete_loots(ids=[loot.id])
print(f"Removed loots: {removed_loots}\n")

# Notes methods
print("Notes methods:\n")
note: Msf.Note = Msf.Note()
note.workspace = workspace.name
note.host = host.address
note.ntype = "host.comments"
note.data = "Unit test host comment"

note.id = msf_rest_api.create_note(note=note)
print(f"New note: {note}\n")

new_note: Msf.Note = msf_rest_api.get_note_by_id(
    workspace=workspace.name, note_id=note.id
)
print(f"New note by id: {new_note}\n")

all_notes: List[Msf.Note] = msf_rest_api.get_notes(workspace=workspace.name)
print(f"All notes: {all_notes}\n")

removed_notes: List[Msf.Note] = msf_rest_api.delete_notes(ids=[note.id])
print(f"Removed notes: {removed_notes}\n")

# Creds and Logins methods
print("Creds and Logins methods:\n")

cred: Msf.Cred = Msf.Cred()
cred.workspace_id = workspace.id
cred.address = host.address
cred.port = service.port
cred.username = "UnitTestUser"
cred.private_data = "UnitTestPassword"
cred.private_type = "password"
cred.module_fullname = "auxiliary/scanner/http/http_login"
cred.service_name = service.name
cred.protocol = service.proto
cred.origin_type = "service"

cred.id = msf_rest_api.create_cred(cred=cred)
print(f"New cred: {cred}\n")

login: Msf.Login = Msf.Login()
login.workspace_id = workspace.id
login.address = host.address
login.port = service.port
login.core_id = cred.id
login.last_attempted_at = "2021-01-01T11:11:11.111Z"
login.service_name = service.name
login.protocol = service.proto
login.status = "Successful"
login.access_level = "admin"

login.id = msf_rest_api.create_login(login=login)
print(f"New login: {login}\n")

new_cred: Msf.Cred = msf_rest_api.get_cred_by_id(
    workspace=workspace.name, cred_id=cred.id
)
print(f"New cred by id: {new_cred}\n")

new_login: Msf.Login = msf_rest_api.get_login_by_id(login_id=login.id)
print(f"New login by id: {new_login}\n")

all_creds: List[Msf.Cred] = msf_rest_api.get_creds(workspace=workspace.name)
print(f"All creds: {all_creds}\n")

all_logins: List[Msf.Login] = msf_rest_api.get_logins()
print(f"All logins: {all_logins}\n")

removed_logins: List[Msf.Login] = msf_rest_api.delete_logins(ids=[login.id])
print(f"Removed logins: {removed_logins}\n")

removed_creds: List[Msf.Cred] = msf_rest_api.delete_creds(ids=[cred.id])
print(f"Removed creds: {removed_creds}\n")

# Workspaces methods
print("Workspaces methods:\n")
workspace_id: int = msf_rest_api.get_workspace_id_by_name(workspace_name=workspace.name)
print(f"New workspace id by name: {workspace_id}\n")

new_workspace: Msf.Workspace = msf_rest_api.get_workspace_by_id(
    workspace_id=workspace.id
)
print(f"New workspace by id: {new_workspace}\n")

all_workspaces: List[Msf.Workspace] = msf_rest_api.get_workspaces()
print(f"All workspaces: {all_workspaces}\n")

removed_workspace: Msf.Workspace = msf_rest_api.delete_workspace(
    workspace_name=workspace.name
)
print(f"Removed workspace: {removed_workspace}\n")
