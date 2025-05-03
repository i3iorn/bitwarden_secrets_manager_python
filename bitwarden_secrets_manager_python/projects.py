import json
from typing import List, Dict, Optional, Any

from bitwarden_secrets_manager_python.core import BitwardenCLI
from bitwarden_secrets_manager_python.core.utils import BWObjects


class ProjectManager:
    def __init__(self, cli: BitwardenCLI):
        self.cli = cli

    def list_projects(self, print_to_console: bool = False) -> List[Dict]:
        response = self.cli.execute([BWObjects.PROJECT, 'list'])
        if print_to_console:
            print(response)
        return response

    def create_project(self, project_id: str, metadata: Optional[Dict[str, Any]] = None, print_to_console: bool = False) -> Dict:
        payload = json.dumps({"id": project_id, **(metadata or {})})
        response = self.cli.execute([BWObjects.PROJECT, 'create', payload])
        if print_to_console:
            print(response)
        return response

    def edit_project(self, project_id: str, updates: Dict[str, Any], print_to_console: bool = False) -> Dict:
        payload = json.dumps(updates)
        response = self.cli.execute([BWObjects.PROJECT, 'edit', project_id, payload])
        if print_to_console:
            print(response)
        return response

    def delete_project(self, project_id: str, print_to_console: bool = False) -> None:
        self.cli.execute([BWObjects.PROJECT, 'delete', project_id], parse_json=False)
        if print_to_console:
            print(f"Deleted project {project_id}")
