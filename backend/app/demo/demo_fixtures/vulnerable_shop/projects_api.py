"""VULNERABLE SHOP -- DELIBERATELY INSECURE DEMO CODE. NOT REAL.

Shows the authorization matrix: three of the four /projects routes are guarded, the fourth was
forgotten. SecureAgent should flag the odd one out as inconsistent authorization.
"""

from flask import Flask

app = Flask(__name__)


@app.route("/projects")
@login_required
def list_projects():
    return "projects"


@app.route("/projects/<project_id>")
@login_required
def get_project(project_id):
    return "project"


@app.route("/projects", methods=["POST"])
@login_required
def create_project():
    return "created"


@app.route("/projects/<project_id>", methods=["DELETE"])
def delete_project(project_id):  # inconsistent authorization: siblings require login, this does not
    return "deleted"
