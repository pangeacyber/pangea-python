import copy
import dataclasses
import logging
import os

# App related imports
from utils.db import Db
from utils.employee import Employee, EmployeeStatus

# Pangea SDK
from pangea.config import PangeaConfig
from pangea.services import Audit, Embargo, Redact

PANGEA_TOKEN = os.getenv("PANGEA_TOKEN")

EMBARGO_CONFIG_ID = os.getenv("EMBARGO_CONFIG_ID")
REDACT_CONFIG_ID = os.getenv("REDACT_CONFIG_ID")
AUDIT_CONFIG_ID = os.getenv("AUDIT_CONFIG_ID")
PANGEA_CSP = os.getenv("PANGEA_CSP")


class App:
    """Demo app showing usage of Pangea SDK"""

    def __init__(self):
        self._db = self._db_instance()
        self._embargo_config = PangeaConfig(domain=f"{PANGEA_CSP}.pangea.cloud", config_id=EMBARGO_CONFIG_ID)
        self._redact_config = PangeaConfig(domain=f"{PANGEA_CSP}.pangea.cloud", config_id=REDACT_CONFIG_ID)
        self._audit_config = PangeaConfig(domain=f"{PANGEA_CSP}.pangea.cloud", config_id=AUDIT_CONFIG_ID)

        # Setup Pangea Audit service
        self._pangea_audit = Audit(token=PANGEA_TOKEN, config=self._audit_config)

        # Setup Pangea Redact service
        self._pangea_redact = Redact(token=PANGEA_TOKEN, config=self._redact_config)

        # Setup Pangea Embargo Service
        self._pangea_embargo = Embargo(token=PANGEA_TOKEN, config=self._embargo_config)

    def _db_instance(self) -> Db:
        return Db()

    def setup(self):
        self._db.setup_employee_table()

    def shutdown(self):
        self._db.teardown()

    def upload_resume(self, user: str, client_ip: str, data: dict) -> (int, str):
        """Handles uploading a candidate's resume into employee Database

        Args:
            data - JSON object containing candidate info
            user - the user that is making the request
            client_ip - the IP address of invoking client

        Returns:
            bool - success, str - message
        """
        logging.info(f"[App.upload_resume] Processing input from {user}, {client_ip}")

        # Add the candidate to database
        emp = data

        candidate = Employee(
            first_name=emp["first_name"],
            last_name=emp["last_name"],
            personal_email=emp["email"],
            phone=emp["phone"],
            date_of_birth=emp["dob"],
            ssn=emp["ssn"],
            status=EmployeeStatus.CANDIDATE,
        )

        # Check client IP against Pangea's Embargo Service
        resp = self._pangea_embargo.ip_check(client_ip)

        logging.info(f"[App.upload_resume] Embargo response: {resp.request_id}, {resp.result}")

        if resp.result["sanctions"] is not None:
            audit_data = {
                "action": "add_employee",
                "actor": user,
                "target": candidate.personal_email,
                "status": "error",
                "message": f"Resume denied - sanctioned country from {client_ip}",
                "source": "web",
            }
            resp = self._pangea_audit.log(event=audit_data)
            if resp.success:
                logging.info(f"[App.upload_resume] Audit log ID: {resp.request_id}, Success: {resp.status}")
            else:
                logging.error(f"[App.upload_resume] Audit log Error: {resp.response.text}")
            return (403, f"Submissions from sanctioned country not allowed")

        ######################################
        # TODO: Upload Driver's License Photo
        ######################################

        ret = self._db.add_employee(candidate)

        # Redact
        resp = self._pangea_redact.redact_structured(emp)
        if resp.success:
            logging.info(
                f"[App.upload_resume] Redacted ID: {resp.request_id}, Success: {resp.status}, Result: {resp.result}"
            )
            emp = resp.result["redacted_data"]  # set to redacted data
        else:
            logging.error(f"App.upload_resume] Redaction Error: {resp.response.text}")

        if ret:
            # Audit log
            audit_data = {
                "action": "add_employee",
                "actor": user,
                "target": candidate.personal_email,
                "status": "success",
                "message": f"Resume accepted.",
                "new": emp,
                "source": "web",
            }

            resp = self._pangea_audit.log(event=audit_data)
            if resp.success:
                logging.info(f"[App.upload_resume] Audit log ID: {resp.request_id}, Success: {resp.status}")
            else:
                logging.error(f"[App.upload_resume] Audit log Error: {resp.response.text}")
            return (201, f"Resume accepted")
        else:
            # Audit log
            audit_data = {
                "action": "add_employee",
                "actor": user,
                "target": candidate.personal_email,
                "status": "error",
                "message": f"Resume denied: {emp}",
                "source": "web",
            }
            resp = self._pangea_audit.log(event=audit_data)
            if resp.success:
                logging.info(f"[App.upload_resume] Audit log ID: {resp.request_id}, Success: {resp.status}")
            else:
                logging.error(f"[App.upload_resume] Audit log Error: {resp.response.text}")
            return (400, f"Bad request")

    def fetch_employee_record(self, user: str, email: str) -> (int, str):
        """Returns an employee record.  Fields may be redacted depending on the user's identity

        Args:
            user - the user that is making the request
            email - the personal or work email of the employee to look up

        Returns:
            bool - success, str - message
        """
        logging.info(f"[App.fetch_employee_record] Processing input from {user}, {email}")

        ##################################
        # TODO: AuthZ to determine access
        ##################################

        ret, emp = self._db.lookup_employee(email)

        # Audit log
        audit_data = {
            "action": "lookup_employee",
            "actor": user,
            "target": email,
            "status": "success" if ret else "error",
            "message": "Requested employee record",
            "source": "web",
        }
        resp = self._pangea_audit.log(event=audit_data)
        if resp.success:
            logging.info(f"[App.fetch_employee_record] Audit log ID: {resp.request_id}, Success: {resp.status}")
        else:
            logging.error(f"[App.fetch_employee_record] Audit log Error: {resp.response.text}")

        if ret:
            return (200, {"employee": dataclasses.asdict(emp)})

        return (400, "Bad request")

    def update_employee(self, user: str, data: dict) -> (int, str):
        """Updates the employee status

        Args:
            user - the user that is making the request -- TODO: this will be AuthZ based on token later
            data - the input fields, i.e.:
                {
                    "email" : "jane.smith@gmail.com",
                    "start_date" : "July 1, 2022",
                    "term_date" : "July 1, 2022",
                    "manager_id" : 1,
                    "department" : "sales",
                    "salary" : "100000"
                    "status" : "contractor",
                    "company_email" "jane.smith@acme.com"
                }

        Returns:
            bool - success, str - message
        """
        logging.info(f"[App.update_employee] Processing input from {user}: {data}")

        ##################################
        # TODO: AuthZ to determine access
        ##################################

        # Fetch employee record
        ret, emp = self._db.lookup_employee(data["email"])

        empold = copy.copy(emp)

        if ret and emp:
            # update the record
            if "start_date" in data:
                emp.start_date = data["start_date"]
            if "term_date" in data:
                emp.term_date = data["term_date"]
            if "manager_id" in data:
                emp.manager_id = data["manager_id"]
            if "department" in data:
                emp.department = data["department"]
            if "salary" in data:
                emp.salary = data["salary"]
            if "status" in data:
                emp.status = EmployeeStatus(data["status"])
            if "company_email" in data:
                emp.company_email = data["company_email"]

            ret = self._db.update_employee(emp)

            # Audit log
            audit_data = {
                "action": "update_employee",
                "actor": user,
                "target": data["email"],
                "status": "success" if ret else "error",
                "message": "Record updated" if ret else "Failed to update record",
                "old": dataclasses.asdict(empold),
                "new": dataclasses.asdict(emp),
                "source": "web",
            }
            resp = self._pangea_audit.log(event=audit_data)
            if resp.success:
                logging.info(f"[App.update_employee] Audit log ID: {resp.request_id}, Success: {resp.status}")
            else:
                logging.error(f"[App.update_employee] Audit log Error: {resp.response.text}")

            if ret:
                logging.info(f"[App.update_employee] Successfully updated employee record")
                return (200, "Success")
            else:
                logging.error(f"[App.update_employee] Database update error")
                return (500, "Datastore update error")
        else:
            logging.error(f'[App.update_employee] Employee {data["email"]} not found')
            return (404, "Employee not found")
