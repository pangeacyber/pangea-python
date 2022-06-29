from dataclasses import dataclass
from enum import IntEnum

class EmployeeStatus(IntEnum):
    UNKNOWN = 1
    CANDIDATE = 2
    FULL_TIME = 3
    CONTRACTOR = 4
    TERMINATED = 5

@dataclass
class Employee:
    """ Class representing an employee 
    """
    employee_id: int = -1
    first_name: str = ''
    last_name: str = ''
    company_email: str = ''
    personal_email: str = ''
    phone: str = ''
    date_of_birth: str = ''
    start_date: str = ''
    term_date: str = ''
    department: str = ''
    manager_id: int = -1
    salary: float = 0.0
    medical: str = ''
    profile_picture_path: str = ''
    dl_picture_path: str = ''
    ssn: str = ''
    status: EmployeeStatus = EmployeeStatus.UNKNOWN
