import logging
import sqlite3 as sl

from utils.employee import Employee, EmployeeStatus


class Db:
    def __init__(self):
        self.init()

    def init(self):
        """Connects to the database"""
        self._conn = sl.connect("demo-app.db")
        logging.info("[Db.init] Connected to database")

    def teardown(self):
        """Closes database connection"""
        self._conn.close()
        logging.info("[Db.teardown] Closed database connection")

    def setup_employee_table(self):
        """Creates the EMPLOYEE table"""
        with self._conn:
            self._conn.execute(
                """
                CREATE TABLE employee (
                    id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
                    first_name TEXT,
                    last_name TEXT,
                    company_email TEXT,
                    personal_email TEXT,
                    phone TEXT,
                    date_of_birth TEXT,
                    start_date TEXT,
                    term_date TEXT,
                    department TEXT,
                    manager INTEGER,
                    salary INTEGER,
                    medical TEXT,
                    profile_picture BLOB,
                    dl_picture BLOB,
                    ssn TEXT,
                    status INTEGER,
                    FOREIGN KEY(manager) REFERENCES employee(id)
                );
            """
            )

            self._conn.execute(
                """
                CREATE UNIQUE INDEX idx_employee_pemail
                    ON employee (personal_email
                );
            """
            )

            self._conn.execute(
                """
                CREATE UNIQUE INDEX idx_employee_cemail
                    ON employee (company_email
                );
            """
            )
        logging.info("[Db.setup_employee_table] Created EMPLOYEE table")

    def add_employee(self, emp: Employee) -> bool:
        """Adds new employee entry
        Args:
            [in] emp - The employee entry.  These are required fields:
                                * first_name
                                * last_name
                                * personal_email
                                * date_of_birth
                                * ssn
                                * status
        Returns: bool
        """
        query = (
            "INSERT INTO employee ( first_name, last_name, personal_email, phone, "
            "date_of_birth, ssn, status) VALUES (?, ?, ?, ?, ?, ?, ?)"
        )
        data = (
            emp.first_name,
            emp.last_name,
            emp.personal_email,
            emp.phone,
            emp.date_of_birth,
            emp.ssn,
            int(emp.status),
        )

        try:
            with self._conn:
                self._conn.execute(query, data)
                logging.info(f"[Db.add_employee] Added employee {emp.first_name}")
                return True
        except sl.IntegrityError as e:
            logging.error(f"[Db.add_employee] Exception: {str(e)}")
        return False

    def lookup_employee(self, email) -> (bool, Employee):
        """Looks up employee entry from email
        Args:
            email - the email's personal or company email

        Returns:
            - bool, Employee record if found
        """
        query = (
            "SELECT first_name, last_name, company_email, personal_email, "
            "date_of_birth, start_date, term_date, department, manager, "
            "salary, medical, ssn, status, id "
            "FROM employee "
            "WHERE personal_email=? OR company_email=?"
        )
        data = (email, email)

        try:
            with self._conn:
                data = self._conn.execute(query, data)

                for row in data:
                    # only expecting one result
                    emp = Employee(
                        first_name=row[0],
                        last_name=row[1],
                        company_email=row[2],
                        personal_email=row[3],
                        date_of_birth=row[4],
                        start_date=row[5],
                        term_date=row[6],
                        department=row[7],
                        manager_id=row[8],
                        salary=row[9],
                        medical=row[10],
                        ssn=row[11],
                        status=row[12],
                        employee_id=row[13],
                    )
                    logging.info(f"[Db.lookup_employee] Retrieved employee {email}")
                    return (True, emp)
                logging.error(f"[Db.lookup_employee] No such employee: {email}")
                return (False, None)
        except Exception as e:
            logging.error(f"[Db.lookup_employee] Exception: {str(e)}")

        return (False, None)

    def update_employee(self, employee: Employee) -> bool:
        """Updates employee record
        Args:
            employee - the record to update

        Returns:
            - bool
        """
        query = (
            "UPDATE employee "
            "SET company_email = ?, "
            "start_date = ?, "
            "term_date = ?, "
            "department = ?, "
            "manager = ?, "
            "salary = ?, "
            "status = ? "
            "WHERE id = ?"
        )
        data = (
            employee.company_email,
            employee.start_date,
            employee.term_date,
            employee.department,
            employee.manager_id,
            employee.salary,
            employee.status,
            employee.employee_id,
        )

        try:
            with self._conn:
                self._conn.execute(query, data)

                logging.info(f"[Db.update_employee] Updated employee record")
                return True
        except Exception as e:
            logging.error(f"[Db.update_employee] Exception: {str(e)}")

        return False
