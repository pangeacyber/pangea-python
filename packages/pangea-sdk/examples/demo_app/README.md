# Pangea Demo App
This is a Demo App to provide example usage of the Pangea python-sdk.

The Demo App sets up a local sqlite DB and a runs a simple web server on localhost.

The App simulates an HR application that allows a user to upload resumes, retrieve employee records, and update employee records.

## Usage

### Environment Setup
Set the following environment variables:
- `PANGEA_TOKEN`
- `PANGEA_DOMAIN` (ex: "aws.us.pangea.cloud")

### API Documentation

Please view `openapi.json`

### Main App Startup
```
python main.py
```
Will start a web server running on `http://localhost:8080`.

### Running the App for the First Time
First time running the App requires a database creation call:

```
POST http://localhost:8080/setup

Authorization: Basic <username> <password>

Body: {}
```

### Submitting a Resume
To upload a resume:
- Make sure to set the HEADER key "ClientIPAddress" to simulate call originating from an external user's IP.  This is to test the Embargo service.  Ex: '175.45.176.1' submission will be rejected due to sanctions.

```
POST http://localhost:8080/upload_resume

Authorization: Basic user@gmail.com password

Header:
    "ClientIPAddress" : "1.1.1.1"

Body:
{
        "first_name" : "Alan",
        "last_name" : "Smith",
        "email" : "alan.smith@gmail.com",
        "phone" : "408-555-1212",
        "dob" : "06-28-1999",
        "ssn" : "123-44-6789"
}
```

### Retrieving Employee record
To view an existing employee record, search by email:

```
GET http://localhost:8080/employee/alan.smith@gmail.com

Authorization: Basic manager@acme.com password
```

### Updating Employee record
To update an existing employee record, i.e. to "hire" the employee:

```
POST http://localhost:8080/update_employee

Authorization: Basic manager@acme.com password

Body:
{
    "email" : "alan.smith@gmail.com",
    "start_date" : "07-01-2022",
    "department" : "sales",
    "salary" : 100000,
    "status" : 4,
    "company_email" : "alan.smith@acme.com"
}
```


### Debug Logs
Debug logs for the App are written to `myapp.log` in the `example/demo_app/` directory.

### Sqlite DB
`demo-app.db` is created in the `example/demo_app/` directory.  To test in sqlite3 tool:

```
sqlite3 demo-app.db
```

## References
Viewing Audit Logs: https://console.pangea.cloud/service/audit/logs
