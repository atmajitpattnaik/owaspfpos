# OWASP Report False Positive Checker

A web application that identifies false positives in OWASP Dependency-Check HTML reports by comparing them against a user-provided dependency tree.

## Features

- **Parse OWASP HTML Reports**: Extracts dependency names, versions, and CVEs from OWASP Dependency-Check HTML reports
- **Parse Dependency Trees**: Processes JSON files containing full dependency trees (direct + nested)
- **False Positive Detection**: Identifies false positives in:
  - Direct dependencies
  - Nested libraries (dependencies of dependencies)
- **User-Friendly Interface**: Simple web interface for file upload and results display
- **JSON Export**: Download results as JSON file

## Installation

1. Install dependencies:
```bash
npm install
```

2. Start the server:
```bash
npm start
```

3. Open your browser and navigate to:
```
http://localhost:3000
```

## Usage

1. **Prepare your files**:
   - OWASP HTML Report: Export from OWASP Dependency-Check
   - dependencies.json: Your project's dependency tree in the following format:

```json
{
  "dependencies": [
    {
      "name": "express",
      "version": "4.17.3",
      "children": [
        {
          "name": "body-parser",
          "version": "1.19.0",
          "children": [
            { "name": "qs", "version": "6.7.0" }
          ]
        }
      ]
    }
  ]
}
```

2. **Upload files**: Use the web interface to upload both files
3. **Analyze**: Click the "Analyze" button
4. **Review results**: View false positives in direct dependencies and nested libraries
5. **Download**: Click "Download false_positives.json" to save results

## Output Format

The application generates a `false_positives.json` file with the following structure:

```json
{
  "falsePositives": {
    "directDependencies": [
      {
        "dependencyName": "log4j-core",
        "reportedVersion": "2.13.0",
        "actualVersions": ["2.14.0"],
        "reason": "Version mismatch. Found versions: 2.14.0"
      }
    ],
    "nestedLibraries": [
      {
        "libraryName": "commons-collections",
        "reportedVersion": "3.2.1",
        "actualVersions": ["3.2.2"],
        "parentDependency": "spring-core",
        "reason": "Version mismatch. Found versions: 3.2.2"
      }
    ]
  }
}
```

## Technical Details

- **Backend**: Node.js with Express
- **HTML Parsing**: Cheerio for parsing OWASP HTML reports
- **File Upload**: Multer for handling file uploads
- **Frontend**: Vanilla HTML/CSS/JavaScript

## Notes

- The application works with standard OWASP Dependency-Check HTML report format
- Dependencies must follow the provided JSON structure
- Version matching is flexible and handles common version format variations

