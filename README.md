# Burp Suite Export Viewer Extension

This extension allows you to view, analyze, and manage exported XML files in Burp Suite. It provides functionality to load multiple XML files at once, search through the log entries, filter the entries based on various criteria, export data from various Burp Suite components, and send requests to Repeater, Intruder, and other extensions.

## Features

- **Load XML Files**: Load multiple XML files into Burp Suite.
- **Search Functionality**: Search through log entries using text or regex.
- **Filter Options**: Filter entries based on method, path, URL, host, status, MIME type, and more.
- **In-Scope Only Option**: Load only those entries that are within the defined scope.
- **View Requests and Responses**: Display detailed information for each log entry, including the request and response.
- **Send to Repeater, Intruder, and Other Extensions**: Send requests from the log entries to Repeater, Intruder, or other extensions for further analysis or manipulation.

## Installation

1. Download the extension code.
2. Open Burp Suite and go to the Extender tab.
3. Click on the Extensions sub-tab and then click Add.
4. In the Burp Extension window, select the Python option.
5. Click Select file and choose the downloaded extension file.
6. Click Next and then click Close.

## Usage

## First You Need to Export to XML files

- from Sitemap or ProxyHistory or Logger or even from Repeater or intruder results
- select requests and responses peer you want to export 
- then right click on it and select `Save Items` options and save it to XML file

### Loading XML Files

1. Go to the "Export Viewer" tab.
2. Click on the "Load XML Exported Files" button.
3. Select the XML files you want to load - It Support Loading Multiple Files :) .
4. If you want to load only the items that are in scope, check the "In Scope Only" checkbox before clicking "Load XML Exported Files".

### Searching Log Entries

1. Enter your search term in the search field.
2. Click the "Search" button.
3. If you want to use regex for searching, check the "Regex Search" checkbox.
4. Filter options can be selected to narrow down the search results.

### Viewing Log Entries

1. Select a log entry from the table to view its details.
2. The request and response details will be displayed in the respective tabs below the table.

### Exporting Data

1. Go to the Proxy history, Logger, Repeater, or Intruder tab.
2. Select the items you want to export, or select all items.
3. Click on the "Save Items" button.
4. Choose the location and filename for the exported XML file.
5. Load the exported XML file into the "Export Viewer" extension by following the steps in the "Loading XML Files" section.

### Sending Requests to Repeater, Intruder, and Other Extensions

1. Select a log entry from the table.
2. Right-click and choose the option to send the request to Repeater, Intruder, or another extension.
3. The selected request will be sent to the chosen extension for further analysis or manipulation.

## Author
Eslam Mohamed (Sysc4ll3r)
