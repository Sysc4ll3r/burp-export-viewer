from org.w3c.dom import Node
from threading import Lock
from javax.xml.parsers import DocumentBuilderFactory
from javax.swing.table import AbstractTableModel
from burp import IBurpExtender, ITab, IMessageEditorController
from burp import IHttpRequestResponse, IParameter, IHttpService

from java.awt import BorderLayout
from java.util import ArrayList, Base64
from java.net import URL
from java.util.regex import Pattern
from java.lang import String

from javax.swing import JScrollPane, JSplitPane, JTabbedPane
from javax.swing import JTable, JButton, JPanel, JFileChooser
from javax.swing import JCheckBox, JTextField


class BurpExtender(IBurpExtender, ITab, IMessageEditorController,
                   AbstractTableModel):

    """
        Implements IBurpExtender
    """

    def registerExtenderCallbacks(self, callbacks):

        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()

        self._callbacks.setExtensionName("Export Viewer")

        self._log = ArrayList()
        self._full_log_data = ArrayList()
        self._lock = Lock()

        self._mainPanel = JPanel(BorderLayout())

        searchPanel = JPanel()
        self._searchField = JTextField(30)
        self._searchButton = JButton('Search')
        self._searchButton.addActionListener(self.searchButtonTapped)
        self._regexCheckBox = JCheckBox('Regex Search')
        searchPanel.add(self._searchField)
        searchPanel.add(self._searchButton)
        searchPanel.add(self._regexCheckBox)

        filterPanel = JPanel()
        self._methodCheckBox = JCheckBox('Method', True)
        self._pathCheckBox = JCheckBox('Path', True)
        self._urlCheckBox = JCheckBox('URL', True)
        self._hostCheckBox = JCheckBox('Host', True)
        self._statusCheckBox = JCheckBox('Status', True)
        self._mimeCheckBox = JCheckBox('MIME', True)
        self._extensionCheckBox = JCheckBox('Extension', True)
        self._paramsCheckBox = JCheckBox('Params', True)
        self._requestCheckBox = JCheckBox('Request', False)
        self._responseCheckBox = JCheckBox('Response', False)
        self._commentCheckBox = JCheckBox('Comment', True)

        filterPanel.add(self._methodCheckBox)
        filterPanel.add(self._pathCheckBox)
        filterPanel.add(self._urlCheckBox)
        filterPanel.add(self._hostCheckBox)
        filterPanel.add(self._mimeCheckBox)
        filterPanel.add(self._statusCheckBox)
        filterPanel.add(self._mimeCheckBox)
        filterPanel.add(self._extensionCheckBox)
        filterPanel.add(self._paramsCheckBox)
        filterPanel.add(self._requestCheckBox)
        filterPanel.add(self._responseCheckBox)
        filterPanel.add(self._commentCheckBox)
        searchPanel.add(filterPanel)
        self._mainPanel.add(searchPanel, BorderLayout.NORTH)

        buttonPanel = JPanel()
        self._loadButton = JButton('Load XML Exported Files')
        self._loadButton.addActionListener(self.loadButtonTapped)
        buttonPanel.add(self._loadButton)
        self._inScopeCheckBox = JCheckBox("In Scope Only")
        buttonPanel.add(self._inScopeCheckBox)
        self._clearButton = JButton('Clear')
        self._clearButton.addActionListener(lambda e: self.resetList())
        buttonPanel.add(self._clearButton)
        self._mainPanel.add(buttonPanel, BorderLayout.SOUTH)

        self._fc = JFileChooser()
        self._fc.setDialogTitle(
            "Select XML Exported Files - You can Choose Multiple files")

        self._fc.setMultiSelectionEnabled(True)

        self._splitpane = JSplitPane(JSplitPane.VERTICAL_SPLIT)
        self._mainPanel.add(self._splitpane, BorderLayout.CENTER)

        self._logTable = Table(self)
        self._scrollPane = JScrollPane(self._logTable)
        self._splitpane.setTopComponent(self._scrollPane)

        self._logTable.setAutoResizeMode(JTable.AUTO_RESIZE_OFF)
        self._logTable.getColumnModel().getColumn(0).setPreferredWidth(40)
        self._logTable.getColumnModel().getColumn(1).setPreferredWidth(60)
        self._logTable.getColumnModel().getColumn(2).setPreferredWidth(70)
        self._logTable.getColumnModel().getColumn(3).setPreferredWidth(300)
        self._logTable.getColumnModel().getColumn(4).setPreferredWidth(500)
        self._logTable.getColumnModel().getColumn(5).setPreferredWidth(300)
        self._logTable.getColumnModel().getColumn(6).setPreferredWidth(100)
        self._logTable.getColumnModel().getColumn(7).setPreferredWidth(100)
        self._logTable.getColumnModel().getColumn(8).setPreferredWidth(100)
        self._logTable.getColumnModel().getColumn(9).setPreferredWidth(100)
        self._logTable.getColumnModel().getColumn(10).setPreferredWidth(230)
        self._logTable.getColumnModel().getColumn(11).setMaxWidth(100000)

        self._tabs = JTabbedPane()
        self._requestViewer = callbacks.createMessageEditor(self, False)
        self._responseViewer = callbacks.createMessageEditor(self, False)
        self._tabs.addTab("Request", self._requestViewer.getComponent())
        self._tabs.addTab("Response", self._responseViewer.getComponent())
        self._splitpane.setBottomComponent(self._tabs)

        self._callbacks.customizeUiComponent(self._mainPanel)
        self._callbacks.customizeUiComponent(self._splitpane)
        self._callbacks.customizeUiComponent(self._logTable)
        self._callbacks.customizeUiComponent(self._scrollPane)
        self._callbacks.customizeUiComponent(self._tabs)

        self._callbacks.addSuiteTab(self)

        return
    """
        Helper Functions
    """

    def loadButtonTapped(self, actionEvent):
        retVal = self._fc.showOpenDialog(None)

        if retVal == JFileChooser.APPROVE_OPTION:
            selectedFiles = self._fc.getSelectedFiles()
            self.resetList()
            for file in selectedFiles:
                self.parseXML(file)
        else:
            print("Open command cancelled by user.")

    def parseXML(self, file):
        dbFactory = DocumentBuilderFactory.newInstance()
        dBuilder = dbFactory.newDocumentBuilder()
        doc = dBuilder.parse(file)
        doc.getDocumentElement().normalize()
        nodeList = doc.getElementsByTagName("item")

        for i in range(0, nodeList.getLength()):
            node = nodeList.item(i)
            if node.getNodeType() == Node.ELEMENT_NODE:

                request = node.getElementsByTagName(
                    "request").item(0).getTextContent()
                response = node.getElementsByTagName(
                    "response").item(0).getTextContent()

                request_isBase64 = node.getElementsByTagName(
                    "request").item(0).getAttribute("base64")
                response_isBase64 = node.getElementsByTagName(
                    "response").item(0).getAttribute("base64")

                if request_isBase64 == "true":
                    request = Base64.getDecoder().decode(request)

                if response_isBase64 == "true":
                    response = Base64.getDecoder().decode(response)

                info = {
                    "time":
                    node.getElementsByTagName("time").item(0).getTextContent(),
                    "url":
                    node.getElementsByTagName("url").item(0).getTextContent(),
                    "host":
                    node.getElementsByTagName("host").item(0).getTextContent(),
                    "port":
                    node.getElementsByTagName("port").item(0).getTextContent(),
                    "protocol":
                    node.getElementsByTagName(
                        "protocol").item(0).getTextContent(),
                    "method":
                    node.getElementsByTagName(
                        "method").item(0).getTextContent(),
                    "path":
                    node.getElementsByTagName("path").item(0).getTextContent(),
                    "extension":
                    node.getElementsByTagName(
                        "extension").item(0).getTextContent(),
                    "request": request,
                    "status":
                    node.getElementsByTagName(
                        "status").item(0).getTextContent(),
                    "responselength":
                    node.getElementsByTagName(
                        "responselength").item(0).getTextContent(),
                    "mimetype":
                    node.getElementsByTagName(
                        "mimetype").item(0).getTextContent(),
                    "response": response,
                    "comment":
                    node.getElementsByTagName(
                        "comment").item(0).getTextContent(),
                    "highlight": ""
                }

                if self._inScopeCheckBox.isSelected() and not self._callbacks.isInScope(URL(info["url"])):
                    continue
                logEntry = LogEntry(info)

                info["path"] = info["path"].split("?")[0]

                params = []
                for param in self._helpers.analyzeRequest(logEntry).getParameters():
                    if param.getType() == IParameter.PARAM_URL:
                        params.append("{}={}".format(
                            param.getName(), param.getValue()))
                info["params"] = "&".join(params)

                self.addLogEntryToList(logEntry)

    def addLogEntryToList(self, logEntry):
        self._lock.acquire()
        row = self._log.size()
        self._log.add(logEntry)
        self._full_log_data.add(logEntry)
        self.fireTableRowsInserted(row, row)
        self._lock.release()

    def resetList(self):
        self._lock.acquire()
        self._log.clear()
        self._full_log_data.clear()
        self.fireTableDataChanged()
        self._lock.release()

    """
        Implements ITab
    """

    def getTabCaption(self):
        return "Export Viewer"

    def getUiComponent(self):
        return self._mainPanel

    """
        Extends AbstractTableModel
    """

    def getRowCount(self):
        try:
            return self._log.size()
        except Exception:
            return 0

    def getColumnCount(self):
        return 12

    def getColumnName(self, columnIndex):
        if columnIndex == 0:
            return "#"
        if columnIndex == 1:
            return "Method"
        if columnIndex == 2:
            return "Protocol"
        if columnIndex == 3:
            return "Host"
        if columnIndex == 4:
            return "Path"
        if columnIndex == 5:
            return "Parameters"
        if columnIndex == 6:
            return "Status"
        if columnIndex == 7:
            return "Length"
        if columnIndex == 8:
            return "MIME type"
        if columnIndex == 9:
            return "Extension"
        if columnIndex == 10:
            return "Time"
        if columnIndex == 11:
            return "Comment"

        return ""

    def getValueAt(self, rowIndex, columnIndex):
        logEntry = self._log.get(rowIndex)

        if columnIndex == 0:
            return "{}".format(rowIndex)
        if columnIndex == 1:
            return logEntry._info["method"]
        if columnIndex == 2:
            return logEntry._info["protocol"]
        if columnIndex == 3:
            return logEntry.getHttpService().getHost()
        if columnIndex == 4:
            return logEntry._info["path"]
        if columnIndex == 5:
            return logEntry._info["params"]
        if columnIndex == 6:
            return logEntry._info["status"]
        if columnIndex == 7:
            return logEntry._info["responselength"]
        if columnIndex == 8:
            return logEntry._info["mimetype"]
        if columnIndex == 9:
            return logEntry._info["extension"]
        if columnIndex == 10:
            return logEntry._info["time"]
        if columnIndex == 11:
            return logEntry._info["comment"]

        return ""

    def searchButtonTapped(self, event):
        searchText = self._searchField.getText().strip()
        if searchText:
            if self._regexCheckBox.isSelected():
                try:
                    regex_pattern = Pattern.compile(
                        searchText, Pattern.CASE_INSENSITIVE)
                    filteredLog = ArrayList()
                    for entry in self._full_log_data:
                        if self.matchesRegex(entry, regex_pattern):
                            filteredLog.add(entry)
                    self.updateTable(filteredLog)
                except Exception as e:
                    print("Invalid regex pattern:", searchText)
                    print(e)
            else:
                filteredLog = ArrayList()
                for entry in self._full_log_data:
                    if self.matchesFilters(searchText, entry):
                        filteredLog.add(entry)
                self.updateTable(filteredLog)
        else:
            self._lock.acquire()
            self.updateTable(self._full_log_data)
            self._lock.release()

    def matchesFilters(self, searchText, entry):
        found = False
        if self._methodCheckBox.isSelected() and searchText in entry._info["method"]:
            found = True
        if self._pathCheckBox.isSelected() and searchText in entry._info["path"]:
            found = True
        if self._urlCheckBox.isSelected() and searchText in entry._info["url"]:
            found = True
        if self._hostCheckBox.isSelected() and searchText in entry._info["host"]:
            found = True
        if self._statusCheckBox.isSelected() and searchText in entry._info["status"]:
            found = True
        if self._mimeCheckBox.isSelected() and searchText in entry._info["mimetype"]:
            found = True
        if self._extensionCheckBox.isSelected() and searchText in entry._info["extension"]:
            found = True
        if self._paramsCheckBox.isSelected() and searchText in entry._info["params"]:
            found = True
        if self._requestCheckBox.isSelected() and searchText in entry._info["request"].toString():
            found = True
        if self._responseCheckBox.isSelected() and searchText in entry._info["response"].toString():
            found = True
        if self._commentCheckBox.isSelected() and searchText in entry._info["comment"]:
            found = True
        return found

    def matchesRegex(self, entry, regex_pattern):
        found = False
        if self._methodCheckBox.isSelected() and regex_pattern.matcher(String(entry._info["method"])).find():
            found = True
        if self._pathCheckBox.isSelected() and regex_pattern.matcher(String(entry._info["path"])).find():
            found = True
        if self._urlCheckBox.isSelected() and regex_pattern.matcher(String(entry._info["url"])).find():
            found = True
        if self._hostCheckBox.isSelected() and regex_pattern.matcher(String(entry._info["host"])).find():
            found = True
        if self._statusCheckBox.isSelected() and regex_pattern.matcher(String(entry._info["status"])).find():
            found = True
        if self._mimeCheckBox.isSelected() and regex_pattern.matcher(String(entry._info["mimetype"])).find():
            found = True
        if self._extensionCheckBox.isSelected() and regex_pattern.matcher(String(entry._info["extension"])).find():
            found = True
        if self._paramsCheckBox.isSelected() and regex_pattern.matcher(String(entry._info["params"])).find():
            found = True
        if self._requestCheckBox.isSelected() and regex_pattern.matcher(String(entry._info["request"])).find():
            found = True
        if self._responseCheckBox.isSelected() and regex_pattern.matcher(String(entry._info["response"])).find():
            found = True
        if self._commentCheckBox.isSelected() and regex_pattern.matcher(String(entry._info["comment"])).find():
            found = True
        return found

    def updateTable(self, entries):
        self._log.clear()
        self._log.addAll(entries)
        self.fireTableDataChanged()

    """
        Implements IMessageEditorController
        Allows request and response viewers to obtain details about the messages being displayed
    """

    def getHttpService(self):
        return self._currentlyDisplayedItem.getHttpService()

    def getRequest(self):
        return self._currentlyDisplayedItem.getRequest()

    def getResponse(self):
        return self._currentlyDisplayedItem.getResponse()


"""
    Extends JTable
    Handles cell selection
"""


class Table(JTable):
    def __init__(self, extender):
        self._extender = extender
        self.setAutoCreateRowSorter(True)
        self.setModel(extender)

    def changeSelection(self, row, col, toggle, extend):
        logEntry = self._extender._log.get(row)
        self._extender._requestViewer.setMessage(logEntry.getRequest(), True)
        self._extender._responseViewer.setMessage(
            logEntry.getResponse(), False)
        self._extender._currentlyDisplayedItem = logEntry

        JTable.changeSelection(self, row, col, toggle, extend)


"""
    Custom class that represents individual log entry
    Holds details of each log entry that is displayed in table and request/response viewer
"""


class LogEntry(IHttpRequestResponse):
    def __init__(self, info):
        self._info = info
        self._httpService = HttpService(
            info["host"], info["port"], info["protocol"])
        self._request = info["request"]
        self._response = info["response"]
        self._comment = info["comment"]
        self._highlight = info["highlight"]

    def getRequest(self):
        return self._request

    def setRequest(self, request):
        self._request = request

    def getResponse(self):
        return self._response

    def setResponse(self, response):
        self._response = response

    def getComment(self):
        return self._comment

    def setComment(self, comment):
        self._comment = comment

    def getHighlight(self):
        return self._highlight

    def setHighlight(self, highlight):
        self._highlight = highlight

    def getHttpService(self):
        return self._httpService

    def setHttpService(self, httpService):
        self._httpService = httpService


class HttpService(IHttpService):
    def __init__(self, host, port, protocol):
        self._host = host
        self._port = int(port)
        self._protocol = protocol

    def getHost(self):
        return str(self._host)

    def getPort(self):
        return int(self._port)

    def getProtocol(self):
        return str(self._protocol)
