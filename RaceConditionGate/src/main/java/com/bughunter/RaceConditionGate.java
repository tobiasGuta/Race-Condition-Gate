package com.bughunter;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.ui.UserInterface;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import burp.api.montoya.ui.contextmenu.MessageEditorHttpRequestResponse;
import burp.api.montoya.ui.editor.EditorOptions;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.HttpResponseEditor;

import javax.swing.*;
import javax.swing.table.AbstractTableModel;
import java.awt.*;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;

public class RaceConditionGate implements BurpExtension, ContextMenuItemsProvider {

    private MontoyaApi api;
    private final RaceTableModel tableModel = new RaceTableModel();
    private HttpRequestEditor requestViewer;
    private HttpResponseEditor responseViewer;

    // The Gate Logic
    private static CountDownLatch gate = new CountDownLatch(1);
    private final List<Thread> activeThreads = new ArrayList<>();

    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;
        api.extension().setName("Race Condition Gate (Pro UI)");

        SwingUtilities.invokeLater(() -> {
            // 1. Setup UI Components
            JTable table = new JTable(tableModel);
            table.setFont(new Font("SansSerif", Font.PLAIN, 12));
            table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);

            // Buttons
            JButton releaseBtn = new JButton("RELEASE ALL");
            releaseBtn.setBackground(new Color(255, 100, 100)); // Red button
            releaseBtn.setForeground(Color.BLACK);
            releaseBtn.setFont(new Font("SansSerif", Font.BOLD, 14));

            JButton clearBtn = new JButton("Clear / Reset");

            JPanel buttonPanel = new JPanel();
            buttonPanel.add(releaseBtn);
            buttonPanel.add(clearBtn);

            // Editors (Request / Response)
            UserInterface ui = api.userInterface();
            requestViewer = ui.createHttpRequestEditor(EditorOptions.READ_ONLY);
            responseViewer = ui.createHttpResponseEditor(EditorOptions.READ_ONLY);

            // 2. Event Listeners

            // Selection Listener (Update Viewers)
            table.getSelectionModel().addListSelectionListener(e -> {
                if (!e.getValueIsAdjusting()) {
                    int selectedRow = table.getSelectedRow();
                    if (selectedRow != -1) {
                        RaceResult result = tableModel.getResult(selectedRow);
                        requestViewer.setRequest(result.request);
                        if (result.response != null) {
                            responseViewer.setResponse(result.response);
                        } else {
                            responseViewer.setResponse(null); // Clear if queued but not sent
                        }
                    }
                }
            });

            // Button Actions
            releaseBtn.addActionListener(e -> releaseGate());
            clearBtn.addActionListener(e -> resetGate());

            // 3. Layout (Split Pane)
            JScrollPane tableScroll = new JScrollPane(table);

            // Bottom Split: Request | Response
            JSplitPane bottomSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, requestViewer.uiComponent(), responseViewer.uiComponent());
            bottomSplit.setResizeWeight(0.5);

            // Main Split: Table | Bottom
            JSplitPane mainSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT, tableScroll, bottomSplit);
            mainSplit.setResizeWeight(0.4);

            // Final Panel
            JPanel mainPanel = new JPanel(new BorderLayout());
            mainPanel.add(buttonPanel, BorderLayout.NORTH);
            mainPanel.add(mainSplit, BorderLayout.CENTER);

            api.userInterface().registerSuiteTab("Race Gate", mainPanel);
        });

        api.userInterface().registerContextMenuItemsProvider(this);
        api.logging().logToOutput("Race Gate Loaded. UI Active.");
    }

    @Override
    public List<Component> provideMenuItems(ContextMenuEvent event) {
        if (event.messageEditorRequestResponse().isEmpty()) return null;

        JMenuItem queueItem = new JMenuItem("Race Gate: Queue This Request");
        MessageEditorHttpRequestResponse editor = event.messageEditorRequestResponse().get();

        queueItem.addActionListener(l -> queueRequest(editor.requestResponse()));

        List<Component> menuList = new ArrayList<>();
        menuList.add(queueItem);
        return menuList;
    }

    private void queueRequest(HttpRequestResponse reqResp) {
        // Clone request
        HttpRequest requestToSend = reqResp.request();

        // Create a result entry for the UI
        RaceResult result = new RaceResult(requestToSend);
        int rowId = tableModel.addResult(result);

        // Spin up the thread
        Thread t = new Thread(() -> {
            try {
                // Wait at the gate
                gate.await();

                // The Race!
                long startTime = System.nanoTime();
                HttpRequestResponse response = api.http().sendRequest(requestToSend);
                long endTime = System.nanoTime();

                // Update UI with results
                result.response = response.response();
                result.status = "Sent";
                result.statusCode = response.response().statusCode();
                result.timeTakenUs = (endTime - startTime) / 1000;

                SwingUtilities.invokeLater(() -> tableModel.fireTableRowsUpdated(rowId, rowId));

            } catch (Exception e) {
                result.status = "Error: " + e.getMessage();
                SwingUtilities.invokeLater(() -> tableModel.fireTableRowsUpdated(rowId, rowId));
            }
        });

        activeThreads.add(t);
        t.start();
    }

    private void releaseGate() {
        if (activeThreads.isEmpty()) return;

        api.logging().logToOutput("Releasing " + activeThreads.size() + " threads!");
        gate.countDown();
    }

    private void resetGate() {
        // 1. Re-create the gate
        gate = new CountDownLatch(1);

        // 2. Clear threads list (old threads will die naturally)
        activeThreads.clear();

        // 3. Clear UI
        tableModel.clear();
        requestViewer.setRequest(null);
        responseViewer.setResponse(null);
    }

    // --- TABLE MODEL ---
    static class RaceTableModel extends AbstractTableModel {
        private final List<RaceResult> results = new ArrayList<>();
        private final String[] columns = {"ID", "Method", "URL", "Status", "Code", "Time (us)"};

        public int addResult(RaceResult result) {
            results.add(result);
            int idx = results.size() - 1;
            result.id = idx + 1;
            fireTableRowsInserted(idx, idx);
            return idx;
        }

        public void clear() {
            results.clear();
            fireTableDataChanged();
        }

        public RaceResult getResult(int rowIndex) { return results.get(rowIndex); }
        @Override public int getRowCount() { return results.size(); }
        @Override public int getColumnCount() { return columns.length; }
        @Override public String getColumnName(int column) { return columns[column]; }
        @Override public Object getValueAt(int rowIndex, int columnIndex) {
            RaceResult r = results.get(rowIndex);
            switch (columnIndex) {
                case 0: return r.id;
                case 1: return r.request.method();
                case 2: return r.request.url();
                case 3: return r.status;
                case 4: return (r.statusCode == 0) ? "" : r.statusCode;
                case 5: return (r.timeTakenUs == 0) ? "" : r.timeTakenUs;
                default: return "";
            }
        }
    }

    // Data Class
    static class RaceResult {
        int id;
        HttpRequest request;
        HttpResponse response; // Null until sent
        String status = "Queued";
        short statusCode = 0;
        long timeTakenUs = 0;

        public RaceResult(HttpRequest request) {
            this.request = request;
        }
    }
}