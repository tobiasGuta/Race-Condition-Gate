package com.bughunter;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.HttpService;
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
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

public class RaceConditionGate implements BurpExtension, ContextMenuItemsProvider {

    private MontoyaApi api;
    private final RaceTableModel tableModel = new RaceTableModel();
    private HttpRequestEditor requestViewer;
    private HttpResponseEditor responseViewer;

    // Thread Management
    private final ExecutorService threadPool = Executors.newCachedThreadPool();
    private final List<Future<?>> activeTasks = new ArrayList<>();

    private static CountDownLatch gate = new CountDownLatch(1);

    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;
        api.extension().setName("Race Condition Gate (Pro UI)");

        SwingUtilities.invokeLater(() -> {
            // UI Setup
            JTable table = new JTable(tableModel);
            table.setFont(new Font("SansSerif", Font.PLAIN, 12));
            table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);

            JButton releaseBtn = new JButton("RELEASE ALL");
            releaseBtn.setBackground(new Color(255, 100, 100));
            releaseBtn.setForeground(Color.BLACK);
            releaseBtn.setFont(new Font("SansSerif", Font.BOLD, 14));

            JButton clearBtn = new JButton("Clear / Reset");

            JPanel buttonPanel = new JPanel();
            buttonPanel.add(releaseBtn);
            buttonPanel.add(clearBtn);

            UserInterface ui = api.userInterface();
            requestViewer = ui.createHttpRequestEditor(EditorOptions.READ_ONLY);
            responseViewer = ui.createHttpResponseEditor(EditorOptions.READ_ONLY);

            // Listeners
            table.getSelectionModel().addListSelectionListener(e -> {
                if (!e.getValueIsAdjusting()) {
                    int selectedRow = table.getSelectedRow();
                    if (selectedRow != -1) {
                        RaceResult result = tableModel.getResult(selectedRow);
                        requestViewer.setRequest(result.request);
                        responseViewer.setResponse(result.response);
                    }
                }
            });

            releaseBtn.addActionListener(e -> releaseGate());
            clearBtn.addActionListener(e -> resetGate());

            // Layout
            JScrollPane tableScroll = new JScrollPane(table);
            JSplitPane bottomSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, requestViewer.uiComponent(), responseViewer.uiComponent());
            bottomSplit.setResizeWeight(0.5);
            JSplitPane mainSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT, tableScroll, bottomSplit);
            mainSplit.setResizeWeight(0.4);

            JPanel mainPanel = new JPanel(new BorderLayout());
            mainPanel.add(buttonPanel, BorderLayout.NORTH);
            mainPanel.add(mainSplit, BorderLayout.CENTER);

            api.userInterface().registerSuiteTab("Race Gate", mainPanel);
        });

        api.userInterface().registerContextMenuItemsProvider(this);
        api.logging().logToOutput("Race Gate Loaded. Compatibility Mode (2023.12.1).");
    }

    @Override
    public List<Component> provideMenuItems(ContextMenuEvent event) {
        if (event.messageEditorRequestResponse().isEmpty()) return null;

        MessageEditorHttpRequestResponse editor = event.messageEditorRequestResponse().get();
        HttpRequestResponse reqResp = editor.requestResponse();

        // Cascading Menu
        JMenu parentMenu = new JMenu("Race Gate Queue");

        JMenuItem item1 = new JMenuItem("Add 1 Request");
        item1.addActionListener(l -> queueBatch(reqResp, 1));

        JMenuItem item10 = new JMenuItem("Add 10 Requests");
        item10.addActionListener(l -> queueBatch(reqResp, 10));

        JMenuItem item20 = new JMenuItem("Add 20 Requests");
        item20.addActionListener(l -> queueBatch(reqResp, 20));

        JMenuItem item30 = new JMenuItem("Add 30 Requests");
        item30.addActionListener(l -> queueBatch(reqResp, 30));

        parentMenu.add(item1);
        parentMenu.add(item10);
        parentMenu.add(item20);
        parentMenu.add(item30);

        List<Component> menuList = new ArrayList<>();
        menuList.add(parentMenu);
        return menuList;
    }

    private void queueBatch(HttpRequestResponse reqResp, int count) {
        for(int i=0; i<count; i++) {
            queueRequest(reqResp);
        }
    }

    private void queueRequest(HttpRequestResponse reqResp) {
        HttpRequest requestToSend = reqResp.request();
        HttpService service = reqResp.httpService(); // Needed for warmer

        RaceResult result = new RaceResult(requestToSend);
        int rowId = tableModel.addResult(result);

        // Submit to Thread Pool
        Future<?> task = threadPool.submit(() -> {
            try {
                // --- FIX FOR 2023.12.1 ---
                // We manually construct the raw HTTP string.
                // This ensures compatibility with older Montoya API versions.
                String warmerString = "HEAD / HTTP/1.1\r\n" +
                        "Host: " + service.host() + "\r\n" +
                        "User-Agent: Warmer\r\n" +
                        "\r\n";

                // We use the factory that accepts (HttpService, String)
                HttpRequest warmer = HttpRequest.httpRequest(service, warmerString);

                api.http().sendRequest(warmer);
                // -------------------------

                // Wait for the button
                gate.await();

                // Execute Race
                long startTime = System.nanoTime();
                HttpRequestResponse response = api.http().sendRequest(requestToSend);
                long endTime = System.nanoTime();

                result.response = response.response();
                result.status = "Done";
                result.statusCode = response.response().statusCode();
                result.timeTakenUs = (endTime - startTime) / 1000;

                updateTableSafe(rowId);

            } catch (InterruptedException e) {
                result.status = "Cancelled";
                Thread.currentThread().interrupt();
                updateTableSafe(rowId);
            } catch (Exception e) {
                result.status = "Error: " + e.getMessage();
                updateTableSafe(rowId);
            }
        });

        activeTasks.add(task);
    }

    private void updateTableSafe(int rowId) {
        SwingUtilities.invokeLater(() -> {
            if (rowId < tableModel.getRowCount()) {
                tableModel.fireTableRowsUpdated(rowId, rowId);
            }
        });
    }

    private void releaseGate() {
        if (activeTasks.isEmpty()) return;
        api.logging().logToOutput("Releasing gate for " + activeTasks.size() + " requests!");
        gate.countDown();
    }

    private void resetGate() {
        gate = new CountDownLatch(1);
        for(Future<?> task : activeTasks) {
            if(!task.isDone()) task.cancel(true);
        }
        activeTasks.clear();
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

    static class RaceResult {
        int id;
        HttpRequest request;
        HttpResponse response;
        String status = "Queued";
        short statusCode = 0;
        long timeTakenUs = 0;

        public RaceResult(HttpRequest request) {
            this.request = request;
        }
    }
}