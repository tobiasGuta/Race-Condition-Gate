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

@SuppressWarnings("unused")
public class RaceConditionGate implements BurpExtension, ContextMenuItemsProvider {

    private MontoyaApi api;
    private final RaceTableModel tableModel = new RaceTableModel();
    private HttpRequestEditor requestViewer;
    private HttpResponseEditor responseViewer;

    // Thread Management
    // CHANGE 1: Use FixedThreadPool to prevent crashing the JVM with too many threads
    private final ExecutorService threadPool = Executors.newFixedThreadPool(100);
    private final List<Future<?>> activeTasks = new ArrayList<>();

    private static CountDownLatch gate = new CountDownLatch(1);

    // CHANGE 2: Variable to track the exact moment the button was pressed
    private volatile long gateReleaseTime = 0;

    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;
        api.extension().setName("Race Condition Gate (Pro UI)");

        SwingUtilities.invokeLater(() -> {
            // UI Setup
            JTable table = new JTable(tableModel);
            table.setFont(new Font("SansSerif", Font.PLAIN, 12));
            table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);

            // Set column widths
            table.getColumnModel().getColumn(0).setPreferredWidth(30); // ID
            table.getColumnModel().getColumn(6).setPreferredWidth(80); // Offset

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
                        if(result.response != null) {
                            responseViewer.setResponse(result.response);
                        } else {
                            responseViewer.setResponse(null);
                        }
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
        api.extension().registerUnloadingHandler(threadPool::shutdownNow); // Cleanup on unload
        api.logging().logToOutput("Race Gate Loaded. Jitter & Port Fixes Applied.");
    }

    @Override
    public List<Component> provideMenuItems(ContextMenuEvent event) {
        if (event.messageEditorRequestResponse().isEmpty()) {
            return null;
        }

        return List.of(createRaceGateMenu(event.messageEditorRequestResponse().get().requestResponse()));
    }

    private JMenu createRaceGateMenu(HttpRequestResponse requestResponse) {
        JMenu parentMenu = new JMenu("Race Gate Queue");

        JMenuItem item1 = new JMenuItem("Add 1 Request");
        item1.addActionListener(l -> queueBatch(requestResponse, 1));

        JMenuItem item10 = new JMenuItem("Add 10 Requests");
        item10.addActionListener(l -> queueBatch(requestResponse, 10));

        JMenuItem item20 = new JMenuItem("Add 20 Requests");
        item20.addActionListener(l -> queueBatch(requestResponse, 20));

        parentMenu.add(item1);
        parentMenu.add(item10);
        parentMenu.add(item20);

        return parentMenu;
    }

    private void queueBatch(HttpRequestResponse reqResp, int count) {
        for(int i=0; i<count; i++) {
            queueRequest(reqResp);
        }
    }

    private void queueRequest(HttpRequestResponse reqResp) {
        HttpRequest requestToSend = reqResp.request();
        HttpService service = reqResp.httpService();

        RaceResult result = new RaceResult(requestToSend);
        int rowId = tableModel.addResult(result);

        Future<?> task = threadPool.submit(() -> {
            try {
                // --- CHANGE 3: Robust Warmer Construction ---
                // Handle non-standard ports (e.g. localhost:8080)
                boolean isStandardPort = (service.secure() && service.port() == 443) ||
                        (!service.secure() && service.port() == 80);

                String hostHeader = isStandardPort ? service.host() : service.host() + ":" + service.port();

                String warmerString = "HEAD / HTTP/1.1\r\n" +
                        "Host: " + hostHeader + "\r\n" +
                        "Connection: keep-alive\r\n" + // Force keep-alive
                        "User-Agent: Warmer\r\n" +
                        "\r\n";

                HttpRequest warmer = HttpRequest.httpRequest(service, warmerString);
                api.http().sendRequest(warmer);
                // --------------------------------------------

                // Wait for the button
                gate.await();

                // --- CHANGE 4: Capture Jitter ---
                long myStartTime = System.nanoTime();
                long offset = (myStartTime - gateReleaseTime) / 1000; // in microseconds

                // Execute Race
                HttpRequestResponse response = api.http().sendRequest(requestToSend);
                long endTime = System.nanoTime();

                result.response = response.response();
                result.status = "Done";
                result.statusCode = response.response().statusCode();
                result.timeTakenUs = (endTime - myStartTime) / 1000;
                result.offsetUs = offset;

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

        // Mark the global start time T-0
        gateReleaseTime = System.nanoTime();
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
        // Added "Offset (us)" column
        private final String[] columns = {"ID", "Method", "URL", "Status", "Code", "Time (us)", "Offset (us)"};

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
            return switch (columnIndex) {
                case 0 -> r.id;
                case 1 -> r.request.method();
                case 2 -> r.request.url();
                case 3 -> r.status;
                case 4 -> (r.statusCode == 0) ? "" : r.statusCode;
                case 5 -> (r.timeTakenUs == 0) ? "" : r.timeTakenUs;
                case 6 -> (r.status.equals("Done")) ? r.offsetUs : ""; // Only show offset if done
                default -> "";
            };
        }
    }

    static class RaceResult {
        int id;
        HttpRequest request;
        HttpResponse response;
        String status = "Queued";
        short statusCode = 0;
        long timeTakenUs = 0;
        long offsetUs = 0; // New field for jitter

        public RaceResult(HttpRequest request) {
            this.request = request;
        }
    }
}
