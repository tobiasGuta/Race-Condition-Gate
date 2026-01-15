package com.bughunter;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
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
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.DataFlavor;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.concurrent.*;

@SuppressWarnings("unused")
public class RaceConditionGate implements BurpExtension, ContextMenuItemsProvider {

    private MontoyaApi api;

    // UI Components
    private final RaceTableModel tableModel = new RaceTableModel();
    private HttpRequestEditor requestViewer;
    private HttpResponseEditor responseViewer;
    private JLabel statsLabel; // Live stats display

    // Thread Management
    private ExecutorService threadPool;
    private final List<Future<?>> activeTasks = new ArrayList<>();
    private static CountDownLatch gate = new CountDownLatch(1);

    // Metrics
    private volatile long gateReleaseTime = 0;

    // Clipboard Injection
    private JCheckBox clipboardInjectionToggle;

    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;
        api.extension().setName("Race Condition Gate (Ultimate)");

        // Initialize default Safe Pool
        this.threadPool = Executors.newFixedThreadPool(20);

        SwingUtilities.invokeLater(() -> {
            // --- UI CONSTRUCTION ---

            // 1. Table Setup
            JTable table = new JTable(tableModel);
            table.setFont(new Font("SansSerif", Font.PLAIN, 12));
            table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);

            // Column Widths
            table.getColumnModel().getColumn(0).setPreferredWidth(30); // ID
            table.getColumnModel().getColumn(4).setPreferredWidth(40); // Code
            table.getColumnModel().getColumn(5).setPreferredWidth(60); // Length
            table.getColumnModel().getColumn(7).setPreferredWidth(80); // Offset

            // 2. Control Panel
            JButton releaseBtn = new JButton("RELEASE ALL");
            releaseBtn.setBackground(new Color(255, 100, 100));
            releaseBtn.setForeground(Color.BLACK);
            releaseBtn.setFont(new Font("SansSerif", Font.BOLD, 14));

            JButton clearBtn = new JButton("Clear / Reset");

            // Turbo Toggle
            JCheckBox turboToggle = new JCheckBox("Turbo Mode");
            turboToggle.setToolTipText("Unchecked: Safe (20 threads). Checked: Unlimited threads (Fast, but risky).");

            // Clipboard Injection Toggle
            clipboardInjectionToggle = new JCheckBox("Inject Clipboard (%s)");
            clipboardInjectionToggle.setToolTipText("If checked, replaces '%s' in the request body with clipboard content.");

            // Stats Label
            statsLabel = new JLabel("Stats: Waiting...");
            statsLabel.setFont(new Font("SansSerif", Font.BOLD, 12));
            statsLabel.setBorder(BorderFactory.createEmptyBorder(0, 20, 0, 0));

            JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
            buttonPanel.add(releaseBtn);
            buttonPanel.add(clearBtn);
            buttonPanel.add(turboToggle);
            buttonPanel.add(clipboardInjectionToggle);
            buttonPanel.add(statsLabel);

            // 3. Editors
            UserInterface ui = api.userInterface();
            requestViewer = ui.createHttpRequestEditor(EditorOptions.READ_ONLY);
            responseViewer = ui.createHttpResponseEditor(EditorOptions.READ_ONLY);

            // 4. Event Listeners
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

            turboToggle.addActionListener(e -> {
                swapThreadPool(turboToggle.isSelected());
                api.logging().logToOutput("Switched to " + (turboToggle.isSelected() ? "Turbo Mode (Unlimited)" : "Safe Mode (20 Threads)"));
            });

            // 5. Layout Assembly
            JScrollPane tableScroll = new JScrollPane(table);
            JSplitPane requestResponseSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, requestViewer.uiComponent(), responseViewer.uiComponent());
            requestResponseSplit.setResizeWeight(0.5);
            JSplitPane mainSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT, tableScroll, requestResponseSplit);
            mainSplit.setResizeWeight(0.4);

            JPanel mainPanel = new JPanel(new BorderLayout());
            mainPanel.add(buttonPanel, BorderLayout.NORTH);
            mainPanel.add(mainSplit, BorderLayout.CENTER);

            api.userInterface().registerSuiteTab("Race Gate", mainPanel);
        });

        api.userInterface().registerContextMenuItemsProvider(this);
        api.extension().registerUnloadingHandler(() -> {
            if(threadPool != null) threadPool.shutdownNow();
        });
        api.logging().logToOutput("Race Gate Ultimate Loaded.");
    }

    // --- CONTEXT MENU ---
    @Override
    public List<Component> provideMenuItems(ContextMenuEvent event) {
        if (event.messageEditorRequestResponse().isEmpty()) return null;
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

        JMenuItem item50 = new JMenuItem("Add 50 Requests (Turbo Rec.)");
        item50.addActionListener(l -> queueBatch(requestResponse, 50));

        parentMenu.add(item1);
        parentMenu.add(item10);
        parentMenu.add(item20);
        parentMenu.add(item50);
        return parentMenu;
    }

    private void queueBatch(HttpRequestResponse reqResp, int count) {
        // If clipboard injection is enabled, get the clipboard content once for the batch
        String[] payloads = null;
        if (clipboardInjectionToggle.isSelected()) {
            String clipboardContent = getClipboardContent();
            if (clipboardContent != null && !clipboardContent.isEmpty()) {
                // Split by newline to get individual payloads
                payloads = clipboardContent.split("\\R");
            }
        }

        for(int i=0; i<count; i++) {
            String payload = null;
            if (payloads != null && payloads.length > 0) {
                payload = payloads[i % payloads.length];
            }
            queueRequest(reqResp, payload);
        }
    }

    private String getClipboardContent() {
        try {
            Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
            if (clipboard.isDataFlavorAvailable(DataFlavor.stringFlavor)) {
                return (String) clipboard.getData(DataFlavor.stringFlavor);
            }
        } catch (Exception e) {
            api.logging().logToError("Failed to access clipboard: " + e.getMessage());
        }
        return null;
    }

    // --- CORE LOGIC ---
    private void queueRequest(HttpRequestResponse reqResp, String payload) {
        HttpRequest requestToSend = reqResp.request();

        // Inject payload if available and placeholder exists
        if (payload != null && !payload.isEmpty()) {
            String body = requestToSend.bodyToString();
            if (body.contains("%s")) {
                String newBody = body.replace("%s", payload);
                requestToSend = requestToSend.withBody(newBody);
            }
        }

        RaceResult result = new RaceResult(requestToSend);
        int rowId = tableModel.addResult(result);

        // Capture final request for lambda
        HttpRequest finalRequestToSend = requestToSend;

        Future<?> task = threadPool.submit(() -> {
            try {
                // 1. SMART WARMER
                // Clone request, strip body, use HEAD, force Keep-Alive
                HttpRequest warmer = finalRequestToSend
                        .withMethod("HEAD")
                        .withPath("/")
                        .withBody(ByteArray.byteArray())
                        .withHeader("Connection", "keep-alive");

                // Send warmer to open socket
                api.http().sendRequest(warmer);

                // 2. WAIT AT GATE
                gate.await();

                // 3. CAPTURE JITTER (OFFSET)
                long myStartTime = System.nanoTime();
                long offset = (myStartTime - gateReleaseTime) / 1000; // microseconds

                // 4. EXECUTE RACE
                HttpRequestResponse response = api.http().sendRequest(finalRequestToSend);
                long endTime = System.nanoTime();

                // 5. RECORD RESULTS
                result.request = finalRequestToSend; // Update request in result to reflect injection
                result.response = response.response();
                result.status = "Done";
                result.statusCode = response.response().statusCode();
                result.length = response.response().body().length();
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
        updateStats(); // Update pending count
    }

    private void releaseGate() {
        if (activeTasks.isEmpty()) return;
        api.logging().logToOutput("Releasing gate for " + activeTasks.size() + " requests!");
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
        updateStats();
    }

    private synchronized void swapThreadPool(boolean turboMode) {
        if (threadPool != null) threadPool.shutdownNow();

        if (turboMode) {
            threadPool = Executors.newCachedThreadPool(); // Unlimited
        } else {
            threadPool = Executors.newFixedThreadPool(20); // Safe
        }
        resetGate();
    }

    // --- UI HELPERS ---
    private void updateTableSafe(int rowId) {
        SwingUtilities.invokeLater(() -> {
            if (rowId < tableModel.getRowCount()) {
                tableModel.fireTableRowsUpdated(rowId, rowId);
                updateStats();
            }
        });
    }

    private void updateStats() {
        SwingUtilities.invokeLater(() -> {
            Map<Short, Integer> counts = new TreeMap<>();
            int pending = 0;
            int completed = 0;

            for (int i = 0; i < tableModel.getRowCount(); i++) {
                RaceResult result = tableModel.getResult(i);
                if ("Done".equals(result.status)) {
                    completed++;
                    counts.put(result.statusCode, counts.getOrDefault(result.statusCode, 0) + 1);
                } else {
                    pending++;
                }
            }

            StringBuilder sb = new StringBuilder("Done: " + completed + "/" + (completed + pending) + "  |  ");
            if (counts.isEmpty()) {
                sb.append("Waiting...");
            } else {
                counts.forEach((code, count) -> sb.append(code).append(": ").append(count).append("   "));
            }

            statsLabel.setText(sb.toString());

            // Visual Alert for anomalies (500s or mixed 200/403)
            if (counts.containsKey((short)500) || counts.containsKey((short)503)) {
                statsLabel.setForeground(Color.RED);
            } else if (counts.size() > 1) {
                statsLabel.setForeground(new Color(0, 150, 0)); // Dark Green for interesting mix
            } else {
                statsLabel.setForeground(Color.BLACK);
            }
        });
    }

    // --- DATA MODELS ---
    static class RaceTableModel extends AbstractTableModel {
        private final List<RaceResult> results = new ArrayList<>();
        private final String[] columns = {"ID", "Method", "URL", "Status", "Code", "Length", "Time (us)", "Offset (us)"};

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
                case 5 -> (r.status.equals("Done")) ? r.length : "";
                case 6 -> (r.timeTakenUs == 0) ? "" : r.timeTakenUs;
                case 7 -> (r.status.equals("Done")) ? r.offsetUs : "";
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
        int length = 0;
        long timeTakenUs = 0;
        long offsetUs = 0;

        public RaceResult(HttpRequest request) {
            this.request = request;
        }
    }
}