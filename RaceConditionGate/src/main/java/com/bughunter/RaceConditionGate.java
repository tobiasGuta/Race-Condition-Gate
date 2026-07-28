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
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.UnaryOperator;

@SuppressWarnings("unused")
public class RaceConditionGate implements BurpExtension, ContextMenuItemsProvider {

    private static final int SAFE_THREAD_LIMIT = 20;
    private static final int TURBO_THREAD_LIMIT = 50;

    private MontoyaApi api;

    // UI Components
    private final RaceTableModel tableModel = new RaceTableModel();
    private HttpRequestEditor requestViewer;
    private HttpResponseEditor responseViewer;
    private JLabel statsLabel; // Live stats display
    private JButton releaseBtn;

    // Thread Management
    private ExecutorService threadPool;
    private final ExecutorService coordinatorPool = Executors.newSingleThreadExecutor();
    private boolean turboMode = false;
    private final Object batchLock = new Object();
    private final List<Future<?>> activeTasks = new ArrayList<>();
    private RaceBatch currentBatch = RaceBatch.empty();
    private RaceBatch.RaceAttempt currentAttempt;
    private final AtomicLong nextBatchId = new AtomicLong(1);
    private final AtomicInteger responseOrder = new AtomicInteger(0);
    private final Map<Integer, ResponseFingerprint> baselineByRequestIndex = new ConcurrentHashMap<>();

    // Request Mutation Controls
    private JCheckBox bestEffortWarmUpToggle;
    private JCheckBox clipboardInjectionToggle;
    private JCheckBox baselineToggle;
    private JCheckBox multiEndpointModeToggle;
    private JSpinner attemptsSpinner;
    private JTextField keywordsField;
    private JTextField successExpressionField;

    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;
        api.extension().setName("Race Condition Gate (Ultimate)");

        // Initialize default Safe Pool
        this.threadPool = Executors.newFixedThreadPool(SAFE_THREAD_LIMIT);

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
            table.getColumnModel().getColumn(7).setPreferredWidth(110); // Dispatch offset

            // 2. Control Panel
            releaseBtn = new JButton("RELEASE ALL");
            releaseBtn.setBackground(new Color(255, 100, 100));
            releaseBtn.setForeground(Color.BLACK);
            releaseBtn.setFont(new Font("SansSerif", Font.BOLD, 14));
            releaseBtn.setEnabled(false);
            releaseBtn.setToolTipText("Thread-level release through Burp's HTTP stack; not last-byte or single-packet synchronization.");

            JButton clearBtn = new JButton("Clear / Reset");

            // Turbo Toggle
            JCheckBox turboToggle = new JCheckBox("Turbo Mode");
            turboToggle.setToolTipText("Bounded 50-thread pool for larger batches; still thread-level synchronization.");

            // Best-effort Warm-up Toggle
            bestEffortWarmUpToggle = new JCheckBox("Best-effort warm-up");
            bestEffortWarmUpToggle.setToolTipText("Optional HEAD / before the gate. May not reuse the same connection and creates extra target traffic.");

            // Clipboard Injection Toggle
            clipboardInjectionToggle = new JCheckBox("Inject Clipboard (%s)");
            clipboardInjectionToggle.setToolTipText("If checked, replaces '%s' in the request body with clipboard content.");

            baselineToggle = new JCheckBox("Baseline");
            baselineToggle.setToolTipText("Send the prepared requests sequentially before racing and compare race responses against that baseline.");

            multiEndpointModeToggle = new JCheckBox("Multi-endpoint");
            multiEndpointModeToggle.setToolTipText("Allow logical races across different endpoints. Leave off for precision batches.");

            attemptsSpinner = new JSpinner(new SpinnerNumberModel(1, 1, 50, 1));
            attemptsSpinner.setToolTipText("Number of race attempts to run. Later attempts auto-release once every worker is ready.");

            keywordsField = new JTextField(14);
            keywordsField.setToolTipText("Comma-separated keywords to count in each response body.");

            successExpressionField = new JTextField(24);
            successExpressionField.setToolTipText("Example: status == 200 and body contains \"redeemed\" and json $.balance changed");

            // Stats Label
            statsLabel = new JLabel("Stats: Waiting...");
            statsLabel.setFont(new Font("SansSerif", Font.BOLD, 12));
            statsLabel.setBorder(BorderFactory.createEmptyBorder(0, 20, 0, 0));
            statsLabel.setToolTipText("Ready means worker threads completed any enabled best-effort warm-up and are waiting on the release latch.");

            JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
            buttonPanel.add(releaseBtn);
            buttonPanel.add(clearBtn);
            buttonPanel.add(turboToggle);
            buttonPanel.add(bestEffortWarmUpToggle);
            buttonPanel.add(clipboardInjectionToggle);
            buttonPanel.add(new JLabel("Attempts"));
            buttonPanel.add(attemptsSpinner);
            buttonPanel.add(baselineToggle);
            buttonPanel.add(multiEndpointModeToggle);
            buttonPanel.add(new JLabel("Keywords"));
            buttonPanel.add(keywordsField);
            buttonPanel.add(new JLabel("Success"));
            buttonPanel.add(successExpressionField);
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
                        RaceResultSnapshot result = tableModel.getResult(selectedRow);
                        requestViewer.setRequest(result.request());
                        if(result.response() != null) {
                            responseViewer.setResponse(result.response());
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
                api.logging().logToOutput("Switched to "
                        + (turboToggle.isSelected() ? "Turbo Mode (50 Threads)" : "Safe Mode (20 Threads)")
                        + ". Synchronization remains thread-level through Burp's HTTP stack.");
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
            coordinatorPool.shutdownNow();
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

        JMenuItem item50 = new JMenuItem("Add 50 Requests (Turbo Mode)");
        item50.addActionListener(l -> queueBatch(requestResponse, 50));

        parentMenu.add(item1);
        parentMenu.add(item10);
        parentMenu.add(item20);
        parentMenu.add(item50);
        return parentMenu;
    }

    private void queueBatch(HttpRequestResponse reqResp, int count) {
        RaceBatch batch;
        boolean bestEffortWarmUp = bestEffortWarmUpToggle.isSelected();
        boolean baselineEnabled = baselineToggle.isSelected();
        boolean multiEndpointMode = multiEndpointModeToggle.isSelected();
        int totalAttempts = (Integer) attemptsSpinner.getValue();
        List<String> keywords = ResponseAnalysis.splitCsv(keywordsField.getText());
        String successExpressionText = successExpressionField.getText();
        SuccessExpression successExpression = SuccessExpression.parse(successExpressionText);
        List<String> jsonPaths = SuccessExpression.jsonPathsFromExpression(successExpressionText);
        List<PreparedRaceRequest> preparedRequests = prepareRequests(reqResp, count);
        TargetMetadata targetMetadata = TargetMetadata.from(preparedRequests.get(0).request());

        synchronized (batchLock) {
            int maxBatchSize = maxBatchSizeForCurrentMode();
            if (count > maxBatchSize) {
                String message = "Current mode supports up to " + maxBatchSize + " synchronized requests."
                        + (turboMode ? "" : " Enable Turbo Mode for 50.");
                api.logging().logToError(message);
                if (statsLabel != null) {
                    statsLabel.setText(message);
                    statsLabel.setForeground(Color.RED);
                }
                return;
            }

            if (!currentBatch.isEmpty() && hasRunningTasksLocked()) {
                String message = "Release or reset the current batch before queueing another one.";
                api.logging().logToError(message);
                if (statsLabel != null) {
                    statsLabel.setText(message);
                    statsLabel.setForeground(Color.RED);
                }
                return;
            }

            activeTasks.clear();
            baselineByRequestIndex.clear();
            responseOrder.set(0);
            currentAttempt = null;
            currentBatch = new RaceBatch(nextBatchId.getAndIncrement(), count, totalAttempts, targetMetadata, multiEndpointMode);
            batch = currentBatch;
        }

        tableModel.clear();
        for (int attempt = 1; attempt <= totalAttempts; attempt++) {
            for (PreparedRaceRequest preparedRequest : preparedRequests) {
                int id = tableModel.getRowCount() + 1;
                tableModel.addResult(RaceResultSnapshot.queued(id, attempt, preparedRequest.requestIndex(), preparedRequest.request()));
            }
        }
        requestViewer.setRequest(null);
        responseViewer.setResponse(null);

        Future<?> coordinator = coordinatorPool.submit(() -> runBatch(
                batch,
                preparedRequests,
                bestEffortWarmUp,
                baselineEnabled,
                keywords,
                jsonPaths,
                successExpression
        ));

        synchronized (batchLock) {
            activeTasks.add(coordinator);
        }

        updateStats();
    }

    private List<PreparedRaceRequest> prepareRequests(HttpRequestResponse reqResp, int count) {
        String[] payloads = null;
        if (clipboardInjectionToggle.isSelected()) {
            String clipboardContent = getClipboardContent();
            if (clipboardContent != null && !clipboardContent.isEmpty()) {
                // Split by newline to get individual payloads
                payloads = clipboardContent.split("\\R");
            }
        }

        List<PreparedRaceRequest> preparedRequests = new ArrayList<>();
        for(int i=0; i<count; i++) {
            String payload = null;
            if (payloads != null && payloads.length > 0) {
                payload = payloads[i % payloads.length];
            }
            preparedRequests.add(new PreparedRaceRequest(i + 1, applyPayload(reqResp.request(), payload)));
        }
        return List.copyOf(preparedRequests);
    }

    private int maxBatchSizeForCurrentMode() {
        return turboMode ? TURBO_THREAD_LIMIT : SAFE_THREAD_LIMIT;
    }

    private boolean hasRunningTasksLocked() {
        for (Future<?> task : activeTasks) {
            if (!task.isDone()) {
                return true;
            }
        }
        return false;
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

    private HttpRequest applyPayload(HttpRequest requestToSend, String payload) {
        if (payload != null && !payload.isEmpty()) {
            String body = requestToSend.bodyToString();
            if (body.contains("%s")) {
                String newBody = body.replace("%s", payload);
                requestToSend = requestToSend.withBody(newBody);
            }
        }
        return requestToSend;
    }

    // --- CORE LOGIC ---
    private void runBatch(
            RaceBatch batch,
            List<PreparedRaceRequest> preparedRequests,
            boolean bestEffortWarmUp,
            boolean baselineEnabled,
            List<String> keywords,
            List<String> jsonPaths,
            SuccessExpression successExpression
    ) {
        try {
            if (baselineEnabled && !batch.isCancelled()) {
                updateStatsText("Running sequential baseline for batch " + batch.batchId() + "...");
                runSequentialBaseline(batch, preparedRequests, keywords, jsonPaths);
            }

            for (int attemptNumber = 1; attemptNumber <= batch.totalAttempts() && !batch.isCancelled(); attemptNumber++) {
                RaceBatch.RaceAttempt attempt = batch.attempt(attemptNumber);
                synchronized (batchLock) {
                    currentAttempt = attempt;
                }

                for (PreparedRaceRequest preparedRequest : preparedRequests) {
                    int rowId = rowIdFor(attemptNumber, preparedRequest.requestIndex(), batch.expectedWorkerCount());
                    Future<?> worker = threadPool.submit(() -> executeRaceRequest(
                            batch,
                            attempt,
                            preparedRequest,
                            rowId,
                            bestEffortWarmUp,
                            keywords,
                            jsonPaths,
                            successExpression
                    ));
                    synchronized (batchLock) {
                        activeTasks.add(worker);
                    }
                }

                attempt.awaitReady();
                updateStats();
                if (attemptNumber > 1) {
                    attempt.release();
                    updateStats();
                }
                attempt.awaitCompletion();
                summarizeAttempt(batch, attempt);
            }
        } catch (InterruptedException e) {
            batch.cancel();
            Thread.currentThread().interrupt();
            updateStatsText("Batch cancelled.");
        } catch (Exception e) {
            batch.cancel();
            api.logging().logToError("Batch failed: " + e.getMessage());
            updateStatsText("Batch failed: " + e.getMessage());
        } finally {
            synchronized (batchLock) {
                if (currentBatch == batch) {
                    currentAttempt = null;
                }
            }
            updateStats();
        }
    }

    private void runSequentialBaseline(
            RaceBatch batch,
            List<PreparedRaceRequest> preparedRequests,
            List<String> keywords,
            List<String> jsonPaths
    ) {
        for (PreparedRaceRequest preparedRequest : preparedRequests) {
            if (batch.isCancelled()) {
                return;
            }

            long start = System.nanoTime();
            HttpRequestResponse response = api.http().sendRequest(preparedRequest.request());
            long responseTimeUs = (System.nanoTime() - start) / 1000;
            ResponseFingerprint fingerprint = ResponseAnalysis.fingerprint(response.response(), responseTimeUs, 0, keywords, jsonPaths);
            baselineByRequestIndex.put(preparedRequest.requestIndex(), fingerprint);
        }
    }

    private void executeRaceRequest(
            RaceBatch batch,
            RaceBatch.RaceAttempt attempt,
            PreparedRaceRequest preparedRequest,
            int rowId,
            boolean bestEffortWarmUp,
            List<String> keywords,
            List<String> jsonPaths,
            SuccessExpression successExpression
    ) {
        try {
            HttpRequest finalRequestToSend = preparedRequest.request();
            if (!batch.isCompatible(TargetMetadata.from(finalRequestToSend))) {
                updateTableSnapshot(rowId, snapshot -> snapshot.withStatus("Error: incompatible target"));
                batch.cancel();
                return;
            }

            updateTableSnapshot(rowId, snapshot -> snapshot.withStatus(bestEffortWarmUp ? "Warming" : "Preparing"));

            if (bestEffortWarmUp) {
                HttpRequest warmer = finalRequestToSend
                        .withMethod("HEAD")
                        .withPath("/")
                        .withBody(ByteArray.byteArray());

                try {
                    api.http().sendRequest(warmer);
                } catch (Exception warmUpFailure) {
                    api.logging().logToError("Best-effort warm-up failed for row " + (rowId + 1) + ": " + warmUpFailure.getMessage());
                }
            }

            if (!markWorkerReady(batch, attempt, rowId)) {
                return;
            }

            attempt.awaitRelease();
            if (!attempt.wasReleasedByBatch()) {
                updateTableSnapshot(rowId, snapshot -> snapshot.withStatus("Cancelled"));
                return;
            }

            long myStartTime = System.nanoTime();
            long dispatchOffset = (myStartTime - attempt.releaseTimeNanos()) / 1000;

            HttpRequestResponse response = api.http().sendRequest(finalRequestToSend);
            long responseTimeUs = (System.nanoTime() - myStartTime) / 1000;
            int order = responseOrder.incrementAndGet();
            ResponseFingerprint fingerprint = ResponseAnalysis.fingerprint(response.response(), responseTimeUs, order, keywords, jsonPaths);
            ResponseFingerprint baseline = baselineByRequestIndex.get(preparedRequest.requestIndex());
            String body = response.response().bodyToString();
            boolean successMatched = successExpression.matches(fingerprint, baseline, body);
            String anomaly = ResponseAnalysis.summarizeDifference(baseline, fingerprint, successMatched);

            updateTableSnapshot(rowId, snapshot -> snapshot.completed(response.response(), fingerprint, responseTimeUs, dispatchOffset, anomaly));
        } catch (InterruptedException e) {
            updateTableSnapshot(rowId, snapshot -> snapshot.withStatus("Cancelled"));
            Thread.currentThread().interrupt();
        } catch (Exception e) {
            updateTableSnapshot(rowId, snapshot -> snapshot.withStatus("Error: " + e.getMessage()));
        } finally {
            attempt.markComplete();
            updateStats();
        }
    }

    private void summarizeAttempt(RaceBatch batch, RaceBatch.RaceAttempt attempt) {
        SwingUtilities.invokeLater(() -> {
            int anomalies = 0;
            int successMatches = 0;
            for (int i = 0; i < tableModel.getRowCount(); i++) {
                RaceResultSnapshot snapshot = tableModel.getResult(i);
                if (snapshot.attempt() == attempt.attemptNumber() && !snapshot.anomaly().isBlank()) {
                    anomalies++;
                    if (snapshot.anomaly().contains("success expression matched")) {
                        successMatches++;
                    }
                }
            }

            String summary = "Batch " + batch.batchId()
                    + " attempt " + attempt.attemptNumber() + "/" + batch.totalAttempts()
                    + ": " + anomalies + " anomalous responses"
                    + (successMatches > 0 ? ", " + successMatches + " success-expression matches" : "");
            api.logging().logToOutput(summary);
            statsLabel.setText(summary);
        });
    }

    private int rowIdFor(int attemptNumber, int requestIndex, int expectedWorkerCount) {
        return (attemptNumber - 1) * expectedWorkerCount + requestIndex - 1;
    }

    private void releaseGate() {
        RaceBatch.RaceAttempt attempt;
        synchronized (batchLock) {
            attempt = currentAttempt;
            if (attempt == null || attempt.isReleased()) return;

            if (!attempt.isReadyToRelease()) {
                api.logging().logToError("Release blocked: Ready " + attempt.readyCount() + "/" + attempt.expectedWorkerCount());
                updateStats();
                return;
            }

            api.logging().logToOutput("Releasing attempt " + attempt.attemptNumber() + " for "
                    + attempt.expectedWorkerCount() + " ready requests!");
            attempt.release();
        }
        updateStats();
    }

    private void resetGate() {
        RaceBatch oldBatch;
        synchronized (batchLock) {
            oldBatch = currentBatch;
            currentBatch = RaceBatch.empty();
            currentAttempt = null;

            for(Future<?> task : activeTasks) {
                if(!task.isDone()) task.cancel(true);
            }
            activeTasks.clear();
        }

        oldBatch.cancel();
        tableModel.clear();
        requestViewer.setRequest(null);
        responseViewer.setResponse(null);
        updateStats();
    }

    private synchronized void swapThreadPool(boolean turboMode) {
        if (threadPool != null) threadPool.shutdownNow();
        this.turboMode = turboMode;

        if (turboMode) {
            threadPool = Executors.newFixedThreadPool(TURBO_THREAD_LIMIT); // Bounded
        } else {
            threadPool = Executors.newFixedThreadPool(SAFE_THREAD_LIMIT); // Safe
        }
        resetGate();
    }

    private boolean markWorkerReady(RaceBatch batch, RaceBatch.RaceAttempt attempt, int rowId) {
        synchronized (batchLock) {
            if (batch != currentBatch || !attempt.markReady()) {
                updateTableSnapshot(rowId, snapshot -> snapshot.withStatus("Cancelled"));
                return false;
            }
        }

        updateTableSnapshot(rowId, snapshot -> snapshot.withStatus("Ready"));
        return true;
    }

    // --- UI HELPERS ---
    private void updateTableSnapshot(int rowId, UnaryOperator<RaceResultSnapshot> updater) {
        SwingUtilities.invokeLater(() -> {
            if (rowId < tableModel.getRowCount()) {
                tableModel.updateResult(rowId, updater.apply(tableModel.getResult(rowId)));
                updateStats();
            }
        });
    }

    private void updateStatsText(String text) {
        SwingUtilities.invokeLater(() -> {
            if (statsLabel != null) {
                statsLabel.setText(text);
            }
        });
    }

    private void updateStats() {
        SwingUtilities.invokeLater(() -> {
            Map<Short, Integer> counts = new TreeMap<>();
            int failed = 0;
            int completed = 0;
            int anomalies = 0;

            for (int i = 0; i < tableModel.getRowCount(); i++) {
                RaceResultSnapshot result = tableModel.getResult(i);
                if ("Done".equals(result.status())) {
                    completed++;
                    counts.put(result.statusCode(), counts.getOrDefault(result.statusCode(), 0) + 1);
                    if (!result.anomaly().isBlank()) {
                        anomalies++;
                    }
                } else if (result.status().startsWith("Error") || "Cancelled".equals(result.status())) {
                    failed++;
                }
            }

            int readyCount;
            int expectedCount;
            boolean released;
            boolean releaseEnabled;
            int attemptNumber;
            int totalAttempts;
            synchronized (batchLock) {
                RaceBatch.RaceAttempt attempt = currentAttempt;
                readyCount = attempt == null ? 0 : attempt.readyCount();
                expectedCount = attempt == null ? 0 : attempt.expectedWorkerCount();
                released = attempt != null && attempt.isReleased();
                releaseEnabled = attempt != null && attempt.isReadyToRelease();
                attemptNumber = attempt == null ? 0 : attempt.attemptNumber();
                totalAttempts = currentBatch.isEmpty() ? 0 : currentBatch.totalAttempts();
            }

            StringBuilder sb = new StringBuilder();
            if (attemptNumber > 0) {
                sb.append("Attempt: ").append(attemptNumber).append("/").append(totalAttempts).append("  |  ");
            }
            sb.append("Ready: ").append(readyCount).append("/").append(expectedCount);
            if (released) {
                sb.append("  |  Released");
            }
            sb.append("  |  Done: ").append(completed).append("/").append(tableModel.getRowCount());
            if (anomalies > 0) {
                sb.append("  |  Anomalies: ").append(anomalies);
            }
            if (failed > 0) {
                sb.append("  |  Failed: ").append(failed);
            }
            sb.append("  |  ");

            if (counts.isEmpty()) {
                sb.append("Waiting...");
            } else {
                counts.forEach((code, count) -> sb.append(code).append(": ").append(count).append("   "));
            }

            statsLabel.setText(sb.toString());
            if (releaseBtn != null) {
                releaseBtn.setEnabled(releaseEnabled);
            }

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
        private final List<RaceResultSnapshot> results = new ArrayList<>();
        private final String[] columns = {
                "ID",
                "Attempt",
                "Method",
                "URL",
                "Status",
                "Code",
                "Length",
                "Time (us)",
                "Dispatch Offset (us)",
                "Body Hash",
                "Order",
                "Anomaly"
        };

        public int addResult(RaceResultSnapshot result) {
            results.add(result);
            int idx = results.size() - 1;
            fireTableRowsInserted(idx, idx);
            return idx;
        }

        public void updateResult(int rowIndex, RaceResultSnapshot result) {
            results.set(rowIndex, result);
            fireTableRowsUpdated(rowIndex, rowIndex);
        }

        public void clear() {
            results.clear();
            fireTableDataChanged();
        }

        public RaceResultSnapshot getResult(int rowIndex) { return results.get(rowIndex); }
        @Override public int getRowCount() { return results.size(); }
        @Override public int getColumnCount() { return columns.length; }
        @Override public String getColumnName(int column) { return columns[column]; }
        @Override public Object getValueAt(int rowIndex, int columnIndex) {
            RaceResultSnapshot r = results.get(rowIndex);
            return switch (columnIndex) {
                case 0 -> r.id();
                case 1 -> r.attempt();
                case 2 -> r.request().method();
                case 3 -> r.request().url();
                case 4 -> r.status();
                case 5 -> (r.statusCode() == 0) ? "" : r.statusCode();
                case 6 -> (r.status().equals("Done")) ? r.length() : "";
                case 7 -> (r.timeTakenUs() == 0) ? "" : r.timeTakenUs();
                case 8 -> (r.status().equals("Done")) ? r.dispatchOffsetUs() : "";
                case 9 -> r.bodyHash();
                case 10 -> (r.responseOrder() == 0) ? "" : r.responseOrder();
                case 11 -> r.anomaly();
                default -> "";
            };
        }
    }

    private record PreparedRaceRequest(int requestIndex, HttpRequest request) {}
}
