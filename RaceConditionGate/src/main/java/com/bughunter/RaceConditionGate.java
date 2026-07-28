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
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.UnaryOperator;
import java.util.regex.PatternSyntaxException;

@SuppressWarnings("unused")
public class RaceConditionGate implements BurpExtension, ContextMenuItemsProvider {

    private static final int SAFE_THREAD_LIMIT = 20;
    private static final int TURBO_THREAD_LIMIT = 50;
    private static final int DEFAULT_MAX_RETAINED_RESPONSE_BODY_KB = 256;
    private static final int DEFAULT_READY_TIMEOUT_SECONDS = 30;

    private MontoyaApi api;

    // UI Components
    private final RaceTableModel tableModel = new RaceTableModel();
    private HttpRequestEditor requestViewer;
    private HttpResponseEditor responseViewer;
    private JLabel statsLabel; // Live stats display
    private JButton armBtn;
    private JButton releaseBtn;

    // Thread Management
    private ExecutorService threadPool;
    private final ExecutorService coordinatorPool = Executors.newSingleThreadExecutor();
    private boolean turboMode = false;
    private final Object batchLock = new Object();
    private final List<PreparedRaceRequest> pendingQueue = new ArrayList<>();
    private final List<Future<?>> activeTasks = new ArrayList<>();
    private RaceBatch currentBatch = RaceBatch.empty();
    private RaceBatch.RaceAttempt currentAttempt;
    private final AtomicLong nextBatchId = new AtomicLong(1);
    private final AtomicInteger batchResponseOrder = new AtomicInteger(0);
    private final Map<Integer, ResponseFingerprint> baselineByRequestIndex = new ConcurrentHashMap<>();
    private final Map<RequestTemplateKey, ResponseFingerprint> baselineByRequestTemplate = new ConcurrentHashMap<>();
    private final Map<Integer, HttpResponse> pendingResponsesByRowId = new ConcurrentHashMap<>();
    private final Map<Integer, String> pendingResponseOmissionsByRowId = new ConcurrentHashMap<>();
    private final Map<Integer, ResponseRetentionBudget> responseRetentionBudgetsByAttempt = new ConcurrentHashMap<>();
    private final Map<Integer, Map<ResponseAnalysis.ClusterKey, Integer>> clusterRepresentativeRowsByAttempt = new ConcurrentHashMap<>();
    private final Object responseRetentionLock = new Object();
    private volatile String statusOverride = "";

    // Request Mutation Controls
    private JCheckBox bestEffortWarmUpToggle;
    private JCheckBox clipboardInjectionToggle;
    private JComboBox<BaselineMode> baselineModeCombo;
    private JCheckBox autoReleaseAttemptsToggle;
    private JCheckBox multiEndpointModeToggle;
    private JSpinner attemptsSpinner;
    private JTextField keywordsField;
    private JTextField successExpressionField;
    private JTextField ignoredHeadersField;
    private JTextArea bodyNormalizationRegexArea;
    private JTextField ignoredJsonFieldsField;
    private JCheckBox ignoreSetCookieToggle;
    private JSpinner maxResponseBodyKbSpinner;
    private JSpinner readyTimeoutSecondsSpinner;

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
            table.getColumnModel().getColumn(5).setPreferredWidth(60); // Normalized UTF-8 byte length
            table.getColumnModel().getColumn(7).setPreferredWidth(110); // Dispatch offset

            // 2. Control Panel
            armBtn = new JButton("ARM BATCH");
            armBtn.setFont(new Font("SansSerif", Font.BOLD, 14));
            armBtn.setEnabled(false);
            armBtn.setToolTipText("Freeze the queued requests, start workers, and wait for Ready: N/N.");

            releaseBtn = new JButton("RELEASE ALL");
            releaseBtn.setBackground(new Color(255, 100, 100));
            releaseBtn.setForeground(Color.BLACK);
            releaseBtn.setFont(new Font("SansSerif", Font.BOLD, 14));
            releaseBtn.setEnabled(false);
            releaseBtn.setToolTipText("Thread-level release through Burp's HTTP stack; not last-byte or single-packet synchronization.");

            JButton clearBtn = new JButton("Clear / Reset");
            JButton removeQueuedBtn = new JButton("Remove");
            removeQueuedBtn.setToolTipText("Remove the selected staged request before arming.");
            JButton duplicateQueuedBtn = new JButton("Duplicate");
            duplicateQueuedBtn.setToolTipText("Duplicate the selected staged request before arming.");
            JButton moveQueuedUpBtn = new JButton("Up");
            moveQueuedUpBtn.setToolTipText("Move the selected staged request up before arming.");
            JButton moveQueuedDownBtn = new JButton("Down");
            moveQueuedDownBtn.setToolTipText("Move the selected staged request down before arming.");
            JButton clearQueueBtn = new JButton("Clear Queue");
            clearQueueBtn.setToolTipText("Clear staged requests without changing other controls.");

            // Turbo Toggle
            JCheckBox turboToggle = new JCheckBox("Turbo Mode");
            turboToggle.setToolTipText("Bounded 50-thread pool for larger batches; still thread-level synchronization.");

            // Best-effort Warm-up Toggle
            bestEffortWarmUpToggle = new JCheckBox("Best-effort warm-up");
            bestEffortWarmUpToggle.setToolTipText("Optional HEAD / before the gate. May not reuse the same connection and creates extra target traffic.");

            // Clipboard Injection Toggle
            clipboardInjectionToggle = new JCheckBox("Inject Clipboard (%s)");
            clipboardInjectionToggle.setToolTipText("If checked, replaces '%s' in the request body with clipboard content.");

            baselineModeCombo = new JComboBox<>(BaselineMode.values());
            baselineModeCombo.setSelectedItem(BaselineMode.NONE);
            baselineModeCombo.setToolTipText("Default is no baseline. Full baseline sends every queued request before racing and can consume one-time state.");

            autoReleaseAttemptsToggle = new JCheckBox("Auto-release attempts");
            autoReleaseAttemptsToggle.setToolTipText("If unchecked, every attempt waits for manual Release so you can restore target state between attempts.");

            multiEndpointModeToggle = new JCheckBox("Multi-endpoint");
            multiEndpointModeToggle.setToolTipText("Allow logical races across different endpoints. Leave off for precision batches.");

            attemptsSpinner = new JSpinner(new SpinnerNumberModel(1, 1, 50, 1));
            attemptsSpinner.setToolTipText("Number of race attempts to run. Leave Auto-release attempts unchecked when target state must be restored manually.");

            keywordsField = new JTextField(14);
            keywordsField.setToolTipText("Comma-separated keywords to count in each response body.");

            successExpressionField = new JTextField(24);
            successExpressionField.setToolTipText("Example: status == 200 and body contains \"redeemed\" and json $.balance changed");

            ignoredHeadersField = new JTextField(10);
            ignoredHeadersField.setToolTipText("Comma-separated response headers to ignore during baseline comparison and clustering.");

            bodyNormalizationRegexArea = new JTextArea(2, 14);
            bodyNormalizationRegexArea.setLineWrap(false);
            bodyNormalizationRegexArea.setToolTipText("One regex per line. Matches are replaced with <ignored> before response length/hash analysis.");
            JScrollPane bodyRegexScroll = new JScrollPane(bodyNormalizationRegexArea);
            bodyRegexScroll.setPreferredSize(new Dimension(170, 44));

            ignoredJsonFieldsField = new JTextField(12);
            ignoredJsonFieldsField.setToolTipText("Comma-separated JSON paths, such as $.csrf or $.requestId, to redact before hashing and ignore in JSON comparisons.");

            ignoreSetCookieToggle = new JCheckBox("Ignore Set-Cookie", true);
            ignoreSetCookieToggle.setToolTipText("Ignore Set-Cookie during response comparison and clustering.");

            maxResponseBodyKbSpinner = new JSpinner(new SpinnerNumberModel(
                    DEFAULT_MAX_RETAINED_RESPONSE_BODY_KB,
                    0,
                    ResponseRetentionBudget.MAX_RETAINED_RESPONSE_BODY_KB,
                    64
            ));
            maxResponseBodyKbSpinner.setToolTipText("Maximum response body size retained for stored representative/success responses. 0 stores metadata only.");

            readyTimeoutSecondsSpinner = new JSpinner(new SpinnerNumberModel(DEFAULT_READY_TIMEOUT_SECONDS, 1, 600, 5));
            readyTimeoutSecondsSpinner.setToolTipText("Maximum time to wait for every worker to finish warm-up/preparation and reach the release gate.");

            // Stats Label
            statsLabel = new JLabel("Stats: Waiting...");
            statsLabel.setFont(new Font("SansSerif", Font.BOLD, 12));
            statsLabel.setBorder(BorderFactory.createEmptyBorder(0, 20, 0, 0));
            statsLabel.setToolTipText("Ready means worker threads completed any enabled best-effort warm-up and are waiting on the release latch.");

            JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
            buttonPanel.add(armBtn);
            buttonPanel.add(releaseBtn);
            buttonPanel.add(clearBtn);
            buttonPanel.add(removeQueuedBtn);
            buttonPanel.add(duplicateQueuedBtn);
            buttonPanel.add(moveQueuedUpBtn);
            buttonPanel.add(moveQueuedDownBtn);
            buttonPanel.add(clearQueueBtn);
            buttonPanel.add(turboToggle);
            buttonPanel.add(bestEffortWarmUpToggle);
            buttonPanel.add(clipboardInjectionToggle);
            buttonPanel.add(new JLabel("Attempts"));
            buttonPanel.add(attemptsSpinner);
            buttonPanel.add(autoReleaseAttemptsToggle);
            buttonPanel.add(new JLabel("Baseline"));
            buttonPanel.add(baselineModeCombo);
            buttonPanel.add(multiEndpointModeToggle);
            buttonPanel.add(new JLabel("Keywords"));
            buttonPanel.add(keywordsField);
            buttonPanel.add(new JLabel("Success"));
            buttonPanel.add(successExpressionField);
            buttonPanel.add(ignoreSetCookieToggle);
            buttonPanel.add(new JLabel("Ignore headers"));
            buttonPanel.add(ignoredHeadersField);
            buttonPanel.add(new JLabel("Body regexes"));
            buttonPanel.add(bodyRegexScroll);
            buttonPanel.add(new JLabel("Ignore JSON"));
            buttonPanel.add(ignoredJsonFieldsField);
            buttonPanel.add(new JLabel("Max body KB"));
            buttonPanel.add(maxResponseBodyKbSpinner);
            buttonPanel.add(new JLabel("Ready timeout"));
            buttonPanel.add(readyTimeoutSecondsSpinner);
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

            armBtn.addActionListener(e -> armBatch());
            releaseBtn.addActionListener(e -> releaseGate());
            clearBtn.addActionListener(e -> resetGate());
            removeQueuedBtn.addActionListener(e -> removeSelectedQueuedRequest(table));
            duplicateQueuedBtn.addActionListener(e -> duplicateSelectedQueuedRequest(table));
            moveQueuedUpBtn.addActionListener(e -> moveSelectedQueuedRequest(table, -1));
            moveQueuedDownBtn.addActionListener(e -> moveSelectedQueuedRequest(table, 1));
            clearQueueBtn.addActionListener(e -> clearStagedQueue());

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
            updateStats();
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

        JMenuItem item1 = new JMenuItem("Queue 1 Request");
        item1.addActionListener(l -> enqueueRequests(requestResponse, 1));

        JMenuItem item10 = new JMenuItem("Queue 10 Requests");
        item10.addActionListener(l -> enqueueRequests(requestResponse, 10));

        JMenuItem item20 = new JMenuItem("Queue 20 Requests");
        item20.addActionListener(l -> enqueueRequests(requestResponse, 20));

        JMenuItem item50 = new JMenuItem("Queue 50 Requests (Turbo Mode)");
        item50.addActionListener(l -> enqueueRequests(requestResponse, 50));

        parentMenu.add(item1);
        parentMenu.add(item10);
        parentMenu.add(item20);
        parentMenu.add(item50);
        return parentMenu;
    }

    private void enqueueRequests(HttpRequestResponse reqResp, int count) {
        List<PreparedRaceRequest> preparedRequests = prepareRequests(reqResp, count);
        synchronized (batchLock) {
            if (!currentBatch.isEmpty() && hasRunningTasksLocked()) {
                showError("Release or reset the armed batch before editing the queue.");
                return;
            }

            int maxBatchSize = maxBatchSizeForCurrentMode();
            if (pendingQueue.size() + preparedRequests.size() > maxBatchSize) {
                showError("Current mode supports up to " + maxBatchSize + " queued workers."
                        + (turboMode ? "" : " Enable Turbo Mode for 50."));
                return;
            }

            if (!currentBatch.isEmpty()) {
                currentBatch = RaceBatch.empty();
                currentAttempt = null;
                activeTasks.clear();
                baselineByRequestIndex.clear();
                baselineByRequestTemplate.clear();
                pendingResponsesByRowId.clear();
                pendingResponseOmissionsByRowId.clear();
                responseRetentionBudgetsByAttempt.clear();
                clusterRepresentativeRowsByAttempt.clear();
                batchResponseOrder.set(0);
                statusOverride = "";
                pendingQueue.clear();
                tableModel.clear();
            }

            for (PreparedRaceRequest preparedRequest : preparedRequests) {
                int requestIndex = pendingQueue.size() + 1;
                PreparedRaceRequest queuedRequest = new PreparedRaceRequest(requestIndex, preparedRequest.request());
                pendingQueue.add(queuedRequest);
                tableModel.addResult(RaceResultSnapshot.queued(requestIndex, 0, requestIndex, queuedRequest.request()));
            }
        }

        updateStats();
    }

    private void removeSelectedQueuedRequest(JTable table) {
        synchronized (batchLock) {
            if (!canEditStagedQueueLocked()) {
                showError("Queue edits are only available before arming a batch.");
                return;
            }

            int selectedRow = selectedModelRow(table);
            if (selectedRow < 0 || selectedRow >= pendingQueue.size()) {
                showError("Select a staged queued request first.");
                return;
            }

            pendingQueue.remove(selectedRow);
            rebuildStagedQueueTableLocked();
            selectQueueRow(table, Math.min(selectedRow, pendingQueue.size() - 1));
        }
        updateStats();
    }

    private void duplicateSelectedQueuedRequest(JTable table) {
        synchronized (batchLock) {
            if (!canEditStagedQueueLocked()) {
                showError("Queue edits are only available before arming a batch.");
                return;
            }

            int selectedRow = selectedModelRow(table);
            if (selectedRow < 0 || selectedRow >= pendingQueue.size()) {
                showError("Select a staged queued request first.");
                return;
            }

            int maxBatchSize = maxBatchSizeForCurrentMode();
            if (pendingQueue.size() >= maxBatchSize) {
                showError("Current mode supports up to " + maxBatchSize + " queued workers."
                        + (turboMode ? "" : " Enable Turbo Mode for 50."));
                return;
            }

            PreparedRaceRequest selected = pendingQueue.get(selectedRow);
            pendingQueue.add(selectedRow + 1, new PreparedRaceRequest(0, selected.request()));
            reindexPendingQueueLocked();
            rebuildStagedQueueTableLocked();
            selectQueueRow(table, selectedRow + 1);
        }
        updateStats();
    }

    private void moveSelectedQueuedRequest(JTable table, int direction) {
        synchronized (batchLock) {
            if (!canEditStagedQueueLocked()) {
                showError("Queue edits are only available before arming a batch.");
                return;
            }

            int selectedRow = selectedModelRow(table);
            int targetRow = selectedRow + direction;
            if (selectedRow < 0 || selectedRow >= pendingQueue.size()) {
                showError("Select a staged queued request first.");
                return;
            }
            if (targetRow < 0 || targetRow >= pendingQueue.size()) {
                return;
            }

            PreparedRaceRequest selected = pendingQueue.remove(selectedRow);
            pendingQueue.add(targetRow, selected);
            reindexPendingQueueLocked();
            rebuildStagedQueueTableLocked();
            selectQueueRow(table, targetRow);
        }
        updateStats();
    }

    private void clearStagedQueue() {
        synchronized (batchLock) {
            if (!canEditStagedQueueLocked()) {
                showError("Queue edits are only available before arming a batch.");
                return;
            }

            pendingQueue.clear();
            tableModel.clear();
            requestViewer.setRequest(null);
            responseViewer.setResponse(null);
        }
        updateStats();
    }

    private boolean canEditStagedQueueLocked() {
        return currentBatch.isEmpty() && !hasRunningTasksLocked();
    }

    private int selectedModelRow(JTable table) {
        int selectedRow = table.getSelectedRow();
        return selectedRow < 0 ? -1 : table.convertRowIndexToModel(selectedRow);
    }

    private void selectQueueRow(JTable table, int modelRow) {
        if (modelRow < 0 || modelRow >= tableModel.getRowCount()) {
            requestViewer.setRequest(null);
            responseViewer.setResponse(null);
            return;
        }

        int viewRow = table.convertRowIndexToView(modelRow);
        table.setRowSelectionInterval(viewRow, viewRow);
    }

    private void reindexPendingQueueLocked() {
        for (int i = 0; i < pendingQueue.size(); i++) {
            PreparedRaceRequest request = pendingQueue.get(i);
            pendingQueue.set(i, new PreparedRaceRequest(i + 1, request.request()));
        }
    }

    private void rebuildStagedQueueTableLocked() {
        tableModel.clear();
        for (PreparedRaceRequest queuedRequest : pendingQueue) {
            tableModel.addResult(RaceResultSnapshot.queued(
                    queuedRequest.requestIndex(),
                    0,
                    queuedRequest.requestIndex(),
                    queuedRequest.request()
            ));
        }
    }

    private void armBatch() {
        RaceBatch batch;
        boolean bestEffortWarmUp = bestEffortWarmUpToggle.isSelected();
        BaselineMode baselineMode = selectedBaselineMode();
        boolean autoReleaseAttempts = autoReleaseAttemptsToggle.isSelected();
        boolean multiEndpointMode = multiEndpointModeToggle.isSelected();
        int totalAttempts = (Integer) attemptsSpinner.getValue();
        int maxRetainedResponseBodyBytes = ((Integer) maxResponseBodyKbSpinner.getValue()) * 1024;
        int readyTimeoutSeconds = (Integer) readyTimeoutSecondsSpinner.getValue();
        List<String> keywords = ResponseAnalysis.splitCsv(keywordsField.getText());
        String successExpressionText = successExpressionField.getText();
        SuccessExpression successExpression;
        try {
            successExpression = SuccessExpression.parse(successExpressionText);
        } catch (SuccessExpression.InvalidExpressionException e) {
            showError(e.getMessage());
            return;
        }
        List<String> jsonPaths = SuccessExpression.jsonPathsFromExpression(successExpressionText);
        ResponseNormalization normalization;
        try {
            normalization = ResponseNormalization.fromUserInput(
                    ResponseAnalysis.splitCsv(ignoredHeadersField.getText()),
                    ResponseAnalysis.splitLines(bodyNormalizationRegexArea.getText()),
                    ResponseAnalysis.splitCsv(ignoredJsonFieldsField.getText()),
                    ignoreSetCookieToggle.isSelected()
            );
        } catch (PatternSyntaxException e) {
            showError("Invalid body normalization regex: " + e.getDescription());
            return;
        }
        for (String headerName : successExpression.referencedHeaders()) {
            if (normalization.ignoresHeader(headerName)) {
                showError("Success expression references ignored header '" + headerName + "'. Remove it from ignored headers or change the expression.");
                return;
            }
        }
        for (String jsonPath : jsonPaths) {
            if (normalization.ignoredJsonFields().contains(jsonPath)) {
                showError("Success expression references ignored JSON field '" + jsonPath + "'. Remove it from ignored JSON fields or change the expression.");
                return;
            }
        }
        List<PreparedRaceRequest> preparedRequests;
        TargetMetadata targetMetadata;

        synchronized (batchLock) {
            if (pendingQueue.isEmpty()) {
                showError("Queue one or more requests before arming the batch.");
                return;
            }

            int maxBatchSize = maxBatchSizeForCurrentMode();
            if (pendingQueue.size() > maxBatchSize) {
                showError("Current mode supports up to " + maxBatchSize + " synchronized requests."
                        + (turboMode ? "" : " Enable Turbo Mode for 50."));
                return;
            }

            if (!currentBatch.isEmpty() && hasRunningTasksLocked()) {
                showError("The current batch is already armed.");
                return;
            }

            preparedRequests = List.copyOf(pendingQueue);
            targetMetadata = TargetMetadata.from(preparedRequests.get(0).request());
            if (!multiEndpointMode) {
                for (PreparedRaceRequest preparedRequest : preparedRequests) {
                    TargetMetadata metadata = TargetMetadata.from(preparedRequest.request());
                    if (!targetMetadata.isCompatibleWith(metadata)) {
                        showError("Queued request " + preparedRequest.requestIndex()
                                + " targets " + metadata.describe()
                                + ". Enable Multi-endpoint mode for logical races across endpoints.");
                        return;
                    }
                }
            }

            for (int i = 0; i < preparedRequests.size(); i++) {
                PreparedRaceRequest preparedRequest = preparedRequests.get(i);
                if (preparedRequest.requestIndex() != i + 1) {
                    showError("Queue index mismatch; reset and queue the batch again.");
                    return;
                }
            }

            int totalOperations = BatchLimits.totalOperations(preparedRequests.size(), totalAttempts);
            if (BatchLimits.exceedsMaximum(preparedRequests.size(), totalAttempts)) {
                showError("Batch rejected: " + totalOperations + " total operations exceeds the " + BatchLimits.MAX_TOTAL_OPERATIONS + " operation limit.");
                return;
            }
            if (BatchLimits.requiresWarning(preparedRequests.size(), totalAttempts) && !confirmHighOperationCount(totalOperations, maxRetainedResponseBodyBytes)) {
                return;
            }

            if (baselineMode.requiresConfirmation() && !confirmDestructiveBaseline(preparedRequests.size())) {
                return;
            }
            if (baselineMode.requiresUnsafeMethodConfirmation(preparedRequests) && !confirmSingleControlRequest(preparedRequests.get(0).request())) {
                return;
            }

            activeTasks.clear();
            baselineByRequestIndex.clear();
            baselineByRequestTemplate.clear();
            pendingResponsesByRowId.clear();
            pendingResponseOmissionsByRowId.clear();
            responseRetentionBudgetsByAttempt.clear();
            clusterRepresentativeRowsByAttempt.clear();
            batchResponseOrder.set(0);
            statusOverride = "";
            currentAttempt = null;
            currentBatch = new RaceBatch(nextBatchId.getAndIncrement(), preparedRequests.size(), totalAttempts, targetMetadata, multiEndpointMode);
            batch = currentBatch;
            pendingQueue.clear();
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
                baselineMode,
                autoReleaseAttempts,
                keywords,
                jsonPaths,
                normalization,
                successExpression.referencedHeaders(),
                maxRetainedResponseBodyBytes,
                readyTimeoutSeconds,
                successExpression
        ));

        synchronized (batchLock) {
            activeTasks.add(coordinator);
        }

        updateStats();
    }

    private void showError(String message) {
        api.logging().logToError(message);
        SwingUtilities.invokeLater(() -> {
            if (statsLabel != null) {
                statsLabel.setText(message);
                statsLabel.setForeground(Color.RED);
            }
        });
    }

    private BaselineMode selectedBaselineMode() {
        Object selected = baselineModeCombo == null ? null : baselineModeCombo.getSelectedItem();
        return selected instanceof BaselineMode mode ? mode : BaselineMode.NONE;
    }

    private boolean confirmDestructiveBaseline(int requestCount) {
        int choice = JOptionPane.showConfirmDialog(
                null,
                "Full baseline will send all " + requestCount + " queued requests sequentially before the race.\n"
                        + "Only continue if the target state is disposable or has already been reset.",
                "Confirm destructive baseline",
                JOptionPane.OK_CANCEL_OPTION,
                JOptionPane.WARNING_MESSAGE
        );
        return choice == JOptionPane.OK_OPTION;
    }

    private boolean confirmSingleControlRequest(HttpRequest request) {
        int choice = JOptionPane.showConfirmDialog(
                null,
                "Single control request will send one real " + request.method() + " request before the race.\n"
                        + "This can mutate target state for actions such as redeem, withdraw, transfer, or confirm.",
                "Confirm mutating control request",
                JOptionPane.OK_CANCEL_OPTION,
                JOptionPane.WARNING_MESSAGE
        );
        return choice == JOptionPane.OK_OPTION;
    }

    private boolean confirmHighOperationCount(int totalOperations, int maxRetainedResponseBodyBytes) {
        int choice = JOptionPane.showConfirmDialog(
                null,
                "This batch will create " + totalOperations + " table rows.\n"
                        + "Full responses are retained only for representatives and success matches up to "
                        + formatBytes(maxRetainedResponseBodyBytes) + " per response and "
                        + formatBytes(ResponseRetentionBudget.MAX_PENDING_ATTEMPT_BYTES) + " per attempt.",
                "Confirm large batch",
                JOptionPane.OK_CANCEL_OPTION,
                JOptionPane.WARNING_MESSAGE
        );
        return choice == JOptionPane.OK_OPTION;
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
            BaselineMode baselineMode,
            boolean autoReleaseAttempts,
            List<String> keywords,
            List<String> jsonPaths,
            ResponseNormalization normalization,
            List<String> expressionHeaderNames,
            int maxRetainedResponseBodyBytes,
            int readyTimeoutSeconds,
            SuccessExpression successExpression
    ) {
        try {
            if (baselineMode != BaselineMode.NONE && !batch.isCancelled()) {
                updateStatsText("Running " + baselineMode.description() + " for batch " + batch.batchId() + "...");
                runSequentialBaseline(batch, preparedRequests, baselineMode, keywords, jsonPaths, normalization, expressionHeaderNames);
            }

            for (int attemptNumber = 1; attemptNumber <= batch.totalAttempts() && !batch.isCancelled(); attemptNumber++) {
                RaceBatch.RaceAttempt attempt = batch.attempt(attemptNumber);
                List<Future<?>> attemptWorkers = new ArrayList<>();
                responseRetentionBudgetsByAttempt.put(attemptNumber, new ResponseRetentionBudget(maxRetainedResponseBodyBytes));
                clusterRepresentativeRowsByAttempt.put(attemptNumber, new ConcurrentHashMap<>());
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
                            normalization,
                            expressionHeaderNames,
                            successExpression
                    ));
                    synchronized (batchLock) {
                        activeTasks.add(worker);
                    }
                    attemptWorkers.add(worker);
                }

                boolean allWorkersReady = attempt.awaitReady(readyTimeoutSeconds, TimeUnit.SECONDS);
                updateStats();
                if (!allWorkersReady) {
                    handleReadyTimeout(batch, attempt, attemptWorkers);
                    break;
                }
                if (attemptNumber > 1 && autoReleaseAttempts) {
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

    private void handleReadyTimeout(RaceBatch batch, RaceBatch.RaceAttempt attempt, List<Future<?>> attemptWorkers) {
        String baseMessage = "Ready timeout: " + attempt.readyCount() + "/" + attempt.expectedWorkerCount() + " workers ready";
        batch.cancel();
        for (Future<?> worker : attemptWorkers) {
            if (!worker.isDone()) {
                worker.cancel(true);
            }
        }

        SwingUtilities.invokeLater(() -> {
            List<Integer> warmUpRows = new ArrayList<>();
            List<Integer> preparationRows = new ArrayList<>();
            List<Integer> queuedRows = new ArrayList<>();
            List<Integer> failedRows = new ArrayList<>();

            for (int i = 0; i < tableModel.getRowCount(); i++) {
                RaceResultSnapshot snapshot = tableModel.getResult(i);
                if (snapshot.attempt() != attempt.attemptNumber() || reachedGate(snapshot)) {
                    continue;
                }

                String reason = timeoutReason(snapshot.status());
                if ("Warming".equals(snapshot.status())) {
                    warmUpRows.add(snapshot.id());
                } else if ("Preparing".equals(snapshot.status())) {
                    preparationRows.add(snapshot.id());
                } else if ("Queued".equals(snapshot.status())) {
                    queuedRows.add(snapshot.id());
                } else {
                    failedRows.add(snapshot.id());
                }

                tableModel.updateResult(i, snapshot
                        .withStatus("Ready timeout")
                        .withAnomaly(appendAnomaly(snapshot.anomaly(), reason)));
            }

            StringBuilder message = new StringBuilder(baseMessage);
            appendTimeoutRows(message, warmUpRows, "failed during warm-up");
            appendTimeoutRows(message, preparationRows, "failed during preparation");
            appendTimeoutRows(message, queuedRows, "never started");
            appendTimeoutRows(message, failedRows, "failed before reaching the gate");
            statusOverride = message.toString();
            api.logging().logToError(statusOverride);
            if (statsLabel != null) {
                statsLabel.setText(statusOverride);
                statsLabel.setForeground(Color.RED);
            }
        });
    }

    private void runSequentialBaseline(
            RaceBatch batch,
            List<PreparedRaceRequest> preparedRequests,
            BaselineMode baselineMode,
            List<String> keywords,
            List<String> jsonPaths,
            ResponseNormalization normalization,
            List<String> expressionHeaderNames
    ) {
        int baselineRequestCount = baselineMode == BaselineMode.SINGLE_REQUEST ? 1 : preparedRequests.size();
        for (PreparedRaceRequest preparedRequest : preparedRequests.subList(0, baselineRequestCount)) {
            if (batch.isCancelled()) {
                return;
            }

            long start = System.nanoTime();
            HttpRequestResponse response = api.http().sendRequest(preparedRequest.request());
            long responseTimeUs = (System.nanoTime() - start) / 1000;
            ResponseFingerprint fingerprint = ResponseAnalysis.fingerprint(response.response(), responseTimeUs, 0, 0, keywords, jsonPaths, normalization, expressionHeaderNames);
            baselineByRequestIndex.put(preparedRequest.requestIndex(), fingerprint);
            baselineByRequestTemplate.put(RequestTemplateKey.from(preparedRequest.request()), fingerprint);
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
            ResponseNormalization normalization,
            List<String> expressionHeaderNames,
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

            if (!markWorkerReady(batch, attempt, preparedRequest.requestIndex(), rowId)) {
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
            int attemptOrder = attempt.nextResponseOrder();
            int batchOrder = batchResponseOrder.incrementAndGet();
            HttpResponse responseMessage = response.response();
            ResponseFingerprint fingerprint = ResponseAnalysis.fingerprint(responseMessage, responseTimeUs, attemptOrder, batchOrder, keywords, jsonPaths, normalization, expressionHeaderNames);
            ResponseFingerprint baseline = baselineFor(preparedRequest);
            String body = responseMessage.bodyToString();
            boolean successMatched = successExpression.matches(fingerprint, baseline, body);
            String anomaly = ResponseAnalysis.summarizeDifference(baseline, fingerprint, successMatched);
            PendingResponseRetention retention = retainPendingResponse(
                    attempt.attemptNumber(),
                    rowId,
                    ResponseAnalysis.ClusterKey.from(fingerprint),
                    responseMessage,
                    successMatched
            );
            HttpResponse retainedResponse = successMatched && retention.retained() ? responseMessage : null;
            if (successMatched && !retention.retained()) {
                anomaly = appendAnomaly(anomaly, retention.omissionMessage());
            }
            String finalAnomaly = anomaly;

            updateTableSnapshot(rowId, snapshot -> snapshot.completed(responseMessage, retainedResponse, fingerprint, responseTimeUs, dispatchOffset, finalAnomaly));
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

    private ResponseFingerprint baselineFor(PreparedRaceRequest preparedRequest) {
        ResponseFingerprint baseline = baselineByRequestIndex.get(preparedRequest.requestIndex());
        if (baseline != null) {
            return baseline;
        }
        return baselineByRequestTemplate.get(RequestTemplateKey.from(preparedRequest.request()));
    }

    private void summarizeAttempt(RaceBatch batch, RaceBatch.RaceAttempt attempt) {
        SwingUtilities.invokeLater(() -> {
            List<Integer> attemptRows = new ArrayList<>();
            List<ResponseFingerprint> fingerprints = new ArrayList<>();
            for (int i = 0; i < tableModel.getRowCount(); i++) {
                RaceResultSnapshot snapshot = tableModel.getResult(i);
                if (snapshot.attempt() == attempt.attemptNumber() && "Done".equals(snapshot.status()) && snapshot.fingerprint() != null) {
                    attemptRows.add(i);
                    fingerprints.add(snapshot.fingerprint());
                }
            }

            String clusterSummary = "";
            if (!fingerprints.isEmpty()) {
                List<ResponseAnalysis.AttemptResponseCluster> clusters = ResponseAnalysis.clusterResponses(fingerprints);
                if (fingerprints.size() > 1) {
                    clusterSummary = ResponseAnalysis.summarizeClusters(clusters);
                }
                Map<ResponseAnalysis.ClusterKey, ResponseAnalysis.AttemptResponseCluster> clustersByKey = new HashMap<>();
                for (ResponseAnalysis.AttemptResponseCluster cluster : clusters) {
                    clustersByKey.put(cluster.key(), cluster);
                }

                int totalResponses = fingerprints.size();
                for (int rowIndex : attemptRows) {
                    RaceResultSnapshot snapshot = tableModel.getResult(rowIndex);
                    ResponseAnalysis.ClusterKey key = ResponseAnalysis.ClusterKey.from(snapshot.fingerprint());
                    ResponseAnalysis.AttemptResponseCluster cluster = clustersByKey.get(key);
                    if (cluster == null) {
                        continue;
                    }

                    RaceResultSnapshot updated = snapshot;
                    if (cluster.divergent()) {
                        updated = updated.withAnomaly(appendAnomaly(updated.anomaly(), cluster.anomalySummary(totalResponses)));
                    }

                    if (shouldAttachClusterRepresentative(attempt.attemptNumber(), key, rowIndex, cluster)) {
                        HttpResponse retainedResponse = pendingResponsesByRowId.get(rowIndex);
                        if (updated.response() == null && retainedResponse != null) {
                            updated = updated.withResponse(retainedResponse);
                        } else if (cluster.divergent() && updated.response() == null) {
                            updated = updated.withAnomaly(appendAnomaly(updated.anomaly(), responseNotRetainedMessage(rowIndex)));
                        }
                    }

                    if (!updated.equals(snapshot)) {
                        tableModel.updateResult(rowIndex, updated);
                    }
                }
            }
            for (int rowIndex : attemptRows) {
                pendingResponsesByRowId.remove(rowIndex);
                pendingResponseOmissionsByRowId.remove(rowIndex);
            }
            responseRetentionBudgetsByAttempt.remove(attempt.attemptNumber());
            clusterRepresentativeRowsByAttempt.remove(attempt.attemptNumber());

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
            if (!clusterSummary.isBlank()) {
                summary += " | " + clusterSummary;
            }
            api.logging().logToOutput(summary);
            statsLabel.setText(summary);
        });
    }

    private String appendAnomaly(String existing, String addition) {
        if (addition == null || addition.isBlank()) {
            return existing;
        }
        if (existing == null || existing.isBlank()) {
            return addition;
        }
        if (existing.contains(addition)) {
            return existing;
        }
        return existing + "; " + addition;
    }

    private boolean reachedGate(RaceResultSnapshot snapshot) {
        return "Ready".equals(snapshot.status()) || "Done".equals(snapshot.status());
    }

    private String timeoutReason(String status) {
        return switch (status) {
            case "Warming" -> "failed during warm-up";
            case "Preparing" -> "failed during preparation";
            case "Queued" -> "never started";
            default -> "failed before reaching the gate";
        };
    }

    private void appendTimeoutRows(StringBuilder message, List<Integer> rows, String reason) {
        if (!rows.isEmpty()) {
            message.append(" | ").append(formatRows(rows)).append(" ").append(reason);
        }
    }

    private String formatRows(List<Integer> rows) {
        if (rows.size() == 1) {
            return "Row " + rows.get(0);
        }
        if (rows.size() == 2) {
            return "Rows " + rows.get(0) + " and " + rows.get(1);
        }
        StringBuilder sb = new StringBuilder("Rows ");
        for (int i = 0; i < rows.size(); i++) {
            if (i > 0) {
                sb.append(i == rows.size() - 1 ? ", and " : ", ");
            }
            sb.append(rows.get(i));
        }
        return sb.toString();
    }

    private PendingResponseRetention retainPendingResponse(
            int attemptNumber,
            int rowId,
            ResponseAnalysis.ClusterKey clusterKey,
            HttpResponse response,
            boolean successMatched
    ) {
        int bodyBytes = response.body().length();
        synchronized (responseRetentionLock) {
            ResponseRetentionBudget budget = responseRetentionBudgetsByAttempt.computeIfAbsent(
                    attemptNumber,
                    ignored -> new ResponseRetentionBudget(DEFAULT_MAX_RETAINED_RESPONSE_BODY_KB * 1024)
            );
            Map<ResponseAnalysis.ClusterKey, Integer> representativeRows = clusterRepresentativeRowsByAttempt.computeIfAbsent(
                    attemptNumber,
                    ignored -> new ConcurrentHashMap<>()
            );

            boolean clusterRepresentative = !representativeRows.containsKey(clusterKey);
            if (clusterRepresentative) {
                representativeRows.put(clusterKey, rowId);
            }

            if (!clusterRepresentative && !successMatched) {
                return new PendingResponseRetention(false, responseNotRetainedMessage());
            }

            String omissionMessage = responseNotRetainedMessage(response, budget);
            if (!budget.tryReserve(bodyBytes)) {
                pendingResponseOmissionsByRowId.put(rowId, omissionMessage);
                return new PendingResponseRetention(false, omissionMessage);
            }

            pendingResponsesByRowId.put(rowId, response);
            return new PendingResponseRetention(true, "");
        }
    }

    private boolean shouldAttachClusterRepresentative(
            int attemptNumber,
            ResponseAnalysis.ClusterKey clusterKey,
            int rowId,
            ResponseAnalysis.AttemptResponseCluster cluster
    ) {
        Map<ResponseAnalysis.ClusterKey, Integer> representativeRows = clusterRepresentativeRowsByAttempt.get(attemptNumber);
        return representativeRows != null
                && representativeRows.getOrDefault(clusterKey, -1) == rowId
                && (cluster.divergent() || !cluster.minority());
    }

    private String responseNotRetainedMessage(HttpResponse response, ResponseRetentionBudget budget) {
        int bodyBytes = response.body().length();
        if (budget.maxPerResponseBytes() <= 0) {
            return responseNotRetainedMessage();
        }
        if (bodyBytes > budget.maxPerResponseBytes()) {
            return "full response not retained (body " + formatBytes(bodyBytes)
                    + " exceeds " + formatBytes(budget.maxPerResponseBytes()) + " per-response limit)";
        }
        return "full response not retained (attempt retention budget "
                + formatBytes(budget.maxPerAttemptBytes()) + " reached)";
    }

    private String responseNotRetainedMessage(int rowId) {
        return pendingResponseOmissionsByRowId.getOrDefault(rowId, responseNotRetainedMessage());
    }

    private String responseNotRetainedMessage() {
        return "full response not retained";
    }

    private String formatBytes(int bytes) {
        if (bytes <= 0) {
            return "0 KB";
        }
        if (bytes % 1024 == 0) {
            return (bytes / 1024) + " KB";
        }
        return bytes + " bytes";
    }

    private int rowIdFor(int attemptNumber, int requestIndex, int expectedWorkerCount) {
        return (attemptNumber - 1) * expectedWorkerCount + requestIndex - 1;
    }

    private record PendingResponseRetention(boolean retained, String omissionMessage) {
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
            pendingQueue.clear();
            baselineByRequestIndex.clear();
            baselineByRequestTemplate.clear();
            pendingResponsesByRowId.clear();
            pendingResponseOmissionsByRowId.clear();
            responseRetentionBudgetsByAttempt.clear();
            clusterRepresentativeRowsByAttempt.clear();
            batchResponseOrder.set(0);
            statusOverride = "";

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

    private boolean markWorkerReady(RaceBatch batch, RaceBatch.RaceAttempt attempt, int workerId, int rowId) {
        synchronized (batchLock) {
            if (batch != currentBatch || !attempt.markReady(workerId)) {
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
            int queuedCount;
            boolean armEnabled;
            synchronized (batchLock) {
                RaceBatch.RaceAttempt attempt = currentAttempt;
                readyCount = attempt == null ? 0 : attempt.readyCount();
                expectedCount = attempt == null ? 0 : attempt.expectedWorkerCount();
                released = attempt != null && attempt.isReleased();
                releaseEnabled = attempt != null && attempt.isReadyToRelease();
                attemptNumber = attempt == null ? 0 : attempt.attemptNumber();
                totalAttempts = currentBatch.isEmpty() ? 0 : currentBatch.totalAttempts();
                queuedCount = pendingQueue.size();
                armEnabled = !pendingQueue.isEmpty() && (currentBatch.isEmpty() || !hasRunningTasksLocked());
            }

            StringBuilder sb = new StringBuilder();
            if (statusOverride != null && !statusOverride.isBlank()) {
                sb.append(statusOverride).append("  |  ");
            }
            if (attemptNumber > 0) {
                sb.append("Attempt: ").append(attemptNumber).append("/").append(totalAttempts).append("  |  ");
            } else if (queuedCount > 0) {
                sb.append("Queued: ").append(queuedCount).append("  |  ");
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
            if (armBtn != null) {
                armBtn.setEnabled(armEnabled);
            }

            // Visual Alert for anomalies (500s or mixed 200/403)
            if (statusOverride != null && !statusOverride.isBlank()) {
                statsLabel.setForeground(Color.RED);
            } else if (counts.containsKey((short)500) || counts.containsKey((short)503)) {
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
                "Attempt Order",
                "Batch Order",
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
                case 1 -> r.attempt() == 0 ? "" : r.attempt();
                case 2 -> r.request().method();
                case 3 -> r.request().url();
                case 4 -> r.status();
                case 5 -> (r.statusCode() == 0) ? "" : r.statusCode();
                case 6 -> (r.status().equals("Done")) ? r.length() : "";
                case 7 -> (r.timeTakenUs() == 0) ? "" : r.timeTakenUs();
                case 8 -> (r.status().equals("Done")) ? r.dispatchOffsetUs() : "";
                case 9 -> r.bodyHash();
                case 10 -> (r.attemptOrder() == 0) ? "" : r.attemptOrder();
                case 11 -> (r.batchOrder() == 0) ? "" : r.batchOrder();
                case 12 -> r.anomaly();
                default -> "";
            };
        }
    }

    private record PreparedRaceRequest(int requestIndex, HttpRequest request) {}

    private enum BaselineMode {
        NONE("No baseline", "no baseline", false),
        SINGLE_REQUEST("Single control request - may mutate state", "single control request", false),
        FULL_DESTRUCTIVE("Full baseline (destructive)", "full destructive baseline", true);

        private final String label;
        private final String description;
        private final boolean requiresConfirmation;

        BaselineMode(String label, String description, boolean requiresConfirmation) {
            this.label = label;
            this.description = description;
            this.requiresConfirmation = requiresConfirmation;
        }

        String description() {
            return description;
        }

        boolean requiresConfirmation() {
            return requiresConfirmation;
        }

        boolean requiresUnsafeMethodConfirmation(List<PreparedRaceRequest> preparedRequests) {
            if (this != SINGLE_REQUEST || preparedRequests.isEmpty()) {
                return false;
            }
            String method = preparedRequests.get(0).request().method();
            return !HttpMethodSafety.isSafeForControlBaseline(method);
        }

        @Override
        public String toString() {
            return label;
        }
    }
}
