# Race Condition Gate (Burp Suite Extension)

**A Thread-Level Orchestration Tool for testing Time-of-Check to Time-of-Use (TOCTOU) Vulnerabilities**

![Java](https://img.shields.io/badge/Java-ED8B00?style=for-the-badge&logo=java&logoColor=white) ![Burp Suite](https://img.shields.io/badge/Burp_Suite-FF6633?style=for-the-badge&logo=burpsuite&logoColor=white) ![Security](https://img.shields.io/badge/Cybersecurity-Bug_Bounty-red?style=for-the-badge)

## Overview
**Race Condition Gate** is a Burp Suite extension designed to facilitate the testing of race conditions in web applications.

Standard requests sent manually through Burp Suite are subject to operator delay and sequential workflow overhead. This extension allows the user to queue multiple requests, optionally run a best-effort warm-up step, capture a sequential baseline, run repeated race attempts, wait until every worker is ready, and then release those Java workers from a shared latch.

This is thread-level orchestration through Burp's Montoya HTTP stack. It does not implement wire-level synchronization such as HTTP/1 last-byte synchronization or HTTP/2 single-packet attacks.

**New in v2.0:** Now includes an optional best-effort connection warm-up control. It can reduce setup latency in some cases, but it does not guarantee that the race request uses the same connection.

## Features

### 1. Advanced Synchronization & Network Logic
* **Best-effort Connection Warm-up:** If enabled, each worker sends a lightweight `HEAD /` request before waiting at the gate. This may encourage DNS resolution or connection setup, but it creates extra target traffic and does not prove the real request will reuse the same connection.
* **Ready-Gated Release:** Each batch owns its own attempt barriers, release latch, cancellation state, batch ID, target metadata, and expected worker count. The release button is enabled only when every worker for the active attempt is waiting at the gate.
* **Readiness Timeout:** The coordinator stops waiting when workers fail to reach the gate within the configured timeout, cancels the attempt, and marks rows that were still warming, preparing, or queued.
* **Bounded Worker Pools:** Safe mode uses 20 threads. Turbo mode uses a bounded 50-thread pool. Safe mode refuses a 50-request batch instead of silently running it in waves.
* **Target Compatibility:** Precision batches enforce the same host, port, TLS mode, and HTTP protocol. Multi-endpoint mode is available when a logical race intentionally spans endpoints.

### 2. Precision Model
Race Condition Gate releases Java workers at approximately the same time, then each worker independently calls Burp's HTTP API. Scheduling, connection reuse, TLS, TCP, HTTP framing, Burp internals, and network transmission can still add variance after release.

For raw timing precision, purpose-built tooling such as Burp Repeater's race-condition features or Turbo Intruder can synchronize closer to the network layer. Race Condition Gate is better suited for workflow, repeatable experiment setup, payload orchestration, result inspection, and lightweight analysis.

The current project dependency is Montoya API `2023.12.1`, so this implementation does not use newer request options for explicit HTTP mode or connection identity. Newer Montoya API documentation exposes request options for HTTP mode and connection IDs; upgrading the dependency would be the right prerequisite before attempting stronger connection control.

### 3. Workflow Efficiency
* **Editable Batch Queueing:** The context menu queues **1, 10, 20, or 50 requests** without immediately starting workers. You can add multiple requests, including different endpoints when Multi-endpoint mode is enabled, then freeze the queue with **ARM BATCH**. The 50-request option requires Turbo mode.
* **Repeated Attempts:** The attempts control supports runs such as `20 requests x 10 attempts`. By default, every attempt waits for a manual release so the tester can manually restore target state between attempts. An explicit auto-release toggle can release later attempts automatically once every worker is ready.
* **Baseline Modes:** Baseline defaults to **No baseline**. **Single control request - may mutate state** sends one control request and shares that fingerprint with queued requests that have an identical method, URL, and body. Unsafe methods such as POST require confirmation. **Full baseline (destructive)** sends every queued request sequentially before racing and requires confirmation because it can consume one-time application state.
* **Attempt-Level Clustering:** Every completed attempt groups responses by status, body hash, response length, and selected headers. Minority clusters, equal split response families, and highly divergent all-unique attempts are marked as anomalies even when baseline mode is disabled.
* **Noise Normalization:** Ignore noisy headers, suppress `Set-Cookie`, redact JSON fields, and replace body regex matches before response length/hash comparison and clustering. Body normalization regexes are entered one per line.
* **Response Memory Limits:** Batches are capped at 500 request operations, with a warning above 200. Full-response retention is capped at 1 MB per response and 32 MB per attempt. The extension keeps metadata for every row, then retains only budgeted full-response representatives for response families and success-expression matches.
* **Validated Success Expressions:** A simple `and` expression can flag interesting responses, for example `status == 200 and body contains "redeemed" and json $.balance changed`. Invalid terms are rejected before the batch is armed, and custom `header ... contains ...` terms are collected for matching.
* **Legacy Compatibility:** Custom HTTP request construction ensures full compatibility with older versions of the Montoya API (2023.12.1+).

### 4. Dedicated UI Dashboard
* **Queue Table:** A clear table showing every queued request, its attempt, method, URL, status, normalized UTF-8 byte length, timing, response family hash, response order, and anomaly notes. Before arming, staged requests can be removed, duplicated, moved up/down, or cleared.
* **Real-Time Feedback:** The UI reports active attempt readiness before release, then updates each row with attempt number, status code, normalized UTF-8 byte length, timing, thread dispatch offset, body hash, response order, and anomaly summary.
* **Split-View Analysis:** Click any row to see the exact **Request** sent and **Response** received in a side-by-side view.
* **Safe Reset:** A "Clear / Reset" button cancels all pending tasks and wipes the slate clean safely.

## Installation

### Prerequisites
* Java Development Kit (JDK) 17 or 21.
* Burp Suite (Community or Professional).
* Gradle.

### Build from Source
1.  Clone the repository:
    ```bash
    git clone [https://github.com/tobiasGuta/Race-Condition-Gate.git](https://github.com/tobiasGuta/Race-Condition-Gate.git)
    cd Race-Condition-Gate
    ```
2.  Build the JAR file:
    ```bash
    ./gradlew clean build
    ```
3.  Load into Burp Suite:
    * Navigate to **Extensions** -> **Installed**.
    * Click **Add** -> Select `build/libs/RaceConditionGate-1.0-SNAPSHOT.jar`.

## Usage Guide

1.  **Prepare a Request:** Send a request to Repeater (e.g., a coupon redemption or money transfer).
2.  **Queue the Attack:**
    * Right-click the request -> **Race Gate Queue**.
    * Select **Queue 10 Requests** (or your desired amount).
    * Use **Remove**, **Duplicate**, **Up**, **Down**, or **Clear Queue** to edit staged requests before arming.
    * For multi-endpoint races, repeat this from additional requests, then enable **Multi-endpoint** before arming.
    * Optionally enable **Best-effort warm-up** if extra `HEAD /` traffic is acceptable for the target and test plan.
    * Optionally choose a safe **Baseline** mode, set **Attempts**, configure comma-separated **Keywords**, and add a **Success** expression.
    * Configure noise controls for dynamic response values such as timestamps, request IDs, CSRF tokens, analytics IDs, or session cookies.
    * Set **Max body KB** to control how large a representative or success-match response body may be before the extension stores metadata only. The control is capped at 1 MB per response, with a 32 MB total retained-response budget per attempt.
    * Set **Ready timeout** to bound how long the coordinator waits for every worker to finish warm-up/preparation and reach the gate.
    * Leave **Auto-release attempts** unchecked when target state must be restored between attempts.
3.  **Execute:**
    * Go to the **"Race Gate"** tab.
    * Click **ARM BATCH** to freeze the queue and start the workers.
    * Wait until the dashboard reports the active attempt is ready.
    * Click the red **RELEASE ALL** button.
4.  **Analyze:**
    * Watch the Status column update.
    * Click on rows to inspect responses. If you see multiple successful transactions (e.g., 200 OK) where only one should exist, treat it as a candidate race-condition finding and validate it with appropriate follow-up testing.
   
<img width="1912" height="886" alt="Screenshot 2025-11-29 153612" src="https://github.com/user-attachments/assets/8d9e8af3-d2b8-44e8-b330-0fbdeda232c5" />

https://github.com/user-attachments/assets/273b21bf-189f-454e-9e8c-6b75cba56d70

## Tech Stack
* **Language:** Java 21
* **API:** Burp Suite Montoya API
* **Concurrency:** `CountDownLatch`, `ExecutorService`, `Future`
* **UI:** Swing (JTable, JSplitPane)

## Repository Hygiene
* The project uses the Groovy `build.gradle` file only.
* Montoya API is declared as `compileOnly` because Burp provides it at runtime.
* Generated `build/` output is ignored and should not be committed.
* GitHub Actions builds the project on pushes and pull requests.
* Tags matching `v*` create GitHub releases with the built JAR attached.
* Unit tests cover batch barriers, duplicate readiness, cancellation, target compatibility, response analysis, success-expression validation, clustering, normalization, and operation limits. Burp UI workflows such as reset during an in-flight warm-up and worker submission failure still need integration coverage inside Burp or a Montoya-backed harness.

## Limitations
* This extension does not control HTTP framing or packet emission directly.
* The optional warm-up request is separate from the race request; Burp may select a different connection for the real request.
* The optional warm-up request can trigger WAF, rate-limit, logging, routing, or authentication-side behavior.
* The optional warm-up does not attempt to force connection reuse with the HTTP/1.1 `Connection` header because that would not provide meaningful HTTP/2 connection control.
* Baseline requests are real target requests. Use **No baseline** for one-time actions such as coupon redemption, withdrawals, transfers, account changes, or order state transitions unless the target state is disposable. The single control request mode still mutates state when used with unsafe methods.
* Repeated attempts can mutate the same target state repeatedly. Keep automatic attempt release disabled unless the test plan includes disposable state or manual state restoration between attempts.
* Automated reset requests or reset hooks between attempts are not implemented yet. A future workflow could let the user stage a dedicated non-gated reset request that runs between attempts.
* Body regex normalization is intentionally simple replacement before hashing. Enter one regex per line; commas are treated as regex text, not separators. Invalid regexes are rejected when arming the batch.
* Success expressions support `status == 200`, `status != 409`, `body contains "text"`, `body not contains "text"`, `header Name contains "text"`, `json $.field == value`, and `json $.field changed`. Unknown terms such as `stats == 200` are rejected before execution.
* Full response bodies are intentionally not retained for every row. A row can still be analyzed through status, normalized length, body hash, response order, dispatch timing, selected headers, and anomaly text.
* Full-response retention is limited to one representative from the dominant response family, one representative from each divergent response family, and success-expression matches while the per-response and per-attempt budgets allow it. Rows may be metadata-only when their response body exceeds **Max body KB**, when that value is set to `0`, or when the attempt budget has already been reserved.
* If Burp's HTTP API call is blocked below Java interruption, a readiness timeout cancels the attempt and updates the UI, but the underlying worker may not stop immediately. Use **Clear / Reset** before starting another batch.
* It does not implement HTTP/1 last-byte synchronization.
* It does not implement HTTP/2 single-packet attacks.
* `Dispatch Offset (us)` measures when a Java worker resumed after latch release and began calling Burp's HTTP API. It does not measure when bytes left the machine, when the server received the request, or when the server began processing it.

## Disclaimer
This tool is for educational purposes and authorized security testing only. Do not use this tool on systems you do not have permission to test. The author is not responsible for any misuse.

# Support
If my tool helped you land a bug bounty, consider buying me a coffee ☕️ as a small thank-you! Everything I build is free, but a little support helps me keep improving and creating more cool stuff ❤️
---

<div align="center">
  <h3>☕ Support My Journey</h3>
</div>


<div align="center">
  <a href="https://www.buymeacoffee.com/tobiasguta">
    <img src="https://cdn.buymeacoffee.com/buttons/v2/default-yellow.png" width="200" />
  </a>
</div>
