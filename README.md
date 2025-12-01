# Race Condition Gate (Burp Suite Extension)

**A Synchronization Tool for testing Time-of-Check to Time-of-Use (TOCTOU) Vulnerabilities**

![Java](https://img.shields.io/badge/Java-ED8B00?style=for-the-badge&logo=java&logoColor=white) ![Burp Suite](https://img.shields.io/badge/Burp_Suite-FF6633?style=for-the-badge&logo=burpsuite&logoColor=white) ![Security](https://img.shields.io/badge/Cybersecurity-Bug_Bounty-red?style=for-the-badge)

## Overview
**Race Condition Gate** is a Burp Suite extension designed to facilitate the testing of race conditions in web applications.

Standard requests sent via Burp Suite (even in Intruder) are subject to network jitter and sequential processing overhead. This extension allows the user to "Queue" multiple requests in a suspended state (using Java threading synchronization) and then "Release" them simultaneously using a single button. This maximizes the probability of multiple requests arriving at the server within the same execution window.

## Features

### 1. The Gate Logic
* **Thread Synchronization:** Uses `java.util.concurrent.CountDownLatch` to pause requests just before they are sent to the network stack.
* **Instant Release:** A dedicated button releases all paused threads instantly, minimizing the time gap between requests.

### 2. Dedicated UI Dashboard
* **Queue Table:** A clear table showing every queued request, its method, and URL.
* **Real-Time Feedback:** Once released, the table updates with the Status Code (e.g., 200 vs 403) and the exact time taken (in microseconds).
* **Split-View Analysis:** Click any row to see the exact **Request** sent and **Response** received in a side-by-side view.

### 3. Workflow Integration
* **Context Menu:** Right-click any request in Repeater/Proxy to `Queue This Request`.
* **One-Click Reset:** A "Clear / Reset" button allows you to wipe the slate clean for the next test iteration.

## Installation

### Prerequisites
* Java Development Kit (JDK) 21.
* Burp Suite (Community or Professional).
* Gradle.

### Build from Source
1.  Clone the repository:
    ```bash
    git clone https://github.com/tobiasGuta/Race-Condition-Gate.git
    cd Race-Condition-Gate
    ```
2.  Build the JAR file:
    ```bash
    ./gradlew clean jar
    ```
3.  Load into Burp Suite:
    * Navigate to **Extensions** -> **Installed**.
    * Click **Add** -> Select `build/libs/RaceConditionGate.jar`.

## Usage Guide

1.  **Prepare a Request:** Send a request to Repeater (e.g., a coupon redemption or money transfer).
2.  **Queue the Attack:**
    * Right-click the request -> **Race Gate: Queue This Request**.
    * Repeat this step for as many concurrent requests as you wish to send (e.g., 10 times).
3.  **Execute:**
    * Go to the **"Race Gate"** tab.
    * Click the red **RELEASE ALL** button.
4.  **Analyze:**
    * Watch the Status column update.
    * Click on rows to inspect responses. If you see multiple successful transactions (e.g., 200 OK) where only one should exist, you have confirmed a vulnerability.
  
<img width="1912" height="886" alt="Screenshot 2025-11-29 153612" src="https://github.com/user-attachments/assets/8d9e8af3-d2b8-44e8-b330-0fbdeda232c5" />

https://github.com/user-attachments/assets/273b21bf-189f-454e-9e8c-6b75cba56d70

## Tech Stack
* **Language:** Java 21
* **API:** Burp Suite Montoya API
* **Concurrency:** `CountDownLatch`, `AtomicInteger`
* **UI:** Swing (JTable, JSplitPane)

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
