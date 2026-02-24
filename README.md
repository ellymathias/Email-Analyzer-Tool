# Email Header Analyzer

A web-based cybersecurity tool designed to analyze raw email headers for potential security risks, spoofing attempts, and suspicious indicators.

## Features

*   **Risk Assessment**: Calculates an overall risk score (Low, Medium, High) based on various security checks.
*   **Authentication Analysis**: Checks SPF, DKIM, and DMARC results extracted from the header.
*   **Spoofing Detection**: Compares 'From' and 'Reply-To' headers to identify potential mismatch attacks.
*   **IP Address Analysis**:
    *   Extracts Origin, Public, and Private IP addresses.
    *   **Reputation Lookup**: Performs real-time lookups using `ip-api.com` to identify the Origin IP's Country, ISP, Organization, and Proxy/VPN status.
*   **Suspicious Indicators**: Flags specific issues like failed authentication checks, unusual hop counts, or known proxy usage.
*   **PDF Export**: Generate a professional PDF report of the analysis results for documentation or sharing.

## Prerequisites

*   Python 3.x
*   pip (Python package installer)

## Installation

1.  **Clone the repository** or download the source code.

2.  **Install dependencies**:
    Open your terminal or command prompt in the project directory and run:
    ```bash
    pip install flask requests
    ```

## Usage

1.  **Start the application**:
    ```bash
    python app.py
    ```

2.  **Access the tool**:
    Open your web browser and navigate to `http://127.0.0.1:5000`.

3.  **Analyze an Email**:
    *   Paste a raw email header into the text area.
    *   Click **Analyze Header**.
    *   Review the risk assessment and detailed breakdown.
    *   Click **Export Results as PDF** to save the report.

## Disclaimer

This tool is for educational and defensive purposes only.