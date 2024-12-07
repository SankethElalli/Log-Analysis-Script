# Log Analysis Tool

A Python-based tool for analyzing web server logs to extract valuable insights, such as:
- Request counts per IP address.
- Most frequently accessed endpoints.
- Detection of suspicious activity (e.g., repeated failed login attempts).
- Exporting results to a CSV file for further analysis.

# Features

1.	Request Counts per IP: Identifies and displays the number of requests made by each IP address.
2.	Frequently Accessed Endpoints: Finds and reports the most accessed endpoints in the server logs.
3.	Suspicious Activity Detection: Flags suspicious activity based on failed login attempts.
4.	CSV Export: Saves the analysis results to a CSV file for easy sharing or further analysis.

# Requirements

Python 3.6 or higher, required Python libraries:
- re (built-in)
- collections (built-in)
- csv (built-in)
- pandas

# CSV Output Format

The generated CSV file includes the following columns:
- IP Address: The source IP address of the request.
- Request Count: The number of requests made by the IP address.
- Endpoint: The most frequently accessed endpoint.
- Access Count: The number of times the most accessed endpoint was requested.
- Failed Login Count: Number of failed login attempts (if any).
