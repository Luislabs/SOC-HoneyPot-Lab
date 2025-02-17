# SOC-HoneyPot-Lab

## Objective

In this lab, the objectives are to configure and analyze honeypot data using a SIEM platform to detect and correlate suspicious activities, simulate real-world attack scenarios for enhanced threat intelligence, and develop effective incident response strategies based on the insights gathered.


### Skills Learned

- Advanced understanding of SIEM concepts and practical application.
- Proficiency in analyzing and interpreting network logs.
- Ability to generate and recognize attack signatures and patterns.
- Enhanced knowledge of network protocols and security vulnerabilities.
- Development of critical thinking and problem-solving skills in cybersecurity.

### Tools Used

- Security Information and Event Management (SIEM) system for log ingestion and analysis.
- Elasticsearch: A search and analytics engine that stores and analyzes data.
- Logstash: A data processing pipeline that collects, transforms, and sends data to Elasticsearch.
- Kibana: A visualization layer that allows users to create dashboards and visualizations.
- Honeypot to attract hackers.
  
## Steps


Example below.

*Step 1: Created a Virtual machine to host Honeypot*
=
![honeypot lab 0](https://github.com/user-attachments/assets/065c16aa-c914-4b8c-928b-50af39c77204)
=
*Step 2: World Map simulator shows where attackers are coming from* 
=
![Honeypot Lab](https://github.com/user-attachments/assets/b7cd9135-67e8-4625-829e-0c4da0ca1a58)

Step 3: SIEM Dashboard used to see ip adresses, brute force methods, etc.
=
![honeypot lab 2](https://github.com/user-attachments/assets/c848a721-6571-4def-997e-26eafd5cde7c)
![honeypot lab 3](https://github.com/user-attachments/assets/04bfba89-9f43-4b0b-b4e1-619e462f0daf)

Step 4: Querying the SIEM logs to quickly identify the origin of the suspicious network activity
=
![honeypot lab 4](https://github.com/user-attachments/assets/3b6a36d2-92a1-4268-9f3e-6c41becc810f)

Step 5: Placed IP adress of attacker on OSINT tool VirusTotal To see if its malicious
=
![Virus total](https://github.com/user-attachments/assets/34c3ff96-77aa-45b0-90d4-6b33bb75f41f)
