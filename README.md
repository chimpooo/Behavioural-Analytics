# Behavioural-Analytics

Objective: Enrichment of threat sharing database for providing Behaviour Analytics through malware analysis and extraction of Indicators and Behaviour.

<img width="452" alt="image" src="https://user-images.githubusercontent.com/95999613/176328566-0384553c-2508-40fd-a062-b3cf6d06178a.png">

Implementation:
1. Extraction hashes are done from Malpedia and Vx-underground. This code uses the burp suite proxy server for analysing the enormous data without causing overload. Also the quota per day analysis in VirusTotal is limited to 500. So, it prevents data limit from going over this limit. 

2. get_vt_collection:
Handles the collection of information from VirusTotal APIs for the hashes fed. If the sample is analysed in VT then it provides the details of the sample in JSON format. 

3. extract_indicators.py
Performs analysis of the complex data in the JSON file and processes the data to extract relevant indicators

4. stix_bundle.py
Normalization of the samples and  collected in STIX format

5. attack_pattern.py
Check the similarity between the attack patterns

6. misp_analysis.py
Data analysis in MISP platform is performed.

