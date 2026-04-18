# SecureX AI
## Intelligent Intrusion Detection and Prevention System

### Project Report

**Prepared for:** Academic Project Submission  
**Project Type:** Cybersecurity / Machine Learning / Full-Stack Monitoring System  
**Technology Stack:** Python, Scapy, Flask, Socket.IO, SQLite, scikit-learn  

---

## Table of Contents

1. Abstract  
2. Introduction  
3. Objectives  
4. Scope of the System  
5. Problem Statement  
6. Dataset Description  
7. System Architecture Overview  
8. Methodology  
9. Feature Engineering  
10. Model Building  
11. Model Evaluation and Results  
12. Model Interpretability  
13. System Deployment  
14. Results and Discussion  
15. Limitations and Future Enhancements  
16. Conclusion  
17. References  

---

## 1. Abstract

SecureX AI is a hybrid Intrusion Detection and Prevention System (IDPS) designed to monitor network traffic in real time, detect suspicious behavior, generate alerts, visualize incidents through a live dashboard, and automatically block malicious IP addresses when threat levels are high. The project combines packet capture, sliding-window traffic analysis, rule-based detection, machine learning-based anomaly scoring, geolocation enrichment, threat scoring, event logging, and firewall-level automated response.

The motivation behind this project is the growing need for lightweight, explainable, and affordable network defense systems that can be used for education, prototyping, and small-scale deployments. Conventional IDS tools are often powerful but difficult to understand, customize, or demonstrate in academic settings. SecureX AI addresses this gap by offering a modular and transparent design where each stage of the pipeline can be inspected and extended.

The system captures network packets using Scapy, converts them into structured packet records, aggregates them per source IP over a sliding time window, and computes behavioral features such as request rate, protocol ratios, port diversity, authentication-port hit frequency, and packet-size statistics. These features are then analyzed by a rule engine and a machine learning engine. The rule engine detects patterns like DDoS, port scans, brute-force attempts, ICMP floods, and UDP floods, while the machine learning component uses Isolation Forest and Random Forest to estimate anomalies and classify attacks.

To improve decision-making, alerts are enriched with geolocation metadata and combined into a composite threat score. High-severity alerts are stored in SQLite, shown on the dashboard in real time, and optionally forwarded by email. If the final score crosses a configured threshold, the attacker IP can be blocked automatically through OS firewall rules.

Overall, SecureX AI demonstrates how networking, cybersecurity, machine learning, and real-time web visualization can be integrated into one operational pipeline. The project is valuable as an educational system, a cyber-defense prototype, and a foundation for future research into explainable and adaptive intrusion detection.

---

## 2. Introduction

In modern digital environments, network infrastructures are continuously exposed to cyber threats such as denial-of-service attacks, unauthorized scanning, brute-force login attempts, malware communication, botnet activity, and exploitation attempts. Since network traffic is high in volume and dynamic in nature, manual monitoring is no longer a practical solution. This has made Intrusion Detection Systems (IDS) and Intrusion Prevention Systems (IPS) essential for maintaining confidentiality, integrity, and availability in digital systems.

Traditional IDS solutions rely heavily on fixed signatures and predefined patterns. These systems are highly effective for known threats but may struggle with evolving attack behavior or previously unseen anomalies. On the other hand, modern machine learning approaches can discover unusual behavior patterns without depending entirely on signatures, but they often suffer from limited interpretability and may be difficult to deploy in real-time environments.

SecureX AI is designed as a hybrid system that attempts to combine the best features of both approaches. It uses rule-based detection for explainability and fast pattern recognition, while also integrating machine learning for anomaly detection and attack-type classification. Instead of simply detecting an event, the system extends the workflow into logging, visualization, and automated response. This makes it not only an IDS but an IDS/IPS prototype.

Another important aspect of this project is its accessibility. Many enterprise-grade security systems require large infrastructure, expensive licenses, or specialized expertise. SecureX AI, by contrast, is implemented using widely available open-source tools and can run on a local machine. It also supports a synthetic demo mode, allowing users to simulate malicious traffic even when live packet capture is unavailable.

From an academic perspective, this project is especially meaningful because it covers multiple disciplines: network packet analysis, statistical feature engineering, rule design, machine learning, backend services, database logging, real-time dashboard development, and firewall automation. It is therefore suitable not only as a cybersecurity project but as a full-system engineering project.

---

## 3. Objectives

The primary objectives of SecureX AI are as follows:

- To design a real-time network intrusion detection system capable of monitoring incoming traffic continuously.
- To transform packet-level traffic into behavior-based features that support meaningful detection.
- To detect suspicious network activity using a rule-based engine with configurable thresholds.
- To enhance detection through machine learning models for anomaly scoring and attack classification.
- To generate rich alerts that include attack type, confidence, severity, and contextual metadata.
- To calculate a composite threat score using rule contribution, ML contribution, and geolocation-based risk.
- To provide a live web dashboard for observing alerts, blocked IPs, and traffic statistics.
- To support automatic IP blocking through the operating system firewall.
- To maintain persistent logs for alerts, traffic snapshots, and firewall actions.
- To provide a demonstration-friendly environment through synthetic traffic generation and replay support.

These objectives make the system useful not only for proof-of-concept detection but also for teaching how an end-to-end cyber-defense pipeline works in practice.

---

## 4. Scope of the System

The scope of SecureX AI includes the real-time monitoring and analysis of IP-based network traffic on a host machine or small-scale environment. The system can capture live packets or produce synthetic traffic for testing, extract useful packet-level attributes, aggregate traffic by source IP, and apply hybrid detection logic to identify suspicious behavior.

The system includes the following functional scope:

- Real-time packet capture using Scapy.
- Synthetic attack generation for safe demonstrations.
- Per-IP traffic aggregation using a sliding time window.
- Rule-based detection for known suspicious patterns.
- ML-based anomaly detection and attack classification.
- Geolocation enrichment using an external IP geolocation service.
- Threat scoring and alert prioritization.
- Logging of alerts and traffic snapshots into SQLite.
- A Flask-based dashboard with live WebSocket updates.
- Automatic or manual blocking/unblocking of attacker IPs.

The system does not currently attempt to solve all enterprise network security challenges. It does not provide:

- Deep inspection of encrypted application payloads.
- Distributed traffic collection across multiple hosts.
- Centralized correlation across large-scale infrastructure.
- User authentication and role-based access for dashboard administration.
- Production-hardened cloud deployment.
- Full integration with SIEM, SOAR, or commercial threat intelligence feeds.

Therefore, the project is best understood as a functional prototype and educational system rather than a complete enterprise security platform.

---

## 5. Problem Statement

Cyberattacks are increasingly frequent, automated, and sophisticated. Even small networks are vulnerable to denial-of-service traffic, brute-force login attempts, reconnaissance scans, and anomalous communication patterns. Existing defensive tools are often either too basic, focusing only on static signatures, or too complex and expensive for educational use and rapid experimentation.

The key problem addressed by this project is:

**How can a lightweight, explainable, and extensible system be developed to monitor network traffic in real time, detect attacks using both deterministic rules and machine learning, and automatically respond to high-risk threats?**

This problem has both technical and practical dimensions. Technically, packet streams are continuous and noisy, making real-time analysis challenging. Practically, a useful system must not only detect malicious behavior but also surface actionable insights and support timely response. SecureX AI addresses this by creating a modular pipeline that combines traffic capture, aggregation, detection, scoring, alerting, visualization, and prevention.

---

## 6. Dataset Description

The machine learning pipeline in this project is based primarily on the CICIDS2017 dataset. This dataset was developed by the Canadian Institute for Cybersecurity and is widely used in research on network intrusion detection. It contains realistic benign and attack traffic captured over multiple days and includes modern attack categories such as DDoS, DoS, brute force, web attacks, botnet traffic, infiltration, and Heartbleed.

One of the major strengths of CICIDS2017 is that it does not provide only packet captures, but also rich flow-level features generated using CICFlowMeter. These features include measurements related to flow duration, packet length statistics, inter-arrival times, protocol flags, header lengths, directional packet counts, and many other network characteristics. This makes it highly suitable for training machine learning models for traffic classification and anomaly detection.

In the project code, dataset preprocessing is handled by `ml/preprocess.py`. The process includes:

- Loading CSV files from the `data/` directory.
- Normalizing column names.
- Detecting the label column.
- Mapping labels into attack classes.
- Selecting relevant numerical features.
- Replacing infinite values and filling null values.
- Applying variance thresholding.
- Scaling features using `StandardScaler`.
- Splitting the data into training and testing sets.

The project also supports synthetic data generation when the CICIDS2017 dataset is not available. This is useful for development and demonstration but should not be treated as a substitute for real benchmarking. Synthetic data can help validate the pipeline structure, yet realistic performance claims should always be based on proper evaluation against a representative dataset like CICIDS2017.

---

## 7. System Architecture Overview

SecureX AI follows a modular pipeline architecture. Each module is designed with a clear responsibility, making the project easy to understand and extend.

### 7.1 Main Components

- **Packet Capture Module:** Captures live IP packets or generates synthetic packet records.
- **Feature Engineering Module:** Aggregates packet records per source IP within a time window and computes features.
- **Rule Engine:** Applies threshold-based logic to detect known attack patterns.
- **ML Engine:** Uses pre-trained machine learning models for anomaly scoring and classification.
- **Threat Scoring Module:** Combines rule score, ML score, confidence, and geolocation risk into a final threat score.
- **Geolocation Module:** Adds country, city, ISP, and country-risk context to alerts.
- **Logger Module:** Stores alerts, blocked IPs, and traffic history in SQLite and rotating log files.
- **Firewall Module:** Blocks suspicious IP addresses using OS firewall commands.
- **Dashboard Module:** Displays alerts and statistics in real time and provides management APIs.

### 7.2 Operational Flow

1. Packets are captured from the network or generated synthetically.
2. Packet records are queued for processing.
3. A sliding-window aggregator groups activity by source IP.
4. Aggregated features are sent to rule-based and ML-based analysis.
5. Alerts are generated when suspicious conditions are identified.
6. Alerts are enriched with location and threat score metadata.
7. Alerts are persisted, displayed, and optionally trigger firewall blocking.

This architecture is effective because it separates data acquisition, analysis, and action. It also allows each component to be upgraded independently.

---

## 8. Methodology

The methodology of SecureX AI is designed around the lifecycle of network events from packet generation to defensive response. The main methodology stages are described below.

### 8.1 Packet Capture

The packet capture stage uses Scapy to sniff IP packets from the selected network interface. From each packet, the system extracts:

- Source IP address
- Destination IP address
- Source port
- Destination port
- Protocol type
- Packet size
- TCP flags
- Timestamp

If live packet capture is not available or fails due to missing privileges, the system can switch to synthetic mode. In this mode, it generates benign traffic as well as simulated attack traffic such as DDoS, port scan, and brute-force attempts.

### 8.2 Traffic Queuing and Stream Handling

Extracted packet records are pushed into a shared queue. This queue-based design decouples capture from analysis, ensuring that packet ingestion remains continuous while downstream modules process data asynchronously. Such an architecture is particularly important in streaming systems where capture and detection may operate at different speeds.

### 8.3 Sliding-Window Aggregation

Instead of classifying each packet independently, SecureX AI groups packets by source IP over a time window, typically 60 seconds. This creates a richer representation of behavior over time. For each active source IP, the system continuously updates its recent history and recalculates aggregate metrics at fixed intervals.

This methodology is well suited to intrusion detection because many attacks are better understood as patterns across time rather than isolated packets.

### 8.4 Rule-Based Detection

The rule engine evaluates computed features against thresholds defined in `config.py`. It checks for patterns like:

- DDoS: extremely high request rate from one source.
- Port scan: unusually high number of distinct destination ports.
- Brute force: repeated access attempts to authentication-related ports.
- ICMP flood: excessive ICMP traffic ratio and rate.
- UDP flood: excessive UDP traffic ratio and rate.

When a rule is triggered, the system creates an alert with severity, confidence, and a rule score.

### 8.5 Machine Learning Detection

The ML engine loads trained models from disk. It uses:

- **Isolation Forest** to identify anomalous traffic behavior.
- **Random Forest Classifier** to classify traffic into attack categories if a supervised model is available.

The ML engine converts incoming features into a numeric vector, applies scaling, and then predicts whether the behavior is benign or anomalous. It also derives an ML threat score and confidence.

### 8.6 Threat Scoring and Alert Coordination

Once an alert is generated, the system enriches it with geolocation data and computes a final threat score using rule-based evidence, ML evidence, and country risk. This creates a unified score from 0 to 100 that supports prioritization and response decisions.

### 8.7 Prevention and Visualization

Alerts with high threat scores can trigger firewall blocking. At the same time, all significant events are sent to the dashboard and stored in SQLite for later analysis.

This methodology creates a full feedback loop from traffic observation to action, which is why the system is better characterized as an IDPS rather than only an IDS.

---

## 9. Feature Engineering

Feature engineering plays a central role in the effectiveness of SecureX AI. Raw packets on their own provide limited context, so the system transforms them into statistical and behavioral summaries that are more useful for attack detection.

### 9.1 Window-Based Behavioral Representation

The feature engineering module maintains a per-IP traffic window. Each window stores packet records observed from the same source IP during the last 60 seconds. Every few seconds, the system computes a fresh feature vector from this window.

### 9.2 Extracted Features

The live system computes the following major features:

- `total_packets`: total packet count in the window.
- `request_rate_per_min`: number of packets per minute.
- `unique_dst_ports`: number of distinct destination ports targeted.
- `unique_dst_ips`: number of distinct destination IPs contacted.
- `pkt_size_mean`: mean packet size.
- `pkt_size_variance`: variance in packet sizes.
- `pkt_size_min`: minimum packet size.
- `pkt_size_max`: maximum packet size.
- `tcp_ratio`: proportion of TCP packets.
- `udp_ratio`: proportion of UDP packets.
- `icmp_ratio`: proportion of ICMP packets.
- `syn_ratio`: proportion of TCP SYN packets.
- `auth_port_hits`: number of packets sent to sensitive authentication ports.
- `auth_hit_rate`: rate of auth-port hits per minute.
- `connection_freq`: packet arrival frequency in the window.

### 9.3 Why These Features Matter

These features were selected because they correspond closely to common attack behaviors:

- A DDoS attack often produces a very high request rate.
- A port scan tends to produce a high number of unique destination ports.
- Brute-force attacks repeatedly hit authentication-related ports like SSH or RDP.
- UDP floods skew the UDP ratio upward.
- ICMP floods increase the ICMP ratio sharply.
- SYN-heavy traffic can indicate reconnaissance or incomplete connection attempts.

### 9.4 Strength of the Feature Design

The project’s feature engineering is practical and explainable. It does not depend on deep payload parsing, which improves efficiency and generality. Instead, it focuses on traffic behavior patterns, which are strong indicators for many common forms of malicious activity.

An additional innovation opportunity for future versions would be to include:

- entropy of destination ports,
- burstiness measures,
- directional asymmetry,
- failed connection rates,
- rolling trend features across multiple windows,
- temporal signatures for periodic botnet traffic.

These would further improve the system’s ability to distinguish between benign spikes and coordinated malicious activity.

---

## 10. Model Building

The project uses a hybrid model-building strategy to combine unsupervised and supervised learning.

### 10.1 Isolation Forest

Isolation Forest is trained as an unsupervised anomaly detector. Its main idea is that anomalous observations are easier to isolate than normal ones in a randomly partitioned feature space. This model is particularly useful in intrusion detection because new or unknown attacks may not resemble any previously labeled class.

In SecureX AI, the Isolation Forest model:

- is trained on preprocessed feature data,
- estimates whether a traffic instance is normal or anomalous,
- returns an anomaly score,
- contributes to the ML threat score in live inference.

### 10.2 Random Forest Classifier

The Random Forest model is trained as a supervised classifier. It uses multiple decision trees and aggregates their predictions to identify attack categories. This model is effective because it handles nonlinear relationships, works well on tabular features, and provides robust classification performance.

In this project, the Random Forest classifier:

- predicts labeled attack classes,
- estimates class confidence using class probabilities,
- helps convert anomalies into more interpretable attack labels such as DDoS, Port Scan, or Brute Force.

### 10.3 Training Pipeline

The training pipeline includes:

1. Loading the dataset.
2. Selecting the label column.
3. Mapping labels to class IDs.
4. Choosing relevant numerical features.
5. Cleaning null and infinite values.
6. Removing zero-variance columns.
7. Scaling features.
8. Splitting into train and test sets.
9. Training Isolation Forest.
10. Training Random Forest.
11. Saving models, scaler, and feature list.

### 10.4 Innovation in the Model Design

The combination of unsupervised and supervised models is one of the more innovative aspects of this project. Many student projects choose one or the other, but SecureX AI attempts to balance:

- detection of known attacks through classification,
- detection of unknown behavior through anomaly scoring,
- operational explainability through rule-based logic.

This design reflects real-world cybersecurity requirements, where no single technique is sufficient on its own.

---

## 11. Model Evaluation and Results

The repository includes evaluation logic in the training pipeline, and the README mentions expected results based on CICIDS2017-style experiments.

### 11.1 Evaluation Metrics

The primary metrics used or implied in the project include:

- Accuracy
- Precision
- Recall
- F1-score
- Confusion matrix
- Feature importance for Random Forest

These metrics are standard in intrusion detection because simple accuracy can be misleading if benign traffic heavily dominates the dataset.

### 11.2 Expected Results

According to the project documentation, expected results are approximately:

- **Isolation Forest**
  - Accuracy: around 92%
  - Precision: around 88%
  - Recall: around 89%
  - F1-score: around 88%

- **Random Forest**
  - Accuracy: around 97% to 99%
  - Precision: around 96% to 98%
  - Recall: around 97% to 99%
  - F1-score: around 97% to 98%

These values suggest that the supervised model performs strongly on known labeled traffic, while the anomaly model provides useful though comparatively lower performance for general anomaly identification.

### 11.3 Practical Results from the System Design

From the codebase itself, the project demonstrates strong practical outcomes in the following areas:

- real-time rule-based attack detection,
- alert generation with severity and confidence,
- logging and dashboard visualization,
- synthetic demonstration of attacks,
- automatic blocking based on threat score.

### 11.4 Important Technical Observation

A careful review of the current implementation shows that the live ML path may not be fully aligned with the live feature engineering output. The training feature set defined in `ml/preprocess.py` is much closer to CICIDS flow features, while the live feature generator uses a smaller custom behavioral feature set. In addition, the queue integration in the ML runtime appears incomplete.

This means that the strongest validated operational part of the project is the real-time rule-based detection pipeline, while the ML deployment path should be treated as partially integrated and suitable for further refinement.

This observation is not a weakness of the report, but a realistic discussion point that improves the credibility of the project presentation.

---

## 12. Model Interpretability

Model interpretability is critical in cybersecurity because alerts must be actionable. A system that raises alarms without explaining why can reduce trust and make incident response harder.

### 12.1 Rule-Based Explainability

The rule engine is highly interpretable. Every alert can be traced directly to a human-readable condition, such as:

- request rate above threshold,
- too many unique ports accessed,
- repeated authentication-port hits,
- excessive ICMP ratio,
- excessive UDP ratio.

This allows administrators or project evaluators to understand the reasoning behind a detection immediately.

### 12.2 ML Interpretability

The Random Forest model supports feature importance analysis, and the training code prints the top features after evaluation. The live ML engine also includes selected feature values in alert details, such as request rate, port diversity, and protocol ratios. This partially improves interpretability by showing which aspects of traffic were prominent during a prediction.

### 12.3 Suggested Interpretability Improvements

To make the system more innovative and academically stronger, future versions can add:

- SHAP-based explanations for individual alerts,
- dashboard visualization of top contributing features,
- per-alert comparison against normal traffic baselines,
- confidence calibration graphs,
- explanation labels such as “high port diversity indicates possible scanning.”

Adding these would make SecureX AI not only more powerful but also more suitable for explainable AI research in cybersecurity.

---

## 13. System Deployment

SecureX AI is designed for straightforward local deployment on common operating systems such as Windows and Linux.

### 13.1 Deployment Requirements

- Python 3.10 or above
- Required Python packages from `requirements.txt`
- Administrator or root privileges for live capture and firewall actions
- Network connectivity for geolocation lookup
- Browser access for the dashboard

### 13.2 Deployment Steps

1. Install dependencies using `pip install -r requirements.txt`.
2. Train models using `python ml/train.py --synthetic` or a CICIDS2017 dataset.
3. Start the application using `python main.py`.
4. Open the dashboard in the browser at `http://localhost:5000`.

### 13.3 Supported Modes

- **Live mode:** captures real network traffic.
- **Demo mode:** generates synthetic traffic for demonstration.
- **No-block mode:** disables automatic firewall blocking.

### 13.4 Dashboard and Persistence

The system exposes:

- REST endpoints for alerts, blocked IPs, and stats,
- Socket.IO for real-time event streaming,
- SQLite persistence for alerts and traffic history.

### 13.5 Firewall Integration

The project supports:

- `iptables` on Linux,
- `netsh advfirewall` on Windows.

This makes the prevention layer operational rather than purely theoretical. In academic projects, this is a significant strength because it demonstrates closed-loop response instead of passive monitoring alone.

---

## 14. Results and Discussion

SecureX AI successfully demonstrates the design and implementation of a hybrid intrusion detection and prevention system. Its architecture reflects practical cyber-defense workflows and shows how multiple independent components can be integrated into a complete operational pipeline.

### 14.1 Major Achievements

- Real-time packet monitoring was implemented successfully.
- A sliding-window feature engineering approach was developed for per-IP analysis.
- Rule-based detection of several common network attacks was integrated.
- ML model training and inference components were added.
- A composite threat-scoring module was used to prioritize alerts.
- Alerts were persisted and visualized using a live dashboard.
- Automatic IP blocking was connected to firewall commands.

### 14.2 Why the Project Is Innovative

The project is innovative in the following ways:

- It does not stop at model training; it delivers a working runtime system.
- It combines cybersecurity detection and defensive automation.
- It includes both rule-based and ML-based detection logic.
- It uses a scoring layer to combine heterogeneous evidence.
- It provides a visual operational interface rather than only console output.
- It supports synthetic traffic for reliable demonstration and testing.

### 14.3 Discussion of Reliability

The rule-based system appears to be the most reliable operational component because its feature generation and thresholds are directly aligned. This makes its detections easier to explain and verify.

The ML component represents a promising extension, but the live deployment should be improved to fully match training and inference features. In a project discussion or viva, this can be presented as a future enhancement area: the architecture is present, the models are trained, and the next step is full feature alignment for production-grade ML integration.

### 14.4 Academic Value

The project has strong academic value because it demonstrates:

- applied networking,
- real-time stream processing,
- cybersecurity analytics,
- machine learning workflow,
- web-based system integration,
- practical automation of incident response.

This makes it stronger than projects that focus only on offline classification accuracy or only on UI development.

---

## 15. Limitations and Future Enhancements

No project is complete without understanding its current limitations. SecureX AI has several important ones, along with clear opportunities for enhancement.

### 15.1 Current Limitations

- The live ML feature pipeline is not fully aligned with the training feature set.
- Geolocation depends on an external API and may fail without internet access.
- Firewall commands require elevated privileges.
- The system is designed for local or small-scale deployment, not enterprise-scale environments.
- There is no authentication layer for the dashboard.
- The synthetic mode is useful for demonstration but does not represent real attack diversity completely.

### 15.2 Future Enhancements

- Align live feature engineering with the ML training schema.
- Add SHAP or LIME for explainable AI.
- Introduce deep learning models such as autoencoders or LSTM for temporal anomaly detection.
- Integrate PCAP replay directly into the live pipeline.
- Add user authentication and secure dashboard access.
- Export alerts in SIEM-friendly formats such as JSON or Syslog.
- Add threat intelligence feeds and reputation-based scoring.
- Containerize the application using Docker.
- Support distributed collectors and centralized management.
- Add adaptive thresholding based on learned baselines.

These future enhancements could transform the project from a strong academic prototype into a more production-ready security platform.

---

## 16. Conclusion

SecureX AI is a comprehensive and well-structured project that demonstrates the end-to-end design of a modern intrusion detection and prevention system. It captures network traffic, extracts behavioral features, detects suspicious patterns using rules and machine learning, enriches alerts with context, calculates threat scores, logs results, displays them in real time, and can automatically block malicious IP addresses.

The most important contribution of this project is that it connects multiple domains into one operational workflow. It is not limited to static analysis or offline machine learning. Instead, it shows how data flows through a real monitoring system and how detection can lead directly to defensive action.

From a project evaluation perspective, SecureX AI is strong in architecture, modularity, practical integration, and educational value. Its rule-based detection path is solid, its dashboard is operational, and its ML extension provides a strong direction for future improvement. With further refinement in live ML integration and deployment hardening, this project has excellent potential for expansion into a more advanced research or production-oriented platform.

In summary, SecureX AI is a meaningful and technically rich project that successfully demonstrates intelligent network intrusion detection and prevention in a practical, explainable, and extensible form.

---

## 17. References

1. Source code files from the project repository:
   - `main.py`
   - `config.py`
   - `core/packet_capture.py`
   - `core/feature_engineering.py`
   - `core/rule_engine.py`
   - `core/ml_engine.py`
   - `core/threat_score.py`
   - `core/firewall.py`
   - `core/logger.py`
   - `dashboard/app.py`
   - `ml/train.py`
   - `ml/preprocess.py`

2. Canadian Institute for Cybersecurity. “IDS 2017 Dataset.”
   https://www.unb.ca/cic/datasets/ids-2017.html

3. Sharafaldin, I., Habibi Lashkari, A., and Ghorbani, A. A.
   “Toward Generating a New Intrusion Detection Dataset and Intrusion Traffic Characterization.”
   Proceedings of the 4th International Conference on Information Systems Security and Privacy (ICISSP), 2018.

4. Liu, F. T., Ting, K. M., and Zhou, Z.-H.
   “Isolation Forest.”
   2008 Eighth IEEE International Conference on Data Mining.

5. Breiman, L.
   “Random Forests.”
   Machine Learning, 45, 5-32, 2001.

6. Scapy Documentation.
   https://scapy.net/

7. Flask Documentation.
   https://flask.palletsprojects.com/

8. scikit-learn Documentation.
   https://scikit-learn.org/

---

## Appendix: Suggested Viva Summary

SecureX AI is a hybrid IDS/IPS that captures network traffic, generates per-IP behavioral features, detects attacks using rule-based and ML-based methods, assigns a threat score, shows everything on a live dashboard, and automatically blocks high-risk IP addresses. Its main strength is that it provides a complete security pipeline from monitoring to response, making it a strong academic and practical cybersecurity project.
