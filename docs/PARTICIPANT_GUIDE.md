# WazuhBOTS -- Participant Guide

Welcome to WazuhBOTS, a "Boss of the SOC" competition powered by Wazuh SIEM. Your mission is to investigate real security incidents by analyzing alerts, correlating events, and uncovering the full attack story. This guide explains how to access the platform, use the investigation tools, and submit your answers.

---

## Table of Contents

- [Overview](#overview)
- [Accessing the Platform](#accessing-the-platform)
- [The CTFd Interface](#the-ctfd-interface)
- [Investigating with Wazuh Dashboard](#investigating-with-wazuh-dashboard)
- [How Flags Work](#how-flags-work)
- [Hints and Scoring](#hints-and-scoring)
- [Tips by Difficulty Level](#tips-by-difficulty-level)
- [Common Wazuh Query Patterns](#common-wazuh-query-patterns)
- [Frequently Asked Questions](#frequently-asked-questions)

---

## Overview

WazuhBOTS presents you with security incident scenarios. Each scenario involves an attacker who has compromised one or more systems in the WazuhBOTS network. The attacks have already been executed, and all resulting logs, alerts, and events are stored in the Wazuh platform.

Your job is to act as a SOC analyst. You will:

1. Read the scenario briefing to understand the context.
2. Use the Wazuh Dashboard to search, filter, and correlate security events.
3. Answer questions about the attack at increasing levels of difficulty.
4. Submit your answers as flags in the CTFd scoreboard.

You are not performing live attacks or defending in real time. Everything has already happened. You are the investigator reconstructing the story from the evidence.

---

## Accessing the Platform

Your facilitator will provide you with the following access information:

| Service           | URL                          | Purpose                          |
|-------------------|------------------------------|----------------------------------|
| CTFd Scoreboard   | `http://<server>:8000`       | View challenges, submit flags    |
| Wazuh Dashboard   | `https://<server>:5601`      | Investigate alerts and events    |

### CTFd Account

1. Navigate to the CTFd URL.
2. Click "Register" to create a participant account (or join a team if teams are enabled).
3. Use the username and email your facilitator assigns, or choose your own in open registration mode.

### Wazuh Dashboard Account

All participants share a read-only analyst account:

- **Username:** `analyst` (or as provided by your facilitator)
- **Password:** (provided by your facilitator)

This account allows you to search and visualize alerts. You cannot modify configurations, rules, or data.

**Important:** The Wazuh Dashboard uses a self-signed TLS certificate. Your browser will display a security warning when you first access it. This is expected. Accept the certificate to proceed.

---

## The CTFd Interface

### Challenges Page

The Challenges page lists all questions organized by scenario. Each challenge shows:

- **Name** -- Includes the difficulty level in brackets (e.g., `[Pup]`, `[Hunter]`, `[Alpha]`, `[Fenrir]`)
- **Category** -- The scenario the challenge belongs to
- **Point Value** -- How many points you earn for a correct answer
- **Description** -- The question and context to guide your investigation
- **Tags** -- Keywords indicating the type of investigation required

### Submitting an Answer

1. Click on a challenge to open it.
2. Read the full description carefully.
3. Investigate using the Wazuh Dashboard.
4. Type your answer in the flag submission field.
5. Click "Submit".

If correct, the points are immediately added to your score. If incorrect, you can try again (there is no penalty for wrong answers unless the facilitator has configured one).

### Scoreboard

The Scoreboard page shows all teams or individuals ranked by total points. During a timed competition, the scoreboard updates in real time. Some competitions may freeze the scoreboard in the final minutes to add suspense.

---

## Investigating with Wazuh Dashboard

The Wazuh Dashboard is your primary investigation tool. It provides a web interface on top of the Wazuh Indexer (based on OpenSearch), allowing you to search through millions of security events.

### Navigation Overview

When you log in to the Wazuh Dashboard, the key areas are:

- **Modules > Security Events** -- The primary investigation view. Shows all Wazuh alerts with filtering, searching, and visualization.
- **Modules > Integrity Monitoring** -- File Integrity Monitoring (FIM) events: file changes, additions, and deletions.
- **Modules > MITRE ATT&CK** -- A heatmap view showing which MITRE techniques were detected.
- **Modules > Vulnerabilities** -- Vulnerability scan results for monitored agents.
- **Discover** -- Raw event search across all indices (advanced users).

### Setting the Time Range

Almost every investigation starts by setting the correct time range for the scenario you are investigating. Each scenario description includes the attack timeframe.

1. In the top-right corner of the Dashboard, click the time picker.
2. Select "Absolute" and enter the start and end dates/times from the scenario briefing.
3. Make sure the timezone is set to UTC.

**If you see zero results, the most common cause is the wrong time range.**

### Filtering Events

Use the filter bar at the top of the Security Events module to narrow down results:

- Click "Add filter" or type directly in the search bar.
- Use KQL (Kibana Query Language) syntax:

```
agent.name: web-srv AND rule.level >= 10
```

Common filter fields:

| Field                    | Description                              | Example                              |
|--------------------------|------------------------------------------|--------------------------------------|
| `agent.name`             | The hostname of the Wazuh agent          | `agent.name: web-srv`                |
| `agent.id`               | The numeric agent ID                     | `agent.id: 001`                      |
| `rule.id`                | The Wazuh rule that fired                | `rule.id: 31103`                     |
| `rule.level`             | Alert severity (0--15)                   | `rule.level >= 10`                   |
| `rule.description`       | Text description of the rule             | `rule.description: *SQL injection*`  |
| `rule.mitre.id`          | MITRE ATT&CK technique ID               | `rule.mitre.id: T1190`              |
| `rule.groups`            | Rule group (e.g., web, syscheck, syslog) | `rule.groups: web`                   |
| `data.srcip`             | Source IP address in the event           | `data.srcip: 203.0.113.47`          |
| `data.dstip`             | Destination IP address                   | `data.dstip: 172.25.0.30`           |
| `syscheck.path`          | File path for FIM events                 | `syscheck.path: /var/www/*`         |
| `data.win.eventdata.*`   | Windows event data fields                | `data.win.eventdata.user: jmartin`   |

### Sorting Results

By default, results are sorted by newest first. For forensic investigation, you often want to sort by oldest first to reconstruct the timeline:

1. Click the "Time" column header to reverse the sort order.
2. Or use the "Sort" option in the Discover view.

### Expanding Event Details

Click on any alert row to expand its full details. This reveals all fields including:

- The full raw log (`full_log`)
- Decoded fields (`data.*`)
- Rule metadata (`rule.*`)
- Agent information (`agent.*`)
- MITRE ATT&CK mappings (`rule.mitre.*`)

Many answers to challenges are found in these expanded detail fields.

### Using Visualizations

The Dashboard includes pre-built visualizations:

- **Alert Timeline** -- Shows alert volume over time. Spikes indicate attack activity.
- **Top Rules** -- Shows which Wazuh rules fired most frequently.
- **Top Agents** -- Shows which hosts generated the most alerts.
- **MITRE ATT&CK Map** -- Highlights which techniques were detected.

You can also create temporary visualizations in Discover by using the "Visualize" button on any field to see value distributions.

---

## How Flags Work

Flags are the answers you submit to CTFd. Simply type the answer value directly — no special wrapper or format needed.

**Important rules for flag submission:**

- Submit the answer value directly (e.g., `247`, not `FLAG{247}`).
- Some flags are case-sensitive (especially filenames, commands, and tool names). The challenge description or a hint may indicate this.
- Some flags are case-insensitive (IP addresses, rule IDs, numbers).
- Do not add leading/trailing spaces.
- If the answer is a number, submit it as `247`, not as `247.0` or `two hundred forty seven`.

**Examples:**

| Question Type        | Answer                | What to Submit                        |
|----------------------|-----------------------|---------------------------------------|
| Alert count          | 247                   | `247`                                 |
| IP address           | 203.0.113.47          | `203.0.113.47`                        |
| Rule ID              | 31103                 | `31103`                               |
| Filename             | cmd.php               | `cmd.php`                             |
| MITRE technique      | T1053.003             | `T1053.003`                           |
| Tool name            | Nikto/2.1.6           | `Nikto/2.1.6`                         |
| Command              | id                    | `id`                                  |

---

## Hints and Scoring

### Point Values by Level

| Level    | Points per Question |
|----------|---------------------|
| Pup      | 100 pts             |
| Hunter   | 200 pts             |
| Alpha    | 300 pts             |
| Fenrir   | 500 pts             |

### Dynamic Scoring

In competition mode, challenge point values decrease as more teams solve them. The minimum value is 50% of the original. This rewards teams who solve challenges early.

### Hints

Each challenge has one to three hints that progressively reveal more information. Hints have a point cost:

- **Pup hints:** 25 points each
- **Hunter hints:** 50 points each
- **Alpha hints:** 75 points each
- **Fenrir hints:** 100 points each

Once you unlock a hint, it remains visible for the rest of the competition. Consider whether the hint is worth the cost before unlocking it.

In **Training Mode**, hints are free.

### First Blood and Time Bonuses

- **First Blood:** The first team to solve a challenge earns a 20% bonus on that challenge's points.
- **Time Bonus:** Solving a challenge within the first hour of the competition earns a 10% bonus.

---

## Tips by Difficulty Level

### Pup (Level 1) -- Getting Started

Pup challenges test your ability to navigate the Wazuh Dashboard and perform basic searches. No deep analysis is required.

**Tips:**
- Start by setting the correct time range for the scenario.
- Use simple filters: `agent.name`, `rule.level`, `data.srcip`.
- The answer is often visible in a dashboard visualization (e.g., the total hit count, the top IP in a chart).
- Read the challenge description carefully. It usually tells you exactly which field to look at.
- If you are new to Wazuh, start with the BOTS Overview dashboard to get oriented.

### Hunter (Level 2) -- Correlating Events

Hunter challenges require you to look beyond a single alert and connect events across time or across different rule groups.

**Tips:**
- Use the timeline to identify the sequence of events.
- Correlate source IPs across different rule groups (e.g., web attacks and FIM events from the same IP).
- Expand event details and examine the `data.*` fields carefully.
- Use the search bar with compound queries: `agent.name: web-srv AND rule.groups: syscheck AND syscheck.event: added`
- Think about the attack kill chain: what would the attacker do after the initial compromise?

### Alpha (Level 3) -- Threat Hunting

Alpha challenges require deep technical knowledge of Wazuh rules, MITRE ATT&CK framework, and forensic analysis.

**Tips:**
- Search for custom rules by ID range: `rule.id >= 87900`.
- Use the MITRE ATT&CK module to identify technique mappings.
- For rule-based questions, examine `rule.mitre.id`, `rule.mitre.tactic`, and `rule.mitre.technique`.
- You may need to correlate events across multiple agents (if the attack spans hosts).
- For command-based questions, look at `data.audit.execve.a*` fields (Linux auditd) or `data.win.eventdata.commandLine` (Windows).
- Understand the difference between scheduled syscheck scans and real-time/whodata monitoring.

### Fenrir (Level 4) -- Expert Challenges

Fenrir challenges demand expert-level forensic reconstruction, evasion detection, and detection engineering skills.

**Tips:**
- These challenges often require understanding what the attacker tried to hide, not just what they did.
- Compare timestamps across different data sources (FIM ctime vs. mtime, log timestamps vs. event timestamps).
- For IOC reconstruction, query all fields across all agents: IPs, domains, hashes, file paths, ports.
- For detection engineering questions, examine the existing custom rules in the alerts and think about what additional conditions would improve them.
- Consider anti-forensic techniques: log deletion, timestamp manipulation, process injection.
- Take your time. Fenrir challenges are meant to be hard. Use scratch paper to build your timeline.

---

## Common Wazuh Query Patterns

Here are query patterns that are useful across multiple challenges:

### Find all alerts for a specific agent
```
agent.name: web-srv
```

### Find high-severity alerts
```
rule.level >= 10
```

### Find alerts from a specific source IP
```
data.srcip: 203.0.113.47
```

### Find SQL injection alerts
```
rule.description: *SQL injection* AND agent.name: web-srv
```

### Find FIM (file integrity) events
```
rule.groups: syscheck AND agent.name: web-srv
```

### Find new files added to the system
```
syscheck.event: added
```

### Find events with a specific MITRE technique
```
rule.mitre.id: T1190
```

### Find SSH brute force alerts
```
rule.id: 5712 AND agent.name: lnx-srv
```

### Find custom WazuhBOTS rules
```
rule.id >= 87900
```

### Find alerts within a specific time window
Set the time picker to the desired range, then add additional filters. For example, to find all high-severity alerts on March 1st:
- Set time range: 2026-03-01T00:00:00Z to 2026-03-01T23:59:59Z
- Filter: `rule.level >= 10`

### Combine multiple conditions
```
agent.name: web-srv AND rule.level >= 7 AND data.srcip: 198.51.100.23
```

---

## Frequently Asked Questions

**Q: I get zero results when I search. What is wrong?**
A: The most common cause is an incorrect time range. Make sure your time picker matches the scenario timeframe (check the challenge description). Also verify you are using the correct agent name and field names.

**Q: How do I know which agent to look at?**
A: Each scenario description specifies the victim host. Scenario 1 (Dark Harvest) uses `web-srv`, Scenario 2 (Iron Gate) uses `dc-srv`, Scenario 3 (Ghost in the Shell) uses `lnx-srv`, and Scenario 4 (Supply Chain Phantom) uses all hosts.

**Q: My flag is correct but CTFd says it is wrong. What do I do?**
A: Submit just the answer value with no extra spaces. If the challenge is case-sensitive, verify the capitalization matches exactly. If you are still stuck, ask your facilitator.

**Q: Can I use the Discover (raw OpenSearch) view instead of the Wazuh modules?**
A: Yes. Discover gives you direct access to all indices and is sometimes more flexible for advanced queries. Use the index pattern `wazuhbots-*` or `wazuh-alerts-*` depending on how data was ingested.

**Q: Is there a way to export my search results?**
A: Yes. In the Discover view, click "Share" or "Export" to download results as CSV. This can be useful for building timelines in a spreadsheet.

**Q: Can my team divide the work?**
A: Absolutely. A common strategy is to have team members work on different difficulty levels or different scenarios simultaneously. The read-only Dashboard account can be used by multiple people at the same time.

**Q: Are there penalties for wrong answers?**
A: In the default configuration, there are no penalties for incorrect submissions. You can try as many times as needed. However, some competitions may enable rate limiting.

---

Good luck, analyst. The SOC is counting on you.
