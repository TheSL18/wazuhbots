# WazuhBOTS -- Facilitator Guide

This guide is for competition organizers, trainers, and instructors who are running a WazuhBOTS event. It covers setting up the platform for different event types, managing participants, configuring scoring, and resetting the environment between rounds.

---

## Table of Contents

- [Before the Event](#before-the-event)
- [Configuring Competition Modes](#configuring-competition-modes)
- [Setting Up a Competition](#setting-up-a-competition)
- [Managing Teams and Participants](#managing-teams-and-participants)
- [Configuring Scoring](#configuring-scoring)
- [Selecting Scenarios](#selecting-scenarios)
- [During the Competition](#during-the-competition)
- [Resetting Between Rounds](#resetting-between-rounds)
- [Post-Event Tasks](#post-event-tasks)
- [Tips for a Successful Event](#tips-for-a-successful-event)
- [Troubleshooting During Events](#troubleshooting-during-events)

---

## Before the Event

### Timeline Checklist

| When               | Task                                                              |
|--------------------|-------------------------------------------------------------------|
| 2 weeks before     | Provision server or cloud instance                               |
| 1 week before      | Deploy WazuhBOTS and run a full test round                       |
| 3 days before      | Share connection details with participants (VPN, URLs, etc.)     |
| 1 day before       | Run `health_check.sh` and verify all services are operational    |
| 1 hour before      | Run `reset_environment.sh` to clear any test data                |
| Event start        | Confirm all teams can access CTFd and Wazuh Dashboard            |
| Event end          | Export scoreboard results and generate certificates              |

### Test Everything

Before the event, complete a full dry run:

1. Deploy the stack: `./scripts/setup.sh`
2. Verify health: `./scripts/health_check.sh`
3. Create a test participant account in CTFd.
4. Log into Wazuh Dashboard with the participant credentials.
5. Solve at least one challenge from each difficulty level to verify flags are correct.
6. Test the reset script: `./scripts/reset_environment.sh`
7. Verify the platform is clean and ready after reset.

### Network Planning

Ensure all participants can reach the server:

- **On-site events:** Participants connect to the same local network as the server. Distribute the server's local IP address.
- **Remote events:** Use a cloud deployment with a public IP or domain. Ensure ports 443 (HTTPS) and 8000 (CTFd) are accessible from the internet. Restrict port 55000 (Wazuh API) to administrators.
- **VPN-based events:** If using a VPN, distribute VPN configuration files in advance and test connectivity before the event.

---

## Configuring Competition Modes

WazuhBOTS supports four modes, set via the `COMPETITION_MODE` variable in `.env`:

### Training Mode

```
COMPETITION_MODE=training
```

Best for: SOC analyst onboarding, internal workshops, classroom labs.

Characteristics:
- No time limit
- Hints are free (zero point cost)
- Scoreboard is visible but rankings are de-emphasized
- Facilitator can walk participants through challenges
- Walkthroughs can be distributed after each section

### Competition Mode

```
COMPETITION_MODE=competition
```

Best for: CTF events, meetups, community competitions.

Characteristics:
- Time-limited (controlled by `COMPETITION_DURATION_HOURS`, default: 4)
- Hints cost points
- Live scoreboard with rankings
- Dynamic scoring (point values decrease with more solves)
- First Blood and time bonuses active

### Self-Guided Mode

```
COMPETITION_MODE=self-guided
```

Best for: Online courses, self-paced learning, published lab exercises.

Characteristics:
- No scoreboard competition
- Unlimited time
- Walkthroughs unlock after a configurable number of failed attempts
- Progressive unlocking (complete level N to unlock level N+1)
- Individual progress tracking

### Public CTF Mode

```
COMPETITION_MODE=public
```

Best for: Open online competitions, conference CTFs.

Characteristics:
- Open registration
- Extended duration (days or weeks)
- Rate limiting on flag submissions to prevent brute force
- Global rankings
- Anti-cheating measures (flag uniqueness, submission logging)

---

## Setting Up a Competition

### Step 1: Deploy the Platform

Follow the [Deployment Guide](DEPLOYMENT.md) to bring up the full stack. For competitions, use the `--no-ingest` and `--no-ctfd` flags if you want to control ingestion and challenge loading separately:

```bash
./scripts/setup.sh --no-ingest --no-ctfd
```

### Step 2: Configure Mode and Duration

Edit `.env`:

```bash
COMPETITION_MODE=competition
COMPETITION_DURATION_HOURS=4
COMPETITION_NAME="WazuhBOTS @ Your Event Name"
```

Restart CTFd to pick up changes:

```bash
docker compose restart ctfd
```

### Step 3: Configure CTFd

Access CTFd at `http://<server>:8000` and complete the initial setup:

1. **Create an admin account.** Use a strong password and save it securely.
2. **Set the competition name** to match your event.
3. **Configure visibility settings:**
   - In Admin Panel > Config > Visibility, set:
     - Account Visibility: Public (for open registration) or Private (admin creates accounts)
     - Score Visibility: Public or Admins Only (if you want to reveal at the end)
     - Challenge Visibility: Private until competition start
4. **Set start and end times** (optional but recommended for competitions):
   - Admin Panel > Config > Time: set competition start and end times.

### Step 4: Load Scenarios and Datasets

```bash
# Ingest datasets into Wazuh Indexer
source .env
python3 scripts/ingest_datasets.py --all

# Load challenges into CTFd
python3 scripts/generate_flags.py
```

To load only specific scenarios:

```bash
python3 scripts/ingest_datasets.py --scenario scenario1_dark_harvest
```

### Step 5: Configure Participant Access to Wazuh Dashboard

The default participant account is:
- Username: `analyst`
- Password: `WazuhBOTS2026!` (or whatever is set in `.env` as `PARTICIPANT_PASSWORD`)

This is a read-only account. Verify it works by logging into the Dashboard and confirming you can see Security Events but cannot modify configurations.

### Step 6: Test Access

Have a co-facilitator or volunteer:
1. Register on CTFd.
2. Log into Wazuh Dashboard with participant credentials.
3. Attempt to solve one challenge to verify the full workflow.

---

## Managing Teams and Participants

### Team Mode vs Individual Mode

Configure team mode in CTFd Admin Panel > Config > Accounts:
- **Team Mode:** Participants register individually and join or create teams. Recommended for competitions with 2--4 person teams.
- **User Mode:** Each participant competes individually. Suitable for training and self-guided modes.

### Pre-Creating Accounts (Private Registration)

For controlled events where you want to pre-create accounts:

1. Set Account Visibility to "Private" in CTFd settings.
2. Use the CTFd Admin Panel > Users > Add User to create accounts manually.
3. Or use the CTFd API to bulk-create users programmatically.

### Distributing Credentials

Prepare a handout or slide with the following information for each team:

```
WazuhBOTS Competition Access
=============================
CTFd Platform:     http://<server>:8000
Wazuh Dashboard:   https://<server>:5601

CTFd Login:        (use your team's registered account)
Dashboard Login:   analyst / WazuhBOTS2026!

Scenario Timeframes:
  Scenario 1 (Dark Harvest):    2026-03-01 UTC
  Scenario 2 (Iron Gate):       2026-03-02 UTC
  Scenario 3 (Ghost Shell):     2026-03-02 UTC
  Scenario 4 (Supply Chain):    2026-03-03 UTC
```

---

## Configuring Scoring

### Default Scoring Configuration

| Setting       | Default Value | Description                                      |
|---------------|---------------|--------------------------------------------------|
| Scoring Type  | Dynamic       | Point values decrease as more teams solve         |
| Minimum Value | 50%           | Challenges never drop below half their base value |
| Hint Cost     | 25--100 pts   | Varies by difficulty level                        |
| First Blood   | +20%          | Bonus for the first team to solve                 |
| Time Bonus    | +10%          | Bonus for solves in the first hour                |

### Modifying Scoring in CTFd

To change scoring behavior:

1. Navigate to CTFd Admin Panel > Challenges.
2. Click on a challenge to edit its properties.
3. Modify point value, decay rate, minimum value, or flag.
4. Use "Challenge Type: Dynamic" for decaying points or "Standard" for fixed points.

### Disabling Hints for Harder Competitions

To remove all hints:

1. Navigate to Admin Panel > Challenges.
2. Edit each challenge and delete associated hints.

Or, to make hints free for training sessions, set all hint costs to 0.

### Freezing the Scoreboard

To freeze the scoreboard in the final minutes (hiding late solves to add suspense):

1. Navigate to Admin Panel > Config > Time.
2. Set "Freeze" to a time before the competition ends (e.g., 15 minutes before).

---

## Selecting Scenarios

You do not need to run all four scenarios. Choose based on your audience and time constraints:

| Audience                    | Recommended Scenarios       | Time Needed |
|-----------------------------|-----------------------------|-------------|
| Beginners / Students        | Scenario 1 only             | 1--2 hours  |
| SOC Analyst N1-N2           | Scenarios 1 and 3           | 2--3 hours  |
| Mixed skill levels          | Scenarios 1, 2, and 3       | 3--4 hours  |
| Advanced / Full competition | All four scenarios           | 4--6 hours  |

To load only specific scenarios, ingest only those datasets and load only those challenge files.

---

## During the Competition

### Facilitator Dashboard

During the event, keep these open in separate browser tabs:

1. **CTFd Admin Panel** -- Monitor submissions, check for issues, view scoreboard.
2. **Health Check** -- Run `./scripts/health_check.sh` periodically to verify all services are running.
3. **Docker Logs** -- Keep a terminal with `docker compose logs -f` to watch for errors.

### Monitoring Submissions

In the CTFd Admin Panel:
- **Submissions** page shows every flag attempt (correct and incorrect).
- Watch for teams that are stuck (many wrong attempts on the same challenge) and consider offering guidance.
- Watch for suspicious patterns (identical wrong attempts across teams may indicate collusion).

### Providing Guidance Without Giving Answers

During training and community events, participants may get stuck. Useful guidance techniques:

- "Have you set the right time range for this scenario?"
- "Try filtering by agent.name to narrow your results."
- "Expand the alert details and look at the data.* fields."
- "This question is about a specific Wazuh module. Which module monitors file changes?"
- "Remember to sort by timestamp to see the chronological order."

Avoid directly revealing answers. The learning happens in the investigation process.

### Common Issues During Events

| Issue                                    | Resolution                                                  |
|------------------------------------------|-------------------------------------------------------------|
| Participant cannot access Wazuh Dashboard | Verify credentials, check browser TLS warning acceptance    |
| Wazuh Dashboard is slow                   | Too many concurrent users; increase Indexer heap in .env    |
| CTFd shows wrong challenge count          | Verify challenge loading; re-run `generate_flags.py`       |
| Participant's flag is rejected             | Check for extra spaces, verify case sensitivity matches     |
| All services are unresponsive             | Run `health_check.sh`, check Docker logs, verify disk space|

---

## Resetting Between Rounds

To run multiple competition rounds (e.g., morning and afternoon sessions), use the reset script:

```bash
./scripts/reset_environment.sh
```

This script will:

1. Stop CTFd services.
2. Clear the CTFd database: scores, submissions, user accounts (preserves admin account).
3. Restart CTFd.
4. Regenerate challenge flags (if `generate_flags.py` is available).
5. Reload challenges into CTFd.

**What is preserved:**
- All Wazuh Indexer datasets (the alert data participants investigate)
- Wazuh Manager configuration and custom rules
- Dashboard saved objects and visualizations
- Docker images and non-CTFd volumes

**What is cleared:**
- All CTFd participant accounts (they must re-register)
- All scores and submissions
- All unlocked hints
- Challenge flags are regenerated with new values (if applicable)

### Reset Options

```bash
./scripts/reset_environment.sh             # Interactive (prompts for confirmation)
./scripts/reset_environment.sh --force     # Skip confirmation prompts
./scripts/reset_environment.sh --full      # Also rebuild all Docker containers
```

The `--full` flag is useful if you suspect container state issues. It stops, rebuilds, and restarts all containers from scratch while preserving volume data.

### After Reset

1. Run `health_check.sh` to verify all services are operational.
2. Complete the CTFd initial setup (create a new admin account).
3. Verify challenges are loaded.
4. Distribute new participant credentials.

---

## Post-Event Tasks

### Export Results

Export the final scoreboard from CTFd:

1. Navigate to Admin Panel > Scoreboard.
2. Use the CTFd API or the export feature to download results as CSV.

```bash
# Using CTFd API (replace TOKEN with your admin API token)
curl -H "Authorization: Token <TOKEN>" http://localhost:8000/api/v1/scoreboard -o scoreboard.json
```

### Generate Certificates

WazuhBOTS includes certificate templates in `branding/certificates/`. After the event:

1. Export the final standings.
2. Use the templates to generate participation or achievement certificates.
3. Distribute to participants.

### Collect Feedback

Gather participant feedback on:
- Which scenarios were most engaging
- Which difficulty levels were appropriate
- Technical issues encountered
- Suggestions for improvement

This feedback improves future events and contributes to the WazuhBOTS project.

### Clean Up

For cloud deployments, remember to:
- Stop or terminate the instance to avoid ongoing charges.
- Export any data you want to keep before destroying the instance.
- If preserving the deployment for future use, stop containers with `docker compose stop` (preserves data) rather than `docker compose down -v` (destroys data).

---

## Tips for a Successful Event

### Before the Event

1. **Test the full workflow** at least once. Register as a participant, solve challenges, verify flags.
2. **Prepare backup access.** Have SSH access to the server in case you need to restart services.
3. **Print or share the Participant Guide.** Ensure all participants have access to the query reference.
4. **Prepare a brief introduction.** Explain WazuhBOTS, the rules, and how to use Wazuh Dashboard before starting.

### During the Event

5. **Start with a walkthrough.** For mixed-skill audiences, solve a sample Pup-level challenge together as a group to demonstrate the workflow.
6. **Monitor the scoreboard.** If no team has solved any challenge after 20 minutes, offer general guidance about time ranges or agent names.
7. **Encourage teamwork.** Remind teams that different members can work on different scenarios or difficulty levels simultaneously.
8. **Keep time visible.** Display a countdown timer prominently.
9. **Have fun.** Play background music. Celebrate First Bloods. Create energy.

### After the Event

10. **Review results together.** Walk through one or two challenges, showing the investigation technique. This is the highest-value learning moment.
11. **Highlight creative approaches.** If a team found an unusual way to solve a challenge, share it with the group.
12. **Share resources.** Point participants to Wazuh documentation, MITRE ATT&CK resources, and how they can run WazuhBOTS on their own.

---

## Troubleshooting During Events

### Emergency: Complete Platform Failure

If all services go down during a competition:

```bash
# Check what is running
docker compose ps

# Restart everything
docker compose restart

# If restart does not help, check logs
docker compose logs --tail=50

# Nuclear option: full redeploy (preserves data volumes)
docker compose down
docker compose up -d
```

### Emergency: Wazuh Dashboard Unresponsive

The most common cause during events is memory pressure from too many concurrent searches:

```bash
# Check Indexer memory usage
docker stats wazuhbots-indexer

# Increase Indexer heap (edit .env, then restart)
# INDEXER_HEAP=4g
docker compose restart wazuh-indexer wazuh-dashboard
```

### Emergency: CTFd Down

```bash
# Restart CTFd and its dependencies
docker compose restart ctfd ctfd-db ctfd-redis

# If CTFd database is corrupted, last resort:
# This clears all CTFd data and requires re-setup
docker compose stop ctfd
docker volume rm wazuhbots_ctfd_db_data
docker compose up -d ctfd-db ctfd-redis ctfd
```

**Warning:** Removing the CTFd database volume during a live competition deletes all scores and submissions. Use only as an absolute last resort.
