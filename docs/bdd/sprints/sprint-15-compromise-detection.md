# Sprint 15 — Compromise Detection & Auto-Suspension

> **Goal**: The system detects signs of client secret compromise (IP anomalies, concurrent sessions, geographic impossibility) and automatically suspends affected clients without administrator intervention.
> **Bounded Context**: Security Monitoring (advanced detection), Client Registration (suspension state)
> **Scenarios**: 27 | Happy: 8 | Edge: 10 | Error: 9
> **Prerequisites**: Sprint 5 (Monitoring — anomaly detection baseline), Sprint 6 (Lifecycle — client status management), Sprint 4 (Access Control — token issuance)
> **Key deliverables**: IP-bound tokens, concurrent session detection, geographic impossibility detection, auto-suspension mechanism, suspended client behavior

### Design Decisions

**1. New client status: `suspended`**
- Sits between `active` and `revoked` in the client lifecycle.
- `suspended` = auto-suspended due to detected anomaly, recoverable via Sprint 16 recovery mechanisms.
- `revoked` = permanent, requires new enrollment with new identifier (unchanged from Sprint 6).
- A suspended client is indistinguishable from a revoked or unknown client in all external responses.

**2. IP binding is per-token, not per-session**
- Each access token is bound to the source IP at issuance time.
- Token validation checks the presenting IP against the bound IP.
- Rejection response is indistinguishable from an expired or invalid token (no information leakage).

**3. Concurrent session detection uses configurable time window**
- Default: two authentications from different IPs within 60 seconds = suspension.
- The threshold and time window are operator-configurable.
- Same-IP authentications within the window are always considered normal.

**4. Geographic impossibility uses maximum travel speed**
- Default speed threshold: 900 km/h (just above commercial aviation).
- Distance is computed as great-circle (Haversine) between GeoIP-resolved locations.
- GeoIP lookup failure is non-blocking: authentication proceeds, detection is skipped.

**5. Auto-suspension is non-reversible by the anomaly detector**
- Once a client is suspended, only Sprint 16 recovery mechanisms can reactivate it.
- The anomaly detector publishes the `ClientSuspended` event but cannot undo it.
- Suspension reason is recorded in the audit log but never disclosed to the client.

---

## Feature: IP Binding

```gherkin
Feature: IP Binding
  As the authentication system
  I want to bind access tokens to the source IP address at issuance time
  So that a stolen token cannot be used from a different network

  Background:
    Given the authentication service is operational
    And Alice is registered with client identifier "alice-payment-service" and status "active"
    And IP binding is enabled in the operator configuration

  # --- Happy Path ---

  Scenario: Token issued with source IP binding
    Given Alice has completed a successful proof verification from IP "203.0.113.10"
    When the access token is issued
    Then the token is bound to source IP "203.0.113.10"
    And the IP binding is recorded in the token metadata
    And the binding is recorded in the audit log

  Scenario: Token accepted from same IP
    Given Alice holds a valid access token bound to IP "203.0.113.10"
    When Alice presents the token from IP "203.0.113.10"
    Then the token is accepted
    And the API call proceeds normally

  # --- Edge Cases ---

  Scenario: Token issued without IP binding when disabled
    Given IP binding is disabled in the operator configuration
    When Alice completes a successful proof verification from IP "203.0.113.10"
    And the access token is issued
    Then the token is NOT bound to any IP address
    And the token is accepted from any source IP

  Scenario: IP change recorded in audit log as suspicious
    Given Alice holds a valid access token bound to IP "203.0.113.10"
    When Alice presents the token from IP "198.51.100.42"
    Then the token is rejected
    And the rejection is recorded in the audit log with event type "ip_binding_violation"
    And the audit entry includes both the bound IP "203.0.113.10" and the presenting IP "198.51.100.42"

  Scenario: IP binding configurable per operator
    Given operator "acme-corp" has IP binding enabled
    And operator "dev-sandbox" has IP binding disabled
    When a client under "acme-corp" receives a token
    Then the token is IP-bound
    When a client under "dev-sandbox" receives a token
    Then the token is NOT IP-bound

  # --- Error Cases ---

  Scenario: Token rejected from different IP is indistinguishable from expired
    Given Alice holds a valid access token bound to IP "203.0.113.10"
    When Alice presents the token from IP "198.51.100.42"
    Then the token is rejected
    And the rejection response is identical to an expired token response
    And the response timing is indistinguishable from an expiry rejection
```

## Feature: Concurrent Session Detection

```gherkin
Feature: Concurrent Session Detection
  As the authentication system
  I want to detect when the same client authenticates from multiple IP addresses simultaneously
  So that I can automatically suspend clients whose secrets may be compromised

  Background:
    Given the authentication service is operational
    And Alice is registered with client identifier "alice-payment-service" and status "active"
    And concurrent session detection is enabled
    And the detection time window is 60 seconds

  # --- Happy Path ---

  Scenario: Two authentications from same IP within time window are normal
    Given Alice successfully authenticates from IP "203.0.113.10" at 14:00:00
    When Alice successfully authenticates from IP "203.0.113.10" at 14:00:30
    Then no anomaly is detected
    And Alice's status remains "active"

  # --- Edge Cases ---

  Scenario: Concurrent detection configurable by operator
    Given operator "high-security" has configured concurrent detection with time window 30 seconds
    And operator "relaxed" has configured concurrent detection with time window 300 seconds
    When a client under "high-security" authenticates from two different IPs within 45 seconds
    Then the client is NOT suspended under the "relaxed" configuration
    When a client under "high-security" authenticates from two different IPs within 25 seconds
    Then the client IS suspended under the "high-security" configuration

  # --- Error Cases ---

  Scenario: Two authentications from different IPs within time window triggers suspension
    Given Alice successfully authenticates from IP "203.0.113.10" at 14:00:00
    When Alice successfully authenticates from IP "198.51.100.42" at 14:00:30
    Then Alice's client status is changed to "suspended"
    And a "ClientSuspended" event is published with reason "concurrent_session"
    And the event includes both IP addresses and timestamps

  Scenario: Suspension published as ClientSuspended event with reason
    Given Alice successfully authenticates from IP "203.0.113.10" at 14:00:00
    When Alice successfully authenticates from IP "198.51.100.42" at 14:00:45
    Then a "ClientSuspended" event is published
    And the event payload includes client identifier "alice-payment-service"
    And the event payload includes reason "concurrent_session"
    And the event payload includes detection details for external system consumption

  Scenario: Client status changes to suspended
    Given Alice successfully authenticates from IP "203.0.113.10" at 14:00:00
    And Alice successfully authenticates from IP "198.51.100.42" at 14:00:30
    When the concurrent session detector processes these authentications
    Then Alice's client status in the registry is "suspended"
    And the status change is recorded in the audit log

  Scenario: Suspended client cannot request challenges
    Given Alice's client status has been changed to "suspended" due to concurrent session detection
    When Alice requests a new authentication challenge
    Then the request is refused
    And the response is indistinguishable from a revoked or unknown client response
```

## Feature: Geographic Impossibility Detection

```gherkin
Feature: Geographic Impossibility Detection
  As the authentication system
  I want to detect when a client authenticates from two locations that are geographically impossible to travel between in the elapsed time
  So that I can automatically suspend clients whose secrets may be compromised

  Background:
    Given the authentication service is operational
    And Alice is registered with client identifier "alice-payment-service" and status "active"
    And geographic impossibility detection is enabled
    And the maximum travel speed threshold is 900 km/h

  # --- Happy Path ---

  Scenario: Authentication from Paris then Tokyo within 5 minutes is impossible
    Given Alice successfully authenticates from IP "203.0.113.10" geolocated to Paris at 14:00:00
    When Alice successfully authenticates from IP "198.51.100.42" geolocated to Tokyo at 14:05:00
    Then the geographic distance between Paris and Tokyo is approximately 9700 km
    And the required speed is approximately 116400 km/h which exceeds 900 km/h
    Then Alice's client status is changed to "suspended"
    And a "ClientSuspended" event is published with reason "geographic_impossibility"
    And the event includes both locations, timestamps, and computed speed

  Scenario: Authentication from Paris then London within 2 hours is possible
    Given Alice successfully authenticates from IP "203.0.113.10" geolocated to Paris at 14:00:00
    When Alice successfully authenticates from IP "198.51.100.42" geolocated to London at 16:00:00
    Then the geographic distance between Paris and London is approximately 340 km
    And the required speed is approximately 170 km/h which is below 900 km/h
    Then no anomaly is detected
    And Alice's status remains "active"

  # --- Edge Cases ---

  Scenario: GeoIP lookup failure does not block authentication
    Given Alice successfully authenticates from IP "203.0.113.10" geolocated to Paris at 14:00:00
    When Alice authenticates from IP "192.0.2.1" for which GeoIP lookup fails at 14:05:00
    Then the authentication proceeds normally
    And geographic impossibility detection is skipped for this pair
    And the GeoIP lookup failure is recorded in the system health log

  Scenario: Geographic detection configurable by operator
    Given operator "strict-mode" has geographic detection enabled with speed threshold 500 km/h
    And operator "air-travel-ok" has geographic detection enabled with speed threshold 1200 km/h
    When a client authenticates from Paris then Frankfurt within 30 minutes
    Then the required speed is approximately 920 km/h
    And the client IS suspended under "strict-mode" (920 > 500)
    And the client is NOT suspended under "air-travel-ok" (920 < 1200)

  # --- Error Cases ---

  Scenario: Impossibility triggers auto-suspension with full audit trail
    Given Alice successfully authenticates from IP "203.0.113.10" geolocated to New York at 14:00:00
    When Alice successfully authenticates from IP "198.51.100.42" geolocated to Sydney at 14:10:00
    Then Alice's client status is changed to "suspended"
    And the audit log records the detection with event type "geographic_impossibility_suspension"
    And the audit entry includes: source locations, timestamps, computed distance, computed speed, and speed threshold
```

## Feature: Auto-Suspension on Critical Anomaly

```gherkin
Feature: Auto-Suspension on Critical Anomaly
  As the authentication system
  I want to automatically suspend clients when critical anomalies are detected
  So that compromised clients are contained without requiring administrator intervention

  Background:
    Given the authentication service is operational
    And Alice is registered with client identifier "alice-payment-service" and status "active"
    And auto-suspension mode is set to "alert_and_suspend"

  # --- Happy Path ---

  Scenario: Volume anomaly at 20x baseline triggers suspension
    Given Alice has an established baseline of 10 authentications per hour
    When Alice authenticates 200 times within 1 hour
    Then Alice's client status is changed to "suspended"
    And a "ClientSuspended" event is published with reason "volume_anomaly"
    And the event includes the baseline rate, observed rate, and multiplier

  # --- Edge Cases ---

  Scenario: Revoked client activity triggers alert but not suspension
    Given Alice's client status is "revoked"
    When someone submits a proof using Alice's client identifier
    Then the authentication is refused
    And a "revoked_client_activity" alert is generated immediately
    And no suspension occurs because the client is already revoked
    And the alert includes the source address and timestamp

  Scenario: Auto-suspension publishes ClientSuspended event
    Given a critical anomaly is detected for Alice
    When auto-suspension is triggered
    Then a "ClientSuspended" event is published
    And the event payload includes client identifier "alice-payment-service"
    And the event payload includes the anomaly type and detection timestamp
    And the event is available for consumption by external systems

  Scenario: Auto-suspension records complete audit trail
    Given a critical anomaly is detected for Alice
    When auto-suspension is triggered
    Then the audit log records the suspension with event type "auto_suspension"
    And the audit entry includes the anomaly type, detection details, and timestamps
    And the audit entry includes the client's previous status before suspension
    And the audit entry includes the detection rule that triggered the suspension

  # --- Error Cases ---

  Scenario: Auto-suspension is configurable between alert-only and alert-plus-suspend
    Given operator "cautious" has auto-suspension mode set to "alert_only"
    And operator "strict" has auto-suspension mode set to "alert_and_suspend"
    When a volume anomaly at 20x baseline is detected for a client under "cautious"
    Then only an alert is generated and the client remains "active"
    When a volume anomaly at 20x baseline is detected for a client under "strict"
    Then the client is suspended and an alert is generated
```

## Feature: Suspended Client Behavior

```gherkin
Feature: Suspended Client Behavior
  As the authentication system
  I want suspended clients to be completely locked out of all authentication operations
  So that a potentially compromised client cannot perform any actions until recovery

  Background:
    Given the authentication service is operational
    And Alice is registered with client identifier "alice-payment-service"
    And Alice's client status is "suspended"

  # --- Edge Cases ---

  Scenario: Suspended client cannot request challenges
    When Alice requests a new authentication challenge
    Then the request is refused
    And the response is indistinguishable from a revoked or unknown client response
    And the response timing is constant regardless of the refusal reason

  Scenario: Suspended client cannot verify proofs
    Given Alice somehow possesses a valid challenge issued before suspension
    When Alice submits a proof against that challenge
    Then the verification is refused
    And the response is indistinguishable from a revoked or unknown client response

  Scenario: Suspended client's existing tokens are rejected
    Given Alice holds an access token issued before the suspension
    When Alice presents the token to access a protected resource
    Then the token is rejected
    And the rejection response is indistinguishable from an expired or invalid token response

  Scenario: Suspended client response is indistinguishable from revoked or unknown
    When Alice requests a challenge
    Then the response body is identical to a revoked client response
    And the response body is identical to an unknown client response
    And the response timing is constant across suspended, revoked, and unknown clients
    And no information about the suspension status is leaked

  # --- Error Cases ---

  Scenario: Suspension reason is recorded but never disclosed to the client
    Given Alice was suspended with reason "concurrent_session"
    When Alice requests a challenge
    Then the response does NOT include any suspension reason
    And the response does NOT indicate that the client is suspended
    And the audit log contains the reason "concurrent_session" for administrator review only
```

---

## TDD Implementation Order

### Phase 1: Suspended Client State

1. **RED**: Client status "suspended" exists as a valid state in the domain model
2. **RED**: Suspended client cannot request challenges (indistinguishable response)
3. **RED**: Suspended client cannot verify proofs (indistinguishable response)
4. **RED**: Suspended client's existing tokens are rejected (indistinguishable response)
5. **RED**: Response timing is constant across suspended, revoked, and unknown clients
6. **RED**: Suspension reason recorded in audit log but never disclosed to client

### Phase 2: IP Binding

7. **RED**: Token issued with source IP binding when enabled
8. **RED**: Token accepted from same IP
9. **RED**: Token rejected from different IP (indistinguishable from expired)
10. **RED**: IP binding violation recorded in audit log with both IPs
11. **RED**: IP binding configurable (enabled/disabled per operator)
12. **RED**: Token issued without IP binding when disabled

### Phase 3: Concurrent Session Detection

13. **RED**: Two authentications from same IP within time window are normal
14. **RED**: Two authentications from different IPs within time window triggers suspension
15. **RED**: ClientSuspended event published with reason "concurrent_session"
16. **RED**: Client status changes to "suspended" in registry
17. **RED**: Detection time window and threshold configurable per operator
18. **RED**: Suspended client cannot request challenges (integration with Phase 1)

### Phase 4: Geographic Impossibility Detection

19. **RED**: Haversine distance computation between two geolocated points
20. **RED**: Required speed computation from distance and elapsed time
21. **RED**: Speed exceeding threshold triggers suspension with reason "geographic_impossibility"
22. **RED**: Speed below threshold does not trigger suspension
23. **RED**: GeoIP lookup failure does not block authentication (graceful degradation)
24. **RED**: Speed threshold configurable per operator

### Phase 5: Auto-Suspension on Critical Anomaly

25. **RED**: Volume anomaly at 20x baseline triggers suspension (not just alert)
26. **RED**: Revoked client activity triggers alert only (not suspension)
27. **RED**: Auto-suspension publishes ClientSuspended event with anomaly details
28. **RED**: Auto-suspension records complete audit trail
29. **RED**: Auto-suspension mode configurable: alert-only vs alert-and-suspend

### Phase 6: Integration & Cross-Cutting

30. **RED**: ClientSuspended event consumed by external systems
31. **RED**: All suspension paths produce indistinguishable client-facing responses
32. **RED**: Constant-time responses across all refusal reasons
33. **RED**: End-to-end: concurrent session detection → suspension → token rejection → audit
