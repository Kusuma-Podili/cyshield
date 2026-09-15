"""
Enterprise CEP Correlation Rules Catalog.
Pre-configured multi-event temporal attack patterns and detection logic.
"""

from typing import List
from cybershield.correlation.schemas import (
    AggregationFunction,
    ConditionOperator,
    CorrelationRule,
    CorrelationWindowType,
    EventFilter,
    SequenceStep,
)


DEFAULT_CORRELATION_RULES: List[CorrelationRule] = [
    CorrelationRule(
        id="CORR-BRUTE-FORCE-SUCCESS",
        name="Brute Force Authentication Followed by Success",
        description="Detects multiple authentication failures followed by a successful login for the same target user within 3 minutes.",
        mitre_technique_id="T1110.001",
        severity="CRITICAL",
        enabled=True,
        window_type=CorrelationWindowType.SLIDING,
        window_seconds=180,
        group_by_fields=["username"],
        sequence_steps=[
            SequenceStep(
                step_id="step1",
                name="Multiple Failed Logins",
                filters=[
                    EventFilter(field="event_type", operator=ConditionOperator.EQUALS, value="AUTH_FAILURE"),
                ],
                min_count=3,
            ),
            SequenceStep(
                step_id="step2",
                name="Subsequent Successful Login",
                filters=[
                    EventFilter(field="event_type", operator=ConditionOperator.EQUALS, value="AUTH_SUCCESS"),
                ],
                min_count=1,
            ),
        ],
        threshold=4.0,
    ),
    CorrelationRule(
        id="CORR-PASSWORD-SPRAY",
        name="Horizontal Password Spray Attack",
        description="Identifies a single source IP attempting authentication across multiple distinct usernames within 5 minutes.",
        mitre_technique_id="T1110.003",
        severity="HIGH",
        enabled=True,
        window_type=CorrelationWindowType.SLIDING,
        window_seconds=300,
        group_by_fields=["src_ip"],
        sequence_steps=[
            SequenceStep(
                step_id="spray_fails",
                name="Failed Logins across Accounts",
                filters=[
                    EventFilter(field="event_type", operator=ConditionOperator.EQUALS, value="AUTH_FAILURE"),
                ],
                min_count=5,
            )
        ],
        aggregation=AggregationFunction.DISTINCT_COUNT,
        aggregation_target_field="username",
        threshold=4.0,
    ),
    CorrelationRule(
        id="CORR-PORT-SCAN-RECON",
        name="High-Rate Network Port Reconnaissance",
        description="Detects an internal host scanning multiple destination ports in under 60 seconds.",
        mitre_technique_id="T1046",
        severity="MEDIUM",
        enabled=True,
        window_type=CorrelationWindowType.SLIDING,
        window_seconds=60,
        group_by_fields=["src_ip"],
        sequence_steps=[
            SequenceStep(
                step_id="port_probes",
                name="Network Connection Probes",
                filters=[
                    EventFilter(field="event_type", operator=ConditionOperator.EQUALS, value="NETWORK_FLOW"),
                ],
                min_count=10,
            )
        ],
        aggregation=AggregationFunction.DISTINCT_COUNT,
        aggregation_target_field="dest_port",
        threshold=8.0,
    ),
    CorrelationRule(
        id="CORR-RANSOMWARE-BURST",
        name="Ransomware Rapid File Encryption Burst",
        description="Detects a rapid spike in file modifications/renames on an endpoint indicating active encryption.",
        mitre_technique_id="T1486",
        severity="CRITICAL",
        enabled=True,
        window_type=CorrelationWindowType.SLIDING,
        window_seconds=30,
        group_by_fields=["host_id"],
        sequence_steps=[
            SequenceStep(
                step_id="file_burst",
                name="Rapid File Modification Activity",
                filters=[
                    EventFilter(field="event_type", operator=ConditionOperator.EQUALS, value="FILE_MODIFIED"),
                ],
                min_count=20,
            )
        ],
        aggregation=AggregationFunction.COUNT,
        threshold=20.0,
    ),
    CorrelationRule(
        id="CORR-ACCOUNT-MANIPULATION-CHAIN",
        name="Suspicious Account Creation and Admin Promotion Chain",
        description="Detects a local account created followed immediately by elevation to administrative group.",
        mitre_technique_id="T1098",
        severity="HIGH",
        enabled=True,
        window_type=CorrelationWindowType.SLIDING,
        window_seconds=300,
        group_by_fields=["target_user"],
        sequence_steps=[
            SequenceStep(
                step_id="create_user",
                name="User Created",
                filters=[
                    EventFilter(field="action", operator=ConditionOperator.EQUALS, value="USER_CREATED"),
                ],
                min_count=1,
            ),
            SequenceStep(
                step_id="add_admin",
                name="Added to Administrators",
                filters=[
                    EventFilter(field="action", operator=ConditionOperator.EQUALS, value="ADDED_TO_ADMIN_GROUP"),
                ],
                min_count=1,
            ),
        ],
        threshold=2.0,
    ),
]
