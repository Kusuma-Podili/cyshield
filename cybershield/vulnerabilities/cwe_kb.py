"""CWE (Common Weakness Enumeration) Offline Knowledge Base & Taxonomy.

Provides offline classification, architectural impact analysis, detection methods,
and prioritized mitigations for the MITRE CWE Top 25 and foundational hardware/software weaknesses.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional


class CWECategory(str, Enum):
    INJECTION = "Injection"
    MEMORY_SAFETY = "Memory Safety"
    BROKEN_ACCESS_CONTROL = "Broken Access Control"
    CRYPTOGRAPHIC_FAILURES = "Cryptographic Failures"
    AUTHENTICATION_FAILURES = "Identification & Authentication Failures"
    SECURITY_MISCONFIGURATION = "Security Misconfiguration"
    INSECURE_DESERIALIZATION = "Insecure Deserialization"
    SSRF = "Server-Side Request Forgery"
    RACE_CONDITIONS = "Concurrency & Race Conditions"
    RESOURCE_MANAGEMENT = "Improper Resource Management"


@dataclass(frozen=True)
class CWEDefinition:
    """Structured offline definition of a Common Weakness Enumeration."""
    cwe_id: str
    name: str
    category: CWECategory
    description: str
    extended_description: str
    likelihood_of_exploit: str  # High, Medium, Low
    common_consequences: List[str]
    mitigations: List[str]
    detection_methods: List[str]
    related_attack_techniques: List[str] = field(default_factory=list)


# Comprehensive Offline CWE Catalog
CWE_CATALOG: Dict[str, CWEDefinition] = {
    "CWE-79": CWEDefinition(
        cwe_id="CWE-79",
        name="Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')",
        category=CWECategory.INJECTION,
        description="The product does not neutralize or incorrectly neutralizes user-controllable input before it is placed in output that is used as a web page that is served to other users.",
        extended_description="Cross-site scripting (XSS) vulnerabilities occur when untrusted data is included in dynamic web pages without proper validation or encoding, allowing attackers to execute arbitrary scripts in the victim's browser context.",
        likelihood_of_exploit="High",
        common_consequences=["Execute Unauthorized Code or Commands", "Read Application Data", "Bypass Protection Mechanism (Steal Session Cookies)"],
        mitigations=[
            "Use context-aware output encoding (HTML, JavaScript, CSS, URL encoding).",
            "Implement a strict Content Security Policy (CSP).",
            "Enable HttpOnly and Secure flags on sensitive session cookies.",
            "Use modern reactive frameworks with automatic template auto-escaping."
        ],
        detection_methods=["Automated Dynamic Analysis (DAST)", "Static Analysis (SAST) taint tracking", "Web Application Firewall (WAF) inspection"],
        related_attack_techniques=["T1059.007", "T1189"]
    ),
    "CWE-89": CWEDefinition(
        cwe_id="CWE-89",
        name="Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')",
        category=CWECategory.INJECTION,
        description="The product constructs all or part of an SQL command using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could modify the intended SQL command.",
        extended_description="SQL injection allows adversaries to bypass authentication, access, modify, or delete sensitive data in databases, and in certain environments execute administrative operating system commands via database stored procedures.",
        likelihood_of_exploit="High",
        common_consequences=["Confidentiality Loss (Data Exfiltration)", "Integrity Loss (Unauthorized Modification)", "Authentication Bypass"],
        mitigations=[
            "Always utilize parameterized queries or prepared statements (Object-Relational Mapping / PDO).",
            "Apply principle of least privilege to database service accounts.",
            "Enforce strict input validation using allowlists for table/column names.",
            "Disable multi-statement execution and dangerous stored procedures (e.g. xp_cmdshell)."
        ],
        detection_methods=["Static Analysis (SAST)", "Dynamic Analysis (DAST)", "Database Activity Monitoring (DAM)"],
        related_attack_techniques=["T1190", "T1059"]
    ),
    "CWE-78": CWEDefinition(
        cwe_id="CWE-78",
        name="Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')",
        category=CWECategory.INJECTION,
        description="The product constructs an OS command using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could modify the intended command.",
        extended_description="Allows remote attackers to execute arbitrary shell commands on the hosting operating system with the privileges of the vulnerable process.",
        likelihood_of_exploit="High",
        common_consequences=["Full Host Compromise", "Execute Unauthorized Code", "Privilege Escalation"],
        mitigations=[
            "Avoid passing user input directly to system command interpreters.",
            "Utilize structured system execution APIs with arguments passed as discrete arrays rather than concatenated shell strings.",
            "Run application processes in restricted chroot, container, or non-privileged user accounts."
        ],
        detection_methods=["Static Code Analysis (SAST)", "Fuzz Testing", "Syscall Monitoring (auditd/EDR)"],
        related_attack_techniques=["T1059.004", "T1059.001"]
    ),
    "CWE-20": CWEDefinition(
        cwe_id="CWE-20",
        name="Improper Input Validation",
        category=CWECategory.SECURITY_MISCONFIGURATION,
        description="The product receives input or data, but it does not validate or incorrectly validates that the input has the properties that are required to process the data safely and correctly.",
        extended_description="Input validation failures can lead to altered control flow, arbitrary resource control, or memory corruption.",
        likelihood_of_exploit="High",
        common_consequences=["Denial of Service", "Integrity Loss", "Unexpected State Transitions"],
        mitigations=[
            "Validate all inputs against strict positive allowlists (type, length, format, range).",
            "Reject malformed or unexpected data early at protocol boundaries."
        ],
        detection_methods=["Automated Fuzzing", "Static Analysis"],
        related_attack_techniques=["T1190"]
    ),
    "CWE-22": CWEDefinition(
        cwe_id="CWE-22",
        name="Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')",
        category=CWECategory.BROKEN_ACCESS_CONTROL,
        description="The product uses external input to construct a pathname that should be within a restricted directory, but it does not properly neutralize sequences such as '..' that can resolve to a location that is outside that directory.",
        extended_description="Path traversal vulnerabilities allow adversaries to read or overwrite critical files on the filesystem, including configuration files, credentials, and source code.",
        likelihood_of_exploit="High",
        common_consequences=["Read Application Data", "Modify Application Data", "Arbitrary Code Execution via file overwrite"],
        mitigations=[
            "Canonicalize all file paths using realpath/abspath and verify that the target directory starts with the designated root path.",
            "Use indirect object references or filesystem UUID lookups instead of direct client-supplied filenames."
        ],
        detection_methods=["Static Analysis", "DAST Path Traversal Fuzzing"],
        related_attack_techniques=["T1083", "T1005"]
    ),
    "CWE-125": CWEDefinition(
        cwe_id="CWE-125",
        name="Out-of-bounds Read",
        category=CWECategory.MEMORY_SAFETY,
        description="The product reads data past the end, or before the beginning, of the intended buffer.",
        extended_description="Can disclose sensitive memory contents such as cryptographic keys, passwords, and ASLR layout offsets, enabling remote exploitation chains.",
        likelihood_of_exploit="High",
        common_consequences=["Information Disclosure", "Denial of Service (Segmentation Fault)"],
        mitigations=[
            "Use memory-safe languages (Rust, Go) for network parsing components.",
            "Perform rigorous bounds checking before pointer arithmetic or index lookups.",
            "Compile with AddressSanitizer (ASan) during development."
        ],
        detection_methods=["Fuzzing with AFL++/LibFuzzer", "Static Analysis"],
        related_attack_techniques=["T1005"]
    ),
    "CWE-787": CWEDefinition(
        cwe_id="CWE-787",
        name="Out-of-bounds Write",
        category=CWECategory.MEMORY_SAFETY,
        description="The product writes data past the end, or before the beginning, of the intended buffer.",
        extended_description="Classic memory corruption vulnerability enabling control-flow hijacking, arbitrary code execution, and sandbox escapes.",
        likelihood_of_exploit="High",
        common_consequences=["Execute Unauthorized Code", "Privilege Escalation", "Denial of Service"],
        mitigations=[
            "Enforce compiler exploit mitigations (Stack Canaries, SafeStack, Control Flow Guard / CET).",
            "Perform strict boundary validation on all length parameters in memory copy operations."
        ],
        detection_methods=["AddressSanitizer", "Fuzzing", "Binary Auditing"],
        related_attack_techniques=["T1203", "T1055"]
    ),
    "CWE-416": CWEDefinition(
        cwe_id="CWE-416",
        name="Use After Free",
        category=CWECategory.MEMORY_SAFETY,
        description="Referencing memory after it has been freed can cause a program to crash, use unexpected values, or execute code.",
        extended_description="Use after free vulnerabilities occur in heap allocators when dangling pointers are reused before reinitialization.",
        likelihood_of_exploit="High",
        common_consequences=["Arbitrary Code Execution", "Memory Corruption", "Denial of Service"],
        mitigations=[
            "Set freed pointers to NULL immediately after deallocation.",
            "Use smart pointers or RAII constructs in modern C++.",
            "Utilize hardened heap allocators with quarantine buffers."
        ],
        detection_methods=["Valgrind Memcheck", "AddressSanitizer (ASan)", "Static Analysis"],
        related_attack_techniques=["T1203"]
    ),
    "CWE-502": CWEDefinition(
        cwe_id="CWE-502",
        name="Deserialization of Untrusted Data",
        category=CWECategory.INSECURE_DESERIALIZATION,
        description="The product deserializes untrusted data without sufficiently verifying that the resulting data will be valid.",
        extended_description="Allows adversaries to instantiate malicious object gadget chains, resulting in remote code execution (e.g. Java ObjectInputStream, Python pickle, YAML unsafe load).",
        likelihood_of_exploit="High",
        common_consequences=["Execute Unauthorized Code", "Denial of Service"],
        mitigations=[
            "Never use binary serialization formats (pickle, Java Serialization) with untrusted sources.",
            "Prefer standardized data serialization formats such as JSON or Protocol Buffers.",
            "Implement object look-ahead validation filters or cryptographic HMAC signing if binary serialization is strictly required."
        ],
        detection_methods=["Static Analysis", "Code Review"],
        related_attack_techniques=["T1190", "T1059"]
    ),
    "CWE-918": CWEDefinition(
        cwe_id="CWE-918",
        name="Server-Side Request Forgery (SSRF)",
        category=CWECategory.SSRF,
        description="The web server receives a URL or similar request from an upstream component and retrieves the contents of this specified URL, but it does not sufficiently ensure that the request is being sent to the expected destination.",
        extended_description="Adversaries use SSRF to pivot inside private perimeter networks, query cloud instance metadata services (169.254.169.254), or exploit unauthenticated internal microservices.",
        likelihood_of_exploit="High",
        common_consequences=["Bypass Firewall/Perimeter", "Credential Theft (Cloud Tokens)", "Internal Network Port Scanning"],
        mitigations=[
            "Block requests to private RFC 1918 / RFC 3927 / loopback IP address ranges.",
            "Disable HTTP redirects on outbound fetching clients.",
            "Enforce IMDSv2 (Session token requirement) on AWS cloud workloads."
        ],
        detection_methods=["Dynamic Application Security Testing (DAST)", "Network Egress Monitoring"],
        related_attack_techniques=["T1552", "T1046"]
    ),
    "CWE-287": CWEDefinition(
        cwe_id="CWE-287",
        name="Improper Authentication",
        category=CWECategory.AUTHENTICATION_FAILURES,
        description="When an actor claims to have a given identity, the product does not prove or insufficiently proves that the claim is correct.",
        extended_description="Encompasses weak credential requirements, broken session identifiers, missing MFA, and authentication bypass flaws.",
        likelihood_of_exploit="High",
        common_consequences=["Gain Privileges", "Bypass Protection Mechanism", "Unauthorized Account Access"],
        mitigations=[
            "Enforce multi-factor authentication (FIDO2/WebAuthn).",
            "Utilize secure modern password hashing algorithms (Argon2id, bcrypt).",
            "Implement account lockout and exponential backoff on authentication endpoints."
        ],
        detection_methods=["Penetration Testing", "Threat Modeling"],
        related_attack_techniques=["T1078", "T1110"]
    ),
    "CWE-862": CWEDefinition(
        cwe_id="CWE-862",
        name="Missing Authorization",
        category=CWECategory.BROKEN_ACCESS_CONTROL,
        description="The product does not perform an authorization check when an actor attempts to access a resource or perform an action.",
        extended_description="Commonly manifests as Insecure Direct Object References (IDOR), allowing users to access or modify records belonging to other tenants.",
        likelihood_of_exploit="High",
        common_consequences=["Confidentiality Loss", "Integrity Loss", "Privilege Escalation"],
        mitigations=[
            "Enforce centralized server-side authorization checks on every state-changing endpoint.",
            "Validate object ownership against the authenticated session principal on every access."
        ],
        detection_methods=["Role-Based Access Control Auditing", "DAST Scans"],
        related_attack_techniques=["T1078"]
    ),
    "CWE-327": CWEDefinition(
        cwe_id="CWE-327",
        name="Use of a Broken or Risky Cryptographic Algorithm",
        category=CWECategory.CRYPTOGRAPHIC_FAILURES,
        description="The product uses a broken or risky cryptographic algorithm or protocol.",
        extended_description="Using deprecated ciphers or hash functions (MD5, SHA1, DES, RC4) compromises data confidentiality and integrity.",
        likelihood_of_exploit="Medium",
        common_consequences=["Bypass Cryptographic Protection", "Recover Cleartext"],
        mitigations=[
            "Mandate modern authenticated encryption ciphers (AES-256-GCM, ChaCha20-Poly1305).",
            "Use cryptographic hash functions from the SHA-2 or SHA-3 families (SHA-256, SHA-512, BLAKE2/3).",
            "Enforce TLS 1.3 with forward secrecy."
        ],
        detection_methods=["Static Analysis", "Cipher Suite Scanner"],
        related_attack_techniques=["T1557"]
    ),
    "CWE-362": CWEDefinition(
        cwe_id="CWE-362",
        name="Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition')",
        category=CWECategory.RACE_CONDITIONS,
        description="The program can run with other code at the same time, and they both access a shared resource without proper synchronization, causing unexpected outcomes.",
        extended_description="Includes Time-of-Check to Time-of-Use (TOCTOU) file access race conditions and multithreaded memory races.",
        likelihood_of_exploit="Medium",
        common_consequences=["Privilege Escalation", "Data Corruption", "Denial of Service"],
        mitigations=[
            "Use atomic operations and file descriptor-based APIs (open with O_NOFOLLOW / O_EXCL).",
            "Apply thread-safe synchronization locks and mutual exclusion primitives."
        ],
        detection_methods=["ThreadSanitizer (TSan)", "Static Concurrency Analysis"],
        related_attack_techniques=["T1068"]
    ),
    "CWE-400": CWEDefinition(
        cwe_id="CWE-400",
        name="Uncontrolled Resource Consumption",
        category=CWECategory.RESOURCE_MANAGEMENT,
        description="The product does not properly control the allocation and maintenance of a limited resource thereby enabling an actor to influence the amount of resources consumed.",
        extended_description="Leads to resource exhaustion attacks (CPU starvation, memory leaks, disk fill-up, socket starvation).",
        likelihood_of_exploit="Medium",
        common_consequences=["Denial of Service"],
        mitigations=[
            "Enforce strict input length and rate limits.",
            "Configure memory and CPU limits at container and OS cgroup levels.",
            "Implement connection timeouts and graceful resource teardown."
        ],
        detection_methods=["Stress / Load Testing", "System Metrics Monitoring"],
        related_attack_techniques=["T1499"]
    )
}


class CWEKnowledgeBase:
    """Offline lookup engine for Common Weakness Enumerations."""

    @classmethod
    def get(cls, cwe_id: str) -> Optional[CWEDefinition]:
        """Retrieve CWE definition by ID (e.g. 'CWE-89' or '89')."""
        normalized_id = cwe_id.upper()
        if not normalized_id.startswith("CWE-"):
            normalized_id = f"CWE-{normalized_id}"
        return CWE_CATALOG.get(normalized_id)

    @classmethod
    def list_all(cls) -> List[CWEDefinition]:
        """Retrieve full catalog of supported CWE definitions."""
        return list(CWE_CATALOG.values())

    @classmethod
    def get_by_category(cls, category: CWECategory) -> List[CWEDefinition]:
        """Filter weaknesses by category."""
        return [cwe for cwe in CWE_CATALOG.values() if cwe.category == category]

    @classmethod
    def search(cls, query: str) -> List[CWEDefinition]:
        """Full-text search across CWE names, descriptions, and mitigation text."""
        q = query.lower()
        results = []
        for cwe in CWE_CATALOG.values():
            if (
                q in cwe.cwe_id.lower()
                or q in cwe.name.lower()
                or q in cwe.description.lower()
                or any(q in m.lower() for m in cwe.mitigations)
            ):
                results.append(cwe)
        return results
