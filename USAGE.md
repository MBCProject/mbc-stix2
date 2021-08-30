# MBC and STIX 2.1: Usage Notes
Machine-readable Malware Behavior Catalog (MBC) data is available via a JSON-based [STIX 2.1](https://oasis-open.github.io/cti-documentation/stix/intro) format. *MBC has been expressed in STIX 2.1 JSON using the STIX 2.1 Committee Specification 03 (CS03).*

The sections below describes how MBC objects and properties map to STIX 2.1 objects and properties. It is assumed that the reader is familiar with STIX.

## MBC Concepts
The following table maps MBC high-level concepts to STIX 2.1 objects. The STIX object types shown are literal strings captured in the **type** property of the STIX object.

|**MBC Concept**|**STIX Object Type**|**Notes**|
|---|---|---|
|Objective|`x-mitre-tactic`|MBC objectives (similar to ATT&CK tactics) are captured using a custom object of type `x-mitre-tactic`, which was defined to capture ATT&CK tactics. Using it instead of defining a new "x-mitre-objective" object enables ATT&CK users to more easily use MBC.|
|Behavior|`attack-pattern`|MBC behaviors (similar to ATT&CK techniques) are captured using the STIX Attack Pattern object.|
|Malware|`malware`|MBC malware examples (aligns with ATT&CK's malware concept) are captured using the STIX Malware object.|

## MBC Content

The following tables map MBC content to STIX 2.1 properties within each of the STIX object types. 
 
Properties required by all STIX objects are included in the examples but are not included in the property tables (e.g., **id**, **created**, etc.). Properties required by the STIX object are included in the property table with no corresponding MBC property.

### Objectives
An MBC Objective is captured in a custom object of type `x-mitre-tactic` via the following properties.

|**MBC Property**|**STIX Property**|
|---|---|
|Name|**name**|
| -- |**x_mitre_shortname** (referenced by Attack Pattern objects (MBC behaviors))|
|ID|**external_references.external_id** where *external_references.source_name* == "mitre-mbc"|
|Description|**description**|
|References - description|**external_references.description** where *external_references.source_name* == "external_source"|
|References - url|**external_references.url** where *external_references.source_name* == "external_source"|

**Example:**

```json
{
  "type": "x-mitre-tactic",
  "spec_version": "2.1",
  "id": "x-mitre-tactic--eb6166b0-f3c9-4124-aeb9-662941baa19e",
  "created_by_ref": "identity--b73c59c1-8560-449a-b8d0-c2ce0533c5bf",
  "created": "2020-02-05T20:28:15.061Z",
  "modified": "2020-02-05T20:28:15.061Z",
  "name": "Anti-Behavioral Analysis",
  "description": "Behaviors that prevent, obstruct, or evade behavioral analysis (sandbox, debugger, etc). Because the underlying methods differ, separate \"detection\" and \"evasion\" behaviors are defined for some anti-behavioral analysis areas (e.g., anti-debugger). \n\nTwo primary resources for anti-behavioral analysis behaviors are [[1]](#1) and [[2]](#2).",
  "external_references": [
    {
      "source_name": "external_source",
      "description": "Unprotect Project, a database about malware self-defense and protection.",
      "url": "http://unprotect.tdgt.org/index.php/Unprotect_Project"
    },
    {
      "source_name": "external_source",
      "description": "InDepthUnpacking, course content for teaching malware anti-analysis techniques and mitigations, with emphasis on packers.",
      "url": "https://github.com/knowmalware/InDepthUnpacking"
    },
    {
      "source_name": "mitre-mbc",
      "url": "https://github.com/MBCProject/mbc-markdown/blob/v2.0/anti-behavioral-analysis/README.md",
      "external_id": "OB0001"
    }
  ],
  "object_marking_refs": [
    "marking-definition--093b6375-cd45-4aa3-8f91-6a03ddd7a3d3"
  ],
  "x_mitre_shortname": "anti-behavioral-analysis"
}
```

### Behaviors
An MBC behavior is captured in a STIX Attack Pattern object (`attack-pattern`) via the following properties:

|**MBC Property**|**STIX Property**|
|---|---|
|Behavior Name|**name**|
|ID | **external_references.external_id** where *external_references.source_name* == "mitre-mbc"|
|Description | **description**|
|Associated MBC Objective(s)|**kill_chain_phases.kill_chain_phase.phase_name** where *kill_chain_phases.kill_chain_name* == "mitre-mbc"|
|Related ATT&CK Technique(s) - ID|**external_references.external_id** where *external_references.source_name* == "mitre-attack"|
|Related ATT&CK Technique(s) - url|**external_references.url** where *external_references.source_name* == "mitre-attack"|
|Reference(s) - url|**external_references.url** where *external_references.source_name* == "external_source"|
|Is Subtechnique|**x_mitre_is_subtechnique** == True when Behavior, Micro-Behavior, Enhanced Technique, or ATT&CK (Sub-)Techniques are present|

**Example:**

```json
{
  "type": "attack-pattern",
  "spec_version": "2.1",
  "id": "attack-pattern--295a3b88-2a7e-4bae-9c50-014fce6d5739",
  "created_by_ref": "identity--b73c59c1-8560-449a-b8d0-c2ce0533c5bf",
  "created": "2020-08-21T20:49:59.486264Z",
  "modified": "2020-08-21T20:49:59.486264Z",
  "name": "Sandbox Detection",
  "description": "Detects whether the malware instance is being executed inside an instrumented sandbox environment (e.g., Cuckoo Sandbox). If so, conditional execution selects a benign execution path.",
  "kill_chain_phases": [
    {
      "kill_chain_name": "mitre-mbc",
      "phase_name": "anti-behavioral-analysis"
    }
  ],
  "external_references": [
    {
      "source_name": "mitre-mbc",
      "url": "https://github.com/MBCProject/mbc-markdown/blob/v2.0/anti-behavioral-analysis/detect-sandbox.md",
      "external_id": "B0007"
    },
    {
      "source_name": "external_source",
      "url": "https://www.fireeye.com/blog/threat-research/2011/01/the-dead-giveaways-of-vm-aware-malware.html"
    },
    {
      "source_name": "external_source",
      "url": "http://labs.lastline.com/exposing-rombertik-turning-the-tables-on-evasive-malware"
    },
    {
      "source_name": "external_source",
      "url": "https://github.com/LordNoteworthy/al-khaser"
    },
    {
      "source_name": "external_source",
      "url": "https://www.fireeye.com/content/dam/fireeye-www/current-threats/pdfs/pf/file/fireeye-hot-knives-through-butter.pdf"
    }
  ],
  "object_marking_refs": [
    "marking-definition--093b6375-cd45-4aa3-8f91-6a03ddd7a3d3"
  ],
  "x_mitre_is_subtechnique": false
}
``` 

### Malware
Malware is captured with a STIX Malware object (`malware`) via the following properties:

|**MBC Property**|**STIX Property**|
|---|---|
|Name|**name**|
|ID|**external_references.external_id** where *external_references.source_name* == "mitre-mbc"|
|Alias(es)|**x_mitre_aliases**|
|Platform(s)|**x_mitre_platform**|
|Year|**x_mitre_year**|
|Description|**description**|
|Reference(s) - url|**external_references.url** where *external_references.source_name* == "external_source"|
|--|**malware_types** where value == "unknown" (required in STIX 2.1)|
|--|**is_family** where value == "true" (required in STIX 2.1)|

**Example:**

```json
{
  "type": "malware",
  "spec_version": "2.1",
  "id": "malware--36e75009-8fd6-467a-aa8c-c6a4d3511dfa",
  "created_by_ref": "identity--b73c59c1-8560-449a-b8d0-c2ce0533c5bf",
  "created": "2020-08-21T20:50:04.345255Z",
  "modified": "2020-08-21T20:50:04.345255Z",
  "name": "Kraken",
  "description": "A family of bots.",
  "malware_types": [
    "unknown"
  ],
  "is_family": true,
  "external_references": [
    {
      "source_name": "mitre-mbc",
      "url": "https://github.com/MBCProject/mbc-markdown/blob/v2.0/xample-malware/kraken.md",
      "external_id": "X0010"
    },
    {
      "source_name": "external_source",
      "url": "http://blog.threatexpert.com/2008/04/kraken-changes-tactics.html"
    }
  ],
  "object_marking_refs": [
    "marking-definition--093b6375-cd45-4aa3-8f91-6a03ddd7a3d3"
  ],
  "x_mitre_aliases": [
    "Bobax"
  ],
  "x_mitre_platform": [
    "Windows"
  ],
  "x_mitre_year": "2008"
}
```

## Malware and Behavior Relationships
MBC captures relationships between malware and the behaviors the malware exhibits. These relationships are captured as STIX Relationship Objects (SRO) where the source of the SRO is the malware object and the target of the SRO is the attack pattern object (behavior). 

In order to track specialized behaviors, techniques, etc. the knowledge base also provides relationships to track these mappings. Those relationships will have relationship_type `subtechnique-of`.

**Example:**

```json
{
  "type": "relationship",
  "spec_version": "2.1",
  "id": "relationship--d1f3731f-61f7-45f4-be59-c3028c327241",
  "created_by_ref": "identity--b73c59c1-8560-449a-b8d0-c2ce0533c5bf",
  "created": "2020-08-21T20:50:04.603292Z",
  "modified": "2020-08-21T20:50:04.603292Z",
  "relationship_type": "uses",
  "description": "Dumping Kraken's c.dll module from the heap of its own process is tricky because its PE-header is wiped out.",
  "source_ref": "malware--36e75009-8fd6-467a-aa8c-c6a4d3511dfa",
  "target_ref": "attack-pattern--7981f82d-ff58-4d38-a420-69d73a67bbc9",
  "object_marking_refs": [
    "marking-definition--093b6375-cd45-4aa3-8f91-6a03ddd7a3d3"
  ]
}
```

```json
{
  "type": "relationship",
  "id": "relationship--97e12116-ad14-47cf-9f12-0d4d935f0d0b",
  "created_by_ref": "identity--b73c59c1-8560-449a-b8d0-c2ce0533c5bf",
  "created": "2020-12-29T20:55:03.775Z",
  "modified": "2020-12-29T20:55:03.775Z",
  "relationship_type": "subtechnique-of",
  "source_ref": "attack-pattern--b16029de-92c1-4b77-b334-733f0d099ecd",
  "target_ref": "attack-pattern--87adc62c-05e8-4594-94f6-d6e034597859",
  "object_marking_refs": [
    "marking-definition--093b6375-cd45-4aa3-8f91-6a03ddd7a3d3"
  ]
}
```

# Accessing MBC Data Using Python

MBC data stored in a STIX 2.1 repository can be queried and manipulated similarly to how ATT&CK data is queried and manipulated. Please read the MITRE/CTI repo [Usage](https://github.com/mitre/cti/blob/master/USAGE.md) for details.

# Using MBC Content in the ATT&CK® Navigator

The [ATT&CK® Navigator](https://github.com/mitre-attack/attack-navigator) has documentation on their repo detailing how to run and load data from other data sources. The example below makes the assumption you are running Docker:

1) Run the [/src/attack_nav_mod.py](/src/attack_nav_mod.py) script. This will generate a new JSON file `mbc-attack-nav-modified.json`.
2) Download a copy of the ATT&CK Navigator repo to your local system.
3) Locate `attack-navigator/nav-app/src/assets/` directory and open it.
4) Move the `mbc-attack-nav-modified.json` created by the [/src/attack_nav_mod.py](/src/attack_nav_mod.py) script to `attack-navigator/nav-app/src/assets/`.
5) Open `config.json` and create a new entry to the configuration with the `"data"` key pointing to a path in your local system or to a path relative to the image (e.g., `assets/mbc-attack-nav-modified.json`)

```json
        {
            "name": "MBC v2.1",
            "domains": [
                {
                    "name": "2.1 Release",
                    "data": ["assets/mbc-attack-nav-modified.json"]
                }
            ]
        }
```

6) Continue with the ATT&CK® Navigator instructions to build and run your instance.
