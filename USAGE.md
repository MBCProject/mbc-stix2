# MBC and STIX 2.1: Usage Notes
Machine-readable Malware Behavior Catalog (MBC) data is available via a JSON-based [STIX 2.1](https://oasis-open.github.io/cti-documentation/stix/intro) format. *MBC has been expressed in STIX 2.1 JSON using the STIX 2.1 Committee Specification 01 (CS01).*

The sections below describes how MBC objects and properties map to STIX 2.1 objects and properties. It is assumed that the reader is familiar with STIX.

## MBC Concepts
The following table maps MBC high-level concepts to STIX 2.1 objects. The STIX object types shown are literal strings captured in the **type** property of the STIX object.

**MBC Concept** | **STIX Object Type** | **Notes**
----------------|----------------------|------------
Objective | `x-mitre-tactic` | MBC objectives (similar to ATT&CK tactics) are captured using a custom object of type `x-mitre-tactic`, which was defined to capture ATT&CK tactics. Using it instead of defining a new "x-mitre-objective" object enables ATT&CK users to more easily use MBC.
Behavior | `attack-pattern` | MBC behaviors (similar to ATT&CK techniques) are captured using the STIX Attack Pattern object.
Malware | `malware` | MBC malware examples (aligns with ATT&CK's malware concept) are captured using the STIX Malware object.

## MBC Content

The following tables map MBC content to STIX 2.1 properties within each of the STIX object types. 
 
Properties required by all STIX objects are included in the examples but are not included in the property tables (e.g., **id**, **created**, etc.). Properties required by the STIX object are included in the property table with no corresponding MBC property.

### Objectives
An MBC Objective is captured in a custom object of type `x-mitre-tactic` via the following properties.

**MBC Property** | **STIX Property**
---------------- | -----------------
Name | **name**
 -- | **x_mitre_shortname** (referenced by Attack Pattern objects (MBC behaviors))
ID | **external_references.external_id** where *external_references.source_name* == "mitre-mbc"
Description | **description**
References - description | **external_references.description** where *external_references.source_name* == "external_source"
References - url | **external_references.url** where *external_references.source_name* == "external_source"

**Example:**

```json
 {
   "type": "x-mitre-tactic",
   "spec_version": "2.1",
   "id": "x-mitre-tactic--746a2a9f-d463-43da-87b1-2eada9a458a6", 
   "created": "2020-01-28T21:09:20.220Z",
   "modified": "2020-01-28T21:09:20.220Z",
   "name": "Anti-Behavioral Analysis",
   "x_mitre_shortname": "anti-behavioral-analysis",
   "description": "Behaviors that prevent, obstruct, or evade behavioral analysis (sandbox, debugger, etc)...",
   "external_references": [
      {
        "source_name": "external_source",
        "description": "Unprotect Project, a database about malware self-defense and protection.",
        "url": "http://unprotect.tdgt.org/index.php/Unprotect_Project"
      },    
      {
        "source_name": "mitre-mbc",
        "external_id": "M9001",
        "url": "https://github.com/MBCProject/mbc-markdown/blob/master/anti-behavioral-analysis/README.md"
      }
   ]
  }
```

### Behaviors
An MBC behavior is captured in a STIX Attack Pattern object (`attack-pattern`) via the following properties:

**MBC Property** | **STIX Property**
---------------- | -----------------
Behavior Name | **name**
ID | **external_references.external_id** where *external_references.source_name* == "mitre-mbc"
Description | **description**
Associated MBC Objective(s)    | **kill_chain_phases.kill_chain_phase.phase_name** where *kill_chain_phases.kill_chain_name* == "mitre-mbc"
Related ATT&CK Technique(s) - ID | **external_references.external_id** where *external_references.source_name* == "mitre-attack"
Related ATT&CK Technique(s) - url | **external_references.url** where *external_references.source_name* == "mitre-attack"
Method(s) - name | **x_mitre_methods.name** where *x_mitre_methods* is a custom property defined to capture MBC methods
Method(s) - description |  **x_mitre_methods.definition**
Reference(s) - url | **external_references.url** where *external_references.source_name* == "external_source"

**Example:**

```json
 {
   "type": "attack-pattern",
   "spec_version": "2.1",
   "id": "attack-pattern--c2b0f8ba-c26a-4590-a19f-82ea28f5ed1d",
   "created": "2020-01-28T21:09:20.322Z",
   "modified": "2020-01-28T21:09:20.322Z",
   "name": "Sandbox Detection",
   "description": "Detects whether the malware instance is being executed inside an instrumented sandbox environment...",
   "kill_chain_phases": [
     {
       "kill_chain_name": "mitre-mbc",
       "phase_name": "anti-behavioral-analysis"
     }
   ],
   "external_references": [
     {
       "source_name": "mitre-mbc",
       "url": "https://github.com/MBCProject/mbc-markdown/blob/master/anti-behavioral-analysis/detect-sandbox.md",
       "external_id": "M0007"
     },
     {
       "source_name": "external_source",
       "url": "https://github.com/LordNoteworthy/al-khaser"
     }
   ],
   "x_mitre_methods": [
     {
       "definition": "Checks clipboard data which can be used to detect whether execution is inside a sandbox.",
       "name": "Check Clipboard Data"
     },
     {
       "definition": "Sandboxes create files on the file system. Malware can check the different folders to find sandbox artifacts.",
       "name": "Check Files"
     }
   ]
 }
``` 

### Malware
Malware is captured with a STIX Malware object (`malware`) via the following properties:

MBC Property | STIX Property
--------------- | ---------------
Name     | **name**
ID | **external_references.external_id** where *external_references.source_name* == "mitre-mbc"
Alias(es) | **x_mitre_aliases**
Platform(s) | **x_mitre_platform**
Year | **x_mitre_year**
Description   | **description**
Reference(s) - url | **external_references.url** where *external_references.source_name* == "external_source"
-- | **malware_types** where value == "unknown" (required in STIX 2.1)
-- | **is_family** where value == "true" (required in STIX 2.1)

**Example:**

```json
 {
   "type": "malware",
   "spec_version": "2.1",
   "id": "malware--b559872a-a3c4-4adf-92c7-d4e79d02a24a",
   "created": "2020-01-28T21:09:21.242Z",
   "modified": "2020-01-28T21:09:21.242Z",
   "name": "Kraken",
   "description": "Kraken is a family of bots.",
   "malware_types": ["unknown"],
   "is_family": true,
   "external_references": [
     {
       "source_name": "mitre-mbc",
       "url": "https://github.com/MBCProject/mbc-markdown/blob/master/xample-malware/kraken.md",
       "external_id": "X0010"
     },
     {
       "source_name": "external_source",
       "url": "http://blog.threatexpert.com/2008/04/kraken-changes-tactics.html"
     }
   ],
   "x_mitre_aliases": ["Bobax"],
   "x_mitre_platform": ["Windows"],
   "x_mitre_year": "2008"
 }
```

## Malware and Behavior Relationships
MBC captures relationships between malware and the behaviors the malware exhibits. These relationships are captured as STIX Relationship Objects (SRO) where the source of the SRO is the malware object and the target of the SRO is the attack pattern object (behavior). 

**Example:**

```json
 {
   "type": "relationship",
   "spec_version": "2.1",
   "id": "relationship--5a75909d-89f5-4d86-93be-758fab713af3",
   "created": "2020-01-28T21:09:21.331Z",
   "modified": "2020-01-28T21:09:21.331Z",
   "relationship_type": "uses",
   "source_ref": "malware--1a1054d0-616f-4968-9384-70c77293ca83",
   "target_ref": "attack-pattern--af6955dd-e692-467b-804b-fe160306f2ac"
 }
```

# Accessing MBC Data Using Python

MBC data stored in a STIX 2.1 repository can be queried and manipulated similarly to how ATT&CK data is queried and manipulated. Please see the Section entitled, "Using Python and STIX 2.0" in the [STIX usage document](https://github.com/mitre/cti/blob/master/USAGE.md) for details.

# Using MBC Content in the ATT&CK® Navigator

The [ATT&CK® Navigator](https://github.com/mitre-attack/attack-navigator) has documentation on their repo detailing how to run and load data from other data sources. The example below makes the assumption you are running Docker:

1) Download a copy of this repo to your local system and locate the `mbc.json` file.
2) Download a copy of the ATT&CK Navigator repo to your local system.
3) Locate `attack-navigator/nav-app/src/assets/config.json` and open it.
4) Change the "enterprise_attack_url" key to a path in your local system or to a path relative to the image (e.g., `assets/mbc.json`)
5) Move the `mbc.json` file to `attack-navigator/nav-app/src/assets/`.
6) Continue with the ATT&CK® Navigator instructions to build and run your instance.
