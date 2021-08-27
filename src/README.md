# Utility Scripts

This folder contains additional resources that may be utilized in conjunction with the [MBC STIX2 repository](/README.md).

| Script | Purpose |
|:---|:---|
| attack_nav_mod.py | This script will modify the MBC content by adding `"x_mitre_platforms": ["N/A"]` to all the attack-pattern objects to satisfy the ATT&K Navigator requirements. This field is not provided by MBC because the behaviors defined in the knowledge base do not contain platform specific information. The script will create a new local file that you can copy over to your navigator installation to create MBC layers.  |
