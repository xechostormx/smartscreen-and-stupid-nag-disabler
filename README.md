# Win11 smartscreen-and-stupid-nag-disabler
removes smart screen, this app is not commonly run, do you want to keep, etc. 

Disable SmartScreen Everywhere (Windows 11 LTSC)
This script disables all SmartScreen components across Windows 11 LTSC, including Windows shell checks, EXE reputation prompts, Attachment Manager zone tagging, and Microsoft Edge’s download reputation system. It also removes Edge’s “This file is not commonly downloaded” and “Keep / Delete” prompts.

The goal is simple: eliminate download friction and reputation warnings while keeping the OS stable and functional.

What This Script Does
The PowerShell script:

Auto‑elevates to Administrator

Disables SmartScreen for:

Windows shell

EXE reputation

Attachment Manager

Microsoft Edge

Disables Edge’s download reputation checks

Removes the “Keep this file” prompt

Allows all downloads without warnings

Stops NTFS zone‑identifier tagging

Leaves Defender and core OS components untouched
