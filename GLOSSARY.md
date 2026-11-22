# MHP3rd Save Editor

A terminal tool for editing Monster Hunter Portable 3rd save files outside the game. This glossary defines the project's language for hunters, character slots, appearance, and the backup and restore workflow.

## Game and save

**MHP3rd**:
Monster Hunter Portable 3rd, the PSP game whose saves this project edits.
_Avoid_: MHP3, MH3rd

**ULJM-05800**:
The Japanese PSP release identifier for MHP3rd; the save format this project targets.
_Avoid_: game ID, JP version

**Save**:
The `MHP3RD.BIN` file that holds all three character slots.
_Avoid_: savegame, save data

**Character slot**:
One of three independent hunter records in a save.
_Avoid_: profile, save slot

**Used slot**:
A character slot containing a hunter.
_Avoid_: occupied slot, active slot

**Empty slot**:
A character slot with no hunter.
_Avoid_: free slot, blank slot

**Hunter**:
The player character stored in a character slot.
_Avoid_: character, avatar, player

## Hunter identity

**Hunter name**:
The name of the hunter in a character slot.
_Avoid_: character name, player name

**Guild card**:
The hunter's shareable profile card.
_Avoid_: card, guildcard

**Guild card name**:
The hunter name copy displayed on the guild card; it is kept in sync with the hunter name.
_Avoid_: card name, alias

**Gender**:
Whether a hunter is male or female.
_Avoid_: sex, body type

**Appearance**:
A hunter's visual identity: gender, face, skin tone, and colour choices.
_Avoid_: look, visuals

**Face**:
A selectable hunter face shape.
_Avoid_: face type, head

**Skin tone**:
A hunter's complexion colour.
_Avoid_: skin colour, complexion

**Voice**:
A hunter's selected voice set.
_Avoid_: sound, voice type

## Editing

**Live save**:
The save currently used by the game.
_Avoid_: current save, original save

**Save changes**:
Replacing the live save with the current edits; a backup is created first.
_Avoid_: install, apply, commit

**Copy appearance + voice**:
The operation that copies a source hunter's appearance and voice onto a target slot, with an optional rename and optional deletion of the source.
_Avoid_: clone, duplicate, copy mode, copy character

**Source slot**:
The character slot a copy reads from.
_Avoid_: origin slot, donor slot

**Target slot**:
The character slot a copy writes to.
_Avoid_: destination slot, recipient slot

**Delete source**:
The option in Copy appearance + voice that empties the source slot after the copy; the slot becomes unused.
_Avoid_: clear slot, erase character, remove source

## Backups and restore

**Backup**:
A full copy of the live save kept before a save or restore.
_Avoid_: snapshot, save copy

**Backup folder**:
The dedicated folder that holds every automatic backup; backups are never pruned automatically.
_Avoid_: archive folder, snapshot directory

**Restore**:
Replacing the live save with a chosen backup; the current live save is backed up first.
_Avoid_: rollback, revert
