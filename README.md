# MHP3rd Save Editor

A small terminal save editor for **Monster Hunter Portable 3rd** (`ULJM-05800`).
It changes:

- hunter name (the guild card copy is updated too)
- gender
- voice
- face
- skin tone (hex RGB)
- copy appearance + voice from another slot
- automatic backups and a restore picker

for character slots 1–3.

No build step and no third-party Python packages. It uses Python 3 and the
system `openssl` command.

## Run

```bash
cd ~/mhp3-save-editor
python3 mhp3_save_editor.py
```

It auto-detects the PPSSPP save at
`~/.config/ppsspp/PSP/SAVEDATA/ULJM05800/MHP3RD.BIN`.

You can also pass a path:

```bash
python3 mhp3_save_editor.py /path/to/MHP3RD.BIN
```

Show the current characters without writing anything:

```bash
python3 mhp3_save_editor.py --check
```

Check syntax and run the self-tests without touching a save:

```bash
python3 -m py_compile mhp3_save_editor.py
python3 mhp3_save_editor.py --selftest
```

## Values

Voice and face use the in-game numbers, starting at 1. Skin uses a hex colour.
The editor converts them to the values stored in the save:

| Field | Input | Stored |
|---|---|---|
| Gender | `M` / `F` | `0` / `1` |
| Voice | `1`–`20` | `0`–`19` |
| Face | `1`–`11` | `0`–`10` |
| Skin | `#RRGGBB` | RGB at `0x828` |

Skin tone is a 24-bit RGB value. Use any colour picker and enter the six hex
digits, with or without `#` (for example `D9CAB1`).

Names are stored as UTF-16LE. The game allows 6 full-width or 12 half-width
characters; the editor enforces that limit. Empty slots are dimmed and cannot
be edited.

The save keeps a separate guild card copy of the hunter name. Changing the
hunter name updates both copies; editing only appearance does not repair an
existing mismatch.

## Copying appearance + voice

From the main menu press `m`, then `c`, choose the target and source slots,
and optionally type a new name. This copies the source's full appearance and
voice. The target keeps its items, equipment and progress; only appearance,
voice and name change.

After copying, it offers to delete the source slot so the appearance and voice
are not left duplicated. This deletion is optional and defaults to No. The
source slot becomes all zeroes, exactly like an unused slot.

## Safety

- The original save is never modified until you answer **yes** to "Install".
- The first save writes `MHP3RD.BIN.edited` next to the original.
- Every install first creates a full backup. See Backups and restore for the
  folder and retention.
- The edited save is decrypted and checked again before it is installed.
  If that check fails, the backup is restored.
- Close PPSSPP before installing. The editor refuses to install or restore
  while it is running.
- Still make your own copy of the save before using this, and test in PPSSPP
  before copying it to a real PSP.

The 16-byte PSP savedata hash is not recomputed; the tool re-encrypts the file
the same way the working open-source editor does. PPSSPP loads it. Real-PSP
behaviour has not been verified.

## Backups and restore

All backups live in `~/.config/ppsspp/PSP/SAVEDATA/backups/mhp3rd/`. Backups
are never pruned; delete them manually when you no longer need them. From the
main menu choose `m` → `r` to open the restore picker. It lists backups newest
first, ten per page. Selecting one shows a preview and asks for confirmation.
Close PPSSPP before restoring; the editor refuses to restore while it is
running. The current save is backed up before the restore, so a restore can
itself be undone.

## Format notes

The save is 1,183,760 bytes and has two encryption layers plus an inner SHA-1.
The decrypted character data starts at:

- character 1 name: `0x800`
- appearance fields: `0x81B`–`0x81E`
- skin RGB: `0x828`–`0x82A`, alpha at `0x82B`
- guild card name: `0x58DD4` (`+0x585D4` from the character base)
- character 2: `+0x60000`
- character 3: `+0xC0000`

The SHA-1 salt is `VQ(DOdIO9?X3!2GmW#XF`.

## Credits

- Save layout and cipher ported from
  [`erickdevit/savemud`](https://github.com/erickdevit/savemud) (MIT).
- Cipher originally documented by
  [`svanheulen/mhef`](https://github.com/svanheulen/mhef) (GPL-3.0).
