import io, pytest
from bippass.cli import shell as sh
from bippass.cli import common as cc
from bippass.core.manager import PasswordManager

def P(s): return bytearray(s, "utf-8")

@pytest.fixture
def profile(tmp_path):
    m = PasswordManager.create("alice", P("prim"), P("sec"), label="Alice")
    v = m.add_empty_vault("Perso"); it = m.add_empty_item(v.uuid); it.set_name("GitHub")
    it.set("logins", ["bob"]); it.set("passwords", [P("hunter2")], data_key=m.data_key)
    it.set("totps", [P("JBSWY3DPEHPK3PXP")], data_key=m.data_key)
    it.add_custom("Recovery", "encrypted", [P("r1"), P("r2")], data_key=m.data_key)
    m.add_empty_vault("Pro")
    f = tmp_path / "p.bippass"; m.save(f); m.close(); return f

def run(lines, monkeypatch, passwords=()):
    pw = iter(passwords); monkeypatch.setattr(cc.getpass, "getpass", lambda prompt: next(pw))
    out = io.StringIO(); s = sh.BippassShell(stdout=out)
    for line in lines: s.onecmd(line)
    return s, out.getvalue()

def test_session(profile, monkeypatch):
    s, out = run([f"load {profile}", "ls", "unlock", "ls", "cd Perso", "ls", "cd 1", "show",
                  "reveal password", "decrypt", "reveal password", "reveal Recovery 2", "totp",
                  "pwd", "cd ..", "cd /", "info", "close"],
                 monkeypatch, ["prim", "sec"])
    assert 'use "unlock" first' in out and "Perso" in out and "GitHub" in out
    assert "********  [1]" in out and 'use "decrypt" first' in out
    assert "password [1]: hunter2" in out and "Recovery [2]: r2" in out and "s left)" in out
    assert "/Perso/GitHub" in out and "decrypted" in out and "Closed." in out
    assert s.manager is None

def test_errors_no_traceback(profile, monkeypatch):
    s, out = run(["ls", "load /nope", f"load {profile}", "unlock", "unlock", "frobnicate", "cd 9", "help", "help cd"],
                 monkeypatch, ["wrong", "prim"])
    assert 'No profile loaded' in out and "error: Wrong primary password." in out
    assert "Unknown command 'frobnicate'" in out and "No vault #9." in out
    assert "Navigation:" in out and "  * cd <vault | item | .. | />" in out and "search" not in out
    assert "Arguments:" in out and "  * <vault> : at the root" in out
    assert "Traceback" not in out

def test_save_as(profile, monkeypatch, tmp_path):
    s, out = run([f"load {profile}", "unlock", f"save {tmp_path/'copy.bippass'}"], monkeypatch, ["prim"])
    assert "Saved to" in out and PasswordManager.read(tmp_path / "copy.bippass").label == "Alice"

def test_every_command_documented():
    from bippass.cli import help_texts
    commands = {n[3:] for n in dir(sh.BippassShell) if n.startswith("do_")} - {"EOF"}
    documented = set(help_texts.COMMANDS) | set(help_texts.ALIASES)
    assert commands == documented
    from bippass.cli.console import Output
    for name in commands:
        out = io.StringIO()
        assert help_texts.print_details(Output(out), name) and out.getvalue().split()[0] == help_texts.COMMANDS[help_texts.ALIASES.get(name, name)].usage.split()[0]

def test_names_with_spaces(tmp_path, monkeypatch):
    m = PasswordManager.create(None, P("p"), P("s"))
    v = m.add_empty_vault("My vault"); it = m.add_empty_item(v.uuid); it.set_name("Example Bank")
    it.add_custom("Card PIN", "encrypted", [P("0000"), P("1111")], data_key=m.data_key)
    it.add_custom("Code 2", "encrypted", [P("c2")], data_key=m.data_key)
    f = tmp_path / "s.bippass"; m.save(f); m.close()
    s, out = run([f"load {f}", "unlock", "decrypt", "cd my VAULT", "cd Example Bank", "show",
                  "reveal Card PIN", "reveal Card PIN 2", 'reveal "Code 2"'], monkeypatch, ["p", "s"])
    assert "error" not in out
    assert "Card PIN [1]: 0000" in out and "Card PIN [2]: 1111" in out and "Code 2 [1]: c2" in out

def test_reveal_singular_and_plural(profile, monkeypatch):
    s, out = run([f"load {profile}", "unlock", "decrypt", "cd Perso", "cd GitHub",
                  "reveal password", "reveal passwords 1", "reveal totp"], monkeypatch, ["prim", "sec"])
    assert "error" not in out and out.count("password [1]: hunter2") == 2 and "totp [1]: JBSWY3DPEHPK3PXP" in out

def test_custom_references(tmp_path, monkeypatch):
    m = PasswordManager.create(None, P("p"), P("s"))
    v = m.add_empty_vault("V"); it = m.add_empty_item(v.uuid); it.set_name("I")
    it.add_custom("password", "encrypted", [P("custom-secret")], data_key=m.data_key)
    it.add_custom("PIN", "encrypted", [P("1")], data_key=m.data_key)
    it.add_custom("PIN", "encrypted", [P("2")], data_key=m.data_key)
    it.add_custom("Empty", "encrypted", [], data_key=m.data_key)
    it.add_custom("Note", "clear", ["hi"])
    f = tmp_path / "e.bippass"; m.save(f); m.close()
    s, out = run([f"load {f}", "unlock", "decrypt", "cd V", "cd I", "show",
                  "reveal c1", "reveal PIN", "reveal c3", "reveal Note"], monkeypatch, ["p", "s"])
    assert "c4  Empty    : (no value)" in out and "c5  Note     : hi  [1]" in out
    assert "password [1]: custom-secret" in out and "PIN [1]: 2" in out
    assert "use c2 or c3" in out and "is not encrypted" in out

def test_blank_custom_names_refused():
    from bippass.core.item import Item
    from bippass.core.uuids import _generate_uuid
    it = Item(_generate_uuid([]))
    with pytest.raises(ValueError): it.add_custom("   ", "clear", [])
    cid = it.add_custom("  PIN ", "clear", []); assert it.custom_name(cid) == "PIN"

def test_encrypt(profile, monkeypatch):
    s, out = run([f"load {profile}", "unlock", "decrypt", "cd Perso", "encrypt", "reveal password",
                  "cd GitHub", "decrypt", "reveal password",
                  "encrypt nope", "lock nope", "rename Renamed", "lock", "ls",
                  f"load {profile}", "unlock", "cd Perso", "ls"],
                 monkeypatch, ["prim", "sec", "sec", "prim"])
    assert 'Encrypted: use "decrypt"' in out and 'use "decrypt" first' in out
    assert out.count("password [1]: hunter2") == 1
    assert "Usage: encrypt" in out and "Usage: lock" in out
    assert f"Locked: {profile} saved and closed." in out and 'use "load" first' in out
    assert out.count("Renamed") >= 2 and s.manager.is_unlocked      # saved before closing

def test_home(profile, monkeypatch):
    s, out = run([f"load {profile}", "unlock", "cd Perso", "cd GitHub", "home", "pwd",
                  "cd Perso", "home", "pwd", "home", "pwd"], monkeypatch, ["prim"])
    assert out.count("/\n") == 3 and s.vault_uuid is None and s.item_uuid is None

def test_editing_session(profile, monkeypatch, tmp_path):
    secrets = ["prim", "sec", "newpw", "newpw", "JBSWY3DPEHPK3PXP", "1234", "1234", "edited", "edited"]
    s, out = run([f"load {profile}", "unlock", "decrypt",
                  "add Banque", "cd Perso", "add New Site", "pwd",
                  "addtofield login --values bob", "addtofield website --values https://a.example.com",
                  "addtofield website --values https://b.example.com", "addtofield password",
                  "addtofield totp", "addfield secret Card PIN", "addfield clear Note --values hello world",
                  "addtofield password --generate 12", "show",
                  "editfield login --value bobby", "editfield website 2 --value https://c.example.com",
                  "editfield password 1", "removefield website 1", "removefield password 2",
                  "removefield Note", "rename Renamed Site", "move Banque", "pwd",
                  "quit", "close"],
                 monkeypatch, secrets)
    assert "error" not in out.replace("error: Unsaved", "UNSAVED"), out
    assert "/Perso/New Site" in out and "/Banque/Renamed Site" in out
    assert "Generated 1 password(s) of 12 characters." in out and "error: Unsaved changes" in out
    assert s.manager is not None and s.dirty

    m = s.manager; item = m.get_item(s.item_uuid)
    assert item.get_name() == "Renamed Site" and item.get("logins") == ["bobby"]
    assert item.get("websites") == ["https://c.example.com"]
    assert item.get("passwords", data_key=m.data_key) == [b"edited"]
    assert item.get("totps", data_key=m.data_key) == [b"JBSWY3DPEHPK3PXP"]
    names = [item.custom_name(c) for c in item.custom_ids()]
    assert names == ["Card PIN"] and m.vault_of(item.uuid).get_name() == "Banque"

    f = tmp_path / "saved.bippass"; s.onecmd(f"save {f}"); assert not s.dirty

def test_remove_and_guards(profile, monkeypatch):
    s, out = run([f"load {profile}", "unlock", "remove Perso", "remove Perso --force", "vaults",
                  "addtofield login --values x", "cd Pro", "addtofield password", "add X", "removefield login",
                  "editfield password", "remove", "close --discard"],
                 monkeypatch, ["prim"])
    assert "holds 1 item(s): add --force" in out and "Removed vault 'Perso'" in out
    assert 'Go into an item first' in out and "'password' has no value." in out
    assert "'login' has no value." in out and "Removed item 'X'" in out and "Closed." in out

def test_secret_never_on_command_line(profile, monkeypatch):
    s, out = run([f"load {profile}", "unlock", "decrypt", "cd Perso", "cd GitHub", "addtofield password --values hunter3",
                  "addtofield password"], monkeypatch, ["prim", "sec", "a", "b"])
    assert "never typed on the command line" in out and "The two values differ" in out

def test_clear(monkeypatch):
    class Tty(io.StringIO):
        def isatty(self): return True
    out = Tty(); s = sh.BippassShell(stdout=out, color=False)
    s.onecmd("clear"); s.onecmd("cls")
    assert out.getvalue() == "\033[3J\033[2J\033[H" * 2
    s2, text = run(["clear", "clear now"], monkeypatch)
    assert text == "error: Usage: clear\n"           # not a terminal: nothing written

def test_show_numbers_every_value(profile, monkeypatch):
    s, out = run([f"load {profile}", "unlock", "cd Perso", "cd GitHub", "addtofield login --values bob2",
                  "addtofield website --values https://a.example.com", "show"], monkeypatch, ["prim"])
    assert "login     : bob  [1]" in out and "login     : bob2  [2]" in out
    assert "website   : https://a.example.com  [1]" in out

def test_addfield_values_and_addtofield(profile, monkeypatch):
    s, out = run([f"load {profile}", "unlock", "decrypt", "cd Perso", "cd GitHub",
                  "addfield clear Backup codes --values 1111; 2222 ; 3\\;3",
                  "addfield clear Backup codes",
                  "addfield secret Card PIN --count 2",
                  "addtofield c2 --values aaa; bbb", "addtofield Card PIN", "addtofield c1 --values x",
                  "addtofield login --values bob2; bob3", "addfield login bob", "addfield secret X --values no",
                  "show"], monkeypatch, ["prim", "sec", "11", "11", "22", "22", "33", "33"])
    m = s.manager; it = m.get_item(s.item_uuid); ids = it.custom_ids()
    names = [it.custom_name(c) for c in ids]
    assert names[-3:] == ["Backup codes", "Backup codes", "Card PIN"]
    assert it.get_custom(ids[-3]) == ["1111", "2222", "3;3", "aaa", "bbb"]   # c2: first "Backup codes"
    assert it.get_custom(ids[-2]) == []
    assert "Usage: addtofield c1 --values" not in out and "never typed on the command line" in out
    assert it.get_custom(ids[-1], data_key=m.data_key) == [b"11", b"22", b"33"]
    assert it.get("logins") == ["bob", "bob2", "bob3"]
    assert "is a predefined field: use \"addtofield login" in out and "never typed on the command line" in out

def test_copy(profile, monkeypatch):
    board = []
    monkeypatch.setattr(sh.clipboard, "copy", lambda text: board.append(text))
    monkeypatch.setattr(sh.clipboard, "paste", lambda: board[-1] if board else "")
    monkeypatch.setattr(sh.clipboard, "CLEAR_AFTER_S", 60.0)
    s, out = run([f"load {profile}", "unlock", "cd Perso", "cd GitHub", "copy login",
                  "copy password", "decrypt", "copy password", "copy totp", "copy Recovery",
                  "copy Recovery 2", "copy nope"], monkeypatch, ["prim", "sec"])
    assert board[:2] == ["bob", "hunter2"] and len(board[2]) == 6 and board[2].isdigit()
    assert board[3] == "r2"
    assert 'use "decrypt" first' in out and "'Recovery' has 2 values" in out and "No field 'nope'" in out
    assert "Copied password to the clipboard (cleared in 60 s)." in out
    s.onecmd("lock")                     # clears the clipboard right away
    assert board[-1] == "" and not s._clipboard.pending


def test_scoped_listings_and_accents(profile, monkeypatch):
    s, out = run([f"load {profile}", "unlock", "items", "show", "cd perso", "vaults", "items",
                  "cd github", "items", "show", "ls", "home", "vaults"], monkeypatch, ["prim"])
    assert out.count('"items" only works in a vault') == 2
    assert '"vaults" only works at the root' in out and "Go into an item first" in out
    assert out.count("login     : bob  [1]") == 2 and "1  Perso" in out


def test_editfield_syntax(profile, monkeypatch):
    s, out = run([f"load {profile}", "unlock", "decrypt", "cd Perso", "cd GitHub",
                  "addtofield login --values a; b", "editfield login --value x",
                  "editfield login 2 --value semi; colon", "editfield login 2 --generate",
                  "editfield password --value no", "editfield Recovery 2 --generate 8",
                  "editfield Recovery 2"],
                 monkeypatch, ["prim", "sec", "new", "new"])
    it = s.manager.get_item(s.item_uuid)
    assert "'login' has 3 values" in out and "--count and --generate are for secret fields" in out
    assert it.get("logins") == ["bob", "semi; colon", "b"] and "never typed on the command line" in out
    rec = it.get_custom(it.custom_ids()[0], data_key=s.manager.data_key)
    assert rec[0] == b"r1" and rec[1] == b"new"


def test_lock_without_changes_and_ctrl_c(profile, monkeypatch):
    def interrupt(prompt): raise KeyboardInterrupt
    monkeypatch.setattr(cc.getpass, "getpass", interrupt)
    out = io.StringIO(); s = sh.BippassShell(stdout=out)
    s.onecmd(f"load {profile}"); s.onecmd("unlock")
    assert "Cancelled." in out.getvalue() and s.manager is not None and not s.manager.is_unlocked
    s.onecmd("lock")
    assert "Locked: closed (nothing to save)." in out.getvalue() and s.manager is None


def test_internal_errors_show_traceback(profile, monkeypatch):
    s, out = run([f"load {profile}"], monkeypatch)
    monkeypatch.setattr(sh.fmt, "print_info", lambda *a: 1 / 0)
    s.onecmd("info")
    assert "internal error" in s.stdout.getvalue() and "ZeroDivisionError" in s.stdout.getvalue()


def test_main_exit_status(tmp_path):
    assert sh.main([str(tmp_path / "missing.bippass")]) == 1


def test_create_passwd_and_autolock(tmp_path, monkeypatch):
    import builtins
    import bippass.cli.profile_commands as pc
    monkeypatch.setattr(pc, "profile_path", lambda uuid: tmp_path / f"{uuid}.bippass")
    monkeypatch.setattr(pc, "ensure_profiles_dir", lambda: tmp_path)
    answers = iter(["alice", ""])
    monkeypatch.setattr(builtins, "input", lambda prompt="": next(answers))
    s, out = run(["create", "add Perso", "save", "passwd primary", "passwd secondary"], monkeypatch,
                 ["p1", "p1", "s1", "s1", "p1", "p2", "p2", "s1", "s2", "s2"])
    assert "Created and saved to" in out and s.manager.label == "alice"
    assert "Primary password changed" in out and "Secondary password changed" in out
    path = s.path
    s.manager.get_vaults()[0].set_name("Renamed"); s._changed()
    s._auto_lock()
    assert s.manager is None and "Locked after inactivity" in s.stdout.getvalue()
    s2, out2 = run([f"load {path}", "unlock", "decrypt", "vaults"], monkeypatch, ["p2", "s2"])
    assert "Renamed" in out2


def test_export_import_generate(profile, tmp_path, monkeypatch):
    import bippass.cli.shell as shm
    copied = []
    monkeypatch.setattr(shm.clipboard, "copy", copied.append)
    exported = tmp_path / "out.bippass"
    s, out = run([f"load {profile}", "unlock", "decrypt", "cd Perso", f"export {exported}",
                  f"export {exported}", "home", f"import {exported}", "vaults",
                  "generate 12 --no-special", "generate 8 --show"],
                 monkeypatch, ["prim", "sec", "e1", "e1", "e2", "e2", "e1", "e2"])
    assert exported.exists() and "already exists" in out
    assert "Imported" in out and "imported items" in out
    assert len(copied[0]) == 12 and copied[0].isalnum() and "Generated 12 characters" in out
    assert len(out.strip().splitlines()[-1]) == 8
