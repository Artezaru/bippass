import json, pytest, threading
from bippass.core.manager import PasswordManager
from bippass.core.item import Item
from bippass.core.exceptions import (PrimaryPasswordError, SecondaryPasswordError, UnsupportedVersionError,
    CorruptedFileError, TamperedDataError, VaultNotFoundError, ItemNotFoundError)

def P(s): return bytearray(s, "utf-8")

def new():
    m = PasswordManager.create("alice", P("prim"), P("sec"))
    v = m.add_empty_vault("Perso"); it = m.add_empty_item(v.uuid)
    it.set_name("GitHub"); it.set("passwords", [P("hunter2")], data_key=m.data_key)
    return m, v, it

def test_roundtrip_and_layers(tmp_path):
    m, v, it = new(); m.set_theme("light"); f = tmp_path / "a.encrypted"; m.save(f); m.close()
    with pytest.raises(RuntimeError): m.get_vaults()
    env = json.loads(f.read_text()); assert set(env) == {"format", "version", "label", "primary_key", "payload"}
    m2 = PasswordManager.read(f)
    with pytest.raises(RuntimeError): m2.get_vaults()
    with pytest.raises(PrimaryPasswordError): m2.unlock(P("bad"))
    m2.unlock(P("prim"))
    assert m2.get_username() == "alice" and m2.get_theme() == "light"
    assert m2.get_item(it.uuid).get_name() == "GitHub"
    with pytest.raises(RuntimeError): m2.data_key
    with pytest.raises(SecondaryPasswordError): m2.decrypt(P("bad"))
    m2.decrypt(P("sec"))
    assert m2.get_item(it.uuid).get("passwords", data_key=m2.data_key) == [b"hunter2"]

def test_save_without_secondary(tmp_path):
    m, v, it = new(); f = tmp_path / "a"; m.save(f)
    m2 = PasswordManager.read(f); m2.unlock(P("prim")); m2.get_item(it.uuid).set_name("X"); m2.save(f)
    m3 = PasswordManager.read(f); m3.unlock(P("prim")); m3.decrypt(P("sec"))
    assert m3.get_item(it.uuid).get_name() == "X"
    assert m3.get_item(it.uuid).get("passwords", data_key=m3.data_key) == [b"hunter2"]

def test_bad_files(tmp_path):
    with pytest.raises(UnsupportedVersionError): PasswordManager.from_bytes(b"PACBxxxx")
    with pytest.raises(CorruptedFileError): PasswordManager.from_bytes(b"hello")
    m, v, it = new(); env = json.loads(m.to_bytes())
    with pytest.raises(UnsupportedVersionError): PasswordManager.from_bytes(json.dumps({**env, "version": 4}).encode())
    with pytest.raises(CorruptedFileError): PasswordManager.from_bytes(json.dumps({**env, "x": 1}).encode())
    tampered = dict(env); other = json.loads(new()[0].to_bytes()); tampered["payload"] = other["payload"]
    m2 = PasswordManager.from_bytes(json.dumps(tampered).encode())
    with pytest.raises(TamperedDataError): m2.unlock(P("prim"))

def test_change_passwords(tmp_path):
    m, v, it = new(); f = tmp_path / "a"
    with pytest.raises(PrimaryPasswordError): m.change_primary_password(P("bad"), P("new"))
    old_dk = m.data_key
    m.change_primary_password(P("prim"), P("prim2"))
    m.change_secondary_password(P("sec"), P("sec2"))
    assert old_dk.is_cleared and m.get_item(it.uuid) is it
    assert it.get("passwords", data_key=m.data_key) == [b"hunter2"]
    with pytest.raises(SecondaryPasswordError): m.change_secondary_password(P("sec"), P("x"))
    m.save(f)
    m2 = PasswordManager.read(f)
    with pytest.raises(PrimaryPasswordError): m2.unlock(P("prim"))
    m2.unlock(P("prim2")); m2.decrypt(P("sec2"))
    assert m2.get_item(it.uuid).get("passwords", data_key=m2.data_key) == [b"hunter2"]

def test_vaults_items():
    m, v, it = new(); w = m.add_empty_vault("Perso")   # duplicate name OK
    m.move_item(it.uuid, w.uuid); assert m.vault_of(it.uuid) is w and len(v) == 0
    d = m.duplicate_item(it.uuid); assert d.uuid != it.uuid and set(w.item_uuids()) == {it.uuid, d.uuid}
    assert d.get("passwords", data_key=m.data_key) == [b"hunter2"]
    with pytest.raises(ValueError): m.remove_vault(w.uuid)
    m.remove_vault(v.uuid); assert m.vault_uuids() == (w.uuid,)
    with pytest.raises(VaultNotFoundError): m.get_vault(v.uuid)
    m.remove_item(d.uuid)
    with pytest.raises(ItemNotFoundError): m.get_item(d.uuid)

def test_export_import(tmp_path):
    m, v, it = new(); f = tmp_path / "x"
    m.export_items(f, [it.uuid], P("ep"), P("es"))
    imported = m.import_items(f, P("ep"), P("es"))       # collides with itself → new uuid
    assert len(imported) == 1 and imported[0].uuid != it.uuid
    assert imported[0].get("passwords", data_key=m.data_key) == [b"hunter2"]
    assert m.vault_of(imported[0].uuid).get_name() == "imported items"
    again = m.import_items(f, P("ep"), P("es"), vault_name="  Reçus  ")
    assert m.vault_of(again[0].uuid).get_name() == "Reçus"

def test_threaded_write(tmp_path):
    m, v, it = new(); f = tmp_path / "a"; data = m.to_bytes()
    t = threading.Thread(target=PasswordManager.write_file, args=(f, data)); t.start()
    it.set_name("changed meanwhile"); t.join()
    m2 = PasswordManager.read(f); m2.unlock(P("prim")); assert m2.get_item(it.uuid).get_name() == "GitHub"
    assert repr(m).startswith("PasswordManager(decrypted")
    m.encrypt(); assert repr(m).startswith("PasswordManager(unlocked")
    m.close(); assert repr(m) == "PasswordManager(closed)"

def test_label(tmp_path):
    m = PasswordManager.create("alice", P("p"), P("s"), label="  Alice ")
    f = tmp_path / "a"; m.save(f)
    r = PasswordManager.read(f); assert r.label == "Alice"          # no password needed
    env = json.loads(f.read_text()); env["label"] = "Mallory"
    t = PasswordManager.from_bytes(json.dumps(env).encode()); assert t.label == "Mallory"
    with pytest.raises(TamperedDataError): t.unlock(P("p"))  # label is authenticated
    r.unlock(P("p")); r.set_label("   "); r.save(f)
    assert PasswordManager.read(f).label is None

def test_profiles(tmp_path, monkeypatch):
    import bippass.core.profiles as pr
    from bippass.core.uuids import UUIDError
    monkeypatch.setattr(pr, "PROFILES_DIR", tmp_path / "profiles"); pr.ensure_profiles_dir()
    with pytest.raises(UUIDError): pr.profile_path("../evil")
    for label in ("bob", None, "Été"):
        m = PasswordManager.create(None, P("p"), P("s"), label=label); m.save(pr.profile_path(m.uuid))
    (pr.PROFILES_DIR / "old.encrypted").write_bytes(b"PACB....")
    (pr.PROFILES_DIR / "junk.bippass").write_bytes(b"not json")
    entries = pr.list_existing_profiles()
    assert [(e.label, e.supported) for e in entries] == [("bob", True), ("Été", True), (None, True)]

def test_encrypt_keeps_content(tmp_path):
    m, v, it = new()
    it.set_name("unsaved"); m.encrypt()
    with pytest.raises(RuntimeError): m.data_key
    assert m.get_item(it.uuid).get_name() == "unsaved"
    with pytest.raises(SecondaryPasswordError): m.decrypt(P("bad"))
    m.decrypt(P("sec"))
    assert m.get_item(it.uuid).get("passwords", data_key=m.data_key) == [b"hunter2"]


def test_lock_timer_and_dates(tmp_path):
    m, v, it = new(); assert m.get_lock_timer_s() == 300
    m.set_lock_timer_s(60)
    with pytest.raises(ValueError): m.set_lock_timer_s(0)
    with pytest.raises(TypeError): m.set_lock_timer_s(True)
    f = tmp_path / "a"; m.save(f)
    r = PasswordManager.read(f); r.unlock(P("prim")); assert r.get_lock_timer_s() == 60
    from bippass.core.common import _check_date
    with pytest.raises(ValueError): _check_date("d", "yesterday", "x")
    assert _check_date("d", None, "now") == "now"


def test_vaults_sorted_by_name():
    m = PasswordManager.create("u", bytearray(b"p"), bytearray(b"s"))
    for name in ("b", None, "Vault 10", "a", "Vault 2"):
        m.add_empty_vault(name)
    assert [v.get_name() for v in m.get_vaults()] == ["a", "b", "Vault 2", "Vault 10", None]
    assert m.vault_uuids() == tuple(v.uuid for v in m.get_vaults())
    v = m.get_vaults()[0]; it = m.add_empty_item(v.uuid)
    m.move_item(it.uuid, v.uuid); assert m.vault_of(it.uuid) is v     # same vault: nothing
