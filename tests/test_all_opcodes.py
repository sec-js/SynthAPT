import agent
import sys

out = open("opcode_test_results_py.txt", "w")

def p(msg):
    out.write(str(msg) + "\n")
    out.flush()

# ── filesystem ──────────────────────────────────────────────────────────────

p("[run_command]")
try:
    p(agent.run_command("whoami"))
except Exception as e:
    p("ERROR: " + str(e))

p("[get_cwd]")
try:
    p(agent.get_cwd())
except Exception as e:
    p("ERROR: " + str(e))

p("[write_file]")
try:
    p(agent.write_file("opcode_test_temp.txt", b"write_file_test_data"))
except Exception as e:
    p("ERROR: " + str(e))

p("[read_file]")
try:
    p(agent.read_file("opcode_test_temp.txt"))
except Exception as e:
    p("ERROR: " + str(e))

p("[delete_file]")
try:
    p(agent.delete_file("opcode_test_temp.txt"))
except Exception as e:
    p("ERROR: " + str(e))

# ── execution ────────────────────────────────────────────────────────────────

p("[wmi_exec]")
try:
    p(agent.wmi_exec("calc.exe"))
except Exception as e:
    p("ERROR: " + str(e))

p("[shell_execute]")
try:
    p(agent.shell_execute("cmd.exe", "open", "/c echo 1"))
except Exception as e:
    p("ERROR: " + str(e))

p("[shell_execute_explorer]")
try:
    p(agent.shell_execute_explorer("cmd.exe", "open", "/c echo 1"))
except Exception as e:
    p("ERROR: " + str(e))

p("[shell_extract]")
try:
    p(agent.shell_extract("C:\\nonexistent_opcode_test.zip"))
except Exception as e:
    p("ERROR: " + str(e))

# ── enumerate ────────────────────────────────────────────────────────────────

p("[list_procs]")
try:
    procs = agent.list_procs()
    p("count=" + str(len(procs)))
except Exception as e:
    p("ERROR: " + str(e))

p("[resolve_hostname]")
try:
    p(agent.resolve_hostname("localhost"))
except Exception as e:
    p("ERROR: " + str(e))

# ── network ──────────────────────────────────────────────────────────────────

p("[http_send]")
try:
    p(agent.http_send("GET", "127.0.0.1", 80, "/", False, ""))
except Exception as e:
    p("ERROR: " + str(e))

p("[portscan]")
try:
    p(agent.portscan("127.0.0.1", "445"))
except Exception as e:
    p("ERROR: " + str(e))

# ── registry ─────────────────────────────────────────────────────────────────

p("[reg_create_key]")
try:
    p(agent.reg_create_key("HKCU\\SOFTWARE\\OpcodeTest"))
except Exception as e:
    p("ERROR: " + str(e))

p("[reg_set_value]")
try:
    p(agent.reg_set_value("HKCU\\SOFTWARE\\OpcodeTest", "TestVal", "REG_SZ", b"TestData123"))
except Exception as e:
    p("ERROR: " + str(e))

p("[reg_query_value]")
try:
    p(agent.reg_query_value("HKCU\\SOFTWARE\\OpcodeTest", "TestVal"))
except Exception as e:
    p("ERROR: " + str(e))

p("[reg_delete_key]")
try:
    p(agent.reg_delete_key("HKCU\\SOFTWARE\\OpcodeTest"))
except Exception as e:
    p("ERROR: " + str(e))

# ── privileges / token ───────────────────────────────────────────────────────

p("[list_thread_privs]")
try:
    p(agent.list_thread_privs())
except Exception as e:
    p("ERROR: " + str(e))

p("[list_process_privs]")
try:
    p(agent.list_process_privs())
except Exception as e:
    p("ERROR: " + str(e))

p("[enable_privilege]")
try:
    p(agent.enable_privilege("SeDebugPrivilege"))
except Exception as e:
    p("ERROR: " + str(e))

p("[make_token]")
try:
    p(agent.make_token(".", "fakeuser_optest", "FakeP@ss1"))
except Exception as e:
    p("ERROR: " + str(e))

p("[impersonate_process]")
try:
    p(agent.impersonate_process(99999999))
except Exception as e:
    p("ERROR: " + str(e))

p("[revert_to_self]")
try:
    p(agent.revert_to_self())
except Exception as e:
    p("ERROR: " + str(e))

# ── user / group ─────────────────────────────────────────────────────────────

p("[get_user_sid]")
try:
    p(agent.get_user_sid("Administrator"))
except Exception as e:
    p("ERROR: " + str(e))

p("[set_user_password]")
try:
    p(agent.set_user_password("nonexistent_optest", "P@ss123!"))
except Exception as e:
    p("ERROR: " + str(e))

p("[add_user_to_localgroup]")
try:
    p(agent.add_user_to_localgroup("Users", "nonexistent_optest"))
except Exception as e:
    p("ERROR: " + str(e))

p("[remove_user_from_localgroup]")
try:
    p(agent.remove_user_from_localgroup("Users", "nonexistent_optest"))
except Exception as e:
    p("ERROR: " + str(e))

p("[add_user_to_group]")
try:
    p(agent.add_user_to_group("Users", "nonexistent_optest"))
except Exception as e:
    p("ERROR: " + str(e))

p("[remove_user_from_group]")
try:
    p(agent.remove_user_from_group("Users", "nonexistent_optest"))
except Exception as e:
    p("ERROR: " + str(e))

# ── ldap / ad ────────────────────────────────────────────────────────────────

p("[create_rbcd_ace]")
try:
    p(agent.create_rbcd_ace("S-1-5-21-1234567890-1234567890-1234567890-1001"))
except Exception as e:
    p("ERROR: " + str(e))

p("[query_ldap]")
try:
    p(agent.query_ldap("DC=test,DC=local", "(objectClass=user)", 2, "cn"))
except Exception as e:
    p("ERROR: " + str(e))

p("[set_ad_attr_str]")
try:
    p(agent.set_ad_attr_str("CN=test,DC=test,DC=local", "description", "test"))
except Exception as e:
    p("ERROR: " + str(e))

p("[set_ad_attr_bin]")
try:
    p(agent.set_ad_attr_bin("CN=test,DC=test,DC=local", "userCertificate", bytes.fromhex("DEADBEEF")))
except Exception as e:
    p("ERROR: " + str(e))

# ── memory ───────────────────────────────────────────────────────────────────

p("[load_library]")
try:
    p(agent.load_library("../staging/python38.dll"))
except Exception as e:
    p("ERROR: " + str(e))

p("[mem_read]")
try:
    p(agent.mem_read("7FFE0000", 16))
except Exception as e:
    p("ERROR: " + str(e))

p("[dll_list]")
try:
    results = agent.dll_list()
    p("count=" + str(len(results)))
except Exception as e:
    p("ERROR: " + str(e))

p("[mem_map]")
try:
    results = agent.mem_map()
    p("count=" + str(len(results)))
except Exception as e:
    p("ERROR: " + str(e))

p("[malfind]")
try:
    results = agent.malfind()
    p("count=" + str(len(results)))
except Exception as e:
    p("ERROR: " + str(e))

p("[ldr_check]")
try:
    results = agent.ldr_check()
    p("count=" + str(len(results)))
except Exception as e:
    p("ERROR: " + str(e))

# ── injection ────────────────────────────────────────────────────────────────

p("[hollow]")
try:
    p(agent.hollow("C:\\Windows\\System32\\notepad.exe", 1))
except Exception as e:
    p("ERROR: " + str(e))

p("[apc_injection]")
try:
    p(agent.apc_injection("C:\\Windows\\System32\\notepad.exe", 1))
except Exception as e:
    p("ERROR: " + str(e))

p("[sacrificial]")
try:
    p(agent.sacrificial("C:\\Windows\\System32\\notepad.exe", 1))
except Exception as e:
    p("ERROR: " + str(e))

p("[create_thread]")
try:
    p(agent.create_thread(1))
except Exception as e:
    p("ERROR: " + str(e))

# ── services ─────────────────────────────────────────────────────────────────

p("[register_service]")
try:
    p(agent.register_service("OpcodeTestSvc"))
except Exception as e:
    p("ERROR: " + str(e))

p("[start_service]")
try:
    p(agent.start_service("nonexistent_svc_optest"))
except Exception as e:
    p("ERROR: " + str(e))

p("[delete_service]")
try:
    p(agent.delete_service("nonexistent_svc_optest"))
except Exception as e:
    p("ERROR: " + str(e))

p("DONE")
out.close()
